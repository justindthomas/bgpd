//! bgpd — RFC 4271 BGP-4 with ribd integration.
//!
//! Pushes best-path winners to ribd as routes with
//! `NextHop::Recursive` next-hops; ribd's NexthopTracker
//! resolves them against the IGP-installed RIB and programs the
//! result into VPP / kernel.
//!
//! Usage:
//!   bgpd --config /etc/bgpd/config.yaml
//!   bgpd query summary
//!   bgpd query neighbors
//!   bgpd query routes
//!
//! v1 RFC scope: 4271 + 4760 (MP-BGP v4/v6 unicast) + 5492
//! (capabilities) + 6793 (4-octet ASN) + 2918 (route refresh) +
//! 7606 (treat-as-withdraw) + 8212 (default-deny EBGP) + 1997
//! (communities). Graceful Restart, ADD-PATH, BMP, RPKI, and BGP
//! Roles are explicitly v2.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::Mutex;
use tracing_subscriber::EnvFilter;

use bgpd::config::BgpDaemonConfig;
use bgpd::control::{
    self, ControlRequest, ControlResponse, NeighborStatus, PeerSummary, RouteEntry, RoutesReply,
    SpeakerSnapshot, SummaryReply, DEFAULT_CONTROL_SOCKET,
};
use bgpd::instance::BgpInstance;

const DEFAULT_CONFIG_PATH: &str = "/etc/bgpd/config.yaml";
const DEFAULT_RIB_SOCKET: &str = "/run/ribd.sock";

enum Command {
    Run(RunArgs),
    Query(QueryArgs),
}

struct RunArgs {
    config_path: PathBuf,
    rib_socket: String,
    control_socket: String,
    use_vcl: bool,
}

struct QueryArgs {
    control_socket: String,
    request: ControlRequest,
    output: OutputFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutputFormat {
    Text,
    Json,
}

fn print_usage_and_exit(code: u8) -> ExitCode {
    eprintln!("Usage:");
    eprintln!(
        "  bgpd [--config PATH] [--rib-socket PATH] [--control-socket PATH] [--vcl]"
    );
    eprintln!("  bgpd query [-o text|json] <summary|neighbors|routes>");
    eprintln!("  bgpd query [-o text|json] advertised <peer-ip>");
    eprintln!("  bgpd query [-o text|json] received <peer-ip>");
    ExitCode::from(code)
}

fn parse_args() -> Option<Command> {
    let raw: Vec<String> = std::env::args().skip(1).collect();
    if raw.is_empty() {
        // Match ospfd's foot-gun guard: a zero-arg invocation
        // shouldn't silently start a daemon — that would race the
        // systemd-managed instance on the control socket.
        return None;
    }

    if raw[0] == "query" {
        // Strip -o/--output <val> pairs before positional parsing so
        // the flag can appear anywhere after `query`.
        let mut output = OutputFormat::Text;
        let mut positional: Vec<String> = Vec::new();
        let mut iter = raw.iter().skip(1);
        while let Some(arg) = iter.next() {
            match arg.as_str() {
                "-o" | "--output" => {
                    let v = iter.next()?;
                    output = match v.as_str() {
                        "text" => OutputFormat::Text,
                        "json" => OutputFormat::Json,
                        _ => return None,
                    };
                }
                _ => positional.push(arg.clone()),
            }
        }

        if positional.is_empty() {
            return None;
        }
        let request = match positional[0].as_str() {
            "summary" => ControlRequest::Summary,
            "neighbors" => ControlRequest::Neighbors,
            "routes" => ControlRequest::Routes,
            "advertised" => {
                let peer = match positional.get(1) {
                    Some(p) => p.clone(),
                    None => {
                        eprintln!("Usage: bgpd query advertised <peer-ip>");
                        return None;
                    }
                };
                ControlRequest::Advertised { peer }
            }
            "received" => {
                let peer = match positional.get(1) {
                    Some(p) => p.clone(),
                    None => {
                        eprintln!("Usage: bgpd query received <peer-ip>");
                        return None;
                    }
                };
                ControlRequest::Received { peer }
            }
            _ => return None,
        };
        return Some(Command::Query(QueryArgs {
            control_socket: DEFAULT_CONTROL_SOCKET.to_string(),
            request,
            output,
        }));
    }

    let mut config_path = PathBuf::from(DEFAULT_CONFIG_PATH);
    let mut rib_socket = DEFAULT_RIB_SOCKET.to_string();
    let mut control_socket = DEFAULT_CONTROL_SOCKET.to_string();
    let mut use_vcl = false;
    let mut i = 0;
    while i < raw.len() {
        match raw[i].as_str() {
            "--config" => {
                config_path = PathBuf::from(raw.get(i + 1)?);
                i += 2;
            }
            "--rib-socket" => {
                rib_socket = raw.get(i + 1)?.clone();
                i += 2;
            }
            "--control-socket" => {
                control_socket = raw.get(i + 1)?.clone();
                i += 2;
            }
            "--vcl" => {
                use_vcl = true;
                i += 1;
            }
            _ => return None,
        }
    }
    Some(Command::Run(RunArgs {
        config_path,
        rib_socket,
        control_socket,
        use_vcl,
    }))
}

fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,bgpd=info")),
        )
        .init();

    let cmd = match parse_args() {
        Some(c) => c,
        None => return print_usage_and_exit(2),
    };

    let runtime = match tokio::runtime::Runtime::new() {
        Ok(r) => r,
        Err(e) => {
            eprintln!("failed to start tokio runtime: {}", e);
            return ExitCode::from(1);
        }
    };

    match cmd {
        Command::Run(args) => match runtime.block_on(run_daemon(&args)) {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("bgpd exited with error: {:#}", e);
                ExitCode::from(1)
            }
        },
        Command::Query(args) => {
            match runtime.block_on(run_query(&args.control_socket, args.request, args.output)) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("query failed: {}", e);
                    ExitCode::from(1)
                }
            }
        }
    }
}

async fn run_daemon(args: &RunArgs) -> anyhow::Result<()> {
    use anyhow::Context;

    tracing::info!(
        config = %args.config_path.display(),
        rib_socket = %args.rib_socket,
        control_socket = %args.control_socket,
        "bgpd starting"
    );

    let config = BgpDaemonConfig::load_from_yaml(&args.config_path)
        .with_context(|| format!("loading {}", args.config_path.display()))?;

    // Seed the snapshot with whatever identity the config carries
    // (router-id, local ASN). This works even when BGP is
    // disabled — the snapshot will report 0 peers and 0 routes
    // via the control socket, which is exactly what an operator
    // running `bgpd query summary` against a configured-but-
    // disabled daemon expects.
    let snapshot = Arc::new(Mutex::new(SpeakerSnapshot::default()));
    {
        let mut snap = snapshot.lock().await;
        snap.local_asn = config.local_asn;
        if let Some(rid) = config.router_id {
            snap.router_id = rid;
        }
    }

    // Bind the control socket BEFORE the disabled check or any
    // peer setup. Two reasons: (1) so `bgpd query summary`
    // works in disabled mode and reports the empty state cleanly,
    // and (2) so a query run during the connect-to-ribd
    // window doesn't fail with ENOENT.
    let _control_handle = control::serve(&args.control_socket, snapshot.clone())
        .await
        .with_context(|| format!("binding control socket {}", args.control_socket))?;

    if !config.enabled {
        tracing::info!(
            asn = config.local_asn,
            "BGP disabled in config; daemon idle, control socket up"
        );
        // Park forever — systemd would otherwise restart us in a
        // tight loop. A future iteration will reload on SIGHUP.
        std::future::pending::<()>().await;
        return Ok(());
    }

    let (mut instance, instance_control_tx) =
        BgpInstance::new(config, args.config_path.clone(), &args.rib_socket, snapshot.clone())
            .await
            .context("creating BgpInstance")?;

    // Initialize VCL if --vcl was passed. The VclApp must live for
    // the entire daemon lifetime — dropping it calls
    // vppcom_app_destroy which tears down all sessions.
    #[cfg(feature = "vcl")]
    let _vcl_app = if args.use_vcl {
        let app = vcl_rs::VclApp::init("bgpd")
            .map_err(|e| anyhow::anyhow!("VCL init failed: {}", e))?;
        let reactor = vcl_rs::VclReactor::new()
            .map_err(|e| anyhow::anyhow!("VCL reactor failed: {}", e))?;
        instance.set_vcl_reactor(reactor);
        tracing::info!("VCL transport enabled — BGP sessions via VPP TCP stack");
        Some(app)
    } else {
        None
    };
    #[cfg(not(feature = "vcl"))]
    if args.use_vcl {
        anyhow::bail!("--vcl requires bgpd built with --features vcl");
    }

    instance.spawn_peers().await.context("spawning peers")?;
    let _listener_handle = instance.start_listener();

    // SIGHUP triggers a config reload: re-read YAML, diff the
    // local-origin set, push withdraws + announces to every
    // Established peer. No session resets. The signal handler
    // itself is a tiny task that just forwards into the
    // instance's control channel.
    let reload_tx = instance_control_tx.clone();
    tokio::spawn(async move {
        use tokio::signal::unix::{signal, SignalKind};
        let mut sighup = match signal(SignalKind::hangup()) {
            Ok(s) => s,
            Err(e) => {
                tracing::warn!("failed to register SIGHUP handler: {}", e);
                return;
            }
        };
        while sighup.recv().await.is_some() {
            tracing::info!("SIGHUP received — requesting config reload");
            if reload_tx
                .send(bgpd::instance::InstanceControl::Reload)
                .await
                .is_err()
            {
                break;
            }
        }
    });

    instance.run().await;
    drop(instance_control_tx);
    Ok(())
}

async fn run_query(
    socket: &str,
    req: ControlRequest,
    output: OutputFormat,
) -> std::io::Result<()> {
    let stream = UnixStream::connect(socket).await?;
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut bytes = serde_json::to_vec(&req)?;
    bytes.push(b'\n');
    write_half.write_all(&bytes).await?;
    write_half.shutdown().await.ok();

    let mut response_line = String::new();
    reader.read_line(&mut response_line).await?;
    let response: ControlResponse = serde_json::from_str(response_line.trim())?;
    match output {
        OutputFormat::Text => print_response(&response),
        OutputFormat::Json => println!("{}", serde_json::to_string_pretty(&response)?),
    }
    Ok(())
}

fn print_response(resp: &ControlResponse) {
    match resp {
        ControlResponse::Summary(s) => print_summary(s),
        ControlResponse::Neighbors(r) => print_neighbors(&r.neighbors),
        ControlResponse::Routes(r) => print_routes("Loc-RIB", r),
        ControlResponse::Advertised(r) => print_routes("Adj-RIB-Out", r),
        ControlResponse::Received(r) => print_routes("Adj-RIB-In", r),
        ControlResponse::Error { error } => eprintln!("error: {}", error),
    }
}

fn print_summary(s: &SummaryReply) {
    println!("Local ASN:        {}", s.local_asn);
    println!("Router ID:        {}", s.router_id);
    println!("Peers:            {} ({} established)", s.peer_count, s.established_count);
    println!("Loc-RIB IPv4:     {}", s.loc_rib_v4_count);
    println!("Loc-RIB IPv6:     {}", s.loc_rib_v6_count);
    println!();
    if s.peers.is_empty() {
        println!("No peers configured.");
        return;
    }
    println!("{:<40} {:<10} {:<14} {:>12}", "Peer", "ASN", "State", "Adj-RIB-In");
    for p in &s.peers {
        print_peer_summary(p);
    }
}

fn print_peer_summary(p: &PeerSummary) {
    println!(
        "{:<40} {:<10} {:<14} {:>12}",
        p.address, p.asn, p.state, p.adj_rib_in_count
    );
}

fn print_neighbors(neighbors: &[NeighborStatus]) {
    if neighbors.is_empty() {
        println!("No neighbors.");
        return;
    }
    println!(
        "{:<40} {:<10} {:<6} {:<14} {:>10} {:>10} {:>8}",
        "Peer", "ASN", "Type", "State", "Hold", "v4-RIB-In", "v6-RIB-In"
    );
    for n in neighbors {
        println!(
            "{:<40} {:<10} {:<6} {:<14} {:>10} {:>10} {:>8}",
            n.address,
            n.asn,
            if n.is_ebgp { "eBGP" } else { "iBGP" },
            n.state,
            n.hold_time,
            n.adj_rib_in_v4_count,
            n.adj_rib_in_v6_count,
        );
    }
}

fn print_routes(label: &str, r: &RoutesReply) {
    if r.routes.is_empty() {
        println!("No routes in {}.", label);
        return;
    }
    println!("{} ({} entries):", label, r.routes.len());
    println!(
        "{:<22} {:<22} {:<8} {:<6} {:<24} {}",
        "Prefix", "Next-Hop", "Origin", "LP", "AS-Path", "From"
    );
    for route in &r.routes {
        print_route_entry(route);
    }
}

fn print_route_entry(r: &RouteEntry) {
    let lp = match r.local_pref {
        Some(v) => v.to_string(),
        None => "-".to_string(),
    };
    println!(
        "{:<22} {:<22} {:<8} {:<6} {:<24} {}",
        r.prefix, r.next_hop, r.origin, lp, r.as_path, r.from_peer,
    );
}
