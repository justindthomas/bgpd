//! End-to-end test for the full bgpd instance pipeline:
//!
//!   fake BGP peer ─TCP─▶ BgpInstance ─Unix─▶ fake ribd
//!
//! Stands up a localhost TCP listener pretending to be a remote
//! BGP peer, a Unix socket pretending to be ribd, constructs
//! a `BgpInstance` from a synthetic `BgpDaemonConfig`, and waits
//! for a chunked-bulk push containing the BGP route the fake
//! peer announces. Exercises every B5+ component in one shot:
//! transport, FSM, Peer driver, instance event loop,
//! Adj-RIB-In, Loc-RIB rebuild, rib_push.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, UnixListener};
use tokio::sync::Mutex;

use bgpd::config::{BgpDaemonConfig, BgpPeerConfig};
use bgpd::control::SpeakerSnapshot;
use bgpd::instance::BgpInstance;
use bgpd::packet::attrs::{AsPathSegment, AsPathSegmentType, Origin, PathAttribute};
use bgpd::packet::caps::{Capability, AFI_IPV4, SAFI_UNICAST};
use bgpd::packet::header::{Header, MessageType, HEADER_LEN};
use bgpd::packet::keepalive;
use bgpd::packet::open::Open;
use bgpd::packet::update::{Prefix4, Update};

use ribd_proto::{
    decode, encode, ClientMsg, ServerMsg, Source as RibSource, PROTOCOL_VERSION,
};

// Use iBGP (same ASN on both sides) so the test exercises the
// full pipeline without hitting the RFC 8212 default-deny that
// bgpd applies to eBGP peers with no explicit policy. The
// T8 policy DSL will add a way to configure accept-all on eBGP.
const REMOTE_ASN: u32 = 65000;
const LOCAL_ASN: u32 = 65000;

/// What the fake ribd captures across all sessions for the
/// test to assert against.
#[derive(Default, Debug)]
struct FakeRibCapture {
    /// (source, prefix-as-string) pairs that arrived via any
    /// chunked bulk. Tracked as a set because the instance
    /// over-pushes for v1 and we want the test to be order-
    /// independent.
    bulk_routes: HashSet<(RibSource, String)>,
    bulk_count: usize,
}

/// Spawn a fake ribd that handles Hello + chunked bulk and
/// records the routes that arrive.
async fn spawn_fake_ribd() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    Arc<Mutex<FakeRibCapture>>,
) {
    let dir = tempfile::tempdir().unwrap();
    let sock_path = dir.path().join("ribd.sock");
    let listener = UnixListener::bind(&sock_path).unwrap();
    let capture = Arc::new(Mutex::new(FakeRibCapture::default()));
    let capture_clone = capture.clone();

    tokio::spawn(async move {
        loop {
            let (stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => break,
            };
            let cap = capture_clone.clone();
            tokio::spawn(handle_fake_rib_session(stream, cap));
        }
    });

    (dir, sock_path, capture)
}

async fn handle_fake_rib_session(
    stream: tokio::net::UnixStream,
    capture: Arc<Mutex<FakeRibCapture>>,
) {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    // Per-connection chunked-bulk staging buffer.
    let mut staging: std::collections::HashMap<
        u64,
        (RibSource, Vec<ribd_proto::Route>),
    > = std::collections::HashMap::new();
    loop {
        let mut len_buf = [0u8; 4];
        if reader.read_exact(&mut len_buf).await.is_err() {
            break;
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        let mut buf = vec![0u8; len];
        if reader.read_exact(&mut buf).await.is_err() {
            break;
        }
        let msg: ClientMsg = decode(&buf).unwrap();
        let reply = match msg {
            ClientMsg::Hello { .. } => ServerMsg::HelloAck {
                server_version: PROTOCOL_VERSION,
            },
            ClientMsg::BulkBegin { source, generation } => {
                staging.insert(generation, (source, Vec::new()));
                ServerMsg::Ok
            }
            ClientMsg::BulkChunk { generation, routes } => {
                if let Some((_src, acc)) = staging.get_mut(&generation) {
                    acc.extend(routes);
                }
                ServerMsg::Ok
            }
            ClientMsg::BulkEnd { source: _, generation } => {
                if let Some((src, routes)) = staging.remove(&generation) {
                    let mut cap = capture.lock().await;
                    cap.bulk_count += 1;
                    for r in routes {
                        cap.bulk_routes.insert((src, format!("{}", r.prefix)));
                    }
                }
                ServerMsg::Ok
            }
            ClientMsg::Bulk { source, routes } => {
                let mut cap = capture.lock().await;
                cap.bulk_count += 1;
                for r in routes {
                    cap.bulk_routes.insert((source, format!("{}", r.prefix)));
                }
                ServerMsg::Ok
            }
            ClientMsg::Update { .. } => ServerMsg::Ok,
            ClientMsg::Query(_) => ServerMsg::Error {
                message: "fake ribd: query not supported in this test".into(),
            },
            ClientMsg::Heartbeat => ServerMsg::Ok,
        };
        let bytes = encode(&reply).unwrap();
        if write_half.write_all(&bytes).await.is_err() {
            break;
        }
    }
}

/// Drive a fake remote BGP peer that owns a pre-bound listener,
/// runs the standard handshake, announces a single IPv4 prefix,
/// and holds the connection briefly so the instance can finish
/// the rib push.
async fn run_fake_bgp_peer(listener: TcpListener) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let (read_half, mut write_half) = sock.into_split();
        let mut reader = BufReader::new(read_half);

        // 1. Read the bgpd OPEN.
        let bytes = read_one_message(&mut reader).await;
        assert_eq!(
            Header::parse(&bytes).unwrap().msg_type,
            MessageType::Open,
            "expected OPEN from bgpd"
        );

        // 2. Send our OPEN back. Use a short hold time so the
        //    test doesn't hang on the default 90s.
        let our_open = Open::new(
            REMOTE_ASN,
            9,
            Ipv4Addr::new(10, 0, 0, 2),
            vec![Capability::Multiprotocol {
                afi: AFI_IPV4,
                safi: SAFI_UNICAST,
            }],
        );
        write_half.write_all(&our_open.encode()).await.unwrap();

        // 3. bgpd should send KEEPALIVE in response.
        let bytes = read_one_message(&mut reader).await;
        assert_eq!(Header::parse(&bytes).unwrap().msg_type, MessageType::Keepalive);

        // 4. Send our KEEPALIVE so bgpd transitions to Established.
        write_half.write_all(&keepalive::encode()).await.unwrap();

        // 5. Announce a route.
        let update = Update {
            withdrawn_v4: Vec::new(),
            path_attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(vec![AsPathSegment {
                    seg_type: AsPathSegmentType::AsSequence,
                    asns: vec![REMOTE_ASN],
                }]),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            nlri_v4: vec![Prefix4 {
                addr: Ipv4Addr::new(192, 0, 2, 0),
                len: 24,
            }],
        };
        write_half.write_all(&update.encode()).await.unwrap();

        // Hold the connection briefly so the instance can finish
        // pushing to ribd, then close.
        tokio::time::sleep(Duration::from_millis(500)).await;
        drop(write_half);
        drop(reader);
    })
}

async fn read_one_message(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
) -> Vec<u8> {
    let mut header = [0u8; HEADER_LEN];
    reader.read_exact(&mut header).await.unwrap();
    let total_len = u16::from_be_bytes([header[16], header[17]]) as usize;
    let mut full = vec![0u8; total_len];
    full[..HEADER_LEN].copy_from_slice(&header);
    if total_len > HEADER_LEN {
        reader.read_exact(&mut full[HEADER_LEN..]).await.unwrap();
    }
    full
}

#[tokio::test]
async fn instance_e2e_pushes_received_route_to_ribd() {
    // 1. Fake ribd.
    let (_ribd_dir, ribd_sock, capture) = spawn_fake_ribd().await;

    // 2. Fake BGP peer listener: bind to an ephemeral port, then
    //    hand the listener to the fake peer task. This avoids
    //    needing CAP_NET_BIND_SERVICE for port 179.
    let bgp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let bgp_addr = bgp_listener.local_addr().unwrap();
    let fake_peer = run_fake_bgp_peer(bgp_listener).await;

    // 3. Synthetic config pointing bgpd at the fake peer.
    let config = BgpDaemonConfig {
        enabled: true,
        local_asn: LOCAL_ASN,
        router_id: Some(Ipv4Addr::new(10, 0, 0, 1)),
        peers: vec![BgpPeerConfig {
            address: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: Some(bgp_addr.port()),
            remote_asn: REMOTE_ASN,
            source_address: None,
            password: None,
            hold_time: Some(9),
            address_families: Vec::new(),
            import_policy: None,
            export_policy: None,
            redistribute: Vec::new(),
        }],
        announced_prefixes_v4: Vec::new(),
        announced_prefixes_v6: Vec::new(),
        aggregates_v4: Vec::new(),
        aggregates_v6: Vec::new(),
        listen_address: None,
        route_maps: std::collections::HashMap::new(),
    };

    // 4. Build the instance against the fake ribd, spawn
    //    peers, run the instance loop in a task.
    let snapshot = Arc::new(Mutex::new(SpeakerSnapshot::default()));
    let (mut instance, _instance_control_tx) = BgpInstance::new(
        config,
        std::path::PathBuf::from("/dev/null"),
        ribd_sock.to_str().unwrap(),
        snapshot.clone(),
    )
    .await
    .expect("instance");
    instance.spawn_peers().await.expect("spawn peers");
    let runner = tokio::spawn(async move {
        instance.run().await;
    });

    // 5. Wait up to 5 seconds for the route to land in the fake
    //    ribd's capture. We poll the capture rather than
    //    using a notify primitive because the fake ribd's
    //    inner loop is lock-free at the protocol level.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    let mut saw_route = false;
    while tokio::time::Instant::now() < deadline {
        {
            let cap = capture.lock().await;
            if cap.bulk_routes.iter().any(|(src, p)| {
                *src == RibSource::BgpInternal && p.starts_with("192.0.2.0")
            }) {
                saw_route = true;
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    // Tear down before asserting so a hung instance doesn't
    // dangle.
    runner.abort();
    let _ = runner.await;
    let _ = fake_peer.await;

    assert!(
        saw_route,
        "bgpd should push the BGP route to ribd. Capture: {:?}",
        *capture.lock().await
    );
}
