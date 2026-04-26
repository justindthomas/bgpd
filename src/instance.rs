//! Top-level BGP speaker instance.
//!
//! Owns the per-peer state, the ribd connection, and the
//! shared [`SpeakerSnapshot`] that backs the control socket.
//! Spawned as a single tokio task that:
//!
//!   1. Connects to ribd.
//!   2. Constructs one [`Peer`] per configured peer, binding each
//!      to a real TCP `connect_info` and a fresh control/state
//!      channel pair, then spawns each as its own tokio task.
//!   3. Aggregates `PeerStateUpdate` events from every peer's
//!      state channel into a single instance-level event loop.
//!   4. On every state change / received UPDATE, refreshes the
//!      `SpeakerSnapshot` so the control socket sees current data.
//!   5. On every received UPDATE or session-up / session-down
//!      transition, recomputes the affected portion of the
//!      Loc-RIB and pushes the result to ribd.
//!
//! v1 keeps the push path simple: every event triggers a full
//! Loc-RIB rebuild + chunked `push_full_rib` to ribd. This is
//! O(loc_rib_size) per UPDATE, which is fine for small lab tables
//! and CI but obviously won't scale to a full DFZ. v2 layers
//! incremental rib_push on top once we have real-peer load to
//! benchmark against — the chunked-bulk protocol on ribd's
//! side is already idempotent (atomic-replace-on-BulkEnd) so
//! over-pushing is correct, just wasteful.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::sync::{mpsc, Mutex};

use ribd_client::RibConnection;

use crate::adj_rib::{AdjRibIn, OriginClass, PeerId, StoredRoute, LOCAL_PEER_ID};
use crate::config::{BgpDaemonConfig, BgpPeerConfig};
use crate::control::{PeerSnapshot, SpeakerSnapshot};
use crate::loc_rib::LocRib;
use crate::local_origin::LocalOrigin;
use crate::peer::fsm::{PeerFsmConfig, PeerState};
use crate::peer::transport::TokioTcpTransport;
use crate::peer::{Peer, PeerConnectInfo, PeerControl, PeerStateUpdate};
use crate::rib_push;
use crate::packet::attrs::{AsPathSegment, AsPathSegmentType, Origin, PathAttribute};
use crate::packet::caps::{AFI_IPV6, SAFI_UNICAST};
use crate::packet::update::{Prefix4, Prefix6, Update};

const DEFAULT_BGP_PORT: u16 = 179;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
/// How long to wait after a session drops to Idle before sending
/// a fresh `PeerControl::Start`. Fixed for v1; v2 should make it
/// exponential per peer with a cap. The FSM treats `Start` from
/// any non-Idle state as a no-op, so racing retries are harmless.
const IDLE_RETRY_BACKOFF: Duration = Duration::from_secs(30);

/// Out-of-band commands the parent (main.rs / signal handlers)
/// can send to the running instance task. `Reload` is used by
/// the SIGHUP handler to trigger a config re-read + diff push to
/// every Established peer without resetting any sessions.
#[derive(Debug)]
pub enum InstanceControl {
    Reload,
}

pub struct BgpInstance {
    config: BgpDaemonConfig,
    /// Path to the YAML this config was loaded from. Used by
    /// `reload_config` to re-read on SIGHUP.
    config_path: std::path::PathBuf,
    snapshot: Arc<Mutex<SpeakerSnapshot>>,
    /// Per-peer control channel sender. Used to send Stop on
    /// shutdown and to inject Start when we want a peer to come
    /// up. Indexed by `PeerId`.
    peer_controls: HashMap<PeerId, mpsc::Sender<PeerControl>>,
    /// Aggregated state-update receiver. Each peer task pushes
    /// events here tagged with its `PeerId`.
    events_rx: mpsc::Receiver<(PeerId, PeerStateUpdate)>,
    events_tx: mpsc::Sender<(PeerId, PeerStateUpdate)>,
    /// Out-of-band control channel from main.rs (SIGHUP etc.).
    control_rx: mpsc::Receiver<InstanceControl>,
    /// Connection to ribd. Held for the lifetime of the
    /// instance; reconnect logic lives in v2.
    rib: RibConnection,
    /// Prefixes to advertise outbound to every peer that reaches
    /// `Established`. Built at startup from `announced_prefixes` +
    /// `redistribute_connected`, refreshed on `reload_config`.
    local_origin: LocalOrigin,
    /// Snapshot of what we last sent each peer for the local-
    /// origin set. When `reload_config` produces a new
    /// `local_origin`, we compute `(new − last_sent)` for
    /// announces and `(last_sent − new)` for withdraws and push
    /// only those deltas. v1 caches a single set globally
    /// because every Established peer receives the same set.
    last_sent_local_origin: LocalOrigin,
    /// Synthetic Adj-RIB-In for locally-originated routes. Lives
    /// alongside the real per-peer Adj-RIB-Ins on
    /// [`SpeakerSnapshot::peers`] but isn't a real peer — its
    /// peer_id is [`LOCAL_PEER_ID`] (0) and the `StoredRoute`
    /// entries inside have `origin_class != PeerLearned`. The
    /// Loc-RIB rebuild path includes this pseudo-peer alongside
    /// every real peer so local-origin routes compete in best-
    /// path the same way peer-learned routes do.
    local_pseudo_rib: AdjRibIn,
    /// Per-peer import/export policies. Populated in
    /// [`spawn_peers`] from the peer config. Absent entries fall
    /// back to the RFC 8212 default for eBGP (deny-all both
    /// directions) or the trust-everything default for iBGP.
    peer_policies: HashMap<PeerId, crate::policy::PeerPolicy>,
    /// Per-peer cache of the current Adj-RIB-Out prefix set.
    /// Updated after every `advertise_to_peer` call and used to
    /// compute the next diff. Cleared when a peer goes Idle.
    adj_rib_out: HashMap<PeerId, AdvertisedPrefixes>,
    /// Parsed aggregate-address configs (prefix + summary_only).
    /// Built at construction from config; rebuilt on SIGHUP.
    parsed_aggregates_v4: Vec<(Prefix4, bool)>,
    parsed_aggregates_v6: Vec<(Prefix6, bool)>,
    #[cfg(feature = "vcl")]
    vcl_reactor: Option<vcl_rs::VclReactor>,
}

impl BgpInstance {
    /// Construct a `BgpInstance` from a parsed `BgpDaemonConfig`.
    /// Connects to ribd as part of construction so a
    /// down-at-start scenario produces a clear error early.
    /// Returns the instance plus a control sender for SIGHUP /
    /// other operator commands.
    pub async fn new(
        config: BgpDaemonConfig,
        config_path: std::path::PathBuf,
        rib_socket_path: &str,
        snapshot: Arc<Mutex<SpeakerSnapshot>>,
    ) -> Result<(Self, mpsc::Sender<InstanceControl>)> {
        let rib = ribd_client::connect_with_retry(
            rib_socket_path,
            "bgpd",
            Duration::from_secs(10),
        )
        .await
        .context("connecting to ribd")?;

        // Seed the snapshot with the speaker's identity so
        // `bgpd query summary` works before any peers come up.
        {
            let mut snap = snapshot.lock().await;
            snap.local_asn = config.local_asn;
            if let Some(rid) = config.router_id {
                snap.router_id = rid;
            }
        }

        let (events_tx, events_rx) = mpsc::channel(256);

        // Build the local-origin prefix set. This queries
        // ribd for connected routes if the config asks for
        // redistribute_connected — we just connected above so
        // the connection is fresh.
        let mut rib = rib;
        let local_origin = LocalOrigin::build(&config, &mut rib)
            .await
            .context("building local-origin prefix set")?;
        if !local_origin.is_empty() {
            tracing::info!(
                v4 = local_origin.v4.len(),
                v6 = local_origin.v6.len(),
                "local-origin prefix set built"
            );
        }

        let (control_tx, control_rx) = mpsc::channel(8);

        let parsed_aggregates_v4 = parse_aggregates_v4(&config.aggregates_v4);
        let parsed_aggregates_v6 = parse_aggregates_v6(&config.aggregates_v6);

        let mut instance = BgpInstance {
            config,
            config_path,
            snapshot,
            peer_controls: HashMap::new(),
            events_rx,
            events_tx,
            control_rx,
            rib,
            local_origin,
            last_sent_local_origin: LocalOrigin::default(),
            local_pseudo_rib: AdjRibIn::new(),
            peer_policies: HashMap::new(),
            adj_rib_out: HashMap::new(),
            parsed_aggregates_v4,
            parsed_aggregates_v6,
            #[cfg(feature = "vcl")]
            vcl_reactor: None,
        };
        instance.rebuild_local_pseudo_rib();
        instance.recompute_aggregates();
        // Initial Loc-RIB build so local-origin routes are
        // visible in queries before any peer sends an UPDATE.
        {
            let mut snap = instance.snapshot.lock().await;
            let loc = rebuild_loc_rib(&snap.peers, &instance.local_pseudo_rib);
            snap.loc_rib = loc;
        }
        Ok((instance, control_tx))
    }

    /// Materialize the current `local_origin` set into the
    /// synthetic local pseudo-peer's Adj-RIB-In. Called at
    /// startup and after every successful `reload_config` so
    /// the next Loc-RIB rebuild sees the up-to-date set.
    ///
    /// Each entry becomes a `StoredRoute::local_origin` with:
    /// - ORIGIN = IGP (locally originated)
    /// - empty AS_PATH (RFC 4271 §5.1.2)
    /// - LOCAL_PREF = 100 (default for iBGP advertisement)
    /// - NEXT_HOP placeholder = 0.0.0.0 / :: (the actual
    ///   next-hop is filled in at outbound-advertise time
    ///   per peer via next-hop-self).
    ///
    /// Check every configured aggregate-address: if ≥1
    /// more-specific exists in the local_pseudo_rib (i.e. any
    /// locally-originated route) or in the overall Loc-RIB, inject
    /// a synthetic aggregate route into the local_pseudo_rib with
    /// `OriginClass::Aggregate`. Remove stale aggregates whose
    /// contributors have disappeared.
    ///
    /// Called after `rebuild_local_pseudo_rib` at startup and after
    /// every Loc-RIB rebuild in the event loop.
    fn recompute_aggregates(&mut self) {
        let local_router_id = self
            .config
            .router_id
            .unwrap_or(Ipv4Addr::UNSPECIFIED);
        let local_asn = self.config.local_asn;

        for (agg, _summary_only) in &self.parsed_aggregates_v4 {
            let has_contributor = self
                .local_pseudo_rib
                .v4_unicast
                .keys()
                .any(|p| is_more_specific_v4(agg, p));
            if has_contributor {
                if !self.local_pseudo_rib.v4_unicast.contains_key(agg) {
                    let route = make_v4_aggregate_route(local_asn, local_router_id);
                    self.local_pseudo_rib.insert_v4(*agg, route);
                }
            } else {
                self.local_pseudo_rib.remove_v4(agg);
            }
        }

        for (agg, _summary_only) in &self.parsed_aggregates_v6 {
            let has_contributor = self
                .local_pseudo_rib
                .v6_unicast
                .keys()
                .any(|p| is_more_specific_v6(agg, p));
            if has_contributor {
                if !self.local_pseudo_rib.v6_unicast.contains_key(agg) {
                    let route = make_v6_aggregate_route(local_asn, local_router_id);
                    self.local_pseudo_rib.insert_v6(*agg, route);
                }
            } else {
                self.local_pseudo_rib.remove_v6(agg);
            }
        }
    }

    /// The `origin_class` per prefix is looked up from the
    /// `LocalOrigin.origin_v4`/`origin_v6` maps, which carry
    /// `Static` for announced_prefixes, `Connected` for
    /// redistribute connected, `Redistribute(source)` for
    /// redistribute ospf/static.
    fn rebuild_local_pseudo_rib(&mut self) {
        use crate::packet::attrs::{Origin as BgpOrigin, PathAttribute};
        use crate::packet::caps::{AFI_IPV6, SAFI_UNICAST};

        self.local_pseudo_rib = AdjRibIn::new();
        let local_router_id = self.config.router_id.unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);

        for prefix in &self.local_origin.v4 {
            let oc = self
                .local_origin
                .origin_v4
                .get(prefix)
                .copied()
                .unwrap_or(OriginClass::Static);
            let path_attrs = vec![
                PathAttribute::Origin(BgpOrigin::Igp),
                PathAttribute::AsPath(Vec::new()),
                PathAttribute::NextHop(std::net::Ipv4Addr::UNSPECIFIED),
                PathAttribute::LocalPref(100),
            ];
            let route = StoredRoute::local_origin(
                path_attrs,
                self.config.local_asn,
                local_router_id,
                oc,
            );
            self.local_pseudo_rib.insert_v4(*prefix, route);
        }

        for prefix in &self.local_origin.v6 {
            let oc = self
                .local_origin
                .origin_v6
                .get(prefix)
                .copied()
                .unwrap_or(OriginClass::Static);
            let path_attrs = vec![
                PathAttribute::Origin(BgpOrigin::Igp),
                PathAttribute::AsPath(Vec::new()),
                PathAttribute::LocalPref(100),
                PathAttribute::MpReachNlri {
                    afi: AFI_IPV6,
                    safi: SAFI_UNICAST,
                    nexthop: vec![0u8; 16],
                    nlri: Vec::new(),
                },
            ];
            let route = StoredRoute::local_origin(
                path_attrs,
                self.config.local_asn,
                local_router_id,
                oc,
            );
            self.local_pseudo_rib.insert_v6(*prefix, route);
        }
    }

    /// Set the VCL reactor for VPP TCP stack integration. When
    /// set, all peer sessions use VclTransport instead of kernel
    /// TCP. Call before `spawn_peers`.
    #[cfg(feature = "vcl")]
    pub fn set_vcl_reactor(&mut self, reactor: vcl_rs::VclReactor) {
        self.vcl_reactor = Some(reactor);
    }

    /// Spawn a Peer task for every configured peer. After this
    /// returns, the instance is ready to enter `run()`.
    pub async fn spawn_peers(&mut self) -> Result<()> {
        // Snapshot the config so the iteration doesn't conflict
        // with the mutable borrow inside spawn_one_peer.
        let peers: Vec<(PeerId, BgpPeerConfig)> = self
            .config
            .peers
            .iter()
            .enumerate()
            .map(|(idx, p)| (idx as PeerId + 1, p.clone()))
            .collect();
        for (peer_id, peer_cfg) in peers {
            self.spawn_one_peer(peer_id, &peer_cfg).await?;
        }
        Ok(())
    }

    async fn spawn_one_peer(
        &mut self,
        peer_id: PeerId,
        cfg: &BgpPeerConfig,
    ) -> Result<()> {
        let router_id = self
            .config
            .router_id
            .ok_or_else(|| anyhow!("BGP router_id required to spawn peer {}", cfg.address))?;
        let fsm_config = PeerFsmConfig {
            local_asn: self.config.local_asn,
            local_router_id: router_id,
            remote_asn: cfg.remote_asn,
            local_hold_time: cfg.hold_time.unwrap_or(90),
            connect_retry: Duration::from_secs(120),
        };
        let connect_info = PeerConnectInfo {
            peer: SocketAddr::new(cfg.address, cfg.port.unwrap_or(DEFAULT_BGP_PORT)),
            source: cfg.source_address.map(|ip| SocketAddr::new(ip, 0)),
            password: cfg.password.clone(),
            timeout: CONNECT_TIMEOUT,
        };

        let (control_tx, control_rx) = mpsc::channel(8);
        let (state_tx, mut state_rx) = mpsc::channel(64);
        let mut peer = Peer::new(fsm_config, control_rx, state_tx);
        peer.set_connect_info(connect_info);
        #[cfg(feature = "vcl")]
        if let Some(reactor) = &self.vcl_reactor {
            peer.set_vcl_reactor(reactor.clone());
        }

        // Seed the snapshot with this peer in Idle state so
        // queries can see it before the session comes up.
        {
            let mut snap = self.snapshot.lock().await;
            snap.peers.push(PeerSnapshot {
                id: peer_id,
                address: cfg.address,
                asn: cfg.remote_asn,
                state: PeerState::Idle,
                negotiated_hold_time: 0,
                is_ebgp: cfg.remote_asn != self.config.local_asn,
                adj_rib_in: AdjRibIn::new(),
            });
        }

        // Forward this peer's state events into the instance's
        // unified event channel, tagging each with the peer id so
        // the instance loop can dispatch them.
        let events_tx = self.events_tx.clone();
        tokio::spawn(async move {
            while let Some(ev) = state_rx.recv().await {
                if events_tx.send((peer_id, ev)).await.is_err() {
                    break;
                }
            }
        });

        // Spawn the driver loop and tell it to start.
        tokio::spawn(async move {
            peer.run().await;
        });
        let _ = control_tx.send(PeerControl::Start).await;

        // Build per-peer policy from config, falling back to
        // RFC 8212 defaults (deny-all for eBGP, accept-all for
        // iBGP) when no explicit policy is configured.
        let is_ebgp = cfg.remote_asn != self.config.local_asn;
        let default_policy = if is_ebgp {
            crate::policy::PeerPolicy::ebgp_default_deny()
        } else {
            crate::policy::PeerPolicy::ibgp_default()
        };
        let import = match &cfg.import_policy {
            Some(pc) => pc.to_policy().unwrap_or(default_policy.import.clone()),
            None => default_policy.import.clone(),
        };
        let export = match &cfg.export_policy {
            Some(pc) => pc.to_policy().unwrap_or(default_policy.export.clone()),
            None => default_policy.export.clone(),
        };
        let policy = crate::policy::PeerPolicy { import, export };
        self.peer_policies.insert(peer_id, policy);

        self.peer_controls.insert(peer_id, control_tx);
        tracing::info!(
            peer = %cfg.address,
            asn = cfg.remote_asn,
            "spawned BGP peer task"
        );
        Ok(())
    }

    /// Main instance loop. Selects on three sources:
    ///
    /// 1. **Per-peer events** — `PeerStateUpdate` from any peer's
    ///    state channel (StateChanged, SessionEstablished,
    ///    UpdateReceived). Drives the cascade into ribd.
    /// 2. **Out-of-band control commands** — `InstanceControl`
    ///    from main.rs (SIGHUP → `Reload`). Drives the
    ///    incremental config-reload path.
    /// Start the BGP listener for passive open if configured.
    /// Spawns a task that accepts inbound TCP connections, validates
    /// source IP against configured peers, and injects the transport
    /// into the matching peer's driver.
    pub fn start_listener(&self) -> Option<tokio::task::JoinHandle<()>> {
        let listen_addr = self.config.listen_address.as_ref()?;
        let addr: SocketAddr = match listen_addr.parse() {
            Ok(a) => a,
            Err(e) => {
                tracing::warn!("invalid listen_address '{}': {}", listen_addr, e);
                return None;
            }
        };

        // Build a map of peer IP → (PeerId, control sender) for
        // fast lookup on accept.
        let mut peer_map: HashMap<IpAddr, (PeerId, mpsc::Sender<PeerControl>)> =
            HashMap::new();
        for (&pid, tx) in &self.peer_controls {
            // Find the peer's address from the snapshot (already
            // populated by spawn_peers).
            // We need to look it up from config since we can't
            // async-lock the snapshot here.
            if let Some(cfg) = self.config.peers.get((pid - 1) as usize) {
                peer_map.insert(cfg.address, (pid, tx.clone()));
            }
        }

        let handle = tokio::spawn(async move {
            let listener = match tokio::net::TcpListener::bind(addr).await {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!("BGP listener bind {} failed: {}", addr, e);
                    return;
                }
            };
            tracing::info!(%addr, "BGP listener started (passive open)");

            loop {
                let (stream, peer_addr) = match listener.accept().await {
                    Ok(s) => s,
                    Err(e) => {
                        tracing::warn!("BGP listener accept error: {}", e);
                        continue;
                    }
                };

                let peer_ip = peer_addr.ip();
                match peer_map.get(&peer_ip) {
                    Some((peer_id, tx)) => {
                        tracing::info!(
                            %peer_addr,
                            peer_id,
                            "accepted inbound BGP connection"
                        );
                        let transport = TokioTcpTransport::from_accepted(stream);
                        let _ = tx
                            .send(PeerControl::InjectTransport(Box::new(transport)))
                            .await;
                    }
                    None => {
                        tracing::warn!(
                            %peer_addr,
                            "rejected inbound BGP connection from unknown peer"
                        );
                        drop(stream);
                    }
                }
            }
        });

        Some(handle)
    }

    /// 3. *(Future)* periodic timers (BGP MED tie-break recompute,
    ///    interface change polling, etc.). v1 has none.
    ///
    /// Returns when the events channel closes (all peers gone),
    /// which should only happen on shutdown.
    pub async fn run(mut self) {
        tracing::info!("BgpInstance entering main loop");
        loop {
            tokio::select! {
                event = self.events_rx.recv() => {
                    let Some((peer_id, event)) = event else {
                        break;
                    };
                    if let Err(e) = self.handle_event(peer_id, event).await {
                        tracing::warn!(peer_id, "instance handle_event failed: {}", e);
                    }
                }
                ctrl = self.control_rx.recv() => {
                    let Some(ctrl) = ctrl else {
                        // control channel closed; treat as
                        // "operator told us nothing" — keep
                        // running on the events channel only.
                        // Replace control_rx with a never-ready
                        // receiver so subsequent selects don't
                        // spin.
                        let (_, rx) = mpsc::channel(1);
                        self.control_rx = rx;
                        continue;
                    };
                    match ctrl {
                        InstanceControl::Reload => {
                            if let Err(e) = self.reload_config().await {
                                tracing::warn!("instance reload failed: {}", e);
                            }
                        }
                    }
                }
            }
        }
        tracing::info!("BgpInstance shut down (events channel closed)");
    }

    /// Re-read the YAML config, re-build the local-origin set,
    /// diff against the cached last-sent set, and push the
    /// per-AFI delta UPDATEs to every Established peer. No
    /// session resets, no per-peer state mutation other than
    /// the single bulk send.
    ///
    /// Scope:
    ///
    /// * Local-origin prefix changes: diff + push delta to every
    ///   Established peer (no session reset).
    /// * Peer add / remove: spawn new peer tasks, Stop removed
    ///   ones, clean up their RIB state. Surviving peers are
    ///   untouched (no session reset).
    /// * Per-peer policy changes on surviving peers: rewrite
    ///   `peer_policies[pid]`, re-run the new import filter
    ///   against the cached `adj_rib_in`, rebuild LocRIB.
    ///   Session stays Established throughout.
    ///
    /// Still out of scope (requires session reset):
    ///
    /// * Changing `local_asn`, `router_id`.
    /// * Changing a peer's `remote_asn`, source address, or other
    ///   FSM-identity fields (treated as "same peer" today even
    ///   though the OPEN would no longer match).
    /// * Auto-reloading on YAML mtime — still SIGHUP-triggered.
    pub async fn reload_config(&mut self) -> Result<()> {
        tracing::info!(path = %self.config_path.display(), "reloading config");

        let new_config =
            BgpDaemonConfig::load_from_yaml(&self.config_path).context("re-reading YAML")?;

        // Peer-set diff. Do this before local-origin so the add/
        // remove doesn't interact with the later push_full.
        let peer_set_changed = self.diff_and_apply_peers(&new_config).await?;

        let new_local_origin = LocalOrigin::build(&new_config, &mut self.rib)
            .await
            .context("rebuilding local-origin")?;

        let added_v4: Vec<Prefix4> = new_local_origin
            .v4
            .iter()
            .filter(|p| !self.last_sent_local_origin.v4.contains(p))
            .copied()
            .collect();
        let removed_v4: Vec<Prefix4> = self
            .last_sent_local_origin
            .v4
            .iter()
            .filter(|p| !new_local_origin.v4.contains(p))
            .copied()
            .collect();
        let added_v6: Vec<Prefix6> = new_local_origin
            .v6
            .iter()
            .filter(|p| !self.last_sent_local_origin.v6.contains(p))
            .copied()
            .collect();
        let removed_v6: Vec<Prefix6> = self
            .last_sent_local_origin
            .v6
            .iter()
            .filter(|p| !new_local_origin.v6.contains(p))
            .copied()
            .collect();

        if added_v4.is_empty()
            && removed_v4.is_empty()
            && added_v6.is_empty()
            && removed_v6.is_empty()
            && !peer_set_changed
        {
            tracing::info!("reload: no local-origin or peer-set changes");
            self.config = new_config;
            self.local_origin = new_local_origin;
            return Ok(());
        }

        tracing::info!(
            added_v4 = added_v4.len(),
            removed_v4 = removed_v4.len(),
            added_v6 = added_v6.len(),
            removed_v6 = removed_v6.len(),
            "reload: pushing local-origin delta"
        );

        // Apply the new config, rebuild the local pseudo-RIB so
        // it reflects the new prefix set, then rebuild Loc-RIB
        // and fan out to every Established peer. The per-peer
        // advertise_to_peer computes its own diff vs the
        // adj_rib_out cache, so we don't need to pass explicit
        // add/remove lists.
        self.local_origin = new_local_origin.clone();
        self.config = new_config;
        self.parsed_aggregates_v4 = parse_aggregates_v4(&self.config.aggregates_v4);
        self.parsed_aggregates_v6 = parse_aggregates_v6(&self.config.aggregates_v6);
        self.rebuild_local_pseudo_rib();
        self.recompute_aggregates();
        {
            let mut snap = self.snapshot.lock().await;
            let loc = rebuild_loc_rib(&snap.peers, &self.local_pseudo_rib);
            snap.loc_rib = loc;
        }
        self.push_full().await?;
        self.advertise_to_all_peers().await;

        self.last_sent_local_origin = new_local_origin;
        Ok(())
    }

    /// Diff the peer set in `new_config` against the currently-
    /// spawned peers (keyed by address) and apply the delta.
    ///
    /// * Peers in old but not in new: Stop, drop from peer_controls
    ///   / peer_policies / adj_rib_out / snapshot.peers.
    /// * Peers in new but not in old: spawn with a fresh PeerId
    ///   (max existing + 1). Identity (local_asn, remote_asn) is
    ///   taken from `new_config` — caller must have already
    ///   validated that neither has drifted for surviving peers.
    /// * Peers in both: if import or export policy changed,
    ///   rewrite peer_policies[pid] and re-filter their cached
    ///   adj_rib_in so denied prefixes exit LocRIB on the next
    ///   rebuild. Session stays Established.
    ///
    /// Returns true if anything changed (caller skips the "no
    /// local-origin changes" early-return in reload_config).
    async fn diff_and_apply_peers(
        &mut self,
        new_config: &BgpDaemonConfig,
    ) -> Result<bool> {
        use std::net::IpAddr;

        let mut changed = false;

        // Map address → PeerId for currently-spawned peers.
        let old_by_addr: HashMap<IpAddr, PeerId> = self
            .config
            .peers
            .iter()
            .enumerate()
            .map(|(idx, p)| (p.address, idx as PeerId + 1))
            .collect();
        let new_by_addr: HashMap<IpAddr, &BgpPeerConfig> = new_config
            .peers
            .iter()
            .map(|p| (p.address, p))
            .collect();

        // Remove peers that are gone from the new config.
        let to_remove: Vec<(PeerId, IpAddr)> = old_by_addr
            .iter()
            .filter(|(addr, _)| !new_by_addr.contains_key(addr))
            .map(|(a, p)| (*p, *a))
            .collect();
        for (pid, addr) in to_remove {
            if let Some(tx) = self.peer_controls.remove(&pid) {
                let _ = tx.send(PeerControl::Stop).await;
            }
            self.peer_policies.remove(&pid);
            self.adj_rib_out.remove(&pid);
            {
                let mut snap = self.snapshot.lock().await;
                snap.peers.retain(|p| p.id != pid);
            }
            tracing::info!(peer = %addr, peer_id = pid, "reload: removed peer");
            changed = true;
        }

        // Apply policy updates to surviving peers.
        for new_p in &new_config.peers {
            let Some(&pid) = old_by_addr.get(&new_p.address) else {
                continue; // New peer — handled below.
            };
            let is_ebgp = new_p.remote_asn != new_config.local_asn;
            let default_policy = if is_ebgp {
                crate::policy::PeerPolicy::ebgp_default_deny()
            } else {
                crate::policy::PeerPolicy::ibgp_default()
            };
            let import = match &new_p.import_policy {
                Some(pc) => pc.to_policy().unwrap_or_else(|_| default_policy.import.clone()),
                None => default_policy.import.clone(),
            };
            let export = match &new_p.export_policy {
                Some(pc) => pc.to_policy().unwrap_or_else(|_| default_policy.export.clone()),
                None => default_policy.export.clone(),
            };
            let new_policy = crate::policy::PeerPolicy { import, export };

            // Unconditionally update + re-filter. The policy types
            // don't cheaply compare (PrefixList holds a Vec), and
            // re-filtering an already-matching set is idempotent
            // + cheap.
            self.peer_policies.insert(pid, new_policy.clone());

            let mut snap = self.snapshot.lock().await;
            if let Some(peer) = snap.peers.iter_mut().find(|p| p.id == pid) {
                let before = peer.adj_rib_in.len();
                peer.adj_rib_in
                    .v4_unicast
                    .retain(|prefix, _| new_policy.import.permits_v4(prefix));
                peer.adj_rib_in
                    .v6_unicast
                    .retain(|prefix, _| new_policy.import.permits_v6(prefix));
                let after = peer.adj_rib_in.len();
                if before != after {
                    tracing::info!(
                        peer = %new_p.address,
                        peer_id = pid,
                        before,
                        after,
                        "reload: import policy dropped prefixes"
                    );
                    changed = true;
                }
            }
        }

        // Add brand-new peers.
        let to_add: Vec<BgpPeerConfig> = new_config
            .peers
            .iter()
            .filter(|p| !old_by_addr.contains_key(&p.address))
            .cloned()
            .collect();
        if !to_add.is_empty() {
            // Pick a fresh PeerId above every existing one.
            let mut next_id = self
                .peer_controls
                .keys()
                .copied()
                .max()
                .unwrap_or(LOCAL_PEER_ID)
                + 1;
            // spawn_one_peer reads self.config.local_asn — switch to
            // the new config first so the newcomer gets the right
            // eBGP/iBGP classification.
            self.config = new_config.clone();
            for peer_cfg in &to_add {
                self.spawn_one_peer(next_id, peer_cfg).await?;
                tracing::info!(
                    peer = %peer_cfg.address,
                    peer_id = next_id,
                    "reload: added peer"
                );
                next_id += 1;
            }
            changed = true;
        } else {
            // No additions, but we still need self.config to reflect
            // the new peer list (so e.g. old_by_addr next time round
            // computes from the post-reload state). The caller will
            // also overwrite self.config when applying local-origin,
            // but do it here too so we're correct in the peer-only
            // case.
            self.config = new_config.clone();
        }

        Ok(changed)
    }

    async fn handle_event(
        &mut self,
        peer_id: PeerId,
        event: PeerStateUpdate,
    ) -> Result<()> {
        match event {
            PeerStateUpdate::StateChanged(new_state) => {
                let mut snap = self.snapshot.lock().await;
                if let Some(p) = snap.peers.iter_mut().find(|p| p.id == peer_id) {
                    p.state = new_state;
                }
                if matches!(new_state, PeerState::Idle) {
                    // Session went down — drop this peer's
                    // Adj-RIB-In and rebuild Loc-RIB so we stop
                    // exporting its routes.
                    if let Some(p) = snap.peers.iter_mut().find(|p| p.id == peer_id) {
                        p.adj_rib_in = AdjRibIn::new();
                    }
                    let loc = rebuild_loc_rib(&snap.peers, &self.local_pseudo_rib);
                    snap.loc_rib = loc;
                    drop(snap);
                    self.push_full().await?;
                    // Forget what this peer had in its Adj-RIB-Out
                    // cache: the next time it comes up we start
                    // from scratch. And fan out the Loc-RIB change
                    // to the remaining peers so they withdraw any
                    // winners that were sourced from this peer.
                    self.adj_rib_out.remove(&peer_id);
                    self.advertise_to_all_peers().await;

                    // Schedule a reconnect attempt. The Peer's
                    // FSM lives forever; nothing inside it
                    // re-arms the connect-retry timer once we
                    // land in Idle. We push a Start in after a
                    // backoff. Spawning in a task means the
                    // instance loop stays responsive while the
                    // backoff sleeps; the FSM will treat the
                    // Start as a no-op if the peer has already
                    // come back up by the time it lands.
                    if let Some(tx) = self.peer_controls.get(&peer_id).cloned() {
                        tokio::spawn(async move {
                            tokio::time::sleep(IDLE_RETRY_BACKOFF).await;
                            let _ = tx.send(PeerControl::Start).await;
                        });
                        tracing::info!(
                            peer_id,
                            backoff_s = IDLE_RETRY_BACKOFF.as_secs(),
                            "scheduled reconnect after Idle"
                        );
                    }
                }
            }
            PeerStateUpdate::SessionEstablished => {
                // Snapshot is updated by the StateChanged path
                // (which always fires before SessionEstablished).
                // We push the current Loc-RIB to ribd now so
                // any routes from other already-Established peers
                // get re-pushed (covering the case where this is
                // the first peer to come up — push is empty but
                // harmless).
                self.push_full().await?;

                // Advertise the current Loc-RIB to the newly-
                // established peer. `advertise_to_peer` walks
                // winners, applies split-horizon + export policy,
                // and emits diffs vs the (empty) cache — which on
                // first contact is a full bulk of whatever Loc-RIB
                // holds (local-origin + any peer-learned winners).
                self.advertise_to_peer(peer_id).await;
            }
            PeerStateUpdate::UpdateReceived(update) => {
                let import_policy = self
                    .peer_policies
                    .get(&peer_id)
                    .map(|pp| pp.import.clone())
                    .unwrap_or_default();
                let snap = self.snapshot.clone();
                {
                    let mut snap = snap.lock().await;
                    apply_update_to_peer(&mut snap, peer_id, update, &import_policy)?;
                    let loc = rebuild_loc_rib(&snap.peers, &self.local_pseudo_rib);
                    snap.loc_rib = loc;
                }
                self.push_full().await?;
                // Fan out the Loc-RIB change to every peer: this
                // is where real transit happens. Each peer gets
                // its own diff (split-horizon + export-policy),
                // so the peer that sent the UPDATE is naturally
                // excluded from seeing its own route bounced
                // back.
                self.advertise_to_all_peers().await;
            }
        }
        Ok(())
    }

    async fn push_full(&mut self) -> Result<()> {
        let snap = self.snapshot.lock().await;
        rib_push::push_full_rib(&mut self.rib, &snap.loc_rib)
            .await
            .context("pushing Loc-RIB to ribd")?;
        Ok(())
    }

    /// Walk the current Loc-RIB, compute the set of prefixes this
    /// peer should have in its Adj-RIB-Out (after split-horizon +
    /// export policy + summary-only suppression), diff against the
    /// cached previous set, and emit withdraws + announces for the
    /// delta. The unified outbound path covers:
    ///
    /// - Session-up: `adj_rib_out[peer]` starts empty, so every
    ///   Loc-RIB winner becomes a fresh announce.
    /// - Transit fan-out: a new peer-learned route rebuilds
    ///   Loc-RIB, then this function runs for every peer,
    ///   pushing the new route to everyone except its source
    ///   (split-horizon).
    /// - SIGHUP reload: local-origin changes flow through Loc-RIB
    ///   and this function emits the diff to every peer.
    /// - Peer-down: when a peer's Adj-RIB-In vanishes, Loc-RIB
    ///   rebuild drops those winners and this function emits
    ///   withdraws to every remaining peer.
    ///
    /// Implemented as four phases — `resolve_advertise_ctx`,
    /// `collect_outbound_routes`, `send_withdraws`, `send_announces` —
    /// so each step is independently testable. Outbound rewrites
    /// (AS_PATH prepend, next-hop-self, LOCAL_PREF strip on eBGP)
    /// come from [`build_outbound_attrs`]. Announces are batched
    /// by source peer_id: routes sharing a winner share path
    /// attributes, and RFC 4271 §5.1.2 guarantees one UPDATE per
    /// group is safe.
    async fn advertise_to_peer(&mut self, peer_id: PeerId) {
        let Some(ctx) = self.resolve_advertise_ctx(peer_id).await else {
            return;
        };
        let (should, groups) = self.collect_outbound_routes(peer_id, &ctx).await;
        let prior = self.adj_rib_out.entry(peer_id).or_default().clone();
        Self::send_withdraws(&ctx, &prior, &should).await;
        Self::send_announces(&ctx, groups).await;
        self.adj_rib_out.insert(peer_id, should);
    }

    /// Phase 1: assemble the per-peer state needed to advertise.
    /// Returns `None` (and the caller silently skips) if the peer
    /// is gone, not Established, or has no resolvable local TCP
    /// address yet.
    async fn resolve_advertise_ctx(&self, peer_id: PeerId) -> Option<AdvertiseCtx> {
        let tx = self.peer_controls.get(&peer_id).cloned()?;
        let (is_ebgp, established) = {
            let snap = self.snapshot.lock().await;
            let p = snap.peers.iter().find(|p| p.id == peer_id)?;
            (p.is_ebgp, p.state == PeerState::Established)
        };
        if !established {
            return None;
        }
        let export_policy = self
            .peer_policies
            .get(&peer_id)
            .map(|pp| pp.export.clone())
            .unwrap_or_default();

        // Local TCP address feeds next-hop-self.
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        if tx.send(PeerControl::QueryLocalAddr(reply_tx)).await.is_err() {
            tracing::warn!(peer_id, "peer task gone, skipping advertise");
            return None;
        }
        let Ok(Some(local_addr)) = reply_rx.await else {
            tracing::warn!(peer_id, "peer has no local addr, skipping advertise");
            return None;
        };
        let (nh_v4, nh_v6) = match local_addr.ip() {
            IpAddr::V4(v4) => (Some(v4), None),
            IpAddr::V6(v6) => (None, Some(v6)),
        };

        Some(AdvertiseCtx {
            tx,
            is_ebgp,
            export_policy,
            local_asn: self.config.local_asn,
            nh_v4,
            nh_v6,
        })
    }

    /// Phase 2: rebuild Loc-RIB and produce the prefix set this
    /// peer should currently have, partitioned by source peer for
    /// per-group UPDATE batching.
    ///
    /// Filters in order: split-horizon (never echo a route back to
    /// its origin), export policy, summary-only suppression for
    /// active aggregates.
    async fn collect_outbound_routes(
        &self,
        peer_id: PeerId,
        ctx: &AdvertiseCtx,
    ) -> (AdvertisedPrefixes, OutboundGroups) {
        let snap = self.snapshot.lock().await;
        let loc = rebuild_loc_rib(&snap.peers, &self.local_pseudo_rib);
        drop(snap);

        let suppressed_v4: Vec<&Prefix4> = self
            .parsed_aggregates_v4
            .iter()
            .filter(|(_, so)| *so)
            .map(|(p, _)| p)
            .collect();
        let suppressed_v6: Vec<&Prefix6> = self
            .parsed_aggregates_v6
            .iter()
            .filter(|(_, so)| *so)
            .map(|(p, _)| p)
            .collect();

        let mut should = AdvertisedPrefixes::default();
        let mut groups = OutboundGroups::default();

        if ctx.nh_v4.is_some() {
            for (prefix, entry) in &loc.v4_unicast {
                if entry.winner.peer_id == peer_id {
                    continue;
                }
                if !ctx.export_policy.permits_v4(prefix) {
                    continue;
                }
                if suppressed_v4.iter().any(|agg| is_more_specific_v4(agg, prefix)) {
                    continue;
                }
                should.v4.insert(*prefix);
                groups
                    .v4
                    .entry(entry.winner.peer_id)
                    .or_default()
                    .push((*prefix, entry.winner.clone()));
            }
        }
        if ctx.nh_v6.is_some() {
            for (prefix, entry) in &loc.v6_unicast {
                if entry.winner.peer_id == peer_id {
                    continue;
                }
                if !ctx.export_policy.permits_v6(prefix) {
                    continue;
                }
                if suppressed_v6.iter().any(|agg| is_more_specific_v6(agg, prefix)) {
                    continue;
                }
                should.v6.insert(*prefix);
                groups
                    .v6
                    .entry(entry.winner.peer_id)
                    .or_default()
                    .push((*prefix, entry.winner.clone()));
            }
        }

        (should, groups)
    }

    /// Phase 3: emit withdraws for prefixes the peer used to have
    /// but no longer should. RFC 4271 §9.1.4 — withdraws precede
    /// announces.
    async fn send_withdraws(
        ctx: &AdvertiseCtx,
        prior: &AdvertisedPrefixes,
        should: &AdvertisedPrefixes,
    ) {
        if ctx.nh_v4.is_some() {
            let withdraw: Vec<Prefix4> = prior
                .v4
                .iter()
                .filter(|p| !should.v4.contains(p))
                .copied()
                .collect();
            if !withdraw.is_empty() {
                let _ = ctx
                    .tx
                    .send(PeerControl::SendUpdate(build_withdraw_v4(&withdraw)))
                    .await;
            }
        }
        if ctx.nh_v6.is_some() {
            let withdraw: Vec<Prefix6> = prior
                .v6
                .iter()
                .filter(|p| !should.v6.contains(p))
                .copied()
                .collect();
            if !withdraw.is_empty() {
                let _ = ctx
                    .tx
                    .send(PeerControl::SendUpdate(build_withdraw_v6(&withdraw)))
                    .await;
            }
        }
    }

    /// Phase 4: emit one UPDATE per source group. Routes sharing a
    /// source share path attributes, so RFC 4271 §5.1.2 lets us
    /// batch them under one set of rewritten outbound attributes.
    async fn send_announces(ctx: &AdvertiseCtx, groups: OutboundGroups) {
        if let Some(nh) = ctx.nh_v4 {
            for group in groups.v4.into_values() {
                let representative = &group[0].1;
                let prefixes: Vec<Prefix4> = group.iter().map(|(p, _)| *p).collect();
                let attrs = build_outbound_v4_attrs(
                    representative,
                    ctx.is_ebgp,
                    ctx.local_asn,
                    nh,
                );
                let update = Update {
                    withdrawn_v4: Vec::new(),
                    path_attributes: attrs,
                    nlri_v4: prefixes,
                };
                let _ = ctx.tx.send(PeerControl::SendUpdate(update)).await;
            }
        }
        if let Some(nh) = ctx.nh_v6 {
            for group in groups.v6.into_values() {
                let representative = &group[0].1;
                let prefixes: Vec<Prefix6> = group.iter().map(|(p, _)| *p).collect();
                let nlri_bytes = encode_v6_nlri(&prefixes);
                let attrs = build_outbound_v6_attrs(
                    representative,
                    ctx.is_ebgp,
                    ctx.local_asn,
                    nh,
                    nlri_bytes,
                );
                let update = Update {
                    withdrawn_v4: Vec::new(),
                    path_attributes: attrs,
                    nlri_v4: Vec::new(),
                };
                let _ = ctx.tx.send(PeerControl::SendUpdate(update)).await;
            }
        }
    }

    /// Fan out a Loc-RIB change to every Established peer.
    /// Called after Adj-RIB-In changes (peer-learned UPDATE) and
    /// after SIGHUP reload.
    async fn advertise_to_all_peers(&mut self) {
        let peer_ids: Vec<PeerId> = self.peer_controls.keys().copied().collect();
        for pid in peer_ids {
            self.advertise_to_peer(pid).await;
        }
    }

}

/// Build an outbound IPv4 UPDATE announcing every prefix in
/// `prefixes` as locally originated. The path-attribute shape
/// follows the peer-type rules from RFC 4271 §5.1:
///
/// - **iBGP** (peer_asn == local_asn): AS_PATH is *empty* (zero
///   segments — see §5.1.2); LOCAL_PREF=100 is included (§5.1.5
///   allows LOCAL_PREF on iBGP); NEXT_HOP is the local TCP
///   address (next-hop-self).
/// - **eBGP** (peer_asn != local_asn): AS_PATH carries a single
///   AS_SEQUENCE segment containing `local_asn` (§5.1.2
///   "prepend the local AS number"); LOCAL_PREF is *omitted*
///   (§5.1.5 "MUST NOT be sent to an external peer"); NEXT_HOP
///   is the local TCP address (next-hop-self, unconditional
///   for v1).
///
/// Used by `advertise_local_origin` on session-up and by the
/// SIGHUP reload-delta path. Pure function so it's easy to
/// unit-test in isolation.
/// Address-family input for [`build_announce`]. Each variant
/// carries the prefixes to announce and the next-hop to advertise.
enum AnnounceAfi<'a> {
    V4 { prefixes: &'a [Prefix4], next_hop: Ipv4Addr },
    V6 { prefixes: &'a [Prefix6], next_hop: Ipv6Addr },
}

/// Build an outbound UPDATE for a freshly-originated set of
/// prefixes (local-origin or aggregate). Common path: ORIGIN(IGP),
/// AS_PATH (eBGP prepends `local_asn`; iBGP empty), LOCAL_PREF=100
/// on iBGP only. AFI tail is either inline NEXT_HOP + nlri_v4 (v4)
/// or a trailing MP_REACH_NLRI (v6, RFC 4760 §3).
fn build_announce(afi: AnnounceAfi<'_>, is_ebgp: bool, local_asn: u32) -> Update {
    let as_path = if is_ebgp {
        vec![AsPathSegment {
            seg_type: AsPathSegmentType::AsSequence,
            asns: vec![local_asn],
        }]
    } else {
        Vec::new()
    };
    let mut path_attributes = vec![
        PathAttribute::Origin(Origin::Igp),
        PathAttribute::AsPath(as_path),
    ];

    let nlri_v4 = match afi {
        AnnounceAfi::V4 { prefixes, next_hop } => {
            path_attributes.push(PathAttribute::NextHop(next_hop));
            if !is_ebgp {
                path_attributes.push(PathAttribute::LocalPref(100));
            }
            prefixes.to_vec()
        }
        AnnounceAfi::V6 { prefixes, next_hop } => {
            if !is_ebgp {
                path_attributes.push(PathAttribute::LocalPref(100));
            }
            path_attributes.push(PathAttribute::MpReachNlri {
                afi: AFI_IPV6,
                safi: SAFI_UNICAST,
                nexthop: next_hop.octets().to_vec(),
                nlri: encode_v6_nlri(prefixes),
            });
            Vec::new()
        }
    };

    Update {
        withdrawn_v4: Vec::new(),
        path_attributes,
        nlri_v4,
    }
}

pub fn build_announce_v4(
    prefixes: &[Prefix4],
    next_hop: Ipv4Addr,
    is_ebgp: bool,
    local_asn: u32,
) -> Update {
    build_announce(AnnounceAfi::V4 { prefixes, next_hop }, is_ebgp, local_asn)
}

pub fn build_announce_v6(
    prefixes: &[Prefix6],
    next_hop: Ipv6Addr,
    is_ebgp: bool,
    local_asn: u32,
) -> Update {
    build_announce(AnnounceAfi::V6 { prefixes, next_hop }, is_ebgp, local_asn)
}

/// Build an outbound IPv4 withdraw UPDATE. The withdrawn-routes
/// field carries the prefixes; the path-attributes block is
/// empty (RFC 4271 §4.3 — withdraw-only UPDATEs have no
/// path attributes).
pub fn build_withdraw_v4(prefixes: &[Prefix4]) -> Update {
    Update {
        withdrawn_v4: prefixes.to_vec(),
        path_attributes: Vec::new(),
        nlri_v4: Vec::new(),
    }
}

/// Build an outbound IPv6 withdraw UPDATE via MP_UNREACH_NLRI.
/// RFC 4760 §4 says MP_UNREACH_NLRI is the only attribute that
/// must be present in a v6 withdraw UPDATE; the legacy
/// withdrawn-routes field stays empty.
pub fn build_withdraw_v6(prefixes: &[Prefix6]) -> Update {
    Update {
        withdrawn_v4: Vec::new(),
        path_attributes: vec![PathAttribute::MpUnreachNlri {
            afi: AFI_IPV6,
            safi: SAFI_UNICAST,
            withdrawn: encode_v6_nlri(prefixes),
        }],
        nlri_v4: Vec::new(),
    }
}

/// Apply one freshly-received UPDATE to the named peer's
/// Adj-RIB-In. Withdrawn prefixes are removed; new NLRI
/// prefixes are inserted with the message's path attributes.
/// Both the legacy v4 fields and MP_REACH/UNREACH v6 fields are
/// honored.
fn apply_update_to_peer(
    snap: &mut SpeakerSnapshot,
    peer_id: PeerId,
    update: Update,
    import_policy: &crate::policy::Policy,
) -> Result<()> {
    let local_asn = snap.local_asn;
    let peer = snap
        .peers
        .iter_mut()
        .find(|p| p.id == peer_id)
        .ok_or_else(|| anyhow!("peer {} not found in snapshot", peer_id))?;
    let is_ebgp = peer.is_ebgp;

    // v4 withdrawals first. Withdrawals are not subject to loop
    // detection or import policy — if the peer previously
    // accepted a route and now withdraws it, we must honor the
    // withdraw regardless of current policy state.
    for prefix in &update.withdrawn_v4 {
        peer.adj_rib_in.remove_v4(prefix);
    }

    // AS_PATH loop detection (RFC 4271 §9.1.2): on an eBGP
    // session, a route whose AS_PATH already contains the local
    // ASN is our own advertisement coming back. Drop it.
    let has_local_asn_in_as_path = is_ebgp
        && update.path_attributes.iter().any(|attr| {
            if let PathAttribute::AsPath(segs) = attr {
                segs.iter().any(|seg| seg.asns.contains(&local_asn))
            } else {
                false
            }
        });

    // v4 announcements: build a StoredRoute from the message's
    // path attributes and insert one entry per NLRI prefix,
    // subject to loop detection and the peer's import policy.
    if !update.nlri_v4.is_empty() && !has_local_asn_in_as_path {
        let stored = StoredRoute::new(
            update.path_attributes.clone(),
            peer_id,
            peer.asn,
            local_asn,
            peer.address,
            ipv4_or_unspec(peer.address),
        );
        for prefix in &update.nlri_v4 {
            if import_policy.permits_v4(prefix) {
                peer.adj_rib_in.insert_v4(*prefix, stored.clone());
            }
        }
    } else if has_local_asn_in_as_path && !update.nlri_v4.is_empty() {
        tracing::debug!(
            peer_id,
            count = update.nlri_v4.len(),
            "dropping v4 NLRI: AS_PATH contains local ASN (loop)"
        );
    }

    // v6 via MP_REACH / MP_UNREACH inside path_attributes.
    let mut v6_announce: Vec<crate::packet::update::Prefix6> = Vec::new();
    let mut v6_withdraw: Vec<crate::packet::update::Prefix6> = Vec::new();
    for attr in &update.path_attributes {
        if let PathAttribute::MpReachNlri { afi, nlri, .. } = attr {
            if *afi == crate::packet::caps::AFI_IPV6 {
                v6_announce.extend(parse_v6_prefixes(nlri));
            }
        }
        if let PathAttribute::MpUnreachNlri { afi, withdrawn, .. } = attr {
            if *afi == crate::packet::caps::AFI_IPV6 {
                v6_withdraw.extend(parse_v6_prefixes(withdrawn));
            }
        }
    }
    for prefix in &v6_withdraw {
        peer.adj_rib_in.remove_v6(prefix);
    }
    if !v6_announce.is_empty() && !has_local_asn_in_as_path {
        let stored = StoredRoute::new(
            update.path_attributes.clone(),
            peer_id,
            peer.asn,
            local_asn,
            peer.address,
            ipv4_or_unspec(peer.address),
        );
        for prefix in &v6_announce {
            if import_policy.permits_v6(prefix) {
                peer.adj_rib_in.insert_v6(*prefix, stored.clone());
            }
        }
    } else if has_local_asn_in_as_path && !v6_announce.is_empty() {
        tracing::debug!(
            peer_id,
            count = v6_announce.len(),
            "dropping v6 NLRI: AS_PATH contains local ASN (loop)"
        );
    }

    Ok(())
}

/// Best-effort: if the peer address is an IPv4, use it as the
/// router-id placeholder for the StoredRoute; otherwise use the
/// unspecified address. The instance doesn't yet know the peer's
/// real BGP router-id (that lives in their OPEN, which we should
/// thread through). v1 falls back to the peer's transport address
/// for sorting purposes — best-path's router-id tiebreak is rule
/// 9, so it almost never fires in practice.
fn ipv4_or_unspec(ip: IpAddr) -> std::net::Ipv4Addr {
    match ip {
        IpAddr::V4(v4) => v4,
        IpAddr::V6(_) => std::net::Ipv4Addr::UNSPECIFIED,
    }
}

fn parse_v6_prefixes(buf: &[u8]) -> Vec<crate::packet::update::Prefix6> {
    let mut out = Vec::new();
    let mut p = 0;
    while p < buf.len() {
        let len = buf[p];
        if len > 128 {
            break;
        }
        let bytes = (len as usize + 7) / 8;
        if buf.len() - p - 1 < bytes {
            break;
        }
        let mut octets = [0u8; 16];
        octets[..bytes].copy_from_slice(&buf[p + 1..p + 1 + bytes]);
        out.push(crate::packet::update::Prefix6 {
            addr: std::net::Ipv6Addr::from(octets),
            len,
        });
        p += 1 + bytes;
    }
    out
}

/// Rebuild Loc-RIB from real peer Adj-RIB-Ins plus the
/// synthetic local pseudo-peer's Adj-RIB-In (T2 addition).
/// Local-origin entries compete with peer-learned routes via
/// the standard best-path tiebreakers; for prefixes nobody else
/// advertises, the local origin wins by default.
fn rebuild_loc_rib(peers: &[PeerSnapshot], local: &AdjRibIn) -> LocRib {
    let mut inputs: Vec<(PeerId, &AdjRibIn)> = Vec::with_capacity(peers.len() + 1);
    for p in peers {
        inputs.push((p.id, &p.adj_rib_in));
    }
    inputs.push((LOCAL_PEER_ID, local));
    LocRib::rebuild(&inputs)
}

/// Address-family tail for [`build_outbound_attrs`]. v4 carries
/// NEXT_HOP inline as an attribute; v6 routes ride inside
/// MP_REACH_NLRI (RFC 4760 §3) which bundles next-hop + NLRI bytes.
enum OutboundAfi {
    V4 { next_hop: Ipv4Addr },
    V6 { next_hop: Ipv6Addr, nlri_bytes: Vec<u8> },
}

/// Rewrite a Loc-RIB winner's path attributes for outbound
/// advertisement to a specific peer. Implements RFC 4271 §5.1
/// rules per peer type:
///
/// - **ORIGIN**: preserved from the winner.
/// - **AS_PATH**:
///   - eBGP: prepend `local_asn` to the leading AS_SEQUENCE
///     segment, or create a new `[local_asn]` segment if the
///     winner's AS_PATH was empty (local-origin) or started
///     with an AS_SET.
///   - iBGP: preserved unchanged.
/// - **NEXT_HOP** (v4): always rewritten to the AFI's
///   `next_hop` (unconditional next-hop-self in v1). v6 routes
///   carry the next-hop inside the trailing MP_REACH_NLRI.
/// - **LOCAL_PREF**: iBGP preserves winner's value or defaults
///   to 100; eBGP omits entirely (§5.1.5).
/// - **MED**: iBGP preserves; eBGP strips by default (operator
///   policy can override in v2).
/// - **Communities**: preserved verbatim in v1.
fn build_outbound_attrs(
    winner: &StoredRoute,
    is_ebgp: bool,
    local_asn: u32,
    afi: OutboundAfi,
) -> Vec<PathAttribute> {
    let mut out: Vec<PathAttribute> = Vec::new();

    let origin = winner
        .find_origin()
        .unwrap_or(crate::packet::attrs::Origin::Incomplete);
    out.push(PathAttribute::Origin(origin));

    let winner_as_path: Vec<AsPathSegment> = winner
        .path_attributes
        .iter()
        .find_map(|a| match a {
            PathAttribute::AsPath(segs) => Some(segs.clone()),
            _ => None,
        })
        .unwrap_or_default();
    let rewritten = if is_ebgp {
        prepend_local_asn(&winner_as_path, local_asn)
    } else {
        winner_as_path
    };
    out.push(PathAttribute::AsPath(rewritten));

    // v4 carries NEXT_HOP inline before LOCAL_PREF; v6 carries it
    // inside the trailing MP_REACH_NLRI.
    let mp_reach = match afi {
        OutboundAfi::V4 { next_hop } => {
            out.push(PathAttribute::NextHop(next_hop));
            None
        }
        OutboundAfi::V6 { next_hop, nlri_bytes } => Some((next_hop, nlri_bytes)),
    };

    // iBGP-only: LOCAL_PREF (default 100) and MED (preserve if present).
    // RFC 4271 §5.1.5 — LOCAL_PREF MUST NOT be sent to eBGP peers.
    if !is_ebgp {
        out.push(PathAttribute::LocalPref(winner.local_pref().unwrap_or(100)));
        if let Some(med) = winner.med() {
            out.push(PathAttribute::MultiExitDisc(med));
        }
    }

    for attr in &winner.path_attributes {
        if let PathAttribute::Communities(c) = attr {
            out.push(PathAttribute::Communities(c.clone()));
        }
    }

    if let Some((next_hop, nlri_bytes)) = mp_reach {
        out.push(PathAttribute::MpReachNlri {
            afi: AFI_IPV6,
            safi: SAFI_UNICAST,
            nexthop: next_hop.octets().to_vec(),
            nlri: nlri_bytes,
        });
    }

    out
}

fn build_outbound_v4_attrs(
    winner: &StoredRoute,
    is_ebgp: bool,
    local_asn: u32,
    local_next_hop: Ipv4Addr,
) -> Vec<PathAttribute> {
    build_outbound_attrs(
        winner,
        is_ebgp,
        local_asn,
        OutboundAfi::V4 { next_hop: local_next_hop },
    )
}

fn build_outbound_v6_attrs(
    winner: &StoredRoute,
    is_ebgp: bool,
    local_asn: u32,
    local_next_hop: Ipv6Addr,
    nlri_bytes: Vec<u8>,
) -> Vec<PathAttribute> {
    build_outbound_attrs(
        winner,
        is_ebgp,
        local_asn,
        OutboundAfi::V6 { next_hop: local_next_hop, nlri_bytes },
    )
}

/// Prepend `local_asn` to a winner's AS_PATH. If the leading
/// segment is an AS_SEQUENCE, insert at position 0 of that
/// segment; otherwise (empty path, or leading AS_SET) emit a
/// new AS_SEQUENCE segment.
fn prepend_local_asn(path: &[AsPathSegment], local_asn: u32) -> Vec<AsPathSegment> {
    if let Some(first) = path.first() {
        if first.seg_type == AsPathSegmentType::AsSequence {
            let mut new_first = first.clone();
            new_first.asns.insert(0, local_asn);
            let mut out = Vec::with_capacity(path.len());
            out.push(new_first);
            out.extend_from_slice(&path[1..]);
            return out;
        }
    }
    let mut out = Vec::with_capacity(path.len() + 1);
    out.push(AsPathSegment {
        seg_type: AsPathSegmentType::AsSequence,
        asns: vec![local_asn],
    });
    out.extend_from_slice(path);
    out
}

/// Serialize v6 NLRI prefixes into the on-the-wire byte form
/// (length + prefix octets) used inside MP_REACH_NLRI /
/// MP_UNREACH_NLRI.
fn encode_v6_nlri(prefixes: &[Prefix6]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in prefixes {
        out.push(p.len);
        let nbytes = (p.len as usize + 7) / 8;
        out.extend_from_slice(&p.addr.octets()[..nbytes]);
    }
    out
}

/// Synthetic v4 aggregate route injected into the local pseudo-RIB
/// when at least one configured `aggregate-address` has a covered
/// contributor. NEXT_HOP is the unspecified address — the
/// outbound rewrite (`build_outbound_attrs`) replaces it with the
/// peer-local NEXT_HOP_SELF.
fn make_v4_aggregate_route(local_asn: u32, router_id: Ipv4Addr) -> StoredRoute {
    StoredRoute::local_origin(
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(Vec::new()),
            PathAttribute::NextHop(Ipv4Addr::UNSPECIFIED),
            PathAttribute::LocalPref(100),
            PathAttribute::AtomicAggregate,
        ],
        local_asn,
        router_id,
        OriginClass::Aggregate,
    )
}

/// Synthetic v6 aggregate route. Same role as the v4 helper but
/// rides in MP_REACH_NLRI (RFC 4760); the placeholder zeros for
/// nexthop / nlri are overwritten on advertise.
fn make_v6_aggregate_route(local_asn: u32, router_id: Ipv4Addr) -> StoredRoute {
    StoredRoute::local_origin(
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(Vec::new()),
            PathAttribute::LocalPref(100),
            PathAttribute::AtomicAggregate,
            PathAttribute::MpReachNlri {
                afi: AFI_IPV6,
                safi: SAFI_UNICAST,
                nexthop: vec![0u8; 16],
                nlri: Vec::new(),
            },
        ],
        local_asn,
        router_id,
        OriginClass::Aggregate,
    )
}

/// Per-peer cache of what's currently advertised in each peer's
/// Adj-RIB-Out. The instance walks Loc-RIB on every change, diffs
/// against this cache, and emits only the delta. Cleared on
/// session-down.
#[derive(Debug, Default, Clone)]
struct AdvertisedPrefixes {
    v4: std::collections::HashSet<Prefix4>,
    v6: std::collections::HashSet<Prefix6>,
}

/// Per-peer state assembled once per `advertise_to_peer` call and
/// threaded through the four phase methods. Owning the `tx` clone
/// here keeps the phase signatures free of `&self`.
struct AdvertiseCtx {
    tx: mpsc::Sender<PeerControl>,
    is_ebgp: bool,
    export_policy: crate::policy::Policy,
    local_asn: u32,
    nh_v4: Option<Ipv4Addr>,
    nh_v6: Option<Ipv6Addr>,
}

/// Loc-RIB winners filtered for outbound and bucketed by source
/// peer. Each bucket becomes one UPDATE — its members share path
/// attributes by construction (same source → same StoredRoute).
#[derive(Default)]
struct OutboundGroups {
    v4: HashMap<PeerId, Vec<(Prefix4, StoredRoute)>>,
    v6: HashMap<PeerId, Vec<(Prefix6, StoredRoute)>>,
}

/// Parse aggregate-address configs into typed prefixes. Unparseable
/// entries are logged and skipped.
fn parse_aggregates_v4(
    configs: &[crate::config::AggregateConfig],
) -> Vec<(Prefix4, bool)> {
    let mut out = Vec::new();
    for c in configs {
        if let Ok(net) = c.prefix.parse::<ipnet::Ipv4Net>() {
            out.push((
                Prefix4 {
                    addr: net.network(),
                    len: net.prefix_len(),
                },
                c.summary_only,
            ));
        } else {
            tracing::warn!(prefix = %c.prefix, "ignoring unparseable v4 aggregate");
        }
    }
    out
}

fn parse_aggregates_v6(
    configs: &[crate::config::AggregateConfig],
) -> Vec<(Prefix6, bool)> {
    let mut out = Vec::new();
    for c in configs {
        if let Ok(net) = c.prefix.parse::<ipnet::Ipv6Net>() {
            out.push((
                Prefix6 {
                    addr: net.network(),
                    len: net.prefix_len(),
                },
                c.summary_only,
            ));
        } else {
            tracing::warn!(prefix = %c.prefix, "ignoring unparseable v6 aggregate");
        }
    }
    out
}

/// True if `specific` is a more-specific of `aggregate` (strictly
/// longer prefix that falls within the aggregate's range).
fn is_more_specific_v4(aggregate: &Prefix4, specific: &Prefix4) -> bool {
    if specific.len <= aggregate.len {
        return false;
    }
    let mask = if aggregate.len == 0 {
        0u32
    } else {
        u32::MAX << (32 - aggregate.len)
    };
    (u32::from(specific.addr) & mask) == (u32::from(aggregate.addr) & mask)
}

fn is_more_specific_v6(aggregate: &Prefix6, specific: &Prefix6) -> bool {
    if specific.len <= aggregate.len {
        return false;
    }
    let agg_bits = u128::from(aggregate.addr);
    let spec_bits = u128::from(specific.addr);
    let mask = if aggregate.len == 0 {
        0u128
    } else {
        u128::MAX << (128 - aggregate.len)
    };
    (spec_bits & mask) == (agg_bits & mask)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::attrs::{
        AsPathSegment, AsPathSegmentType, Origin, PathAttribute,
    };
    use crate::packet::update::{Prefix4, Update};
    use std::net::Ipv4Addr;

    fn snapshot_with_peer() -> SpeakerSnapshot {
        let mut snap = SpeakerSnapshot::default();
        snap.local_asn = 65000;
        snap.router_id = Ipv4Addr::new(10, 0, 0, 1);
        snap.peers.push(PeerSnapshot {
            id: 1,
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            asn: 65001,
            state: PeerState::Established,
            negotiated_hold_time: 90,
            is_ebgp: true,
            adj_rib_in: AdjRibIn::new(),
        });
        snap
    }

    fn p4(a: u8, b: u8, c: u8, d: u8, len: u8) -> Prefix4 {
        Prefix4 {
            addr: Ipv4Addr::new(a, b, c, d),
            len,
        }
    }

    #[test]
    fn apply_update_inserts_v4_nlri() {
        let mut snap = snapshot_with_peer();
        let update = Update {
            withdrawn_v4: Vec::new(),
            path_attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(vec![AsPathSegment {
                    seg_type: AsPathSegmentType::AsSequence,
                    asns: vec![65001],
                }]),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            nlri_v4: vec![p4(192, 0, 2, 0, 24), p4(198, 51, 100, 0, 24)],
        };
        apply_update_to_peer(&mut snap, 1, update, &crate::policy::Policy::AcceptAll).unwrap();
        assert_eq!(snap.peers[0].adj_rib_in.v4_unicast.len(), 2);
    }

    #[test]
    fn apply_update_removes_withdrawn_v4() {
        let mut snap = snapshot_with_peer();
        // Pre-populate one prefix.
        let stored = StoredRoute::new(
            Vec::new(),
            1,
            65001,
            65000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            Ipv4Addr::new(10, 0, 0, 2),
        );
        snap.peers[0]
            .adj_rib_in
            .insert_v4(p4(192, 0, 2, 0, 24), stored);
        // Withdraw it.
        let update = Update {
            withdrawn_v4: vec![p4(192, 0, 2, 0, 24)],
            path_attributes: Vec::new(),
            nlri_v4: Vec::new(),
        };
        apply_update_to_peer(&mut snap, 1, update, &crate::policy::Policy::AcceptAll).unwrap();
        assert!(snap.peers[0].adj_rib_in.v4_unicast.is_empty());
    }

    #[test]
    fn is_more_specific_v4_basic() {
        let agg = Prefix4 {
            addr: Ipv4Addr::new(10, 0, 0, 0),
            len: 8,
        };
        // 10.1.0.0/16 is a more-specific of 10.0.0.0/8
        assert!(is_more_specific_v4(
            &agg,
            &Prefix4 {
                addr: Ipv4Addr::new(10, 1, 0, 0),
                len: 16
            }
        ));
        // 10.0.0.0/8 is NOT more-specific of itself (equal len)
        assert!(!is_more_specific_v4(&agg, &agg));
        // 192.168.0.0/16 is not covered by 10.0.0.0/8
        assert!(!is_more_specific_v4(
            &agg,
            &Prefix4 {
                addr: Ipv4Addr::new(192, 168, 0, 0),
                len: 16
            }
        ));
        // 0.0.0.0/0 covers everything (len=0)
        let default = Prefix4 {
            addr: Ipv4Addr::new(0, 0, 0, 0),
            len: 0,
        };
        assert!(is_more_specific_v4(
            &default,
            &Prefix4 {
                addr: Ipv4Addr::new(192, 0, 2, 0),
                len: 24
            }
        ));
    }

    #[test]
    fn aggregate_parse_and_config_round_trip() {
        let configs = vec![
            crate::config::AggregateConfig {
                prefix: "10.0.0.0/8".into(),
                summary_only: true,
            },
            crate::config::AggregateConfig {
                prefix: "bad-prefix".into(),
                summary_only: false,
            },
        ];
        let parsed = parse_aggregates_v4(&configs);
        assert_eq!(parsed.len(), 1, "bad prefix should be skipped");
        assert_eq!(parsed[0].0.addr, Ipv4Addr::new(10, 0, 0, 0));
        assert_eq!(parsed[0].0.len, 8);
        assert!(parsed[0].1);
    }

    #[test]
    fn prepend_local_asn_into_leading_sequence() {
        let path = vec![AsPathSegment {
            seg_type: AsPathSegmentType::AsSequence,
            asns: vec![65001, 65002],
        }];
        let out = prepend_local_asn(&path, 65100);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].seg_type, AsPathSegmentType::AsSequence);
        assert_eq!(out[0].asns, vec![65100, 65001, 65002]);
    }

    #[test]
    fn prepend_local_asn_into_empty_path_creates_new_sequence() {
        let out = prepend_local_asn(&[], 65100);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].seg_type, AsPathSegmentType::AsSequence);
        assert_eq!(out[0].asns, vec![65100]);
    }

    #[test]
    fn prepend_local_asn_before_leading_set_adds_new_segment() {
        let path = vec![AsPathSegment {
            seg_type: AsPathSegmentType::AsSet,
            asns: vec![65050, 65051],
        }];
        let out = prepend_local_asn(&path, 65100);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].seg_type, AsPathSegmentType::AsSequence);
        assert_eq!(out[0].asns, vec![65100]);
        assert_eq!(out[1].seg_type, AsPathSegmentType::AsSet);
    }

    #[test]
    fn outbound_v4_attrs_ebgp_rewrite_prepends_strips_nh_self() {
        // Peer-learned route with LOCAL_PREF, MED, communities,
        // upstream AS_PATH.
        let winner = StoredRoute::new(
            vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(vec![AsPathSegment {
                    seg_type: AsPathSegmentType::AsSequence,
                    asns: vec![65001],
                }]),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                PathAttribute::LocalPref(200),
                PathAttribute::MultiExitDisc(50),
                PathAttribute::Communities(vec![0xFFFFFF01]),
            ],
            1,
            65001,
            65100,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            Ipv4Addr::new(10, 0, 0, 2),
        );
        let attrs = build_outbound_v4_attrs(
            &winner,
            true, // eBGP outbound
            65100,
            Ipv4Addr::new(192, 0, 2, 254),
        );

        // AS_PATH prepended: [65100, 65001]
        let segs = attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::AsPath(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(segs[0].asns, vec![65100, 65001]);

        // NEXT_HOP is local addr, not the peer's nexthop.
        let nh = attrs.iter().find_map(|a| match a {
            PathAttribute::NextHop(n) => Some(*n),
            _ => None,
        });
        assert_eq!(nh, Some(Ipv4Addr::new(192, 0, 2, 254)));

        // LOCAL_PREF and MED stripped on eBGP.
        assert!(!attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::LocalPref(_))));
        assert!(!attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::MultiExitDisc(_))));

        // Communities preserved.
        assert!(attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::Communities(c) if c == &vec![0xFFFFFF01])));
    }

    #[test]
    fn outbound_v4_attrs_ibgp_preserves_as_path_and_local_pref() {
        let winner = StoredRoute::new(
            vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(vec![AsPathSegment {
                    seg_type: AsPathSegmentType::AsSequence,
                    asns: vec![65001],
                }]),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
                PathAttribute::LocalPref(200),
            ],
            1,
            65001,
            65100,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            Ipv4Addr::new(10, 0, 0, 2),
        );
        let attrs = build_outbound_v4_attrs(
            &winner,
            false, // iBGP outbound
            65100,
            Ipv4Addr::new(192, 0, 2, 254),
        );

        // AS_PATH preserved (no prepend).
        let segs = attrs
            .iter()
            .find_map(|a| match a {
                PathAttribute::AsPath(s) => Some(s.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(segs[0].asns, vec![65001]);

        // LOCAL_PREF preserved.
        assert!(attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::LocalPref(200))));

        // NEXT_HOP still rewritten to local (unconditional
        // next-hop-self in v1).
        assert!(attrs
            .iter()
            .any(|a| matches!(a, PathAttribute::NextHop(n) if *n == Ipv4Addr::new(192, 0, 2, 254))));
    }

    #[test]
    fn apply_update_drops_v4_when_as_path_has_local_asn_on_ebgp() {
        // RFC 4271 §9.1.2 AS_PATH loop detection: an eBGP
        // peer (is_ebgp=true) that sends us a route whose
        // AS_PATH already contains our local ASN is our own
        // advertisement coming back. Drop it.
        let mut snap = snapshot_with_peer(); // peer is eBGP
        let update = Update {
            withdrawn_v4: Vec::new(),
            path_attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(vec![AsPathSegment {
                    seg_type: AsPathSegmentType::AsSequence,
                    // local_asn (65000) is in the path — loop.
                    asns: vec![65001, 65000, 65002],
                }]),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            nlri_v4: vec![p4(192, 0, 2, 0, 24)],
        };
        apply_update_to_peer(&mut snap, 1, update, &crate::policy::Policy::AcceptAll).unwrap();
        assert!(
            snap.peers[0].adj_rib_in.v4_unicast.is_empty(),
            "eBGP loop must be dropped"
        );
    }

    #[test]
    fn apply_update_does_not_loop_detect_on_ibgp() {
        // iBGP sessions preserve the AS_PATH unchanged from the
        // origin, so "local ASN appears" is expected and must
        // not trigger loop detection. Only eBGP applies the
        // §9.1.2 rule.
        let mut snap = snapshot_with_peer();
        snap.peers[0].is_ebgp = false;
        snap.peers[0].asn = 65000;
        let update = Update {
            withdrawn_v4: Vec::new(),
            path_attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(vec![AsPathSegment {
                    seg_type: AsPathSegmentType::AsSequence,
                    asns: vec![65000],
                }]),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            nlri_v4: vec![p4(192, 0, 2, 0, 24)],
        };
        apply_update_to_peer(&mut snap, 1, update, &crate::policy::Policy::AcceptAll).unwrap();
        assert_eq!(snap.peers[0].adj_rib_in.v4_unicast.len(), 1);
    }

    #[test]
    fn apply_update_drops_routes_rejected_by_import_policy() {
        // RFC 8212 default-deny: with Policy::DenyAll an eBGP
        // peer's inbound UPDATE is discarded even when the
        // AS_PATH is clean.
        let mut snap = snapshot_with_peer();
        let update = Update {
            withdrawn_v4: Vec::new(),
            path_attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(vec![AsPathSegment {
                    seg_type: AsPathSegmentType::AsSequence,
                    asns: vec![65001],
                }]),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 2)),
            ],
            nlri_v4: vec![p4(192, 0, 2, 0, 24)],
        };
        apply_update_to_peer(&mut snap, 1, update, &crate::policy::Policy::DenyAll).unwrap();
        assert!(snap.peers[0].adj_rib_in.v4_unicast.is_empty());
    }

    #[test]
    fn apply_update_withdraw_ignores_policy() {
        // Withdrawals are never filtered by policy — a policy
        // change must not strand a previously-installed route.
        let mut snap = snapshot_with_peer();
        let stored = StoredRoute::new(
            Vec::new(),
            1,
            65001,
            65000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            Ipv4Addr::new(10, 0, 0, 2),
        );
        snap.peers[0]
            .adj_rib_in
            .insert_v4(p4(192, 0, 2, 0, 24), stored);
        let update = Update {
            withdrawn_v4: vec![p4(192, 0, 2, 0, 24)],
            path_attributes: Vec::new(),
            nlri_v4: Vec::new(),
        };
        apply_update_to_peer(&mut snap, 1, update, &crate::policy::Policy::DenyAll).unwrap();
        assert!(snap.peers[0].adj_rib_in.v4_unicast.is_empty());
    }

    #[test]
    fn build_announce_v4_shape() {
        let prefixes = vec![
            Prefix4 {
                addr: Ipv4Addr::new(23, 177, 24, 96),
                len: 29,
            },
            Prefix4 {
                addr: Ipv4Addr::new(192, 168, 20, 0),
                len: 24,
            },
        ];
        let nh = Ipv4Addr::new(23, 177, 24, 9);
        let update = build_announce_v4(&prefixes, nh, false, 65100);
        // Round-trip via encode/parse to verify the wire bytes.
        let bytes = update.encode();
        let parsed = Update::parse_body(&bytes[crate::packet::header::HEADER_LEN..]).unwrap();
        assert_eq!(parsed.nlri_v4.len(), 2);
        assert_eq!(parsed.nlri_v4[0].len, 29);
        assert_eq!(parsed.nlri_v4[1].len, 24);
        // ORIGIN, AS_PATH (empty seq), NEXT_HOP, LOCAL_PREF.
        let has_origin = parsed
            .path_attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::Origin(Origin::Igp)));
        let has_next_hop = parsed
            .path_attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::NextHop(addr) if *addr == nh));
        let has_local_pref = parsed
            .path_attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::LocalPref(100)));
        assert!(has_origin && has_next_hop && has_local_pref);
        // RFC 4271 §5.1.2: locally-originated iBGP routes carry
        // an AS_PATH attribute with **zero segments**, not one
        // segment with zero ASNs. VyOS (and FRR) reject the
        // latter as malformed.
        let as_path = parsed.path_attributes.iter().find_map(|a| match a {
            PathAttribute::AsPath(segs) => Some(segs),
            _ => None,
        });
        let segs = as_path.unwrap();
        assert!(
            segs.is_empty(),
            "iBGP-originated AS_PATH must have zero segments, got {:?}",
            segs
        );
    }

    #[test]
    fn build_announce_v4_ebgp_prepends_local_asn_and_omits_local_pref() {
        // RFC 4271 §5.1.2 + §5.1.5: eBGP-originated routes prepend
        // the local ASN and MUST NOT include LOCAL_PREF.
        let prefixes = vec![Prefix4 {
            addr: Ipv4Addr::new(192, 0, 2, 0),
            len: 24,
        }];
        let nh = Ipv4Addr::new(10, 0, 0, 1);
        let update = build_announce_v4(&prefixes, nh, true, 65100);
        let bytes = update.encode();
        let parsed = Update::parse_body(&bytes[crate::packet::header::HEADER_LEN..]).unwrap();

        // AS_PATH carries [AS_SEQUENCE { 65100 }]
        let as_path = parsed.path_attributes.iter().find_map(|a| match a {
            PathAttribute::AsPath(segs) => Some(segs),
            _ => None,
        });
        let segs = as_path.expect("eBGP UPDATE must carry AS_PATH");
        assert_eq!(segs.len(), 1, "expect one AS_SEQUENCE segment");
        assert!(matches!(
            segs[0].seg_type,
            crate::packet::attrs::AsPathSegmentType::AsSequence
        ));
        assert_eq!(segs[0].asns, vec![65100]);

        // LOCAL_PREF MUST NOT be present on eBGP UPDATEs.
        let has_local_pref = parsed
            .path_attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::LocalPref(_)));
        assert!(
            !has_local_pref,
            "eBGP UPDATE must omit LOCAL_PREF (RFC 4271 §5.1.5)"
        );

        // NEXT_HOP is the local address (next-hop-self).
        let has_next_hop = parsed
            .path_attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::NextHop(addr) if *addr == nh));
        assert!(has_next_hop);
    }

    #[test]
    fn build_announce_v6_ebgp_prepends_local_asn_and_omits_local_pref() {
        let prefixes = vec![Prefix6 {
            addr: "2001:db8::".parse().unwrap(),
            len: 32,
        }];
        let nh: std::net::Ipv6Addr = "2001:db8:ffff::1".parse().unwrap();
        let update = build_announce_v6(&prefixes, nh, true, 65100);
        let bytes = update.encode();
        let parsed = Update::parse_body(&bytes[crate::packet::header::HEADER_LEN..]).unwrap();

        let as_path = parsed.path_attributes.iter().find_map(|a| match a {
            PathAttribute::AsPath(segs) => Some(segs),
            _ => None,
        });
        let segs = as_path.expect("eBGP UPDATE must carry AS_PATH");
        assert_eq!(segs.len(), 1);
        assert_eq!(segs[0].asns, vec![65100]);

        let has_local_pref = parsed
            .path_attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::LocalPref(_)));
        assert!(!has_local_pref);

        // v6 routes ride in MP_REACH_NLRI; next-hop is there.
        let v6 = parsed.ipv6_nlri().unwrap();
        assert_eq!(v6.len(), 1);
    }

    #[test]
    fn build_announce_v4_ibgp_empty_as_path_and_has_local_pref() {
        let prefixes = vec![Prefix4 {
            addr: Ipv4Addr::new(192, 0, 2, 0),
            len: 24,
        }];
        let nh = Ipv4Addr::new(10, 0, 0, 1);
        let update = build_announce_v4(&prefixes, nh, false, 65100);
        let bytes = update.encode();
        let parsed = Update::parse_body(&bytes[crate::packet::header::HEADER_LEN..]).unwrap();
        let segs = parsed
            .path_attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::AsPath(segs) => Some(segs),
                _ => None,
            })
            .unwrap();
        assert!(segs.is_empty(), "iBGP AS_PATH must have zero segments");
        assert!(parsed
            .path_attributes
            .iter()
            .any(|a| matches!(a, PathAttribute::LocalPref(100))));
    }

    #[test]
    fn build_withdraw_v4_shape() {
        let prefixes = vec![Prefix4 {
            addr: Ipv4Addr::new(192, 0, 2, 0),
            len: 24,
        }];
        let update = build_withdraw_v4(&prefixes);
        let bytes = update.encode();
        let parsed = Update::parse_body(&bytes[crate::packet::header::HEADER_LEN..]).unwrap();
        // Withdraw-only UPDATE: withdrawn_v4 populated, no path
        // attributes, no nlri. RFC 4271 §4.3.
        assert_eq!(parsed.withdrawn_v4.len(), 1);
        assert_eq!(parsed.path_attributes.len(), 0);
        assert_eq!(parsed.nlri_v4.len(), 0);
    }

    #[test]
    fn build_withdraw_v6_shape() {
        let prefixes = vec![Prefix6 {
            addr: "2602:f90e:10::".parse().unwrap(),
            len: 64,
        }];
        let update = build_withdraw_v6(&prefixes);
        let bytes = update.encode();
        let parsed = Update::parse_body(&bytes[crate::packet::header::HEADER_LEN..]).unwrap();
        // v6 withdraw rides inside MP_UNREACH_NLRI; legacy
        // withdrawn-routes field stays empty.
        assert_eq!(parsed.withdrawn_v4.len(), 0);
        let v6 = parsed.ipv6_withdrawn().unwrap();
        assert_eq!(v6.len(), 1);
        assert_eq!(v6[0].len, 64);
    }

    #[test]
    fn local_origin_diff_computation() {
        // Pin the diff semantics that reload_config relies on:
        // (added) = new − old, (removed) = old − new. The actual
        // diff is inline in reload_config rather than a helper,
        // so this test mirrors that filter.
        let p_a = Prefix4 {
            addr: Ipv4Addr::new(10, 0, 0, 0),
            len: 8,
        };
        let p_b = Prefix4 {
            addr: Ipv4Addr::new(192, 0, 2, 0),
            len: 24,
        };
        let p_c = Prefix4 {
            addr: Ipv4Addr::new(198, 51, 100, 0),
            len: 24,
        };

        let old_set = vec![p_a, p_b];
        let new_set = vec![p_b, p_c];

        let added: Vec<Prefix4> = new_set.iter().filter(|p| !old_set.contains(p)).copied().collect();
        let removed: Vec<Prefix4> = old_set.iter().filter(|p| !new_set.contains(p)).copied().collect();

        assert_eq!(added, vec![p_c]);
        assert_eq!(removed, vec![p_a]);
    }

    #[test]
    fn build_announce_v6_shape() {
        let prefixes = vec![Prefix6 {
            addr: "2602:f90e:10::".parse().unwrap(),
            len: 64,
        }];
        let nh: std::net::Ipv6Addr = "2602:f90e::101".parse().unwrap();
        let update = build_announce_v6(&prefixes, nh, false, 65100);
        let bytes = update.encode();
        let parsed = Update::parse_body(&bytes[crate::packet::header::HEADER_LEN..]).unwrap();
        // v6 routes ride inside MP_REACH_NLRI, not the legacy field.
        assert!(parsed.nlri_v4.is_empty());
        let v6 = parsed.ipv6_nlri().unwrap();
        assert_eq!(v6.len(), 1);
        assert_eq!(v6[0].len, 64);
        // MP_REACH next-hop is the local v6 address.
        let nh_bytes = parsed.path_attributes.iter().find_map(|a| match a {
            PathAttribute::MpReachNlri { nexthop, .. } => Some(nexthop.clone()),
            _ => None,
        });
        assert_eq!(nh_bytes.unwrap(), nh.octets().to_vec());
    }

    #[test]
    fn rebuild_loc_rib_picks_per_prefix_winner() {
        let mut snap = SpeakerSnapshot::default();
        snap.local_asn = 65000;
        // Two peers, same prefix, peer 2 wins on shorter AS_PATH.
        for (id, asn, asns) in [
            (1u32, 65001u32, vec![65001, 65002, 65003]),
            (2u32, 65002u32, vec![65002]),
        ] {
            let mut p = PeerSnapshot {
                id,
                address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, id as u8)),
                asn,
                state: PeerState::Established,
                negotiated_hold_time: 90,
                is_ebgp: true,
                adj_rib_in: AdjRibIn::new(),
            };
            let stored = StoredRoute::new(
                vec![
                    PathAttribute::Origin(Origin::Igp),
                    PathAttribute::AsPath(vec![AsPathSegment {
                        seg_type: AsPathSegmentType::AsSequence,
                        asns,
                    }]),
                    PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, id as u8)),
                ],
                id,
                asn,
                65000,
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, id as u8)),
                Ipv4Addr::new(10, 0, 0, id as u8),
            );
            p.adj_rib_in.insert_v4(p4(192, 0, 2, 0, 24), stored);
            snap.peers.push(p);
        }
        let empty_local = AdjRibIn::new();
        let loc = rebuild_loc_rib(&snap.peers, &empty_local);
        assert_eq!(loc.v4_unicast.len(), 1);
        assert_eq!(loc.v4_unicast.values().next().unwrap().winner.peer_id, 2);
    }
}
