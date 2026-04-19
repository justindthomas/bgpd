//! Unix-socket query protocol for `bgpd query`.
//!
//! Mirrors `ospfd::control`: line-delimited JSON request /
//! response, one connection per query, no streaming. Each request
//! is a JSON object tagged by its `command` field; each response
//! is a single JSON line.
//!
//! Supported commands:
//!
//! - `summary` — speaker overview: ASN, router-id, peer count,
//!   per-peer state summary, total Loc-RIB size.
//! - `neighbors` — per-peer details (state, ASN, hold time,
//!   Adj-RIB-In size, established time).
//! - `routes` — current Loc-RIB winners (v4 + v6, with
//!   resolved-next-hop annotation for diagnostics).
//! - `advertised <peer>` — Adj-RIB-Out for the named peer.
//! - `received <peer>` — Adj-RIB-In for the named peer.
//!
//! The protocol is intentionally read-only. Config changes must be
//! made to the YAML file; `SIGHUP` triggers a diff-based reload.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::Mutex;

use crate::adj_rib::{AdjRibIn, PeerId, StoredRoute};
use crate::loc_rib::LocRib;
use crate::peer::fsm::PeerState;

pub const DEFAULT_CONTROL_SOCKET: &str = "/run/bgpd.sock";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "snake_case")]
pub enum ControlRequest {
    Summary,
    Neighbors,
    Routes,
    Advertised {
        peer: String,
    },
    Received {
        peer: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ControlResponse {
    Summary(SummaryReply),
    Neighbors(NeighborsReply),
    Routes(RoutesReply),
    Advertised(RoutesReply),
    Received(RoutesReply),
    Error { error: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SummaryReply {
    pub local_asn: u32,
    pub router_id: String,
    pub peer_count: usize,
    pub established_count: usize,
    pub loc_rib_v4_count: usize,
    pub loc_rib_v6_count: usize,
    pub peers: Vec<PeerSummary>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerSummary {
    pub address: String,
    pub asn: u32,
    pub state: String,
    pub adj_rib_in_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborsReply {
    pub neighbors: Vec<NeighborStatus>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NeighborStatus {
    pub address: String,
    pub asn: u32,
    pub state: String,
    /// Negotiated hold time after a successful OPEN exchange.
    /// Zero means keepalives disabled.
    pub hold_time: u16,
    pub adj_rib_in_v4_count: usize,
    pub adj_rib_in_v6_count: usize,
    /// True for eBGP, false for iBGP.
    pub is_ebgp: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutesReply {
    pub routes: Vec<RouteEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteEntry {
    pub prefix: String,
    pub next_hop: String,
    pub source: String,
    pub as_path: String,
    pub local_pref: Option<u32>,
    pub med: Option<u32>,
    pub origin: String,
    pub from_peer: String,
    /// Number of competing candidates considered during best-path
    /// for this prefix. >1 means there's something to learn from
    /// `imp show route <prefix> detail` once that lands.
    pub candidate_count: usize,
}

/// Snapshot of speaker state shared with the control task. The
/// instance layer (B5/B7 wiring) is responsible for refreshing
/// this on every relevant FSM event so the control task doesn't
/// need to lock the running instance.
#[derive(Debug)]
pub struct SpeakerSnapshot {
    pub local_asn: u32,
    pub router_id: std::net::Ipv4Addr,
    pub peers: Vec<PeerSnapshot>,
    pub loc_rib: LocRib,
}

impl Default for SpeakerSnapshot {
    fn default() -> Self {
        SpeakerSnapshot {
            local_asn: 0,
            router_id: std::net::Ipv4Addr::UNSPECIFIED,
            peers: Vec::new(),
            loc_rib: LocRib::new(),
        }
    }
}

/// Per-peer view, also part of the speaker snapshot. Stores an
/// owned `AdjRibIn` so the control handler can answer
/// `received <peer>` queries without holding any locks against
/// the live peer task.
#[derive(Debug)]
pub struct PeerSnapshot {
    pub id: PeerId,
    pub address: std::net::IpAddr,
    pub asn: u32,
    pub state: PeerState,
    pub negotiated_hold_time: u16,
    pub is_ebgp: bool,
    pub adj_rib_in: AdjRibIn,
}

/// Spawn the control listener task. Returns once the listener is
/// bound; the task then runs forever accepting connections. The
/// caller is expected to hold the `JoinHandle` and abort it on
/// shutdown.
pub async fn serve(
    socket_path: &str,
    snapshot: Arc<Mutex<SpeakerSnapshot>>,
) -> std::io::Result<tokio::task::JoinHandle<()>> {
    // Remove a stale socket if a previous instance left one.
    // The error is ignored if it doesn't exist.
    let _ = std::fs::remove_file(socket_path);
    let listener = UnixListener::bind(socket_path)?;
    tracing::info!(socket = %socket_path, "bgpd control listener ready");
    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _)) => {
                    let snap = snapshot.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_one(stream, snap).await {
                            tracing::warn!("control client error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("control listener accept failed: {}", e);
                    break;
                }
            }
        }
    });
    Ok(handle)
}

async fn handle_one(
    stream: UnixStream,
    snapshot: Arc<Mutex<SpeakerSnapshot>>,
) -> std::io::Result<()> {
    let (read_half, mut write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut line = String::new();
    if reader.read_line(&mut line).await? == 0 {
        return Ok(());
    }
    let response = match serde_json::from_str::<ControlRequest>(line.trim()) {
        Ok(req) => handle_request(req, &snapshot).await,
        Err(e) => ControlResponse::Error {
            error: format!("invalid request: {}", e),
        },
    };
    let mut bytes = serde_json::to_vec(&response)?;
    bytes.push(b'\n');
    write_half.write_all(&bytes).await?;
    Ok(())
}

async fn handle_request(
    req: ControlRequest,
    snapshot: &Arc<Mutex<SpeakerSnapshot>>,
) -> ControlResponse {
    let snap = snapshot.lock().await;
    match req {
        ControlRequest::Summary => ControlResponse::Summary(build_summary(&snap)),
        ControlRequest::Neighbors => {
            ControlResponse::Neighbors(NeighborsReply {
                neighbors: snap.peers.iter().map(neighbor_status).collect(),
            })
        }
        ControlRequest::Routes => {
            ControlResponse::Routes(RoutesReply {
                routes: build_routes_reply(&snap.loc_rib, &snap.peers),
            })
        }
        ControlRequest::Advertised { peer } => {
            match snap.peers.iter().find(|p| p.address.to_string() == peer) {
                Some(peer_snap) => {
                    let routes = build_advertised_reply(
                        &snap.loc_rib,
                        peer_snap.id,
                        peer_snap.address,
                        &snap.peers,
                    );
                    ControlResponse::Advertised(RoutesReply { routes })
                }
                None => ControlResponse::Error {
                    error: format!("unknown peer {}", peer),
                },
            }
        }
        ControlRequest::Received { peer } => {
            match snap.peers.iter().find(|p| p.address.to_string() == peer) {
                Some(peer_snap) => ControlResponse::Received(RoutesReply {
                    routes: routes_from_adj_rib_in(&peer_snap.adj_rib_in),
                }),
                None => ControlResponse::Error {
                    error: format!("unknown peer {}", peer),
                },
            }
        }
    }
}

fn build_summary(snap: &SpeakerSnapshot) -> SummaryReply {
    let established_count = snap
        .peers
        .iter()
        .filter(|p| p.state == PeerState::Established)
        .count();
    SummaryReply {
        local_asn: snap.local_asn,
        router_id: snap.router_id.to_string(),
        peer_count: snap.peers.len(),
        established_count,
        loc_rib_v4_count: snap.loc_rib.v4_unicast.len(),
        loc_rib_v6_count: snap.loc_rib.v6_unicast.len(),
        peers: snap
            .peers
            .iter()
            .map(|p| PeerSummary {
                address: p.address.to_string(),
                asn: p.asn,
                state: format!("{:?}", p.state),
                adj_rib_in_count: p.adj_rib_in.len(),
            })
            .collect(),
    }
}

fn neighbor_status(p: &PeerSnapshot) -> NeighborStatus {
    NeighborStatus {
        address: p.address.to_string(),
        asn: p.asn,
        state: format!("{:?}", p.state),
        hold_time: p.negotiated_hold_time,
        adj_rib_in_v4_count: p.adj_rib_in.v4_unicast.len(),
        adj_rib_in_v6_count: p.adj_rib_in.v6_unicast.len(),
        is_ebgp: p.is_ebgp,
    }
}

fn build_routes_reply(loc: &LocRib, peers: &[PeerSnapshot]) -> Vec<RouteEntry> {
    let mut out = Vec::new();
    for (prefix, entry) in &loc.v4_unicast {
        out.push(stored_route_to_entry(
            format!("{}/{}", prefix.addr, prefix.len),
            &entry.winner,
            entry.candidate_count,
            peers,
        ));
    }
    for (prefix, entry) in &loc.v6_unicast {
        out.push(stored_route_to_entry(
            format!("{}/{}", prefix.addr, prefix.len),
            &entry.winner,
            entry.candidate_count,
            peers,
        ));
    }
    out
}

/// Build the Adj-RIB-Out view for a given peer: Loc-RIB winners
/// that would be advertised (after split-horizon — skip routes
/// whose winner.peer_id matches the queried peer). Policy
/// filtering is not applied here since the control handler
/// doesn't have access to per-peer policies; this shows the
/// "pre-policy" outbound set.
fn build_advertised_reply(
    loc: &LocRib,
    peer_id: PeerId,
    peer_addr: std::net::IpAddr,
    peers: &[PeerSnapshot],
) -> Vec<RouteEntry> {
    let mut out = Vec::new();
    // A v4-transport peer carries only v4 NLRI; a v6-transport
    // peer carries only v6 via MP_REACH_NLRI. Filter accordingly
    // — this matches what advertise_to_peer actually sends.
    if peer_addr.is_ipv4() {
        for (prefix, entry) in &loc.v4_unicast {
            if entry.winner.peer_id == peer_id {
                continue;
            }
            out.push(stored_route_to_entry(
                format!("{}/{}", prefix.addr, prefix.len),
                &entry.winner,
                1,
                peers,
            ));
        }
    } else {
        for (prefix, entry) in &loc.v6_unicast {
            if entry.winner.peer_id == peer_id {
                continue;
            }
            out.push(stored_route_to_entry(
                format!("{}/{}", prefix.addr, prefix.len),
                &entry.winner,
                1,
                peers,
            ));
        }
    }
    out
}

fn routes_from_adj_rib_in(rib: &AdjRibIn) -> Vec<RouteEntry> {
    let mut out = Vec::new();
    for (prefix, route) in &rib.v4_unicast {
        out.push(stored_route_to_entry(
            format!("{}/{}", prefix.addr, prefix.len),
            route,
            1,
            &[],
        ));
    }
    for (prefix, route) in &rib.v6_unicast {
        out.push(stored_route_to_entry(
            format!("{}/{}", prefix.addr, prefix.len),
            route,
            1,
            &[],
        ));
    }
    out
}

fn stored_route_to_entry(
    prefix: String,
    route: &StoredRoute,
    candidate_count: usize,
    peers: &[PeerSnapshot],
) -> RouteEntry {
    let next_hop = crate::rib_push::route_next_hop(route)
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| "<unknown>".into());
    let as_path = format_as_path(route);
    let origin = match route.find_origin() {
        Some(crate::packet::attrs::Origin::Igp) => "i",
        Some(crate::packet::attrs::Origin::Egp) => "e",
        Some(crate::packet::attrs::Origin::Incomplete) => "?",
        None => "?",
    };
    let from_peer = peers
        .iter()
        .find(|p| p.id == route.peer_id)
        .map(|p| p.address.to_string())
        .unwrap_or_else(|| route.peer_address.to_string());
    RouteEntry {
        prefix,
        next_hop,
        source: if route.is_ebgp { "ebgp" } else { "ibgp" }.into(),
        as_path,
        local_pref: route.local_pref(),
        med: route.med(),
        origin: origin.into(),
        from_peer,
        candidate_count,
    }
}

fn format_as_path(route: &StoredRoute) -> String {
    use crate::packet::attrs::PathAttribute;
    for attr in &route.path_attributes {
        if let PathAttribute::AsPath(segments) = attr {
            let mut parts = Vec::new();
            for seg in segments {
                match seg.seg_type {
                    crate::packet::attrs::AsPathSegmentType::AsSequence => {
                        for asn in &seg.asns {
                            parts.push(asn.to_string());
                        }
                    }
                    crate::packet::attrs::AsPathSegmentType::AsSet => {
                        let inner: Vec<String> =
                            seg.asns.iter().map(|a| a.to_string()).collect();
                        parts.push(format!("{{{}}}", inner.join(",")));
                    }
                }
            }
            return parts.join(" ");
        }
    }
    String::new()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adj_rib::AdjRibIn;
    use crate::packet::attrs::{
        AsPathSegment, AsPathSegmentType, Origin, PathAttribute,
    };
    use crate::packet::update::Prefix4;
    use std::net::{IpAddr, Ipv4Addr};

    fn route(peer_id: PeerId, peer_asn: u32, asns: Vec<u32>) -> StoredRoute {
        StoredRoute::new(
            vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(vec![AsPathSegment {
                    seg_type: AsPathSegmentType::AsSequence,
                    asns,
                }]),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, peer_id as u8)),
                PathAttribute::LocalPref(150),
            ],
            peer_id,
            peer_asn,
            65000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, peer_id as u8)),
            Ipv4Addr::new(10, 0, 0, peer_id as u8),
        )
    }

    fn p4(a: u8, b: u8, c: u8, d: u8, len: u8) -> Prefix4 {
        Prefix4 {
            addr: Ipv4Addr::new(a, b, c, d),
            len,
        }
    }

    #[test]
    fn request_serializes_with_snake_case_command() {
        let req = ControlRequest::Summary;
        let s = serde_json::to_string(&req).unwrap();
        assert_eq!(s, "{\"command\":\"summary\"}");
    }

    #[test]
    fn advertised_request_round_trip() {
        let req = ControlRequest::Advertised { peer: "10.0.0.1".into() };
        let s = serde_json::to_string(&req).unwrap();
        let back: ControlRequest = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, ControlRequest::Advertised { peer } if peer == "10.0.0.1"));
    }

    #[test]
    fn build_summary_counts_established() {
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
        snap.peers.push(PeerSnapshot {
            id: 2,
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)),
            asn: 65002,
            state: PeerState::Idle,
            negotiated_hold_time: 0,
            is_ebgp: true,
            adj_rib_in: AdjRibIn::new(),
        });
        let summary = build_summary(&snap);
        assert_eq!(summary.peer_count, 2);
        assert_eq!(summary.established_count, 1);
        assert_eq!(summary.local_asn, 65000);
    }

    #[test]
    fn neighbor_status_extracts_per_peer_state() {
        let snap = PeerSnapshot {
            id: 1,
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            asn: 65001,
            state: PeerState::Established,
            negotiated_hold_time: 90,
            is_ebgp: true,
            adj_rib_in: AdjRibIn::new(),
        };
        let status = neighbor_status(&snap);
        assert_eq!(status.asn, 65001);
        assert_eq!(status.state, "Established");
        assert_eq!(status.hold_time, 90);
    }

    #[test]
    fn build_routes_reply_renders_winners() {
        let mut rib = AdjRibIn::new();
        rib.insert_v4(p4(192, 0, 2, 0, 24), route(1, 65001, vec![65001, 65002]));
        let loc = LocRib::rebuild(&[(1, &rib)]);
        let peers = vec![PeerSnapshot {
            id: 1,
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            asn: 65001,
            state: PeerState::Established,
            negotiated_hold_time: 90,
            is_ebgp: true,
            adj_rib_in: AdjRibIn::new(),
        }];
        let entries = build_routes_reply(&loc, &peers);
        assert_eq!(entries.len(), 1);
        let e = &entries[0];
        assert_eq!(e.prefix, "192.0.2.0/24");
        assert_eq!(e.next_hop, "10.0.0.1");
        assert_eq!(e.source, "ebgp");
        assert_eq!(e.as_path, "65001 65002");
        assert_eq!(e.local_pref, Some(150));
        assert_eq!(e.origin, "i");
    }

    #[test]
    fn format_as_path_handles_set_segments() {
        let mut r = route(1, 65001, vec![]);
        // Replace AS_PATH with a set segment.
        for attr in &mut r.path_attributes {
            if let PathAttribute::AsPath(segs) = attr {
                segs.clear();
                segs.push(AsPathSegment {
                    seg_type: AsPathSegmentType::AsSequence,
                    asns: vec![65001],
                });
                segs.push(AsPathSegment {
                    seg_type: AsPathSegmentType::AsSet,
                    asns: vec![65010, 65011, 65012],
                });
            }
        }
        let s = format_as_path(&r);
        assert_eq!(s, "65001 {65010,65011,65012}");
    }
}
