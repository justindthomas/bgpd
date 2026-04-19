//! Loc-RIB → ribd integration.
//!
//! Translates [`crate::loc_rib::LocRib`] winners into
//! [`ribd_proto::Route`] + [`ribd_proto::NextHop::Recursive`]
//! and pushes them via [`ribd_client::RibConnection`]. Three
//! operations:
//!
//! - **Bulk push**: convert the entire Loc-RIB to a chunked bulk
//!   per source. Used on session up, on periodic resync, and on
//!   reconnect to ribd. The chunked bulk gives ribd
//!   atomic-replace semantics — no half-states visible.
//! - **Incremental update**: send a single `Update::Add` per new
//!   winner and `Update::Delete` per withdrawn prefix. Used in
//!   the steady state.
//! - **Source split**: eBGP routes go in as
//!   [`ribd_proto::Source::Bgp`] (admin distance 20), iBGP as
//!   [`ribd_proto::Source::BgpInternal`] (admin distance 200).
//!   ribd's Source enum already has both with the right ADs.
//!
//! Recursive next-hops mean we *never* have to track IGP changes
//! ourselves: ribd's NexthopTracker re-resolves dependents
//! when the underlying IGP route changes, and the resolved direct
//! paths flow back into VPP / kernel automatically. From
//! bgpd's perspective the BGP next-hop is just an opaque IP.
//!
//! ## Chunk sizing
//!
//! `MAX_FRAME_LEN` in ribd-proto is 16 MB. Each `Route` with
//! a single recursive next-hop encodes to ~80 bytes (Prefix +
//! Source enum + NextHop + tag/metric/admin_distance fields). At
//! 80 bytes/route, ~200_000 routes fit per 16 MB frame. We use a
//! conservative 50_000 to leave headroom for variable-sized
//! attributes once we start carrying them per route.

use std::net::IpAddr;

use ribd_client::{ClientError, RibConnection};
use ribd_proto::{
    Action, NextHop, Prefix as RibPrefix, Route as RibRoute, Source as RibSource,
};

use crate::adj_rib::StoredRoute;
use crate::loc_rib::LocRib;
use crate::packet::update::{Prefix4, Prefix6};

/// How many routes to put in each `BulkChunk` frame. See module
/// docstring for sizing rationale.
pub const CHUNK_SIZE: usize = 50_000;

/// Convert a Loc-RIB winner's `(prefix, StoredRoute)` pair into
/// an `ribd_proto::Route` ready to push. Picks the right
/// `Source` (Bgp vs BgpInternal) from the eBGP/iBGP flag and
/// emits a `NextHop::Recursive` so ribd does the resolution.
fn build_v4_route(prefix: &Prefix4, route: &StoredRoute) -> Option<RibRoute> {
    let nh_addr = route.next_hop_v4()?;
    let source = if route.is_ebgp {
        RibSource::Bgp
    } else {
        RibSource::BgpInternal
    };
    let mut a = [0u8; 16];
    a[..4].copy_from_slice(&prefix.addr.octets());
    Some(RibRoute {
        prefix: RibPrefix {
            af: ribd_proto::Af::V4,
            addr: a,
            len: prefix.len,
        },
        source,
        next_hops: vec![NextHop::recursive_v4(nh_addr)],
        // BGP best-path's metric concept is MED; pass it through
        // so ribd can use it as the same-source tiebreak.
        metric: route.med().unwrap_or(0),
        tag: 0,
        admin_distance: None,
    })
}

fn build_v6_route(prefix: &Prefix6, route: &StoredRoute) -> Option<RibRoute> {
    let nh_addr = route.next_hop_v6()?;
    let source = if route.is_ebgp {
        RibSource::Bgp
    } else {
        RibSource::BgpInternal
    };
    Some(RibRoute {
        prefix: RibPrefix {
            af: ribd_proto::Af::V6,
            addr: prefix.addr.octets(),
            len: prefix.len,
        },
        source,
        next_hops: vec![NextHop::recursive_v6(nh_addr)],
        metric: route.med().unwrap_or(0),
        tag: 0,
        admin_distance: None,
    })
}

/// Build the full route list to push for a given source. eBGP
/// and iBGP routes are pushed under different `Source` values, so
/// each call covers exactly one source.
fn collect_routes(loc: &LocRib, source: RibSource) -> Vec<RibRoute> {
    let want_ebgp = matches!(source, RibSource::Bgp);
    let mut out = Vec::with_capacity(loc.len());
    for (prefix, entry) in &loc.v4_unicast {
        // Locally-originated routes (announced_prefixes, redistribute,
        // aggregates) came from ribd originally or don't belong in
        // it — don't push them back. Only peer-learned routes get
        // installed to the ribd as BGP sources.
        if entry.winner.origin_class.is_local() {
            continue;
        }
        if entry.winner.is_ebgp != want_ebgp {
            continue;
        }
        if let Some(r) = build_v4_route(prefix, &entry.winner) {
            out.push(r);
        }
    }
    for (prefix, entry) in &loc.v6_unicast {
        if entry.winner.origin_class.is_local() {
            continue;
        }
        if entry.winner.is_ebgp != want_ebgp {
            continue;
        }
        if let Some(r) = build_v6_route(prefix, &entry.winner) {
            out.push(r);
        }
    }
    out
}

/// Push the full Loc-RIB to ribd as two chunked bulks, one
/// per source. Used on ribd session establishment and on
/// reconnect — gives ribd a clean atomic snapshot.
pub async fn push_full_rib(
    conn: &mut RibConnection,
    loc: &LocRib,
) -> Result<(), ClientError> {
    let ebgp_routes = collect_routes(loc, RibSource::Bgp);
    let ibgp_routes = collect_routes(loc, RibSource::BgpInternal);

    tracing::info!(
        ebgp = ebgp_routes.len(),
        ibgp = ibgp_routes.len(),
        "pushing Loc-RIB to ribd as chunked bulks"
    );

    conn.push_bulk_chunked(RibSource::Bgp, ebgp_routes, CHUNK_SIZE)
        .await?;
    conn.push_bulk_chunked(RibSource::BgpInternal, ibgp_routes, CHUNK_SIZE)
        .await?;
    Ok(())
}

/// Push a single incremental change. Used in the steady state
/// when a single UPDATE arrives and changes a single best-path
/// winner. The caller has already done the per-prefix best-path
/// recompute and knows whether this is an Add or Delete.
pub async fn push_incremental(
    conn: &mut RibConnection,
    prefix_v4: Option<&Prefix4>,
    prefix_v6: Option<&Prefix6>,
    new_winner: Option<&StoredRoute>,
) -> Result<(), ClientError> {
    match (prefix_v4, prefix_v6, new_winner) {
        (Some(p), None, Some(w)) => {
            if let Some(route) = build_v4_route(p, w) {
                conn.update(Action::Add, route).await?;
            }
        }
        (None, Some(p), Some(w)) => {
            if let Some(route) = build_v6_route(p, w) {
                conn.update(Action::Add, route).await?;
            }
        }
        (Some(p), None, None) => {
            // Delete: synthesise a stub route with the right
            // (prefix, source). next_hops are ignored on delete by
            // ribd's session handler, so an empty Vec is fine.
            let mut a = [0u8; 16];
            a[..4].copy_from_slice(&p.addr.octets());
            // We don't know whether the prior winner was eBGP or
            // iBGP from this signature alone; the caller is
            // expected to delete from both sources. Most
            // implementations would track that — for v1 we send
            // both deletes. Cheap and correct.
            for source in [RibSource::Bgp, RibSource::BgpInternal] {
                let route = RibRoute {
                    prefix: RibPrefix {
                        af: ribd_proto::Af::V4,
                        addr: a,
                        len: p.len,
                    },
                    source,
                    next_hops: Vec::new(),
                    metric: 0,
                    tag: 0,
                    admin_distance: None,
                };
                conn.update(Action::Delete, route).await?;
            }
        }
        (None, Some(p), None) => {
            for source in [RibSource::Bgp, RibSource::BgpInternal] {
                let route = RibRoute {
                    prefix: RibPrefix {
                        af: ribd_proto::Af::V6,
                        addr: p.addr.octets(),
                        len: p.len,
                    },
                    source,
                    next_hops: Vec::new(),
                    metric: 0,
                    tag: 0,
                    admin_distance: None,
                };
                conn.update(Action::Delete, route).await?;
            }
        }
        _ => {
            // (None, None, _) or (Some, Some, _) — caller bug.
            tracing::warn!("push_incremental called with invalid prefix combination");
        }
    }
    Ok(())
}

/// Convenience: extract the BGP next-hop IP from a stored route
/// (v4 or v6). Used by the control socket query path to render
/// "via X" without re-walking the path attributes.
pub fn route_next_hop(route: &StoredRoute) -> Option<IpAddr> {
    if let Some(v4) = route.next_hop_v4() {
        return Some(IpAddr::V4(v4));
    }
    if let Some(v6) = route.next_hop_v6() {
        return Some(IpAddr::V6(v6));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adj_rib::AdjRibIn;
    use crate::loc_rib::LocRib;
    use crate::packet::attrs::{
        AsPathSegment, AsPathSegmentType, Origin, PathAttribute,
    };
    use std::net::Ipv4Addr;

    fn ebgp_route(asn: u32, local: u32, nh: Ipv4Addr) -> StoredRoute {
        StoredRoute::new(
            vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(vec![AsPathSegment {
                    seg_type: AsPathSegmentType::AsSequence,
                    asns: vec![asn],
                }]),
                PathAttribute::NextHop(nh),
            ],
            1,
            asn,
            local,
            std::net::IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            Ipv4Addr::new(10, 0, 0, 1),
        )
    }

    fn p4(a: u8, b: u8, c: u8, d: u8, len: u8) -> Prefix4 {
        Prefix4 {
            addr: Ipv4Addr::new(a, b, c, d),
            len,
        }
    }

    #[test]
    fn build_v4_route_uses_recursive_nexthop() {
        let route = ebgp_route(65001, 65000, Ipv4Addr::new(10, 0, 0, 5));
        let prefix = p4(192, 0, 2, 0, 24);
        let r = build_v4_route(&prefix, &route).unwrap();
        assert_eq!(r.source, RibSource::Bgp);
        assert_eq!(r.next_hops.len(), 1);
        assert!(r.next_hops[0].is_recursive());
        // recursive_v4 zero-pads the addr to 16 bytes.
        assert_eq!(&r.next_hops[0].addr[..4], &[10, 0, 0, 5]);
    }

    #[test]
    fn build_v4_route_routes_ibgp_to_bgp_internal() {
        let route = ebgp_route(65000, 65000, Ipv4Addr::new(10, 0, 0, 5));
        // peer_asn == local_asn → is_ebgp false
        assert!(!route.is_ebgp);
        let r = build_v4_route(&p4(192, 0, 2, 0, 24), &route).unwrap();
        assert_eq!(r.source, RibSource::BgpInternal);
    }

    #[test]
    fn build_v4_route_propagates_med_as_metric() {
        let mut route = ebgp_route(65001, 65000, Ipv4Addr::new(10, 0, 0, 5));
        route.path_attributes.push(PathAttribute::MultiExitDisc(42));
        let r = build_v4_route(&p4(192, 0, 2, 0, 24), &route).unwrap();
        assert_eq!(r.metric, 42);
    }

    #[test]
    fn collect_routes_filters_by_source() {
        let mut rib_a = AdjRibIn::new();
        let mut rib_b = AdjRibIn::new();
        rib_a.insert_v4(
            p4(192, 0, 2, 0, 24),
            ebgp_route(65001, 65000, Ipv4Addr::new(10, 0, 0, 1)),
        );
        rib_b.insert_v4(
            p4(198, 51, 100, 0, 24),
            // peer_asn == local_asn → iBGP
            ebgp_route(65000, 65000, Ipv4Addr::new(10, 0, 0, 2)),
        );
        let loc = LocRib::rebuild(&[(1, &rib_a), (2, &rib_b)]);
        let ebgp = collect_routes(&loc, RibSource::Bgp);
        let ibgp = collect_routes(&loc, RibSource::BgpInternal);
        assert_eq!(ebgp.len(), 1);
        assert_eq!(ibgp.len(), 1);
        assert_eq!(ebgp[0].source, RibSource::Bgp);
        assert_eq!(ibgp[0].source, RibSource::BgpInternal);
    }

    #[test]
    fn route_next_hop_extracts_v4() {
        let route = ebgp_route(65001, 65000, Ipv4Addr::new(10, 0, 0, 5));
        let nh = route_next_hop(&route).unwrap();
        match nh {
            IpAddr::V4(v4) => assert_eq!(v4, Ipv4Addr::new(10, 0, 0, 5)),
            _ => panic!("expected v4"),
        }
    }
}
