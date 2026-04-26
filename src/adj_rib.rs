//! Adj-RIB-In and Adj-RIB-Out, per peer per address family.
//!
//! Each peer's view of routes is stored here verbatim — no
//! best-path selection happens at this layer. Best-path selection
//! and aggregation across peers belongs in [`crate::loc_rib`],
//! which scans every peer's Adj-RIB-In on demand.
//!
//! Storage is split by address family so the keys can be the
//! statically-typed `Prefix4` / `Prefix6` from
//! [`crate::packet::update`] rather than a tagged union.

use std::collections::HashMap;
use std::time::Instant;

use crate::packet::attrs::PathAttribute;
use crate::packet::update::{Prefix4, Prefix6};

/// Identifier for the peer a stored route came from. We don't
/// hold a reference back to the Peer struct here because that
/// would tangle Adj-RIB lifetimes with the driver task; instead
/// each peer has a stable `PeerId` allocated by the instance
/// layer at startup. v1 uses a small `u32`; v2 might switch to
/// the peer's IP address when we add per-peer ABM stats.
pub type PeerId = u32;

/// Sentinel `PeerId` used for routes that didn't come from any
/// real BGP peer. Locally-originated routes (announced_prefixes,
/// redistribute_*, aggregates) get this id so they can sit in a
/// synthetic "local" pseudo-peer's Adj-RIB-In and compete in
/// best-path against peer-learned routes through the standard
/// path. Real peers get ids starting at 1.
pub const LOCAL_PEER_ID: PeerId = 0;

/// Why a `StoredRoute` exists. Drives outbound-path decisions
/// (locally-originated routes always get next-hop-self;
/// peer-learned routes preserve the peer's NEXT_HOP for iBGP
/// re-advertisement) and per-source export filtering once the
/// policy DSL grows beyond accept/deny.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OriginClass {
    /// Received from a BGP peer over the wire.
    PeerLearned,
    /// `announced_prefixes` — operator-specified static
    /// origination, equivalent to FRR's `network <prefix>`.
    Static,
    /// `redistribute connected` — directly-attached interface
    /// prefix, sourced from ribd's seeded connected set.
    Connected,
    /// `redistribute <protocol>` — route originated by another
    /// routing daemon, queried from ribd by source.
    Redistribute(ribd_proto::Source),
    /// Synthesized aggregate (`aggregate-address`).
    Aggregate,
}

impl OriginClass {
    /// True if this route was originated locally (any non-peer
    /// origin). Outbound rewrites use this to decide whether
    /// "next-hop self" applies unconditionally.
    pub fn is_local(self) -> bool {
        !matches!(self, OriginClass::PeerLearned)
    }
}

/// A route as stored in Adj-RIB-In. Holds the producer-supplied
/// path attributes plus the metadata best-path needs (peer id,
/// arrival time, eBGP-vs-iBGP flag) and the origin class that
/// drives outbound rewrites and source-based filtering.
#[derive(Debug, Clone)]
pub struct StoredRoute {
    pub path_attributes: Vec<PathAttribute>,
    pub peer_id: PeerId,
    pub peer_asn: u32,
    /// True if the peer is an eBGP neighbor (peer_asn != local_asn).
    /// For locally-originated routes (origin_class != PeerLearned)
    /// this is always false because the synthetic local pseudo-
    /// peer uses local_asn as its peer_asn.
    pub is_ebgp: bool,
    /// Peer's neighbor address. Used as the lowest-priority
    /// tiebreaker in best-path selection. For local-origin
    /// routes this is the unspecified address.
    pub peer_address: std::net::IpAddr,
    /// Local router-id. Stored on the route (not looked up at
    /// selection time) so a router-id change doesn't churn
    /// existing best-path winners.
    pub peer_router_id: std::net::Ipv4Addr,
    pub received_at: Instant,
    /// Why this route exists. See [`OriginClass`].
    pub origin_class: OriginClass,
}

impl StoredRoute {
    /// Construct a `StoredRoute` for a peer-learned route.
    /// For locally-originated routes use [`Self::local_origin`].
    pub fn new(
        path_attributes: Vec<PathAttribute>,
        peer_id: PeerId,
        peer_asn: u32,
        local_asn: u32,
        peer_address: std::net::IpAddr,
        peer_router_id: std::net::Ipv4Addr,
    ) -> Self {
        StoredRoute {
            path_attributes,
            peer_id,
            peer_asn,
            is_ebgp: peer_asn != local_asn,
            peer_address,
            peer_router_id,
            received_at: Instant::now(),
            origin_class: OriginClass::PeerLearned,
        }
    }

    /// Construct a `StoredRoute` representing a locally-
    /// originated route — one of `announced_prefixes`,
    /// `redistribute connected`, `redistribute <protocol>`, or
    /// an aggregate. The synthetic local pseudo-peer uses
    /// [`LOCAL_PEER_ID`] and `local_asn` for its asn so
    /// `is_ebgp` evaluates false. The route is given an empty
    /// AS_PATH and `Origin::Igp` per RFC 4271 §5.1.2 for
    /// locally-originated routes; the actual NEXT_HOP is filled
    /// in at outbound-advertise time per peer (next-hop-self).
    /// Caller is responsible for any LOCAL_PREF.
    pub fn local_origin(
        path_attributes: Vec<PathAttribute>,
        local_asn: u32,
        local_router_id: std::net::Ipv4Addr,
        origin_class: OriginClass,
    ) -> Self {
        debug_assert!(
            origin_class.is_local(),
            "local_origin called with PeerLearned class"
        );
        StoredRoute {
            path_attributes,
            peer_id: LOCAL_PEER_ID,
            peer_asn: local_asn,
            is_ebgp: false,
            peer_address: std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
            peer_router_id: local_router_id,
            received_at: Instant::now(),
            origin_class,
        }
    }

    pub fn find_origin(&self) -> Option<crate::packet::attrs::Origin> {
        self.path_attributes.iter().find_map(|a| match a {
            PathAttribute::Origin(o) => Some(*o),
            _ => None,
        })
    }

    /// Sum of ASNs across every AS_SEQUENCE segment plus 1 per
    /// AS_SET segment (RFC 4271 §9.1.2.2's "shortest AS_PATH"
    /// counts a set as 1). Returns 0 if no AS_PATH is present.
    pub fn as_path_length(&self) -> usize {
        use crate::packet::attrs::AsPathSegmentType::{AsSequence, AsSet};
        self.path_attributes
            .iter()
            .find_map(|a| match a {
                PathAttribute::AsPath(segments) => Some(segments),
                _ => None,
            })
            .map(|segments| {
                segments
                    .iter()
                    .map(|seg| match seg.seg_type {
                        AsSequence => seg.asns.len(),
                        AsSet => 1,
                    })
                    .sum()
            })
            .unwrap_or(0)
    }

    pub fn local_pref(&self) -> Option<u32> {
        self.path_attributes.iter().find_map(|a| match a {
            PathAttribute::LocalPref(lp) => Some(*lp),
            _ => None,
        })
    }

    pub fn med(&self) -> Option<u32> {
        self.path_attributes.iter().find_map(|a| match a {
            PathAttribute::MultiExitDisc(med) => Some(*med),
            _ => None,
        })
    }

    pub fn next_hop_v4(&self) -> Option<std::net::Ipv4Addr> {
        self.path_attributes.iter().find_map(|a| match a {
            PathAttribute::NextHop(nh) => Some(*nh),
            _ => None,
        })
    }

    /// Extract the IPv6 next-hop from an MP_REACH_NLRI attribute,
    /// if any. v1 takes the first 16 bytes; the link-local
    /// next-hop (RFC 2545) lives in the second 16 bytes when
    /// present and is not used by v1.
    pub fn next_hop_v6(&self) -> Option<std::net::Ipv6Addr> {
        self.path_attributes.iter().find_map(|a| match a {
            PathAttribute::MpReachNlri { afi, nexthop, .. }
                if *afi == crate::packet::caps::AFI_IPV6 && nexthop.len() >= 16 =>
            {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&nexthop[..16]);
                Some(std::net::Ipv6Addr::from(octets))
            }
            _ => None,
        })
    }
}

/// Routes received from a single peer. One per session.
#[derive(Debug, Default)]
pub struct AdjRibIn {
    pub v4_unicast: HashMap<Prefix4, StoredRoute>,
    pub v6_unicast: HashMap<Prefix6, StoredRoute>,
}

impl AdjRibIn {
    pub fn new() -> Self {
        AdjRibIn::default()
    }

    pub fn insert_v4(&mut self, prefix: Prefix4, route: StoredRoute) {
        self.v4_unicast.insert(prefix, route);
    }

    pub fn remove_v4(&mut self, prefix: &Prefix4) -> Option<StoredRoute> {
        self.v4_unicast.remove(prefix)
    }

    pub fn insert_v6(&mut self, prefix: Prefix6, route: StoredRoute) {
        self.v6_unicast.insert(prefix, route);
    }

    pub fn remove_v6(&mut self, prefix: &Prefix6) -> Option<StoredRoute> {
        self.v6_unicast.remove(prefix)
    }

    pub fn len(&self) -> usize {
        self.v4_unicast.len() + self.v6_unicast.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Routes scheduled for advertisement to a peer. Same shape as
/// AdjRibIn — they're symmetric. v1 isn't doing route reflection
/// or ADD-PATH so a single entry per (peer, prefix) is enough.
#[derive(Debug, Default)]
pub struct AdjRibOut {
    pub v4_unicast: HashMap<Prefix4, StoredRoute>,
    pub v6_unicast: HashMap<Prefix6, StoredRoute>,
}

impl AdjRibOut {
    pub fn new() -> Self {
        AdjRibOut::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::attrs::{
        AsPathSegment, AsPathSegmentType, Origin, PathAttribute,
    };
    use std::net::{IpAddr, Ipv4Addr};

    fn route(asns: Vec<u32>, peer_id: PeerId, peer_asn: u32) -> StoredRoute {
        StoredRoute::new(
            vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(vec![AsPathSegment {
                    seg_type: AsPathSegmentType::AsSequence,
                    asns,
                }]),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, peer_id as u8)),
            ],
            peer_id,
            peer_asn,
            65000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, peer_id as u8)),
            Ipv4Addr::new(10, 0, 0, peer_id as u8),
        )
    }

    #[test]
    fn as_path_length_counts_sequence_asns() {
        let r = route(vec![65001, 65002, 65003], 1, 65001);
        assert_eq!(r.as_path_length(), 3);
    }

    #[test]
    fn as_path_length_counts_set_as_one() {
        let r = StoredRoute::new(
            vec![PathAttribute::AsPath(vec![
                AsPathSegment {
                    seg_type: AsPathSegmentType::AsSequence,
                    asns: vec![65001, 65002],
                },
                AsPathSegment {
                    seg_type: AsPathSegmentType::AsSet,
                    asns: vec![65010, 65011, 65012, 65013],
                },
            ])],
            1,
            65001,
            65000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            Ipv4Addr::new(10, 0, 0, 1),
        );
        // 2 seq ASNs + 1 (set counts as one) = 3
        assert_eq!(r.as_path_length(), 3);
    }

    #[test]
    fn local_pref_extracted_when_present() {
        let mut r = route(vec![65001], 1, 65001);
        r.path_attributes.push(PathAttribute::LocalPref(150));
        assert_eq!(r.local_pref(), Some(150));
    }

    #[test]
    fn ebgp_flag_set_when_asns_differ() {
        let r = route(vec![65001], 1, 65001);
        assert!(r.is_ebgp);
    }

    #[test]
    fn ibgp_flag_when_asns_match() {
        let r = StoredRoute::new(
            Vec::new(),
            1,
            65000,
            65000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            Ipv4Addr::new(10, 0, 0, 1),
        );
        assert!(!r.is_ebgp);
    }

    #[test]
    fn peer_learned_default_origin_class() {
        let r = route(vec![65001], 1, 65001);
        assert_eq!(r.origin_class, OriginClass::PeerLearned);
        assert!(!r.origin_class.is_local());
    }

    #[test]
    fn local_origin_constructor_static() {
        let r = StoredRoute::local_origin(
            vec![PathAttribute::Origin(crate::packet::attrs::Origin::Igp)],
            65000,
            Ipv4Addr::new(10, 0, 0, 1),
            OriginClass::Static,
        );
        assert_eq!(r.peer_id, LOCAL_PEER_ID);
        assert_eq!(r.peer_asn, 65000);
        assert!(!r.is_ebgp, "local-origin routes are never eBGP");
        assert_eq!(r.origin_class, OriginClass::Static);
        assert!(r.origin_class.is_local());
        assert_eq!(
            r.peer_address,
            std::net::IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        );
    }

    #[test]
    fn local_origin_constructor_redistribute_ospf() {
        // Wrap a Source variant inside Redistribute so the
        // outbound layer can later filter "redistribute ospf"
        // separately from "redistribute static".
        let r = StoredRoute::local_origin(
            Vec::new(),
            65000,
            Ipv4Addr::new(10, 0, 0, 1),
            OriginClass::Redistribute(ribd_proto::Source::OspfIntra),
        );
        match r.origin_class {
            OriginClass::Redistribute(ribd_proto::Source::OspfIntra) => {}
            other => panic!("wrong class: {:?}", other),
        }
    }

    #[test]
    fn origin_class_is_local_predicate() {
        assert!(!OriginClass::PeerLearned.is_local());
        assert!(OriginClass::Static.is_local());
        assert!(OriginClass::Connected.is_local());
        assert!(
            OriginClass::Redistribute(ribd_proto::Source::OspfIntra).is_local()
        );
        assert!(OriginClass::Aggregate.is_local());
    }

    #[test]
    fn adj_rib_in_insert_and_remove() {
        let mut rib = AdjRibIn::new();
        let p = Prefix4 {
            addr: Ipv4Addr::new(192, 0, 2, 0),
            len: 24,
        };
        rib.insert_v4(p, route(vec![65001], 1, 65001));
        assert_eq!(rib.len(), 1);
        let removed = rib.remove_v4(&p).unwrap();
        assert_eq!(removed.peer_id, 1);
        assert!(rib.is_empty());
    }
}
