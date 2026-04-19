//! Local RIB — the speaker's chosen-best routes per address
//! family per prefix.
//!
//! Built by collecting Adj-RIB-In contributions from every active
//! peer and running [`crate::bestpath::select_best`] per prefix.
//! v1 recomputes lazily on demand: `compute_v4()` / `compute_v6()`
//! produce a fresh `LocRib` from a slice of `(PeerId, &AdjRibIn)`.
//! Once we have lots of peers and lots of prefixes we'll move to
//! incremental updates, but the lazy approach is simple and keeps
//! the surface small for B5 (rib_push) to consume.

use std::collections::HashMap;

use crate::adj_rib::{AdjRibIn, PeerId, StoredRoute};
use crate::bestpath;
use crate::packet::update::{Prefix4, Prefix6};

#[derive(Debug, Clone)]
pub struct LocRibEntry {
    pub winner: StoredRoute,
    /// How many candidates competed for this prefix. Exposed via
    /// the control socket (B6) so operators can see "this prefix
    /// has 3 candidates, BGP chose path 2 because of LOCAL_PREF".
    pub candidate_count: usize,
}

#[derive(Debug, Default)]
pub struct LocRib {
    pub v4_unicast: HashMap<Prefix4, LocRibEntry>,
    pub v6_unicast: HashMap<Prefix6, LocRibEntry>,
}

impl LocRib {
    pub fn new() -> Self {
        LocRib::default()
    }

    /// Recompute from scratch. `inputs` is a slice of
    /// `(peer_id, &AdjRibIn)` pairs — typically one per
    /// established BGP session. Held by reference so the caller
    /// doesn't have to clone every Adj-RIB-In.
    pub fn rebuild(inputs: &[(PeerId, &AdjRibIn)]) -> Self {
        let mut out = LocRib::new();

        // v4 unicast: bucket every (peer, prefix) by prefix, then
        // run select_best per prefix.
        let mut v4_buckets: HashMap<Prefix4, Vec<StoredRoute>> = HashMap::new();
        for (_peer_id, rib) in inputs {
            for (prefix, route) in &rib.v4_unicast {
                v4_buckets
                    .entry(*prefix)
                    .or_default()
                    .push(route.clone());
            }
        }
        for (prefix, candidates) in v4_buckets {
            if let Some(idx) = bestpath::select_best(&candidates) {
                let count = candidates.len();
                let winner = candidates.into_iter().nth(idx).unwrap();
                out.v4_unicast.insert(
                    prefix,
                    LocRibEntry {
                        winner,
                        candidate_count: count,
                    },
                );
            }
        }

        // v6 unicast: same.
        let mut v6_buckets: HashMap<Prefix6, Vec<StoredRoute>> = HashMap::new();
        for (_peer_id, rib) in inputs {
            for (prefix, route) in &rib.v6_unicast {
                v6_buckets
                    .entry(*prefix)
                    .or_default()
                    .push(route.clone());
            }
        }
        for (prefix, candidates) in v6_buckets {
            if let Some(idx) = bestpath::select_best(&candidates) {
                let count = candidates.len();
                let winner = candidates.into_iter().nth(idx).unwrap();
                out.v6_unicast.insert(
                    prefix,
                    LocRibEntry {
                        winner,
                        candidate_count: count,
                    },
                );
            }
        }

        out
    }

    pub fn len(&self) -> usize {
        self.v4_unicast.len() + self.v6_unicast.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adj_rib::AdjRibIn;
    use crate::packet::attrs::{
        AsPathSegment, AsPathSegmentType, Origin, PathAttribute,
    };
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
    fn rebuild_picks_winner_per_prefix() {
        let mut rib_a = AdjRibIn::new();
        let mut rib_b = AdjRibIn::new();
        // Same prefix, two peers. Peer B has shorter AS_PATH.
        let p = p4(192, 0, 2, 0, 24);
        rib_a.insert_v4(p, route(1, 65001, vec![65001, 65002, 65003]));
        rib_b.insert_v4(p, route(2, 65002, vec![65002]));

        let loc = LocRib::rebuild(&[(1, &rib_a), (2, &rib_b)]);
        assert_eq!(loc.v4_unicast.len(), 1);
        let entry = &loc.v4_unicast[&p];
        assert_eq!(entry.winner.peer_id, 2);
        assert_eq!(entry.candidate_count, 2);
    }

    #[test]
    fn rebuild_includes_unique_prefixes_from_each_peer() {
        let mut rib_a = AdjRibIn::new();
        let mut rib_b = AdjRibIn::new();
        rib_a.insert_v4(p4(192, 0, 2, 0, 24), route(1, 65001, vec![65001]));
        rib_b.insert_v4(p4(198, 51, 100, 0, 24), route(2, 65002, vec![65002]));
        let loc = LocRib::rebuild(&[(1, &rib_a), (2, &rib_b)]);
        assert_eq!(loc.v4_unicast.len(), 2);
    }

    #[test]
    fn rebuild_empty_inputs_returns_empty() {
        let loc = LocRib::rebuild(&[]);
        assert!(loc.is_empty());
    }

    #[test]
    fn rebuild_handles_single_peer_single_prefix() {
        let mut rib = AdjRibIn::new();
        rib.insert_v4(p4(192, 0, 2, 0, 24), route(1, 65001, vec![65001]));
        let loc = LocRib::rebuild(&[(1, &rib)]);
        assert_eq!(loc.v4_unicast.len(), 1);
        assert_eq!(loc.v4_unicast.values().next().unwrap().candidate_count, 1);
    }
}
