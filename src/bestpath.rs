//! BGP best-path selection — RFC 4271 §9.1.2 tiebreaker chain.
//!
//! Pure logic over [`crate::adj_rib::StoredRoute`] slices. Each
//! tiebreaker is a `compare_*` function so it can be unit-tested
//! in isolation; the public [`select_best`] composes them in the
//! RFC-mandated order and returns the winning index (or `None`
//! if no candidates were supplied).
//!
//! ## v1 scope
//!
//! Implements rules 1, 3, 4, 5, 6, 8, 9, 11 from RFC 4271 §9.1.2:
//!
//!   1. Highest LOCAL_PREF
//!   2. Locally originated (skipped — v1 doesn't aggregate /
//!      redistribute, all routes come from peers)
//!   3. Shortest AS_PATH
//!   4. Lowest ORIGIN
//!   5. Lowest MED (within same neighbor AS, by default)
//!   6. eBGP over iBGP
//!   7. Lowest IGP metric to BGP next-hop **(skipped — requires
//!      querying ribd from inside the FSM, which v1 avoids)**
//!   8. Oldest received (stability tiebreaker)
//!   9. Lowest router-id
//!  10. Lowest cluster-list length (skipped — v1 has no RR)
//!  11. Lowest neighbor address
//!
//! Skipped rules are correctness preserving: 2 and 10 cannot fire
//! in v1 because they require features we don't implement, and 7
//! is the place where ECMP across iBGP would be tightened — for
//! v1 the lower-numbered tiebreakers usually decide first, and
//! ECMP across iBGP is a deliberate v2 feature.

use std::cmp::Ordering;

use crate::adj_rib::StoredRoute;
use crate::packet::attrs::Origin;

/// Compare two routes for best-path selection. `Less` means `a`
/// is preferred (it sits earlier in the sort order).
fn compare(a: &StoredRoute, b: &StoredRoute) -> Ordering {
    // 1. Higher LOCAL_PREF wins.
    let lp_a = a.local_pref().unwrap_or(100);
    let lp_b = b.local_pref().unwrap_or(100);
    if lp_a != lp_b {
        return lp_b.cmp(&lp_a); // higher first
    }

    // 3. Shorter AS_PATH wins.
    let len_a = a.as_path_length();
    let len_b = b.as_path_length();
    if len_a != len_b {
        return len_a.cmp(&len_b);
    }

    // 4. Lower ORIGIN wins (IGP < EGP < INCOMPLETE).
    let origin_a = a.find_origin().unwrap_or(Origin::Incomplete) as u8;
    let origin_b = b.find_origin().unwrap_or(Origin::Incomplete) as u8;
    if origin_a != origin_b {
        return origin_a.cmp(&origin_b);
    }

    // 5. Lower MED wins. RFC 4271 §9.1.2.2(c) restricts this
    //    comparison to routes from the same neighbor AS, but RFC
    //    7311 ("always-compare-med") relaxes it. v1 follows the
    //    strict rule: only compare MEDs when the routes' first
    //    AS in the AS_PATH match. If they don't, MED is skipped.
    let neighbor_as_a = first_as(a);
    let neighbor_as_b = first_as(b);
    if neighbor_as_a == neighbor_as_b {
        let med_a = a.med().unwrap_or(0);
        let med_b = b.med().unwrap_or(0);
        if med_a != med_b {
            return med_a.cmp(&med_b);
        }
    }

    // 6. eBGP over iBGP.
    if a.is_ebgp != b.is_ebgp {
        return if a.is_ebgp {
            Ordering::Less
        } else {
            Ordering::Greater
        };
    }

    // 7. Lowest IGP metric to BGP next-hop — skipped, see module docstring.

    // 8. Oldest received first.
    if a.received_at != b.received_at {
        return a.received_at.cmp(&b.received_at);
    }

    // 9. Lower router-id wins.
    if a.peer_router_id != b.peer_router_id {
        return a.peer_router_id.cmp(&b.peer_router_id);
    }

    // 11. Lower neighbor address wins.
    a.peer_address.cmp(&b.peer_address)
}

fn first_as(r: &StoredRoute) -> Option<u32> {
    for attr in &r.path_attributes {
        if let crate::packet::attrs::PathAttribute::AsPath(segments) = attr {
            for seg in segments {
                if let Some(first) = seg.asns.first() {
                    return Some(*first);
                }
            }
        }
    }
    None
}

/// Pick the best route from a slice of candidates. Returns the
/// winning index, or `None` if `candidates` is empty.
pub fn select_best(candidates: &[StoredRoute]) -> Option<usize> {
    if candidates.is_empty() {
        return None;
    }
    let mut best = 0;
    for i in 1..candidates.len() {
        if compare(&candidates[i], &candidates[best]) == Ordering::Less {
            best = i;
        }
    }
    Some(best)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::attrs::{
        AsPathSegment, AsPathSegmentType, Origin, PathAttribute,
    };
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::Duration;

    fn base(asns: Vec<u32>) -> Vec<PathAttribute> {
        vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(vec![AsPathSegment {
                seg_type: AsPathSegmentType::AsSequence,
                asns,
            }]),
            PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
        ]
    }

    fn route(
        peer_id: u32,
        peer_asn: u32,
        local_asn: u32,
        attrs: Vec<PathAttribute>,
    ) -> StoredRoute {
        StoredRoute::new(
            attrs,
            peer_id,
            peer_asn,
            local_asn,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, peer_id as u8)),
            Ipv4Addr::new(10, 0, 0, peer_id as u8),
        )
    }

    #[test]
    fn local_pref_higher_wins() {
        let mut a = base(vec![65001]);
        a.push(PathAttribute::LocalPref(100));
        let mut b = base(vec![65001]);
        b.push(PathAttribute::LocalPref(200));
        let cands = vec![route(1, 65001, 65000, a), route(2, 65001, 65000, b)];
        assert_eq!(select_best(&cands), Some(1));
    }

    #[test]
    fn shorter_as_path_wins() {
        let cands = vec![
            route(1, 65001, 65000, base(vec![65001, 65002, 65003])),
            route(2, 65001, 65000, base(vec![65001])),
        ];
        assert_eq!(select_best(&cands), Some(1));
    }

    #[test]
    fn lower_origin_wins() {
        let mut a = base(vec![65001]);
        // Replace ORIGIN
        a[0] = PathAttribute::Origin(Origin::Egp);
        let mut b = base(vec![65001]);
        b[0] = PathAttribute::Origin(Origin::Igp);
        let cands = vec![route(1, 65001, 65000, a), route(2, 65001, 65000, b)];
        assert_eq!(select_best(&cands), Some(1));
    }

    #[test]
    fn lower_med_wins_within_same_neighbor_as() {
        let mut a = base(vec![65001, 65002]);
        a.push(PathAttribute::MultiExitDisc(200));
        let mut b = base(vec![65001, 65002]);
        b.push(PathAttribute::MultiExitDisc(50));
        let cands = vec![route(1, 65001, 65000, a), route(2, 65001, 65000, b)];
        assert_eq!(select_best(&cands), Some(1));
    }

    #[test]
    fn med_not_compared_across_neighbor_as() {
        // First AS in AS_PATH differs; MED comparison must be
        // skipped. Both routes are eBGP with the same LP / origin
        // / path length, so we fall through to step 8 (oldest)
        // and then step 9 (router-id). Force identical arrival
        // times so router-id fires.
        let mut a_attrs = base(vec![65001]);
        a_attrs.push(PathAttribute::MultiExitDisc(50));
        let mut b_attrs = base(vec![65002]);
        b_attrs.push(PathAttribute::MultiExitDisc(200));
        let mut a = route(2, 65001, 65000, a_attrs);
        let mut b = route(1, 65002, 65000, b_attrs);
        let now = std::time::Instant::now();
        a.received_at = now;
        b.received_at = now;
        // peer 1 has router-id 10.0.0.1, peer 2 has 10.0.0.2; 1 wins.
        let cands = vec![a, b];
        assert_eq!(select_best(&cands), Some(1));
    }

    #[test]
    fn ebgp_beats_ibgp() {
        let cands = vec![
            // iBGP (peer_asn == local_asn)
            route(1, 65000, 65000, base(vec![65001])),
            // eBGP
            route(2, 65001, 65000, base(vec![65001])),
        ];
        assert_eq!(select_best(&cands), Some(1));
    }

    #[test]
    fn oldest_wins_when_otherwise_tied() {
        let now = std::time::Instant::now();
        let mut a = route(2, 65001, 65000, base(vec![65001]));
        let mut b = route(1, 65001, 65000, base(vec![65001]));
        // Force a older than b.
        a.received_at = now - Duration::from_secs(60);
        b.received_at = now;
        // a wins (oldest), index 0.
        let cands = vec![a, b];
        assert_eq!(select_best(&cands), Some(0));
    }

    #[test]
    fn lowest_router_id_breaks_tie() {
        // Same arrival time so we fall through to router-id.
        let now = std::time::Instant::now();
        let mut a = route(5, 65001, 65000, base(vec![65001]));
        let mut b = route(2, 65001, 65000, base(vec![65001]));
        a.received_at = now;
        b.received_at = now;
        // peer 2 has router-id 10.0.0.2, peer 5 has 10.0.0.5; 2 wins.
        let cands = vec![a, b];
        assert_eq!(select_best(&cands), Some(1));
    }

    #[test]
    fn neighbor_address_is_final_tiebreaker() {
        // Engineer a tie all the way down to peer_address. We
        // override router-id to the same value so step 9 doesn't
        // fire.
        let now = std::time::Instant::now();
        let mut a = route(5, 65001, 65000, base(vec![65001]));
        let mut b = route(2, 65001, 65000, base(vec![65001]));
        a.received_at = now;
        b.received_at = now;
        a.peer_router_id = Ipv4Addr::new(10, 0, 0, 99);
        b.peer_router_id = Ipv4Addr::new(10, 0, 0, 99);
        // peer_address comparison: 10.0.0.5 vs 10.0.0.2 → b wins.
        let cands = vec![a, b];
        assert_eq!(select_best(&cands), Some(1));
    }

    #[test]
    fn empty_candidates_returns_none() {
        let cands: Vec<StoredRoute> = vec![];
        assert_eq!(select_best(&cands), None);
    }

    #[test]
    fn single_candidate_wins_trivially() {
        let cands = vec![route(1, 65001, 65000, base(vec![65001]))];
        assert_eq!(select_best(&cands), Some(0));
    }

    #[test]
    fn local_pref_overrides_as_path_length() {
        // Even though `b` has a longer AS_PATH, its LP is higher
        // and LP is rule 1 — must win.
        let mut a = base(vec![65001]);
        a.push(PathAttribute::LocalPref(100));
        let mut b = base(vec![65001, 65002, 65003, 65004]);
        b.push(PathAttribute::LocalPref(500));
        let cands = vec![route(1, 65001, 65000, a), route(2, 65001, 65000, b)];
        assert_eq!(select_best(&cands), Some(1));
    }
}
