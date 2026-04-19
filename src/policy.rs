//! Import / export policy.
//!
//! The v1 policy primitive is intentionally tiny:
//!
//! - [`Policy::AcceptAll`] — pass everything through unchanged.
//! - [`Policy::DenyAll`] — drop everything.
//! - [`Policy::PrefixFilter`] — accept only routes whose prefix
//!   matches one of the entries in the filter list.
//!
//! That's enough to:
//!
//! 1. Stand up a default-deny eBGP peer per RFC 8212 (use
//!    [`Policy::DenyAll`] when the operator hasn't configured
//!    one explicitly).
//! 2. Restrict a peer to a known list of prefixes (typical for an
//!    upstream that only announces its allocations).
//! 3. Allow everything from a trusted iBGP peer.
//!
//! The policy DSL grows in v2 (AS-path filters, set-actions for
//! local-pref/MED/communities, route-maps, etc.). For v1 the
//! priority is "bgpd doesn't accidentally accept the full
//! Internet from a misconfigured upstream", which the
//! AcceptAll/DenyAll/PrefixFilter trio covers.

use crate::adj_rib::StoredRoute;
use crate::packet::update::{Prefix4, Prefix6};

/// A single import/export policy. Same shape for both directions
/// — the difference is just which side calls [`apply_v4`] /
/// [`apply_v6`].
#[derive(Debug, Clone)]
pub enum Policy {
    AcceptAll,
    DenyAll,
    PrefixFilter {
        v4: Vec<Prefix4>,
        v6: Vec<Prefix6>,
    },
}

impl Default for Policy {
    fn default() -> Self {
        // RFC 8212: an EBGP session with no explicit policy
        // accepts and advertises nothing. Higher-level config
        // overrides this for iBGP and for explicitly-configured
        // policies.
        Policy::DenyAll
    }
}

impl Policy {
    /// Apply this policy to a single v4 route. Returns the route
    /// (possibly unchanged) if it's permitted, or `None` if the
    /// policy filters it out.
    pub fn apply_v4(&self, prefix: &Prefix4, route: StoredRoute) -> Option<StoredRoute> {
        match self {
            Policy::AcceptAll => Some(route),
            Policy::DenyAll => None,
            Policy::PrefixFilter { v4, .. } => {
                if v4.iter().any(|allowed| allowed == prefix) {
                    Some(route)
                } else {
                    None
                }
            }
        }
    }

    pub fn apply_v6(&self, prefix: &Prefix6, route: StoredRoute) -> Option<StoredRoute> {
        match self {
            Policy::AcceptAll => Some(route),
            Policy::DenyAll => None,
            Policy::PrefixFilter { v6, .. } => {
                if v6.iter().any(|allowed| allowed == prefix) {
                    Some(route)
                } else {
                    None
                }
            }
        }
    }
}

/// Per-peer policy bundle: separate import (Adj-RIB-In ←
/// received) and export (Adj-RIB-Out → advertised) sides.
#[derive(Debug, Clone, Default)]
pub struct PeerPolicy {
    pub import: Policy,
    pub export: Policy,
}

impl PeerPolicy {
    /// Convenience constructor for an iBGP peer where the v1
    /// default is "trust everything" because iBGP routes have
    /// already been filtered at the eBGP edge.
    pub fn ibgp_default() -> Self {
        PeerPolicy {
            import: Policy::AcceptAll,
            export: Policy::AcceptAll,
        }
    }

    /// RFC 8212 default for an eBGP peer with no explicit policy.
    pub fn ebgp_default_deny() -> Self {
        PeerPolicy {
            import: Policy::DenyAll,
            export: Policy::DenyAll,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::attrs::{Origin, PathAttribute};
    use std::net::{IpAddr, Ipv4Addr};

    fn route() -> StoredRoute {
        StoredRoute::new(
            vec![PathAttribute::Origin(Origin::Igp)],
            1,
            65001,
            65000,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
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
    fn accept_all_passes_through() {
        let p = p4(192, 0, 2, 0, 24);
        let result = Policy::AcceptAll.apply_v4(&p, route());
        assert!(result.is_some());
    }

    #[test]
    fn deny_all_drops_everything() {
        let p = p4(192, 0, 2, 0, 24);
        let result = Policy::DenyAll.apply_v4(&p, route());
        assert!(result.is_none());
    }

    #[test]
    fn prefix_filter_admits_only_listed_v4() {
        let allowed = vec![p4(192, 0, 2, 0, 24), p4(198, 51, 100, 0, 24)];
        let policy = Policy::PrefixFilter {
            v4: allowed,
            v6: Vec::new(),
        };
        assert!(policy.apply_v4(&p4(192, 0, 2, 0, 24), route()).is_some());
        assert!(policy.apply_v4(&p4(10, 0, 0, 0, 8), route()).is_none());
    }

    #[test]
    fn ebgp_default_is_deny_all() {
        let pp = PeerPolicy::ebgp_default_deny();
        assert!(matches!(pp.import, Policy::DenyAll));
        assert!(matches!(pp.export, Policy::DenyAll));
    }

    #[test]
    fn ibgp_default_is_accept_all() {
        let pp = PeerPolicy::ibgp_default();
        assert!(matches!(pp.import, Policy::AcceptAll));
        assert!(matches!(pp.export, Policy::AcceptAll));
    }

    #[test]
    fn rfc_8212_default_policy_is_deny() {
        let pp = PeerPolicy::default();
        assert!(matches!(pp.import, Policy::DenyAll));
        assert!(matches!(pp.export, Policy::DenyAll));
    }
}
