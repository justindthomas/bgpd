//! Per-peer import / export policy.
//!
//! After the route-map migration, policy is one of three things:
//!
//! - [`Policy::AcceptAll`] — pass everything through unchanged.
//! - [`Policy::DenyAll`] — drop everything.
//! - [`Policy::RouteMap`] — walk a compiled route-map (with the
//!   universal subset plus bgpd's match extras: community,
//!   as_path_contains, local_pref).
//!
//! YAML side: `import_policy` / `export_policy` is a single
//! string. `accept-all` and `deny-all` resolve to the keyword
//! variants; any other string is looked up in the top-level
//! `route_maps:` block.
//!
//! RFC 8212: an eBGP peer with no explicit policy gets DenyAll
//! both directions; iBGP defaults to AcceptAll.

use ribd_proto::Source;

use crate::adj_rib::OriginClass;
use crate::adj_rib::StoredRoute;
use crate::config::BgpRouteMap;
use crate::packet::attrs::PathAttribute;
use crate::packet::update::{Prefix4, Prefix6};

/// A single import/export policy. Same shape for both directions
/// — the difference is just which side calls
/// [`Policy::permits_v4`] / [`Policy::permits_v6`].
#[derive(Debug, Clone)]
pub enum Policy {
    AcceptAll,
    DenyAll,
    /// Reference to a compiled top-level route-map. The map is
    /// cloned in here at peer-spawn / reload time so the policy
    /// is self-contained.
    RouteMap(BgpRouteMap),
}

impl Default for Policy {
    fn default() -> Self {
        // RFC 8212: an eBGP session with no explicit policy
        // accepts and advertises nothing. Higher-level config
        // overrides this for iBGP and for explicitly-configured
        // policies.
        Policy::DenyAll
    }
}

impl Policy {
    /// Whether this policy permits a v4 prefix carrying these
    /// path attributes. The path attributes are needed so route-
    /// map evaluation can consult BGP-specific match extras
    /// (community, as_path_contains, local_pref).
    ///
    /// `source` is the route's projected ribd `Source` — used by
    /// the route-map's universal `source:` clause. For peer-
    /// learned routes, callers pass `Bgp` or `BgpInternal`; for
    /// locally-originated routes the projection from
    /// `OriginClass` is the canonical mapping.
    pub fn permits_v4(
        &self,
        prefix: &Prefix4,
        path_attrs: &[PathAttribute],
        source: Source,
    ) -> bool {
        match self {
            Policy::AcceptAll => true,
            Policy::DenyAll => false,
            Policy::RouteMap(map) => {
                let pfx = ribd_proto::Prefix::v4(prefix.addr, prefix.len);
                evaluate_route_map(map, pfx, source, path_attrs)
            }
        }
    }

    pub fn permits_v6(
        &self,
        prefix: &Prefix6,
        path_attrs: &[PathAttribute],
        source: Source,
    ) -> bool {
        match self {
            Policy::AcceptAll => true,
            Policy::DenyAll => false,
            Policy::RouteMap(map) => {
                let pfx = ribd_proto::Prefix::v6(prefix.addr, prefix.len);
                evaluate_route_map(map, pfx, source, path_attrs)
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

/// Resolve a YAML policy name to a runtime [`Policy`]. Accepts
/// the reserved keywords `"accept-all"` / `"deny-all"`; anything
/// else is looked up in `route_maps`. An unknown name returns
/// `None` so callers can fall back to the default.
pub fn resolve_policy_name(
    name: &str,
    route_maps: &std::collections::HashMap<String, BgpRouteMap>,
) -> Option<Policy> {
    match name {
        "accept-all" => Some(Policy::AcceptAll),
        "deny-all" => Some(Policy::DenyAll),
        other => route_maps.get(other).cloned().map(Policy::RouteMap),
    }
}

/// Project the source of a peer-learned [`StoredRoute`] to a
/// ribd [`Source`] for route-map evaluation. Locally-originated
/// routes use their `OriginClass` source; peer-learned routes
/// fall back to `Bgp` or `BgpInternal` depending on session type.
pub fn source_for_route(stored: &StoredRoute) -> Source {
    match stored.origin_class {
        OriginClass::Connected => Source::Connected,
        OriginClass::Static | OriginClass::Aggregate => Source::Static,
        OriginClass::Redistribute(s) => s,
        OriginClass::PeerLearned => {
            if stored.is_ebgp {
                Source::Bgp
            } else {
                Source::BgpInternal
            }
        }
    }
}

/// Walk the statements of a compiled bgpd route-map. Mirrors the
/// evaluator embedded in `instance::evaluate_route_map`; kept
/// separate so [`Policy::permits_v4`] / [`Policy::permits_v6`]
/// have a self-contained call path. No-statement-matched defaults
/// to deny.
fn evaluate_route_map(
    map: &BgpRouteMap,
    prefix: ribd_proto::Prefix,
    source: Source,
    path_attrs: &[PathAttribute],
) -> bool {
    struct Ctx {
        prefix: ribd_proto::Prefix,
        source: Source,
    }
    impl ribd_routemap::MatchContext for Ctx {
        fn prefix(&self) -> ribd_proto::Prefix {
            self.prefix
        }
        fn source(&self) -> Source {
            self.source
        }
    }
    let ctx = Ctx { prefix, source };
    for stmt in &map.statements {
        if !stmt.match_.evaluate_universal(&ctx) {
            continue;
        }
        if !crate::route_map::evaluate_bgp_match(&stmt.match_.extra, path_attrs) {
            continue;
        }
        return matches!(stmt.action, ribd_routemap::Action::Permit);
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn p4(a: u8, b: u8, c: u8, d: u8, len: u8) -> Prefix4 {
        Prefix4 {
            addr: Ipv4Addr::new(a, b, c, d),
            len,
        }
    }

    fn compile_map(yaml: &str) -> BgpRouteMap {
        let parsed: ribd_routemap::RouteMapYaml<
            crate::route_map::BgpMatchYaml,
            crate::route_map::BgpSetYaml,
        > = serde_yaml::from_str(yaml).unwrap();
        crate::route_map::compile(parsed).unwrap()
    }

    #[test]
    fn accept_all_passes_through() {
        let p = Policy::AcceptAll;
        assert!(p.permits_v4(&p4(10, 0, 0, 0, 8), &[], Source::Bgp));
    }

    #[test]
    fn deny_all_drops_everything() {
        let p = Policy::DenyAll;
        assert!(!p.permits_v4(&p4(10, 0, 0, 0, 8), &[], Source::Bgp));
    }

    #[test]
    fn ebgp_default_is_deny_all() {
        let pol = PeerPolicy::ebgp_default_deny();
        assert!(matches!(pol.import, Policy::DenyAll));
        assert!(matches!(pol.export, Policy::DenyAll));
    }

    #[test]
    fn ibgp_default_is_accept_all() {
        let pol = PeerPolicy::ibgp_default();
        assert!(matches!(pol.import, Policy::AcceptAll));
        assert!(matches!(pol.export, Policy::AcceptAll));
    }

    #[test]
    fn rfc_8212_default_policy_is_deny() {
        // Anything that just calls Policy::default() should land
        // on DenyAll. The eBGP/iBGP distinction lives in
        // PeerPolicy::*_default helpers and the spawn path picks
        // the right one.
        let p = Policy::default();
        assert!(matches!(p, Policy::DenyAll));
    }

    #[test]
    fn route_map_filters_by_prefix_list() {
        // ribd-routemap's prefix_list is exact-match in v1; range
        // semantics belong with `prefix_length:`. Use an exact
        // match here so the test reflects current semantics.
        let map = compile_map(
            r#"
name: only-23
statements:
  - seq: 10
    action: permit
    match:
      prefix_list: ["23.0.0.0/8"]
  - seq: 20
    action: deny
"#,
        );
        let p = Policy::RouteMap(map);
        assert!(p.permits_v4(&p4(23, 0, 0, 0, 8), &[], Source::Bgp));
        assert!(!p.permits_v4(&p4(23, 1, 2, 0, 24), &[], Source::Bgp));
        assert!(!p.permits_v4(&p4(10, 0, 0, 0, 8), &[], Source::Bgp));
    }

    #[test]
    fn resolve_policy_name_handles_keywords_and_lookup() {
        let mut maps = std::collections::HashMap::new();
        maps.insert(
            "from-upstream".to_string(),
            compile_map(
                r#"
name: from-upstream
statements:
  - seq: 10
    action: permit
"#,
            ),
        );
        assert!(matches!(
            resolve_policy_name("accept-all", &maps),
            Some(Policy::AcceptAll)
        ));
        assert!(matches!(
            resolve_policy_name("deny-all", &maps),
            Some(Policy::DenyAll)
        ));
        assert!(matches!(
            resolve_policy_name("from-upstream", &maps),
            Some(Policy::RouteMap(_))
        ));
        assert!(resolve_policy_name("nonexistent", &maps).is_none());
    }
}
