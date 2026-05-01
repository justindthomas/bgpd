//! bgpd-specific route-map extras.
//!
//! Sits on top of `ribd-routemap` and contributes BGP-only match
//! clauses (and, eventually, set clauses) that ride alongside the
//! universal subset via serde's `flatten`. Operators write a
//! single map at the top level:
//!
//! ```yaml
//! route_maps:
//!   - name: from-upstream
//!     statements:
//!       - seq: 10
//!         action: permit
//!         match:
//!           prefix_list: [10.0.0.0/8]      # universal
//!           community: ["65000:100"]       # bgpd-specific
//!           local_pref: 200                # bgpd-specific
//! ```
//!
//! The route-map evaluator walks the universal clauses first
//! (cheaper) and then asks this module to evaluate the BGP-only
//! extras. A statement matches only if both halves agree.
//!
//! v1 ships **match-only** for BGP extras. Set-clause application
//! (community_add / set local_pref / etc.) parses but is not yet
//! applied to the advertised path attributes — that's a follow-up
//! once we have a clean mutation point in the advertise pipeline.

use serde::Deserialize;
use thiserror::Error;

use crate::packet::attrs::PathAttribute;

// ---- on-disk YAML types (the `E` parameter for ribd-routemap) ----

/// BGP-specific match extras. Flattened into `MatchYaml<E>` so the
/// keys appear at the same indentation as the universal ones.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct BgpMatchYaml {
    /// Match if the route's AS_PATH contains this ASN anywhere.
    /// Implements a subset of FRR's `match as-path` without
    /// requiring a regex engine; for full regex see v2.
    #[serde(default)]
    pub as_path_contains: Option<u32>,
    /// Match if the route's COMMUNITIES attribute contains *every*
    /// listed community. Communities are written as
    /// `<asn>:<value>` decimal strings (e.g. `"65000:100"`).
    /// Empty list = no constraint.
    #[serde(default)]
    pub community: Vec<String>,
    /// Match if the route's LOCAL_PREF equals this value.
    #[serde(default)]
    pub local_pref: Option<u32>,
}

/// BGP-specific set extras. Parsed from YAML; v1 does not yet
/// apply these to outbound path attributes.
#[derive(Debug, Default, Clone, Deserialize)]
pub struct BgpSetYaml {
    /// Append these communities to the route's COMMUNITIES
    /// attribute on advertise.
    #[serde(default)]
    pub community_add: Vec<String>,
    /// Remove these communities (if present).
    #[serde(default)]
    pub community_remove: Vec<String>,
    /// Replace LOCAL_PREF with this value.
    #[serde(default)]
    pub local_pref: Option<u32>,
}

// ---- compiled / runtime types ----

/// Compiled form of [`BgpMatchYaml`] — communities pre-parsed to
/// their wire-format `u32` so evaluation is allocation-free.
#[derive(Debug, Default, Clone)]
pub struct BgpMatch {
    pub as_path_contains: Option<u32>,
    pub community: Vec<u32>,
    pub local_pref: Option<u32>,
}

/// Compiled form of [`BgpSetYaml`].
#[derive(Debug, Default, Clone)]
pub struct BgpSet {
    pub community_add: Vec<u32>,
    pub community_remove: Vec<u32>,
    pub local_pref: Option<u32>,
}

#[derive(Debug, Error)]
pub enum CompileError {
    #[error("invalid community {0:?}: expected `<asn>:<value>` with both 16-bit decimal")]
    BadCommunity(String),
}

// ---- compile impls ----

impl BgpMatchYaml {
    pub fn compile(self) -> Result<BgpMatch, CompileError> {
        let community = self
            .community
            .iter()
            .map(|s| parse_community(s))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(BgpMatch {
            as_path_contains: self.as_path_contains,
            community,
            local_pref: self.local_pref,
        })
    }
}

impl BgpSetYaml {
    pub fn compile(self) -> Result<BgpSet, CompileError> {
        let community_add = self
            .community_add
            .iter()
            .map(|s| parse_community(s))
            .collect::<Result<Vec<_>, _>>()?;
        let community_remove = self
            .community_remove
            .iter()
            .map(|s| parse_community(s))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(BgpSet {
            community_add,
            community_remove,
            local_pref: self.local_pref,
        })
    }
}

/// Compile a `RouteMapYaml<BgpMatchYaml, BgpSetYaml>` — what bgpd
/// reads from the top-level `route_maps:` block — into the runtime
/// `RouteMap<BgpMatch, BgpSet>` form. Universal clauses go through
/// the shared crate; BGP-specific clauses are compiled here.
pub fn compile(
    yaml: ribd_routemap::RouteMapYaml<BgpMatchYaml, BgpSetYaml>,
) -> Result<ribd_routemap::RouteMap<BgpMatch, BgpSet>, RouteMapCompileError> {
    use ribd_routemap::{Match, Set, Statement};

    let universal = yaml.compile().map_err(RouteMapCompileError::Universal)?;
    let mut statements = Vec::with_capacity(universal.statements.len());
    for stmt in universal.statements {
        let match_extra = stmt
            .match_
            .extra
            .compile()
            .map_err(RouteMapCompileError::Bgp)?;
        let set_extra = stmt
            .set
            .extra
            .compile()
            .map_err(RouteMapCompileError::Bgp)?;
        statements.push(Statement {
            seq: stmt.seq,
            action: stmt.action,
            match_: Match {
                prefix_list: stmt.match_.prefix_list,
                prefix_length: stmt.match_.prefix_length,
                source: stmt.match_.source,
                tag: stmt.match_.tag,
                metric: stmt.match_.metric,
                metric_range: stmt.match_.metric_range,
                next_hop: stmt.match_.next_hop,
                next_hop_in: stmt.match_.next_hop_in,
                extra: match_extra,
            },
            set: Set {
                metric: stmt.set.metric,
                metric_add: stmt.set.metric_add,
                tag: stmt.set.tag,
                next_hop: stmt.set.next_hop,
                extra: set_extra,
            },
        });
    }
    Ok(ribd_routemap::RouteMap {
        name: universal.name,
        statements,
    })
}

#[derive(Debug, Error)]
pub enum RouteMapCompileError {
    #[error("universal clause: {0}")]
    Universal(ribd_routemap::CompileError),
    #[error("bgp extra: {0}")]
    Bgp(CompileError),
}

// ---- evaluation ----

/// Evaluate the BGP-specific match extras against a route's path
/// attributes. Returns true iff every populated clause holds.
/// Caller AND-combines this with the universal evaluator.
pub fn evaluate_bgp_match(m: &BgpMatch, path_attrs: &[PathAttribute]) -> bool {
    if let Some(target) = m.as_path_contains {
        let mut found = false;
        for attr in path_attrs {
            if let PathAttribute::AsPath(segs) = attr {
                if segs.iter().any(|s| s.asns.contains(&target)) {
                    found = true;
                    break;
                }
            }
        }
        if !found {
            return false;
        }
    }
    if !m.community.is_empty() {
        let route_communities: Vec<u32> = path_attrs
            .iter()
            .filter_map(|a| match a {
                PathAttribute::Communities(c) => Some(c.clone()),
                _ => None,
            })
            .flatten()
            .collect();
        if !m.community.iter().all(|c| route_communities.contains(c)) {
            return false;
        }
    }
    if let Some(want) = m.local_pref {
        let actual = path_attrs.iter().find_map(|a| match a {
            PathAttribute::LocalPref(v) => Some(*v),
            _ => None,
        });
        if actual != Some(want) {
            return false;
        }
    }
    true
}

// ---- helpers ----

/// Parse a `"asn:value"` decimal community string into a 32-bit
/// wire form (`asn << 16 | value`). Both halves must fit in 16
/// bits; we don't yet support the 32-bit extended-community form.
fn parse_community(s: &str) -> Result<u32, CompileError> {
    let (l, r) = s.split_once(':').ok_or_else(|| CompileError::BadCommunity(s.into()))?;
    let asn: u16 = l.parse().map_err(|_| CompileError::BadCommunity(s.into()))?;
    let val: u16 = r.parse().map_err(|_| CompileError::BadCommunity(s.into()))?;
    Ok(((asn as u32) << 16) | val as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::attrs::{AsPathSegment, AsPathSegmentType, PathAttribute};

    #[test]
    fn parse_community_round_trip() {
        assert_eq!(parse_community("65000:100").unwrap(), 65000u32 << 16 | 100);
        assert_eq!(parse_community("0:0").unwrap(), 0);
        assert!(parse_community("65000").is_err());
        assert!(parse_community("notanumber:100").is_err());
        assert!(parse_community("65000:99999999").is_err());
    }

    #[test]
    fn community_match_requires_all_listed() {
        let m = BgpMatch {
            community: vec![0x00010001, 0x00020002],
            ..Default::default()
        };
        let with_both = vec![PathAttribute::Communities(vec![
            0x00010001, 0x00020002, 0x00030003,
        ])];
        assert!(evaluate_bgp_match(&m, &with_both));

        let with_one = vec![PathAttribute::Communities(vec![0x00010001])];
        assert!(!evaluate_bgp_match(&m, &with_one));

        let none = vec![];
        assert!(!evaluate_bgp_match(&m, &none));
    }

    #[test]
    fn empty_community_is_no_constraint() {
        let m = BgpMatch::default();
        assert!(evaluate_bgp_match(&m, &[]));
    }

    #[test]
    fn as_path_contains_matches() {
        let m = BgpMatch {
            as_path_contains: Some(64500),
            ..Default::default()
        };
        let attrs = vec![PathAttribute::AsPath(vec![AsPathSegment {
            seg_type: AsPathSegmentType::AsSequence,
            asns: vec![65000, 64500, 65001],
        }])];
        assert!(evaluate_bgp_match(&m, &attrs));

        let other = vec![PathAttribute::AsPath(vec![AsPathSegment {
            seg_type: AsPathSegmentType::AsSequence,
            asns: vec![65000, 65001],
        }])];
        assert!(!evaluate_bgp_match(&m, &other));
    }

    #[test]
    fn local_pref_exact_match() {
        let m = BgpMatch {
            local_pref: Some(200),
            ..Default::default()
        };
        assert!(evaluate_bgp_match(
            &m,
            &[PathAttribute::LocalPref(200)]
        ));
        assert!(!evaluate_bgp_match(
            &m,
            &[PathAttribute::LocalPref(100)]
        ));
        assert!(!evaluate_bgp_match(&m, &[]));
    }

    #[test]
    fn compile_bgp_match_yaml_round_trip() {
        let yaml = BgpMatchYaml {
            as_path_contains: Some(65000),
            community: vec!["65000:100".into(), "65001:200".into()],
            local_pref: Some(150),
        };
        let compiled = yaml.compile().unwrap();
        assert_eq!(compiled.as_path_contains, Some(65000));
        assert_eq!(compiled.community.len(), 2);
        assert_eq!(compiled.community[0], 65000u32 << 16 | 100);
        assert_eq!(compiled.local_pref, Some(150));
    }

    #[test]
    fn compile_full_route_map_with_bgp_extras() {
        let yaml: ribd_routemap::RouteMapYaml<BgpMatchYaml, BgpSetYaml> =
            serde_yaml::from_str(
                r#"
name: from-upstream
statements:
  - seq: 10
    action: permit
    match:
      prefix_list: ["10.0.0.0/8"]
      community: ["65000:100"]
      local_pref: 200
"#,
            )
            .unwrap();
        let map = compile(yaml).unwrap();
        assert_eq!(map.statements.len(), 1);
        let s = &map.statements[0];
        assert_eq!(s.match_.prefix_list.len(), 1);
        assert_eq!(s.match_.extra.community.len(), 1);
        assert_eq!(s.match_.extra.local_pref, Some(200));
    }
}
