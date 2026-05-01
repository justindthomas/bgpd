//! Configuration types for bgpd.
//!
//! The on-disk format is YAML at `/etc/bgpd/config.yaml`; this
//! module deserializes the `bgp:` block. Mirrors `ospfd::config`.
//!
//! ## Field set
//!
//! The v1 field set is intentionally minimal. Extra fields needed
//! for production upstream sessions — TCP_MD5SIG `password`,
//! custom `hold_time`, address-family negotiation lists — will be
//! added in a follow-up once there are real peers to test them
//! against. For lab and CI use against ExaBGP / GoBGP the current
//! set is sufficient.

use std::collections::HashMap;
use std::path::Path;

use ribd_routemap::RouteMapYaml;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::route_map::{BgpMatch, BgpMatchYaml, BgpSet, BgpSetYaml};

/// bgpd's compiled route-map type alias — the universal types
/// parameterized over our BGP-specific match and set extras. The
/// instance and config layers traffic in this throughout.
pub type BgpRouteMap = ribd_routemap::RouteMap<BgpMatch, BgpSet>;

/// Top-level BGP daemon configuration. Loaded from the `bgp:`
/// section of the YAML config file. All fields default-empty so
/// an absent `bgp:` block parses as "BGP disabled".
///
/// `enabled` is intentionally separate from `local_asn`: an
/// operator can stage an ASN + router-id in YAML without flipping
/// BGP on yet, and `bgpd query summary` will report the
/// configured identity even when no peers are running.
#[derive(Debug, Clone, Default)]
pub struct BgpDaemonConfig {
    /// Whether to actually start peer sessions. When false, the
    /// daemon parks idle but the control socket still binds and
    /// reports configured identity through `bgpd query`.
    pub enabled: bool,
    /// Local autonomous system number (4-octet, RFC 6793).
    pub local_asn: u32,
    /// BGP router-id — the speaker's identity in OPEN messages and
    /// best-path tiebreaks. Conventionally a loopback IPv4 address.
    pub router_id: Option<std::net::Ipv4Addr>,
    /// Configured peers. v1 supports IPv4 and IPv6 transports.
    pub peers: Vec<BgpPeerConfig>,
    /// Static IPv4 prefixes to originate from BGP. Equivalent to
    /// FRR's `network <prefix>` under address-family ipv4 unicast.
    /// Each prefix is announced to every Established peer once
    /// the session comes up.
    pub announced_prefixes_v4: Vec<crate::packet::update::Prefix4>,
    /// Static IPv6 prefixes to originate from BGP.
    pub announced_prefixes_v6: Vec<crate::packet::update::Prefix6>,
    /// Aggregate (summary) addresses. When ≥1 more-specific prefix
    /// exists in the Loc-RIB for a configured aggregate, bgpd
    /// synthesizes a covering route with `OriginClass::Aggregate`.
    /// If `summary_only` is set, the more-specifics are suppressed
    /// in Adj-RIB-Out.
    pub aggregates_v4: Vec<AggregateConfig>,
    pub aggregates_v6: Vec<AggregateConfig>,
    /// Listen address for incoming BGP connections (passive open).
    /// When set, bgpd binds a TCP listener and accepts
    /// connections from configured peers. Connections from unknown
    /// source IPs are rejected with a NOTIFICATION.
    pub listen_address: Option<String>,
    /// Compiled route-maps, keyed by name. Built from the
    /// top-level `route_maps:` YAML block at config load time.
    /// Per-peer redistribute entries reference these by name; the
    /// advertise path looks them up to permit/deny redistributed
    /// routes. v1: bgpd uses universal-only (`NoExtras`) clauses;
    /// task #7 adds bgpd-specific match/set extras.
    pub route_maps: HashMap<String, BgpRouteMap>,
}

/// Configuration for one aggregate-address.
#[derive(Debug, Clone)]
pub struct AggregateConfig {
    pub prefix: String,
    pub summary_only: bool,
}

/// One per-peer redistribute rule. Describes what kind of
/// ribd-installed route to advertise to this peer and (optionally)
/// which route-map filters/transforms it.
#[derive(Debug, Clone)]
pub struct RedistributeRule {
    pub protocol: RedistributeProtocol,
    pub route_map: Option<String>,
}

/// Which protocol's routes to redistribute. Maps to the protocol
/// strings accepted in YAML (`connected`, `ospf`, `static`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RedistributeProtocol {
    Connected,
    Ospf,
    Static,
}

/// Per-peer configuration. Captures the operationally-meaningful
/// knobs only; advanced policy lives on the `policy` field once
/// `bgpd::policy` exists.
#[derive(Debug, Clone)]
pub struct BgpPeerConfig {
    /// Peer's IP address (the TCP destination).
    pub address: std::net::IpAddr,
    /// Peer's TCP port. Defaults to the IANA-assigned 179. Tests
    /// override this to use ephemeral ports against a fake peer.
    pub port: Option<u16>,
    /// Remote AS — used to classify the session as eBGP or iBGP.
    pub remote_asn: u32,
    /// Local source address. Typically a loopback for iBGP, the
    /// connected interface address for eBGP. Optional; if unset
    /// the OS picks one.
    pub source_address: Option<std::net::IpAddr>,
    /// TCP MD5 password (RFC 2385) for the session. None means no
    /// MD5. Required by virtually every real upstream provider.
    pub password: Option<String>,
    /// Hold time advertised in OPEN. Defaults to 90s if unset
    /// (RFC 4271 §10).
    pub hold_time: Option<u16>,
    /// Address families to negotiate (RFC 4760). Empty = IPv4
    /// unicast only, matching the legacy single-AFI session.
    pub address_families: Vec<BgpAddressFamily>,
    /// Import policy — applied to every route received from this
    /// peer before it enters Adj-RIB-In. The string is either the
    /// reserved keyword `"accept-all"` / `"deny-all"`, or the name
    /// of a top-level `route_maps:` entry. Defaults to AcceptAll
    /// for iBGP and DenyAll for eBGP (RFC 8212).
    pub import_policy: Option<String>,
    /// Export policy — applied to every Loc-RIB winner before it's
    /// advertised to this peer. Same shape as `import_policy`.
    pub export_policy: Option<String>,
    /// Per-peer redistribute rules. Each rule names a protocol
    /// (`connected`/`ospf`/`static`) and an optional route-map.
    /// Routes from a protocol are advertised to this peer only if
    /// a rule for that protocol is present, and only if the
    /// referenced route-map (if any) permits them.
    pub redistribute: Vec<RedistributeRule>,
}

impl BgpPeerConfig {
    pub fn redistribute_connected(&self) -> bool {
        self.has_rule(RedistributeProtocol::Connected)
    }
    pub fn redistribute_ospf(&self) -> bool {
        self.has_rule(RedistributeProtocol::Ospf)
    }
    pub fn redistribute_static(&self) -> bool {
        self.has_rule(RedistributeProtocol::Static)
    }
    pub fn has_rule(&self, protocol: RedistributeProtocol) -> bool {
        self.redistribute.iter().any(|r| r.protocol == protocol)
    }
    /// Find the route-map name (if any) attached to the rule for
    /// `protocol`. Returns `None` either when the protocol has no
    /// rule (caller should already have filtered via `has_rule`)
    /// or when the rule doesn't reference a map.
    pub fn route_map_for(&self, protocol: RedistributeProtocol) -> Option<&str> {
        self.redistribute
            .iter()
            .find(|r| r.protocol == protocol)
            .and_then(|r| r.route_map.as_deref())
    }
}

/// Negotiated address family. v1 supports IPv4 and IPv6 unicast
/// only — VPNv4, EVPN, FlowSpec, etc. are explicitly v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BgpAddressFamily {
    Ipv4Unicast,
    Ipv6Unicast,
}

/// Errors the YAML loader can return.
#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("I/O reading {path}: {source}")]
    Io {
        path: String,
        #[source]
        source: std::io::Error,
    },
    #[error("YAML parse: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("invalid router_id {0}: {1}")]
    InvalidRouterId(String, std::net::AddrParseError),
    #[error("invalid peer_ip {0}: {1}")]
    InvalidPeerIp(String, std::net::AddrParseError),
    #[error("invalid CIDR prefix {0}")]
    InvalidPrefix(String),
    #[error("BGP config missing required field {0}")]
    MissingField(&'static str),
    #[error("unknown redistribute protocol {0}")]
    UnknownRedistributeProtocol(String),
    #[error("route-map {0}: {1}")]
    RouteMapCompile(String, crate::route_map::RouteMapCompileError),
    #[error("duplicate route-map name: {0}")]
    DuplicateRouteMapName(String),
}

/// On-disk shape of the `bgp:` block in the YAML config file.
/// Fields we don't yet honor are deserialized and ignored —
/// leaving them in the YAML doesn't break us.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct BgpYamlConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub asn: Option<u32>,
    #[serde(default)]
    pub router_id: Option<String>,
    #[serde(default)]
    pub peers: Vec<BgpPeerYaml>,
    /// Mixed v4/v6 prefix list (each entry is a CIDR string).
    /// Stable schema across releases.
    #[serde(default)]
    pub announced_prefixes: Vec<String>,
    #[serde(default)]
    pub listen_address: Option<String>,
    #[serde(default)]
    pub aggregate_addresses_v4: Vec<AggregateAddressYaml>,
    #[serde(default)]
    pub aggregate_addresses_v6: Vec<AggregateAddressYaml>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct AggregateAddressYaml {
    pub prefix: String,
    #[serde(default)]
    pub summary_only: bool,
}

/// A redistribute entry. The optional fields are ignored by bgpd
/// v1 — only the protocol matters.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct BgpRedistributeYaml {
    pub protocol: String,
    #[serde(default)]
    pub route_map: Option<String>,
    #[serde(default)]
    pub metric: Option<i32>,
}

/// On-disk shape of a single BGP peer entry.
#[derive(Debug, Clone, Default, Deserialize)]
pub struct BgpPeerYaml {
    #[serde(default)]
    pub name: String,
    pub peer_ip: String,
    pub peer_asn: u32,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub update_source: Option<String>,
    #[serde(default)]
    pub import_policy: Option<String>,
    #[serde(default)]
    pub export_policy: Option<String>,
    /// Per-peer redistribute list. Each entry has a `protocol`
    /// field — `connected`, `ospf`, or `static` are honored in
    /// v1. Routes from these protocols are advertised to this
    /// peer only; other peers must opt in via their own
    /// redistribute list.
    #[serde(default)]
    pub redistribute: Vec<BgpRedistributeYaml>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RouterYaml {
    #[serde(default)]
    pub bgp: BgpYamlConfig,
    /// Top-level route-maps shared across daemons (bgpd, ospfd,
    /// future producers). Each map is referenced by name from
    /// per-peer redistribute entries. bgpd parses these with its
    /// own match/set extras (community, as_path_contains,
    /// local_pref, etc.) so a single map can express both
    /// universal and BGP-specific clauses; ospfd reads the same
    /// top-level block with `NoExtras`.
    #[serde(default)]
    pub route_maps: Vec<RouteMapYaml<BgpMatchYaml, BgpSetYaml>>,
}

impl BgpDaemonConfig {
    /// Load `BgpDaemonConfig` from a YAML file. Returns an empty
    /// config (BGP disabled) if the file has no `bgp:` block.
    /// Errors on parse failure or invalid IPs. Also picks up the
    /// top-level `route_maps:` block if present.
    pub fn load_from_yaml(path: &Path) -> Result<Self, ConfigError> {
        let bytes = std::fs::read(path).map_err(|e| ConfigError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        let router: RouterYaml = serde_yaml::from_slice(&bytes)?;
        Self::from_router_yaml(router)
    }

    /// Build from a parsed `RouterYaml` so callers (main.rs,
    /// `reload_config`) get both the bgp block and the top-level
    /// route-maps in one shot. Tests that don't care about
    /// route-maps can keep using [`Self::from_yaml`].
    pub fn from_router_yaml(router: RouterYaml) -> Result<Self, ConfigError> {
        let mut bgp = Self::from_yaml(router.bgp)?;
        let mut maps: HashMap<String, BgpRouteMap> = HashMap::new();
        for m in router.route_maps {
            let name = m.name.clone();
            if maps.contains_key(&name) {
                return Err(ConfigError::DuplicateRouteMapName(name));
            }
            let compiled = crate::route_map::compile(m)
                .map_err(|e| ConfigError::RouteMapCompile(name.clone(), e))?;
            maps.insert(name, compiled);
        }
        bgp.route_maps = maps;
        Ok(bgp)
    }

    /// Convert an already-parsed `BgpYamlConfig` into the
    /// daemon's typed config. Split out so unit tests can drive
    /// it without going through the filesystem.
    ///
    /// Parses identity fields (asn, router_id) whether or not
    /// `enabled` is set so `bgpd query summary` can report the
    /// configured identity even in disabled mode. Peer parsing
    /// also runs in disabled mode so YAML validation errors
    /// surface early. The `enabled` field on the returned struct
    /// is what main.rs uses to decide whether to actually spawn
    /// peer tasks.
    ///
    /// Tests that need route-maps go through
    /// [`Self::from_router_yaml`] instead; this entry-point
    /// returns `route_maps` empty.
    pub fn from_yaml(yaml: BgpYamlConfig) -> Result<Self, ConfigError> {
        // Identity is optional in disabled mode — a truly empty
        // bgp: block parses as fully-default. Validation only
        // fires when fields are present.
        let local_asn = yaml.asn.unwrap_or(0);
        let router_id = match &yaml.router_id {
            Some(rid) => Some(
                rid.parse::<std::net::Ipv4Addr>()
                    .map_err(|e| ConfigError::InvalidRouterId(rid.clone(), e))?,
            ),
            None => None,
        };
        let mut peers = Vec::with_capacity(yaml.peers.len());
        for p in yaml.peers {
            let address = p
                .peer_ip
                .parse::<std::net::IpAddr>()
                .map_err(|e| ConfigError::InvalidPeerIp(p.peer_ip.clone(), e))?;
            let source_address = match p.update_source {
                Some(s) => Some(
                    s.parse::<std::net::IpAddr>()
                        .map_err(|e| ConfigError::InvalidPeerIp(s, e))?,
                ),
                None => None,
            };
            let mut redistribute = Vec::with_capacity(p.redistribute.len());
            for entry in p.redistribute {
                let protocol = match entry.protocol.as_str() {
                    "connected" => RedistributeProtocol::Connected,
                    "ospf" => RedistributeProtocol::Ospf,
                    "static" => RedistributeProtocol::Static,
                    other => {
                        return Err(ConfigError::UnknownRedistributeProtocol(
                            other.to_string(),
                        ))
                    }
                };
                redistribute.push(RedistributeRule {
                    protocol,
                    route_map: entry.route_map,
                });
            }
            peers.push(BgpPeerConfig {
                address,
                port: None,
                remote_asn: p.peer_asn,
                source_address,
                password: None,
                hold_time: None,
                address_families: Vec::new(),
                import_policy: p.import_policy,
                export_policy: p.export_policy,
                redistribute,
            });
        }
        // Parse announced_prefixes — a mixed list of CIDR
        // strings. Split into v4 and v6 buckets at parse time so
        // the rest of the daemon doesn't need to re-discriminate.
        let mut announced_v4 = Vec::new();
        let mut announced_v6 = Vec::new();
        for cidr in &yaml.announced_prefixes {
            let p: ipnet::IpNet = cidr
                .parse()
                .map_err(|_| ConfigError::InvalidPrefix(cidr.clone()))?;
            match p {
                ipnet::IpNet::V4(v4) => announced_v4.push(crate::packet::update::Prefix4 {
                    addr: v4.network(),
                    len: v4.prefix_len(),
                }),
                ipnet::IpNet::V6(v6) => announced_v6.push(crate::packet::update::Prefix6 {
                    addr: v6.network(),
                    len: v6.prefix_len(),
                }),
            }
        }

        // Enabled-but-no-asn is a real configuration error worth
        // surfacing — peers can't form sessions without a local
        // ASN to put in the OPEN message.
        if yaml.enabled && local_asn == 0 {
            return Err(ConfigError::MissingField("asn"));
        }
        let mut aggregates_v4 = Vec::new();
        for a in &yaml.aggregate_addresses_v4 {
            aggregates_v4.push(AggregateConfig {
                prefix: a.prefix.clone(),
                summary_only: a.summary_only,
            });
        }
        let mut aggregates_v6 = Vec::new();
        for a in &yaml.aggregate_addresses_v6 {
            aggregates_v6.push(AggregateConfig {
                prefix: a.prefix.clone(),
                summary_only: a.summary_only,
            });
        }

        Ok(BgpDaemonConfig {
            enabled: yaml.enabled,
            local_asn,
            router_id,
            peers,
            announced_prefixes_v4: announced_v4,
            announced_prefixes_v6: announced_v6,
            aggregates_v4,
            aggregates_v6,
            listen_address: yaml.listen_address,
            route_maps: HashMap::new(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_yaml_yields_disabled_config() {
        let yaml = BgpYamlConfig::default();
        let cfg = BgpDaemonConfig::from_yaml(yaml).unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.local_asn, 0);
        assert!(cfg.peers.is_empty());
    }

    #[test]
    fn disabled_yaml_with_identity_preserves_asn_and_router_id() {
        // jt-router pattern: ASN + router_id staged in YAML
        // without `enabled: true`. The control socket should
        // still report the configured identity in disabled mode.
        let yaml = BgpYamlConfig {
            enabled: false,
            asn: Some(65100),
            router_id: Some("23.177.24.9".into()),
            peers: Vec::new(),
            ..Default::default()
        };
        let cfg = BgpDaemonConfig::from_yaml(yaml).unwrap();
        assert!(!cfg.enabled);
        assert_eq!(cfg.local_asn, 65100);
        assert_eq!(cfg.router_id, Some("23.177.24.9".parse().unwrap()));
    }

    #[test]
    fn enabled_yaml_with_one_peer() {
        let yaml = BgpYamlConfig {
            enabled: true,
            asn: Some(65000),
            router_id: Some("10.0.0.1".into()),
            peers: vec![BgpPeerYaml {
                name: "upstream".into(),
                peer_ip: "192.0.2.1".into(),
                peer_asn: 65001,
                description: None,
                update_source: Some("10.0.0.1".into()),
                import_policy: None,
                export_policy: None,
                redistribute: Vec::new(),
            }],
            ..Default::default()
        };
        let cfg = BgpDaemonConfig::from_yaml(yaml).unwrap();
        assert!(cfg.enabled);
        assert_eq!(cfg.local_asn, 65000);
        assert_eq!(cfg.router_id, Some("10.0.0.1".parse().unwrap()));
        assert_eq!(cfg.peers.len(), 1);
        assert_eq!(cfg.peers[0].remote_asn, 65001);
        assert_eq!(
            cfg.peers[0].address,
            "192.0.2.1".parse::<std::net::IpAddr>().unwrap()
        );
        assert!(cfg.peers[0].source_address.is_some());
    }

    #[test]
    fn enabled_without_asn_errors() {
        let yaml = BgpYamlConfig {
            enabled: true,
            asn: None,
            ..Default::default()
        };
        let err = BgpDaemonConfig::from_yaml(yaml).unwrap_err();
        assert!(matches!(err, ConfigError::MissingField("asn")));
    }

    #[test]
    fn invalid_router_id_errors() {
        let yaml = BgpYamlConfig {
            enabled: true,
            asn: Some(65000),
            router_id: Some("not-an-ip".into()),
            ..Default::default()
        };
        let err = BgpDaemonConfig::from_yaml(yaml).unwrap_err();
        assert!(matches!(err, ConfigError::InvalidRouterId(_, _)));
    }

    #[test]
    fn full_yaml_round_trip_via_router_yaml() {
        let blob = r#"
bgp:
  enabled: true
  asn: 65000
  router_id: "10.0.0.1"
  peers:
    - name: upstream
      peer_ip: "192.0.2.1"
      peer_asn: 65001
"#;
        let router: RouterYaml = serde_yaml::from_str(blob).unwrap();
        let cfg = BgpDaemonConfig::from_yaml(router.bgp).unwrap();
        assert_eq!(cfg.local_asn, 65000);
        assert_eq!(cfg.peers.len(), 1);
    }

    #[test]
    fn import_policy_string_round_trip_via_yaml() {
        let blob = r#"
bgp:
  enabled: true
  asn: 65000
  peers:
    - name: a
      peer_ip: "192.0.2.1"
      peer_asn: 65001
      import_policy: accept-all
    - name: b
      peer_ip: "192.0.2.2"
      peer_asn: 65002
      import_policy: my-import-map
"#;
        let router: RouterYaml = serde_yaml::from_str(blob).unwrap();
        let cfg = BgpDaemonConfig::from_yaml(router.bgp).unwrap();
        assert_eq!(cfg.peers[0].import_policy.as_deref(), Some("accept-all"));
        assert_eq!(cfg.peers[1].import_policy.as_deref(), Some("my-import-map"));
    }

    #[test]
    fn peer_yaml_with_import_export_policy_round_trip() {
        let blob = r#"
bgp:
  enabled: true
  asn: 65000
  peers:
    - name: upstream
      peer_ip: "192.0.2.1"
      peer_asn: 65001
"#;
        let router: RouterYaml = serde_yaml::from_str(blob).unwrap();
        let cfg = BgpDaemonConfig::from_yaml(router.bgp).unwrap();
        // No policy set → None
        assert!(cfg.peers[0].import_policy.is_none());
        assert!(cfg.peers[0].export_policy.is_none());
    }

    #[test]
    fn redistribute_parsed_per_peer() {
        let blob = r#"
bgp:
  enabled: true
  asn: 65000
  peers:
    - name: a
      peer_ip: "192.0.2.1"
      peer_asn: 65001
      redistribute:
        - protocol: connected
        - protocol: ospf
    - name: b
      peer_ip: "192.0.2.2"
      peer_asn: 65002
      redistribute:
        - protocol: static
"#;
        let router: RouterYaml = serde_yaml::from_str(blob).unwrap();
        let cfg = BgpDaemonConfig::from_yaml(router.bgp).unwrap();
        assert!(cfg.peers[0].redistribute_connected());
        assert!(cfg.peers[0].redistribute_ospf());
        assert!(!cfg.peers[0].redistribute_static());
        assert!(!cfg.peers[1].redistribute_connected());
        assert!(!cfg.peers[1].redistribute_ospf());
        assert!(cfg.peers[1].redistribute_static());
    }

    #[test]
    fn route_maps_compile_from_router_yaml_and_attach_to_redistribute_rule() {
        let blob = r#"
route_maps:
  - name: my-prefixes-only
    statements:
      - seq: 10
        action: permit
        match:
          prefix_list: ["23.177.24.0/24"]
      - seq: 20
        action: deny
bgp:
  enabled: true
  asn: 65000
  peers:
    - name: upstream
      peer_ip: "192.0.2.1"
      peer_asn: 65001
      redistribute:
        - protocol: connected
          route_map: my-prefixes-only
"#;
        let router: RouterYaml = serde_yaml::from_str(blob).unwrap();
        let cfg = BgpDaemonConfig::from_router_yaml(router).unwrap();
        assert_eq!(cfg.route_maps.len(), 1);
        let map = cfg.route_maps.get("my-prefixes-only").unwrap();
        assert_eq!(map.statements.len(), 2);
        assert_eq!(
            cfg.peers[0].route_map_for(RedistributeProtocol::Connected),
            Some("my-prefixes-only")
        );
    }

    #[test]
    fn route_map_compile_error_propagates() {
        let blob = r#"
route_maps:
  - name: bad
    statements:
      - seq: 10
        action: permit
        match:
          prefix_list: ["not-a-cidr"]
"#;
        let router: RouterYaml = serde_yaml::from_str(blob).unwrap();
        let err = BgpDaemonConfig::from_router_yaml(router).unwrap_err();
        assert!(matches!(err, ConfigError::RouteMapCompile(_, _)));
    }

    #[test]
    fn unknown_redistribute_protocol_errors() {
        let blob = r#"
bgp:
  enabled: true
  asn: 65000
  peers:
    - name: a
      peer_ip: "192.0.2.1"
      peer_asn: 65001
      redistribute:
        - protocol: isis
"#;
        let router: RouterYaml = serde_yaml::from_str(blob).unwrap();
        let err = BgpDaemonConfig::from_yaml(router.bgp).unwrap_err();
        assert!(matches!(err, ConfigError::UnknownRedistributeProtocol(_)));
    }

    #[test]
    fn missing_bgp_block_in_router_yaml_is_disabled() {
        let blob = "hostname: jt-router\n";
        let router: RouterYaml = serde_yaml::from_str(blob).unwrap();
        let cfg = BgpDaemonConfig::from_yaml(router.bgp).unwrap();
        assert_eq!(cfg.local_asn, 0);
    }
}
