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

use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Top-level BGP daemon configuration. Loaded from the `bgp:`
/// section of the YAML config file. All fields default-empty so
/// an absent `bgp:` block parses as "BGP disabled".
///
/// `enabled` is intentionally separate from `local_asn`: an
/// operator can stage an ASN + router-id in YAML without flipping
/// BGP on yet, and `bgpd query summary` will report the
/// configured identity even when no peers are running.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BgpDaemonConfig {
    /// Whether to actually start peer sessions. When false, the
    /// daemon parks idle but the control socket still binds and
    /// reports configured identity through `bgpd query`.
    #[serde(default)]
    pub enabled: bool,
    /// Local autonomous system number (4-octet, RFC 6793).
    #[serde(default)]
    pub local_asn: u32,
    /// BGP router-id — the speaker's identity in OPEN messages and
    /// best-path tiebreaks. Conventionally a loopback IPv4 address.
    #[serde(default)]
    pub router_id: Option<std::net::Ipv4Addr>,
    /// Configured peers. v1 supports IPv4 and IPv6 transports.
    #[serde(default)]
    pub peers: Vec<BgpPeerConfig>,
    /// Static IPv4 prefixes to originate from BGP. Equivalent to
    /// FRR's `network <prefix>` under address-family ipv4 unicast.
    /// Each prefix is announced to every Established peer once
    /// the session comes up.
    #[serde(default)]
    pub announced_prefixes_v4: Vec<crate::packet::update::Prefix4>,
    /// Static IPv6 prefixes to originate from BGP.
    #[serde(default)]
    pub announced_prefixes_v6: Vec<crate::packet::update::Prefix6>,
    /// If true, redistribute every ribd-installed
    /// `Source::Connected` IPv4 prefix as a locally-originated
    /// BGP route. Snapshot at bgpd startup; no incremental
    /// updates on interface change in v1.
    #[serde(default)]
    pub redistribute_connected_v4: bool,
    /// IPv6 equivalent of [`Self::redistribute_connected_v4`].
    #[serde(default)]
    pub redistribute_connected_v6: bool,
    /// If true, redistribute every ribd-installed OSPF IPv4
    /// route (Intra/Inter/Ext1/Ext2) as a locally-originated BGP
    /// route. Equivalent to FRR `redistribute ospf`.
    #[serde(default)]
    pub redistribute_ospf_v4: bool,
    /// IPv6 equivalent — redistributes OSPFv3 routes.
    #[serde(default)]
    pub redistribute_ospf_v6: bool,
    /// If true, redistribute ribd's `Source::Static` IPv4
    /// routes into BGP. Equivalent to FRR `redistribute static`.
    #[serde(default)]
    pub redistribute_static_v4: bool,
    /// IPv6 equivalent.
    #[serde(default)]
    pub redistribute_static_v6: bool,
    /// Aggregate (summary) addresses. When ≥1 more-specific prefix
    /// exists in the Loc-RIB for a configured aggregate, bgpd
    /// synthesizes a covering route with `OriginClass::Aggregate`.
    /// If `summary_only` is set, the more-specifics are suppressed
    /// in Adj-RIB-Out.
    #[serde(default)]
    pub aggregates_v4: Vec<AggregateConfig>,
    #[serde(default)]
    pub aggregates_v6: Vec<AggregateConfig>,
    /// Listen address for incoming BGP connections (passive open).
    /// When set, bgpd binds a TCP listener and accepts
    /// connections from configured peers. Connections from unknown
    /// source IPs are rejected with a NOTIFICATION.
    #[serde(default)]
    pub listen_address: Option<String>,
}

/// Configuration for one aggregate-address.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AggregateConfig {
    pub prefix: String,
    #[serde(default)]
    pub summary_only: bool,
}

/// Per-peer configuration. Captures the operationally-meaningful
/// knobs only; advanced policy lives on the `policy` field once
/// `bgpd::policy` exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BgpPeerConfig {
    /// Peer's IP address (the TCP destination).
    pub address: std::net::IpAddr,
    /// Peer's TCP port. Defaults to the IANA-assigned 179. Tests
    /// override this to use ephemeral ports against a fake peer.
    #[serde(default)]
    pub port: Option<u16>,
    /// Remote AS — used to classify the session as eBGP or iBGP.
    pub remote_asn: u32,
    /// Local source address. Typically a loopback for iBGP, the
    /// connected interface address for eBGP. Optional; if unset
    /// the OS picks one.
    #[serde(default)]
    pub source_address: Option<std::net::IpAddr>,
    /// TCP MD5 password (RFC 2385) for the session. None means no
    /// MD5. Required by virtually every real upstream provider.
    #[serde(default)]
    pub password: Option<String>,
    /// Hold time advertised in OPEN. Defaults to 90s if unset
    /// (RFC 4271 §10).
    #[serde(default)]
    pub hold_time: Option<u16>,
    /// Address families to negotiate (RFC 4760). Empty = IPv4
    /// unicast only, matching the legacy single-AFI session.
    #[serde(default)]
    pub address_families: Vec<BgpAddressFamily>,
    /// Import policy — applied to every route received from this
    /// peer before it enters Adj-RIB-In. Defaults to AcceptAll for
    /// iBGP and DenyAll for eBGP (RFC 8212).
    #[serde(default)]
    pub import_policy: Option<PolicyConfig>,
    /// Export policy — applied to every Loc-RIB winner before it's
    /// advertised to this peer. Same default behavior.
    #[serde(default)]
    pub export_policy: Option<PolicyConfig>,
}

/// Per-peer policy configuration, deserialized from YAML.
///
/// ```yaml
/// import_policy: accept-all
/// export_policy: deny-all
/// import_policy:
///   prefix_list: ["10.0.0.0/8", "192.168.0.0/16"]
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum PolicyConfig {
    Named(String),
    PrefixList { prefix_list: Vec<String> },
}

/// Negotiated address family. v1 supports IPv4 and IPv6 unicast
/// only — VPNv4, EVPN, FlowSpec, etc. are explicitly v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BgpAddressFamily {
    Ipv4Unicast,
    Ipv6Unicast,
}

impl PolicyConfig {
    /// Convert the config representation into a runtime `Policy`.
    /// Errors on unparseable prefixes in a prefix list.
    pub fn to_policy(&self) -> Result<crate::policy::Policy, ConfigError> {
        match self {
            PolicyConfig::Named(name) => match name.as_str() {
                "accept-all" => Ok(crate::policy::Policy::AcceptAll),
                "deny-all" => Ok(crate::policy::Policy::DenyAll),
                other => Err(ConfigError::MissingField(
                    // Not ideal error variant, but avoids adding one for v1.
                    Box::leak(format!("unknown policy name: {other}").into_boxed_str()),
                )),
            },
            PolicyConfig::PrefixList { prefix_list } => {
                let mut v4 = Vec::new();
                let mut v6 = Vec::new();
                for cidr in prefix_list {
                    let p: ipnet::IpNet = cidr
                        .parse()
                        .map_err(|_| ConfigError::InvalidPrefix(cidr.clone()))?;
                    match p {
                        ipnet::IpNet::V4(v) => v4.push(crate::packet::update::Prefix4 {
                            addr: v.network(),
                            len: v.prefix_len(),
                        }),
                        ipnet::IpNet::V6(v) => v6.push(crate::packet::update::Prefix6 {
                            addr: v.network(),
                            len: v.prefix_len(),
                        }),
                    }
                }
                Ok(crate::policy::Policy::PrefixFilter { v4, v6 })
            }
        }
    }
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
    /// Each entry has a `protocol` field; `connected` is the only
    /// one v1 honors.
    #[serde(default)]
    pub redistribute_ipv4: Vec<BgpRedistributeYaml>,
    #[serde(default)]
    pub redistribute_ipv6: Vec<BgpRedistributeYaml>,
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
    pub import_policy: Option<PolicyConfig>,
    #[serde(default)]
    pub export_policy: Option<PolicyConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct RouterYaml {
    #[serde(default)]
    pub bgp: BgpYamlConfig,
}

impl BgpDaemonConfig {
    /// Load `BgpDaemonConfig` from a YAML file. Returns an empty
    /// config (BGP disabled) if the file has no `bgp:` block.
    /// Errors on parse failure or invalid IPs.
    pub fn load_from_yaml(path: &Path) -> Result<Self, ConfigError> {
        let bytes = std::fs::read(path).map_err(|e| ConfigError::Io {
            path: path.display().to_string(),
            source: e,
        })?;
        let router: RouterYaml = serde_yaml::from_slice(&bytes)?;
        Self::from_yaml(router.bgp)
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

        let redistribute_connected_v4 = yaml
            .redistribute_ipv4
            .iter()
            .any(|r| r.protocol == "connected");
        let redistribute_connected_v6 = yaml
            .redistribute_ipv6
            .iter()
            .any(|r| r.protocol == "connected");
        let redistribute_ospf_v4 = yaml
            .redistribute_ipv4
            .iter()
            .any(|r| r.protocol == "ospf");
        let redistribute_ospf_v6 = yaml
            .redistribute_ipv6
            .iter()
            .any(|r| r.protocol == "ospf");
        let redistribute_static_v4 = yaml
            .redistribute_ipv4
            .iter()
            .any(|r| r.protocol == "static");
        let redistribute_static_v6 = yaml
            .redistribute_ipv6
            .iter()
            .any(|r| r.protocol == "static");

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
            redistribute_connected_v4,
            redistribute_connected_v6,
            redistribute_ospf_v4,
            redistribute_ospf_v6,
            redistribute_static_v4,
            redistribute_static_v6,
            aggregates_v4,
            aggregates_v6,
            listen_address: yaml.listen_address,
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
    fn policy_config_accept_all() {
        let pc = PolicyConfig::Named("accept-all".into());
        assert!(matches!(
            pc.to_policy().unwrap(),
            crate::policy::Policy::AcceptAll
        ));
    }

    #[test]
    fn policy_config_deny_all() {
        let pc = PolicyConfig::Named("deny-all".into());
        assert!(matches!(
            pc.to_policy().unwrap(),
            crate::policy::Policy::DenyAll
        ));
    }

    #[test]
    fn policy_config_prefix_list_parses_mixed() {
        let pc = PolicyConfig::PrefixList {
            prefix_list: vec![
                "10.0.0.0/8".into(),
                "2001:db8::/32".into(),
            ],
        };
        let policy = pc.to_policy().unwrap();
        match policy {
            crate::policy::Policy::PrefixFilter { v4, v6 } => {
                assert_eq!(v4.len(), 1);
                assert_eq!(v6.len(), 1);
                assert_eq!(v4[0].addr, std::net::Ipv4Addr::new(10, 0, 0, 0));
                assert_eq!(v4[0].len, 8);
            }
            _ => panic!("expected PrefixFilter"),
        }
    }

    #[test]
    fn policy_config_unknown_name_errors() {
        let pc = PolicyConfig::Named("bogus".into());
        assert!(pc.to_policy().is_err());
    }

    #[test]
    fn policy_config_bad_prefix_errors() {
        let pc = PolicyConfig::PrefixList {
            prefix_list: vec!["not-a-cidr".into()],
        };
        assert!(pc.to_policy().is_err());
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
    fn redistribute_ospf_and_static_parsed_from_yaml() {
        let yaml = BgpYamlConfig {
            enabled: true,
            asn: Some(65000),
            redistribute_ipv4: vec![
                BgpRedistributeYaml {
                    protocol: "ospf".into(),
                    ..Default::default()
                },
                BgpRedistributeYaml {
                    protocol: "static".into(),
                    ..Default::default()
                },
            ],
            redistribute_ipv6: vec![BgpRedistributeYaml {
                protocol: "ospf".into(),
                ..Default::default()
            }],
            ..Default::default()
        };
        let cfg = BgpDaemonConfig::from_yaml(yaml).unwrap();
        assert!(cfg.redistribute_ospf_v4);
        assert!(cfg.redistribute_static_v4);
        assert!(cfg.redistribute_ospf_v6);
        assert!(!cfg.redistribute_static_v6);
        assert!(!cfg.redistribute_connected_v4);
    }

    #[test]
    fn missing_bgp_block_in_router_yaml_is_disabled() {
        let blob = "hostname: jt-router\n";
        let router: RouterYaml = serde_yaml::from_str(blob).unwrap();
        let cfg = BgpDaemonConfig::from_yaml(router.bgp).unwrap();
        assert_eq!(cfg.local_asn, 0);
    }
}
