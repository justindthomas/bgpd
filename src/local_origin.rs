//! Locally-originated routes — the prefix set bgpd
//! advertises outbound to BGP peers.
//!
//! Two contributing sources today:
//!
//! 1. Static `announced_prefixes_v4` / `announced_prefixes_v6`
//!    from the YAML config. Equivalent to FRR's
//!    `network <prefix>` under address-family.
//! 2. `redistribute connected` (per family). Snapshot of every
//!    `Source::Connected` route ribd has at startup, queried
//!    via `ribd-client`. Source-of-truth is ribd's
//!    `seed_connected_routes` which dumps VPP at its own startup.
//!    No live interface refresh in v1 — a daemon restart picks
//!    up new addresses.
//!
//! Both sources are merged into a single dedupe-by-prefix set
//! per AFI. The instance layer reads from this on
//! `SessionEstablished` and builds initial outbound UPDATEs.

use std::collections::HashSet;

use anyhow::{Context, Result};
use ribd_client::RibConnection;
use ribd_proto::{Af, QueryReply, QueryRequest, Source as RibSource};

use crate::adj_rib::OriginClass;
use crate::config::BgpDaemonConfig;
use crate::packet::update::{Prefix4, Prefix6};

/// The prefixes bgpd should advertise outbound to peers.
/// Always sorted + deduplicated so repeated calls produce the
/// same wire bytes. The `origin_v4`/`origin_v6` maps carry
/// per-prefix metadata so `rebuild_local_pseudo_rib` can tag
/// each route with the correct `OriginClass`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LocalOrigin {
    pub v4: Vec<Prefix4>,
    pub v6: Vec<Prefix6>,
    pub origin_v4: std::collections::HashMap<Prefix4, OriginClass>,
    pub origin_v6: std::collections::HashMap<Prefix6, OriginClass>,
}

impl LocalOrigin {
    /// Build the local-origin set for the given config. Queries
    /// ribd for its `Source::Connected` routes if either
    /// `redistribute_connected_v4` or `redistribute_connected_v6`
    /// is set; static `announced_prefixes_*` are always merged in.
    pub async fn build(
        config: &BgpDaemonConfig,
        rib: &mut RibConnection,
    ) -> Result<Self> {
        let mut v4: HashSet<Prefix4> = HashSet::new();
        let mut v6: HashSet<Prefix6> = HashSet::new();
        let mut origin_v4 = std::collections::HashMap::new();
        let mut origin_v6 = std::collections::HashMap::new();

        for p in &config.announced_prefixes_v4 {
            v4.insert(*p);
            origin_v4.entry(*p).or_insert(OriginClass::Static);
        }
        for p in &config.announced_prefixes_v6 {
            v6.insert(*p);
            origin_v6.entry(*p).or_insert(OriginClass::Static);
        }

        // Query ribd for all installed routes if any
        // redistribute flag is set. A single query covers all
        // sources; we filter locally.
        let need_query = config.redistribute_connected_v4
            || config.redistribute_connected_v6
            || config.redistribute_ospf_v4
            || config.redistribute_ospf_v6
            || config.redistribute_static_v4
            || config.redistribute_static_v6;
        if need_query {
            let reply = rib
                .query(QueryRequest::InstalledRoutes)
                .await
                .context("querying ribd for installed routes")?;
            let routes = match reply {
                QueryReply::InstalledRoutes(rs) => rs,
                other => {
                    anyhow::bail!("unexpected query reply: {:?}", other);
                }
            };
            for r in routes {
                let dominated_v4 = match r.source {
                    RibSource::Connected => config.redistribute_connected_v4,
                    RibSource::Static => config.redistribute_static_v4,
                    RibSource::OspfIntra
                    | RibSource::OspfInter
                    | RibSource::OspfExt1
                    | RibSource::OspfExt2 => config.redistribute_ospf_v4,
                    _ => false,
                };
                let dominated_v6 = match r.source {
                    RibSource::Connected => config.redistribute_connected_v6,
                    RibSource::Static => config.redistribute_static_v6,
                    RibSource::Ospf6Intra
                    | RibSource::Ospf6Inter
                    | RibSource::Ospf6Ext1
                    | RibSource::Ospf6Ext2 => config.redistribute_ospf_v6,
                    _ => false,
                };
                let oc = match r.source {
                    RibSource::Connected => OriginClass::Connected,
                    RibSource::Static => OriginClass::Static,
                    src => OriginClass::Redistribute(src),
                };
                match r.prefix.af {
                    Af::V4 if dominated_v4 => {
                        let mut octets = [0u8; 4];
                        octets.copy_from_slice(&r.prefix.addr[..4]);
                        let pfx = Prefix4 {
                            addr: std::net::Ipv4Addr::from(octets),
                            len: r.prefix.len,
                        };
                        v4.insert(pfx);
                        origin_v4.entry(pfx).or_insert(oc);
                    }
                    Af::V6 if dominated_v6 => {
                        let pfx = Prefix6 {
                            addr: std::net::Ipv6Addr::from(r.prefix.addr),
                            len: r.prefix.len,
                        };
                        v6.insert(pfx);
                        origin_v6.entry(pfx).or_insert(oc);
                    }
                    _ => {}
                }
            }
        }

        let mut v4_sorted: Vec<Prefix4> = v4.into_iter().collect();
        v4_sorted.sort_by(|a, b| (a.addr, a.len).cmp(&(b.addr, b.len)));
        let mut v6_sorted: Vec<Prefix6> = v6.into_iter().collect();
        v6_sorted.sort_by(|a, b| (a.addr, a.len).cmp(&(b.addr, b.len)));

        Ok(LocalOrigin {
            v4: v4_sorted,
            v6: v6_sorted,
            origin_v4,
            origin_v6,
        })
    }

    pub fn is_empty(&self) -> bool {
        self.v4.is_empty() && self.v6.is_empty()
    }

    pub fn len(&self) -> usize {
        self.v4.len() + self.v6.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn p4(a: u8, b: u8, c: u8, d: u8, len: u8) -> Prefix4 {
        Prefix4 {
            addr: Ipv4Addr::new(a, b, c, d),
            len,
        }
    }

    fn p6(s: &str, len: u8) -> Prefix6 {
        Prefix6 {
            addr: s.parse::<Ipv6Addr>().unwrap(),
            len,
        }
    }

    #[test]
    fn local_origin_default_is_empty() {
        let lo = LocalOrigin::default();
        assert!(lo.is_empty());
        assert_eq!(lo.len(), 0);
    }

    #[test]
    fn local_origin_sort_and_dedupe_contract() {
        // Construct a local origin set manually, simulating what
        // build() would produce after dedupe — verify the sort
        // contract callers depend on for stable wire bytes.
        let mut v4 = vec![
            p4(192, 168, 1, 0, 24),
            p4(10, 0, 0, 0, 8),
            p4(192, 168, 1, 0, 24), // dup
        ];
        v4.sort_by(|a, b| (a.addr, a.len).cmp(&(b.addr, b.len)));
        v4.dedup();
        assert_eq!(v4, vec![p4(10, 0, 0, 0, 8), p4(192, 168, 1, 0, 24)]);

        let mut v6 = vec![p6("2001:db8::", 32), p6("2602:f90e::", 40)];
        v6.sort_by(|a, b| (a.addr, a.len).cmp(&(b.addr, b.len)));
        assert_eq!(v6, vec![p6("2001:db8::", 32), p6("2602:f90e::", 40)]);
    }
}
