//! bgpd — BGP-4 routing daemon.
//!
//! Mirrors the layout of `ospfd` so that future maintenance
//! lives in the same mental model.
//!
//! ## Module map
//!
//! - [`config`] — `BgpDaemonConfig`, peer config, address-family
//!   config. Loaded from `/etc/bgpd/config.yaml` under the
//!   top-level `bgp:` key.
//! - [`control`] — `/run/bgpd.sock` query protocol. Mirrors
//!   `ospfd::control`: JSON line-delimited request/response
//!   with `Summary`, `Neighbors`, `Routes`, `Advertised`,
//!   `Received` queries.
//! - [`instance`] — top-level BGP speaker. Owns the peer table, the
//!   Loc-RIB, and the ribd connection. Drives the per-peer
//!   tasks.
//! - [`peer`] — per-peer state: FSM, transport, timers,
//!   Adj-RIB-In/Out.
//! - [`packet`] — wire format: header, OPEN, UPDATE, NOTIFICATION,
//!   KEEPALIVE, ROUTE-REFRESH, capability TLVs, path attributes.
//! - [`adj_rib`] — Adj-RIB-In and Adj-RIB-Out per peer per
//!   AFI/SAFI. Pre-policy and post-policy storage.
//! - [`loc_rib`] — the speaker's Loc-RIB. Holds the post-best-path
//!   winners that get pushed to ribd.
//! - [`bestpath`] — the RFC 4271 §9.1 tiebreaker chain.
//! - [`policy`] — v1 import/export policy: prefix-list, AS-path
//!   filter, set local-pref/MED, communities (RFC 1997).
//! - [`rib_push`] — converts Loc-RIB winners to ribd-client
//!   `BulkBegin/Chunk/End` on session up, and incremental `Update`
//!   messages thereafter. Always uses `NextHop::Recursive` —
//!   ribd does the actual resolution.
//! - [`error`] — RFC 7606 treat-as-withdraw / attribute-discard
//!   classification and BGP NOTIFICATION error codes.

pub mod adj_rib;
pub mod bestpath;
pub mod config;
pub mod control;
pub mod error;
pub mod instance;
pub mod loc_rib;
pub mod local_origin;
pub mod packet;
pub mod peer;
pub mod policy;
pub mod rib_push;
pub mod route_map;
