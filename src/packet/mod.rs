//! BGP wire format.
//!
//! Module breakdown follows the message types defined in RFC 4271
//! plus the extensions we implement in v1:
//!
//! - [`header`] — 19-byte BGP header (16-byte marker + 2-byte
//!   length + 1-byte type) per RFC 4271 §4.1.
//! - [`open`] — OPEN message + capability advertisement (RFC 5492).
//! - [`update`] — UPDATE message and path attribute encoding.
//! - [`notification`] — NOTIFICATION error codes (RFC 4271 §6).
//! - [`keepalive`] — header-only KEEPALIVE message.
//! - [`refresh`] — RFC 2918 ROUTE-REFRESH.
//! - [`caps`] — RFC 5492 capability TLV codec, including 4-octet
//!   ASN (RFC 6793) and MP-BGP (RFC 4760).
//! - [`attrs`] — path attributes: ORIGIN, AS_PATH (4-octet),
//!   NEXT_HOP, MED, LOCAL_PREF, ATOMIC_AGGREGATE, AGGREGATOR,
//!   COMMUNITIES (RFC 1997), MP_REACH_NLRI / MP_UNREACH_NLRI
//!   (RFC 4760).

pub mod attrs;
pub mod caps;
pub mod header;
pub mod keepalive;
pub mod notification;
pub mod open;
pub mod refresh;
pub mod update;
