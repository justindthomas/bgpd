//! UPDATE message (RFC 4271 §4.3 + RFC 4760 + RFC 7606).
//!
//! Wire format:
//!
//! ```text
//!  +-----------------------------------------------------+
//!  |   Withdrawn Routes Length (2 octets)                |
//!  +-----------------------------------------------------+
//!  |   Withdrawn Routes (variable, IPv4 NLRI)            |
//!  +-----------------------------------------------------+
//!  |   Total Path Attribute Length (2 octets)            |
//!  +-----------------------------------------------------+
//!  |   Path Attributes (variable)                        |
//!  +-----------------------------------------------------+
//!  |   Network Layer Reachability Information (variable, |
//!  |     IPv4 NLRI)                                      |
//!  +-----------------------------------------------------+
//! ```
//!
//! NLRI is encoded as a sequence of `<length, prefix>` tuples
//! where `length` is one byte (the prefix length in bits) and
//! `prefix` is `ceil(length/8)` bytes (the leading bits, with the
//! trailing bits in the last byte zero-padded).
//!
//! IPv4 NLRI travels in the legacy fields (top-level Withdrawn /
//! NLRI). IPv6 NLRI rides inside MP_REACH_NLRI / MP_UNREACH_NLRI
//! per RFC 4760. We expose `ipv4_nlri()`, `ipv4_withdrawn()`,
//! `ipv6_nlri()`, and `ipv6_withdrawn()` accessors that paper over
//! the difference at the call site.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{AttributeErrorAction, ErrorCode, ParseError, UpdateMessageSubcode};
use crate::packet::attrs::PathAttribute;
use crate::packet::header::{Header, MessageType, HEADER_LEN, MAX_MESSAGE_LEN};
use crate::packet::read_u16_be;

/// A parsed UPDATE message. Holds the raw (Withdrawn / Path
/// attributes / NLRI) decomposition; higher-level processing
/// (best-path, etc.) lives in [`crate::adj_rib`] and friends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Update {
    pub withdrawn_v4: Vec<Prefix4>,
    pub path_attributes: Vec<PathAttribute>,
    pub nlri_v4: Vec<Prefix4>,
}

/// Convenience type for IPv4 NLRI entries.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct Prefix4 {
    pub addr: Ipv4Addr,
    pub len: u8,
}

/// Convenience type for IPv6 NLRI entries (carried inside
/// MP_REACH/UNREACH).
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize,
)]
pub struct Prefix6 {
    pub addr: Ipv6Addr,
    pub len: u8,
}

impl Update {
    /// Build an empty UPDATE — useful as a starting point for
    /// constructors and as the "End-of-RIB" marker (RFC 4724 §5,
    /// even though we don't implement Graceful Restart in v1, the
    /// EoR shape is just an empty IPv4 UPDATE).
    pub fn empty() -> Self {
        Update {
            withdrawn_v4: Vec::new(),
            path_attributes: Vec::new(),
            nlri_v4: Vec::new(),
        }
    }

    /// Encode the full UPDATE message including BGP header.
    pub fn encode(&self) -> Vec<u8> {
        let withdrawn_block = encode_nlri_v4(&self.withdrawn_v4);
        let mut attrs_block = Vec::new();
        for attr in &self.path_attributes {
            attrs_block.extend(attr.encode());
        }
        let nlri_block = encode_nlri_v4(&self.nlri_v4);
        let body_len = 2 + withdrawn_block.len() + 2 + attrs_block.len() + nlri_block.len();
        let total_len = HEADER_LEN + body_len;
        debug_assert!(total_len <= MAX_MESSAGE_LEN, "UPDATE too large");
        let mut buf = vec![0u8; total_len];
        Header::encode(&mut buf, MessageType::Update);
        let mut p = HEADER_LEN;
        buf[p..p + 2].copy_from_slice(&(withdrawn_block.len() as u16).to_be_bytes());
        p += 2;
        buf[p..p + withdrawn_block.len()].copy_from_slice(&withdrawn_block);
        p += withdrawn_block.len();
        buf[p..p + 2].copy_from_slice(&(attrs_block.len() as u16).to_be_bytes());
        p += 2;
        buf[p..p + attrs_block.len()].copy_from_slice(&attrs_block);
        p += attrs_block.len();
        buf[p..p + nlri_block.len()].copy_from_slice(&nlri_block);
        buf
    }

    /// Parse an UPDATE body (the bytes after the 19-byte BGP
    /// header). Returns the decomposed UPDATE; RFC 7606 attribute
    /// errors propagate as [`ParseError::Update`] with the right
    /// `action` so the FSM can decide whether to NOTIFICATION or
    /// treat-as-withdraw.
    pub fn parse_body(body: &[u8]) -> Result<Self, ParseError> {
        if body.len() < 4 {
            return Err(ParseError::Update {
                code: ErrorCode::UpdateMessage,
                subcode: UpdateMessageSubcode::MalformedAttributeList as u8,
                message: format!("UPDATE body too short: {} bytes", body.len()),
                action: AttributeErrorAction::SessionReset,
            });
        }
        let withdrawn_len = read_u16_be(&body[..2]) as usize;
        let mut p = 2;
        if body.len() - p < withdrawn_len {
            return Err(ParseError::Update {
                code: ErrorCode::UpdateMessage,
                subcode: UpdateMessageSubcode::MalformedAttributeList as u8,
                message: format!(
                    "withdrawn block declares {} bytes, only {} left",
                    withdrawn_len,
                    body.len() - p
                ),
                action: AttributeErrorAction::SessionReset,
            });
        }
        let withdrawn_v4 = parse_nlri_v4(&body[p..p + withdrawn_len])?;
        p += withdrawn_len;
        if body.len() - p < 2 {
            return Err(ParseError::Update {
                code: ErrorCode::UpdateMessage,
                subcode: UpdateMessageSubcode::MalformedAttributeList as u8,
                message: "UPDATE missing path attribute length field".into(),
                action: AttributeErrorAction::SessionReset,
            });
        }
        let attr_len = read_u16_be(&body[p..p + 2]) as usize;
        p += 2;
        if body.len() - p < attr_len {
            return Err(ParseError::Update {
                code: ErrorCode::UpdateMessage,
                subcode: UpdateMessageSubcode::MalformedAttributeList as u8,
                message: format!(
                    "path attribute block declares {} bytes, only {} left",
                    attr_len,
                    body.len() - p
                ),
                action: AttributeErrorAction::SessionReset,
            });
        }
        let attrs_buf = &body[p..p + attr_len];
        p += attr_len;
        let nlri_v4 = parse_nlri_v4(&body[p..])?;

        let mut path_attributes = Vec::new();
        let mut q = 0;
        while q < attrs_buf.len() {
            let (attr, n) = PathAttribute::parse(&attrs_buf[q..])?;
            path_attributes.push(attr);
            q += n;
        }

        Ok(Update {
            withdrawn_v4,
            path_attributes,
            nlri_v4,
        })
    }

    /// Convenience: extract IPv6 NLRI from any `MpReachNlri`
    /// attribute. The MP_REACH NLRI bytes are encoded the same way
    /// as legacy IPv4 NLRI but with 16-byte addresses.
    pub fn ipv6_nlri(&self) -> Result<Vec<Prefix6>, ParseError> {
        for attr in &self.path_attributes {
            if let PathAttribute::MpReachNlri { afi, safi: _, nlri, .. } = attr {
                if *afi != crate::packet::caps::AFI_IPV6 {
                    continue;
                }
                return parse_nlri_v6(nlri);
            }
        }
        Ok(Vec::new())
    }

    /// Convenience: extract IPv6 withdrawn prefixes from any
    /// `MpUnreachNlri` attribute.
    pub fn ipv6_withdrawn(&self) -> Result<Vec<Prefix6>, ParseError> {
        for attr in &self.path_attributes {
            if let PathAttribute::MpUnreachNlri { afi, safi: _, withdrawn } = attr {
                if *afi != crate::packet::caps::AFI_IPV6 {
                    continue;
                }
                return parse_nlri_v6(withdrawn);
            }
        }
        Ok(Vec::new())
    }
}

/// Encode a list of IPv4 prefixes in BGP NLRI format:
/// `<length(1)> <prefix(ceil(length/8))>`.
fn encode_nlri_v4(prefixes: &[Prefix4]) -> Vec<u8> {
    let mut out = Vec::new();
    for p in prefixes {
        out.push(p.len);
        let bytes = (p.len as usize + 7) / 8;
        out.extend_from_slice(&p.addr.octets()[..bytes]);
    }
    out
}

fn parse_nlri_v4(buf: &[u8]) -> Result<Vec<Prefix4>, ParseError> {
    let mut out = Vec::new();
    let mut p = 0;
    while p < buf.len() {
        let len = buf[p];
        if len > 32 {
            return Err(ParseError::Update {
                code: ErrorCode::UpdateMessage,
                subcode: UpdateMessageSubcode::InvalidNetworkField as u8,
                message: format!("IPv4 NLRI prefix length {} > 32", len),
                action: AttributeErrorAction::TreatAsWithdraw,
            });
        }
        let bytes = (len as usize + 7) / 8;
        if buf.len() - p - 1 < bytes {
            return Err(ParseError::Update {
                code: ErrorCode::UpdateMessage,
                subcode: UpdateMessageSubcode::InvalidNetworkField as u8,
                message: "IPv4 NLRI truncated".into(),
                action: AttributeErrorAction::TreatAsWithdraw,
            });
        }
        let mut octets = [0u8; 4];
        octets[..bytes].copy_from_slice(&buf[p + 1..p + 1 + bytes]);
        out.push(Prefix4 {
            addr: Ipv4Addr::from(octets),
            len,
        });
        p += 1 + bytes;
    }
    Ok(out)
}

fn parse_nlri_v6(buf: &[u8]) -> Result<Vec<Prefix6>, ParseError> {
    let mut out = Vec::new();
    let mut p = 0;
    while p < buf.len() {
        let len = buf[p];
        if len > 128 {
            return Err(ParseError::Update {
                code: ErrorCode::UpdateMessage,
                subcode: UpdateMessageSubcode::InvalidNetworkField as u8,
                message: format!("IPv6 NLRI prefix length {} > 128", len),
                action: AttributeErrorAction::TreatAsWithdraw,
            });
        }
        let bytes = (len as usize + 7) / 8;
        if buf.len() - p - 1 < bytes {
            return Err(ParseError::Update {
                code: ErrorCode::UpdateMessage,
                subcode: UpdateMessageSubcode::InvalidNetworkField as u8,
                message: "IPv6 NLRI truncated".into(),
                action: AttributeErrorAction::TreatAsWithdraw,
            });
        }
        let mut octets = [0u8; 16];
        octets[..bytes].copy_from_slice(&buf[p + 1..p + 1 + bytes]);
        out.push(Prefix6 {
            addr: Ipv6Addr::from(octets),
            len,
        });
        p += 1 + bytes;
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::attrs::{AsPathSegment, AsPathSegmentType, Origin};

    fn p4(a: u8, b: u8, c: u8, d: u8, len: u8) -> Prefix4 {
        Prefix4 {
            addr: Ipv4Addr::new(a, b, c, d),
            len,
        }
    }

    #[test]
    fn empty_update_round_trip() {
        // RFC 4724 End-of-RIB shape — empty UPDATE for IPv4 unicast.
        let update = Update::empty();
        let bytes = update.encode();
        // Header (19) + withdrawn_len (2) + attr_len (2) = 23
        assert_eq!(bytes.len(), 23);
        let header = Header::parse(&bytes).unwrap();
        assert_eq!(header.msg_type, MessageType::Update);
        let parsed = Update::parse_body(&bytes[HEADER_LEN..]).unwrap();
        assert_eq!(parsed, update);
    }

    #[test]
    fn update_with_v4_nlri_and_attrs_round_trip() {
        let update = Update {
            withdrawn_v4: Vec::new(),
            path_attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(vec![AsPathSegment {
                    seg_type: AsPathSegmentType::AsSequence,
                    asns: vec![65001, 65002],
                }]),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
                PathAttribute::LocalPref(150),
                PathAttribute::Communities(vec![(65000u32 << 16) | 200]),
            ],
            nlri_v4: vec![p4(192, 0, 2, 0, 24), p4(198, 51, 100, 0, 24)],
        };
        let bytes = update.encode();
        let parsed = Update::parse_body(&bytes[HEADER_LEN..]).unwrap();
        assert_eq!(parsed, update);
    }

    #[test]
    fn withdrawn_v4_only_round_trip() {
        let update = Update {
            withdrawn_v4: vec![p4(10, 0, 0, 0, 8), p4(192, 168, 1, 0, 24)],
            path_attributes: Vec::new(),
            nlri_v4: Vec::new(),
        };
        let bytes = update.encode();
        let parsed = Update::parse_body(&bytes[HEADER_LEN..]).unwrap();
        assert_eq!(parsed, update);
    }

    #[test]
    fn nlri_short_prefix_uses_partial_bytes() {
        // /20 uses 3 bytes of address (20 bits → ceil(20/8) = 3).
        let prefixes = vec![p4(10, 0, 0, 0, 20)];
        let encoded = encode_nlri_v4(&prefixes);
        assert_eq!(encoded, vec![20, 10, 0, 0]);
        let parsed = parse_nlri_v4(&encoded).unwrap();
        assert_eq!(parsed, prefixes);
    }

    #[test]
    fn nlri_default_route_uses_zero_bytes_of_address() {
        let prefixes = vec![p4(0, 0, 0, 0, 0)];
        let encoded = encode_nlri_v4(&prefixes);
        assert_eq!(encoded, vec![0]);
        let parsed = parse_nlri_v4(&encoded).unwrap();
        assert_eq!(parsed, prefixes);
    }

    #[test]
    fn nlri_rejects_oversized_prefix_length() {
        let bad = vec![33, 10, 0, 0, 0, 0]; // /33 doesn't exist for IPv4
        let err = parse_nlri_v4(&bad).unwrap_err();
        match err {
            ParseError::Update { subcode, action, .. } => {
                assert_eq!(subcode, UpdateMessageSubcode::InvalidNetworkField as u8);
                assert_eq!(action, AttributeErrorAction::TreatAsWithdraw);
            }
            other => panic!("wrong error: {:?}", other),
        }
    }

    #[test]
    fn mp_reach_v6_round_trip_via_update() {
        // Build an MP_REACH UPDATE for 2001:db8::/32 with next-hop
        // 2001:db8::1.
        let nlri = {
            let mut v = Vec::new();
            v.push(32u8); // prefix length
            v.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
            v
        };
        let nh = vec![
            0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
        ];
        let update = Update {
            withdrawn_v4: Vec::new(),
            path_attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(vec![AsPathSegment {
                    seg_type: AsPathSegmentType::AsSequence,
                    asns: vec![65001],
                }]),
                PathAttribute::MpReachNlri {
                    afi: crate::packet::caps::AFI_IPV6,
                    safi: crate::packet::caps::SAFI_UNICAST,
                    nexthop: nh.clone(),
                    nlri,
                },
            ],
            nlri_v4: Vec::new(),
        };
        let bytes = update.encode();
        let parsed = Update::parse_body(&bytes[HEADER_LEN..]).unwrap();
        let v6 = parsed.ipv6_nlri().unwrap();
        assert_eq!(v6.len(), 1);
        assert_eq!(v6[0].len, 32);
        assert_eq!(v6[0].addr, "2001:db8::".parse::<Ipv6Addr>().unwrap());
    }

    #[test]
    fn mp_unreach_v6_round_trip_via_update() {
        let withdrawn = {
            let mut v = Vec::new();
            v.push(32u8);
            v.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8]);
            v
        };
        let update = Update {
            withdrawn_v4: Vec::new(),
            path_attributes: vec![PathAttribute::MpUnreachNlri {
                afi: crate::packet::caps::AFI_IPV6,
                safi: crate::packet::caps::SAFI_UNICAST,
                withdrawn,
            }],
            nlri_v4: Vec::new(),
        };
        let bytes = update.encode();
        let parsed = Update::parse_body(&bytes[HEADER_LEN..]).unwrap();
        let withdrawn = parsed.ipv6_withdrawn().unwrap();
        assert_eq!(withdrawn.len(), 1);
        assert_eq!(withdrawn[0].len, 32);
    }

    #[test]
    fn parse_rejects_truncated_body() {
        let err = Update::parse_body(&[0, 0, 0]).unwrap_err();
        assert!(matches!(err, ParseError::Update { .. }));
    }

    #[test]
    fn parse_rejects_inconsistent_lengths() {
        // Withdrawn length declares 100 bytes but only 4 follow.
        let bad = vec![0, 100, 0, 0, 0, 0];
        let err = Update::parse_body(&bad).unwrap_err();
        assert!(matches!(err, ParseError::Update { .. }));
    }

    #[test]
    fn many_v4_prefixes_round_trip() {
        // 100 /24 prefixes — exercises multi-prefix NLRI loops.
        let mut nlri = Vec::with_capacity(100);
        for i in 0..100u8 {
            nlri.push(p4(192, 0, i, 0, 24));
        }
        let update = Update {
            withdrawn_v4: Vec::new(),
            path_attributes: vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(vec![AsPathSegment {
                    seg_type: AsPathSegmentType::AsSequence,
                    asns: vec![65001],
                }]),
                PathAttribute::NextHop(Ipv4Addr::new(10, 0, 0, 1)),
            ],
            nlri_v4: nlri,
        };
        let bytes = update.encode();
        let parsed = Update::parse_body(&bytes[HEADER_LEN..]).unwrap();
        assert_eq!(parsed.nlri_v4.len(), 100);
        assert_eq!(parsed, update);
    }
}
