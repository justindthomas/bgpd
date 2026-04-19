//! BGP path attributes (RFC 4271 §5 + RFC 4760 + RFC 1997 + RFC 6793).
//!
//! Wire format for a single attribute (RFC 4271 §4.3):
//!
//! ```text
//!  +------------------+
//!  |  Attr. Flags     |  1 byte
//!  +------------------+
//!  |  Attr. Type Code |  1 byte
//!  +------------------+
//!  |  Attr. Length    |  1 or 2 bytes (extended-length flag)
//!  +------------------+
//!  |  Attribute Value |  variable
//!  ~                  ~
//!  +------------------+
//! ```
//!
//! Attribute Flags bits (high to low):
//!   bit 0 (0x80): Optional        — 0=well-known, 1=optional
//!   bit 1 (0x40): Transitive      — 1 for well-known; varies for optional
//!   bit 2 (0x20): Partial         — set if any AS along the path lacked support
//!   bit 3 (0x10): Extended Length — 1 = 2-byte length, 0 = 1-byte length
//!   bits 4..7: zero
//!
//! v1 implements the attribute type codes listed in the module
//! docstring of `bgpd/src/packet/attrs.rs`. AS_PATH parsing is
//! always 4-octet (RFC 6793) — we negotiate the capability on every
//! session, so peers send 4-octet AS_PATH unconditionally. If a
//! peer chooses not to advertise the capability we still send and
//! accept 4-octet via AS4_PATH negotiation… but RFC 6793 §6
//! deprecates that path; v1 simply requires 4-octet support.

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::error::{AttributeErrorAction, ErrorCode, ParseError, UpdateMessageSubcode};

// Attribute type codes (IANA "BGP Path Attributes").
pub const ATTR_ORIGIN: u8 = 1;
pub const ATTR_AS_PATH: u8 = 2;
pub const ATTR_NEXT_HOP: u8 = 3;
pub const ATTR_MULTI_EXIT_DISC: u8 = 4;
pub const ATTR_LOCAL_PREF: u8 = 5;
pub const ATTR_ATOMIC_AGGREGATE: u8 = 6;
pub const ATTR_AGGREGATOR: u8 = 7;
pub const ATTR_COMMUNITIES: u8 = 8;
pub const ATTR_MP_REACH_NLRI: u8 = 14;
pub const ATTR_MP_UNREACH_NLRI: u8 = 15;

// Attribute flag bits.
pub const FLAG_OPTIONAL: u8 = 0x80;
pub const FLAG_TRANSITIVE: u8 = 0x40;
pub const FLAG_PARTIAL: u8 = 0x20;
pub const FLAG_EXTENDED_LENGTH: u8 = 0x10;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Origin {
    Igp = 0,
    Egp = 1,
    Incomplete = 2,
}

impl Origin {
    pub fn from_u8(v: u8) -> Result<Self, ParseError> {
        match v {
            0 => Ok(Origin::Igp),
            1 => Ok(Origin::Egp),
            2 => Ok(Origin::Incomplete),
            other => Err(ParseError::Update {
                code: ErrorCode::UpdateMessage,
                subcode: UpdateMessageSubcode::InvalidOriginAttribute as u8,
                message: format!("invalid ORIGIN value {}", other),
                // 7606 §3.g: invalid ORIGIN is treat-as-withdraw.
                action: AttributeErrorAction::TreatAsWithdraw,
            }),
        }
    }
}

/// AS_PATH segment types (RFC 4271 §5.1.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum AsPathSegmentType {
    AsSet = 1,
    AsSequence = 2,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsPathSegment {
    pub seg_type: AsPathSegmentType,
    pub asns: Vec<u32>,
}

impl AsPathSegment {
    /// Encode one segment: 1-byte type, 1-byte ASN count, N×4-byte
    /// ASNs (RFC 6793 §3, 4-octet form).
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(2 + 4 * self.asns.len());
        out.push(self.seg_type as u8);
        out.push(self.asns.len() as u8);
        for asn in &self.asns {
            out.extend_from_slice(&asn.to_be_bytes());
        }
        out
    }

    /// Parse one segment, returning (segment, bytes consumed).
    pub fn parse(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.len() < 2 {
            return Err(ParseError::Update {
                code: ErrorCode::UpdateMessage,
                subcode: UpdateMessageSubcode::MalformedAsPath as u8,
                message: "AS_PATH segment header truncated".into(),
                action: AttributeErrorAction::SessionReset,
            });
        }
        let seg_type = match buf[0] {
            1 => AsPathSegmentType::AsSet,
            2 => AsPathSegmentType::AsSequence,
            other => {
                return Err(ParseError::Update {
                    code: ErrorCode::UpdateMessage,
                    subcode: UpdateMessageSubcode::MalformedAsPath as u8,
                    message: format!("unknown AS_PATH segment type {}", other),
                    action: AttributeErrorAction::SessionReset,
                })
            }
        };
        let count = buf[1] as usize;
        let need = 2 + 4 * count;
        if buf.len() < need {
            return Err(ParseError::Update {
                code: ErrorCode::UpdateMessage,
                subcode: UpdateMessageSubcode::MalformedAsPath as u8,
                message: format!(
                    "AS_PATH segment: declared {} ASNs, only {} bytes left",
                    count,
                    buf.len() - 2
                ),
                action: AttributeErrorAction::SessionReset,
            });
        }
        let mut asns = Vec::with_capacity(count);
        for i in 0..count {
            let off = 2 + 4 * i;
            asns.push(u32::from_be_bytes([
                buf[off],
                buf[off + 1],
                buf[off + 2],
                buf[off + 3],
            ]));
        }
        Ok((AsPathSegment { seg_type, asns }, need))
    }
}

/// A parsed BGP path attribute. The wire flags are reconstructed
/// from the variant on encode (well-known mandatory attributes
/// have their flag bits prescribed by RFC 4271 §5.1; we don't let
/// callers override them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathAttribute {
    Origin(Origin),
    AsPath(Vec<AsPathSegment>),
    NextHop(Ipv4Addr),
    MultiExitDisc(u32),
    LocalPref(u32),
    AtomicAggregate,
    Aggregator { asn: u32, addr: Ipv4Addr },
    /// Standard communities, RFC 1997. Each community is a 32-bit
    /// value; the high 16 bits are conventionally the ASN.
    Communities(Vec<u32>),
    /// MP_REACH_NLRI body (RFC 4760 §3). v1 only stores the
    /// per-AFI/SAFI fields in raw form; the higher-level UPDATE
    /// parser unpacks NLRI.
    MpReachNlri {
        afi: u16,
        safi: u8,
        nexthop: Vec<u8>,
        nlri: Vec<u8>,
    },
    MpUnreachNlri {
        afi: u16,
        safi: u8,
        withdrawn: Vec<u8>,
    },
    /// Anything else: preserved verbatim with its flags so we can
    /// re-encode optional-transitive attributes the speaker doesn't
    /// understand (RFC 4271 §9 "the speaker SHOULD pass it on").
    Unknown {
        flags: u8,
        type_code: u8,
        value: Vec<u8>,
    },
}

impl PathAttribute {
    pub fn type_code(&self) -> u8 {
        match self {
            PathAttribute::Origin(_) => ATTR_ORIGIN,
            PathAttribute::AsPath(_) => ATTR_AS_PATH,
            PathAttribute::NextHop(_) => ATTR_NEXT_HOP,
            PathAttribute::MultiExitDisc(_) => ATTR_MULTI_EXIT_DISC,
            PathAttribute::LocalPref(_) => ATTR_LOCAL_PREF,
            PathAttribute::AtomicAggregate => ATTR_ATOMIC_AGGREGATE,
            PathAttribute::Aggregator { .. } => ATTR_AGGREGATOR,
            PathAttribute::Communities(_) => ATTR_COMMUNITIES,
            PathAttribute::MpReachNlri { .. } => ATTR_MP_REACH_NLRI,
            PathAttribute::MpUnreachNlri { .. } => ATTR_MP_UNREACH_NLRI,
            PathAttribute::Unknown { type_code, .. } => *type_code,
        }
    }

    /// Default flags for this attribute type per RFC 4271 §5.1 +
    /// RFC 4760 §6 + RFC 1997. Used by the encoder; receivers only
    /// validate them when an attribute's flags are wrong in a way
    /// that's diagnostically interesting.
    pub fn default_flags(&self) -> u8 {
        match self {
            PathAttribute::Origin(_)
            | PathAttribute::AsPath(_)
            | PathAttribute::NextHop(_)
            | PathAttribute::LocalPref(_)
            | PathAttribute::AtomicAggregate => FLAG_TRANSITIVE,
            // MED is optional non-transitive.
            PathAttribute::MultiExitDisc(_) => FLAG_OPTIONAL,
            // Aggregator is optional transitive.
            PathAttribute::Aggregator { .. } => FLAG_OPTIONAL | FLAG_TRANSITIVE,
            // Communities (RFC 1997) is optional transitive.
            PathAttribute::Communities(_) => FLAG_OPTIONAL | FLAG_TRANSITIVE,
            // MP_REACH/UNREACH (RFC 4760) are optional non-transitive.
            PathAttribute::MpReachNlri { .. } | PathAttribute::MpUnreachNlri { .. } => {
                FLAG_OPTIONAL
            }
            PathAttribute::Unknown { flags, .. } => *flags,
        }
    }

    /// Encode just this attribute's value (no flags/type/length).
    fn encode_value(&self) -> Vec<u8> {
        match self {
            PathAttribute::Origin(o) => vec![*o as u8],
            PathAttribute::AsPath(segments) => {
                let mut out = Vec::new();
                for seg in segments {
                    out.extend(seg.encode());
                }
                out
            }
            PathAttribute::NextHop(addr) => addr.octets().to_vec(),
            PathAttribute::MultiExitDisc(med) => med.to_be_bytes().to_vec(),
            PathAttribute::LocalPref(lp) => lp.to_be_bytes().to_vec(),
            PathAttribute::AtomicAggregate => Vec::new(),
            PathAttribute::Aggregator { asn, addr } => {
                let mut out = Vec::with_capacity(8);
                out.extend_from_slice(&asn.to_be_bytes());
                out.extend_from_slice(&addr.octets());
                out
            }
            PathAttribute::Communities(cs) => {
                let mut out = Vec::with_capacity(4 * cs.len());
                for c in cs {
                    out.extend_from_slice(&c.to_be_bytes());
                }
                out
            }
            PathAttribute::MpReachNlri {
                afi,
                safi,
                nexthop,
                nlri,
            } => {
                let mut out = Vec::with_capacity(5 + nexthop.len() + nlri.len());
                out.extend_from_slice(&afi.to_be_bytes());
                out.push(*safi);
                out.push(nexthop.len() as u8);
                out.extend_from_slice(nexthop);
                out.push(0); // Reserved per RFC 4760 §3
                out.extend_from_slice(nlri);
                out
            }
            PathAttribute::MpUnreachNlri {
                afi,
                safi,
                withdrawn,
            } => {
                let mut out = Vec::with_capacity(3 + withdrawn.len());
                out.extend_from_slice(&afi.to_be_bytes());
                out.push(*safi);
                out.extend_from_slice(withdrawn);
                out
            }
            PathAttribute::Unknown { value, .. } => value.clone(),
        }
    }

    /// Encode the full attribute (flags + type + length + value).
    /// Uses 1-byte length when possible, 2-byte (extended) length
    /// when the value exceeds 255 bytes.
    pub fn encode(&self) -> Vec<u8> {
        let value = self.encode_value();
        let mut flags = self.default_flags();
        let extended = value.len() > 255;
        if extended {
            flags |= FLAG_EXTENDED_LENGTH;
        }
        let mut out = Vec::with_capacity(4 + value.len());
        out.push(flags);
        out.push(self.type_code());
        if extended {
            out.extend_from_slice(&(value.len() as u16).to_be_bytes());
        } else {
            out.push(value.len() as u8);
        }
        out.extend_from_slice(&value);
        out
    }

    /// Parse one path attribute from the start of `buf`. Returns
    /// the parsed attribute and the number of bytes consumed.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.len() < 3 {
            return Err(ParseError::Update {
                code: ErrorCode::UpdateMessage,
                subcode: UpdateMessageSubcode::MalformedAttributeList as u8,
                message: format!(
                    "path attribute header truncated: {} bytes",
                    buf.len()
                ),
                action: AttributeErrorAction::SessionReset,
            });
        }
        let flags = buf[0];
        let type_code = buf[1];
        let extended = flags & FLAG_EXTENDED_LENGTH != 0;
        let (value_len, header_len) = if extended {
            if buf.len() < 4 {
                return Err(ParseError::Update {
                    code: ErrorCode::UpdateMessage,
                    subcode: UpdateMessageSubcode::AttributeLengthError as u8,
                    message: "extended-length attribute header truncated".into(),
                    action: AttributeErrorAction::SessionReset,
                });
            }
            (u16::from_be_bytes([buf[2], buf[3]]) as usize, 4)
        } else {
            (buf[2] as usize, 3)
        };
        if buf.len() < header_len + value_len {
            return Err(ParseError::Update {
                code: ErrorCode::UpdateMessage,
                subcode: UpdateMessageSubcode::AttributeLengthError as u8,
                message: format!(
                    "attribute type {}: declared {} bytes, only {} available",
                    type_code,
                    value_len,
                    buf.len() - header_len
                ),
                action: AttributeErrorAction::SessionReset,
            });
        }
        let value = &buf[header_len..header_len + value_len];
        let attr = match type_code {
            ATTR_ORIGIN => {
                if value.len() != 1 {
                    return Err(ParseError::Update {
                        code: ErrorCode::UpdateMessage,
                        subcode: UpdateMessageSubcode::AttributeLengthError as u8,
                        message: format!("ORIGIN must be 1 byte, got {}", value.len()),
                        action: AttributeErrorAction::TreatAsWithdraw,
                    });
                }
                PathAttribute::Origin(Origin::from_u8(value[0])?)
            }
            ATTR_AS_PATH => {
                let mut segments = Vec::new();
                let mut p = 0;
                while p < value.len() {
                    let (seg, n) = AsPathSegment::parse(&value[p..])?;
                    segments.push(seg);
                    p += n;
                }
                PathAttribute::AsPath(segments)
            }
            ATTR_NEXT_HOP => {
                if value.len() != 4 {
                    return Err(ParseError::Update {
                        code: ErrorCode::UpdateMessage,
                        subcode: UpdateMessageSubcode::InvalidNextHopAttribute as u8,
                        message: format!("NEXT_HOP must be 4 bytes, got {}", value.len()),
                        action: AttributeErrorAction::TreatAsWithdraw,
                    });
                }
                PathAttribute::NextHop(Ipv4Addr::from([
                    value[0], value[1], value[2], value[3],
                ]))
            }
            ATTR_MULTI_EXIT_DISC => {
                if value.len() != 4 {
                    return Err(ParseError::Update {
                        code: ErrorCode::UpdateMessage,
                        subcode: UpdateMessageSubcode::AttributeLengthError as u8,
                        message: format!("MED must be 4 bytes, got {}", value.len()),
                        action: AttributeErrorAction::TreatAsWithdraw,
                    });
                }
                PathAttribute::MultiExitDisc(u32::from_be_bytes([
                    value[0], value[1], value[2], value[3],
                ]))
            }
            ATTR_LOCAL_PREF => {
                if value.len() != 4 {
                    return Err(ParseError::Update {
                        code: ErrorCode::UpdateMessage,
                        subcode: UpdateMessageSubcode::AttributeLengthError as u8,
                        message: format!("LOCAL_PREF must be 4 bytes, got {}", value.len()),
                        action: AttributeErrorAction::TreatAsWithdraw,
                    });
                }
                PathAttribute::LocalPref(u32::from_be_bytes([
                    value[0], value[1], value[2], value[3],
                ]))
            }
            ATTR_ATOMIC_AGGREGATE => {
                if !value.is_empty() {
                    return Err(ParseError::Update {
                        code: ErrorCode::UpdateMessage,
                        subcode: UpdateMessageSubcode::AttributeLengthError as u8,
                        message: format!(
                            "ATOMIC_AGGREGATE must be 0 bytes, got {}",
                            value.len()
                        ),
                        action: AttributeErrorAction::AttributeDiscard,
                    });
                }
                PathAttribute::AtomicAggregate
            }
            ATTR_AGGREGATOR => {
                // 4-octet AGGREGATOR per RFC 6793 §5: 4-byte ASN +
                // 4-byte address = 8 bytes total. The legacy 6-byte
                // form (2-byte ASN) is technically possible from an
                // ancient peer; we treat it as malformed and
                // discard the attribute (RFC 7606 §6).
                if value.len() != 8 {
                    return Err(ParseError::Update {
                        code: ErrorCode::UpdateMessage,
                        subcode: UpdateMessageSubcode::AttributeLengthError as u8,
                        message: format!("AGGREGATOR must be 8 bytes (4-octet ASN), got {}", value.len()),
                        action: AttributeErrorAction::AttributeDiscard,
                    });
                }
                let asn = u32::from_be_bytes([value[0], value[1], value[2], value[3]]);
                let addr = Ipv4Addr::from([value[4], value[5], value[6], value[7]]);
                PathAttribute::Aggregator { asn, addr }
            }
            ATTR_COMMUNITIES => {
                if value.len() % 4 != 0 {
                    return Err(ParseError::Update {
                        code: ErrorCode::UpdateMessage,
                        subcode: UpdateMessageSubcode::OptionalAttributeError as u8,
                        message: format!(
                            "COMMUNITIES length {} not a multiple of 4",
                            value.len()
                        ),
                        action: AttributeErrorAction::AttributeDiscard,
                    });
                }
                let mut cs = Vec::with_capacity(value.len() / 4);
                for chunk in value.chunks(4) {
                    cs.push(u32::from_be_bytes([
                        chunk[0], chunk[1], chunk[2], chunk[3],
                    ]));
                }
                PathAttribute::Communities(cs)
            }
            ATTR_MP_REACH_NLRI => {
                // RFC 4760 §3: AFI(2) + SAFI(1) + NHLen(1) +
                // NextHop(NHLen) + Reserved(1) + NLRI(rest)
                if value.len() < 5 {
                    return Err(ParseError::Update {
                        code: ErrorCode::UpdateMessage,
                        subcode: UpdateMessageSubcode::OptionalAttributeError as u8,
                        message: "MP_REACH_NLRI too short".into(),
                        action: AttributeErrorAction::TreatAsWithdraw,
                    });
                }
                let afi = u16::from_be_bytes([value[0], value[1]]);
                let safi = value[2];
                let nh_len = value[3] as usize;
                if value.len() < 4 + nh_len + 1 {
                    return Err(ParseError::Update {
                        code: ErrorCode::UpdateMessage,
                        subcode: UpdateMessageSubcode::OptionalAttributeError as u8,
                        message: "MP_REACH_NLRI nexthop length exceeds attribute".into(),
                        action: AttributeErrorAction::TreatAsWithdraw,
                    });
                }
                let nexthop = value[4..4 + nh_len].to_vec();
                // value[4 + nh_len] is the Reserved byte
                let nlri = value[4 + nh_len + 1..].to_vec();
                PathAttribute::MpReachNlri {
                    afi,
                    safi,
                    nexthop,
                    nlri,
                }
            }
            ATTR_MP_UNREACH_NLRI => {
                if value.len() < 3 {
                    return Err(ParseError::Update {
                        code: ErrorCode::UpdateMessage,
                        subcode: UpdateMessageSubcode::OptionalAttributeError as u8,
                        message: "MP_UNREACH_NLRI too short".into(),
                        action: AttributeErrorAction::TreatAsWithdraw,
                    });
                }
                let afi = u16::from_be_bytes([value[0], value[1]]);
                let safi = value[2];
                let withdrawn = value[3..].to_vec();
                PathAttribute::MpUnreachNlri {
                    afi,
                    safi,
                    withdrawn,
                }
            }
            _ => PathAttribute::Unknown {
                flags,
                type_code,
                value: value.to_vec(),
            },
        };
        Ok((attr, header_len + value_len))
    }
}

/// Parse the AGGREGATOR attribute's address as an IPv6 if needed.
/// Used by tests; not part of the wire path. Kept here so the
/// helper colocates with the parser it documents.
#[allow(dead_code)]
fn ipv6_from_bytes(b: &[u8]) -> Option<Ipv6Addr> {
    if b.len() != 16 {
        return None;
    }
    let mut a = [0u8; 16];
    a.copy_from_slice(b);
    Some(Ipv6Addr::from(a))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roundtrip(attr: &PathAttribute) -> PathAttribute {
        let bytes = attr.encode();
        let (parsed, consumed) = PathAttribute::parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len(), "consumed != produced");
        parsed
    }

    #[test]
    fn origin_roundtrip_all_values() {
        for o in [Origin::Igp, Origin::Egp, Origin::Incomplete] {
            let attr = PathAttribute::Origin(o);
            assert_eq!(roundtrip(&attr), attr);
        }
    }

    #[test]
    fn next_hop_roundtrip() {
        let attr = PathAttribute::NextHop(Ipv4Addr::new(192, 0, 2, 1));
        assert_eq!(roundtrip(&attr), attr);
    }

    #[test]
    fn local_pref_roundtrip() {
        let attr = PathAttribute::LocalPref(150);
        assert_eq!(roundtrip(&attr), attr);
    }

    #[test]
    fn med_roundtrip() {
        let attr = PathAttribute::MultiExitDisc(42);
        assert_eq!(roundtrip(&attr), attr);
    }

    #[test]
    fn atomic_aggregate_roundtrip() {
        let attr = PathAttribute::AtomicAggregate;
        assert_eq!(roundtrip(&attr), attr);
    }

    #[test]
    fn aggregator_roundtrip_4octet_asn() {
        let attr = PathAttribute::Aggregator {
            asn: 4_200_000_000,
            addr: Ipv4Addr::new(10, 0, 0, 1),
        };
        assert_eq!(roundtrip(&attr), attr);
    }

    #[test]
    fn as_path_sequence_roundtrip() {
        let attr = PathAttribute::AsPath(vec![AsPathSegment {
            seg_type: AsPathSegmentType::AsSequence,
            asns: vec![64512, 64513, 4_200_000_000],
        }]);
        assert_eq!(roundtrip(&attr), attr);
    }

    #[test]
    fn as_path_set_after_sequence_roundtrip() {
        let attr = PathAttribute::AsPath(vec![
            AsPathSegment {
                seg_type: AsPathSegmentType::AsSequence,
                asns: vec![65000, 65001],
            },
            AsPathSegment {
                seg_type: AsPathSegmentType::AsSet,
                asns: vec![65010, 65011, 65012],
            },
        ]);
        assert_eq!(roundtrip(&attr), attr);
    }

    #[test]
    fn communities_roundtrip() {
        let attr = PathAttribute::Communities(vec![
            (65000u32 << 16) | 100,
            (65000u32 << 16) | 200,
        ]);
        assert_eq!(roundtrip(&attr), attr);
    }

    #[test]
    fn mp_reach_v6_roundtrip() {
        let attr = PathAttribute::MpReachNlri {
            afi: 2,
            safi: 1,
            nexthop: vec![
                0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
            ],
            nlri: vec![0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0],
        };
        let parsed = roundtrip(&attr);
        match parsed {
            PathAttribute::MpReachNlri {
                afi,
                safi,
                nexthop,
                nlri,
            } => {
                assert_eq!(afi, 2);
                assert_eq!(safi, 1);
                assert_eq!(nexthop.len(), 16);
                assert_eq!(nlri.len(), 9);
            }
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn mp_unreach_roundtrip() {
        let attr = PathAttribute::MpUnreachNlri {
            afi: 2,
            safi: 1,
            withdrawn: vec![0x40, 0x20, 0x01, 0x0d, 0xb8, 0x00, 0x01, 0, 0],
        };
        assert_eq!(roundtrip(&attr), attr);
    }

    #[test]
    fn extended_length_roundtrip() {
        // Build a Communities attribute with > 255 bytes of value
        // (66 communities × 4 bytes = 264 bytes) so extended-length
        // encoding kicks in.
        let cs: Vec<u32> = (0u32..66).collect();
        let attr = PathAttribute::Communities(cs.clone());
        let bytes = attr.encode();
        // First byte should have FLAG_EXTENDED_LENGTH set.
        assert_ne!(bytes[0] & FLAG_EXTENDED_LENGTH, 0);
        // Length is now 2 bytes — header is 4 bytes total.
        let parsed = roundtrip(&attr);
        match parsed {
            PathAttribute::Communities(parsed_cs) => assert_eq!(parsed_cs, cs),
            other => panic!("wrong variant: {:?}", other),
        }
    }

    #[test]
    fn unknown_optional_transitive_preserved() {
        // A made-up optional-transitive attribute (type 99) with
        // 5 bytes of opaque value. Should round-trip into Unknown
        // and back out with bytes intact (per RFC 4271 §9 we
        // forward optional-transitive attributes we don't grok).
        let mut bytes = Vec::new();
        bytes.push(FLAG_OPTIONAL | FLAG_TRANSITIVE);
        bytes.push(99);
        bytes.push(5);
        bytes.extend_from_slice(&[1, 2, 3, 4, 5]);
        let (parsed, consumed) = PathAttribute::parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        match &parsed {
            PathAttribute::Unknown {
                flags,
                type_code,
                value,
            } => {
                assert_eq!(*flags & (FLAG_OPTIONAL | FLAG_TRANSITIVE), FLAG_OPTIONAL | FLAG_TRANSITIVE);
                assert_eq!(*type_code, 99);
                assert_eq!(value, &vec![1, 2, 3, 4, 5]);
            }
            other => panic!("wrong variant: {:?}", other),
        }
        // Re-encoding the Unknown preserves the bytes.
        let re = parsed.encode();
        assert_eq!(re, bytes);
    }

    #[test]
    fn parse_rejects_truncated_attribute_value() {
        // type 5 (LOCAL_PREF), length 4, but only 2 bytes follow.
        let bad = vec![FLAG_TRANSITIVE, ATTR_LOCAL_PREF, 4, 0, 1];
        let err = PathAttribute::parse(&bad).unwrap_err();
        match err {
            ParseError::Update { subcode, .. } => {
                assert_eq!(subcode, UpdateMessageSubcode::AttributeLengthError as u8);
            }
            other => panic!("wrong error: {:?}", other),
        }
    }

    #[test]
    fn invalid_origin_is_treat_as_withdraw() {
        // Per RFC 7606 §3.g.
        let bad = vec![FLAG_TRANSITIVE, ATTR_ORIGIN, 1, 99];
        let err = PathAttribute::parse(&bad).unwrap_err();
        match err {
            ParseError::Update { action, .. } => {
                assert_eq!(action, AttributeErrorAction::TreatAsWithdraw);
            }
            other => panic!("wrong error: {:?}", other),
        }
    }
}
