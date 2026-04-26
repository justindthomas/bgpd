//! OPEN message (RFC 4271 §4.2 + RFC 5492 capabilities).
//!
//! Wire format:
//!
//! ```text
//!   0                   1                   2                   3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+
//!  |    Version    |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |     My Autonomous System      |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |           Hold Time           |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                         BGP Identifier                        |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  | Opt Parm Len  |
//!  +-+-+-+-+-+-+-+-+
//!  |                                                               |
//!  |             Optional Parameters (variable)                    |
//!  |                                                               |
//!  +---------------------------------------------------------------+
//! ```
//!
//! "My Autonomous System" is a 16-bit field. For 4-octet ASNs
//! (RFC 6793) the speaker advertises `AS_TRANS` (23456) here and
//! the real 32-bit ASN inside a 4-octet ASN capability. We always
//! send the 4-octet ASN capability, so for any ASN ≤ 65535 we put
//! it in both places, and for any ASN > 65535 we put 23456 here
//! and the real value in the capability. Receivers prefer the
//! capability if present.
//!
//! Optional Parameters: each parameter has a 1-byte type, 1-byte
//! length, then the value. Type 2 is "Capabilities" (RFC 5492);
//! the value is a sequence of capability TLVs as parsed by
//! [`crate::packet::caps`]. v1 only emits / understands type-2
//! optional parameters.

use std::net::Ipv4Addr;

use crate::error::{ErrorCode, OpenMessageSubcode, ParseError};
use crate::packet::caps::{Capability, CAPABILITY_FOUR_OCTET_ASN};
use crate::packet::header::{Header, MessageType, HEADER_LEN};
use crate::packet::{read_ipv4, read_u16_be};

/// BGP version field. RFC 4271 fixes this at 4 (and there is no 5).
pub const BGP_VERSION: u8 = 4;

/// AS_TRANS (RFC 6793 §9): the 16-bit ASN value placed in the
/// "My Autonomous System" field when the real ASN is a 4-octet
/// value. Receivers must look at the 4-octet ASN capability for
/// the actual value.
pub const AS_TRANS: u16 = 23456;

/// Optional parameter type: Capabilities (RFC 5492).
pub const OPT_PARAM_CAPABILITIES: u8 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Open {
    /// Speaker's actual 32-bit ASN. For ≤16-bit ASNs, callers
    /// see the same value here as in the wire "My AS" field; for
    /// >16-bit ASNs, the wire field is AS_TRANS but this struct
    /// always carries the real value.
    pub asn: u32,
    pub hold_time: u16,
    pub bgp_identifier: Ipv4Addr,
    pub capabilities: Vec<Capability>,
}

impl Open {
    /// Build a new OPEN with the four-octet-ASN capability already
    /// inserted (always emitted in v1) and any caller-provided
    /// extra capabilities appended after it.
    pub fn new(
        asn: u32,
        hold_time: u16,
        bgp_identifier: Ipv4Addr,
        extra_caps: Vec<Capability>,
    ) -> Self {
        let mut caps = vec![Capability::FourOctetAsn(asn)];
        caps.extend(extra_caps);
        Open {
            asn,
            hold_time,
            bgp_identifier,
            capabilities: caps,
        }
    }

    /// What goes in the "My Autonomous System" wire field for this
    /// speaker. Either the real 16-bit value or AS_TRANS for
    /// 4-octet ASNs.
    pub fn wire_asn(&self) -> u16 {
        if self.asn > u16::MAX as u32 {
            AS_TRANS
        } else {
            self.asn as u16
        }
    }

    /// Encode the full OPEN message including BGP header.
    pub fn encode(&self) -> Vec<u8> {
        // Build the optional-parameters block first so we know its
        // length, then prepend the fixed-length OPEN body, then the
        // header.
        let mut caps_block: Vec<u8> = Vec::new();
        for cap in &self.capabilities {
            caps_block.extend(cap.encode());
        }
        let opt_params_len = if caps_block.is_empty() {
            0
        } else {
            // type + len + caps
            2 + caps_block.len()
        };
        let body_len = 1 /* version */
            + 2 /* my AS */
            + 2 /* hold time */
            + 4 /* BGP ID */
            + 1 /* opt parm len */
            + opt_params_len;
        let total_len = HEADER_LEN + body_len;
        let mut buf = vec![0u8; total_len];
        Header::encode(&mut buf, MessageType::Open);
        let mut p = HEADER_LEN;
        buf[p] = BGP_VERSION;
        p += 1;
        buf[p..p + 2].copy_from_slice(&self.wire_asn().to_be_bytes());
        p += 2;
        buf[p..p + 2].copy_from_slice(&self.hold_time.to_be_bytes());
        p += 2;
        buf[p..p + 4].copy_from_slice(&self.bgp_identifier.octets());
        p += 4;
        buf[p] = opt_params_len as u8;
        p += 1;
        if !caps_block.is_empty() {
            buf[p] = OPT_PARAM_CAPABILITIES;
            buf[p + 1] = caps_block.len() as u8;
            buf[p + 2..p + 2 + caps_block.len()].copy_from_slice(&caps_block);
        }
        buf
    }

    /// Parse an OPEN body (the bytes *after* the 19-byte BGP header).
    pub fn parse_body(body: &[u8]) -> Result<Self, ParseError> {
        if body.len() < 10 {
            return Err(ParseError::Open {
                code: ErrorCode::OpenMessage,
                subcode: 0,
                message: format!("OPEN body too short: {} bytes (min 10)", body.len()),
            });
        }
        let version = body[0];
        if version != BGP_VERSION {
            return Err(ParseError::Open {
                code: ErrorCode::OpenMessage,
                subcode: OpenMessageSubcode::UnsupportedVersionNumber as u8,
                message: format!("unsupported BGP version {}", version),
            });
        }
        let wire_asn = read_u16_be(&body[1..3]);
        let hold_time = read_u16_be(&body[3..5]);
        let bgp_identifier = read_ipv4(&body[5..9]);
        let opt_parm_len = body[9] as usize;
        if body.len() < 10 + opt_parm_len {
            return Err(ParseError::Open {
                code: ErrorCode::OpenMessage,
                subcode: 0,
                message: format!(
                    "OPEN optional parameters declared {} bytes but only {} available",
                    opt_parm_len,
                    body.len() - 10
                ),
            });
        }
        let opt_params = &body[10..10 + opt_parm_len];
        let mut capabilities: Vec<Capability> = Vec::new();
        let mut p = 0;
        while p < opt_params.len() {
            if opt_params.len() - p < 2 {
                return Err(ParseError::Open {
                    code: ErrorCode::OpenMessage,
                    subcode: 0,
                    message: "truncated optional parameter".into(),
                });
            }
            let p_type = opt_params[p];
            let p_len = opt_params[p + 1] as usize;
            if opt_params.len() - p - 2 < p_len {
                return Err(ParseError::Open {
                    code: ErrorCode::OpenMessage,
                    subcode: 0,
                    message: format!(
                        "optional parameter type {} declares {} bytes but only {} left",
                        p_type,
                        p_len,
                        opt_params.len() - p - 2
                    ),
                });
            }
            let p_value = &opt_params[p + 2..p + 2 + p_len];
            if p_type == OPT_PARAM_CAPABILITIES {
                let caps = Capability::parse_many(p_value)
                    .map_err(|e| ParseError::Open {
                        code: ErrorCode::OpenMessage,
                        subcode: OpenMessageSubcode::UnsupportedCapability as u8,
                        message: format!("capability parse: {}", e),
                    })?;
                capabilities.extend(caps);
            } else {
                return Err(ParseError::Open {
                    code: ErrorCode::OpenMessage,
                    subcode: OpenMessageSubcode::UnsupportedOptionalParameter as u8,
                    message: format!("unknown optional parameter type {}", p_type),
                });
            }
            p += 2 + p_len;
        }

        // Resolve the real ASN: prefer the 4-octet capability over
        // the 2-byte wire field if it's present.
        let mut asn: u32 = wire_asn as u32;
        for cap in &capabilities {
            if let Capability::FourOctetAsn(v) = cap {
                asn = *v;
                break;
            }
        }
        // RFC 6793 §4.1: if the wire ASN is AS_TRANS but no
        // 4-octet ASN cap was advertised, the OPEN is malformed.
        if wire_asn == AS_TRANS
            && !capabilities
                .iter()
                .any(|c| c.code() == CAPABILITY_FOUR_OCTET_ASN)
        {
            return Err(ParseError::Open {
                code: ErrorCode::OpenMessage,
                subcode: OpenMessageSubcode::BadPeerAs as u8,
                message: "AS_TRANS in My AS but no 4-octet ASN capability".into(),
            });
        }

        Ok(Open {
            asn,
            hold_time,
            bgp_identifier,
            capabilities,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::packet::caps::{AFI_IPV4, AFI_IPV6, SAFI_UNICAST};

    #[test]
    fn open_round_trip_16bit_asn() {
        let open = Open::new(
            65001,
            90,
            Ipv4Addr::new(10, 0, 0, 1),
            vec![
                Capability::Multiprotocol {
                    afi: AFI_IPV4,
                    safi: SAFI_UNICAST,
                },
                Capability::RouteRefresh,
            ],
        );
        let bytes = open.encode();
        let header = Header::parse(&bytes).unwrap();
        assert_eq!(header.msg_type, MessageType::Open);
        assert_eq!(header.length as usize, bytes.len());
        let parsed = Open::parse_body(&bytes[HEADER_LEN..]).unwrap();
        assert_eq!(parsed.asn, 65001);
        assert_eq!(parsed.hold_time, 90);
        assert_eq!(parsed.bgp_identifier, Ipv4Addr::new(10, 0, 0, 1));
        // Capabilities present: MP, RefRefresh, plus the
        // automatically-inserted 4-octet ASN.
        assert!(parsed
            .capabilities
            .iter()
            .any(|c| matches!(c, Capability::FourOctetAsn(65001))));
        assert!(parsed
            .capabilities
            .iter()
            .any(|c| matches!(c, Capability::Multiprotocol { afi: 1, safi: 1 })));
        assert!(parsed
            .capabilities
            .iter()
            .any(|c| matches!(c, Capability::RouteRefresh)));
    }

    #[test]
    fn open_round_trip_4octet_asn() {
        let open = Open::new(
            4_200_000_000,
            180,
            Ipv4Addr::new(192, 0, 2, 1),
            vec![Capability::Multiprotocol {
                afi: AFI_IPV6,
                safi: SAFI_UNICAST,
            }],
        );
        // Wire ASN must be AS_TRANS for >16-bit ASNs.
        assert_eq!(open.wire_asn(), AS_TRANS);
        let bytes = open.encode();
        // Spot-check the wire layout: byte 19 is version, 20-21 is wire ASN.
        assert_eq!(bytes[19], BGP_VERSION);
        assert_eq!(
            u16::from_be_bytes([bytes[20], bytes[21]]),
            AS_TRANS
        );
        let parsed = Open::parse_body(&bytes[HEADER_LEN..]).unwrap();
        // Parsed ASN must be the real 4-octet value, not AS_TRANS.
        assert_eq!(parsed.asn, 4_200_000_000);
        assert_eq!(parsed.hold_time, 180);
    }

    #[test]
    fn open_rejects_unsupported_version() {
        let open = Open::new(65000, 90, Ipv4Addr::new(10, 0, 0, 1), vec![]);
        let bytes = open.encode();
        let mut tampered = bytes.clone();
        tampered[19] = 5; // version 5 doesn't exist
        let err = Open::parse_body(&tampered[HEADER_LEN..]).unwrap_err();
        match err {
            ParseError::Open { subcode, .. } => {
                assert_eq!(
                    subcode,
                    OpenMessageSubcode::UnsupportedVersionNumber as u8
                );
            }
            other => panic!("wrong error: {:?}", other),
        }
        let _ = open; // silence unused
    }

    #[test]
    fn open_rejects_truncated_body() {
        let bad = vec![BGP_VERSION, 0, 1]; // 3 bytes, need 10
        let err = Open::parse_body(&bad).unwrap_err();
        assert!(matches!(err, ParseError::Open { .. }));
    }

    #[test]
    fn open_rejects_as_trans_without_capability() {
        // Hand-craft an OPEN that uses AS_TRANS in the wire field
        // but advertises no 4-octet ASN capability. RFC 6793
        // requires the cap; this should be rejected.
        let mut body = vec![BGP_VERSION, 0, 0, 0, 90];
        // wire ASN AS_TRANS = 23456
        body[1..3].copy_from_slice(&AS_TRANS.to_be_bytes());
        // BGP identifier
        body.extend_from_slice(&[10, 0, 0, 1]);
        // opt parm len = 0
        body.push(0);
        let err = Open::parse_body(&body).unwrap_err();
        match err {
            ParseError::Open { subcode, .. } => {
                assert_eq!(subcode, OpenMessageSubcode::BadPeerAs as u8);
            }
            other => panic!("wrong error: {:?}", other),
        }
    }

    #[test]
    fn open_round_trip_no_extra_caps() {
        // Even with no caller-provided caps, the 4-octet ASN cap
        // is still emitted automatically.
        let open = Open::new(65000, 60, Ipv4Addr::new(10, 0, 0, 1), vec![]);
        let bytes = open.encode();
        let parsed = Open::parse_body(&bytes[HEADER_LEN..]).unwrap();
        assert_eq!(parsed.capabilities.len(), 1);
        assert!(matches!(
            parsed.capabilities[0],
            Capability::FourOctetAsn(65000)
        ));
    }
}
