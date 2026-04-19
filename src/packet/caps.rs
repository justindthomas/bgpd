//! Capability TLVs (RFC 5492).
//!
//! Capabilities are advertised inside the OPEN message's optional
//! parameters area. Each capability has a 1-byte code, a 1-byte
//! length, and a variable-length value:
//!
//! ```text
//!  +------------------------------+
//!  | Capability Code (1 octet)    |
//!  +------------------------------+
//!  | Capability Length (1 octet)  |
//!  +------------------------------+
//!  | Capability Value (variable)  |
//!  ~                              ~
//!  +------------------------------+
//! ```
//!
//! v1 understands three capability codes:
//!
//! - **1** Multiprotocol Extensions (RFC 4760, 4 bytes: AFI/Reserved/SAFI)
//! - **2** Route Refresh (RFC 2918, length 0)
//! - **65** 4-octet AS Number (RFC 6793, 4 bytes: ASN)
//!
//! Everything else gets parsed into [`Capability::Unknown`] and
//! preserved so we can echo it back in NOTIFICATION subcode 7
//! ("Unsupported Capability") if needed.

use crate::error::ParseError;

pub const CAPABILITY_MULTIPROTOCOL: u8 = 1;
pub const CAPABILITY_ROUTE_REFRESH: u8 = 2;
pub const CAPABILITY_FOUR_OCTET_ASN: u8 = 65;

/// IANA AFI numbers used by BGP MP-BGP (RFC 4760).
pub const AFI_IPV4: u16 = 1;
pub const AFI_IPV6: u16 = 2;

/// IANA SAFI numbers used by BGP.
pub const SAFI_UNICAST: u8 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Capability {
    Multiprotocol { afi: u16, safi: u8 },
    RouteRefresh,
    FourOctetAsn(u32),
    /// Anything we don't recognize. Preserved verbatim so we can
    /// reflect it in error reporting.
    Unknown { code: u8, value: Vec<u8> },
}

impl Capability {
    pub fn code(&self) -> u8 {
        match self {
            Capability::Multiprotocol { .. } => CAPABILITY_MULTIPROTOCOL,
            Capability::RouteRefresh => CAPABILITY_ROUTE_REFRESH,
            Capability::FourOctetAsn(_) => CAPABILITY_FOUR_OCTET_ASN,
            Capability::Unknown { code, .. } => *code,
        }
    }

    /// Encode a single capability as `code | len | value`.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            Capability::Multiprotocol { afi, safi } => {
                let mut v = vec![CAPABILITY_MULTIPROTOCOL, 4];
                v.extend_from_slice(&afi.to_be_bytes());
                v.push(0); // Reserved
                v.push(*safi);
                v
            }
            Capability::RouteRefresh => vec![CAPABILITY_ROUTE_REFRESH, 0],
            Capability::FourOctetAsn(asn) => {
                let mut v = vec![CAPABILITY_FOUR_OCTET_ASN, 4];
                v.extend_from_slice(&asn.to_be_bytes());
                v
            }
            Capability::Unknown { code, value } => {
                let mut v = vec![*code, value.len() as u8];
                v.extend_from_slice(value);
                v
            }
        }
    }

    /// Parse one capability TLV from the start of `buf`. Returns
    /// the parsed cap and the number of bytes consumed.
    pub fn parse(buf: &[u8]) -> Result<(Self, usize), ParseError> {
        if buf.len() < 2 {
            return Err(ParseError::Capability(format!(
                "capability TLV too short: {} bytes",
                buf.len()
            )));
        }
        let code = buf[0];
        let len = buf[1] as usize;
        if buf.len() < 2 + len {
            return Err(ParseError::Capability(format!(
                "capability code {} length {} exceeds buffer ({} bytes left)",
                code,
                len,
                buf.len() - 2
            )));
        }
        let value = &buf[2..2 + len];
        let cap = match code {
            CAPABILITY_MULTIPROTOCOL => {
                if value.len() != 4 {
                    return Err(ParseError::Capability(format!(
                        "MP-BGP capability must be 4 bytes, got {}",
                        value.len()
                    )));
                }
                let afi = u16::from_be_bytes([value[0], value[1]]);
                // value[2] is the Reserved byte — ignored on receive.
                let safi = value[3];
                Capability::Multiprotocol { afi, safi }
            }
            CAPABILITY_ROUTE_REFRESH => {
                if !value.is_empty() {
                    return Err(ParseError::Capability(format!(
                        "Route-Refresh capability must be 0 bytes, got {}",
                        value.len()
                    )));
                }
                Capability::RouteRefresh
            }
            CAPABILITY_FOUR_OCTET_ASN => {
                if value.len() != 4 {
                    return Err(ParseError::Capability(format!(
                        "4-octet ASN capability must be 4 bytes, got {}",
                        value.len()
                    )));
                }
                Capability::FourOctetAsn(u32::from_be_bytes([
                    value[0], value[1], value[2], value[3],
                ]))
            }
            _ => Capability::Unknown {
                code,
                value: value.to_vec(),
            },
        };
        Ok((cap, 2 + len))
    }

    /// Parse a sequence of capability TLVs out of a buffer (the
    /// "Capabilities Optional Parameter" payload).
    pub fn parse_many(mut buf: &[u8]) -> Result<Vec<Self>, ParseError> {
        let mut out = Vec::new();
        while !buf.is_empty() {
            let (cap, consumed) = Self::parse(buf)?;
            out.push(cap);
            buf = &buf[consumed..];
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multiprotocol_v4_unicast_round_trip() {
        let cap = Capability::Multiprotocol {
            afi: AFI_IPV4,
            safi: SAFI_UNICAST,
        };
        let bytes = cap.encode();
        // code=1 len=4 afi=0x0001 reserved=0 safi=1
        assert_eq!(bytes, vec![1, 4, 0, 1, 0, 1]);
        let (parsed, consumed) = Capability::parse(&bytes).unwrap();
        assert_eq!(parsed, cap);
        assert_eq!(consumed, 6);
    }

    #[test]
    fn multiprotocol_v6_unicast_round_trip() {
        let cap = Capability::Multiprotocol {
            afi: AFI_IPV6,
            safi: SAFI_UNICAST,
        };
        let (parsed, _) = Capability::parse(&cap.encode()).unwrap();
        assert_eq!(parsed, cap);
    }

    #[test]
    fn route_refresh_round_trip() {
        let cap = Capability::RouteRefresh;
        let bytes = cap.encode();
        assert_eq!(bytes, vec![2, 0]);
        let (parsed, consumed) = Capability::parse(&bytes).unwrap();
        assert_eq!(parsed, Capability::RouteRefresh);
        assert_eq!(consumed, 2);
    }

    #[test]
    fn four_octet_asn_round_trip() {
        let cap = Capability::FourOctetAsn(64512);
        let bytes = cap.encode();
        assert_eq!(bytes, vec![65, 4, 0, 0, 0xfc, 0x00]);
        let (parsed, _) = Capability::parse(&bytes).unwrap();
        assert_eq!(parsed, cap);
    }

    #[test]
    fn four_octet_asn_large() {
        // ASN 4_200_000_000 — typical 32-bit private range.
        let cap = Capability::FourOctetAsn(4_200_000_000);
        let (parsed, _) = Capability::parse(&cap.encode()).unwrap();
        assert_eq!(parsed, cap);
    }

    #[test]
    fn unknown_capability_preserved() {
        // Code 70 with 3 bytes of value.
        let bytes = vec![70, 3, 0xaa, 0xbb, 0xcc];
        let (parsed, consumed) = Capability::parse(&bytes).unwrap();
        assert_eq!(consumed, 5);
        match parsed {
            Capability::Unknown { code, value } => {
                assert_eq!(code, 70);
                assert_eq!(value, vec![0xaa, 0xbb, 0xcc]);
            }
            other => panic!("expected Unknown, got {:?}", other),
        }
    }

    #[test]
    fn parse_many_reads_all_capabilities() {
        let mut buf = Vec::new();
        buf.extend(Capability::RouteRefresh.encode());
        buf.extend(
            Capability::Multiprotocol {
                afi: AFI_IPV4,
                safi: SAFI_UNICAST,
            }
            .encode(),
        );
        buf.extend(Capability::FourOctetAsn(65001).encode());
        let caps = Capability::parse_many(&buf).unwrap();
        assert_eq!(caps.len(), 3);
        assert_eq!(caps[0], Capability::RouteRefresh);
        assert!(matches!(caps[1], Capability::Multiprotocol { afi: 1, safi: 1 }));
        assert_eq!(caps[2], Capability::FourOctetAsn(65001));
    }

    #[test]
    fn parse_rejects_truncated_value() {
        // code=1 declares len=4 but only 2 bytes follow.
        let bad = vec![1, 4, 0, 1];
        let err = Capability::parse(&bad).unwrap_err();
        assert!(matches!(err, ParseError::Capability(_)));
    }

    #[test]
    fn parse_rejects_wrong_mp_length() {
        let bad = vec![1, 5, 0, 1, 0, 1, 0]; // 5 bytes instead of 4
        let err = Capability::parse(&bad).unwrap_err();
        assert!(matches!(err, ParseError::Capability(_)));
    }
}
