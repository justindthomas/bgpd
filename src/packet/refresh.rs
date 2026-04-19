//! ROUTE-REFRESH message (RFC 2918, RFC 7313 enhanced).
//!
//! Wire format (RFC 2918 §3):
//!
//! ```text
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |       AFI (16 bits)           |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |   Reserved    |     SAFI      |
//!  +---------------+---------------+
//! ```
//!
//! Total message length = 19 + 4 = 23 bytes. RFC 7313's enhanced
//! refresh adds a "subtype" in the Reserved byte (Begin-of-RIB /
//! End-of-RIB markers); v1 ignores those subtypes (sends 0,
//! tolerates non-zero on receive).

use crate::error::ParseError;
use crate::packet::header::{Header, MessageType, HEADER_LEN};

pub const ROUTE_REFRESH_LEN: usize = HEADER_LEN + 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RouteRefresh {
    pub afi: u16,
    pub safi: u8,
}

impl RouteRefresh {
    pub fn encode(&self) -> Vec<u8> {
        let mut buf = vec![0u8; ROUTE_REFRESH_LEN];
        Header::encode(&mut buf, MessageType::RouteRefresh);
        buf[HEADER_LEN..HEADER_LEN + 2].copy_from_slice(&self.afi.to_be_bytes());
        // buf[HEADER_LEN + 2] is the Reserved/Subtype byte — left
        // as zero per RFC 7313's "Normal Route-Refresh".
        buf[HEADER_LEN + 3] = self.safi;
        buf
    }

    pub fn parse_body(body: &[u8]) -> Result<Self, ParseError> {
        if body.len() < 4 {
            return Err(ParseError::Notification {
                code: crate::error::ErrorCode::RouteRefreshMessage,
                subcode: 0,
                message: format!(
                    "ROUTE-REFRESH body too short: {} bytes (need 4)",
                    body.len()
                ),
            });
        }
        let afi = u16::from_be_bytes([body[0], body[1]]);
        let safi = body[3];
        Ok(RouteRefresh { afi, safi })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_refresh_round_trip_v4_unicast() {
        // AFI 1 / SAFI 1 = IPv4 unicast (IANA address-family-numbers).
        let rr = RouteRefresh { afi: 1, safi: 1 };
        let bytes = rr.encode();
        assert_eq!(bytes.len(), ROUTE_REFRESH_LEN);
        let header = Header::parse(&bytes).unwrap();
        assert_eq!(header.msg_type, MessageType::RouteRefresh);
        let parsed = RouteRefresh::parse_body(&bytes[HEADER_LEN..]).unwrap();
        assert_eq!(parsed, rr);
    }

    #[test]
    fn route_refresh_round_trip_v6_unicast() {
        let rr = RouteRefresh { afi: 2, safi: 1 };
        let bytes = rr.encode();
        let parsed = RouteRefresh::parse_body(&bytes[HEADER_LEN..]).unwrap();
        assert_eq!(parsed, rr);
    }
}
