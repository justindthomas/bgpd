//! BGP message header (RFC 4271 §4.1).
//!
//! Wire format:
//!
//! ```text
//!   0                   1                   2                   3
//!   0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |                                                               |
//!  +                                                               +
//!  |                                                               |
//!  +                           Marker (16 bytes)                   +
//!  |                                                               |
//!  +                                                               +
//!  |                                                               |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |          Length (16 bits, total msg len incl. header)         |
//!  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//!  |     Type      |
//!  +-+-+-+-+-+-+-+-+
//! ```
//!
//! The Marker field is all-ones (`0xff` × 16) for unauthenticated
//! sessions. Authenticated sessions used to use it for an MD5
//! signature per RFC 2385's original spec, but modern deployments
//! moved that to the TCP layer (TCP_MD5SIG) and the marker is
//! always `0xff`. RFC 4271 §4.1 says implementations MUST set it
//! to all-ones when sending and MUST verify it on receive.

use crate::error::{ErrorCode, MessageHeaderSubcode, ParseError};

pub const HEADER_LEN: usize = 19;
pub const MIN_MESSAGE_LEN: usize = 19;
pub const MAX_MESSAGE_LEN: usize = 4096;

pub const MARKER: [u8; 16] = [0xff; 16];

/// BGP message type codes (RFC 4271 §4.1, RFC 2918 for ROUTE-REFRESH).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Open = 1,
    Update = 2,
    Notification = 3,
    Keepalive = 4,
    RouteRefresh = 5,
}

impl MessageType {
    pub fn from_u8(v: u8) -> Result<Self, ParseError> {
        match v {
            1 => Ok(MessageType::Open),
            2 => Ok(MessageType::Update),
            3 => Ok(MessageType::Notification),
            4 => Ok(MessageType::Keepalive),
            5 => Ok(MessageType::RouteRefresh),
            other => Err(ParseError::Header {
                code: ErrorCode::MessageHeader,
                subcode: MessageHeaderSubcode::BadMessageType as u8,
                message: format!("unknown BGP message type {}", other),
            }),
        }
    }
}

/// Parsed BGP header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Header {
    pub length: u16,
    pub msg_type: MessageType,
}

impl Header {
    /// Parse the 19-byte BGP header. Validates the marker (all
    /// ones), the length range, and the message type. Returns the
    /// parsed header on success; returns a `ParseError` matching
    /// the RFC 4271 §6.1 NOTIFICATION subcodes on failure so the
    /// caller can escalate to a NOTIFICATION + session reset.
    pub fn parse(buf: &[u8]) -> Result<Self, ParseError> {
        if buf.len() < HEADER_LEN {
            return Err(ParseError::Truncated {
                wanted: HEADER_LEN,
                got: buf.len(),
            });
        }
        if buf[..16] != MARKER {
            return Err(ParseError::Header {
                code: ErrorCode::MessageHeader,
                // RFC 4271 §6.1: "Connection Not Synchronized" is
                // the subcode for a bad marker. Receivers reset the
                // session on this.
                subcode: MessageHeaderSubcode::ConnectionNotSynchronized as u8,
                message: "marker must be all ones".into(),
            });
        }
        let length = u16::from_be_bytes([buf[16], buf[17]]);
        let length_us = length as usize;
        if length_us < MIN_MESSAGE_LEN || length_us > MAX_MESSAGE_LEN {
            return Err(ParseError::Header {
                code: ErrorCode::MessageHeader,
                subcode: MessageHeaderSubcode::BadMessageLength as u8,
                message: format!(
                    "BGP message length {} out of range [{}, {}]",
                    length, MIN_MESSAGE_LEN, MAX_MESSAGE_LEN
                ),
            });
        }
        let msg_type = MessageType::from_u8(buf[18])?;
        Ok(Header { length, msg_type })
    }

    /// Encode the header into the first 19 bytes of `out`. The
    /// caller has already sized `out` to the full message length
    /// (including this header). Length is taken from `out.len()`.
    pub fn encode(out: &mut [u8], msg_type: MessageType) {
        debug_assert!(out.len() >= HEADER_LEN);
        out[..16].copy_from_slice(&MARKER);
        let len = out.len() as u16;
        out[16..18].copy_from_slice(&len.to_be_bytes());
        out[18] = msg_type as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_header_roundtrip() {
        // KEEPALIVE is the smallest possible BGP message: header
        // only, length = 19. Useful as a header-format sanity
        // check — both encode and decode see exactly the bytes
        // they're supposed to.
        let mut buf = vec![0u8; HEADER_LEN];
        Header::encode(&mut buf, MessageType::Keepalive);
        assert_eq!(buf[..16], MARKER);
        assert_eq!(u16::from_be_bytes([buf[16], buf[17]]), HEADER_LEN as u16);
        assert_eq!(buf[18], 4);
        let h = Header::parse(&buf).unwrap();
        assert_eq!(h.msg_type, MessageType::Keepalive);
        assert_eq!(h.length, HEADER_LEN as u16);
    }

    #[test]
    fn parse_rejects_bad_marker() {
        let mut buf = vec![0u8; HEADER_LEN];
        Header::encode(&mut buf, MessageType::Keepalive);
        buf[5] = 0; // corrupt one byte of the marker
        let err = Header::parse(&buf).unwrap_err();
        match err {
            ParseError::Header { code, subcode, .. } => {
                assert_eq!(code, ErrorCode::MessageHeader);
                assert_eq!(
                    subcode,
                    MessageHeaderSubcode::ConnectionNotSynchronized as u8
                );
            }
            other => panic!("wrong error: {:?}", other),
        }
    }

    #[test]
    fn parse_rejects_too_short() {
        let buf = vec![0u8; 5];
        let err = Header::parse(&buf).unwrap_err();
        assert!(matches!(err, ParseError::Truncated { .. }));
    }

    #[test]
    fn parse_rejects_length_below_minimum() {
        // Forge a header with length = 18 (one less than the legal
        // minimum). RFC 4271 §6.1 says this triggers "Bad Message
        // Length".
        let mut buf = vec![0xffu8; HEADER_LEN];
        buf[16..18].copy_from_slice(&18u16.to_be_bytes());
        buf[18] = 4;
        let err = Header::parse(&buf).unwrap_err();
        match err {
            ParseError::Header { subcode, .. } => {
                assert_eq!(subcode, MessageHeaderSubcode::BadMessageLength as u8);
            }
            other => panic!("wrong error: {:?}", other),
        }
    }

    #[test]
    fn parse_rejects_length_above_maximum() {
        let mut buf = vec![0xffu8; HEADER_LEN];
        buf[16..18].copy_from_slice(&4097u16.to_be_bytes());
        buf[18] = 2;
        let err = Header::parse(&buf).unwrap_err();
        match err {
            ParseError::Header { subcode, .. } => {
                assert_eq!(subcode, MessageHeaderSubcode::BadMessageLength as u8);
            }
            other => panic!("wrong error: {:?}", other),
        }
    }

    #[test]
    fn parse_rejects_unknown_message_type() {
        let mut buf = vec![0xffu8; HEADER_LEN];
        buf[16..18].copy_from_slice(&(HEADER_LEN as u16).to_be_bytes());
        buf[18] = 99;
        let err = Header::parse(&buf).unwrap_err();
        match err {
            ParseError::Header { subcode, .. } => {
                assert_eq!(subcode, MessageHeaderSubcode::BadMessageType as u8);
            }
            other => panic!("wrong error: {:?}", other),
        }
    }

    #[test]
    fn message_type_round_trip_all_values() {
        for (val, ty) in [
            (1u8, MessageType::Open),
            (2, MessageType::Update),
            (3, MessageType::Notification),
            (4, MessageType::Keepalive),
            (5, MessageType::RouteRefresh),
        ] {
            assert_eq!(MessageType::from_u8(val).unwrap(), ty);
            assert_eq!(ty as u8, val);
        }
    }
}
