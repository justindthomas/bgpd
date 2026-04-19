//! NOTIFICATION message (RFC 4271 §4.5).
//!
//! Wire format:
//!
//! ```text
//!  +-+-+-+-+-+-+-+-+
//!  |  Error Code   |
//!  +-+-+-+-+-+-+-+-+
//!  | Error Subcode |
//!  +-+-+-+-+-+-+-+-+
//!  |  Data (variable, may be empty)                                |
//!  +---------------------------------------------------------------+
//! ```
//!
//! Total length = 19 (header) + 2 (code+subcode) + |data| ≤ 4096.
//! Sent immediately before closing the TCP connection on any fatal
//! error. The receiver logs it and closes too.

use crate::error::{ErrorCode, ParseError};
use crate::packet::header::{Header, MessageType, HEADER_LEN, MAX_MESSAGE_LEN};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Notification {
    pub code: ErrorCode,
    pub subcode: u8,
    pub data: Vec<u8>,
}

impl Notification {
    pub fn new(code: ErrorCode, subcode: u8, data: Vec<u8>) -> Self {
        Notification { code, subcode, data }
    }

    /// Encode the full BGP message (header + body) into a Vec.
    pub fn encode(&self) -> Vec<u8> {
        let body_len = 2 + self.data.len();
        let total_len = HEADER_LEN + body_len;
        debug_assert!(total_len <= MAX_MESSAGE_LEN, "NOTIFICATION too large");
        let mut buf = vec![0u8; total_len];
        Header::encode(&mut buf, MessageType::Notification);
        buf[HEADER_LEN] = self.code as u8;
        buf[HEADER_LEN + 1] = self.subcode;
        buf[HEADER_LEN + 2..].copy_from_slice(&self.data);
        buf
    }

    /// Parse a NOTIFICATION body (the bytes *after* the BGP header).
    /// Caller is expected to have already validated the header.
    pub fn parse_body(body: &[u8]) -> Result<Self, ParseError> {
        if body.len() < 2 {
            return Err(ParseError::Notification {
                code: ErrorCode::MessageHeader,
                subcode: 0,
                message: format!(
                    "NOTIFICATION body too short: {} bytes (need at least 2)",
                    body.len()
                ),
            });
        }
        let code = parse_error_code(body[0])?;
        let subcode = body[1];
        let data = body[2..].to_vec();
        Ok(Notification { code, subcode, data })
    }
}

fn parse_error_code(v: u8) -> Result<ErrorCode, ParseError> {
    match v {
        1 => Ok(ErrorCode::MessageHeader),
        2 => Ok(ErrorCode::OpenMessage),
        3 => Ok(ErrorCode::UpdateMessage),
        4 => Ok(ErrorCode::HoldTimerExpired),
        5 => Ok(ErrorCode::FsmError),
        6 => Ok(ErrorCode::Cease),
        7 => Ok(ErrorCode::RouteRefreshMessage),
        other => Err(ParseError::Notification {
            code: ErrorCode::MessageHeader,
            subcode: 0,
            message: format!("unknown NOTIFICATION error code {}", other),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::OpenMessageSubcode;

    #[test]
    fn notification_round_trip_no_data() {
        let n = Notification::new(
            ErrorCode::OpenMessage,
            OpenMessageSubcode::BadPeerAs as u8,
            vec![],
        );
        let bytes = n.encode();
        assert_eq!(bytes.len(), HEADER_LEN + 2);
        let header = Header::parse(&bytes).unwrap();
        assert_eq!(header.msg_type, MessageType::Notification);
        assert_eq!(header.length as usize, bytes.len());
        let parsed = Notification::parse_body(&bytes[HEADER_LEN..]).unwrap();
        assert_eq!(parsed, n);
    }

    #[test]
    fn notification_round_trip_with_data() {
        let data = vec![0xde, 0xad, 0xbe, 0xef];
        let n = Notification::new(ErrorCode::Cease, 6, data.clone());
        let bytes = n.encode();
        assert_eq!(bytes.len(), HEADER_LEN + 2 + data.len());
        let parsed = Notification::parse_body(&bytes[HEADER_LEN..]).unwrap();
        assert_eq!(parsed.data, data);
    }

    #[test]
    fn notification_rejects_short_body() {
        let err = Notification::parse_body(&[1]).unwrap_err();
        assert!(matches!(err, ParseError::Notification { .. }));
    }

    #[test]
    fn notification_rejects_unknown_code() {
        let err = Notification::parse_body(&[99, 0]).unwrap_err();
        assert!(matches!(err, ParseError::Notification { .. }));
    }
}
