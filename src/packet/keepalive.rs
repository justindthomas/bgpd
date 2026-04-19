//! KEEPALIVE message (RFC 4271 §4.4).
//!
//! Header-only: 19 bytes, no payload. Sent every Keepalive
//! interval (default Hold/3) and on demand. The codec is trivial
//! enough that there's no separate `Keepalive` struct — call
//! [`encode`] and you get the bytes.

use crate::packet::header::{Header, MessageType, HEADER_LEN};

/// Encode a KEEPALIVE message into a fresh `Vec<u8>`.
pub fn encode() -> Vec<u8> {
    let mut buf = vec![0u8; HEADER_LEN];
    Header::encode(&mut buf, MessageType::Keepalive);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keepalive_encode_decode() {
        let buf = encode();
        assert_eq!(buf.len(), HEADER_LEN);
        let h = Header::parse(&buf).unwrap();
        assert_eq!(h.msg_type, MessageType::Keepalive);
        assert_eq!(h.length as usize, HEADER_LEN);
    }
}
