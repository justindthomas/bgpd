//! BGP error types.
//!
//! Two distinct concerns share this module:
//!
//! 1. **NOTIFICATION error codes / subcodes** (RFC 4271 §6) used
//!    when sending a NOTIFICATION to tear down the session.
//! 2. **Parse-side error types** ([`ParseError`]) carried back from
//!    the codec layer, including enough information to construct
//!    the matching NOTIFICATION at the FSM layer.
//!
//! RFC 7606 attribute error classification (treat-as-withdraw vs
//! attribute-discard vs session reset) is layered on top in
//! [`super::packet::update`] once UPDATE parsing exists; the
//! primitive used there is the [`AttributeErrorAction`] enum
//! defined here.

use thiserror::Error;

/// RFC 4271 §6 + RFC 7606 NOTIFICATION top-level error codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ErrorCode {
    MessageHeader = 1,
    OpenMessage = 2,
    UpdateMessage = 3,
    HoldTimerExpired = 4,
    FsmError = 5,
    Cease = 6,
    /// RFC 7313: ROUTE-REFRESH error category.
    RouteRefreshMessage = 7,
}

/// RFC 4271 §6.1 — Message Header error subcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageHeaderSubcode {
    ConnectionNotSynchronized = 1,
    BadMessageLength = 2,
    BadMessageType = 3,
}

/// RFC 4271 §6.2 — OPEN Message error subcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum OpenMessageSubcode {
    UnsupportedVersionNumber = 1,
    BadPeerAs = 2,
    BadBgpIdentifier = 3,
    UnsupportedOptionalParameter = 4,
    UnacceptableHoldTime = 6,
    /// RFC 5492.
    UnsupportedCapability = 7,
}

/// RFC 4271 §6.3 + RFC 7606 — UPDATE Message error subcodes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum UpdateMessageSubcode {
    MalformedAttributeList = 1,
    UnrecognizedWellKnownAttribute = 2,
    MissingWellKnownAttribute = 3,
    AttributeFlagsError = 4,
    AttributeLengthError = 5,
    InvalidOriginAttribute = 6,
    InvalidNextHopAttribute = 8,
    OptionalAttributeError = 9,
    InvalidNetworkField = 10,
    MalformedAsPath = 11,
}

/// RFC 7606 §4 — what to do with an UPDATE attribute that fails
/// validation. The default RFC 4271 behavior is "session reset",
/// which is far too disruptive — 7606 reclassifies most attribute
/// errors as either treat-as-withdraw (drop the affected NLRI) or
/// attribute-discard (keep the NLRI, drop the bad attribute).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttributeErrorAction {
    /// Send NOTIFICATION + reset the session (RFC 4271 default).
    SessionReset,
    /// Withdraw all NLRI carried by this UPDATE; do not reset.
    TreatAsWithdraw,
    /// Discard the offending attribute, keep the rest of the
    /// UPDATE.
    AttributeDiscard,
}

/// Codec-side parse error. Carries enough information for the FSM
/// to construct the matching NOTIFICATION when an error is fatal,
/// or to feed RFC 7606's classifier when it's recoverable.
#[derive(Debug, Clone, Error)]
pub enum ParseError {
    #[error("BGP message truncated: wanted {wanted} bytes, got {got}")]
    Truncated { wanted: usize, got: usize },
    #[error("BGP header error: {message}")]
    Header {
        code: ErrorCode,
        subcode: u8,
        message: String,
    },
    #[error("BGP OPEN error: {message}")]
    Open {
        code: ErrorCode,
        subcode: u8,
        message: String,
    },
    #[error("BGP UPDATE error: {message}")]
    Update {
        code: ErrorCode,
        subcode: u8,
        message: String,
        /// RFC 7606 classification — what the FSM should *do* with
        /// this error. Codec just classifies; the FSM acts.
        action: AttributeErrorAction,
    },
    #[error("BGP NOTIFICATION error: {message}")]
    Notification {
        code: ErrorCode,
        subcode: u8,
        message: String,
    },
    #[error("BGP capability decode error: {0}")]
    Capability(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_code_values_match_rfc() {
        // Sanity: the wire values for each top-level code must
        // match RFC 4271 §6 / RFC 7313 verbatim. A regression here
        // would silently mis-classify NOTIFICATIONs.
        assert_eq!(ErrorCode::MessageHeader as u8, 1);
        assert_eq!(ErrorCode::OpenMessage as u8, 2);
        assert_eq!(ErrorCode::UpdateMessage as u8, 3);
        assert_eq!(ErrorCode::HoldTimerExpired as u8, 4);
        assert_eq!(ErrorCode::FsmError as u8, 5);
        assert_eq!(ErrorCode::Cease as u8, 6);
        assert_eq!(ErrorCode::RouteRefreshMessage as u8, 7);
    }

    #[test]
    fn header_subcodes_match_rfc() {
        assert_eq!(MessageHeaderSubcode::ConnectionNotSynchronized as u8, 1);
        assert_eq!(MessageHeaderSubcode::BadMessageLength as u8, 2);
        assert_eq!(MessageHeaderSubcode::BadMessageType as u8, 3);
    }

    #[test]
    fn open_subcodes_match_rfc() {
        assert_eq!(OpenMessageSubcode::UnsupportedVersionNumber as u8, 1);
        assert_eq!(OpenMessageSubcode::BadPeerAs as u8, 2);
        assert_eq!(OpenMessageSubcode::BadBgpIdentifier as u8, 3);
        assert_eq!(OpenMessageSubcode::UnsupportedOptionalParameter as u8, 4);
        assert_eq!(OpenMessageSubcode::UnacceptableHoldTime as u8, 6);
        assert_eq!(OpenMessageSubcode::UnsupportedCapability as u8, 7);
    }
}
