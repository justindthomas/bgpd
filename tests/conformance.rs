//! Conformance tests covering RFC 4271 / 4760 / 7606 corner cases
//! that aren't exercised by the unit tests in the wire-format
//! modules. Modelled on the structure of ospfd's
//! conformance.rs but smaller — we don't have a v3 wire format
//! to cover separately.
//!
//! Each test takes a hand-crafted byte buffer (or a buffer
//! produced by encoding a known shape), runs it through the
//! parser, and asserts the outcome matches the RFC requirement.
//! These are the tests we care about most when something on the
//! wire surprises us — it's where the comments-as-RFC-citations
//! pay off.

use bgpd::error::{AttributeErrorAction, ErrorCode, ParseError, UpdateMessageSubcode};
use bgpd::packet::attrs::{
    AsPathSegment, AsPathSegmentType, Origin, PathAttribute, ATTR_LOCAL_PREF, ATTR_NEXT_HOP,
    ATTR_ORIGIN, FLAG_TRANSITIVE,
};
use bgpd::packet::caps::{Capability, AFI_IPV6, SAFI_UNICAST};
use bgpd::packet::header::{Header, MessageType, HEADER_LEN};
use bgpd::packet::open::{Open, AS_TRANS, BGP_VERSION};
use bgpd::packet::update::{Prefix4, Update};

// ---------- header conformance ----------

#[test]
fn rfc4271_4_1_marker_must_be_all_ones() {
    // RFC 4271 §4.1: the marker MUST be set to all ones for
    // unauthenticated sessions, and any other value MUST cause
    // a NOTIFICATION with subcode "Connection Not Synchronized".
    let mut buf = vec![0xffu8; HEADER_LEN];
    Header::encode(&mut buf, MessageType::Keepalive);
    buf[0] = 0; // corrupt marker
    let err = Header::parse(&buf).unwrap_err();
    match err {
        ParseError::Header { code, subcode, .. } => {
            assert_eq!(code, ErrorCode::MessageHeader);
            assert_eq!(
                subcode,
                bgpd::error::MessageHeaderSubcode::ConnectionNotSynchronized as u8
            );
        }
        other => panic!("wrong error: {:?}", other),
    }
}

#[test]
fn rfc4271_4_1_message_length_below_19_rejected() {
    let mut buf = vec![0xffu8; HEADER_LEN];
    buf[16..18].copy_from_slice(&18u16.to_be_bytes());
    buf[18] = 4;
    let err = Header::parse(&buf).unwrap_err();
    assert!(matches!(err, ParseError::Header { .. }));
}

#[test]
fn rfc4271_4_1_message_length_above_4096_rejected() {
    let mut buf = vec![0xffu8; HEADER_LEN];
    buf[16..18].copy_from_slice(&4097u16.to_be_bytes());
    buf[18] = 2;
    let err = Header::parse(&buf).unwrap_err();
    assert!(matches!(err, ParseError::Header { .. }));
}

// ---------- OPEN conformance ----------

#[test]
fn rfc4271_4_2_only_version_4_accepted() {
    let open = Open::new(65000, 90, "10.0.0.1".parse().unwrap(), vec![]);
    let mut bytes = open.encode();
    bytes[HEADER_LEN] = 5; // version field
    let err = Open::parse_body(&bytes[HEADER_LEN..]).unwrap_err();
    match err {
        ParseError::Open { subcode, .. } => {
            assert_eq!(
                subcode,
                bgpd::error::OpenMessageSubcode::UnsupportedVersionNumber as u8
            );
        }
        other => panic!("wrong error: {:?}", other),
    }
}

#[test]
fn rfc6793_4octet_asn_uses_as_trans_in_wire_field() {
    let open = Open::new(4_200_000_000, 90, "10.0.0.1".parse().unwrap(), vec![]);
    let bytes = open.encode();
    // wire ASN at bytes[20..22] (after version byte)
    let wire_asn = u16::from_be_bytes([bytes[20], bytes[21]]);
    assert_eq!(wire_asn, AS_TRANS);
    // decoder recovers the real ASN from the cap
    let parsed = Open::parse_body(&bytes[HEADER_LEN..]).unwrap();
    assert_eq!(parsed.asn, 4_200_000_000);
}

#[test]
fn rfc6793_as_trans_without_capability_is_bad_peer_as() {
    // RFC 6793 §4.1: an OPEN with AS_TRANS in the wire field
    // MUST advertise the 4-octet ASN capability. If it doesn't,
    // the receiver must treat the session as malformed.
    let mut body = Vec::new();
    body.push(BGP_VERSION);
    body.extend_from_slice(&AS_TRANS.to_be_bytes());
    body.extend_from_slice(&90u16.to_be_bytes()); // hold time
    body.extend_from_slice(&[10, 0, 0, 1]); // BGP identifier
    body.push(0); // opt parm len
    let err = Open::parse_body(&body).unwrap_err();
    match err {
        ParseError::Open { subcode, .. } => {
            assert_eq!(
                subcode,
                bgpd::error::OpenMessageSubcode::BadPeerAs as u8
            );
        }
        other => panic!("wrong error: {:?}", other),
    }
}

#[test]
fn rfc5492_unknown_optional_parameter_rejected() {
    // OPEN with an unrecognized optional parameter type MUST be
    // rejected with subcode 4 ("Unsupported Optional Parameter").
    let mut body = Vec::new();
    body.push(BGP_VERSION);
    body.extend_from_slice(&65000u16.to_be_bytes());
    body.extend_from_slice(&90u16.to_be_bytes());
    body.extend_from_slice(&[10, 0, 0, 1]);
    body.push(3); // opt parm len = 3
    body.push(99); // bogus parameter type
    body.push(1); // length 1
    body.push(0); // value
    let err = Open::parse_body(&body).unwrap_err();
    match err {
        ParseError::Open { subcode, .. } => {
            assert_eq!(
                subcode,
                bgpd::error::OpenMessageSubcode::UnsupportedOptionalParameter as u8
            );
        }
        other => panic!("wrong error: {:?}", other),
    }
}

#[test]
fn rfc4760_mp_bgp_capability_round_trip_v6() {
    let open = Open::new(
        65000,
        90,
        "10.0.0.1".parse().unwrap(),
        vec![Capability::Multiprotocol {
            afi: AFI_IPV6,
            safi: SAFI_UNICAST,
        }],
    );
    let bytes = open.encode();
    let parsed = Open::parse_body(&bytes[HEADER_LEN..]).unwrap();
    assert!(parsed
        .capabilities
        .iter()
        .any(|c| matches!(c, Capability::Multiprotocol { afi: 2, safi: 1 })));
}

// ---------- UPDATE / RFC 7606 conformance ----------

#[test]
fn rfc7606_3g_invalid_origin_is_treat_as_withdraw() {
    // ORIGIN value 99 — not 0/1/2 — RFC 7606 §3.g says
    // treat-as-withdraw, NOT session reset.
    let bad = vec![FLAG_TRANSITIVE, ATTR_ORIGIN, 1, 99];
    let err = PathAttribute::parse(&bad).unwrap_err();
    match err {
        ParseError::Update { action, subcode, .. } => {
            assert_eq!(action, AttributeErrorAction::TreatAsWithdraw);
            assert_eq!(
                subcode,
                UpdateMessageSubcode::InvalidOriginAttribute as u8
            );
        }
        other => panic!("wrong error: {:?}", other),
    }
}

#[test]
fn rfc7606_3h_next_hop_wrong_length_is_treat_as_withdraw() {
    // NEXT_HOP must be exactly 4 bytes per RFC 4271 §5.1.3.
    // RFC 7606 §3.h moves this from session-reset to
    // treat-as-withdraw.
    let bad = vec![FLAG_TRANSITIVE, ATTR_NEXT_HOP, 3, 10, 0, 0];
    let err = PathAttribute::parse(&bad).unwrap_err();
    match err {
        ParseError::Update { action, .. } => {
            assert_eq!(action, AttributeErrorAction::TreatAsWithdraw);
        }
        other => panic!("wrong error: {:?}", other),
    }
}

#[test]
fn rfc7606_local_pref_wrong_length_is_treat_as_withdraw() {
    let bad = vec![FLAG_TRANSITIVE, ATTR_LOCAL_PREF, 3, 0, 0, 100];
    let err = PathAttribute::parse(&bad).unwrap_err();
    match err {
        ParseError::Update { action, .. } => {
            assert_eq!(action, AttributeErrorAction::TreatAsWithdraw);
        }
        other => panic!("wrong error: {:?}", other),
    }
}

#[test]
fn rfc4271_5_1_2_as_path_set_counts_as_one_in_length() {
    // §5.1.2.2's "shortest AS_PATH" rule counts an AS_SET as a
    // single hop regardless of its size. Our as_path_length()
    // must agree.
    let route = bgpd::adj_rib::StoredRoute::new(
        vec![PathAttribute::AsPath(vec![
            AsPathSegment {
                seg_type: AsPathSegmentType::AsSequence,
                asns: vec![65001, 65002],
            },
            AsPathSegment {
                seg_type: AsPathSegmentType::AsSet,
                asns: vec![65010, 65011, 65012, 65013, 65014],
            },
        ])],
        1,
        65001,
        65000,
        std::net::IpAddr::V4("10.0.0.1".parse().unwrap()),
        "10.0.0.1".parse().unwrap(),
    );
    assert_eq!(route.as_path_length(), 3);
}

#[test]
fn rfc4271_5_1_3_next_hop_must_be_v4_address() {
    // NEXT_HOP must be 4 bytes. Anything else is malformed.
    // We accept only the wire-correct shape.
    let attr = PathAttribute::NextHop("10.0.0.1".parse().unwrap());
    let bytes = attr.encode();
    let (parsed, _) = PathAttribute::parse(&bytes).unwrap();
    assert_eq!(parsed, attr);
}

#[test]
fn rfc4760_mp_reach_v6_default_route_round_trip() {
    // Default route (::/0) carried via MP_REACH_NLRI with a
    // 16-byte v6 next-hop. Tests the boundary conditions: NLRI
    // is a single byte (length 0), nexthop length is exactly 16.
    let nlri = vec![0u8]; // /0, no address bytes
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
                afi: AFI_IPV6,
                safi: SAFI_UNICAST,
                nexthop: nh,
                nlri,
            },
        ],
        nlri_v4: Vec::new(),
    };
    let bytes = update.encode();
    let parsed = Update::parse_body(&bytes[HEADER_LEN..]).unwrap();
    let v6 = parsed.ipv6_nlri().unwrap();
    assert_eq!(v6.len(), 1);
    assert_eq!(v6[0].len, 0);
}

#[test]
fn rfc4271_4_3_default_route_v4_round_trip() {
    // The IPv4 default route lives in the legacy NLRI field with
    // prefix length 0 and zero address bytes.
    let update = Update {
        withdrawn_v4: Vec::new(),
        path_attributes: vec![
            PathAttribute::Origin(Origin::Igp),
            PathAttribute::AsPath(vec![AsPathSegment {
                seg_type: AsPathSegmentType::AsSequence,
                asns: vec![65001],
            }]),
            PathAttribute::NextHop("10.0.0.1".parse().unwrap()),
        ],
        nlri_v4: vec![Prefix4 {
            addr: std::net::Ipv4Addr::new(0, 0, 0, 0),
            len: 0,
        }],
    };
    let bytes = update.encode();
    let parsed = Update::parse_body(&bytes[HEADER_LEN..]).unwrap();
    assert_eq!(parsed.nlri_v4.len(), 1);
    assert_eq!(parsed.nlri_v4[0].len, 0);
}

#[test]
fn rfc4271_4_3_withdraw_only_update_round_trip() {
    // An UPDATE with no path attributes and no NLRI but a
    // populated withdrawn-routes field (a withdraw-only message)
    // must round-trip cleanly.
    let update = Update {
        withdrawn_v4: vec![Prefix4 {
            addr: std::net::Ipv4Addr::new(192, 0, 2, 0),
            len: 24,
        }],
        path_attributes: Vec::new(),
        nlri_v4: Vec::new(),
    };
    let bytes = update.encode();
    let parsed = Update::parse_body(&bytes[HEADER_LEN..]).unwrap();
    assert_eq!(parsed, update);
}

#[test]
fn rfc4271_eor_is_empty_update_for_v4() {
    // RFC 4724 §5: End-of-RIB for IPv4 unicast is an empty
    // UPDATE. Encoded length should be exactly 23 bytes
    // (header + 2 + 2).
    let bytes = Update::empty().encode();
    assert_eq!(bytes.len(), 23);
    let header = Header::parse(&bytes).unwrap();
    assert_eq!(header.msg_type, MessageType::Update);
    let parsed = Update::parse_body(&bytes[HEADER_LEN..]).unwrap();
    assert!(parsed.nlri_v4.is_empty());
    assert!(parsed.withdrawn_v4.is_empty());
    assert!(parsed.path_attributes.is_empty());
}

// ---------- best-path conformance ----------

#[test]
fn rfc4271_9_1_2_local_pref_outranks_as_path_length() {
    use bgpd::adj_rib::StoredRoute;
    use bgpd::bestpath::select_best;

    let make = |asns: Vec<u32>, local_pref: u32, peer_id: u32| -> StoredRoute {
        StoredRoute::new(
            vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(vec![AsPathSegment {
                    seg_type: AsPathSegmentType::AsSequence,
                    asns,
                }]),
                PathAttribute::NextHop("10.0.0.1".parse().unwrap()),
                PathAttribute::LocalPref(local_pref),
            ],
            peer_id,
            65001,
            65000,
            std::net::IpAddr::V4(format!("10.0.0.{}", peer_id).parse().unwrap()),
            format!("10.0.0.{}", peer_id).parse().unwrap(),
        )
    };
    // Long path, high LP vs short path, low LP.
    let cands = vec![
        make(vec![65001, 65002, 65003, 65004], 500, 1),
        make(vec![65001], 100, 2),
    ];
    // Step 1 (LOCAL_PREF) decides before step 3 (path length).
    assert_eq!(select_best(&cands), Some(0));
}

#[test]
fn rfc4271_9_1_2_ebgp_preferred_over_ibgp() {
    use bgpd::adj_rib::StoredRoute;
    use bgpd::bestpath::select_best;

    let make = |peer_asn: u32, peer_id: u32| -> StoredRoute {
        StoredRoute::new(
            vec![
                PathAttribute::Origin(Origin::Igp),
                PathAttribute::AsPath(vec![AsPathSegment {
                    seg_type: AsPathSegmentType::AsSequence,
                    asns: vec![65001],
                }]),
                PathAttribute::NextHop("10.0.0.1".parse().unwrap()),
            ],
            peer_id,
            peer_asn,
            65000,
            std::net::IpAddr::V4(format!("10.0.0.{}", peer_id).parse().unwrap()),
            format!("10.0.0.{}", peer_id).parse().unwrap(),
        )
    };
    let cands = vec![
        make(65000, 1), // iBGP
        make(65001, 2), // eBGP
    ];
    assert_eq!(select_best(&cands), Some(1));
}

// ---------- malformed packet tests ----------

#[test]
fn header_parse_truncated_input() {
    // Less than 19 bytes — Header::parse must return Truncated.
    let buf = vec![0xff; 10];
    let err = Header::parse(&buf).unwrap_err();
    assert!(matches!(err, ParseError::Truncated { wanted: 19, .. }));
}

#[test]
fn update_body_too_short_returns_session_reset() {
    // An UPDATE body with only 3 bytes (need ≥4 for the two
    // length fields).
    let body = vec![0u8; 3];
    let err = Update::parse_body(&body).unwrap_err();
    match err {
        ParseError::Update { action, .. } => {
            assert_eq!(action, AttributeErrorAction::SessionReset);
        }
        other => panic!("wrong error: {:?}", other),
    }
}

#[test]
fn update_withdrawn_length_exceeds_body_returns_session_reset() {
    // withdrawn_len says 100 bytes but body is only 10 bytes.
    let mut body = vec![0u8; 10];
    body[0..2].copy_from_slice(&100u16.to_be_bytes());
    let err = Update::parse_body(&body).unwrap_err();
    match err {
        ParseError::Update {
            action, subcode, ..
        } => {
            assert_eq!(action, AttributeErrorAction::SessionReset);
            assert_eq!(
                subcode,
                UpdateMessageSubcode::MalformedAttributeList as u8
            );
        }
        other => panic!("wrong error: {:?}", other),
    }
}

#[test]
fn update_attr_length_exceeds_body_returns_session_reset() {
    // withdrawn_len=0, attr_len=200, but only a few bytes left.
    let mut body = vec![0u8; 10];
    body[0..2].copy_from_slice(&0u16.to_be_bytes()); // withdrawn_len
    body[2..4].copy_from_slice(&200u16.to_be_bytes()); // attr_len
    let err = Update::parse_body(&body).unwrap_err();
    match err {
        ParseError::Update {
            action, subcode, ..
        } => {
            assert_eq!(action, AttributeErrorAction::SessionReset);
            assert_eq!(
                subcode,
                UpdateMessageSubcode::MalformedAttributeList as u8
            );
        }
        other => panic!("wrong error: {:?}", other),
    }
}

#[test]
fn as_path_segment_unknown_type_returns_malformed() {
    // Segment type 99 is not 1 (SET) or 2 (SEQUENCE).
    let buf = vec![99, 1, 0, 0, 0xFE, 0x09]; // type=99, count=1, asn=65033
    let err = AsPathSegment::parse(&buf).unwrap_err();
    match err {
        ParseError::Update { subcode, .. } => {
            assert_eq!(subcode, UpdateMessageSubcode::MalformedAsPath as u8);
        }
        other => panic!("wrong error: {:?}", other),
    }
}

#[test]
fn as_path_segment_truncated_asn_data() {
    // Declares 5 ASNs (20 bytes of data) but only 6 bytes of
    // buffer remain after the 2-byte header.
    let buf = vec![2, 5, 0, 0, 0, 1, 0, 0]; // type=SEQ, count=5, only 6 data bytes
    let err = AsPathSegment::parse(&buf).unwrap_err();
    match err {
        ParseError::Update { subcode, .. } => {
            assert_eq!(subcode, UpdateMessageSubcode::MalformedAsPath as u8);
        }
        other => panic!("wrong error: {:?}", other),
    }
}

#[test]
fn as_path_segment_header_truncated() {
    // Only 1 byte �� need at least 2 for type + count.
    let buf = vec![2];
    let err = AsPathSegment::parse(&buf).unwrap_err();
    match err {
        ParseError::Update { subcode, .. } => {
            assert_eq!(subcode, UpdateMessageSubcode::MalformedAsPath as u8);
        }
        other => panic!("wrong error: {:?}", other),
    }
}

#[test]
fn open_truncated_body_returns_error() {
    // OPEN body with only 3 bytes (need ≥10).
    let body = vec![4, 0, 1]; // version=4, partial ASN
    let err = Open::parse_body(&body).unwrap_err();
    assert!(matches!(err, ParseError::Open { .. } | ParseError::Truncated { .. }));
}

#[test]
fn update_nlri_prefix_length_exceeds_32_rejected() {
    // A v4 NLRI with prefix length 33 — impossible.
    let mut body = vec![0u8; 8];
    body[0..2].copy_from_slice(&0u16.to_be_bytes()); // withdrawn_len=0
    body[2..4].copy_from_slice(&0u16.to_be_bytes()); // attr_len=0
    body.push(33); // prefix_len=33, illegal for IPv4
    body.extend_from_slice(&[10, 0, 0, 0, 0]); // 5 prefix bytes
    let err = Update::parse_body(&body).unwrap_err();
    match err {
        ParseError::Update { subcode, .. } => {
            assert_eq!(
                subcode,
                UpdateMessageSubcode::InvalidNetworkField as u8
            );
        }
        other => panic!("wrong error: {:?}", other),
    }
}

#[test]
fn header_bad_message_type_rejected() {
    // Message type 99 is not valid (valid: 1-5).
    let mut buf = vec![0xff; HEADER_LEN];
    buf[16..18].copy_from_slice(&19u16.to_be_bytes());
    buf[18] = 99;
    let err = Header::parse(&buf).unwrap_err();
    assert!(matches!(err, ParseError::Header { .. }));
}
