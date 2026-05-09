#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the UPDATE message body parser (RFC 4271 §4.3 + RFC 7606 attribute
// error classification + RFC 4760 MP-BGP). The UPDATE body is by far the
// most complex BGP parser: nested length-prefixed regions for withdrawn
// routes, path attributes, and NLRI, with attribute parsing recursively
// invoking the path-attribute decoder.
//
// This is the prime fuzz target — historically the source of most
// CVE-flagged BGP parser bugs (oversized AS_PATHs, malformed
// MP_REACH_NLRI lengths, attribute flag/length-byte mismatches per
// RFC 7606). Reachable by any established BGP peer.
fuzz_target!(|data: &[u8]| {
    if let Ok(update) = bgpd::packet::update::Update::parse_body(data) {
        // Exercise the IPv6 NLRI / withdrawn extractors too — they walk
        // the path attributes again and invoke parse_nlri_v6 on the
        // MP_REACH/MP_UNREACH nlri bytes, which is its own attack
        // surface and isn't reached by parse_body alone.
        let _ = update.ipv6_nlri();
        let _ = update.ipv6_withdrawn();
    }
});
