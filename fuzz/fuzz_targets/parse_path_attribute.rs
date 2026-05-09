#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz a single PathAttribute decode (RFC 4271 §5 + RFC 4760 MP-BGP
// extensions). parse_update reaches this transitively, but BGP's framing
// (withdrawn-len + attr-len prefixes) eats most of the input budget, so
// fuzzing the attribute decoder directly gets deeper coverage on flag /
// type / length-byte permutations and the per-attribute-kind decoders
// (AS_PATH, AGGREGATOR, COMMUNITIES, MP_REACH_NLRI, etc.).
fuzz_target!(|data: &[u8]| {
    let _ = bgpd::packet::attrs::PathAttribute::parse(data);
});
