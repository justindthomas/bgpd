#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the OPEN message body parser (RFC 4271 §4.2 + RFC 5492 capability
// TLVs). OPEN is the first message a peer sends after TCP connect, so
// any panic here is reachable by anyone able to TCP-connect to port 179.
// The capability decoder (RFC 5492) lives behind this parse; oversized
// or self-referential TLVs are the historical bug class.
fuzz_target!(|data: &[u8]| {
    let _ = bgpd::packet::open::Open::parse_body(data);
});
