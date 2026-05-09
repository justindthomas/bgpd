#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the BGP message header parser (RFC 4271 §4.1, 19 bytes:
// 16-byte marker + 2-byte length + 1-byte type). Every BGP message
// that arrives on a peer socket hits this first; a panic here is a
// remote DoS via any TCP/179 traffic.
fuzz_target!(|data: &[u8]| {
    let _ = bgpd::packet::header::Header::parse(data);
});
