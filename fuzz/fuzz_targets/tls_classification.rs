#![no_main]

use libfuzzer_sys::fuzz_target;
use mitm_tls::classify_tls_error;

fuzz_target!(|data: &[u8]| {
    let message = String::from_utf8_lossy(data);
    let reason = classify_tls_error(&message);
    let _ = reason.code();
});
