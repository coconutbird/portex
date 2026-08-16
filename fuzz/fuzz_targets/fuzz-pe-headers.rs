#![no_main]

use libfuzzer_sys::fuzz_target;
use portex::PeHeaders;

fuzz_target!(|data: &[u8]| {
    let _ = PeHeaders::from_slice(data);
});
