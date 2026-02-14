#![no_main]

use libfuzzer_sys::fuzz_target;
use portex::PEHeaders;

fuzz_target!(|data: &[u8]| {
    // Try to parse headers only (lighter weight parsing)
    // This should never panic, only return errors for invalid input
    let _ = PEHeaders::read_from(data);
});

