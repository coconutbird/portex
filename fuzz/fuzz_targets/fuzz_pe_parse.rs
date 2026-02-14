#![no_main]

use libfuzzer_sys::fuzz_target;
use portex::PE;

fuzz_target!(|data: &[u8]| {
    // Try to parse the data as a PE file
    // This should never panic, only return errors for invalid input
    let _ = PE::parse(data);
});

