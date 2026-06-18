//! Fuzz the in-crate container-format detection (`sniff`/`detect`) on arbitrary
//! bytes — magic-sniffing must never panic, overflow, or mis-index.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let _ = disk_forensic::container::sniff(&mut Cursor::new(data));
    // `detect` works on raw header/footer slices.
    let _ = disk_forensic::container::detect(data, data);
});
