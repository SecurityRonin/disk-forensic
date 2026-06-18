//! Fuzz the full container-open path on a malformed "evidence file": this drives
//! sniff + the decoder dispatch, including the in-crate VHD decoder. `open` takes
//! a path, so the input is written to a temp file. It must return Ok or a typed
//! Err — never panic, abort, or over-allocate.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Write;

fuzz_target!(|data: &[u8]| {
    let Ok(mut tmp) = tempfile::NamedTempFile::new() else {
        return;
    };
    if tmp.write_all(data).is_err() {
        return;
    }
    if let Ok(opened) = disk_forensic::container::open(tmp.path()) {
        // Touch the decoded view so a lazy decoder actually runs.
        let _ = opened.size;
    }
});
