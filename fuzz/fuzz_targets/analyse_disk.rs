//! Fuzz target: feed arbitrary bytes as a disk image to `analyse_disk`.
//!
//! Invariants: never panics; returns `Ok` (with an accessible report) or a
//! well-typed `Err`, on crafted / corrupted / truncated input.
#![no_main]
use libfuzzer_sys::fuzz_target;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let mut cursor = Cursor::new(data);
    match disk_forensic::analyse_disk(&mut cursor, data.len() as u64) {
        Ok(report) => {
            let _ = report.scheme();
            let _ = report.has_anomalies();
            let _ = disk_forensic::report::text_report(&report);
        }
        Err(disk_forensic::Error::UnknownScheme) => {}
        Err(disk_forensic::Error::Apm(_)) => {}
        Err(disk_forensic::Error::Mbr(_)) => {}
        Err(disk_forensic::Error::Io(_)) => {}
    }
});
