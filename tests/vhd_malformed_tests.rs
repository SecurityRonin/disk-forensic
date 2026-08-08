//! Malformed-VHD robustness: a header length field must not drive an
//! unbounded allocation.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::io::Write;

const FOOTER: u64 = 512;
const DYN_HEADER: u64 = 1024;

/// Build a dynamic VHD whose `cxsparse` header claims `max_entries` BAT entries.
///
/// The file itself is tiny: footer mirror at 0, dynamic header at 512, and a
/// single BAT sector after it. Only `max_entries` is adversarial.
fn dynamic_vhd(max_entries: u32) -> tempfile::NamedTempFile {
    let table_offset = FOOTER + DYN_HEADER;

    let mut footer = [0u8; 512];
    footer[0..8].copy_from_slice(b"conectix");
    footer[16..24].copy_from_slice(&FOOTER.to_be_bytes()); // data_offset
    footer[48..56].copy_from_slice(&(2 * 1024 * 1024u64).to_be_bytes()); // current_size
    footer[60..64].copy_from_slice(&3u32.to_be_bytes()); // disk_type = dynamic

    let mut dh = [0u8; 1024];
    dh[0..8].copy_from_slice(b"cxsparse");
    dh[16..24].copy_from_slice(&table_offset.to_be_bytes());
    dh[28..32].copy_from_slice(&max_entries.to_be_bytes());
    dh[32..36].copy_from_slice(&(2 * 1024 * 1024u32).to_be_bytes()); // block_size

    let mut f = tempfile::NamedTempFile::new().unwrap();
    f.write_all(&footer).unwrap(); // mirror at 0
    f.write_all(&dh).unwrap();
    f.write_all(&[0u8; 512]).unwrap(); // one sector of BAT
    f.write_all(&footer).unwrap(); // trailing footer
    f.flush().unwrap();
    f
}

#[test]
fn vhd_bat_entry_count_is_bounded_by_the_file() {
    // 0xFFFF_FFFF entries x 4 bytes = 16 GiB. The file is under 3 KiB, so this
    // must be rejected from the header alone - never allocated speculatively.
    let f = dynamic_vhd(u32::MAX);
    let err = disk_forensic::container::open(f.path()).expect_err("must reject");
    let msg = err.to_string();
    assert!(
        msg.contains("BAT") || msg.contains("bat"),
        "expected a BAT-bounds error naming the offending size, got: {msg}"
    );
}

#[test]
fn vhd_with_honest_bat_still_opens() {
    // 128 entries x 4 = 512 bytes, exactly the BAT sector written above.
    let f = dynamic_vhd(128);
    assert!(
        disk_forensic::container::open(f.path()).is_ok(),
        "a well-formed dynamic VHD must still open"
    );
}
