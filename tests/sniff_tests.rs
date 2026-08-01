//! Sniffing the container format from a seekable reader (header + footer).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use disk_forensic::container::{sniff, ContainerFormat};
use forensicnomicon::{ewf, vhd};
use std::io::{Cursor, Seek};

#[test]
fn sniffs_raw_disk() {
    let mut disk = vec![0u8; 4096];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    assert_eq!(sniff(&mut Cursor::new(disk)).unwrap(), ContainerFormat::Raw);
}

#[test]
fn sniffs_ewf_from_header() {
    let mut disk = vec![0u8; 4096];
    disk[..8].copy_from_slice(&ewf::EVF1_SIGNATURE);
    assert_eq!(sniff(&mut Cursor::new(disk)).unwrap(), ContainerFormat::Ewf);
}

#[test]
fn sniffs_vhd_from_trailing_footer() {
    // A fixed VHD's "conectix" cookie is only in the last 512 bytes.
    let mut disk = vec![0u8; 4096];
    let n = disk.len();
    disk[n - 512..n - 512 + 8].copy_from_slice(vhd::FOOTER_COOKIE);
    assert_eq!(sniff(&mut Cursor::new(disk)).unwrap(), ContainerFormat::Vhd);
}

#[test]
fn sniff_rewinds_the_reader() {
    let mut c = Cursor::new(vec![0u8; 4096]);
    let _ = sniff(&mut c).unwrap();
    assert_eq!(c.stream_position().unwrap(), 0, "reader must be rewound");
}

#[test]
fn sniffs_short_image_without_footer() {
    // Sub-512-byte input must not panic (no footer to read).
    assert_eq!(
        sniff(&mut Cursor::new(vec![0u8; 16])).unwrap(),
        ContainerFormat::Raw
    );
}
