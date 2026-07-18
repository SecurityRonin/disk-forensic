//! Archive-layer (peel) opener tests: `disk_forensic::container::open`
//! transparently unwraps a compression-wrapped image via `archive-core`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use disk_forensic::container::{open, ContainerFormat};
use flate2::write::GzEncoder;
use flate2::Compression;
use std::io::{Read, Write};

const VHD_FIXED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/df-fixed.vhd");

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

/// Write `bytes` to a temp file whose name ends in `suffix` (so the opener sees
/// the extension). The returned path deletes on drop.
fn temp_with_suffix(suffix: &str, bytes: &[u8]) -> tempfile::TempPath {
    let mut f = tempfile::Builder::new().suffix(suffix).tempfile().unwrap();
    f.write_all(bytes).unwrap();
    f.flush().unwrap();
    f.into_temp_path()
}

#[test]
fn opens_gzipped_raw_image() {
    let raw: Vec<u8> = (0..8192u32).map(|i| (i % 251) as u8).collect();
    let tp = temp_with_suffix(".dd.gz", &gzip(&raw));
    let mut img = open(&tp).unwrap();
    assert_eq!(img.format, ContainerFormat::Raw);
    assert_eq!(img.size, 8192);
    let mut got = Vec::new();
    img.reader.read_to_end(&mut got).unwrap();
    assert_eq!(got, raw, "peeled bytes must match the original raw image");
}

#[test]
fn coincidental_gzip_magic_without_extension_opens_as_raw() {
    // Starts with gzip magic but is named `.raw` — must NOT be peeled.
    let mut raw = vec![0x1F, 0x8B, 0x08, 0x00];
    raw.extend((0..4096u32).map(|i| (i % 251) as u8));
    let tp = temp_with_suffix(".raw", &raw);
    let img = open(&tp).unwrap();
    assert_eq!(img.format, ContainerFormat::Raw);
}

#[test]
fn corrupt_gzip_named_gz_fails_loud() {
    // Valid gzip header then garbage deflate → decode fails → loud error, never
    // silently mis-analyzed.
    let bad = [
        0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0, 0xFF, 0xDE, 0xAD, 0xBE, 0xEF, 0x00,
    ];
    let tp = temp_with_suffix(".gz", &bad);
    assert!(open(&tp).is_err());
}

#[test]
fn opens_gzipped_container() {
    // A compression-wrapped *container* (evidence.vhd.gz) spills to a temp file
    // and re-opens as the inner container.
    let vhd = std::fs::read(VHD_FIXED).unwrap();
    let tp = temp_with_suffix(".vhd.gz", &gzip(&vhd));
    let img = open(&tp).unwrap();
    assert_eq!(img.format, ContainerFormat::Vhd);
}

#[test]
fn stops_peeling_at_max_depth() {
    // Five nested gzips: the opener peels the bounded maximum then opens the
    // still-compressed remainder as raw (no infinite recursion).
    let mut cur = vec![0xABu8; 1024];
    for _ in 0..5 {
        cur = gzip(&cur);
    }
    let tp = temp_with_suffix(".gz", &cur);
    let img = open(&tp).unwrap();
    assert_eq!(img.format, ContainerFormat::Raw);
}
