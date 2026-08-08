//! Provenance breadcrumbs normalized from each scheme's native fields.

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;
use common::{build_gpt, build_mbr};
use disk_forensic::{analyse_disk, normalize};
use std::io::Cursor;

const APM: &[u8] = include_bytes!("data/apm.bin");

fn rep(disk: &[u8]) -> forensicnomicon::report::Report {
    normalize::report(&analyse_disk(&mut Cursor::new(disk.to_vec()), disk.len() as u64).unwrap())
}

#[test]
fn mbr_provenance_includes_boot_code_and_era() {
    let r = rep(&build_mbr());
    assert!(r
        .provenance
        .iter()
        .any(|p| p.label == "boot code" && p.source == "mbr-partition-forensic"));
    assert!(r.provenance.iter().any(|p| p.label.contains("era")));
}

#[test]
fn gpt_provenance_includes_disk_guid_and_sha256() {
    let r = rep(&build_gpt());
    assert!(r
        .provenance
        .iter()
        .any(|p| p.label == "disk GUID" && p.source == "gpt-partition-forensic"));
    assert!(r.provenance.iter().any(|p| p.label.contains("SHA-256")));
}

#[test]
fn apm_provenance_includes_block_size() {
    let r = rep(APM);
    assert!(r
        .provenance
        .iter()
        .any(|p| p.label == "block size" && p.source == "apm-partition-forensic"));
}
