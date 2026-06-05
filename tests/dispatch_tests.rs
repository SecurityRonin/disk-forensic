//! Scheme auto-detection and dispatch to the correct parser.

mod common;
use common::{build_gpt, build_mbr};
use disk_forensic::{analyse_disk, DiskReport, Error, Scheme};
use std::io::Cursor;

/// Real Apple Partition Map image (from apm-forensic's fixtures).
const APM: &[u8] = include_bytes!("data/apm.bin");

#[test]
fn dispatches_apm() {
    let report = analyse_disk(&mut Cursor::new(APM), APM.len() as u64).unwrap();
    assert_eq!(report.scheme(), Scheme::Apm);
    match report {
        DiskReport::Apm(a) => assert!(!a.partitions.is_empty()),
        other => panic!("expected Apm, got {other:?}"),
    }
}

#[test]
fn dispatches_classic_mbr() {
    let disk = build_mbr();
    let report = analyse_disk(&mut Cursor::new(&disk), disk.len() as u64).unwrap();
    assert_eq!(report.scheme(), Scheme::Mbr);
    assert!(matches!(report, DiskReport::Mbr(_)));
}

#[test]
fn dispatches_gpt() {
    let disk = build_gpt();
    let report = analyse_disk(&mut Cursor::new(&disk), disk.len() as u64).unwrap();
    assert_eq!(report.scheme(), Scheme::Gpt);
    // The GPT variant carries the protective MBR analysis with .gpt populated.
    match report {
        DiskReport::Gpt(m) => assert!(m.gpt.is_some(), "GPT should be parsed"),
        other => panic!("expected Gpt, got {other:?}"),
    }
}

#[test]
fn unpartitioned_disk_is_unknown_scheme() {
    let disk = vec![0u8; 4096];
    let err = analyse_disk(&mut Cursor::new(&disk), disk.len() as u64).unwrap_err();
    assert!(matches!(err, Error::UnknownScheme));
}
