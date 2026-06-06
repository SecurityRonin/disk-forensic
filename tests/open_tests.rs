//! Opening images: raw passthrough, E01 (EWF) decoding, and unsupported
//! containers — feeding a decoded `Read + Seek` view into `analyse_disk`.

use disk_forensic::container::{open, ContainerFormat, OpenError};
use disk_forensic::{analyse_disk, Scheme};
use std::path::Path;

const E01: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/data/gpt_130_partitions.E01"
);
const APM: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/apm.bin");

#[test]
fn opens_and_analyses_e01_as_gpt() {
    // A real GPT disk wrapped in E01 — decode, then the partition analysis runs
    // over the decoded media exactly as for a raw disk.
    let mut opened = open(Path::new(E01)).unwrap();
    assert_eq!(opened.format, ContainerFormat::Ewf);
    assert!(opened.size > 0);
    let report = analyse_disk(&mut opened.reader, opened.size).unwrap();
    assert_eq!(report.scheme(), Scheme::Gpt);
}

#[test]
fn opens_raw_image_in_place() {
    let opened = open(Path::new(APM)).unwrap();
    assert_eq!(opened.format, ContainerFormat::Raw);
    assert!(opened.size > 0);
}

#[test]
fn unsupported_container_is_reported() {
    let p = std::env::temp_dir().join(format!("df_open_{}_vmdk.img", std::process::id()));
    let mut data = vec![0u8; 1024];
    data[..4].copy_from_slice(&forensicnomicon::vmdk::VMDK4_MAGIC.to_le_bytes());
    std::fs::write(&p, &data).unwrap();
    let err = open(&p).unwrap_err();
    assert!(
        matches!(err, OpenError::Unsupported(ContainerFormat::Vmdk)),
        "got {err:?}"
    );
    let _ = std::fs::remove_file(&p);
}
