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
const VMDK: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/df.vmdk");

#[test]
fn opens_and_analyses_vmdk_as_mbr() {
    // A real qemu-img VMDK (monolithicSparse) wrapping an MBR disk — decode the
    // sparse extents, then the partition analysis runs over the decoded media.
    let mut opened = open(Path::new(VMDK)).unwrap();
    assert_eq!(opened.format, ContainerFormat::Vmdk);
    assert_eq!(opened.size, 1024 * 1024, "decoded virtual disk size");
    let report = analyse_disk(&mut opened.reader, opened.size).unwrap();
    assert_eq!(report.scheme(), Scheme::Mbr);
}

const VHDX: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/df.vhdx");

#[test]
fn opens_and_analyses_vhdx_as_mbr() {
    // A real qemu-img VHDX wrapping an MBR disk.
    let mut opened = open(Path::new(VHDX)).unwrap();
    assert_eq!(opened.format, ContainerFormat::Vhdx);
    assert_eq!(opened.size, 1024 * 1024, "decoded virtual disk size");
    let report = analyse_disk(&mut opened.reader, opened.size).unwrap();
    assert_eq!(report.scheme(), Scheme::Mbr);
}

// qemu rounds a VHD's virtual size up to CHS geometry, so both subformats decode
// to 1_079_296 bytes (not the 1 MiB raw source). Verified against the real footer.
const VHD_VIRTUAL_SIZE: u64 = 1_079_296;
const VHD_DYNAMIC: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/df-dynamic.vhd");
const VHD_FIXED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/df-fixed.vhd");

#[test]
fn opens_and_analyses_dynamic_vhd_as_mbr() {
    // A real qemu-img dynamic VHD (footer + cxsparse header + BAT) over an MBR.
    let mut opened = open(Path::new(VHD_DYNAMIC)).unwrap();
    assert_eq!(opened.format, ContainerFormat::Vhd);
    assert_eq!(opened.size, VHD_VIRTUAL_SIZE);
    let report = analyse_disk(&mut opened.reader, opened.size).unwrap();
    assert_eq!(report.scheme(), Scheme::Mbr);
}

#[test]
fn opens_and_analyses_fixed_vhd_as_mbr() {
    // A real qemu-img fixed VHD (raw data + trailing footer) over an MBR.
    let mut opened = open(Path::new(VHD_FIXED)).unwrap();
    assert_eq!(opened.format, ContainerFormat::Vhd);
    assert_eq!(opened.size, VHD_VIRTUAL_SIZE);
    let report = analyse_disk(&mut opened.reader, opened.size).unwrap();
    assert_eq!(report.scheme(), Scheme::Mbr);
}

const ISO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/df.iso");

#[test]
fn opens_iso_as_filesystem_passthrough() {
    // An ISO 9660 image needs no container decoding — it IS a flat filesystem
    // image, so open() returns it as a passthrough reader tagged Iso; disk4n6
    // routes it to the filesystem analyzer instead of the partition parsers.
    let opened = open(Path::new(ISO)).unwrap();
    assert_eq!(opened.format, ContainerFormat::Iso);
    assert!(opened.size > 0);
}

const DMG: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/df.dmg");

#[test]
fn opens_and_analyses_dmg_as_mbr() {
    // A real hdiutil UDZO DMG over an MBR disk — udif exposes the image as blkx
    // entries; open() reconstructs the whole disk and analyses it.
    let mut opened = open(Path::new(DMG)).unwrap();
    assert_eq!(opened.format, ContainerFormat::Dmg);
    assert_eq!(opened.size, 1024 * 1024, "reconstructed disk size");
    let report = analyse_disk(&mut opened.reader, opened.size).unwrap();
    assert_eq!(report.scheme(), Scheme::Mbr);
}

const QCOW2: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/df.qcow2");

#[test]
fn opens_and_analyses_qcow2_as_mbr() {
    // A real qemu-img QCOW2 (v3) wrapping an MBR disk — decode the cluster
    // mapping, then partition analysis runs over the decoded media.
    let mut opened = open(Path::new(QCOW2)).unwrap();
    assert_eq!(opened.format, ContainerFormat::Qcow2);
    assert_eq!(opened.size, 1024 * 1024, "decoded virtual disk size");
    let report = analyse_disk(&mut opened.reader, opened.size).unwrap();
    assert_eq!(report.scheme(), Scheme::Mbr);
}

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
    // AFF4 (ZIP-based) has no decoder crate yet — it must be recognized and
    // reported as unsupported, not misparsed.
    let p = std::env::temp_dir().join(format!("df_open_{}_aff4.img", std::process::id()));
    let mut data = vec![0u8; 1024];
    data[..4].copy_from_slice(&forensicnomicon::aff4::ZIP_LOCAL_FILE_HEADER_MAGIC);
    std::fs::write(&p, &data).unwrap();
    let err = open(&p).unwrap_err();
    assert!(
        matches!(err, OpenError::Unsupported(ContainerFormat::Aff4)),
        "got {err:?}"
    );
    let _ = std::fs::remove_file(&p);
}
