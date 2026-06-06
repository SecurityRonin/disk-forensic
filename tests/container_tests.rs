//! Container-format detection (magic-sniff) — which decoder a disk image needs.

use disk_forensic::container::{detect, ContainerFormat};
use forensicnomicon::{aff4, dmg, ewf, qcow2, vhd, vhdx, vmdk};

fn hdr(magic: &[u8]) -> Vec<u8> {
    let mut h = vec![0u8; 1024];
    h[..magic.len()].copy_from_slice(magic);
    h
}

#[test]
fn detects_ewf_e01() {
    assert_eq!(
        detect(&hdr(&ewf::EVF1_SIGNATURE), &[0u8; 512]),
        ContainerFormat::Ewf
    );
}

#[test]
fn detects_vhdx() {
    assert_eq!(
        detect(&hdr(vhdx::FILE_IDENTIFIER), &[0u8; 512]),
        ContainerFormat::Vhdx
    );
}

#[test]
fn detects_vmdk() {
    assert_eq!(
        detect(&hdr(&vmdk::VMDK4_MAGIC.to_le_bytes()), &[0u8; 512]),
        ContainerFormat::Vmdk
    );
}

#[test]
fn detects_qcow2() {
    assert_eq!(
        detect(&hdr(&qcow2::MAGIC.to_be_bytes()), &[0u8; 512]),
        ContainerFormat::Qcow2
    );
}

#[test]
fn detects_aff4_zip() {
    assert_eq!(
        detect(&hdr(&aff4::ZIP_LOCAL_FILE_HEADER_MAGIC), &[0u8; 512]),
        ContainerFormat::Aff4
    );
}

#[test]
fn detects_vhd_by_footer_cookie() {
    // A fixed VHD carries the "conectix" cookie only in its trailing footer.
    let mut footer = vec![0u8; 512];
    footer[..8].copy_from_slice(vhd::FOOTER_COOKIE);
    assert_eq!(detect(&[0u8; 1024], &footer), ContainerFormat::Vhd);
}

#[test]
fn detects_dmg_by_koly_trailer() {
    let mut footer = vec![0u8; 512];
    footer[..4].copy_from_slice(&dmg::KOLY_MAGIC.to_be_bytes());
    assert_eq!(detect(&[0u8; 1024], &footer), ContainerFormat::Dmg);
}

#[test]
fn detects_iso9660_by_cd001_at_pvd() {
    // ECMA-119: the Primary Volume Descriptor's "CD001" sits at offset 32769.
    let mut h = vec![0u8; 40000];
    h[32769..32774].copy_from_slice(b"CD001");
    assert_eq!(detect(&h, &[0u8; 512]), ContainerFormat::Iso);
}

#[test]
fn raw_when_no_container_magic() {
    // A bare MBR/GPT/APM disk has no container wrapper.
    let mut h = vec![0u8; 1024];
    h[510] = 0x55;
    h[511] = 0xAA;
    assert_eq!(detect(&h, &[0u8; 512]), ContainerFormat::Raw);
}
