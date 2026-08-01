//! Per-format decode-error paths: a file whose magic sniffs as a given
//! container but whose body is not a valid image of that format must surface a
//! loud, typed [`OpenError::Decode`] naming the format — never a panic and never
//! a bogus disk. Each fixture carries a real offset-0 (or footer) signature so
//! [`container::open`] routes it to the matching decoder, which then rejects the
//! junk body. This exercises the otherwise-untested error arm of every decoder.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use disk_forensic::container::{open, ContainerFormat, OpenError};
use forensicnomicon::{dmg, ewf, qcow2, vhd, vhdx, vmdk};

fn write_temp(name: &str, bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    (dir, path)
}

/// Assert that opening `bytes` fails with a typed decode error for `format`.
fn assert_decode_error(name: &str, bytes: &[u8], format: ContainerFormat) {
    let (_dir, path) = write_temp(name, bytes);
    let err = open(&path).unwrap_err();
    assert!(
        matches!(err, OpenError::Decode(f, _) if f == format),
        "expected Decode({format:?}, _), got {err:?}"
    );
}

#[test]
fn ewf_signature_with_junk_body_is_a_decode_error() {
    let mut bytes = ewf::EVF1_SIGNATURE.to_vec();
    bytes.resize(bytes.len() + 1024, 0);
    assert_decode_error("junk.E01", &bytes, ContainerFormat::Ewf);
}

#[test]
fn vmdk_magic_with_junk_body_is_a_decode_error() {
    let mut bytes = vmdk::VMDK4_MAGIC.to_le_bytes().to_vec();
    bytes.resize(bytes.len() + 1024, 0);
    assert_decode_error("junk.vmdk", &bytes, ContainerFormat::Vmdk);
}

#[test]
fn qcow2_magic_with_junk_body_is_a_decode_error() {
    let mut bytes = qcow2::MAGIC.to_be_bytes().to_vec();
    bytes.resize(bytes.len() + 1024, 0);
    assert_decode_error("junk.qcow2", &bytes, ContainerFormat::Qcow2);
}

#[test]
fn vhd_cookie_with_junk_body_is_a_decode_error() {
    // A dynamic VHD mirrors its footer cookie at offset 0; the junk that follows
    // is not a valid footer/header, so the hand-rolled VHD decoder rejects it.
    let mut bytes = vhd::FOOTER_COOKIE.to_vec();
    bytes.resize(bytes.len() + 1024, 0);
    assert_decode_error("junk.vhd", &bytes, ContainerFormat::Vhd);
}

#[test]
fn vhdx_identifier_with_junk_body_is_a_decode_error() {
    let mut bytes = vhdx::FILE_IDENTIFIER.to_vec();
    bytes.resize(bytes.len() + 2048, 0);
    assert_decode_error("junk.vhdx", &bytes, ContainerFormat::Vhdx);
}

#[test]
fn dmg_koly_footer_with_junk_body_is_a_decode_error() {
    // The KOLY trailer sits at the start of the final 512-byte block. Its
    // xml_length (koly[224..232]) claims an XML plist far larger than the file,
    // so the DMG decoder rejects it as out-of-bounds rather than decoding a disk.
    let mut bytes = vec![0u8; 1024];
    bytes[512..516].copy_from_slice(&dmg::KOLY_MAGIC.to_be_bytes());
    // koly begins at file offset 512; xml_length is koly[224..232].
    bytes[512 + 224..512 + 232].copy_from_slice(&u64::MAX.to_be_bytes());
    assert_decode_error("junk.dmg", &bytes, ContainerFormat::Dmg);
}

#[test]
fn opened_image_debug_is_non_exhaustive() {
    // The Box<dyn ReadSeek> reader is not Debug, so OpenedImage's hand-written
    // Debug renders format + size and finishes non-exhaustively.
    let apm = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/apm.bin");
    let opened = open(std::path::Path::new(apm)).unwrap();
    let rendered = format!("{opened:?}");
    assert!(rendered.contains("OpenedImage"), "got {rendered}");
    assert!(rendered.contains("Raw"), "got {rendered}");
    assert!(rendered.contains(".."), "non-exhaustive marker: {rendered}");
}
