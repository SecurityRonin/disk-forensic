//! AFF4 in the universal container opener.
//!
//! A *physical* AFF4 (`aff4:ImageStream` / `aff4:Map`) is a raw disk view, so it
//! belongs in [`container::open`] alongside E01/VMDK/etc. A *logical* AFF4
//! (`aff4:FileImage`) is a file collection, not a disk — `open` must refuse it
//! with an honest, actionable [`OpenError::LogicalContainer`] rather than hand
//! back a bogus disk reader.
//!
//! Fixtures come from `aff4::testutil` (the reader crate's own spec-faithful
//! builder), so ground truth is independent of disk-forensic.

use disk_forensic::container::{open, ContainerFormat, OpenError};
use std::io::{Read, Seek, SeekFrom};

/// `test_aff4` stores the payload in a single chunk whose `aff4:size` (and
/// therefore the reader's virtual disk size) is exactly the fixture builder's
/// `CHUNK_SIZE` (512 bytes in `aff4::testutil`).
const AFF4_VIRTUAL_SIZE: u64 = 512;

fn write_temp(name: &str, bytes: &[u8]) -> (tempfile::TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join(name);
    std::fs::write(&path, bytes).unwrap();
    (dir, path)
}

#[test]
fn opens_and_reads_physical_aff4_disk() {
    // A physical AFF4 disk image (aff4:ImageStream). container::open must decode
    // it to a Read + Seek disk view and read the payload back byte-for-byte.
    let payload: &[u8] = b"AFF4-PHYSICAL-DISK-PAYLOAD\x00\x01\x02\x03\xfe\xff";
    let bytes = aff4::testutil::test_aff4(payload);
    let (_dir, path) = write_temp("physical.aff4", &bytes);

    let mut opened = open(&path).unwrap();
    assert_eq!(opened.format, ContainerFormat::Aff4);
    assert_eq!(opened.size, AFF4_VIRTUAL_SIZE, "decoded virtual disk size");

    let mut buf = vec![0u8; payload.len()];
    opened.reader.seek(SeekFrom::Start(0)).unwrap();
    opened.reader.read_exact(&mut buf).unwrap();
    assert_eq!(buf, payload, "decoded disk bytes at offset 0");

    // Bytes past the payload are the chunk's zero fill (virtual size 64 KiB).
    let mut tail = [0u8; 4];
    opened
        .reader
        .seek(SeekFrom::Start(AFF4_VIRTUAL_SIZE - 4))
        .unwrap();
    opened.reader.read_exact(&mut tail).unwrap();
    assert_eq!(tail, [0u8; 4], "zero fill at end of the virtual disk");
}

#[test]
fn logical_aff4_is_reported_as_logical_container_not_a_disk() {
    // A logical AFF4 (aff4:FileImage) has no disk underneath. container::open
    // must NOT return a bogus disk reader — it must flag it as a logical
    // container and point at disk_forensic::logical::open.
    let bytes =
        aff4::testutil::test_aff4_logical("evidence.txt", b"hello logical", &"0".repeat(32));
    let (_dir, path) = write_temp("logical.aff4", &bytes);

    let err = open(&path).unwrap_err();
    assert!(
        matches!(err, OpenError::LogicalContainer(ContainerFormat::Aff4)),
        "got {err:?}"
    );
    assert!(
        err.to_string().contains("logical"),
        "message should name the logical path: {err}"
    );
}

#[test]
fn truncated_aff4_errors_without_panic() {
    // A half-written AFF4 (corrupt ZIP central directory) must surface a loud
    // typed error, never panic and never a silent empty disk.
    let bytes = aff4::testutil::test_aff4(b"payload-to-be-truncated");
    let truncated = &bytes[..bytes.len() / 2];
    let (_dir, path) = write_temp("truncated.aff4", truncated);

    let err = open(&path).unwrap_err();
    assert!(
        matches!(
            err,
            OpenError::Decode(ContainerFormat::Aff4, _) | OpenError::Io(_)
        ),
        "got {err:?}"
    );
}

#[test]
fn map_backed_aff4_with_corrupt_map_entry_is_a_disk_decode_error() {
    // A Map-backed AFF4 whose turtle classifies it as a disk (container_kind ==
    // Disk) but whose /map ZIP entry is corrupt: container::open must surface a
    // typed decode error from the *disk reader* (Aff4Reader::open), not silently
    // yield a bogus disk. This exercises the disk-open error arm specifically,
    // distinct from the metadata-classification error path.
    let mut bytes = aff4::testutil::test_aff4_map(b"MAP-PAYLOAD");
    // The /map entry is a 28-byte STORED blob beginning with two little-endian
    // u64 512s (map_offset, length). Find it and flip a byte so the ZIP CRC on
    // read fails when the reader loads /map.
    let needle = {
        let mut n = Vec::new();
        n.extend_from_slice(&512u64.to_le_bytes());
        n.extend_from_slice(&512u64.to_le_bytes());
        n
    };
    let pos = bytes
        .windows(needle.len())
        .position(|w| w == needle)
        .expect("map binary should be present in the fixture");
    bytes[pos] ^= 0xFF;

    let (_dir, path) = write_temp("corrupt-map.aff4", &bytes);

    // Classification still says Disk — the corruption is only in the stream data.
    assert_eq!(
        aff4::container_kind(&path).unwrap(),
        aff4::ContainerKind::Disk,
        "turtle still classifies the container as a disk"
    );

    let err = open(&path).unwrap_err();
    assert!(
        matches!(err, OpenError::Decode(ContainerFormat::Aff4, _)),
        "got {err:?}"
    );
}
