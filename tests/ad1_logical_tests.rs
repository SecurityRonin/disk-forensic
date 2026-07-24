//! AD1 and the logical-container path.
//!
//! AD1 (FTK "Custom Content Image") is a *logical* file tree with no raw disk, so
//! [`container::open`] must refuse it with an honest
//! [`OpenError::LogicalContainer`] pointing at [`disk_forensic::logical::open`],
//! and `logical::open` must list its entries and read a file's bytes back.
//!
//! Fixtures come from `ad1::testfix` (the reader crate's spec-faithful builder,
//! ground truth via independent flate2 + RustCrypto), so correctness is not
//! self-referential.

use disk_forensic::container::{open, ContainerFormat, OpenError};
use disk_forensic::logical;

/// Build a single-segment AD1 image from `ad1`'s sample tree; return the temp
/// dir (keep it alive), the path, and the expected per-entry facts (DFS order).
fn build_ad1() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    Vec<ad1::testfix::Expected>,
) {
    let built = ad1::testfix::build(ad1::testfix::sample_tree());
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("image.ad1");
    std::fs::write(&path, &built.bytes).unwrap();
    (dir, path, built.expected)
}

#[test]
fn container_open_refuses_ad1_as_logical_container() {
    // AD1 is a file tree, not a disk. open() must not hand back a bogus disk
    // reader — it must flag the logical container and name logical::open.
    let (_dir, path, _expected) = build_ad1();
    let err = open(&path).unwrap_err();
    assert!(
        matches!(err, OpenError::LogicalContainer(ContainerFormat::Ad1)),
        "got {err:?}"
    );
    assert!(
        err.to_string().contains("logical::open"),
        "message should point the caller at logical::open: {err}"
    );
}

#[test]
fn logical_open_lists_and_reads_ad1_files() {
    let (_dir, path, expected) = build_ad1();
    let mut img = logical::open(&path).unwrap();
    assert_eq!(img.format(), ContainerFormat::Ad1);

    // Every expected file/dir surfaces, at its recorded path and size.
    for ex in &expected {
        let got = img
            .entries()
            .iter()
            .find(|e| e.path == ex.path)
            .unwrap_or_else(|| panic!("entry {:?} missing from the AD1 tree", ex.path));
        assert_eq!(got.is_dir, ex.is_dir, "is_dir for {:?}", ex.path);
        assert_eq!(got.size, ex.size, "size for {:?}", ex.path);
    }

    // A known file reads back byte-for-byte.
    let file = expected
        .iter()
        .find(|e| !e.is_dir && e.data.as_ref().is_some_and(|d| !d.is_empty()))
        .expect("sample tree has at least one non-empty file");
    let idx = img
        .entries()
        .iter()
        .position(|e| e.path == file.path)
        .unwrap();
    let bytes = img.read_file(idx).unwrap();
    assert_eq!(
        &bytes,
        file.data.as_ref().unwrap(),
        "content of {:?}",
        file.path
    );
}

#[test]
fn logical_open_rejects_a_directory_read() {
    let (_dir, path, expected) = build_ad1();
    let mut img = logical::open(&path).unwrap();
    let dir_path = expected
        .iter()
        .find(|e| e.is_dir)
        .expect("sample tree has a directory")
        .path
        .clone();
    let idx = img
        .entries()
        .iter()
        .position(|e| e.path == dir_path)
        .unwrap();
    let err = img.read_file(idx).unwrap_err();
    assert!(
        matches!(err, logical::LogicalError::IsDirectory(_)),
        "got {err:?}"
    );
}

#[test]
fn logical_open_rejects_a_raw_disk_image() {
    // A raw MBR disk is not a logical container — logical::open must say so and
    // point back at container::open, not parse garbage.
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("raw.dd");
    let mut disk = vec![0u8; 512];
    disk[510] = 0x55;
    disk[511] = 0xAA;
    std::fs::write(&path, &disk).unwrap();
    let err = logical::open(&path).unwrap_err();
    assert!(
        matches!(
            err,
            logical::LogicalError::NotLogical(ContainerFormat::Raw, _)
        ),
        "got {err:?}"
    );
}

#[test]
fn truncated_ad1_errors_without_panic() {
    // A first segment cut off inside its header/tree (AD1 stores the tree first,
    // bulk data after) must surface a loud typed error, never panic. 40 bytes
    // keeps the "ADSEGMENTEDFILE" marker so the sniffer still routes to AD1, but
    // the item-tree walk runs off the end.
    let built = ad1::testfix::build(ad1::testfix::sample_tree());
    let truncated = &built.bytes[..40];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("truncated.ad1");
    std::fs::write(&path, truncated).unwrap();
    let err = logical::open(&path).unwrap_err();
    assert!(
        matches!(
            err,
            logical::LogicalError::Ad1(_) | logical::LogicalError::Io(_)
        ),
        "got {err:?}"
    );
}

#[test]
fn ad1_file_with_truncated_data_reads_without_panic() {
    // The tree opens, but a file whose bulk chunk data was cut off must fail the
    // read loudly (or short-read), never panic — AD1's read_at is the codec-like
    // surface that untrusted truncation targets.
    let built = ad1::testfix::build(ad1::testfix::sample_tree());
    // Keep the tree + metadata (first ~half), drop the bulk file data.
    let truncated = &built.bytes[..built.bytes.len() / 2];
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("data_truncated.ad1");
    std::fs::write(&path, truncated).unwrap();

    let mut img = logical::open(&path).expect("tree is intact, open succeeds");
    // The large file (a.bin, 200 KiB) had its data truncated: reading it must
    // return an error or fewer bytes than declared, and must not panic.
    let idx = img
        .entries()
        .iter()
        .position(|e| e.path.ends_with("a.bin"))
        .expect("a.bin listed");
    let declared = img.entries()[idx].size;
    match img.read_file(idx) {
        Ok(bytes) => assert!(
            (bytes.len() as u64) < declared,
            "a truncated file must not yield its full declared length"
        ),
        Err(logical::LogicalError::Ad1(_) | logical::LogicalError::Io(_)) => {}
        Err(other) => panic!("unexpected error kind: {other:?}"),
    }
}

#[test]
fn logical_open_reads_a_logical_aff4() {
    // The logical path also covers AFF4-Logical (aff4:FileImage). container::open
    // refuses it (see aff4_tests); logical::open lists and reads it.
    let content = b"aff4 logical file body";
    let bytes = aff4::testutil::test_aff4_logical("notes.txt", content, &"0".repeat(32));
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("logical.aff4");
    std::fs::write(&path, &bytes).unwrap();

    let mut img = logical::open(&path).unwrap();
    assert_eq!(img.format(), ContainerFormat::Aff4);
    let idx = img
        .entries()
        .iter()
        .position(|e| e.path.ends_with("notes.txt"))
        .expect("the logical file should be listed");
    assert_eq!(img.read_file(idx).unwrap(), content);
}

#[test]
fn logical_open_rejects_a_physical_aff4() {
    // A physical AFF4 is a disk, not a logical container: logical::open must
    // reject it and send the caller to container::open.
    let bytes = aff4::testutil::test_aff4(b"physical payload");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("physical.aff4");
    std::fs::write(&path, &bytes).unwrap();
    let err = logical::open(&path).unwrap_err();
    assert!(
        matches!(
            err,
            logical::LogicalError::NotLogical(ContainerFormat::Aff4, _)
        ),
        "got {err:?}"
    );
}

#[test]
fn logical_image_debug_shows_format_and_entry_count() {
    // LogicalImage holds a non-Debug backend, so its hand-written Debug renders
    // the format and the entry count (never the raw backend handle).
    let (_dir, path, _expected) = build_ad1();
    let img = logical::open(&path).unwrap();
    let rendered = format!("{img:?}");
    assert!(rendered.contains("LogicalImage"), "got {rendered}");
    assert!(rendered.contains("Ad1"), "format missing: {rendered}");
    assert!(
        rendered.contains(&format!("entries: {}", img.entries().len())),
        "entry count missing: {rendered}"
    );
}
