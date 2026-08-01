//! DAR (Denis Corbin Disk `ARchiver`) and the logical-container path.
//!
//! DAR is a *logical* backup archive (a file tree), not a raw disk, so
//! [`container::open`] must refuse it with [`OpenError::LogicalContainer`]
//! pointing at [`disk_forensic::logical::open`], and `logical::open` must list
//! its entries and read a file's bytes back.
//!
//! The fixture `tests/data/v11_hello.dar` is a real `dar`-produced archive
//! (format 11) holding `files/hello.txt`; provenance mirrors dar-core's corpus.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use disk_forensic::container::{open, ContainerFormat, OpenError};
use disk_forensic::logical;

fn fixture() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/v11_hello.dar")
}

#[test]
fn container_open_refuses_dar_as_logical_container() {
    let err = open(&fixture()).unwrap_err();
    assert!(
        matches!(err, OpenError::LogicalContainer(ContainerFormat::Dar)),
        "got {err:?}"
    );
    assert!(
        err.to_string().contains("logical::open"),
        "message should point the caller at logical::open: {err}"
    );
}

#[test]
fn logical_open_lists_and_reads_dar_files() {
    let mut img = logical::open(&fixture()).unwrap();
    assert_eq!(img.format(), ContainerFormat::Dar);
    assert!(!img.entries().is_empty(), "the DAR tree must not be empty");

    // A known file (`files/hello.txt`) is listed and reads back non-empty.
    let idx = img
        .entries()
        .iter()
        .position(|e| !e.is_dir && e.path.ends_with("hello.txt"))
        .expect("files/hello.txt should be listed");
    let bytes = img.read_file(idx).unwrap();
    assert!(!bytes.is_empty(), "hello.txt should have content");
    assert_eq!(
        bytes.len() as u64,
        img.entries()[idx].size,
        "read length must match the entry's declared size"
    );
}

#[test]
fn logical_open_rejects_a_directory_read() {
    let mut img = logical::open(&fixture()).unwrap();
    if let Some(idx) = img.entries().iter().position(|e| e.is_dir) {
        let err = img.read_file(idx).unwrap_err();
        assert!(
            matches!(err, logical::LogicalError::IsDirectory(_)),
            "got {err:?}"
        );
    }
}
