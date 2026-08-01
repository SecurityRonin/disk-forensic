//! Container-level forensic findings ride on the opened image.
//!
//! disk4n6 decodes a VMDK to a disk view; it must also run `vmdk-forensic`'s
//! `analyse()` so VMDK anomalies (RGD mismatch, dangling pointers, unclean
//! shutdown, …) aggregate into the normalized report alongside the partition and
//! filesystem findings — not silently dropped at the container boundary.

#![allow(clippy::unwrap_used, clippy::expect_used)]

const DF_VMDK: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/df.vmdk");

#[test]
fn vmdk_unclean_shutdown_surfaces_in_opened_image() {
    // df.vmdk is a clean monolithicSparse image; flip the uncleanShutdown byte
    // (sparse-header offset 72) so analyse() reports VMDK-UNCLEAN-SHUTDOWN, then
    // assert that finding rides on the OpenedImage.
    let mut bytes = std::fs::read(DF_VMDK).expect("read df.vmdk fixture");
    bytes[72] = 1;
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("unclean.vmdk");
    std::fs::write(&p, &bytes).unwrap();

    let opened = disk_forensic::container::open(&p).expect("open mutated vmdk");
    let codes: Vec<&str> = opened.findings.iter().map(|f| f.code.as_ref()).collect();
    assert!(
        codes.contains(&"VMDK-UNCLEAN-SHUTDOWN"),
        "VMDK forensic findings surface on the opened image, got: {codes:?}"
    );
}

#[test]
fn clean_vmdk_has_no_container_findings() {
    // The pristine fixture has no anomalies — findings stays empty, so a clean
    // image is not falsely flagged.
    let opened =
        disk_forensic::container::open(std::path::Path::new(DF_VMDK)).expect("open clean vmdk");
    assert!(
        opened.findings.is_empty(),
        "a clean VMDK has no container findings, got: {:?}",
        opened
            .findings
            .iter()
            .map(|f| f.code.as_ref())
            .collect::<Vec<_>>()
    );
}
