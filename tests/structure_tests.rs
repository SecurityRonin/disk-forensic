//! Structure/layout rendering for a GPT whose partition carries an
//! *unrecognized* type GUID. Both the text structure report and the layout
//! bridge fall back to the raw GUID string when `type_name()` is `None`, which
//! only an unknown-type partition exercises (the stock fixtures all use known
//! GPT type GUIDs).

#![allow(clippy::unwrap_used, clippy::expect_used)]

mod common;
use common::build_gpt_with;
use disk_forensic::{analyse_disk, layout, report};
use std::io::Cursor;

const UNKNOWN_TYPE: &str = "deadbeef-1234-5678-9abc-def012345678";

#[test]
fn unknown_gpt_partition_type_renders_the_raw_guid() {
    let disk = build_gpt_with(UNKNOWN_TYPE, "Mystery");
    let dr = analyse_disk(&mut Cursor::new(&disk), disk.len() as u64).unwrap();

    // text_report -> gpt_structure renders the raw GUID for an unknown type.
    let text = report::text_report(&dr).to_lowercase();
    assert!(text.contains("deadbeef"), "raw type GUID missing:\n{text}");

    // from_report -> gpt_partitions maps the same partition, carrying the GUID
    // as its partition_type instead of a friendly name.
    let disk_layout = layout::from_report(&dr, "evidence.img", disk.len() as u64);
    let part = disk_layout
        .partitions
        .first()
        .expect("the GPT partition should be laid out");
    assert_eq!(
        part.partition_type.as_deref().map(str::to_lowercase),
        Some(UNKNOWN_TYPE.to_string()),
        "layout should carry the raw GUID as the partition type"
    );
}
