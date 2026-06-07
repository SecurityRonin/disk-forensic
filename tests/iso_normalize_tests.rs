//! Normalizing an ISO 9660 analysis into the shared forensicnomicon::report
//! model — provenance completeness and the temporal timeline.

use disk_forensic::normalize;
use std::fs::File;

const ISO: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/df.iso");

fn iso_report() -> forensicnomicon::report::Report {
    let mut f = File::open(ISO).unwrap();
    let a = iso9660_forensic::analyse(&mut f).unwrap();
    normalize::iso_report(&a)
}

#[test]
fn iso_provenance_surfaces_volume_system_and_authoring_intel() {
    let r = iso_report();
    let labels: Vec<&str> = r.provenance.iter().map(|p| p.label.as_str()).collect();

    assert!(r
        .provenance
        .iter()
        .any(|p| p.label == "volume label" && p.value == "DFTEST"));
    // mastering/system fingerprint (hdiutil writes the Apple system identifier)
    assert!(
        r.provenance
            .iter()
            .any(|p| p.label.contains("system") && p.value.contains("APPLE")),
        "system/mastering id missing: {labels:?}"
    );
    // PVD session count
    assert!(
        r.provenance.iter().any(|p| p.label.contains("session")),
        "session count missing: {labels:?}"
    );
    // Rock Ridge authoring-account intel (PX owner uids/gids)
    assert!(
        r.provenance
            .iter()
            .any(|p| p.label.to_lowercase().contains("owner")),
        "Rock Ridge owner intel missing: {labels:?}"
    );
    // every breadcrumb attributes to the analyzer and carries a non-empty value
    // (empty PVD strings like publisher/application must be dropped, not emitted)
    assert!(r
        .provenance
        .iter()
        .all(|p| p.source == "iso9660-forensic" && !p.value.is_empty()));
}

#[test]
fn iso_timeline_reconstructs_the_authoring_window() {
    let r = iso_report();
    assert!(
        !r.timeline.is_empty(),
        "ISO temporal data should populate a timeline"
    );
    assert!(
        r.timeline
            .iter()
            .any(|e| e.event.to_lowercase().contains("creat")),
        "volume-created event missing: {:?}",
        r.timeline
    );
    assert!(r.timeline.iter().all(|e| e.source == "iso9660-forensic"));
    assert!(r.timeline.iter().all(|e| e.when.is_some()));
}

#[test]
fn iso_findings_attribute_to_iso_forensic() {
    let r = iso_report();
    // df.iso is clean; any findings that surface must attribute correctly.
    assert!(r
        .findings
        .iter()
        .all(|f| f.source.analyzer == "iso9660-forensic"));
}
