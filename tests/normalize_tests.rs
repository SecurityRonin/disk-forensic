//! Normalizing each scheme's native analysis into the shared
//! forensicnomicon::report::Report model.

mod common;
use common::{build_gpt, build_mbr};
use disk_forensic::{analyse_disk, normalize};
use std::io::Cursor;

const APM: &[u8] = include_bytes!("data/apm.bin");

fn report_of(disk: &[u8]) -> forensicnomicon::report::Report {
    let dr = analyse_disk(&mut Cursor::new(disk.to_vec()), disk.len() as u64).unwrap();
    normalize::report(&dr)
}

#[test]
fn normalizes_mbr_findings_with_source_and_evidence() {
    let r = report_of(&build_mbr());
    assert!(!r.findings.is_empty(), "an all-zero-boot MBR has anomalies");
    assert!(r.findings.iter().all(|f| f.source.analyzer == "mbr-forensic"));
    assert!(r.findings.iter().any(|f| f.code.starts_with("MBR-")));
    assert!(
        r.findings[0].evidence.iter().any(|e| e.field == "offset"),
        "MBR findings carry their byte offset as evidence"
    );
    assert!(r.max_severity().is_some());
}

#[test]
fn normalizes_gpt_disk_attributing_protective_mbr_findings() {
    let r = report_of(&build_gpt());
    // A GPT disk's protective MBR yields mbr-forensic findings; the (clean) GPT
    // may add none. Every finding has a non-empty code + a valid source.
    assert!(r.findings.iter().any(|f| f.source.analyzer == "mbr-forensic"));
    assert!(r
        .findings
        .iter()
        .all(|f| !f.code.is_empty() && !f.source.analyzer.is_empty()));
}

#[test]
fn normalizes_apm_attributing_to_apm_forensic() {
    let r = report_of(APM);
    // Real APM fixture is clean, but every finding (if any) attributes to apm.
    assert!(r.findings.iter().all(|f| f.source.analyzer == "apm-forensic"));
    let _ = r.max_severity();
}
