//! disk4n6's presentation of the normalized findings Report.

mod common;
use common::build_mbr;
use disk_forensic::{analyse_disk, normalize, report::render};
use std::io::Cursor;

#[test]
fn renders_findings_grouped_by_severity_with_source_and_evidence() {
    let disk = build_mbr();
    let dr = analyse_disk(&mut Cursor::new(&disk), disk.len() as u64).unwrap();
    let rep = normalize::report(&dr);
    let text = render(&rep);

    // A severity header for the highest finding present.
    let top = rep.max_severity().unwrap();
    assert!(
        text.contains(&top.to_string()),
        "severity header missing:\n{text}"
    );
    // The first finding's code, source attribution, and offset evidence appear.
    let f = &rep.findings[0];
    assert!(text.contains(&f.code), "code missing:\n{text}");
    assert!(text.contains("mbr-forensic"), "source missing:\n{text}");
    assert!(text.contains("offset"), "evidence missing:\n{text}");
}

#[test]
fn clean_report_renders_a_clean_line() {
    let rep = forensicnomicon::report::Report::default();
    let text = render(&rep);
    assert!(text.to_lowercase().contains("clean") || text.contains("no findings"));
}

#[test]
fn renders_provenance_breadcrumbs() {
    let disk = build_mbr();
    let dr = analyse_disk(&mut Cursor::new(&disk), disk.len() as u64).unwrap();
    let rep = normalize::report(&dr);
    let text = render(&rep);
    assert!(text.contains("Provenance"), "provenance section missing:\n{text}");
    // A specific breadcrumb (label + its source) is shown.
    let p = &rep.provenance[0];
    assert!(text.contains(&p.label), "breadcrumb label missing:\n{text}");
    assert!(text.contains(&p.value), "breadcrumb value missing:\n{text}");
}
