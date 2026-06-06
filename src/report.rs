//! Human-readable text rendering for disk4n6.
//!
//! [`render`] is the presentation of the normalized [`forensicnomicon::report::Report`]
//! (the cross-scheme findings view). [`text_report`] renders the per-scheme
//! structural detail; it currently delegates to each analyzer's renderer and is
//! being migrated to render the native structs directly here.

use core::fmt::Write as _;

use forensicnomicon::report::{Report, Severity};

use crate::DiskReport;

/// Severities in descending order, for grouped rendering.
const SEVERITY_ORDER: [Severity; 5] = [
    Severity::Critical,
    Severity::High,
    Severity::Medium,
    Severity::Low,
    Severity::Info,
];

/// Render the normalized findings [`Report`] as a severity-grouped text block —
/// the uniform cross-scheme view (a future GUI consumes the same `Report`).
#[must_use]
pub fn render(report: &Report) -> String {
    let mut s = String::new();

    // ── Findings (severity-grouped) ──────────────────────────────────────────
    if report.findings.is_empty() {
        s.push_str("Findings: none (clean)\n");
    } else {
        let _ = writeln!(s, "Forensic findings ({}):", report.findings.len());
        for sev in SEVERITY_ORDER {
            let group = report.findings.iter().filter(|f| f.severity == sev);
            let mut header_written = false;
            for f in group {
                if !header_written {
                    let _ = writeln!(s, "\n  [{sev}]");
                    header_written = true;
                }
                let _ = writeln!(
                    s,
                    "    {}  ({} / {}): {}",
                    f.code, f.source.analyzer, f.source.scope, f.note
                );
                for e in &f.evidence {
                    let _ = writeln!(s, "        {} = {}", e.field, e.value);
                }
            }
        }
    }

    // ── Provenance breadcrumbs ───────────────────────────────────────────────
    if !report.provenance.is_empty() {
        s.push_str("\nProvenance:\n");
        for p in &report.provenance {
            let _ = writeln!(s, "  {}: {}  ({})", p.label, p.value, p.source);
        }
    }

    // ── Timeline (the reconstructed biography) ───────────────────────────────
    if !report.timeline.is_empty() {
        s.push_str("\nTimeline:\n");
        for e in &report.timeline {
            let when = e.when.as_deref().unwrap_or("?");
            let _ = writeln!(s, "  [{when}] {}  ({})", e.event, e.source);
        }
    }

    s
}

/// Render a disk analysis as a multi-line text report, showing the full detail
/// from each scheme's own parser.
#[must_use]
pub fn text_report(report: &DiskReport) -> String {
    match report {
        DiskReport::Apm(a) => apm_forensic::report::text_report(a),
        DiskReport::Mbr(m) => mbr_forensic::report::text_report(m),
        // For GPT, show the protective-MBR analysis followed by the full GPT
        // report (partitions, GUIDs, CRC status) from gpt-forensic.
        DiskReport::Gpt(m) => {
            let mut s = mbr_forensic::report::text_report(m);
            if let Some(gpt) = &m.gpt {
                s.push('\n');
                s.push_str(&gpt_forensic::report::text_report(gpt));
            }
            s
        }
    }
}
