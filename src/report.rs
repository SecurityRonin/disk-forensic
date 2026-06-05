//! Human-readable text rendering of a [`DiskReport`].
//!
//! Each scheme already has a renderer in its own crate; this delegates to the
//! right one so the unified CLI prints a scheme-appropriate report.

use crate::DiskReport;

/// Render a disk analysis as a multi-line text report.
#[must_use]
pub fn text_report(report: &DiskReport) -> String {
    match report {
        DiskReport::Apm(a) => apm_forensic::report::text_report(a),
        // Both carry an MbrAnalysis; mbr-forensic's renderer already includes
        // the GPT cross-check section for the Gpt case.
        DiskReport::Mbr(m) | DiskReport::Gpt(m) => mbr_forensic::report::text_report(m),
    }
}
