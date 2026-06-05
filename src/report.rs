//! Human-readable text rendering of a [`DiskReport`].
//!
//! Each scheme already has a renderer in its own crate; this delegates to the
//! right one so the unified CLI prints a scheme-appropriate report.

use crate::DiskReport;

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
