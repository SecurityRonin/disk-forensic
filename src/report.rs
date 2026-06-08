//! Human-readable text rendering for disk4n6.
//!
//! [`render`] is the presentation of the normalized [`forensicnomicon::report::Report`]
//! (the cross-scheme findings/provenance/timeline view). [`text_report`] renders
//! the per-scheme structural inventory directly from the analyzers' native typed
//! structs. All presentation lives here; the analyzer libraries are pure data.

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
            let group = report.findings.iter().filter(|f| f.severity == Some(sev));
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

/// Render the per-scheme **structural** inventory (partition/volume layout) from
/// the analyzers' native typed structs. Anomalies are intentionally omitted —
/// they are shown uniformly by [`render`] from the normalized findings model.
/// disk4n6 owns this presentation; the analyzer libraries are pure data.
#[must_use]
pub fn text_report(report: &DiskReport) -> String {
    match report {
        DiskReport::Apm(a) => apm_structure(a),
        DiskReport::Mbr(m) => mbr_structure(m),
        DiskReport::Gpt(m) => {
            let mut s = mbr_structure(m);
            if let Some(gpt) = &m.gpt {
                s.push('\n');
                s.push_str(&gpt_structure(gpt));
            }
            s
        }
    }
}

/// Width of the GPT report's horizontal rule.
const RULE: usize = 80;

fn mbr_structure(a: &mbr_partition_forensic::MbrAnalysis) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "MBR Forensic Analysis");
    let _ = writeln!(s, "  disk signature : {:#010x}", a.disk_serial);
    let _ = writeln!(s, "  boot code      : {:?}", a.boot_code_id);
    let _ = writeln!(s, "  partitioning   : {:?}", a.era);
    let _ = writeln!(s, "\nPartition table ({} entries):", a.partitions.len());
    if a.partitions.is_empty() {
        let _ = writeln!(s, "  (no primary partitions)");
    }
    for p in &a.partitions {
        let fs = match p.detected_fs {
            Some(fs) => format!("{fs:?}"),
            None => "-".to_string(),
        };
        let _ = writeln!(
            s,
            "  [{}] {:<24} LBA {:>12}..={:<12}  fs={}",
            p.index,
            p.declared_type.name(),
            p.lba_start,
            p.lba_end,
            fs,
        );
    }
    if let Some(gpt) = &a.gpt {
        let _ = writeln!(
            s,
            "\nGPT cross-check: {} GPT partition entries",
            gpt.partitions.len()
        );
    }
    s
}

fn gpt_structure(a: &gpt_partition_forensic::GptAnalysis) -> String {
    let mut out = String::new();
    out.push_str("GPT Forensic Analysis\n");
    out.push_str(&"=".repeat(RULE));
    out.push('\n');
    let rev_hi = a.primary.revision >> 16;
    let rev_lo = a.primary.revision & 0xFFFF;
    let _ = writeln!(out, "Disk GUID:       {}", a.disk_guid);
    let _ = writeln!(out, "Revision:        {rev_hi}.{rev_lo}");
    let _ = writeln!(
        out,
        "Header CRC:      {}",
        if a.primary.header_crc_valid {
            "valid"
        } else {
            "INVALID"
        }
    );
    let _ = writeln!(
        out,
        "Usable LBAs:     {}..{}",
        a.primary.first_usable_lba, a.primary.last_usable_lba
    );
    let _ = writeln!(out, "Sector size:     {} bytes", a.sector_size);
    let _ = writeln!(out, "GPT SHA-256:     {}", a.gpt_sha256);
    match &a.backup {
        Some(b) => {
            let _ = writeln!(out, "Backup GPT:      present (LBA {})", b.my_lba);
        }
        None => out.push_str("Backup GPT:      MISSING\n"),
    }
    out.push('\n');
    let _ = writeln!(out, "Partitions ({}):", a.partitions.len());
    let _ = writeln!(
        out,
        "{:<3} {:<31} {:<12} {:<11} NAME",
        "#", "TYPE", "FIRST LBA", "LAST LBA"
    );
    for (i, p) in a.partitions.iter().enumerate() {
        let ty = p
            .type_name()
            .map_or_else(|| p.type_guid.to_string(), ToString::to_string);
        let _ = writeln!(
            out,
            "{i:<3} {ty:<31} {:<12} {:<11} {}",
            p.first_lba, p.last_lba, p.name
        );
    }
    out
}

fn apm_structure(a: &apm_partition_forensic::ApmAnalysis) -> String {
    let mut s = String::new();
    let _ = writeln!(s, "APM Forensic Analysis");
    let _ = writeln!(s, "  block size     : {} bytes", a.block_size);
    let _ = writeln!(s, "  device blocks  : {}", a.device_block_count);
    let _ = writeln!(s, "\nPartition map ({} entries):", a.partitions.len());
    if a.partitions.is_empty() {
        let _ = writeln!(s, "  (no partition entries)");
    }
    for (i, p) in a.partitions.iter().enumerate() {
        let _ = writeln!(
            s,
            "  [{}] {:<20} {:<24} blocks {:>10}..={:<10}",
            i,
            p.name,
            p.type_name,
            p.start_block,
            p.end_block(),
        );
    }
    s
}
