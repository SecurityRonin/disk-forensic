//! Normalize each scheme's native analysis into the shared
//! [`forensicnomicon::report`] model, so disk4n6 (and a future GUI) render one
//! uniform [`Report`] instead of N bespoke `XxxAnalysis` types.

use forensicnomicon::report::{Category, Finding, Location, Provenance, Report, Source};

use crate::DiskReport;

/// Coarse forensic category derived from a finding's stable code. A pragmatic
/// first pass (keyword-based); refined per-analyzer over time.
fn classify(code: &str) -> Category {
    let c = code.to_ascii_uppercase();
    if c.contains("CRC") || c.contains("INTEGRITY") {
        Category::Integrity
    } else if c.contains("OVERLAP")
        || c.contains("OOB")
        || c.contains("BOUND")
        || c.contains("CHS")
        || c.contains("MAP-COUNT")
    {
        Category::Structure
    } else if c.contains("RESIDUAL")
        || c.contains("SLACK")
        || c.contains("GAP")
        || c.contains("CARVE")
        || c.contains("UNMAPPED")
        || c.contains("ZEROLEN")
    {
        Category::Residue
    } else if c.contains("HIDDEN")
        || c.contains("CONCEAL")
        || c.contains("WIPED")
        || c.contains("ERASED")
        || c.contains("PROTECTIVE")
    {
        Category::Concealment
    } else if c.contains("BOOT") {
        Category::Threat
    } else {
        Category::Structure
    }
}

// Since 0.4.0 every analyzer re-exports `forensicnomicon::report::Severity` as
// its own `Severity`, so an anomaly's severity is already the canonical type —
// no per-scheme translation is needed.

/// Normalize an MBR analysis. Findings carry their byte offset as evidence.
#[must_use]
pub fn mbr_findings(a: &mbr_forensic::MbrAnalysis) -> Vec<Finding> {
    a.anomalies
        .iter()
        .map(|an| {
            Finding::observation(an.severity, classify(an.code), an.code.to_string())
                .note(an.note.clone())
                .source(Source {
                    analyzer: "mbr-forensic".to_string(),
                    scope: "MBR".to_string(),
                    version: None,
                })
                .evidence_at(
                    "offset",
                    format!("{:#x}", an.offset),
                    Location::ByteOffset(an.offset),
                )
                .build()
        })
        .collect()
}

/// Normalize a GPT analysis.
#[must_use]
pub fn gpt_findings(a: &gpt_forensic::GptAnalysis) -> Vec<Finding> {
    a.anomalies
        .iter()
        .map(|an| {
            Finding::observation(an.severity, classify(an.code), an.code.to_string())
                .note(an.note.clone())
                .source(Source {
                    analyzer: "gpt-forensic".to_string(),
                    scope: "GPT".to_string(),
                    version: None,
                })
                .build()
        })
        .collect()
}

/// Normalize an Apple Partition Map analysis.
#[must_use]
pub fn apm_findings(a: &apm_forensic::ApmAnalysis) -> Vec<Finding> {
    a.anomalies
        .iter()
        .map(|an| {
            Finding::observation(an.severity, classify(an.code), an.code.to_string())
                .note(an.note.clone())
                .source(Source {
                    analyzer: "apm-forensic".to_string(),
                    scope: "APM".to_string(),
                    version: None,
                })
                .build()
        })
        .collect()
}

/// Provenance breadcrumbs from an MBR analysis.
#[must_use]
pub fn mbr_provenance(a: &mbr_forensic::MbrAnalysis) -> Vec<Provenance> {
    vec![
        Provenance {
            label: "boot code".to_string(),
            value: format!("{:?}", a.boot_code_id),
            source: "mbr-forensic".to_string(),
        },
        Provenance {
            label: "partitioning era".to_string(),
            value: format!("{:?}", a.era),
            source: "mbr-forensic".to_string(),
        },
        Provenance {
            label: "disk signature".to_string(),
            value: format!("{:#010x}", a.disk_serial),
            source: "mbr-forensic".to_string(),
        },
    ]
}

/// Provenance breadcrumbs from a GPT analysis.
#[must_use]
pub fn gpt_provenance(a: &gpt_forensic::GptAnalysis) -> Vec<Provenance> {
    vec![
        Provenance {
            label: "disk GUID".to_string(),
            value: a.disk_guid.to_string(),
            source: "gpt-forensic".to_string(),
        },
        Provenance {
            label: "sector size".to_string(),
            value: format!("{} bytes", a.sector_size),
            source: "gpt-forensic".to_string(),
        },
        Provenance {
            label: "GPT SHA-256".to_string(),
            value: a.gpt_sha256.clone(),
            source: "gpt-forensic".to_string(),
        },
    ]
}

/// Provenance breadcrumbs from an APM analysis.
#[must_use]
pub fn apm_provenance(a: &apm_forensic::ApmAnalysis) -> Vec<Provenance> {
    vec![
        Provenance {
            label: "block size".to_string(),
            value: format!("{} bytes", a.block_size),
            source: "apm-forensic".to_string(),
        },
        Provenance {
            label: "device blocks".to_string(),
            value: a.device_block_count.to_string(),
            source: "apm-forensic".to_string(),
        },
    ]
}

/// Build the unified [`Report`] from a [`DiskReport`]. A GPT disk contributes
/// both its protective-MBR and parsed-GPT findings and provenance.
#[must_use]
pub fn report(disk: &DiskReport) -> Report {
    let (findings, provenance) = match disk {
        DiskReport::Apm(a) => (apm_findings(a), apm_provenance(a)),
        DiskReport::Mbr(m) => (mbr_findings(m), mbr_provenance(m)),
        DiskReport::Gpt(m) => {
            let mut findings = mbr_findings(m);
            let mut provenance = mbr_provenance(m);
            if let Some(gpt) = &m.gpt {
                findings.extend(gpt_findings(gpt));
                provenance.extend(gpt_provenance(gpt));
            }
            (findings, provenance)
        }
    };
    let mut out = Report::default();
    out.findings = findings;
    out.provenance = provenance;
    out
}
