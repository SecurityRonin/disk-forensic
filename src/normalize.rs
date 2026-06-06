//! Normalize each scheme's native analysis into the shared
//! [`forensicnomicon::report`] model, so disk4n6 (and a future GUI) render one
//! uniform [`Report`] instead of N bespoke `XxxAnalysis` types.

use forensicnomicon::report::{Category, Evidence, Finding, Location, Report, Severity, Source};

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

macro_rules! map_severity {
    ($name:ident, $native:path) => {
        fn $name(s: $native) -> Severity {
            use $native as S;
            match s {
                S::Info => Severity::Info,
                S::Low => Severity::Low,
                S::Medium => Severity::Medium,
                S::High => Severity::High,
                S::Critical => Severity::Critical,
            }
        }
    };
}
map_severity!(mbr_sev, mbr_forensic::Severity);
map_severity!(gpt_sev, gpt_forensic::Severity);
map_severity!(apm_sev, apm_forensic::Severity);

/// Normalize an MBR analysis. Findings carry their byte offset as evidence.
#[must_use]
pub fn mbr_findings(a: &mbr_forensic::MbrAnalysis) -> Vec<Finding> {
    a.anomalies
        .iter()
        .map(|an| Finding {
            severity: mbr_sev(an.severity),
            category: classify(an.code),
            code: an.code.to_string(),
            note: an.note.clone(),
            source: Source {
                analyzer: "mbr-forensic".to_string(),
                scope: "MBR".to_string(),
            },
            evidence: vec![Evidence {
                field: "offset".to_string(),
                value: format!("{:#x}", an.offset),
                location: Some(Location::ByteOffset(an.offset)),
            }],
        })
        .collect()
}

/// Normalize a GPT analysis.
#[must_use]
pub fn gpt_findings(a: &gpt_forensic::GptAnalysis) -> Vec<Finding> {
    a.anomalies
        .iter()
        .map(|an| Finding {
            severity: gpt_sev(an.severity),
            category: classify(an.code),
            code: an.code.to_string(),
            note: an.note.clone(),
            source: Source {
                analyzer: "gpt-forensic".to_string(),
                scope: "GPT".to_string(),
            },
            evidence: Vec::new(),
        })
        .collect()
}

/// Normalize an Apple Partition Map analysis.
#[must_use]
pub fn apm_findings(a: &apm_forensic::ApmAnalysis) -> Vec<Finding> {
    a.anomalies
        .iter()
        .map(|an| Finding {
            severity: apm_sev(an.severity),
            category: classify(an.code),
            code: an.code.to_string(),
            note: an.note.clone(),
            source: Source {
                analyzer: "apm-forensic".to_string(),
                scope: "APM".to_string(),
            },
            evidence: Vec::new(),
        })
        .collect()
}

/// Build the unified [`Report`] from a [`DiskReport`]. A GPT disk contributes
/// both its protective-MBR findings and its parsed-GPT findings.
#[must_use]
pub fn report(disk: &DiskReport) -> Report {
    let findings = match disk {
        DiskReport::Apm(a) => apm_findings(a),
        DiskReport::Mbr(m) => mbr_findings(m),
        DiskReport::Gpt(m) => {
            let mut v = mbr_findings(m);
            if let Some(gpt) = &m.gpt {
                v.extend(gpt_findings(gpt));
            }
            v
        }
    };
    Report {
        findings,
        provenance: Vec::new(),
        timeline: Vec::new(),
    }
}
