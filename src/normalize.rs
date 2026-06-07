//! Normalize each scheme's native analysis into the shared
//! [`forensicnomicon::report`] model, so disk4n6 (and a future GUI) render one
//! uniform [`Report`] instead of N bespoke `XxxAnalysis` types.

use forensicnomicon::report::{
    Category, Finding, Location, Provenance, Report, Source, TimelineEvent,
};

use crate::DiskReport;

// Findings are categorized with the canonical `Category::from_code` from
// forensicnomicon — the single source of truth for the code→category taxonomy,
// shared with every analyzer rather than re-derived here.

// Since 0.4.0 every analyzer re-exports `forensicnomicon::report::Severity` as
// its own `Severity`, so an anomaly's severity is already the canonical type —
// no per-scheme translation is needed.

/// Normalize an MBR analysis. Findings carry their byte offset as evidence.
#[must_use]
pub fn mbr_findings(a: &mbr_forensic::MbrAnalysis) -> Vec<Finding> {
    a.anomalies
        .iter()
        .map(|an| {
            Finding::observation(an.severity, Category::from_code(an.code), an.code.to_string())
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
            Finding::observation(an.severity, Category::from_code(an.code), an.code.to_string())
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
            Finding::observation(an.severity, Category::from_code(an.code), an.code.to_string())
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

/// Map `iso9660-forensic`'s own severity into the canonical one. Unlike the
/// 0.4.0 partition analyzers, the published ISO crate predates the shared report
/// model, so it carries a self-contained `Severity` we translate here.
fn iso_sev(s: iso9660_forensic::findings::Severity) -> forensicnomicon::report::Severity {
    use forensicnomicon::report::Severity as F;
    use iso9660_forensic::findings::Severity as I;
    match s {
        I::Info => F::Info,
        I::Low => F::Low,
        I::Medium => F::Medium,
        I::High => F::High,
        I::Critical => F::Critical,
    }
}

/// Normalize an ISO 9660 analysis into findings.
#[must_use]
pub fn iso_findings(a: &iso9660_forensic::IsoAnalysis) -> Vec<Finding> {
    a.anomalies
        .iter()
        .map(|an| {
            Finding::observation(iso_sev(an.severity), Category::from_code(an.code), an.code.to_string())
                .note(an.note.clone())
                .source(Source {
                    analyzer: "iso9660-forensic".to_string(),
                    scope: "ISO 9660".to_string(),
                    version: None,
                })
                .build()
        })
        .collect()
}

/// Provenance breadcrumbs from an ISO 9660 volume. Temporal facts (creation,
/// modification, authoring window) are normalized into the [`iso_timeline`]
/// instead; empty PVD strings are dropped rather than emitted as noise.
#[must_use]
pub fn iso_provenance(a: &iso9660_forensic::IsoAnalysis) -> Vec<Provenance> {
    let v = &a.volume;
    let mut entries: Vec<(&str, String)> = vec![
        ("volume label", v.volume_label.clone()),
        ("system identifier", v.system_id.clone()),
        ("volume set", v.volume_set_id.clone()),
        ("publisher", v.publisher_id.clone()),
        ("data preparer", v.data_preparer_id.clone()),
        ("application", v.application_id.clone()),
        ("sector mode", v.sector_mode.clone()),
        (
            "extensions",
            format!("Rock Ridge: {}, Joliet: {}", v.has_rock_ridge, v.has_joliet),
        ),
        ("sessions", v.session_count.to_string()),
    ];
    if v.has_enhanced_volume_descriptor {
        entries.push(("enhanced volume descriptor", "present".to_string()));
    }
    if !v.rock_ridge_uids.is_empty() || !v.rock_ridge_gids.is_empty() {
        entries.push((
            "Rock Ridge owners",
            format!("uids {:?}, gids {:?}", v.rock_ridge_uids, v.rock_ridge_gids),
        ));
    }
    if !v.boot_entries.is_empty() {
        let platforms: Vec<&str> = v.boot_entries.iter().map(|b| b.platform.as_str()).collect();
        entries.push((
            "El Torito boot",
            format!("{} entries ({})", v.boot_entries.len(), platforms.join(", ")),
        ));
    }
    entries
        .into_iter()
        .filter(|(_, value)| !value.is_empty())
        .map(|(label, value)| Provenance {
            label: label.to_string(),
            value,
            source: "iso9660-forensic".to_string(),
        })
        .collect()
}

/// Reconstruct the volume's datable biography from an ISO 9660 analysis: the
/// PVD creation/modification stamps and the file-recorded-time authoring window.
#[must_use]
pub fn iso_timeline(a: &iso9660_forensic::IsoAnalysis) -> Vec<TimelineEvent> {
    let v = &a.volume;
    [
        (&v.creation_time, "ISO 9660 volume created"),
        (&v.modification_time, "ISO 9660 volume last modified"),
        (
            &v.earliest_file_time,
            "earliest file recorded time (authoring window start)",
        ),
        (
            &v.latest_file_time,
            "latest file recorded time (authoring window end)",
        ),
    ]
    .into_iter()
    .filter_map(|(when, event)| {
        when.as_ref().map(|w| TimelineEvent {
            when: Some(w.clone()),
            source: "iso9660-forensic".to_string(),
            event: event.to_string(),
        })
    })
    .collect()
}

/// Build the unified [`Report`] from an ISO 9660 analysis.
#[must_use]
pub fn iso_report(a: &iso9660_forensic::IsoAnalysis) -> Report {
    let mut out = Report::default();
    out.findings = iso_findings(a);
    out.provenance = iso_provenance(a);
    out.timeline = iso_timeline(a);
    out
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
