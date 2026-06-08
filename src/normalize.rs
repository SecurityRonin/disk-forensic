//! Normalize each scheme's native analysis into the shared
//! [`forensicnomicon::report`] model, so disk4n6 (and a future GUI) render one
//! uniform [`Report`] instead of N bespoke `XxxAnalysis` types.

use forensicnomicon::report::{Finding, Observation, Provenance, Report, Source, TimelineEvent};

use crate::DiskReport;

/// Convert an analyzer's anomalies into canonical findings via the
/// [`Observation`] trait — the conversion (severity, category, note, evidence,
/// MITRE, confidence) lives in `forensicnomicon`, not duplicated here.
fn findings_of<'a, O: Observation + 'a>(
    anomalies: impl IntoIterator<Item = &'a O>,
    analyzer: &str,
    scope: &str,
) -> Vec<Finding> {
    anomalies
        .into_iter()
        .map(|an| {
            an.to_finding(Source {
                analyzer: analyzer.to_string(),
                scope: scope.to_string(),
                version: None,
            })
        })
        .collect()
}

// Findings are categorized with the canonical `Category::from_code` from
// forensicnomicon — the single source of truth for the code→category taxonomy,
// shared with every analyzer rather than re-derived here.

// Since 0.4.0 every analyzer re-exports `forensicnomicon::report::Severity` as
// its own `Severity`, so an anomaly's severity is already the canonical type —
// no per-scheme translation is needed.

/// Normalize an MBR analysis. Findings carry their byte offset as evidence
/// (sourced from the analyzer's `Observation::evidence`).
#[must_use]
pub fn mbr_findings(a: &mbr_partition_forensic::MbrAnalysis) -> Vec<Finding> {
    findings_of(&a.anomalies, "mbr-partition-forensic", "MBR")
}

/// Normalize a GPT analysis.
#[must_use]
pub fn gpt_findings(a: &gpt_partition_forensic::GptAnalysis) -> Vec<Finding> {
    findings_of(&a.anomalies, "gpt-partition-forensic", "GPT")
}

/// Normalize an Apple Partition Map analysis.
#[must_use]
pub fn apm_findings(a: &apm_partition_forensic::ApmAnalysis) -> Vec<Finding> {
    findings_of(&a.anomalies, "apm-partition-forensic", "APM")
}

/// Provenance breadcrumbs from an MBR analysis.
#[must_use]
pub fn mbr_provenance(a: &mbr_partition_forensic::MbrAnalysis) -> Vec<Provenance> {
    vec![
        Provenance {
            label: "boot code".to_string(),
            value: format!("{:?}", a.boot_code_id),
            source: "mbr-partition-forensic".to_string(),
        },
        Provenance {
            label: "partitioning era".to_string(),
            value: format!("{:?}", a.era),
            source: "mbr-partition-forensic".to_string(),
        },
        Provenance {
            label: "disk signature".to_string(),
            value: format!("{:#010x}", a.disk_serial),
            source: "mbr-partition-forensic".to_string(),
        },
    ]
}

/// Provenance breadcrumbs from a GPT analysis.
#[must_use]
pub fn gpt_provenance(a: &gpt_partition_forensic::GptAnalysis) -> Vec<Provenance> {
    vec![
        Provenance {
            label: "disk GUID".to_string(),
            value: a.disk_guid.to_string(),
            source: "gpt-partition-forensic".to_string(),
        },
        Provenance {
            label: "sector size".to_string(),
            value: format!("{} bytes", a.sector_size),
            source: "gpt-partition-forensic".to_string(),
        },
        Provenance {
            label: "GPT SHA-256".to_string(),
            value: a.gpt_sha256.clone(),
            source: "gpt-partition-forensic".to_string(),
        },
    ]
}

/// Provenance breadcrumbs from an APM analysis.
#[must_use]
pub fn apm_provenance(a: &apm_partition_forensic::ApmAnalysis) -> Vec<Provenance> {
    vec![
        Provenance {
            label: "block size".to_string(),
            value: format!("{} bytes", a.block_size),
            source: "apm-partition-forensic".to_string(),
        },
        Provenance {
            label: "device blocks".to_string(),
            value: a.device_block_count.to_string(),
            source: "apm-partition-forensic".to_string(),
        },
    ]
}

/// Normalize an ISO 9660 analysis into findings via the shared [`Observation`]
/// trait (iso9660-forensic 0.5.0 onward re-exports `report::Severity` and
/// implements `Observation`, like the rest of the fleet).
#[must_use]
pub fn iso_findings(a: &iso9660_forensic::IsoAnalysis) -> Vec<Finding> {
    findings_of(&a.anomalies, "iso9660-forensic", "ISO 9660")
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
