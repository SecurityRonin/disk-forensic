//! Bridge an analyzed image's [`DiskReport`] into the [`livedisk`] layout model,
//! so the proportional partition bar renders for evidence files (E01, VMDK, …)
//! exactly as it does for a live disk. This is presentation glue only — the
//! authoritative structural analysis stays in the per-scheme reports; here we
//! map partition extents (LBA × sector → byte offsets) onto the unified
//! [`PhysicalDisk`]/[`Partition`] shape `livedisk` already knows how to draw.

use livedisk::{Partition, PhysicalDisk};

use crate::DiskReport;

/// Convert a disk analysis into a [`PhysicalDisk`] for rendering. `name` labels
/// the disk (typically the image path) and `size_bytes` is the decoded media
/// size used for the bar's denominator and trailing free space.
#[must_use]
pub fn from_report(report: &DiskReport, name: &str, size_bytes: u64) -> PhysicalDisk {
    let (sector, partitions) = match report {
        DiskReport::Gpt(mbr) => gpt_partitions(mbr),
        DiskReport::Mbr(mbr) => mbr_partitions(mbr),
        DiskReport::Apm(apm) => apm_partitions(apm),
    };
    // The bar's denominator is the disk capacity. Use the decoded media size, but
    // never let it fall below the partitions' own extent — a truncated or sparse
    // image can be shorter than the layout its table declares.
    let extent = partitions
        .iter()
        .map(|p| p.start_offset + p.size_bytes)
        .max()
        .unwrap_or(0);
    PhysicalDisk {
        device_path: name.to_string(),
        name: name.to_string(),
        size_bytes: size_bytes.max(extent),
        logical_sector_size: sector,
        physical_sector_size: sector,
        model: None,
        serial: None,
        removable: false,
        read_only: false,
        synthesized: false,
        partitions,
    }
}

fn part(name: String, start: u64, size: u64, ty: String, label: Option<String>) -> Partition {
    Partition {
        device_path: String::new(),
        name,
        start_offset: start,
        size_bytes: size,
        partition_type: (!ty.is_empty()).then_some(ty),
        mount_point: None,
        filesystem: None,
        label,
    }
}

fn gpt_partitions(mbr: &mbr_partition_forensic::MbrAnalysis) -> (u32, Vec<Partition>) {
    let Some(gpt) = &mbr.gpt else {
        return (512, Vec::new());
    };
    let sector = gpt.sector_size;
    let parts = gpt
        .partitions
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let ty = p
                .type_name()
                .map_or_else(|| p.type_guid.to_string(), ToString::to_string);
            let label = (!p.name.is_empty()).then(|| p.name.clone());
            part(
                format!("part{}", i + 1),
                p.first_lba * sector,
                (p.last_lba - p.first_lba + 1) * sector,
                ty,
                label,
            )
        })
        .collect();
    (sector as u32, parts)
}

fn mbr_partitions(mbr: &mbr_partition_forensic::MbrAnalysis) -> (u32, Vec<Partition>) {
    const SECTOR: u64 = 512;
    let parts = mbr
        .partitions
        .iter()
        .map(|p| {
            part(
                format!("part{}", p.index),
                p.lba_start * SECTOR,
                (p.lba_end - p.lba_start + 1) * SECTOR,
                p.declared_type.name().to_string(),
                None,
            )
        })
        .collect();
    (SECTOR as u32, parts)
}

fn apm_partitions(apm: &apm_partition_forensic::ApmAnalysis) -> (u32, Vec<Partition>) {
    let bs = apm.block_size as u64;
    let parts = apm
        .partitions
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let name = if p.name.is_empty() {
                format!("part{}", i + 1)
            } else {
                p.name.clone()
            };
            part(
                name,
                p.start_block as u64 * bs,
                (p.end_block() as u64 - p.start_block as u64 + 1) * bs,
                p.type_name.clone(),
                None,
            )
        })
        .collect();
    (bs as u32, parts)
}
