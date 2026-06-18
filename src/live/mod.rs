//! Live-system block-device enumeration — list the physical disks and their
//! partitions on the *running host*, in one unified model across macOS, Linux,
//! and Windows. This is the `disk4n6 list` counterpart to image analysis: where
//! [`crate::analyse_disk`] inspects an evidence file, [`enumerate`] inspects the
//! machine you are sitting at, the way `diskutil list`, `lsblk`, and `diskpart`
//! do — but with a single output shape regardless of platform.
//!
//! Discovery is the only OS-specific part. Each backend (sysfs on Linux, the
//! IOKit `IOMedia` registry on macOS, `DeviceIoControl` on Windows) fills the
//! same [`PhysicalDisk`]/[`Partition`] structs; everything downstream — the
//! [`render_disks`] table, the JSON form, and feeding a chosen device node back
//! into [`crate::analyse_disk`] — is platform-agnostic.
//!
//! Listing layout/metadata works **unprivileged** on all three platforms (it
//! reads the kernel's device registry, not raw sectors); only *reading a device*
//! for analysis needs root/Administrator. Backends therefore never silently
//! return an empty list on a permission problem — they surface [`Error`].

use core::fmt::Write as _;

mod bar;
pub use bar::render_disk_bar;

#[cfg(target_os = "linux")]
mod linux;
#[cfg(target_os = "macos")]
mod macos;
#[cfg(windows)]
mod windows;

/// A whole physical (or, on macOS, synthesized) disk on the live system.
///
/// `size_bytes` and the sector sizes come from the OS/driver layer, not from the
/// on-disk partition table — only the kernel knows the device's true geometry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct PhysicalDisk {
    /// OS path to open for raw access (`/dev/disk0`, `/dev/sda`,
    /// `\\.\PhysicalDrive0`).
    pub device_path: String,
    /// Short kernel identifier (`disk0`, `sda`, `PhysicalDrive0`).
    pub name: String,
    /// Total device size in bytes, as reported by the driver.
    pub size_bytes: u64,
    /// Smallest addressable I/O unit (logical sector), in bytes.
    pub logical_sector_size: u32,
    /// Physical sector size in bytes (4096 on 4Kn/512e media; may exceed
    /// `logical_sector_size`).
    pub physical_sector_size: u32,
    /// Device model string, when the driver exposes one.
    pub model: Option<String>,
    /// Device serial number, when the driver exposes one.
    pub serial: Option<String>,
    /// Removable media (USB stick, SD card, optical).
    pub removable: bool,
    /// Device is write-protected / read-only at the driver level.
    pub read_only: bool,
    /// Not a backing physical device but a kernel-synthesized one (macOS APFS
    /// container, Linux device-mapper/LVM). Real evidence imaging targets the
    /// backing physical disk; synthesized disks are shown for completeness.
    pub synthesized: bool,
    /// Partitions/slices carved out of this disk, in on-disk order.
    pub partitions: Vec<Partition>,
}

/// A partition (slice/volume) within a [`PhysicalDisk`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Partition {
    /// OS path to open for raw access to just this partition.
    pub device_path: String,
    /// Short kernel identifier (`disk0s1`, `sda1`, `nvme0n1p1`).
    pub name: String,
    /// Byte offset of the partition's first sector from the start of the disk.
    pub start_offset: u64,
    /// Partition length in bytes.
    pub size_bytes: u64,
    /// Partition type as the OS names it (GPT type GUID/name, MBR type byte, or
    /// platform content hint), when known.
    pub partition_type: Option<String>,
    /// Current mount point, when the partition is mounted.
    pub mount_point: Option<String>,
    /// Mounted filesystem type, when known.
    pub filesystem: Option<String>,
    /// Volume label, when known.
    pub label: Option<String>,
}

/// Failure enumerating live devices.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Live enumeration has no backend for this target OS.
    #[error("live device enumeration is not supported on this platform")]
    Unsupported,
    /// An I/O error while reading the OS device registry.
    #[error("I/O error enumerating devices: {0}")]
    Io(#[from] std::io::Error),
    /// The platform enumeration API returned an error.
    #[error("device enumeration failed: {0}")]
    Os(String),
}

/// Enumerate every physical disk on the live system, each with its partitions.
///
/// Dispatches to the platform backend. The list is best-effort complete: a disk
/// whose details cannot be read is still listed with whatever the OS provided.
///
/// # Errors
/// [`Error::Unsupported`] on a target without a backend, [`Error::Io`] /
/// [`Error::Os`] when the OS device registry cannot be read.
pub fn enumerate() -> Result<Vec<PhysicalDisk>, Error> {
    #[cfg(target_os = "linux")]
    {
        linux::enumerate()
    }
    #[cfg(target_os = "macos")]
    {
        macos::enumerate()
    }
    #[cfg(windows)]
    {
        windows::enumerate()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
    {
        Err(Error::Unsupported)
    }
}

/// Format a byte count the way disk utilities do — decimal (SI) units with one
/// fractional digit (`4.0 TB`, `524.3 MB`, `24.6 KB`), matching `diskutil`/
/// `lsblk` so output is recognisable. Bytes under 1000 render as `N B`.
#[must_use]
pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    if bytes < 1000 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// Render the enumerated disks as a unified, indented text table — the
/// `disk4n6 list` human view. Whole disks are flush-left; their partitions are
/// indented beneath them, so the layout reads the same on every platform.
#[must_use]
pub fn render_disks(disks: &[PhysicalDisk]) -> String {
    let mut s = String::new();
    if disks.is_empty() {
        s.push_str("No disks found.\n");
        return s;
    }
    let _ = writeln!(s, "{:<14} {:>10}  {:<6} {}", "NAME", "SIZE", "TYPE", "INFO");
    for d in disks {
        let kind = if d.synthesized { "synth" } else { "disk" };
        let mut info = d.model.clone().unwrap_or_default();
        if d.removable {
            info = if info.is_empty() {
                "removable".to_string()
            } else {
                format!("{info} (removable)")
            };
        }
        let _ = writeln!(
            s,
            "{:<14} {:>10}  {:<6} {}",
            d.name,
            human_size(d.size_bytes),
            kind,
            info.trim()
        );
        for p in &d.partitions {
            let indented = format!("  {}", p.name);
            let _ = writeln!(
                s,
                "{:<14} {:>10}  {:<6} {}",
                indented,
                human_size(p.size_bytes),
                "part",
                partition_info(p)
            );
        }
    }
    s
}

/// The trailing description column for a partition row: type, then mount point
/// and label when present (`Apple_APFS  /Volumes/Data [DATA]`).
fn partition_info(p: &Partition) -> String {
    let mut parts: Vec<String> = Vec::new();
    if let Some(t) = &p.partition_type {
        parts.push(t.clone());
    }
    if let Some(m) = &p.mount_point {
        parts.push(m.clone());
    }
    if let Some(l) = &p.label {
        parts.push(format!("[{l}]"));
    }
    parts.join("  ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_disk() -> PhysicalDisk {
        PhysicalDisk {
            device_path: "/dev/disk0".into(),
            name: "disk0".into(),
            size_bytes: 4_000_000_000_000,
            logical_sector_size: 512,
            physical_sector_size: 4096,
            model: Some("APPLE SSD AP4096".into()),
            serial: None,
            removable: false,
            read_only: false,
            synthesized: false,
            partitions: vec![Partition {
                device_path: "/dev/disk0s1".into(),
                name: "disk0s1".into(),
                start_offset: 20480,
                size_bytes: 524_300_000,
                partition_type: Some("Apple_APFS_ISC".into()),
                mount_point: None,
                filesystem: None,
                label: None,
            }],
        }
    }

    #[test]
    fn human_size_matches_decimal_units() {
        assert_eq!(human_size(512), "512 B");
        assert_eq!(human_size(999), "999 B");
        assert_eq!(human_size(1000), "1.0 KB");
        assert_eq!(human_size(24_576), "24.6 KB");
        assert_eq!(human_size(524_300_000), "524.3 MB");
        assert_eq!(human_size(5_400_000_000), "5.4 GB");
        assert_eq!(human_size(4_000_000_000_000), "4.0 TB");
    }

    #[test]
    fn render_disks_shows_disk_then_indented_partitions() {
        let out = render_disks(&[sample_disk()]);
        assert!(out.contains("NAME"));
        assert!(out.contains("disk0"));
        assert!(out.contains("4.0 TB"));
        assert!(out.contains("APPLE SSD AP4096"));
        // The partition is indented and tagged `part` with its type.
        assert!(out.contains("  disk0s1"));
        assert!(out.contains("Apple_APFS_ISC"));
        let disk_line = out.lines().find(|l| l.contains("disk0 ")).unwrap();
        assert!(disk_line.contains("disk"));
    }

    #[test]
    fn render_disks_empty_is_explicit() {
        assert_eq!(render_disks(&[]), "No disks found.\n");
    }

    #[test]
    fn partition_info_joins_type_mount_label() {
        let p = Partition {
            device_path: "/dev/disk0s2".into(),
            name: "disk0s2".into(),
            start_offset: 0,
            size_bytes: 1,
            partition_type: Some("Apple_APFS".into()),
            mount_point: Some("/Volumes/Data".into()),
            label: Some("DATA".into()),
            filesystem: None,
        };
        assert_eq!(partition_info(&p), "Apple_APFS  /Volumes/Data  [DATA]");
    }

    #[test]
    fn removable_flag_annotates_info() {
        let mut d = sample_disk();
        d.model = None;
        d.removable = true;
        let out = render_disks(&[d]);
        assert!(out.contains("removable"));
    }
}
