//! Pure parsing for the Linux sysfs backend — turning the raw text of
//! `/sys/block/*` files and `/proc/mounts` into the unified model.
//!
//! sysfs reports every size in **512-byte sectors** (the kernel ABI fixes the
//! unit at 512 regardless of the device's logical block size), so byte sizes are
//! `value * 512`. The file/dir walk that gathers these strings lives in the
//! Linux-gated `linux` module; everything here is pure and host-independent so
//! the tests run on any platform.

use super::{Partition, PhysicalDisk};

/// sysfs's fixed sector unit for `size`/`start` values, in bytes.
const SYSFS_SECTOR: u64 = 512;

/// Raw `/sys/block/<disk>` file contents for one whole disk (un-parsed).
pub(super) struct RawDisk {
    /// Kernel name (`sda`, `nvme0n1`).
    pub name: String,
    /// `size` — disk size in 512-byte sectors.
    pub size: String,
    /// `removable` — `1`/`0`.
    pub removable: String,
    /// `ro` — read-only flag, `1`/`0`.
    pub ro: String,
    /// `queue/logical_block_size`.
    pub logical: String,
    /// `queue/physical_block_size`.
    pub physical: String,
    /// `device/model`, when present.
    pub model: Option<String>,
    /// Partition child directories.
    pub partitions: Vec<RawPart>,
}

/// Raw `/sys/block/<disk>/<part>` file contents for one partition.
pub(super) struct RawPart {
    /// Kernel name (`sda1`, `nvme0n1p1`).
    pub name: String,
    /// `size` — partition size in 512-byte sectors.
    pub size: String,
    /// `start` — first sector offset in 512-byte sectors.
    pub start: String,
}

/// Parse `/proc/mounts` into `(device, mountpoint, fstype)` for `/dev/*` mounts
/// only (device name with the `/dev/` prefix stripped). Mount-point octal
/// escapes (`\040` → space) are decoded.
pub(super) fn parse_mounts(content: &str) -> Vec<(String, String, String)> {
    unimplemented!("RED: parse_mounts")
}

/// Build the unified disk model from raw sysfs strings and `/proc/mounts`.
pub(super) fn build(disks: Vec<RawDisk>, mounts_content: &str) -> Vec<PhysicalDisk> {
    unimplemented!("RED: build")
}

/// Trim and parse a sysfs integer file, defaulting to 0 on any garbage.
fn parse_u64(s: &str) -> u64 {
    s.trim().parse().unwrap_or(0)
}

/// Decode mount-point octal escapes used in `/proc/mounts` (`\040`, `\011`,
/// `\012`, `\134`).
fn decode_octal(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\\' {
            let digits: String = chars.clone().take(3).collect();
            if digits.len() == 3 && digits.chars().all(|d| ('0'..='7').contains(&d)) {
                if let Ok(byte) = u8::from_str_radix(&digits, 8) {
                    out.push(byte as char);
                    for _ in 0..3 {
                        chars.next();
                    }
                    continue;
                }
            }
        }
        out.push(c);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rd(name: &str, size: &str, parts: Vec<RawPart>) -> RawDisk {
        RawDisk {
            name: name.into(),
            size: size.into(),
            removable: "0".into(),
            ro: "0".into(),
            logical: "512".into(),
            physical: "4096".into(),
            model: Some("  Samsung SSD 990  ".into()),
            partitions: parts,
        }
    }
    fn rp(name: &str, start: &str, size: &str) -> RawPart {
        RawPart {
            name: name.into(),
            start: start.into(),
            size: size.into(),
        }
    }

    #[test]
    fn parse_mounts_keeps_dev_mounts_and_decodes_spaces() {
        let content = "\
sysfs /sys sysfs rw 0 0
/dev/sda1 / ext4 rw 0 0
proc /proc proc rw 0 0
/dev/sdb1 /mnt/my\\040disk xfs rw 0 0
";
        let m = parse_mounts(content);
        assert_eq!(
            m,
            vec![
                ("sda1".into(), "/".into(), "ext4".into()),
                ("sdb1".into(), "/mnt/my disk".into(), "xfs".into()),
            ]
        );
    }

    #[test]
    fn build_converts_sectors_to_bytes_and_attaches_mounts() {
        // 2048-sector disk = 1 MiB; one partition starting at sector 2048.
        let disks = vec![rd("sda", "2048", vec![rp("sda1", "2048", "1024")])];
        let out = build(disks, "/dev/sda1 /boot vfat rw 0 0\n");
        assert_eq!(out.len(), 1);
        let d = &out[0];
        assert_eq!(d.device_path, "/dev/sda");
        assert_eq!(d.size_bytes, 2048 * 512);
        assert_eq!(d.logical_sector_size, 512);
        assert_eq!(d.physical_sector_size, 4096);
        assert_eq!(d.model.as_deref(), Some("Samsung SSD 990")); // trimmed
        assert_eq!(d.partitions.len(), 1);
        let p = &d.partitions[0];
        assert_eq!(p.start_offset, 2048 * 512);
        assert_eq!(p.size_bytes, 1024 * 512);
        assert_eq!(p.mount_point.as_deref(), Some("/boot"));
        assert_eq!(p.filesystem.as_deref(), Some("vfat"));
    }

    #[test]
    fn build_sorts_partitions_by_offset() {
        let disks = vec![rd(
            "nvme0n1",
            "100000",
            vec![
                rp("nvme0n1p2", "50000", "10"),
                rp("nvme0n1p1", "2048", "10"),
            ],
        )];
        let out = build(disks, "");
        let names: Vec<&str> = out[0].partitions.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, ["nvme0n1p1", "nvme0n1p2"]);
    }

    #[test]
    fn build_flags_removable_ro_and_dm_synthesized() {
        let mut d = rd("dm-0", "100", vec![]);
        d.removable = "1".into();
        d.ro = "1".into();
        let out = build(vec![d], "");
        assert!(out[0].removable);
        assert!(out[0].read_only);
        assert!(out[0].synthesized);
    }

    #[test]
    fn build_defaults_physical_to_logical_when_zero() {
        let mut d = rd("sda", "100", vec![]);
        d.physical = "0".into();
        d.logical = "512".into();
        let out = build(vec![d], "");
        assert_eq!(out[0].physical_sector_size, 512);
    }
}
