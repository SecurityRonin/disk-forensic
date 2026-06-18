//! macOS live-device backend — the IOKit `IOMedia` registry.
//!
//! `IOServiceGetMatchingServices("IOMedia")` yields every whole disk *and*
//! partition the kernel knows about (physical and APFS-synthesized alike), each
//! carrying CF properties: `Size`, `Preferred Block Size`, `Base` (byte offset
//! within its whole disk), `Whole`, `Removable`, `Writable`, `Content`
//! (partition type), and `BSD Name`. We read those into flat [`RawMedia`]
//! records, then [`assemble`] groups partitions under their whole disks by BSD
//! name (`disk0s2` → `disk0`).
//!
//! Only [`collect_media`] touches FFI; [`assemble`] is pure and unit-tested.
//! Enumeration is unprivileged — IOKit answers without root.
#![allow(
    unsafe_code,
    reason = "IOKit/CoreFoundation FFI is inherently unsafe; isolated to collect_media + read_media, each call annotated with SAFETY"
)]

use std::ffi::CString;

use super::{Error, Partition, PhysicalDisk};
use core_foundation::base::{CFType, TCFType};
use core_foundation::boolean::CFBoolean;
use core_foundation::dictionary::CFDictionary;
use core_foundation::number::CFNumber;
use core_foundation::string::CFString;
use core_foundation_sys::base::kCFAllocatorDefault;
use core_foundation_sys::dictionary::{CFDictionaryRef, CFMutableDictionaryRef};
use io_kit_sys::types::{io_object_t, io_registry_entry_t};
use io_kit_sys::{
    kIOMasterPortDefault, IOIteratorNext, IOObjectCopyClass, IOObjectRelease,
    IORegistryEntryCreateCFProperties, IOServiceGetMatchingServices, IOServiceMatching,
};

/// `kern_return_t` success sentinel (`KERN_SUCCESS`), avoiding a direct `mach2`
/// dependency for the single constant we need.
const KERN_SUCCESS: i32 = 0;

/// One `IOMedia` registry node, flattened from its CF property dictionary.
#[derive(Debug, Clone, PartialEq, Eq)]
struct RawMedia {
    /// `BSD Name` — `disk0`, `disk0s1`.
    bsd: String,
    /// `Size` in bytes.
    size: u64,
    /// `Preferred Block Size` — the device's logical sector size.
    block: u32,
    /// `Base` — byte offset of this media within its whole disk.
    base: u64,
    /// `Whole` — true for a whole disk, false for a partition.
    whole: bool,
    /// `Removable`.
    removable: bool,
    /// `Writable` — read-only is its negation.
    writable: bool,
    /// `Content` — partition type (`Apple_APFS`, `EFI`, a GPT type GUID…).
    content: String,
    /// IOKit class name; `AppleAPFS*` marks a synthesized (non-physical) disk.
    class: String,
}

pub(super) fn enumerate() -> Result<Vec<PhysicalDisk>, Error> {
    Ok(assemble(collect_media()?))
}

/// Group flat [`RawMedia`] into whole disks each owning their partitions.
///
/// Partitions attach to the whole disk named by the leading `diskN` of their BSD
/// name; disks are ordered by their numeric index and partitions by on-disk
/// offset. Pure — the unit tests exercise this without IOKit.
fn assemble(media: Vec<RawMedia>) -> Vec<PhysicalDisk> {
    let mut disks: Vec<PhysicalDisk> = media
        .iter()
        .filter(|m| m.whole)
        .map(|m| PhysicalDisk {
            device_path: format!("/dev/{}", m.bsd),
            name: m.bsd.clone(),
            size_bytes: m.size,
            logical_sector_size: m.block,
            physical_sector_size: m.block,
            model: None,
            serial: None,
            removable: m.removable,
            read_only: !m.writable,
            synthesized: m.class.starts_with("AppleAPFS"),
            partitions: Vec::new(),
        })
        .collect();

    for m in media.iter().filter(|m| !m.whole) {
        let parent = whole_disk_of(&m.bsd);
        if let Some(d) = disks.iter_mut().find(|d| d.name == parent) {
            d.partitions.push(Partition {
                device_path: format!("/dev/{}", m.bsd),
                name: m.bsd.clone(),
                start_offset: m.base,
                size_bytes: m.size,
                partition_type: (!m.content.is_empty()).then(|| m.content.clone()),
                mount_point: None,
                filesystem: None,
                label: None,
            });
        }
    }

    for d in &mut disks {
        d.partitions.sort_by_key(|p| p.start_offset);
    }
    disks.sort_by_key(|d| disk_index(&d.name));
    disks
}

/// The whole-disk BSD name owning a partition: `disk3s1s1` → `disk3`.
fn whole_disk_of(bsd: &str) -> String {
    let rest = bsd.strip_prefix("disk").unwrap_or(bsd);
    let num: String = rest.chars().take_while(char::is_ascii_digit).collect();
    format!("disk{num}")
}

/// Numeric index from a `diskN` name, for ordering (`disk10` after `disk2`).
fn disk_index(name: &str) -> u64 {
    name.strip_prefix("disk")
        .and_then(|n| n.parse().ok())
        .unwrap_or(u64::MAX)
}

/// Walk the `IOMedia` registry into flat [`RawMedia`] records (FFI shell).
fn collect_media() -> Result<Vec<RawMedia>, Error> {
    let class = CString::new("IOMedia").expect("static string has no NUL");
    let mut out = Vec::new();
    // SAFETY: `class` is a valid NUL-terminated C string for the duration of the
    // call; IOServiceMatching copies it. The returned dictionary is consumed by
    // IOServiceGetMatchingServices (it releases the reference), so we must not.
    unsafe {
        let matching = IOServiceMatching(class.as_ptr());
        if matching.is_null() {
            return Err(Error::Os("IOServiceMatching(IOMedia) returned null".into()));
        }
        let mut iter: io_object_t = 0;
        let kr = IOServiceGetMatchingServices(kIOMasterPortDefault, matching.cast(), &mut iter);
        if kr != KERN_SUCCESS {
            return Err(Error::Os(format!(
                "IOServiceGetMatchingServices failed (kern_return {kr})"
            )));
        }
        loop {
            let entry = IOIteratorNext(iter);
            if entry == 0 {
                break;
            }
            if let Some(m) = read_media(entry) {
                out.push(m);
            }
            // SAFETY: `entry` is a live object handle from the iterator.
            IOObjectRelease(entry);
        }
        // SAFETY: `iter` is a live iterator handle.
        IOObjectRelease(iter);
    }
    Ok(out)
}

/// Read one registry entry's CF properties into a [`RawMedia`] (FFI shell).
unsafe fn read_media(entry: io_registry_entry_t) -> Option<RawMedia> {
    let mut props: CFMutableDictionaryRef = core::ptr::null_mut();
    // SAFETY: `entry` is live; `props` receives an owned (create-rule) dict ref.
    let kr = IORegistryEntryCreateCFProperties(entry, &mut props, kCFAllocatorDefault, 0);
    if kr != KERN_SUCCESS || props.is_null() {
        return None;
    }
    // SAFETY: create rule — we take ownership of the dict from CoreFoundation.
    let dict: CFDictionary<CFString, CFType> =
        CFDictionary::wrap_under_create_rule(props as CFDictionaryRef);

    let bsd = dict_string(&dict, "BSD Name")?;
    let class_ref = IOObjectCopyClass(entry);
    let class = if class_ref.is_null() {
        String::new()
    } else {
        // SAFETY: create rule — IOObjectCopyClass returns an owned CFString.
        CFString::wrap_under_create_rule(class_ref).to_string()
    };

    Some(RawMedia {
        bsd,
        size: dict_i64(&dict, "Size").unwrap_or(0).max(0) as u64,
        block: dict_i64(&dict, "Preferred Block Size")
            .unwrap_or(512)
            .max(1) as u32,
        base: dict_i64(&dict, "Base").unwrap_or(0).max(0) as u64,
        whole: dict_bool(&dict, "Whole").unwrap_or(false),
        removable: dict_bool(&dict, "Removable").unwrap_or(false),
        writable: dict_bool(&dict, "Writable").unwrap_or(true),
        content: dict_string(&dict, "Content").unwrap_or_default(),
        class,
    })
}

fn dict_i64(d: &CFDictionary<CFString, CFType>, key: &str) -> Option<i64> {
    d.find(CFString::new(key))
        .and_then(|v| v.downcast::<CFNumber>())
        .and_then(|n| n.to_i64())
}

fn dict_bool(d: &CFDictionary<CFString, CFType>, key: &str) -> Option<bool> {
    d.find(CFString::new(key))
        .and_then(|v| v.downcast::<CFBoolean>())
        .map(bool::from)
}

fn dict_string(d: &CFDictionary<CFString, CFType>, key: &str) -> Option<String> {
    d.find(CFString::new(key))
        .and_then(|v| v.downcast::<CFString>())
        .map(|s| s.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn whole(bsd: &str, size: u64, removable: bool, class: &str) -> RawMedia {
        RawMedia {
            bsd: bsd.into(),
            size,
            block: 512,
            base: 0,
            whole: true,
            removable,
            writable: true,
            content: String::new(),
            class: class.into(),
        }
    }

    fn part(bsd: &str, base: u64, size: u64, content: &str) -> RawMedia {
        RawMedia {
            bsd: bsd.into(),
            size,
            block: 512,
            base,
            whole: false,
            removable: false,
            writable: true,
            content: content.into(),
            class: "IOMedia".into(),
        }
    }

    #[test]
    fn assemble_groups_partitions_under_whole_disks() {
        // Mirrors the `diskutil list` oracle: disk0 (GPT, 3 parts), disk4 (bare),
        // disk5 (GPT, 1 part) — deliberately out of order to test sorting.
        let media = vec![
            part("disk0s2", 600_000_000, 3_990_000_000_000, "Apple_APFS"),
            whole("disk5", 8_000_000_000_000, true, "IOMedia"),
            part("disk0s1", 20480, 524_300_000, "Apple_APFS_ISC"),
            whole("disk0", 4_000_000_000_000, false, "IOMedia"),
            part("disk5s1", 20480, 8_000_000_000_000, "Microsoft Basic Data"),
            part(
                "disk0s3",
                3_990_600_000_000,
                5_400_000_000,
                "Apple_APFS_Recovery",
            ),
            whole("disk4", 2_000_000_000_000, true, "IOMedia"),
        ];
        let disks = assemble(media);

        // Ordered disk0, disk4, disk5.
        assert_eq!(
            disks.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
            ["disk0", "disk4", "disk5"]
        );
        let disk0 = &disks[0];
        assert_eq!(disk0.partitions.len(), 3);
        // Partitions sorted by start offset → s1, s2, s3.
        assert_eq!(
            disk0
                .partitions
                .iter()
                .map(|p| p.name.as_str())
                .collect::<Vec<_>>(),
            ["disk0s1", "disk0s2", "disk0s3"]
        );
        assert_eq!(
            disk0.partitions[0].partition_type.as_deref(),
            Some("Apple_APFS_ISC")
        );
        assert_eq!(disk0.device_path, "/dev/disk0");
        assert!(!disk0.removable);
        // disk4 is a bare whole disk with no partitions.
        assert!(disks[1].partitions.is_empty());
        assert!(disks[1].removable);
        // disk5 has its one partition.
        assert_eq!(disks[2].partitions.len(), 1);
    }

    #[test]
    fn assemble_flags_synthesized_apfs_disks() {
        let media = vec![
            whole("disk0", 4_000_000_000_000, false, "IOMedia"),
            whole("disk3", 4_000_000_000_000, false, "AppleAPFSMedia"),
        ];
        let disks = assemble(media);
        assert!(!disks[0].synthesized, "physical disk0");
        assert!(disks[1].synthesized, "synthesized disk3");
    }

    #[test]
    fn assemble_read_only_from_writable_flag() {
        let mut m = whole("disk9", 1_000_000, false, "IOMedia");
        m.writable = false;
        let disks = assemble(vec![m]);
        assert!(disks[0].read_only);
    }

    #[test]
    fn whole_disk_of_strips_partition_suffix() {
        assert_eq!(whole_disk_of("disk0s2"), "disk0");
        assert_eq!(whole_disk_of("disk3s3s1"), "disk3");
        assert_eq!(whole_disk_of("disk10s1"), "disk10");
        assert_eq!(whole_disk_of("disk7"), "disk7");
    }

    #[test]
    fn empty_content_becomes_none_partition_type() {
        let disks = assemble(vec![
            whole("disk0", 100, false, "IOMedia"),
            part("disk0s1", 0, 100, ""),
        ]);
        assert_eq!(disks[0].partitions[0].partition_type, None);
    }
}
