//! Linux live-device backend — the `/sys/block` sysfs walk.
//!
//! Pure file I/O only: gather each whole disk's `/sys/block/<disk>` attribute
//! files and its partition child directories into raw strings, read
//! `/proc/mounts`, and hand both to the host-independent [`super::sysfs::build`].
//! All sizing/grouping logic — and its tests — live in `sysfs`. Enumeration is
//! unprivileged (sysfs is world-readable); only reading a device for analysis
//! needs root.

use std::fs;
use std::path::Path;

use super::sysfs::{self, RawDisk, RawPart};
use super::{Error, PhysicalDisk};

/// Purely virtual block devices that are never imaging targets.
fn is_virtual(name: &str) -> bool {
    name.starts_with("ram") || name.starts_with("zram")
}

pub(super) fn enumerate() -> Result<Vec<PhysicalDisk>, Error> {
    let block = Path::new("/sys/block");
    let mut raw = Vec::new();

    for entry in fs::read_dir(block)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if is_virtual(&name) {
            continue;
        }
        let base = entry.path();
        let read = |rel: &str| fs::read_to_string(base.join(rel)).unwrap_or_default();

        let mut partitions = Vec::new();
        for sub in fs::read_dir(&base)? {
            let sub = sub?;
            let pname = sub.file_name().to_string_lossy().into_owned();
            // A partition is a child dir named after the disk that carries a
            // `partition` file (distinguishes it from `queue/`, `device/`, etc.).
            if !pname.starts_with(&name) {
                continue;
            }
            let ppath = sub.path();
            if !ppath.join("partition").exists() {
                continue;
            }
            partitions.push(RawPart {
                name: pname,
                size: fs::read_to_string(ppath.join("size")).unwrap_or_default(),
                start: fs::read_to_string(ppath.join("start")).unwrap_or_default(),
            });
        }

        raw.push(RawDisk {
            name,
            size: read("size"),
            removable: read("removable"),
            ro: read("ro"),
            logical: read("queue/logical_block_size"),
            physical: read("queue/physical_block_size"),
            model: fs::read_to_string(base.join("device/model")).ok(),
            partitions,
        });
    }

    let mounts = fs::read_to_string("/proc/mounts").unwrap_or_default();
    Ok(sysfs::build(raw, &mounts))
}
