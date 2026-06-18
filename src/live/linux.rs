//! Linux live-device backend (sysfs `/sys/block` walk) — implementation pending.

use super::{Error, PhysicalDisk};

pub(super) fn enumerate() -> Result<Vec<PhysicalDisk>, Error> {
    Err(Error::Os("Linux backend not yet implemented".into()))
}
