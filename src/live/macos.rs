//! macOS live-device backend (IOKit `IOMedia` registry) — implementation pending.

use super::{Error, PhysicalDisk};

pub(super) fn enumerate() -> Result<Vec<PhysicalDisk>, Error> {
    Err(Error::Os("macOS backend not yet implemented".into()))
}
