//! Windows live-device backend (`DeviceIoControl`) — implementation pending.

use super::{Error, PhysicalDisk};

pub(super) fn enumerate() -> Result<Vec<PhysicalDisk>, Error> {
    Err(Error::Os("Windows backend not yet implemented".into()))
}
