//! Windows live-device backend — `DeviceIoControl` over `\\.\PhysicalDriveN`.
//!
//! Probe `\\.\PhysicalDrive0..` ; for each handle query total length
//! (`IOCTL_DISK_GET_LENGTH_INFO`), sector size
//! (`IOCTL_DISK_GET_DRIVE_GEOMETRY_EX`), and the partition table
//! (`IOCTL_DISK_GET_DRIVE_LAYOUT_EX`), then decode the layout bytes with the
//! tested [`super::drive_layout::parse_drive_layout`]. Only the FFI lives here;
//! the byte parsing and its tests are host-independent.
//!
//! Unlike Linux/macOS, opening a physical drive for the layout IOCTL needs
//! **read access**, i.e. an elevated (Administrator) token — the same
//! requirement as `diskpart`. Without it we fail loud rather than report an
//! empty machine.
#![allow(
    unsafe_code,
    reason = "Win32 DeviceIoControl/CreateFileW FFI is inherently unsafe; isolated to this backend with per-call SAFETY notes"
)]

use std::ptr;

use windows_sys::Win32::Foundation::{
    CloseHandle, GetLastError, ERROR_ACCESS_DENIED, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
    GENERIC_READ, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateFileW, FILE_SHARE_READ, FILE_SHARE_WRITE, OPEN_EXISTING,
};
use windows_sys::Win32::System::Ioctl::{
    IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, IOCTL_DISK_GET_LENGTH_INFO,
};
use windows_sys::Win32::System::IO::DeviceIoControl;

use super::drive_layout::parse_drive_layout;
use super::{Error, Partition, PhysicalDisk};

/// Upper bound on `\\.\PhysicalDriveN` indices to probe.
const MAX_DRIVES: u32 = 64;
/// Generous layout buffer — enough for a 128-entry GPT (48 + 128*144 ≈ 18 KiB).
const LAYOUT_BUF: usize = 32 * 1024;
/// `BytesPerSector` offset within `DISK_GEOMETRY_EX`.
const GEOMETRY_BYTES_PER_SECTOR: usize = 20;

pub(super) fn enumerate() -> Result<Vec<PhysicalDisk>, Error> {
    let mut disks = Vec::new();
    let mut access_denied = false;

    for n in 0..MAX_DRIVES {
        let path = wide(&format!(r"\\.\PhysicalDrive{n}"));
        // SAFETY: `path` is a valid NUL-terminated wide string; all pointer
        // arguments are either it or null, as CreateFileW permits.
        let handle = unsafe {
            CreateFileW(
                path.as_ptr(),
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                ptr::null(),
                OPEN_EXISTING,
                0,
                ptr::null_mut(),
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            // SAFETY: GetLastError reads thread-local state; always sound.
            match unsafe { GetLastError() } {
                ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND => {}
                ERROR_ACCESS_DENIED => access_denied = true,
                _ => {}
            }
            continue;
        }
        if let Some(disk) = read_disk(handle, n) {
            disks.push(disk);
        }
        // SAFETY: `handle` is a live handle we opened above.
        unsafe { CloseHandle(handle) };
    }

    if disks.is_empty() && access_denied {
        return Err(Error::Os(
            "access denied opening \\\\.\\PhysicalDrive* — run as Administrator".into(),
        ));
    }
    disks.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(disks)
}

/// Query one open physical-drive handle into a [`PhysicalDisk`].
fn read_disk(handle: HANDLE, index: u32) -> Option<PhysicalDisk> {
    let mut len_buf = [0u8; 8];
    let size_bytes = if ioctl(handle, IOCTL_DISK_GET_LENGTH_INFO, &mut len_buf).is_some() {
        i64::from_le_bytes(len_buf).max(0) as u64
    } else {
        0
    };

    let mut geo = [0u8; 32];
    let sector = if ioctl(handle, IOCTL_DISK_GET_DRIVE_GEOMETRY_EX, &mut geo).is_some() {
        u32::from_le_bytes([
            geo[GEOMETRY_BYTES_PER_SECTOR],
            geo[GEOMETRY_BYTES_PER_SECTOR + 1],
            geo[GEOMETRY_BYTES_PER_SECTOR + 2],
            geo[GEOMETRY_BYTES_PER_SECTOR + 3],
        ])
    } else {
        0
    };
    let sector = if sector == 0 { 512 } else { sector };

    let mut layout_buf = vec![0u8; LAYOUT_BUF];
    let parsed = match ioctl(handle, IOCTL_DISK_GET_DRIVE_LAYOUT_EX, &mut layout_buf) {
        Some(_) => parse_drive_layout(&layout_buf),
        None => return None,
    };

    let name = format!("PhysicalDrive{index}");
    let device_path = format!(r"\\.\PhysicalDrive{index}");
    let mut partitions: Vec<Partition> = parsed
        .partitions
        .iter()
        .map(|p| Partition {
            device_path: device_path.clone(),
            name: format!("{name}p{}", p.number),
            start_offset: p.start_offset,
            size_bytes: p.length,
            partition_type: p.type_desc.clone(),
            mount_point: None,
            filesystem: None,
            label: p.name.clone(),
        })
        .collect();
    partitions.sort_by_key(|p| p.start_offset);

    Some(PhysicalDisk {
        device_path,
        name,
        size_bytes,
        logical_sector_size: sector,
        physical_sector_size: sector,
        model: None,
        serial: None,
        removable: false,
        read_only: false,
        synthesized: false,
        partitions,
    })
}

/// Issue a no-input `DeviceIoControl`, returning the bytes written on success.
fn ioctl(handle: HANDLE, code: u32, out: &mut [u8]) -> Option<u32> {
    let mut returned: u32 = 0;
    // SAFETY: `handle` is live; `out` is a valid writable buffer of the stated
    // length; the input pointer is null with zero length, as this IOCTL allows.
    let ok = unsafe {
        DeviceIoControl(
            handle,
            code,
            ptr::null(),
            0,
            out.as_mut_ptr().cast(),
            out.len() as u32,
            &mut returned,
            ptr::null_mut(),
        )
    };
    (ok != 0).then_some(returned)
}

/// A NUL-terminated UTF-16 copy of `s` for the `*W` Win32 APIs.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}
