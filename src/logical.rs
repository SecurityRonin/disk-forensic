//! Logical file containers — image formats that hold a *file tree*, not a raw
//! disk.
//!
//! Some forensic containers carry captured files rather than a block device:
//! AccessData **AD1** (FTK "Custom Content Image") and **AFF4-Logical**
//! (`aff4:FileImage` collections). They have no partition table or filesystem to
//! walk with the partition parsers, so they do not fit [`crate::container::open`]
//! (which yields a `Read + Seek` *disk* view). [`open`] is their home: it lists
//! entries (logical path + metadata) and reads a file's bytes.
//!
//! ```no_run
//! let mut img = disk_forensic::logical::open(std::path::Path::new("evidence.ad1"))?;
//! for e in img.entries() {
//!     println!("{} ({} bytes){}", e.path, e.size, if e.is_dir { " [dir]" } else { "" });
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

use std::fs::File;
use std::path::Path;

use crate::container::{sniff, ContainerFormat};

/// One entry in a logical container's file tree.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct LogicalEntry {
    /// Logical path as recorded in the image (`/`-separated).
    pub path: String,
    /// `true` for a directory node (no file data). AFF4-Logical carries only
    /// files, so its entries are always `false`.
    pub is_dir: bool,
    /// Uncompressed content length in bytes (`0` for directories).
    pub size: u64,
}

/// Failure opening or reading a logical container.
#[derive(Debug, thiserror::Error)]
pub enum LogicalError {
    /// I/O failure opening or reading the file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The file is not a logical container this module handles (e.g. it is a raw
    /// disk image or a *physical* AFF4 — open those with
    /// [`crate::container::open`]). The message names the sniffed format.
    #[error("{0:?} is not a logical file container: {1}")]
    NotLogical(ContainerFormat, String),
    /// An AD1 read failed (corrupt structure, encrypted image, I/O).
    #[error("AD1 error: {0}")]
    Ad1(#[from] ad1::Ad1Error),
    /// An AFF4-Logical read failed.
    #[error("AFF4 error: {0}")]
    Aff4(#[from] aff4::Aff4Error),
    /// A DAR read failed.
    #[error("DAR error: {0}")]
    Dar(#[from] dar::DarError),
    /// [`LogicalImage::read_file`] was given an out-of-range entry index.
    #[error("no entry at index {0}")]
    NoSuchEntry(usize),
    /// [`LogicalImage::read_file`] was asked to read a directory entry.
    #[error("entry '{0}' is a directory, not a file")]
    IsDirectory(String),
}

/// The reader backing a [`LogicalImage`], one per logical container format.
enum Backend {
    /// AD1 (`ad1-core`).
    Ad1(ad1::Ad1Reader),
    /// AFF4-Logical (`aff4::LogicalContainer`).
    Aff4(aff4::LogicalContainer),
    /// DAR (`dar-core`).
    Dar(dar::DarReader<std::fs::File>),
}

/// An opened logical file container: its entry list plus the backend reader.
pub struct LogicalImage {
    format: ContainerFormat,
    entries: Vec<LogicalEntry>,
    backend: Backend,
}

impl core::fmt::Debug for LogicalImage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LogicalImage")
            .field("format", &self.format)
            .field("entries", &self.entries.len())
            .finish()
    }
}

impl LogicalImage {
    /// The logical container format that was opened.
    #[must_use]
    pub fn format(&self) -> ContainerFormat {
        self.format
    }

    /// The file tree: one [`LogicalEntry`] per captured file/directory, in the
    /// order the backend records them. Index into this slice for
    /// [`Self::read_file`].
    #[must_use]
    pub fn entries(&self) -> &[LogicalEntry] {
        &self.entries
    }

    /// Read the full content of the file at `index` in [`Self::entries`].
    ///
    /// # Errors
    /// [`LogicalError::NoSuchEntry`] if `index` is out of range,
    /// [`LogicalError::IsDirectory`] for a directory entry, or the backend's
    /// [`LogicalError::Ad1`] / [`LogicalError::Aff4`] on a read fault.
    pub fn read_file(&mut self, index: usize) -> Result<Vec<u8>, LogicalError> {
        let meta = self
            .entries
            .get(index)
            .ok_or(LogicalError::NoSuchEntry(index))?;
        if meta.is_dir {
            return Err(LogicalError::IsDirectory(meta.path.clone()));
        }
        match &mut self.backend {
            Backend::Ad1(reader) => {
                let entry = reader
                    .entries()
                    .get(index)
                    .ok_or(LogicalError::NoSuchEntry(index))?;
                let size = entry.size;
                let mut buf = vec![0u8; usize::try_from(size).unwrap_or(usize::MAX)];
                let mut filled: u64 = 0;
                while filled < size {
                    let n = reader.read_at(entry, filled, &mut buf[filled as usize..])?;
                    if n == 0 {
                        break;
                    }
                    filled += n as u64;
                }
                buf.truncate(filled as usize);
                Ok(buf)
            }
            Backend::Aff4(container) => {
                // aff4's read_file borrows &mut self while the entry is borrowed
                // from &self.files(); clone the entry to release that borrow.
                let entry = container
                    .files()
                    .get(index)
                    .ok_or(LogicalError::NoSuchEntry(index))?
                    .clone();
                Ok(container.read_file(&entry)?)
            }
            Backend::Dar(reader) => {
                // entries() returns an owned Vec, so the borrow ends before the
                // &mut extract; index by position to recover the byte-exact path.
                let entry = reader
                    .entries()
                    .into_iter()
                    .nth(index)
                    .ok_or(LogicalError::NoSuchEntry(index))?;
                Ok(reader.extract(&entry.path)?)
            }
        }
    }
}

/// Open a logical file container (AD1 or AFF4-Logical) at `path`.
///
/// Sniffs the format and dispatches to the matching reader. A raw disk image or
/// a *physical* AFF4 is rejected with [`LogicalError::NotLogical`] naming the
/// format — open those with [`crate::container::open`] instead.
///
/// # Errors
/// [`LogicalError::Io`] on a read failure, [`LogicalError::NotLogical`] for a
/// non-logical input, or the backend error for a corrupt/encrypted container.
pub fn open(path: &Path) -> Result<LogicalImage, LogicalError> {
    let format = {
        let mut file = File::open(path)?;
        sniff(&mut file)?
    };
    match format {
        ContainerFormat::Ad1 => open_ad1(path),
        ContainerFormat::Aff4 => open_aff4_logical(path),
        ContainerFormat::Dar => open_dar(path),
        other => Err(LogicalError::NotLogical(
            other,
            "not a logical file container — try disk_forensic::container::open".into(),
        )),
    }
}

/// Open an AD1 image and project its entries.
fn open_ad1(path: &Path) -> Result<LogicalImage, LogicalError> {
    let reader = ad1::Ad1Reader::open(path)?;
    let entries = reader
        .entries()
        .iter()
        .map(|e| LogicalEntry {
            path: e.path.clone(),
            is_dir: e.is_dir,
            size: e.size,
        })
        .collect();
    Ok(LogicalImage {
        format: ContainerFormat::Ad1,
        entries,
        backend: Backend::Ad1(reader),
    })
}

/// Open an AFF4-Logical container and project its entries.
///
/// A *physical* AFF4 (or an encrypted one) is not a logical container: classify
/// first and reject it with [`LogicalError::NotLogical`] so the caller is sent
/// to [`crate::container::open`], rather than getting an opaque parse error.
fn open_aff4_logical(path: &Path) -> Result<LogicalImage, LogicalError> {
    match aff4::container_kind(path)? {
        aff4::ContainerKind::Logical => {}
        aff4::ContainerKind::Disk => {
            return Err(LogicalError::NotLogical(
                ContainerFormat::Aff4,
                "this AFF4 is a physical disk image — open it with disk_forensic::container::open"
                    .into(),
            ));
        }
        aff4::ContainerKind::Encrypted => {
            return Err(LogicalError::NotLogical(
                ContainerFormat::Aff4,
                "this AFF4 is encrypted (aff4:EncryptedStream) — needs a password".into(),
            ));
        }
    }
    let container = aff4::LogicalContainer::open(path)?;
    let entries = container
        .files()
        .iter()
        .map(|e| LogicalEntry {
            path: e.original_file_name.clone(),
            is_dir: false,
            size: e.size,
        })
        .collect();
    Ok(LogicalImage {
        format: ContainerFormat::Aff4,
        entries,
        backend: Backend::Aff4(container),
    })
}

/// Open a DAR archive and project its entries.
///
/// DAR records paths as raw bytes (it archives filesystems that do not guarantee
/// UTF-8); the listed [`LogicalEntry::path`] is the lossy-UTF-8 display form,
/// while [`LogicalImage::read_file`] indexes back into the reader's own entries
/// for the byte-exact extraction key.
fn open_dar(path: &Path) -> Result<LogicalImage, LogicalError> {
    let reader = dar::DarReader::open(File::open(path)?)?;
    let entries = reader
        .entries()
        .iter()
        .map(|e| LogicalEntry {
            path: String::from_utf8_lossy(&e.path).into_owned(),
            is_dir: matches!(e.kind, dar::EntryKind::Directory),
            size: e.size,
        })
        .collect();
    Ok(LogicalImage {
        format: ContainerFormat::Dar,
        entries,
        backend: Backend::Dar(reader),
    })
}
