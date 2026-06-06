//! # disk-forensic
//!
//! Point it at any disk image and it identifies the partitioning scheme — MBR,
//! GPT, or Apple Partition Map — and dispatches to the matching forensic parser,
//! so you get the right structural analysis without choosing a crate up front.
//!
//! It is pure orchestration: scheme detection comes from the
//! [`forensicnomicon`](https://docs.rs/forensicnomicon) knowledge base, and every
//! real parse is delegated to a sibling crate
//! ([`mbr_forensic`], [`gpt_forensic`], [`apm_forensic`]). Like them, it works
//! over any `Read + Seek`, so it composes with the container crates (`ewf`,
//! `vhd`, …) for E01/VHD/VMDK evidence.
//!
//! ```no_run
//! use std::fs::File;
//! let mut img = File::open("disk.img")?;
//! let size = img.metadata()?.len();
//! match disk_forensic::analyse_disk(&mut img, size)? {
//!     disk_forensic::DiskReport::Gpt(a) => println!("GPT, {} partitions", a.partitions.len()),
//!     disk_forensic::DiskReport::Mbr(a) => println!("MBR, {} partitions", a.partitions.len()),
//!     disk_forensic::DiskReport::Apm(a) => println!("APM, {} partitions", a.partitions.len()),
//! }
//! # Ok::<(), disk_forensic::Error>(())
//! ```

use std::io::{Read, Seek, SeekFrom};

pub mod normalize;
pub mod report;

pub use forensicnomicon::partition_schemes::Scheme;

/// Bytes read from the start (LBA 0 + LBA 1) for scheme detection.
const BOOT_AREA_BYTES: usize = 1024;
/// Upper bound on bytes the APM parser reads — the map lives in the first blocks.
const APM_MAX_BYTES: usize = 1 << 20;

/// Crate-level error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// No MBR, GPT, or APM signature was found in the boot area (e.g. a disk
    /// with a filesystem written directly to it, or unrecognised media).
    #[error("unrecognised partitioning scheme (no MBR, GPT, or APM signature found)")]
    UnknownScheme,
    /// The Apple Partition Map parser failed.
    #[error("APM analysis failed: {0}")]
    Apm(#[from] apm_forensic::Error),
    /// The MBR/GPT parser failed.
    #[error("MBR/GPT analysis failed: {0}")]
    Mbr(#[from] mbr_forensic::Error),
    /// I/O failure while reading the disk image.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// A full forensic analysis, tagged by the partitioning scheme that was found.
///
/// The `Gpt` variant carries the protective-MBR analysis with its parsed GPT
/// (`.gpt` is `Some`); `Mbr` is a classic MBR with no GPT.
#[derive(Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum DiskReport {
    /// Apple Partition Map.
    Apm(apm_forensic::ApmAnalysis),
    /// Classic Master Boot Record (no GPT).
    Mbr(Box<mbr_forensic::MbrAnalysis>),
    /// GUID Partition Table (protective MBR + parsed GPT).
    Gpt(Box<mbr_forensic::MbrAnalysis>),
}

impl DiskReport {
    /// The detected partitioning scheme.
    #[must_use]
    pub fn scheme(&self) -> Scheme {
        match self {
            DiskReport::Apm(_) => Scheme::Apm,
            DiskReport::Mbr(_) => Scheme::Mbr,
            DiskReport::Gpt(_) => Scheme::Gpt,
        }
    }

    /// `true` when the analysis recorded at least one anomaly — the CLI's
    /// non-zero exit signal for triage pipelines.
    #[must_use]
    pub fn has_anomalies(&self) -> bool {
        match self {
            DiskReport::Apm(a) => !a.anomalies.is_empty(),
            DiskReport::Mbr(m) | DiskReport::Gpt(m) => !m.anomalies.is_empty(),
        }
    }
}

/// Detect the partitioning scheme of the disk behind `reader` and run the
/// matching forensic parser.
///
/// `disk_size_bytes` bounds MBR/GPT gap and out-of-bounds analysis (pass the
/// image length; `0` skips it). The reader is rewound before each parser runs.
///
/// # Errors
/// [`Error::UnknownScheme`] when no scheme signature is present, [`Error::Apm`] /
/// [`Error::Mbr`] when the chosen parser fails, or [`Error::Io`] on a read error.
pub fn analyse_disk<R: Read + Seek>(
    reader: &mut R,
    disk_size_bytes: u64,
) -> Result<DiskReport, Error> {
    let boot = read_boot_area(reader)?;
    match forensicnomicon::partition_schemes::detect_scheme(&boot) {
        Some(Scheme::Apm) => Ok(DiskReport::Apm(apm_forensic::analyse_reader(
            reader,
            APM_MAX_BYTES,
        )?)),
        Some(Scheme::Gpt | Scheme::Mbr) => {
            let mbr = mbr_forensic::analyse(reader, disk_size_bytes)?;
            // The parser's own GPT detection is authoritative for the label: a
            // protective MBR with a parseable GPT → Gpt, otherwise classic Mbr.
            if mbr.gpt.is_some() {
                Ok(DiskReport::Gpt(Box::new(mbr)))
            } else {
                Ok(DiskReport::Mbr(Box::new(mbr)))
            }
        }
        None => Err(Error::UnknownScheme),
    }
}

/// Read up to [`BOOT_AREA_BYTES`] from the start, tolerating short reads and EOF.
fn read_boot_area<R: Read + Seek>(reader: &mut R) -> Result<Vec<u8>, std::io::Error> {
    reader.seek(SeekFrom::Start(0))?;
    let mut buf = vec![0u8; BOOT_AREA_BYTES];
    let mut filled = 0;
    while filled < BOOT_AREA_BYTES {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    buf.truncate(filled);
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error as IoError, ErrorKind};

    #[test]
    fn error_display_covers_every_variant() {
        assert!(Error::UnknownScheme.to_string().contains("unrecognised"));
        let apm: Error = apm_forensic::Error::NotApm.into();
        assert!(apm.to_string().contains("APM"));
        let mbr: Error = mbr_forensic::Error::TooShort(1).into();
        assert!(mbr.to_string().contains("MBR"));
        let io: Error = IoError::other("boom").into();
        assert!(io.to_string().contains("I/O"));
    }

    /// Yields `Interrupted` once (must be retried), then a hard error.
    struct FlakyReader {
        interrupted_once: bool,
    }
    impl Read for FlakyReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            if self.interrupted_once {
                Err(IoError::other("hard read failure"))
            } else {
                self.interrupted_once = true;
                Err(IoError::from(ErrorKind::Interrupted))
            }
        }
    }
    impl Seek for FlakyReader {
        fn seek(&mut self, _: SeekFrom) -> std::io::Result<u64> {
            Ok(0)
        }
    }

    #[test]
    fn read_boot_area_retries_interrupted_then_propagates_error() {
        let mut r = FlakyReader {
            interrupted_once: false,
        };
        let err = read_boot_area(&mut r).unwrap_err();
        assert_eq!(err.to_string(), "hard read failure");
    }

    #[test]
    fn read_boot_area_stops_at_eof_on_short_image() {
        // A sub-1024-byte reader hits the `Ok(0) => break` path.
        let mut r = std::io::Cursor::new(vec![0u8; 16]);
        let boot = read_boot_area(&mut r).unwrap();
        assert_eq!(boot.len(), 16);
    }
}
