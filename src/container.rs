//! Container-format detection (magic-sniff) — which decoder a disk image needs.
//!
//! disk4n6 analyses a `Read + Seek` view of a *disk*. Most evidence arrives
//! wrapped in a container (E01, VHD/VHDX, VMDK, QCOW2, AFF4, DMG); this sniffs
//! the magic so an opener can pick the right decoder. The magics come from the
//! `forensicnomicon` knowledge modules (single source of truth). A flat raw/`dd`
//! image has no wrapper and is analysed in place.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

use forensicnomicon::{aff4, dmg, ewf, qcow2, vhd, vhdx, vmdk};

/// Anything that can be both read and seeked — the disk view `analyse_disk`
/// consumes. A blanket impl covers every `Read + Seek`, so a decoder's reader or
/// a plain `File` both box into `Box<dyn ReadSeek>`.
pub trait ReadSeek: Read + Seek {}
impl<T: Read + Seek> ReadSeek for T {}

/// A decoded, analysable disk image.
pub struct OpenedImage {
    /// The container format it was decoded from (`Raw` for a flat image).
    pub format: ContainerFormat,
    /// Logical disk size in bytes (the decoded media size).
    pub size: u64,
    /// A `Read + Seek` view of the decoded disk, ready for `analyse_disk`.
    pub reader: Box<dyn ReadSeek>,
}

impl core::fmt::Debug for OpenedImage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenedImage")
            .field("format", &self.format)
            .field("size", &self.size)
            .finish_non_exhaustive()
    }
}

/// Owning `Read + Seek` adapter for the `qcow` crate, whose reader borrows *both*
/// the parsed image and the backing file. We own both and rebuild a short-lived
/// borrowed reader per call (disjoint field borrows), tracking the logical
/// position ourselves. QCOW2 only — legacy QCOW1 is rejected at `open()`.
struct QcowView {
    qcow: ::qcow::Qcow2,
    file: File,
    pos: u64,
}

impl Read for QcowView {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let mut r = self.qcow.reader(&mut self.file);
        r.seek(SeekFrom::Start(self.pos))?;
        let n = r.read(buf)?;
        drop(r);
        self.pos += n as u64;
        Ok(n)
    }
}

impl Seek for QcowView {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let np: i64 = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => {
                let end = self.qcow.reader(&mut self.file).seek(SeekFrom::End(0))?;
                end as i64 + o
            }
            SeekFrom::Current(o) => self.pos as i64 + o,
        };
        if np < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before start of disk",
            ));
        }
        self.pos = np as u64;
        Ok(self.pos)
    }
}

/// Failure opening/decoding an image.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// I/O failure opening or reading the file.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// A recognized container's decoder failed (corrupt/unsupported variant).
    #[error("{0:?} decode error: {1}")]
    Decode(ContainerFormat, String),
    /// An optical (ISO 9660) image — a filesystem, not a partitioned disk;
    /// analyse it with `iso9660-forensic` (FS dispatch is not yet wired here).
    #[error(
        "ISO 9660 optical image — a filesystem, not a partitioned disk; analyse it with \
         iso9660-forensic (disk4n6 filesystem dispatch is not yet wired)"
    )]
    Optical,
    /// The container format is recognized but its decoder is not yet wired —
    /// decode it to a raw image first.
    #[error("{0:?} container decoding is not yet supported — decode it to a raw image first")]
    Unsupported(ContainerFormat),
}

/// Open `path`, sniff its container format, and return a decoded `Read + Seek`
/// disk view: raw images pass through; E01/EWF is decoded; other recognized
/// containers return [`OpenError::Unsupported`].
///
/// # Errors
/// [`OpenError::Io`] on a read failure, [`OpenError::Decode`] on a corrupt
/// image, or [`OpenError::Unsupported`] for a container whose decoder is not yet
/// wired.
pub fn open(path: &Path) -> Result<OpenedImage, OpenError> {
    let mut file = File::open(path)?;
    let format = sniff(&mut file)?;
    match format {
        ContainerFormat::Raw => {
            let size = file.metadata()?.len();
            Ok(OpenedImage {
                format,
                size,
                reader: Box::new(file),
            })
        }
        ContainerFormat::Ewf => {
            // `ewf` (imported) is forensicnomicon's magic module; the decoder is
            // the external `ewf` crate, reached via the absolute path.
            let reader = ::ewf::EwfReader::open(path)
                .map_err(|e| OpenError::Decode(format, e.to_string()))?;
            let size = reader.total_size();
            Ok(OpenedImage {
                format,
                size,
                reader: Box::new(reader),
            })
        }
        ContainerFormat::Vmdk => {
            // `vmdk` (imported) is forensicnomicon's magic module; the decoder is
            // the external `vmdk` crate, reached via the absolute path. The chain
            // reader resolves any snapshot/delta extents to the base image.
            let reader = ::vmdk::VmdkChainReader::open(path)
                .map_err(|e| OpenError::Decode(format, e.to_string()))?;
            let size = reader.virtual_disk_size();
            Ok(OpenedImage {
                format,
                size,
                reader: Box::new(reader),
            })
        }
        ContainerFormat::Qcow2 => {
            let mut file = File::open(path)?;
            let dq = ::qcow::load(&mut file).map_err(|e| OpenError::Decode(format, e.to_string()))?;
            if dq.version() == 1 {
                return Err(OpenError::Decode(
                    format,
                    "legacy QCOW1 is not supported".to_string(),
                ));
            }
            let mut view = QcowView {
                qcow: dq.unwrap_qcow2(),
                file,
                pos: 0,
            };
            let size = view.seek(SeekFrom::End(0))?;
            view.seek(SeekFrom::Start(0))?;
            Ok(OpenedImage {
                format,
                size,
                reader: Box::new(view),
            })
        }
        ContainerFormat::Iso => Err(OpenError::Optical),
        other => Err(OpenError::Unsupported(other)),
    }
}

/// Bytes read from the start for header-magic detection — large enough to reach
/// the ISO 9660 PVD "CD001" at offset 32769.
const HEADER_SNIFF_BYTES: usize = 34816;
/// Bytes read from the end for footer/trailer-magic detection (VHD, DMG).
const FOOTER_SNIFF_BYTES: u64 = 512;

/// A detected disk-image container format.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum ContainerFormat {
    /// No container wrapper — a flat raw/`dd` image (analyse in place).
    Raw,
    /// Expert Witness Format (EnCase E01 / Ex01 / logical L01).
    Ewf,
    /// Microsoft VHD (fixed / dynamic / differencing).
    Vhd,
    /// Microsoft VHDX.
    Vhdx,
    /// VMware VMDK (sparse extent).
    Vmdk,
    /// QEMU / KVM QCOW2.
    Qcow2,
    /// Advanced Forensic Format 4 (ZIP-based).
    Aff4,
    /// Apple Disk Image (UDIF).
    Dmg,
    /// ISO 9660 optical-disc image (a filesystem, not a partitioned disk —
    /// analysed by `iso9660-forensic` rather than the partition parsers).
    Iso,
}

/// Sniff the container format from a disk image's `header` (its first bytes,
/// ideally ≥512) and `footer` (its last 512 bytes — VHD's `conectix` cookie and
/// DMG's `koly` trailer live at the *end* of the file).
///
/// Returns [`ContainerFormat::Raw`] when no wrapper magic is present (a bare
/// MBR/GPT/APM disk).
#[must_use]
pub fn detect(header: &[u8], footer: &[u8]) -> ContainerFormat {
    // ── Offset-0 magics ──────────────────────────────────────────────────────
    if header.starts_with(&ewf::EVF1_SIGNATURE)
        || header.starts_with(&ewf::EVF2_SIGNATURE)
        || header.starts_with(&ewf::LEF2_SIGNATURE)
    {
        return ContainerFormat::Ewf;
    }
    if header.starts_with(vhdx::FILE_IDENTIFIER) {
        return ContainerFormat::Vhdx;
    }
    // A dynamic VHD mirrors its footer cookie at offset 0.
    if header.starts_with(vhd::FOOTER_COOKIE) {
        return ContainerFormat::Vhd;
    }
    if header.starts_with(&vmdk::VMDK4_MAGIC.to_le_bytes()) {
        return ContainerFormat::Vmdk;
    }
    if header.starts_with(&qcow2::MAGIC.to_be_bytes()) {
        return ContainerFormat::Qcow2;
    }
    if header.starts_with(&aff4::ZIP_LOCAL_FILE_HEADER_MAGIC) {
        return ContainerFormat::Aff4;
    }
    // ── Optical (ISO 9660): "CD001" at the PVD, offset 32769 (ECMA-119) ───────
    const ISO_PVD_OFFSET: usize = 32769;
    if header.len() >= ISO_PVD_OFFSET + 5 && &header[ISO_PVD_OFFSET..ISO_PVD_OFFSET + 5] == b"CD001"
    {
        return ContainerFormat::Iso;
    }
    // ── Footer / trailer magics ──────────────────────────────────────────────
    if footer.starts_with(vhd::FOOTER_COOKIE) {
        return ContainerFormat::Vhd;
    }
    if footer.starts_with(&dmg::KOLY_MAGIC.to_be_bytes()) {
        return ContainerFormat::Dmg;
    }
    ContainerFormat::Raw
}

/// Sniff the container format of a seekable image: read its header and trailing
/// footer, classify via [`detect`], and **rewind the reader to 0** for the
/// caller. A sub-512-byte image is read without a footer.
///
/// # Errors
/// Propagates any I/O error from seeking/reading the image.
pub fn sniff<R: Read + Seek>(reader: &mut R) -> std::io::Result<ContainerFormat> {
    let len = reader.seek(SeekFrom::End(0))?;

    reader.seek(SeekFrom::Start(0))?;
    let header_len = (len as usize).min(HEADER_SNIFF_BYTES);
    let mut header = vec![0u8; header_len];
    reader.read_exact(&mut header)?;

    let footer = if len >= FOOTER_SNIFF_BYTES {
        reader.seek(SeekFrom::End(-(FOOTER_SNIFF_BYTES as i64)))?;
        let mut f = vec![0u8; FOOTER_SNIFF_BYTES as usize];
        reader.read_exact(&mut f)?;
        f
    } else {
        Vec::new()
    };

    reader.seek(SeekFrom::Start(0))?;
    Ok(detect(&header, &footer))
}
