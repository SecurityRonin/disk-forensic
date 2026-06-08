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

use forensicnomicon::report::Finding;
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
    /// Container-level forensic findings (e.g. VMDK redundant-GD / dangling-pointer
    /// / provenance anomalies), surfaced so they aggregate into the normalized
    /// report alongside the partition/filesystem findings. Empty for containers
    /// without a forensic analyzer.
    pub findings: Vec<Finding>,
}

impl core::fmt::Debug for OpenedImage {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("OpenedImage")
            .field("format", &self.format)
            .field("size", &self.size)
            .finish_non_exhaustive()
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
                findings: Vec::new(),
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
                findings: Vec::new(),
            })
        }
        ContainerFormat::Vmdk => {
            // `vmdk` (imported) is forensicnomicon's magic module; the decoder is
            // the external `vmdk` crate, reached via the absolute path. The chain
            // reader resolves any snapshot/delta extents to the base image.
            let reader = ::vmdk::VmdkChainReader::open(path)
                .map_err(|e| OpenError::Decode(format, e.to_string()))?;
            let size = reader.virtual_disk_size();
            // Run the VMDK forensic analyzer over the same path so its findings
            // (RGD mismatch, dangling pointers, unclean shutdown, FTP-mangling)
            // aggregate into the report. A failed analysis must not fail the open —
            // the disk view is still usable — so it degrades to no findings.
            let findings = File::open(path)
                .ok()
                .map(vmdk_forensic::VmdkIntegrity::new)
                .and_then(|mut i| i.analyse().ok())
                .unwrap_or_default();
            Ok(OpenedImage {
                format,
                size,
                reader: Box::new(reader),
                findings,
            })
        }
        ContainerFormat::Qcow2 => {
            // Our qcow2-core reader owns the file and is Read + Seek directly;
            // it rejects QCOW1 / encrypted / backing-file images at open().
            let reader = ::qcow2::Qcow2Reader::open(path)
                .map_err(|e| OpenError::Decode(format, e.to_string()))?;
            let size = reader.virtual_disk_size();
            Ok(OpenedImage {
                format,
                size,
                reader: Box::new(reader),
                findings: Vec::new(),
            })
        }
        ContainerFormat::Vhd => {
            // Hand-rolled decoder (no crate): handles fixed + dynamic subformats.
            let reader = crate::vhd::VhdReader::open(File::open(path)?)
                .map_err(|e| OpenError::Decode(format, e.to_string()))?;
            let size = reader.virtual_size();
            Ok(OpenedImage {
                format,
                size,
                reader: Box::new(reader),
                findings: Vec::new(),
            })
        }
        ContainerFormat::Vhdx => {
            // Our own `vhdx-core` reader (imported as `vhdx`) returns an owned
            // `VhdxReader` that is itself `Read + Seek` with a real `Result` — box
            // it directly; no adapter and no panic guard needed.
            let reader = ::vhdx::VhdxReader::open(path)
                .map_err(|e| OpenError::Decode(format, e.to_string()))?;
            let size = reader.virtual_disk_size();
            Ok(OpenedImage {
                format,
                size,
                reader: Box::new(reader),
                findings: Vec::new(),
            })
        }
        ContainerFormat::Dmg => {
            let bytes =
                decode_dmg(path).map_err(|e| OpenError::Decode(format, e.to_string()))?;
            Ok(OpenedImage {
                format,
                size: bytes.len() as u64,
                reader: Box::new(std::io::Cursor::new(bytes)),
                findings: Vec::new(),
            })
        }
        ContainerFormat::Iso => {
            // An ISO 9660 image needs no container decoding — it is a flat
            // filesystem image. Pass the file through; disk4n6 routes the `Iso`
            // format to the filesystem analyzer instead of the partition parsers.
            let size = file.metadata()?.len();
            Ok(OpenedImage {
                format,
                size,
                reader: Box::new(file),
                findings: Vec::new(),
            })
        }
        other => Err(OpenError::Unsupported(other)),
    }
}

/// Reconstruct a whole DMG (UDIF) disk image in memory. The `udif` crate exposes
/// a DMG as ordered blkx entries (MBR, free gaps, partitions) rather than a
/// single disk view, so we concatenate them in disk order; sparse `Apple_Free`
/// entries (no compressed bytes) become zero-fill. Unlike the streaming
/// decoders this buffers the entire disk in memory — a limitation of the crate's
/// partition-oriented API.
fn decode_dmg(path: &Path) -> std::io::Result<Vec<u8>> {
    let to_io =
        |e: ::udif::DppError| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string());
    let mut archive = ::udif::DmgArchive::open(path).map_err(to_io)?;
    let parts = archive.partitions();
    let mut disk = Vec::new();
    for p in &parts {
        let want = p.size as usize;
        if p.compressed_size == 0 {
            // Free / unallocated space stored sparsely → zero-fill.
            disk.resize(disk.len() + want, 0);
        } else {
            let mut data = archive.extract_partition(p.id).map_err(to_io)?;
            data.resize(want, 0);
            disk.append(&mut data);
        }
    }
    Ok(disk)
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
