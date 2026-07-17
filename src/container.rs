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

/// Anything that can be both read and seeked, and moved across threads — the
/// disk view `analyse_disk` consumes. A blanket impl covers every
/// `Read + Seek + Send`, so a decoder's reader or a plain `File` both box into
/// `Box<dyn ReadSeek + Send>`. `Send` lets a consumer hand the decoded disk (or
/// a partition slice of it) to a background mount thread.
pub trait ReadSeek: Read + Seek + Send {}
impl<T: Read + Seek + Send> ReadSeek for T {}

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
    /// decode it to a raw image first. A defensive arm for any future
    /// recognized-but-unwired format; every format `sniff` recognizes today is
    /// either decoded or routed.
    #[error("{0:?} container decoding is not yet supported — decode it to a raw image first")]
    Unsupported(ContainerFormat),
    /// The format is a *logical* file container (AD1, or an AFF4-Logical
    /// `aff4:FileImage` collection), not a raw disk image — it has no block
    /// device / partition table underneath, so it does not fit `open`'s
    /// `Read + Seek` disk contract. Open it with [`crate::logical::open`].
    #[error(
        "{0:?} is a logical file container, not a raw disk image — open it with \
         `disk_forensic::logical::open`"
    )]
    LogicalContainer(ContainerFormat),
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
    open_depth(path, 0)
}

/// Maximum nested compression layers to peel before giving up (bomb guard).
const MAX_PEEL_DEPTH: usize = 4;

fn open_depth(path: &Path, depth: usize) -> Result<OpenedImage, OpenError> {
    // Transparently peel an OUTER compression wrapper (evidence.dd.gz -> dd)
    // via archive-core — but only when BOTH the content magic and the file
    // extension agree it is a wrapper, so a raw disk with coincidental magic
    // still opens as raw. A raw inner is served from memory; a container inner
    // is spilled to a temp file and re-opened.
    if depth < MAX_PEEL_DEPTH {
        if let Some(inner) = try_peel(path)? {
            if sniff_bytes(&inner) == ContainerFormat::Raw {
                let size = inner.len() as u64;
                return Ok(OpenedImage {
                    format: ContainerFormat::Raw,
                    size,
                    reader: Box::new(std::io::Cursor::new(inner)),
                    findings: Vec::new(),
                });
            }
            let tmp = spill_to_tmp(&inner)?;
            return open_depth(&tmp, depth + 1);
        }
    }
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
            // Our own `dmg-core` reader is `Read + Seek` directly (no buffering)
            // and decodes every UDIF block codec — ADC/zlib/bzip2/LZFSE/LZMA —
            // in pure Rust. `::dmg` is the crate; `dmg` (imported) is
            // forensicnomicon's magic module used for sniffing.
            let reader = ::dmg::DmgReader::open(File::open(path)?)
                .map_err(|e| OpenError::Decode(format, e.to_string()))?;
            let size = reader.virtual_disk_size();
            Ok(OpenedImage {
                format,
                size,
                reader: Box::new(reader),
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
        ContainerFormat::Aff4 => {
            // `aff4` (imported) is forensicnomicon's magic module; the reader is
            // the external `aff4` crate, reached via the absolute path. AFF4 has
            // two shapes: a physical disk image (aff4:ImageStream / aff4:Map) is
            // a Read + Seek disk view; a logical collection (aff4:FileImage) is a
            // file tree with no disk underneath. Classify cheaply first so a
            // logical container is routed out instead of yielding a bogus disk.
            match ::aff4::container_kind(path)
                .map_err(|e| OpenError::Decode(format, e.to_string()))?
            {
                ::aff4::ContainerKind::Disk => {
                    let reader = ::aff4::Aff4Reader::open(path)
                        .map_err(|e| OpenError::Decode(format, e.to_string()))?;
                    let size = reader.virtual_disk_size();
                    Ok(OpenedImage {
                        format,
                        size,
                        reader: Box::new(reader),
                        findings: Vec::new(),
                    })
                }
                ::aff4::ContainerKind::Logical => Err(OpenError::LogicalContainer(format)),
                ::aff4::ContainerKind::Encrypted => Err(OpenError::Decode(
                    format,
                    "encrypted AFF4 container (aff4:EncryptedStream) — needs a password".into(),
                )),
            }
        }
        ContainerFormat::Ad1 => {
            // AD1 is FTK's logical "Custom Content Image" — a file tree, no raw
            // disk. It cannot yield a Read + Seek disk view; route it to
            // `logical::open`.
            Err(OpenError::LogicalContainer(format))
        }
        ContainerFormat::Dar => {
            // DAR (Disk ARchiver) is a logical backup archive — a file tree, no
            // raw disk. Route it to `logical::open` like AD1.
            Err(OpenError::LogicalContainer(format))
        }
    }
}

/// Bytes read from the start for header-magic detection — large enough to reach
/// the ISO 9660 PVD "CD001" at offset 32769.
const HEADER_SNIFF_BYTES: usize = 34816;
/// Bytes read from the end for footer/trailer-magic detection (VHD, DMG).
const FOOTER_SNIFF_BYTES: u64 = 512;
/// AD1 offset-0 signature — the "ADSEGMENTEDFILE" segmented-file marker (the
/// trailing NUL of `ADSEGMENTEDFILE\0` is not required to disambiguate). Mirrors
/// `ad1-core`'s `AD1_SEGMENTED_MARKER`.
const AD1_SEGMENTED_MARKER: &[u8] = b"ADSEGMENTEDFILE";
/// DAR offset-0 magic — `SAUV_MAGIC_NUMBER` (123) as a big-endian u32. Mirrors
/// `dar-core`'s `DAR_MAGIC`.
const DAR_MAGIC: [u8; 4] = [0x00, 0x00, 0x00, 0x7b];

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
    /// Advanced Forensic Format 4 (ZIP-based). Physical (`aff4:ImageStream` /
    /// `aff4:Map`) images decode to a disk view via [`open`]; logical
    /// (`aff4:FileImage`) collections are read via [`crate::logical::open`].
    Aff4,
    /// AccessData AD1 (FTK "Custom Content Image") — a *logical* file container,
    /// not a raw disk. Read via [`crate::logical::open`]; [`open`] refuses it
    /// with [`OpenError::LogicalContainer`].
    Ad1,
    /// DAR (Denis Corbin Disk ARchiver) backup archive — a *logical* file
    /// container, not a raw disk. Read via [`crate::logical::open`].
    Dar,
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
    // AccessData AD1 (FTK "Custom Content Image"): the segmented-file marker
    // "ADSEGMENTEDFILE\0" sits at offset 0 (al3ks1s/AD1-tools; `ad1-core`'s
    // AD1_SEGMENTED_MARKER). forensicnomicon carries no AD1 magic module yet, so
    // the signature is spelled out here.
    if header.starts_with(AD1_SEGMENTED_MARKER) {
        return ContainerFormat::Ad1;
    }
    // DAR (Disk ARchiver): the SAUV magic (123, big-endian u32) at offset 0.
    if header.starts_with(&DAR_MAGIC) {
        return ContainerFormat::Dar;
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
/// Attempt to peel one outer compression wrapper. Returns the inner bytes when
/// `path` is a compression-wrapped image (magic AND extension agree), `None`
/// when it is not a wrapper, and an error only when a genuinely-named wrapper
/// fails to decode.
fn try_peel(path: &Path) -> Result<Option<Vec<u8>>, OpenError> {
    let name = path.file_name().and_then(|n| n.to_str());
    // Sniff the head only — never slurp a large non-wrapper image.
    let mut head = [0u8; 16];
    let read = {
        let mut file = File::open(path)?;
        file.read(&mut head)?
    };
    if !archive_core::sniff(name, &head[..read]).is_compression_wrapper() {
        return Ok(None);
    }
    // Require the extension to agree — a raw disk with coincidental magic but no
    // compression extension must open as raw, not be mis-peeled.
    let Some(name) = name else {
        return Ok(None); // cov:unreachable: a path that File::open succeeded on has a file name
    };
    if !has_compression_ext(name) {
        return Ok(None);
    }
    let data = std::fs::read(path)?;
    match archive_core::peel_bytes(&data, Some(name)) {
        Ok(archive_core::PeelOutcome::Peeled { inner, .. }) => Ok(Some(inner)),
        Ok(_) => Ok(None), // cov:unreachable: head-sniff already confirmed a compression wrapper
        Err(e) => Err(OpenError::Decode(
            ContainerFormat::Raw,
            format!("archive peel failed: {e}"),
        )),
    }
}

/// Does the file name carry a compression-wrapper extension (incl. tar aliases)?
fn has_compression_ext(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    [
        ".gz", ".bz2", ".xz", ".tgz", ".taz", ".tbz", ".tbz2", ".txz", ".tzst", ".tlz", ".zst",
        ".z",
    ]
    .iter()
    .any(|e| lower.ends_with(e))
}

/// Sniff an in-memory (peeled) image's container format.
fn sniff_bytes(bytes: &[u8]) -> ContainerFormat {
    sniff(&mut std::io::Cursor::new(bytes)).unwrap_or(ContainerFormat::Raw)
}

/// Spill peeled bytes to a temp file so a path-based container decoder can open
/// them (the rare compression-wrapped *container*, e.g. `evidence.E01.gz`).
fn spill_to_tmp(bytes: &[u8]) -> Result<std::path::PathBuf, OpenError> {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("disk4n6-peel-{}-{n}.img", std::process::id()));
    std::fs::write(&path, bytes)?;
    Ok(path)
}

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
