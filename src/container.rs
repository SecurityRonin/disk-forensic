//! Container-format detection (magic-sniff) — which decoder a disk image needs.
//!
//! disk4n6 analyses a `Read + Seek` view of a *disk*. Most evidence arrives
//! wrapped in a container (E01, VHD/VHDX, VMDK, QCOW2, AFF4, DMG); this sniffs
//! the magic so an opener can pick the right decoder. The magics come from the
//! `forensicnomicon` knowledge modules (single source of truth). A flat raw/`dd`
//! image has no wrapper and is analysed in place.

use std::io::{Read, Seek, SeekFrom};

use forensicnomicon::{aff4, dmg, ewf, qcow2, vhd, vhdx, vmdk};

/// Bytes read from the start for header-magic detection.
const HEADER_SNIFF_BYTES: usize = 4096;
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
