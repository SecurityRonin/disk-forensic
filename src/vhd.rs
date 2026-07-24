//! Minimal forensic decoder for Microsoft VHD (Virtual PC, `"conectix"`): the
//! fixed and dynamic subformats. Differencing disks (which need a parent chain)
//! are rejected.
//!
//! Layout (all multi-byte fields big-endian):
//! - A 512-byte **footer** ends the file (fixed) or is mirrored at offset 0 too
//!   (dynamic). `current_size` (offset 48) is the virtual disk size; `disk_type`
//!   (offset 60) is 2 = fixed, 3 = dynamic, 4 = differencing.
//! - A dynamic disk adds a 1024-byte `"cxsparse"` header (at the footer's
//!   `data_offset`) carrying the BAT location, entry count, and block size, then
//!   a Block Allocation Table of `u32` sector offsets (`0xFFFF_FFFF` = sparse),
//!   each pointing at a block that begins with a sector bitmap.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};

const FOOTER_LEN: u64 = 512;
const SECTOR: u64 = 512;
const UNALLOCATED: u32 = 0xFFFF_FFFF;

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg.into())
}

/// A `Read + Seek` view of the decoded VHD disk.
#[derive(Debug)]
pub(crate) struct VhdReader {
    file: File,
    virtual_size: u64,
    layout: Layout,
    pos: u64,
}

#[derive(Debug)]
enum Layout {
    /// Data is stored verbatim from offset 0; the trailing footer is excluded.
    Fixed,
    /// Sparse blocks located via the BAT.
    Dynamic {
        block_size: u64,
        /// Per-block sector-bitmap size, rounded up to whole sectors.
        bitmap_sectors: u64,
        bat: Vec<u32>,
    },
}

impl VhdReader {
    /// Parse a VHD `file` and return a decoded disk view positioned at 0.
    pub(crate) fn open(mut file: File) -> io::Result<Self> {
        let len = file.seek(SeekFrom::End(0))?;
        if len < FOOTER_LEN {
            return Err(invalid("VHD smaller than its 512-byte footer"));
        }

        // The footer ends the file; dynamic disks also mirror it at offset 0.
        let mut footer = [0u8; 512];
        file.seek(SeekFrom::End(-(FOOTER_LEN as i64)))?;
        file.read_exact(&mut footer)?;
        if &footer[0..8] != b"conectix" {
            file.seek(SeekFrom::Start(0))?;
            file.read_exact(&mut footer)?;
            if &footer[0..8] != b"conectix" {
                return Err(invalid("missing VHD 'conectix' cookie"));
            }
        }

        let data_offset = u64::from_be_bytes(footer[16..24].try_into().unwrap());
        let virtual_size = u64::from_be_bytes(footer[48..56].try_into().unwrap());
        let disk_type = u32::from_be_bytes(footer[60..64].try_into().unwrap());

        let layout = match disk_type {
            2 => Layout::Fixed,
            3 => Self::parse_dynamic(&mut file, data_offset)?,
            4 => {
                return Err(invalid(
                    "differencing VHDs (parent required) are not supported",
                ))
            }
            other => return Err(invalid(format!("unsupported VHD disk type {other}"))),
        };

        Ok(Self {
            file,
            virtual_size,
            layout,
            pos: 0,
        })
    }

    fn parse_dynamic(file: &mut File, data_offset: u64) -> io::Result<Layout> {
        let mut dh = [0u8; 1024];
        file.seek(SeekFrom::Start(data_offset))?;
        file.read_exact(&mut dh)?;
        if &dh[0..8] != b"cxsparse" {
            return Err(invalid("missing dynamic-disk 'cxsparse' header"));
        }
        let table_offset = u64::from_be_bytes(dh[16..24].try_into().unwrap());
        let max_entries = u32::from_be_bytes(dh[28..32].try_into().unwrap()) as usize;
        let block_size = u64::from(u32::from_be_bytes(dh[32..36].try_into().unwrap()));
        if block_size == 0 || block_size % SECTOR != 0 {
            return Err(invalid("invalid VHD block size"));
        }

        let mut bat_raw = vec![0u8; max_entries * 4];
        file.seek(SeekFrom::Start(table_offset))?;
        file.read_exact(&mut bat_raw)?;
        let bat = bat_raw
            .chunks_exact(4)
            .map(|c| u32::from_be_bytes(c.try_into().unwrap()))
            .collect();

        let sectors_per_block = block_size / SECTOR;
        let bitmap_sectors = sectors_per_block.div_ceil(8).div_ceil(SECTOR);
        Ok(Layout::Dynamic {
            block_size,
            bitmap_sectors,
            bat,
        })
    }

    /// The logical disk size in bytes (the footer's `current_size`).
    pub(crate) fn virtual_size(&self) -> u64 {
        self.virtual_size
    }
}

impl Read for VhdReader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() || self.pos >= self.virtual_size {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(self.virtual_size - self.pos);

        match &self.layout {
            Layout::Fixed => {
                self.file.seek(SeekFrom::Start(self.pos))?;
                let n = self.file.read(&mut buf[..want as usize])?;
                self.pos += n as u64;
                Ok(n)
            }
            Layout::Dynamic {
                block_size,
                bitmap_sectors,
                bat,
            } => {
                // Serve at most one block per call (Read may return short).
                let block = (self.pos / block_size) as usize;
                let off_in_block = self.pos % block_size;
                let chunk = want.min(block_size - off_in_block) as usize;
                let entry = bat.get(block).copied().unwrap_or(UNALLOCATED);
                if entry == UNALLOCATED {
                    buf[..chunk].fill(0);
                    self.pos += chunk as u64;
                    Ok(chunk)
                } else {
                    let data_start = u64::from(entry) * SECTOR + bitmap_sectors * SECTOR;
                    self.file.seek(SeekFrom::Start(data_start + off_in_block))?;
                    let n = self.file.read(&mut buf[..chunk])?;
                    self.pos += n as u64;
                    Ok(n)
                }
            }
        }
    }
}

impl Seek for VhdReader {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        let np: i64 = match pos {
            SeekFrom::Start(o) => o as i64,
            SeekFrom::End(o) => self.virtual_size as i64 + o,
            SeekFrom::Current(o) => self.pos as i64 + o,
        };
        if np < 0 {
            return Err(invalid("seek before start of disk"));
        }
        self.pos = np as u64;
        Ok(self.pos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn tmp(bytes: &[u8]) -> File {
        // A process-unique, monotonically-increasing id — never a pointer
        // address, which can collide across parallel test threads (identical
        // stack slots) and, on Windows, trigger a sharing violation when one
        // test still holds the file open while another re-creates the path.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = std::env::temp_dir().join(format!("vhd_unit_{}_{}.bin", std::process::id(), n));
        let mut f = File::create(&p).unwrap();
        f.write_all(bytes).unwrap();
        f.sync_all().unwrap();
        File::open(&p).unwrap()
    }

    #[test]
    fn rejects_file_smaller_than_footer() {
        let err = VhdReader::open(tmp(&[0u8; 100])).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn rejects_missing_cookie() {
        let err = VhdReader::open(tmp(&[0u8; 1024])).unwrap_err();
        assert!(err.to_string().contains("conectix"));
    }

    #[test]
    fn rejects_differencing_disk() {
        let mut footer = [0u8; 512];
        footer[0..8].copy_from_slice(b"conectix");
        footer[60..64].copy_from_slice(&4u32.to_be_bytes()); // differencing
        let mut data = vec![0u8; 512];
        data.extend_from_slice(&footer);
        let err = VhdReader::open(tmp(&data)).unwrap_err();
        assert!(err.to_string().contains("differencing"));
    }
}
