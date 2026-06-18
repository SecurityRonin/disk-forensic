//! Pure parsing of Windows' `DRIVE_LAYOUT_INFORMATION_EX` byte buffer (the
//! `IOCTL_DISK_GET_DRIVE_LAYOUT_EX` result) into partition records.
//!
//! Offsets are fixed by the `#[repr(C)]` structs in `windows-sys`
//! (`Windows::Win32::System::Ioctl`): the `PartitionEntry` array starts at byte
//! 48, and each `PARTITION_INFORMATION_EX` is 144 bytes — `StartingOffset` at
//! +8, `PartitionLength` at +16, `PartitionNumber` at +24, the GPT type GUID at
//! +32 and GPT name (`[u16; 36]`) at +72, or the MBR type byte at +32. Parsing
//! the raw bytes (rather than transmuting the struct) keeps this safe and
//! host-independent, so the tests run anywhere; only the `DeviceIoControl` call
//! that fills the buffer is Windows-gated in `windows`.

/// Byte offset of the first `PARTITION_INFORMATION_EX` in the layout buffer.
const PARTITION_ENTRY_OFFSET: usize = 48;
/// Size of one `PARTITION_INFORMATION_EX`.
const ENTRY_SIZE: usize = 144;
/// `PARTITION_STYLE` discriminants.
const STYLE_MBR: u32 = 0;
const STYLE_GPT: u32 = 1;

/// One partition decoded from the layout buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ParsedPartition {
    /// `PartitionNumber`.
    pub number: u32,
    /// `StartingOffset` in bytes.
    pub start_offset: u64,
    /// `PartitionLength` in bytes.
    pub length: u64,
    /// GPT type GUID (canonical string) or MBR type byte (`0xNN`).
    pub type_desc: Option<String>,
    /// GPT partition name, when non-empty.
    pub name: Option<String>,
}

/// The decoded drive layout: partition style plus its non-empty partitions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ParsedLayout {
    /// `PartitionStyle` (0 = MBR, 1 = GPT, 2 = RAW).
    pub style: u32,
    /// Partitions with a non-zero length, in table order.
    pub partitions: Vec<ParsedPartition>,
}

/// Parse a `DRIVE_LAYOUT_INFORMATION_EX` buffer. Empty (zero-length) slots —
/// e.g. unused MBR table entries — are skipped.
pub(super) fn parse_drive_layout(buf: &[u8]) -> ParsedLayout {
    if buf.len() < 8 {
        return ParsedLayout {
            style: u32::MAX,
            partitions: Vec::new(),
        };
    }
    let style = u32_le(buf, 0);
    let count = u32_le(buf, 4) as usize;
    let mut partitions = Vec::new();
    for i in 0..count {
        let e = PARTITION_ENTRY_OFFSET + i * ENTRY_SIZE;
        if e + ENTRY_SIZE > buf.len() {
            break;
        }
        let entry = &buf[e..e + ENTRY_SIZE];
        let length = i64_le(entry, 16).max(0) as u64;
        if length == 0 {
            continue;
        }
        let (type_desc, name) = match style {
            STYLE_GPT => {
                let name = utf16_name(&entry[72..144]);
                (
                    Some(format_guid(&entry[32..48])),
                    (!name.is_empty()).then_some(name),
                )
            }
            STYLE_MBR => {
                let ty = entry[32];
                if ty == 0 {
                    continue;
                }
                (Some(format!("0x{ty:02X}")), None)
            }
            _ => (None, None),
        };
        partitions.push(ParsedPartition {
            number: u32_le(entry, 24),
            start_offset: i64_le(entry, 8).max(0) as u64,
            length,
            type_desc,
            name,
        });
    }
    ParsedLayout { style, partitions }
}

/// Format a 16-byte little-endian Windows GUID as its canonical uppercase
/// string (`EBD0A0A2-B9E5-4433-87C0-68B6B72699C7`).
fn format_guid(b: &[u8]) -> String {
    format!(
        "{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        u32_le(b, 0),
        u16_le(b, 4),
        u16_le(b, 6),
        b[8],
        b[9],
        b[10],
        b[11],
        b[12],
        b[13],
        b[14],
        b[15],
    )
}

fn u16_le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32_le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn i64_le(b: &[u8], o: usize) -> i64 {
    i64::from_le_bytes(b[o..o + 8].try_into().expect("8 bytes"))
}

/// Decode a UTF-16LE region up to the first NUL, trimmed.
fn utf16_name(b: &[u8]) -> String {
    let units: Vec<u16> = b
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .take_while(|&u| u != 0)
        .collect();
    String::from_utf16_lossy(&units).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Basic Data Partition type GUID, in on-disk mixed-endian byte order.
    const BASIC_DATA: [u8; 16] = [
        0xA2, 0xA0, 0xD0, 0xEB, 0xE5, 0xB9, 0x33, 0x44, 0x87, 0xC0, 0x68, 0xB6, 0xB7, 0x26, 0x99,
        0xC7,
    ];

    fn put_u32(b: &mut [u8], o: usize, v: u32) {
        b[o..o + 4].copy_from_slice(&v.to_le_bytes());
    }
    fn put_i64(b: &mut [u8], o: usize, v: i64) {
        b[o..o + 8].copy_from_slice(&v.to_le_bytes());
    }

    fn one_entry_buf(style: u32) -> Vec<u8> {
        let mut b = vec![0u8; PARTITION_ENTRY_OFFSET + ENTRY_SIZE];
        put_u32(&mut b, 0, style); // PartitionStyle
        put_u32(&mut b, 4, 1); // PartitionCount
        let e = PARTITION_ENTRY_OFFSET;
        put_u32(&mut b, e, style); // entry PartitionStyle
        put_i64(&mut b, e + 8, 1_048_576); // StartingOffset
        put_i64(&mut b, e + 16, 256 * 1024 * 1024); // PartitionLength
        put_u32(&mut b, e + 24, 1); // PartitionNumber
        b
    }

    #[test]
    fn format_guid_canonical_uppercase() {
        assert_eq!(
            format_guid(&BASIC_DATA),
            "EBD0A0A2-B9E5-4433-87C0-68B6B72699C7"
        );
    }

    #[test]
    fn parse_gpt_partition_with_type_and_name() {
        let mut b = one_entry_buf(STYLE_GPT);
        let e = PARTITION_ENTRY_OFFSET;
        b[e + 32..e + 48].copy_from_slice(&BASIC_DATA); // GPT type GUID
        for (i, u) in "Basic".encode_utf16().enumerate() {
            let o = e + 72 + i * 2;
            b[o..o + 2].copy_from_slice(&u.to_le_bytes());
        }
        let layout = parse_drive_layout(&b);
        assert_eq!(layout.style, STYLE_GPT);
        assert_eq!(layout.partitions.len(), 1);
        let p = &layout.partitions[0];
        assert_eq!(p.number, 1);
        assert_eq!(p.start_offset, 1_048_576);
        assert_eq!(p.length, 256 * 1024 * 1024);
        assert_eq!(
            p.type_desc.as_deref(),
            Some("EBD0A0A2-B9E5-4433-87C0-68B6B72699C7")
        );
        assert_eq!(p.name.as_deref(), Some("Basic"));
    }

    #[test]
    fn parse_mbr_partition_type_byte() {
        let mut b = one_entry_buf(STYLE_MBR);
        let e = PARTITION_ENTRY_OFFSET;
        b[e + 32] = 0x07; // NTFS/exFAT MBR type
        let layout = parse_drive_layout(&b);
        assert_eq!(layout.style, STYLE_MBR);
        assert_eq!(layout.partitions.len(), 1);
        assert_eq!(layout.partitions[0].type_desc.as_deref(), Some("0x07"));
        assert_eq!(layout.partitions[0].name, None);
    }

    #[test]
    fn parse_skips_empty_slots() {
        // MBR style, count 4, only entry 0 populated → 1 partition returned.
        let mut b = vec![0u8; PARTITION_ENTRY_OFFSET + 4 * ENTRY_SIZE];
        put_u32(&mut b, 0, STYLE_MBR);
        put_u32(&mut b, 4, 4);
        let e = PARTITION_ENTRY_OFFSET;
        put_i64(&mut b, e + 16, 100 * 1024 * 1024); // entry 0 length
        b[e + 32] = 0x0c;
        let layout = parse_drive_layout(&b);
        assert_eq!(layout.partitions.len(), 1);
    }

    #[test]
    fn parse_truncated_buffer_is_safe() {
        // Claims 4 partitions but only holds bytes for the header → no panic.
        let mut b = vec![0u8; PARTITION_ENTRY_OFFSET];
        put_u32(&mut b, 0, STYLE_GPT);
        put_u32(&mut b, 4, 4);
        let layout = parse_drive_layout(&b);
        assert!(layout.partitions.is_empty());
    }

    #[test]
    fn utf16_name_stops_at_nul_and_trims() {
        let mut bytes = Vec::new();
        for u in "EFI ".encode_utf16() {
            bytes.extend_from_slice(&u.to_le_bytes());
        }
        bytes.extend_from_slice(&[0, 0, 0x41, 0]); // NUL then stray 'A'
        assert_eq!(utf16_name(&bytes), "EFI");
    }
}
