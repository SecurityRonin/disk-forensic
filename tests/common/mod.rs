//! Synthetic disk-image builders for the dispatch tests.
//!
//! All images are built in memory with correct signatures/CRCs, so the tests
//! need no committed binary blobs (the APM fixture aside).

#![allow(dead_code)]

pub const SECTOR: usize = 512;
pub const SECTORS: usize = 64;

/// A minimal classic-MBR disk: one Linux partition, boot signature, no GPT.
pub fn build_mbr() -> Vec<u8> {
    let mut d = vec![0u8; SECTOR * SECTORS];
    d[510] = 0x55;
    d[511] = 0xAA;
    let e = 446;
    d[e + 4] = 0x83; // Linux
    d[e + 8..e + 12].copy_from_slice(&2u32.to_le_bytes());
    d[e + 12..e + 16].copy_from_slice(&10u32.to_le_bytes());
    d
}

fn guid_bytes(s: &str) -> [u8; 16] {
    let g: Vec<&str> = s.split('-').collect();
    let g1 = u32::from_str_radix(g[0], 16).unwrap();
    let g2 = u16::from_str_radix(g[1], 16).unwrap();
    let g3 = u16::from_str_radix(g[2], 16).unwrap();
    let g4 = u16::from_str_radix(g[3], 16).unwrap();
    let g5 = u64::from_str_radix(g[4], 16).unwrap();
    let mut b = [0u8; 16];
    b[0..4].copy_from_slice(&g1.to_le_bytes());
    b[4..6].copy_from_slice(&g2.to_le_bytes());
    b[6..8].copy_from_slice(&g3.to_le_bytes());
    b[8..10].copy_from_slice(&g4.to_be_bytes());
    b[10..16].copy_from_slice(&g5.to_be_bytes()[2..8]);
    b
}

fn gpt_entry(type_guid: &str, unique: &str, first: u64, last: u64, name: &str) -> [u8; 128] {
    let mut e = [0u8; 128];
    e[0..16].copy_from_slice(&guid_bytes(type_guid));
    e[16..32].copy_from_slice(&guid_bytes(unique));
    e[32..40].copy_from_slice(&first.to_le_bytes());
    e[40..48].copy_from_slice(&last.to_le_bytes());
    for (i, u) in name.encode_utf16().enumerate() {
        e[56 + i * 2..58 + i * 2].copy_from_slice(&u.to_le_bytes());
    }
    e
}

#[allow(clippy::too_many_arguments)]
fn gpt_header(
    my_lba: u64,
    alt_lba: u64,
    entry_lba: u64,
    first_usable: u64,
    last_usable: u64,
    num: u32,
    esize: u32,
    array_crc: u32,
) -> [u8; 512] {
    let mut s = [0u8; 512];
    s[0..8].copy_from_slice(b"EFI PART");
    s[8..12].copy_from_slice(&0x0001_0000u32.to_le_bytes());
    s[12..16].copy_from_slice(&92u32.to_le_bytes());
    s[24..32].copy_from_slice(&my_lba.to_le_bytes());
    s[32..40].copy_from_slice(&alt_lba.to_le_bytes());
    s[40..48].copy_from_slice(&first_usable.to_le_bytes());
    s[48..56].copy_from_slice(&last_usable.to_le_bytes());
    s[56..72].copy_from_slice(&guid_bytes("12345678-1234-5678-1234-567812345678"));
    s[72..80].copy_from_slice(&entry_lba.to_le_bytes());
    s[80..84].copy_from_slice(&num.to_le_bytes());
    s[84..88].copy_from_slice(&esize.to_le_bytes());
    s[88..92].copy_from_slice(&array_crc.to_le_bytes());
    let crc = gpt_partition_forensic::crc32::checksum(&s[..92]);
    s[16..20].copy_from_slice(&crc.to_le_bytes());
    s
}

/// A spec-valid GPT disk (protective MBR + primary/backup headers + array).
pub fn build_gpt() -> Vec<u8> {
    build_gpt_with("0FC63DAF-8483-4772-8E79-3D69D8477DE4", "Linux")
}

/// A spec-valid GPT disk with a single partition of the given type GUID and
/// name. An unrecognized type GUID (so `type_name()` is `None`) and an empty
/// name exercise the fallback arms that render/layout take for anonymous,
/// unknown-type partitions.
pub fn build_gpt_with(type_guid: &str, name: &str) -> Vec<u8> {
    let mut disk = vec![0u8; SECTOR * SECTORS];
    disk[450] = 0xEE; // protective MBR entry type
    disk[454..458].copy_from_slice(&1u32.to_le_bytes());
    disk[458..462].copy_from_slice(&((SECTORS - 1) as u32).to_le_bytes());
    disk[510] = 0x55;
    disk[511] = 0xAA;

    let mut array = vec![0u8; 4 * 128];
    array[0..128].copy_from_slice(&gpt_entry(
        type_guid,
        "00000000-0000-0000-0000-000000000001",
        3,
        30,
        name,
    ));
    let array_crc = gpt_partition_forensic::crc32::checksum(&array);
    let primary = gpt_header(1, 63, 2, 3, 61, 4, 128, array_crc);
    let backup = gpt_header(63, 1, 62, 3, 61, 4, 128, array_crc);
    disk[SECTOR..SECTOR + 512].copy_from_slice(&primary);
    disk[2 * SECTOR..2 * SECTOR + array.len()].copy_from_slice(&array);
    disk[62 * SECTOR..62 * SECTOR + array.len()].copy_from_slice(&array);
    disk[63 * SECTOR..63 * SECTOR + 512].copy_from_slice(&backup);
    disk
}
