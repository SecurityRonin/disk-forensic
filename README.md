# disk-forensic

[![Crates.io](https://img.shields.io/crates/v/disk-forensic.svg)](https://crates.io/crates/disk-forensic)
[![docs.rs](https://img.shields.io/docsrs/disk-forensic)](https://docs.rs/disk-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/disk-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/disk-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Point `disk4n6` at any disk image or forensic container — E01, VMDK, VHDX, VHD, QCOW2, DMG, raw `dd`, or an ISO — and it decodes the wrapper, identifies the partitioning scheme (MBR / GPT / APM), and runs the right forensic parser.** No carving out a raw image first, no guessing which tool to reach for.

## See it work in 30 seconds

```console
$ cargo install disk-forensic   # crate: disk-forensic, binary: disk4n6
$ disk4n6 evidence.E01          # an EnCase image straight off the shelf
```

```text
Scheme: Gpt

MBR Forensic Analysis
  disk signature : 0x00000000
  boot code      : AllZeros
  partitioning   : Unknown

Partition table (1 entries):
  [0] GPT Protective MBR       LBA            1..=409599        fs=Unknown

GPT cross-check: 131 GPT partition entries

GPT Forensic Analysis
================================================================================
Disk GUID:       9D71FE48-F2FB-43F1-9326-36644D4D4E70
Revision:        1.0
```

That E01 was decoded, the protective MBR cross-checked, and the GPT parsed — one
command, no intermediate files. Exit code is `0` when clean and `1` when any
anomaly is present, so it drops straight into a triage pipeline. Add `--json`
(build with `--features serde`) for machine-readable output.

## Feed it almost any image — the wrapper is detected by content, not extension

`disk4n6` sniffs the container magic, decodes it to a `Read + Seek` view of the
raw disk, and analyses that. Rename a `.vmdk` to `.bin` and it still works.

| Input | Handling |
|---|---|
| Raw / `dd` | analysed in place |
| **E01 / EWF** (EnCase) | decoded |
| **VMDK** (VMware) | decoded — follows snapshot/delta extent chains to the base image |
| **VHDX** (Hyper-V) | decoded |
| **VHD** (Virtual PC, fixed + dynamic) | decoded (built-in) |
| **QCOW2** (QEMU/KVM) | decoded |
| **DMG** (Apple UDIF) | decoded |
| **ISO 9660** (optical) | routed to filesystem analysis (see below) |
| AFF4 | recognised, but decode to raw first — decoder not yet wired |

A corrupt or unsupported-variant container fails **loud** with a clear decode
error rather than silently producing wrong output.

## Optical media gets a filesystem report

An ISO is a filesystem, not a partitioned disk, so `disk4n6` routes it to
[`iso9660-forensic`](https://github.com/SecurityRonin/iso9660-forensic) and
renders the same normalized findings / provenance / **timeline** view — volume
identity, mastering-tool fingerprint, Rock Ridge authoring owners, structural
anomalies, and the reconstructed authoring window:

```console
$ disk4n6 image.iso
```

```text
Filesystem: ISO 9660

Findings: none (clean)

Provenance:
  volume label: DFTEST  (iso9660-forensic)
  system identifier: APPLE INC., TYPE: 0002  (iso9660-forensic)
  sector mode: Iso2048  (iso9660-forensic)
  extensions: Rock Ridge: true, Joliet: true  (iso9660-forensic)
  sessions: 1  (iso9660-forensic)
  Rock Ridge owners: uids [501], gids [0]  (iso9660-forensic)
```

A **Timeline** section then reconstructs the volume's authoring window from the
PVD and file-recorded times — on real media these diverge into a span you can
reason about (a file dated *after* its own volume, or in the future, becomes a
finding).

## Rust library

```toml
[dependencies]
disk-forensic = "0.5"
```

```rust
use std::fs::File;

// Decode whatever container the evidence arrived in, then analyse the disk.
let opened = disk_forensic::container::open(std::path::Path::new("evidence.E01"))?;
let mut img = opened.reader;

match disk_forensic::analyse_disk(&mut img, opened.size)? {
    disk_forensic::DiskReport::Gpt(a) => println!("GPT: {} partitions", a.partitions.len()),
    disk_forensic::DiskReport::Mbr(a) => println!("MBR: {} partitions", a.partitions.len()),
    disk_forensic::DiskReport::Apm(a) => println!("APM: {} partitions", a.partitions.len()),
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

`analyse_disk` takes any `Read + Seek`, so you can also feed it a raw image
directly. A disk with no recognised scheme (e.g. a filesystem written straight to
the media) returns [`Error::UnknownScheme`] rather than mis-parsing. Each
analyzer normalizes into the shared
[`forensicnomicon::report`](https://github.com/SecurityRonin/forensicnomicon)
model, so findings and provenance render uniformly across every scheme and the
ISO filesystem layer.

## The scheme parsers

`disk-forensic` is pure orchestration — it classifies the scheme using the cited
magics in [`forensicnomicon`](https://github.com/SecurityRonin/forensicnomicon)
and delegates every real parse to a focused, dependency-light sibling. Use them
directly when you already know the scheme, or through this crate when you don't:

| Crate | Scheme |
|---|---|
| [`mbr-partition-forensic`](https://github.com/SecurityRonin/mbr-partition-forensic) | Master Boot Record — boot-code fingerprinting, gap/slack carving, **per-partition VBR filesystem fingerprinting**, protective-MBR/GPT detection |
| [`gpt-partition-forensic`](https://github.com/SecurityRonin/gpt-partition-forensic) | GUID Partition Table — CRC32 integrity, primary/backup reconciliation |
| [`apm-partition-forensic`](https://github.com/SecurityRonin/apm-partition-forensic) | Apple Partition Map — classic Mac and hybrid optical media |

## Design

- **Secure by default** — one auto-detecting entry point: a caller cannot pick the wrong decoder or parser for a disk, and the zero-config path is the correct one.
- **Fails loud** — a corrupt container or unknown scheme returns a typed error; it never emits silently wrong output.
- **`#![forbid(unsafe_code)]`** and fuzz-tested (`cargo fuzz`) against crafted/corrupted input.
- **Validated against real images**, not just synthetic fixtures — real EnCase/qemu/hdiutil containers and a genuine NTFS volume from a public CTF disk. See [`docs/VALIDATION.md`](docs/VALIDATION.md).

---

[Privacy Policy](https://securityronin.github.io/disk-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/disk-forensic/terms/) · © 2026 Security Ronin Ltd
