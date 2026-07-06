# disk-forensic

[![Crates.io](https://img.shields.io/crates/v/disk-forensic.svg)](https://crates.io/crates/disk-forensic)
[![docs.rs](https://img.shields.io/docsrs/disk-forensic)](https://docs.rs/disk-forensic)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/disk-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/disk-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**`disk4n6` is the fleet's universal forensic disk layer: point it at any container — E01, VMDK, VHDX, VHD, QCOW2, DMG, raw `dd`, or ISO — and it decodes the wrapper, identifies the partitioning scheme (MBR / GPT / APM), and runs the right forensic parser. Run it bare and it maps every physical disk and partition on the live system — macOS, Linux, and Windows in one unified output — with acquisition-integrity findings you need before you image.**

The library is also the foundation for the fleet's [universal forensic VFS](#architecture): a layered trait model that will let `issen`, `4n6mount`, and `disk4n6` share one open-any-image entry point rather than three parallel detection stacks.

## See it work in 30 seconds

```console
$ cargo install disk-forensic   # crate: disk-forensic, binary: disk4n6
```

**Triage the live system** — run it bare. No image to decode, no platform-specific tool to remember (`diskutil` / `sfdisk` / `fdisk` all in one):

```console
$ disk4n6
```

```text
All storage (2 physical disks, 1.1 TB total):
 disk0  [########################################################]    1.0 TB  94.1%
 disk1  [###                                                     ]   64.0 GB   5.9%

/dev/disk0  1.0 TB
[.=####################################################+.]
 .  -  free (unallocated)              24.6 KB   0.0%
 =  1  disk0s1  C12A7328-F81F-11D2-BA4B-00A0C93EC93B   536.9 MB   0.1%
 #  2  disk0s2  7C3457EF-0000-11AA-AA11-00306543ECAC     1.0 TB  99.4%
 +  3  disk0s3  52637672-7900-11AA-AA11-00306543ECAC     5.4 GB   0.5%

/dev/disk1  64.0 GB
[=#######################################################]
 =  1  disk1s1  EBD0A0A2-B9E5-4433-87C0-68B6B72699C7   200.0 MB   0.3%
 #  2  disk1s2  EBD0A0A2-B9E5-4433-87C0-68B6B72699C7    63.8 GB  99.7%

Acquisition-integrity findings:
  disk0  [HIGH] LIVE-MOUNTED: device has mounted volume(s) during acquisition; live writes may alter the image — consistent with imaging a running system
```

The overview bar scales every disk against the largest so relative sizes read at a glance; each per-disk bar lays out partitions and free space proportionally.

**Analyse an image** — hand it the evidence:

```console
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

That E01 was decoded, the protective MBR cross-checked, and the GPT parsed — one command, no intermediate files. Exit code is `0` when clean and `1` when any anomaly is present, so it drops straight into a triage pipeline. Add `--json` (build with `--features serde`) for machine-readable output in either mode.

## Live triage: one output across macOS, Linux, and Windows

Before you acquire, you need to know what's attached and whether touching it is safe. `disk4n6` enumerates the host's physical disks and partitions through the native interface on each platform — **macOS IOKit**, **Linux sysfs (`/sys/block`)**, **Windows `DeviceIoControl`** — and normalises them into one model, so the same command and the same output work everywhere. The enumeration and rendering live in [`livedisk-core`](https://crates.io/crates/livedisk-core); the acquisition findings come from [`livedisk-forensic`](https://crates.io/crates/livedisk-forensic).

The findings are observations bearing on a forensically sound acquisition — never verdicts:

| Code | Meaning |
|---|---|
| `LIVE-MOUNTED` | a volume is mounted during acquisition (live writes may alter the image) |
| `LIVE-WRITABLE` | the device **being acquired** is writable — no write-blocker engaged. Shown when you point `disk4n6` at a specific target device, not in the host overview |
| `LIVE-REMOVABLE` | removable media |
| `LIVE-SECTOR-4KN` | logical/physical sector sizes differ (512e / 4Kn) |
| `LIVE-SYNTHESIZED` | a synthesized container overlay (APFS container, device-mapper/LVM), not a backing physical store |

`LIVE-SYNTHESIZED` is informational, not a recommendation: whether to image the synthesized device or the underlying physical store is a forensic decision for the examiner, not the tool.

## Feed it almost any image — the wrapper is detected by content, not extension

`disk4n6` sniffs the container magic, decodes it to a `Read + Seek` view of the raw disk, and analyses that. Rename a `.vmdk` to `.bin` and it still works.

| Input | Handling |
|---|---|
| Raw / `dd` | analysed in place |
| **E01 / EWF** (EnCase) | decoded |
| **VMDK** (VMware) | decoded — follows snapshot/delta extent chains to the base image |
| **VHDX** (Hyper-V) | decoded |
| **VHD** (Virtual PC, fixed + dynamic) | decoded (built-in) |
| **QCOW2** (QEMU/KVM) | decoded |
| **DMG** (Apple UDIF) | decoded — pure-Rust codecs (ADC / zlib / bzip2 / LZFSE / LZMA), no C dependencies |
| **ISO 9660** (optical) | routed to filesystem analysis (see below) |
| AFF4 | recognised; decoder not yet wired |

A corrupt or unsupported-variant container fails loud with a clear decode error rather than silently producing wrong output.

## Optical media gets a filesystem report

An ISO is a filesystem, not a partitioned disk, so `disk4n6` routes it to [`iso9660-forensic`](https://github.com/SecurityRonin/iso9660-forensic) and renders the same normalized findings / provenance / timeline view — volume identity, mastering-tool fingerprint, Rock Ridge authoring owners, structural anomalies, and the reconstructed authoring window:

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

A **Timeline** section then reconstructs the volume's authoring window from the PVD and file-recorded times — on real media these diverge into a span you can reason about.

## Rust library

```toml
[dependencies]
disk-forensic = "0.9"
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

`analyse_disk` takes any `Read + Seek`, so you can feed it a raw image directly. A disk with no recognised scheme returns [`Error::UnknownScheme`] rather than mis-parsing. Each analyser normalizes into the shared [`forensicnomicon::report`](https://github.com/SecurityRonin/forensicnomicon) model, so findings and provenance render uniformly across every scheme and the ISO filesystem layer.

For live enumeration, depend on [`livedisk-core`](https://crates.io/crates/livedisk-core) directly:

```rust
for disk in livedisk::enumerate()? {
    println!("{}: {} bytes, {} partitions", disk.name, disk.size_bytes, disk.partitions.len());
}
# Ok::<(), livedisk::Error>(())
```

## The scheme parsers

`disk-forensic` is pure orchestration — it classifies the scheme using the cited magics in [`forensicnomicon`](https://github.com/SecurityRonin/forensicnomicon) and delegates every real parse to a focused, dependency-light sibling. Use them directly when you already know the scheme, or through this crate when you don't:

| Crate | Scheme |
|---|---|
| [`mbr-partition-forensic`](https://github.com/SecurityRonin/mbr-partition-forensic) | Master Boot Record — boot-code fingerprinting, gap/slack carving, per-partition VBR filesystem fingerprinting, protective-MBR/GPT detection |
| [`gpt-partition-forensic`](https://github.com/SecurityRonin/gpt-partition-forensic) | GUID Partition Table — CRC32 integrity, primary/backup reconciliation |
| [`apm-partition-forensic`](https://github.com/SecurityRonin/apm-partition-forensic) | Apple Partition Map — classic Mac and hybrid optical media |

## Architecture

`disk-forensic` is being restructured as the fleet's **universal forensic VFS** — a single open-any-image entry point shared by `issen`, `4n6mount`, and `disk4n6`, rather than three parallel detection stacks. See the [full design doc](docs/design/2026-07-06-universal-forensic-vfs.md) for the detailed specification.

### The layered model

Six transform kinds, each a trait, compose as a graph. Every transform consumes an `ImageSource` and yields either another `ImageSource` or a terminal `FileSystem`. The resolver applies them in the order the evidence requires — crypto may appear before or after volume detection depending on the image:

```
PathSpec (locator, self-describing, serde-safe)
   │ resolves (graph walk)
   ▼
ImageSource  ── positioned read_at(&self), no write, no seek cursor ──┐
   ├── ContainerDecoder  E01 / VMDK / VHDX / QCOW2 / DMG / AFF4      │
   ├── VolumeSystem      MBR / GPT / APM / VSS / APFS-container       │
   ├── CryptoLayer       BitLocker / LUKS / FileVault                  │
   └── FileSystem        NTFS / ext4 / HFS+ / APFS / ISO / FAT → FsNode
```

`ImageSource` has `read_at(&self)` — no seek cursor, no write method anywhere in the trait. That single choice delivers parallel reads across a shared stack (`&self` composes across threads; `&mut self` Seek cannot) and makes evidence read-only by construction rather than by convention.

`PathSpec` is a self-describing locator that carries the full open-recipe for an artifact. It round-trips through a report or evidence row without carrying credentials (credentials are supplied at resolve time through a `CredentialSource`, so a serialized address is safe to log).

### Development status

| Phase | Scope | Status |
|---|---|---|
| — | **Today:** container decode (E01/VMDK/VHDX/VHD/QCOW2/DMG/raw/ISO), MBR/GPT/APM parsing, live triage (macOS/Linux/Windows), ISO filesystem analysis, acquisition-integrity findings | ✅ Shipped |
| 1 | Extract `forensic-vfs-core`: `ImageSource` + adapters + `PathSpec` + `FileSystem` trait (relocate from `4n6mount`). Non-breaking re-exports during transition. | In development |
| 2 | `forensic-vfs-engine`: `Vfs::open` + registry over existing containers and schemes; per-partition filesystem mounting. | Planned |
| 3 | One issen provider replaces 8 per-format wrapper crates (ADR-0010). | Planned |
| 4 | `4n6mount` migrates onto the engine, dropping its own detect/dispatch. | Planned |
| 5 | Crypto + snapshots + nesting: `CryptoLayer` (BitLocker/LUKS/FileVault), VSS `VolumeSystem`, nested images, `TemporalCohort` snapshots. | Planned |
| 6 | In-tree trait impls per reader crate; shims deleted. | Planned |

Each phase is gated on the Case-001 Szechuan end-to-end ingest producing identical event counts and artifacts to the pre-phase baseline.

### Design properties

- **Secure by default** — one auto-detecting entry point: a caller cannot pick the wrong decoder or parser for a disk, and the zero-config path is the correct one.
- **Read-only by construction** — the `ImageSource` trait has no write method; a write is uncompilable, not merely undocumented.
- **Fails loud** — a corrupt container or unknown scheme returns a typed error with the offending bytes and offset; it never emits silently wrong output.
- **`#![forbid(unsafe_code)]`** and fuzz-tested (`cargo fuzz`) against crafted/corrupted input.
- **Validated against real images** — real EnCase/qemu/hdiutil containers and a genuine NTFS volume from a public CTF disk. See [`docs/VALIDATION.md`](docs/VALIDATION.md).

---

[Privacy Policy](https://securityronin.github.io/disk-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/disk-forensic/terms/) · © 2026 Security Ronin Ltd
