# disk-forensic

[![Crates.io](https://img.shields.io/crates/v/disk-forensic.svg)](https://crates.io/crates/disk-forensic)
[![docs.rs](https://img.shields.io/docsrs/disk-forensic)](https://docs.rs/disk-forensic)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/disk-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/disk-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**`disk4n6` is the fleet's universal forensic disk layer: point it at any container — E01, VMDK, VHDX, VHD, QCOW2, DMG, raw `dd`, or ISO — and it decodes the wrapper, identifies the partitioning scheme (MBR / GPT / APM), and runs the right forensic parser. Run it bare and it maps every physical disk and partition on the live system — macOS, Linux, and Windows in one unified output — with acquisition-integrity findings you need before you image.**

The library is also the foundation for the fleet's [universal forensic VFS](#architecture): a layered trait model that lets `issen`, [`4n6mount`](https://github.com/SecurityRonin/4n6mount), and `disk4n6` share one open-any-image entry point instead of three parallel detection stacks.

## [`4n6mount`](https://github.com/SecurityRonin/4n6mount) — mount any image as a filesystem

[`4n6mount`](https://github.com/SecurityRonin/4n6mount) FUSE-mounts any image `disk-forensic` can open, so evidence becomes a normal read-only directory. It walks E01 · VMDK · VHDX · QCOW2 · DMG, through MBR / GPT / APM partitions, past BitLocker / LUKS / FileVault encryption, into NTFS / ext4 / APFS / XFS / …, then exposes the resolved filesystem as a directory you can `ls`, `grep`, and `cat` — and point any tool at. One `mount` covers every format on every OS. The four VFS contracts exist so one engine drives this for all three front-ends.

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

### Universal container abstraction — `container::open`

One call sniffs the container magic, decodes the wrapper, and hands back a uniform `Read + Seek` view of the raw disk. The caller never names a format:

```rust
use disk_forensic::container::{self, OpenedImage};

let img: OpenedImage = container::open(std::path::Path::new("evidence.E01"))?;
// img.format : ContainerFormat   — which wrapper was detected
// img.size   : u64               — decoded media size in bytes
// img.reader : Box<dyn ReadSeek>  — a Read + Seek view of the raw disk
let mut disk = img.reader;
# Ok::<(), Box<dyn std::error::Error>>(())
```

`ReadSeek` is `Read + Seek`, blanket-impl'd for every reader, so a decoded EWF/VMDK/QCOW2 reader and a plain raw `File` box into the same `Box<dyn ReadSeek>`. Need only the classification? `container::sniff(&mut reader)` (or the pure `container::detect(header, footer)`) returns the detected `ContainerFormat` without decoding.

| Container | `container::open` behaviour |
|---|---|
| Raw / `dd` | passed through in place |
| E01 / EWF (EnCase) | decoded |
| VMDK (VMware) | decoded — follows snapshot/delta extent chains to the base image |
| VHDX (Hyper-V) | decoded |
| VHD (Virtual PC, fixed + dynamic) | decoded |
| QCOW2 (QEMU/KVM) | decoded |
| DMG (Apple UDIF) | decoded — pure-Rust ADC / zlib / bzip2 / LZFSE / LZMA codecs |
| ISO 9660 (optical) | passed through to the filesystem analyser (a filesystem, not a partitioned disk) |
| AFF4 (physical) | decoded — an `aff4:ImageStream` / `aff4:Map` image opens as a `Read + Seek` disk view |
| AFF4 (logical) / AD1 | **logical file containers, not disks** — `container::open` refuses them with `OpenError::LogicalContainer`; open them with `disk_forensic::logical::open` |

A corrupt or unsupported-variant container fails loud with `OpenError::Decode`; a logical file container (AD1, or an AFF4-Logical `aff4:FileImage` collection) returns `OpenError::LogicalContainer` naming `logical::open`. There is no silent wrong-output path.

##### Logical containers

Some evidence is a *file tree*, not a raw disk: AccessData **AD1** (FTK “Custom Content Image”) and **AFF4-Logical** (`aff4:FileImage`). These have no partition table, so they live in `disk_forensic::logical` rather than `container::open`:

```rust
let mut img = disk_forensic::logical::open(std::path::Path::new("evidence.ad1"))?;
for e in img.entries() {                     // LogicalEntry: path, is_dir, size
    if !e.is_dir { /* img.read_file(index) → the file's bytes */ }
}
# Ok::<(), Box<dyn std::error::Error>>(())
```

#### Two layers: containers, then volumes and filesystems

`disk-forensic::container` opens the **container** — the wrapper down to raw disk bytes as `Read + Seek`. Mounting **volumes and filesystems** over those bytes belongs to [`forensic-vfs`](https://github.com/SecurityRonin/forensic-vfs) and its engine, which compose the full stack behind one `Arc<dyn ImageSource>` (e.g. `E01 → GPT → BitLocker → NTFS`). The pipeline:

- image file
- → `container::open` → `Read + Seek` / `ImageSource` (raw disk bytes)
- → volume system (MBR / GPT / APM)
- → filesystem (NTFS / ext4 / APFS / HFS+ / FAT / ISO)
- → files

`disk-forensic` itself parses the volume layer (MBR/GPT/APM) and the ISO filesystem; [`forensic-vfs`](https://github.com/SecurityRonin/forensic-vfs) defines the `ImageSource` byte-edge plus the volume/crypto/filesystem traits, and `forensic-vfs-engine` composes the concrete readers (NTFS/ext4/APFS/HFS+/FAT/…) into a `Vfs::open(path) → Evidence` walk.

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

`disk-forensic` is one of three front-ends over the fleet's universal forensic VFS — a single open-any-image entry point shared by `issen`, `4n6mount`, and `disk4n6`, instead of three parallel detection stacks. The stack is three tiers: the published [`forensic-vfs`](https://crates.io/crates/forensic-vfs) contract leaf (0.3 — the four trait contracts plus the generic `Registry::resolve` resolver), the `forensic-vfs-engine` orchestration library that wires in the concrete readers, and the front-ends on top.

[`docs/architecture.md`](docs/architecture.md) is the source of truth: the four-component crate breakdown, the layered `ImageSource` model, and the phase-by-phase status. The [full design doc](docs/design/2026-07-06-universal-forensic-vfs.md) carries the detailed specification.

### Design properties

- **Secure by default** — one auto-detecting entry point: a caller cannot pick the wrong decoder or parser for a disk, and the zero-config path is the correct one.
- **Read-only by construction** — the `ImageSource` trait has no write method; a write is uncompilable, not merely undocumented.
- **Fails loud** — a corrupt container or unknown scheme returns a typed error with the offending bytes and offset; it never emits silently wrong output.
- **`#![forbid(unsafe_code)]`** and fuzz-tested (`cargo fuzz`) against crafted/corrupted input.
- **Validated against real images** — real EnCase/qemu/hdiutil containers and a genuine NTFS volume from a public CTF disk. See [`docs/VALIDATION.md`](docs/VALIDATION.md).

---

[Privacy Policy](https://securityronin.github.io/disk-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/disk-forensic/terms/) · © 2026 Security Ronin Ltd
