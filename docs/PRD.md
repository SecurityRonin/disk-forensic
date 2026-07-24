# disk-forensic — Product Requirements

*Reverse-written from the shipped code, README, and git history (same-session read
of `src/`, `Cargo.toml`, and `docs/` on 2026-07-24). Every current-state claim is
grounded in the tree; the load-bearing decisions live as ADRs
[0001](decisions/0001-universal-auto-detecting-container-abstraction.md)–[0008](decisions/0008-application-msrv-tracks-pinned-toolchain.md)
under [`docs/decisions/`](decisions/). The shared filesystem-VFS story is the
companion [forensic-vfs PRD](https://github.com/SecurityRonin/forensic-vfs/blob/main/docs/PRD.md);
this document covers `disk-forensic`'s own role and the `disk4n6` product.*

## Executive Summary

`disk4n6` is a forensic examiner's first-touch disk tool. Point it at any disk
image — E01, VMDK, VHDX, VHD, QCOW2, DMG, raw `dd`, physical AFF4, or ISO — and it
decodes the wrapper by content (not extension), identifies the partitioning scheme
(MBR / GPT / APM), and runs the right forensic parser, in one command with no
intermediate files. Run it bare and it maps every physical disk and partition on
the live host — macOS, Linux, and Windows in one unified output — with
acquisition-integrity findings the examiner needs *before* imaging.

The single binary is `disk4n6`; the library crate `disk-forensic` exposes the same
capability programmatically (`container::open`, `analyse_disk`) and is one of three
front-ends — with `issen` and `4n6mount` — over the fleet's universal container
entry point, so the fleet has one container-decode stack, not three.

Two design commitments carry the product: **secure by default** (one
auto-detecting entry point, so a caller cannot choose the wrong decoder) and
**fail loud** (a corrupt container or unknown scheme returns a typed error with the
offending bytes, never silent wrong output).

## 1. Problem

A disk arrives as evidence and the examiner must answer, quickly and defensibly:
what container is this, what partitioning scheme does it use, and is anything
structurally anomalous? The status quo forces a chain of format-specific tools
(`ewfmount` → `mmls` → a scheme-specific parser), each with its own invocation,
and each a chance to pick the wrong decoder for a mislabeled file. Before imaging
a live machine, the examiner also needs a cross-platform view of attached storage
and whether touching it is safe — today that means `diskutil` on macOS, `lsblk` /
`fdisk` on Linux, and a different tool again on Windows.

## 2. Users and use cases

- **DFIR / forensic analyst** — receives a disk image, wants immediate scheme
  identification and structural findings without a multi-tool pipeline; triages a
  live system before acquisition.
- **Incident responder** — runs `disk4n6` bare on a running host to enumerate
  physical disks and surface acquisition risks (mounted volumes, no write-blocker,
  removable media, 4Kn geometry).
- **Fleet tooling (`issen`, `4n6mount`)** — link `disk-forensic` as a library for
  the shared `container::open` / `logical::open` entry point.

## 3. What it does

- **Container decode** — auto-detects and decodes E01/EWF, VMDK (following
  snapshot/delta extent chains), VHDX, VHD (fixed + dynamic), QCOW2, DMG (pure-Rust
  ADC/zlib/bzip2/LZFSE/LZMA), and physical AFF4 to a `Read + Seek` view of the raw
  disk; raw/`dd` is analysed in place; a compression-wrapped image is peeled first
  (ADR 1, ADR 4).
- **Volume-system parsing** — MBR / GPT / APM, each delegated to a focused sibling
  analyzer (ADR 2).
- **ISO 9660 filesystem analysis** — optical media is routed to `iso9660-forensic`
  and rendered in the same findings/provenance/timeline view.
- **Logical file containers** — AD1, AFF4-Logical, and DAR archives are file trees,
  opened via `logical::open` and refused with a typed error by `container::open`
  (ADR 5).
- **Live triage** — host physical-disk / partition enumeration across
  macOS (IOKit) / Linux (sysfs) / Windows (`DeviceIoControl`), with a proportional
  partition-layout view, plus acquisition-integrity findings (ADR 3).
- **Uniform reporting** — every scheme and container finding normalizes into the
  shared `forensicnomicon::report` model; text by default, JSON with
  `--features serde` (ADR 6). Exit code `0` clean, `1` on any anomaly.

## 4. Scope

- Container detection and decode to a raw-disk byte stream.
- Volume-system (MBR/GPT/APM) detection, dispatch, and normalized reporting.
- ISO 9660 filesystem-level analysis (routed).
- Logical-container enumeration and byte-exact file reads (AD1 / AFF4-Logical /
  DAR).
- Live host disk enumeration and acquisition-integrity findings.
- A single `disk4n6` binary plus a `disk-forensic` library API.

## 5. Non-goals

- **No filesystem parsing beyond ISO routing.** Mounting volumes and filesystems
  (NTFS/ext4/APFS/HFS+/FAT) over the decoded bytes belongs to `forensic-vfs` and
  `forensic-vfs-engine`; `disk-forensic` parses only the volume layer and the ISO
  filesystem.
- **No partition-parsing algorithms in-repo.** Every real parse is delegated to a
  sibling analyzer (ADR 2).
- **No `unsafe` in this crate.** All OS FFI lives in `livedisk-core` (ADR 3).
- **No writes to evidence.** The read path is `Read + Seek`; there is no write
  method to call.
- **No verdicts.** Acquisition and structural findings are observations
  ("consistent with"), never legal conclusions (ADR 6).

## 6. Artifact family

Container wrappers (E01/EWF, VMDK, VHDX, VHD, QCOW2, DMG, physical AFF4, raw/dd),
compression wrappers (peeled via `archive-core`), volume systems (MBR, GPT, Apple
Partition Map), the ISO 9660 optical filesystem, logical evidence archives (AD1,
AFF4-Logical, DAR), and live host block devices on macOS / Linux / Windows.

## 7. Validation approach

- **Real-artifact validation** — `container::open` / `analyse_disk` are validated
  against real EnCase / qemu / hdiutil containers and a genuine NTFS volume from a
  public CTF disk, documented in [`docs/VALIDATION.md`](VALIDATION.md) and the
  per-format entries in [`docs/validation-inventory.md`](validation-inventory.md).
- **Fuzzing** — `cargo fuzz` targets over the detect/dispatch seam
  (`fuzz/fuzz_targets/{sniff,container_open,analyse_disk}.rs`) drive crafted /
  corrupted input; the crate is `#![forbid(unsafe_code)]`.
- **Fail-loud contract** — corrupt or unsupported-variant containers return
  `OpenError::Decode`; a logical container returns `OpenError::LogicalContainer`;
  an unrecognized scheme returns `Error::UnknownScheme`. There is no silent
  wrong-output path.
- **Umbrella-map gate** — as the umbrella orchestrator/registry, a CI `umbrella-map`
  job asserts every reader listed in `docs/umbrella-members.txt` is registered in
  the validation inventory, and `mkdocs build --strict` catches dangling links
  (see [`CLAUDE.md`](../CLAUDE.md)).

## 8. Distribution

`disk4n6` ships as a standalone binary for macOS / Linux / Windows plus Homebrew,
apt (Cloudsmith), and winget, driven by a signed `v[0-9]*` tag; the `disk-forensic`
library publishes to crates.io via release-plz. The CLI supports the conventional
`-V` / `--version`. See the fleet release SOP for the pipeline.
