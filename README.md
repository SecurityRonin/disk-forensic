# disk-forensic

[![Crates.io](https://img.shields.io/crates/v/disk-forensic.svg)](https://crates.io/crates/disk-forensic)
[![docs.rs](https://img.shields.io/docsrs/disk-forensic)](https://docs.rs/disk-forensic)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![CI](https://github.com/SecurityRonin/disk-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/disk-forensic/actions)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Point it at any disk image — it identifies the partitioning scheme (MBR, GPT, or Apple Partition Map) and runs the right forensic parser.** One command, one dependency, no guessing which crate to reach for.

## See it work in 30 seconds

```console
$ cargo install disk-forensic   # crate: disk-forensic, binary: disk4n6
$ disk4n6 disk.img
```

```text
Scheme: Apm

APM Forensic Analysis
  block size     : 512 bytes
  device blocks  : 6144

Partition map (2 entries):
  [0] Apple                Apple_partition_map      blocks          1..=63
  [1] disk image           Apple_HFS                blocks         64..=6143

Anomalies: none

Highest severity: none (clean)
```

Hand it an MBR disk and you get the MBR report; a GPT disk and you get the GPT
cross-check — the same binary, auto-detected. Exit code is `0` when clean and
`1` when any anomaly is present, so it drops straight into a triage pipeline.
Add `--json` (with `--features serde`) for machine-readable output.

## Why a separate crate

Each partitioning scheme has its own focused, dependency-light parser. This crate
is **pure orchestration**: it reads the boot area, classifies the scheme using the
cited magics in [`forensicnomicon`](https://github.com/SecurityRonin/forensicnomicon),
and delegates every real parse to the matching sibling. You depend on one crate
and get all three schemes; the parsers stay independently usable.

## Rust library

```toml
[dependencies]
disk-forensic = "0.1"
```

```rust
use std::fs::File;

let mut img = File::open("disk.img")?;
let size = img.metadata()?.len();

match disk_forensic::analyse_disk(&mut img, size)? {
    disk_forensic::DiskReport::Gpt(a) => println!("GPT: {} partitions", a.partitions.len()),
    disk_forensic::DiskReport::Mbr(a) => println!("MBR: {} partitions", a.partitions.len()),
    disk_forensic::DiskReport::Apm(a) => println!("APM: {} partitions", a.partitions.len()),
}
# Ok::<(), disk_forensic::Error>(())
```

It takes any `Read + Seek`, so it composes with the container crates (`ewf`,
`vhd`, `vmdk`, …) — analyse E01/VHD/VMDK evidence without first carving out a raw
image. A disk with no recognised scheme (e.g. a filesystem written directly to
the media) returns [`Error::UnknownScheme`] rather than mis-parsing.

## The scheme parsers

`disk-forensic` is the front door to three sibling crates — use them directly when
you already know the scheme, or through this crate when you don't:

| Crate | Scheme |
|---|---|
| [`mbr-forensic`](https://github.com/SecurityRonin/mbr-forensic) | Master Boot Record (legacy BIOS; also detects the protective-MBR/GPT case) |
| [`gpt-forensic`](https://github.com/SecurityRonin/gpt-forensic) | GUID Partition Table (UEFI) — CRC32 integrity, primary/backup reconciliation |
| [`apm-forensic`](https://github.com/SecurityRonin/apm-forensic) | Apple Partition Map (classic Mac and hybrid optical media) |

## Design

- **Dependency-light** — only `thiserror` plus the four sibling crates; no parsing logic of its own.
- **`#![forbid(unsafe_code)]`**, fuzz-tested (`cargo fuzz`) against crafted/corrupted input, **100% function coverage**.
- **Secure by default** — one auto-detecting entry point means a caller cannot pick the wrong parser for a disk.

---

[Privacy Policy](https://securityronin.github.io/disk-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/disk-forensic/terms/) · © 2026 Security Ronin Ltd
