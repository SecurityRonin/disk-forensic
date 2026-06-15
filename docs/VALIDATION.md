# Validation

`disk-forensic` is validated against **real images produced by real tools**, not
only synthetic fixtures — the doer/checker discipline: code you validated only
with fixtures you hand-built inherits your own blind spots. Where a third-party
decoder crate does the work, its output was byte-exact verified (boot signature
*and* a marker planted deep in the disk) through that crate before it was wired
into `open()`.

All fixtures live in [`tests/data/`](https://github.com/SecurityRonin/disk-forensic/tree/main/tests/data) and the assertions are in
[`tests/open_tests.rs`](https://github.com/SecurityRonin/disk-forensic/blob/main/tests/open_tests.rs) and
[`tests/cli_tests.rs`](https://github.com/SecurityRonin/disk-forensic/blob/main/tests/cli_tests.rs). Run `cargo test --all-features`.

## Container decoders

Each container fixture wraps the **same known MBR disk** (a 1 MiB image with a
recognisable marker at sector 100), produced from a raw image with the tool a
real examiner would encounter, then decoded back and checked.

| Format | Fixture | How produced | Decoder | Asserted |
|---|---|---|---|---|
| Raw / `dd` | `apm.bin` | committed | in-place | scheme parses |
| E01 / EWF | `gpt_130_partitions.E01` | **real EnCase image** (130-partition GPT) | `ewf` | decodes → `Scheme::Gpt` |
| VMDK | `df.vmdk` | `qemu-img convert -O vmdk` (monolithicSparse) | `vmdk` | decodes → `Scheme::Mbr`, virtual size exact |
| QCOW2 | `df.qcow2` | `qemu-img convert -O qcow2` (v3) | `qcow` | decodes → `Scheme::Mbr`, virtual size exact |
| VHDX | `df.vhdx` | `qemu-img convert -O vhdx` | `vhdx` | decodes → `Scheme::Mbr`, virtual size exact |
| VHD (dynamic) | `df-dynamic.vhd` | `qemu-img convert -O vpc` | built-in (`src/vhd.rs`) | decodes → `Scheme::Mbr`, CHS-rounded size |
| VHD (fixed) | `df-fixed.vhd` | `qemu-img convert -O vpc -o subformat=fixed` | built-in (`src/vhd.rs`) | decodes → `Scheme::Mbr`, CHS-rounded size |
| DMG | `df.dmg` | `hdiutil convert -format UDZO` | `udif` | decodes → `Scheme::Mbr` |
| ISO 9660 | `df.iso` | `hdiutil makehybrid -iso -joliet` | `iso9660-forensic` | volume label + clean exit |
| AFF4 | — | n/a | none yet | recognised → `OpenError::Unsupported` (synthetic magic) |

The VHD virtual size is qemu's CHS-geometry-rounded value (1 079 296 bytes, not
1 MiB) — the test asserts the **real** value observed in the footer, a concrete
example of why synthetic-only assumptions are unsafe.

## Real NTFS, end to end

`tests/data/ntfs.vmdk` carries a **genuine NTFS boot region** — the real
`$Boot`/BPB (OEM `"NTFS    "`) extracted from `MaxPowersCDrive.E01` of the
public **DEF CON DFIR CTF 2018** image — re-based onto a compact 64 MiB disk with
real Windows MBR boot code and wrapped in a sparse VMDK (192 KiB). Only the BPB
`hidden_sectors`/`total_sectors` were adjusted so the geometry stays
self-consistent with the compact layout.

`vmdk_with_real_ntfs_fingerprints_the_partition` asserts the whole stack on real
data: **VMDK decode → MBR parse → the partition fingerprints as
`DetectedFs::Ntfs`** (filesystem identified from its real VBR, not the partition
type byte alone).

This validates filesystem fingerprinting at the partition level. `disk-forensic`
does not parse NTFS internals (`$MFT`, etc.) — that is a filesystem analyzer's
job — so the fixture is a boot-region slice, not a fully mountable volume.

## Report normalization

Every layer is normalized into the shared
[`forensicnomicon::report`](https://github.com/SecurityRonin/forensicnomicon)
model (`Report { findings, provenance, timeline }`), categorized with the
canonical `Category::from_code`, so disk4n6 renders one uniform view.

| Layer | Findings | Provenance | Timeline | Finding evidence offset |
|---|---|---|---|---|
| MBR | ✅ | ✅ | — (no datable events) | ✅ (`offset`) |
| GPT | ✅ | ✅ | — (no datable events) | ✗ — analyzer exposes no uniform offset |
| APM | ✅ | ✅ | — (no datable events) | ✗ — analyzer exposes no uniform offset |
| ISO 9660 | ✅ | ✅ (full volume + Rock Ridge authoring intel) | ✅ (PVD create/modify + authoring window) | ✗ — offsets are per-`AnomalyKind` |

`tests/iso_normalize_tests.rs` checks the ISO provenance completeness and the
reconstructed timeline against the real `df.iso` volume (system/mastering id,
session count, Rock Ridge owners, and the create/authoring-window events),
asserting timeline events by **structure** — present, attributed, and datable
(`when.is_some()`) — never by literal timestamp value.

**Known boundary:** uniform per-finding byte-offset evidence is only produced for
MBR, because only `mbr-forensic` exposes a top-level `Anomaly.offset`. GPT/APM/ISO
bury offsets inside individual `AnomalyKind` variants; surfacing them uniformly
requires those analyzer crates to expose an offset, not a per-variant match here.

## Safety properties

- `#![forbid(unsafe_code)]` (enforced via `[lints.rust]`).
- Fuzz target (`cargo fuzz`, `fuzz/fuzz_targets/analyse_disk.rs`) exercises
  `analyse_disk` against crafted/corrupted input.
- Corrupt or unsupported-variant containers fail with a typed
  `OpenError::Decode` rather than producing silently wrong output; a legacy
  QCOW1 and a VHD differencing disk are rejected explicitly.
