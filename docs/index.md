# disk-forensic

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

That E01 was decoded, the protective MBR cross-checked, and the GPT parsed — one command, no intermediate files. Exit code is `0` when clean and `1` when any anomaly is present, so it drops straight into a triage pipeline. Add `--json` (build with `--features serde`) for machine-readable output.

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
| **DMG** (Apple UDIF) | decoded |
| **ISO 9660** (optical) | routed to filesystem analysis |
| AFF4 | recognised, but decode to raw first — decoder not yet wired |

A corrupt or unsupported-variant container fails **loud** with a clear decode error rather than silently producing wrong output.

## Design

- **Secure by default** — one auto-detecting entry point: a caller cannot pick the wrong decoder or parser for a disk, and the zero-config path is the correct one.
- **Fails loud** — a corrupt container or unknown scheme returns a typed error; it never emits silently wrong output.
- **`#![forbid(unsafe_code)]`** and fuzz-tested (`cargo fuzz`) against crafted/corrupted input.
- **Validated against real images**, not just synthetic fixtures — real EnCase/qemu/hdiutil containers and a genuine NTFS volume from a public CTF disk. See [Validation](VALIDATION.md).
