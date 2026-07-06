# disk-forensic

**`disk4n6` is the fleet's universal forensic disk layer.** Point it at any container — E01, VMDK, VHDX, VHD, QCOW2, DMG, raw `dd`, or ISO — and it decodes the wrapper, identifies the partitioning scheme (MBR / GPT / APM), and runs the right forensic parser. Run it bare and it maps every physical disk and partition on the live system — macOS, Linux, and Windows in one unified output — with acquisition-integrity findings you need before you image.

The library is also the foundation for the fleet's [universal forensic VFS](architecture.md): a layered trait model that will let `issen`, `4n6mount`, and `disk4n6` share one open-any-image entry point rather than three parallel detection stacks.

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
| AFF4 | recognised; decoder not yet wired |

A corrupt or unsupported-variant container fails loud with a clear decode error rather than silently producing wrong output.

## Design properties

- **Secure by default** — one auto-detecting entry point: a caller cannot pick the wrong decoder or parser for a disk.
- **Read-only by construction** — the `ImageSource` trait has no write method; a write is uncompilable, not merely undocumented.
- **Fails loud** — a corrupt container or unknown scheme returns a typed error with the offending bytes; it never emits silently wrong output.
- **`#![forbid(unsafe_code)]`** and fuzz-tested (`cargo fuzz`) against crafted/corrupted input.
- **Validated against real images** — real EnCase/qemu/hdiutil containers and a genuine NTFS volume from a public CTF disk. See [Validation](VALIDATION.md).

## Architecture direction

`disk-forensic` is being restructured around a layered `ImageSource` trait that composes container decoders, volume systems, crypto layers, and filesystems as a graph — rather than a fixed decode pipeline. The design is specified and the first extraction phase (`forensic-vfs-core`) is in development. See [Architecture](architecture.md) for the layered model, crate structure, and phase-by-phase development status.
