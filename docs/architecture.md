# Architecture — disk-forensic (a VFS consumer)

`disk-forensic` / `disk4n6` is the analyst-facing disk tool. It owns
`container::open` — the content-sniffing container-decode entry point that `issen`,
`4n6mount`, and `disk4n6` share for raw-disk evidence, so there is one container
stack, not three. The complementary *filesystem*-VFS story — the layered `*Open`
model and the reader fleet — is `forensic-vfs` (below). Consolidating disk-forensic's
general open-any-image walk onto `forensic-vfs-engine` is planned, not yet wired.
This page documents disk-forensic's **own** role.

The shared VFS story — the layered `*Open` model, the `SourceOpen` resolution
graph, the crate topology, and the full reader fleet — is documented once, in
[forensic-vfs](https://github.com/SecurityRonin/forensic-vfs), which is the source
of truth:

- [README](https://github.com/SecurityRonin/forensic-vfs#readme) — the pitch, and the [reader fleet](https://github.com/SecurityRonin/forensic-vfs#the-reader-fleet) umbrella: every archive / container / encryption / filesystem reader, grouped by layer, with per-reader wiring status.
- [`docs/architecture.md`](https://github.com/SecurityRonin/forensic-vfs/blob/main/docs/architecture.md) — the five `*Open` traits, the `SourceOpen` resolution graph, and the `forensic-vfs` / `forensic-vfs-resolver` / `forensic-vfs-engine` crate topology.
- [`docs/PRD.md`](https://github.com/SecurityRonin/forensic-vfs/blob/main/docs/PRD.md) — the reverse-written spec, the ranked coverage matrix, and the remaining work.
- [`docs/decisions/` ADRs](https://github.com/SecurityRonin/forensic-vfs/tree/main/docs/decisions) — every design decision (positioned-read-not-seek, no-write-path, credentials out-of-band, the archive / resolver split).

## What disk-forensic owns

`disk-forensic` / `disk4n6` is the analyst-facing disk tool. Its own
responsibilities — the work that is *not* delegated to the shared engine:

- **Container decode** — E01 / VMDK / VHDX / VHD / QCOW2 / DMG / AFF4 / raw, plus ISO routed to filesystem analysis.
- **Volume-system parsing** — MBR / GPT / APM partition tables, each delegated to a focused sibling: [mbr-partition-forensic](https://github.com/SecurityRonin/mbr-partition-forensic), [gpt-partition-forensic](https://github.com/SecurityRonin/gpt-partition-forensic), [apm-partition-forensic](https://github.com/SecurityRonin/apm-partition-forensic).
- **ISO 9660 filesystem analysis** — routed to [iso9660-forensic](https://github.com/SecurityRonin/iso9660-forensic).
- **Live triage** — host physical-disk / partition enumeration across macOS / Linux / Windows.
- **Acquisition-integrity findings**.
- **Report rendering** — text / JSON / DFXML / HTML, normalized into the shared [`forensicnomicon::report`](https://github.com/SecurityRonin/forensicnomicon) findings / provenance / timeline model.

Today disk-forensic decodes containers through its own `container::open` stack
(`ewf` / `vmdk` / `qcow2` / `vhdx` / `dmg` / `aff4` / `archive-core` plus the
MBR/GPT/APM parsers). For the *general* open-any-image walk — composing archive →
container → volume → encryption → filesystem across the whole reader fleet — the
planned consolidation is to delegate to `forensic-vfs-engine` rather than grow a
second detect-and-dispatch stack. That migration is not yet wired: disk-forensic
carries no `forensic-vfs` dependency at present.

## Development status

| Scope | Status |
|---|---|
| Container decode (E01/VMDK/VHDX/VHD/QCOW2/DMG/AFF4/raw/ISO), MBR/GPT/APM parsing, ISO filesystem analysis, live triage (macOS/Linux/Windows), acquisition-integrity findings | ✅ Shipped |
| Migration onto `forensic-vfs-engine` for the general open-any-image walk | Planned — not yet wired (no `forensic-vfs` dependency); gated on the Case-001 parity check below |

The fleet-wide VFS migration roadmap and per-reader wiring status live in
[forensic-vfs PRD §7](https://github.com/SecurityRonin/forensic-vfs/blob/main/docs/PRD.md)
and the [reader fleet](https://github.com/SecurityRonin/forensic-vfs#the-reader-fleet)
table. Each migration phase is gated on the Case-001 Szechuan end-to-end ingest
producing identical event counts and artifacts to the pre-phase baseline — no
silent regressions.
