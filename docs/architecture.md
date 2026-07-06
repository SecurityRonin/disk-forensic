# Architecture — Universal Forensic VFS

`disk-forensic` is being restructured as the fleet's universal forensic VFS: a single open-any-image entry point shared by `issen`, `4n6mount`, and `disk4n6`, rather than three parallel detection and dispatch stacks. The full specification is in [`docs/design/2026-07-06-universal-forensic-vfs.md`](design/2026-07-06-universal-forensic-vfs.md).

## The layered model

Six transform kinds, each a trait in `forensic-vfs-core`, compose as a graph. Every transform consumes an `ImageSource` and yields either another `ImageSource` or a terminal `FileSystem`. The resolver applies them in whatever order the evidence requires — crypto may appear before or after volume detection:

```
PathSpec (locator, self-describing, serde-safe)
   │ resolves (graph walk)
   ▼
ImageSource  ── positioned read_at(&self), no write, no seek cursor ──────┐
   ├── ContainerDecoder  E01 / VMDK / VHDX / QCOW2 / DMG / AFF4 / AD1    │
   ├── VolumeSystem      MBR / GPT / APM / VSS / APFS-container           │
   ├── CryptoLayer       BitLocker / LUKS / FileVault                      │
   └── FileSystem        NTFS / ext4 / HFS+ / APFS / ISO / FAT → FsNode  ─┘
```

Real nesting orders the graph must handle, and that a fixed-lane model cannot: `E01 → GPT → BitLocker → NTFS`, `raw → LUKS → LVM → ext4`, `E01 → APFS-container(encrypted volume) → APFS`.

## Core types

### `ImageSource`

The universal edge: a read-only, randomly-addressable byte stream. Positioned reads (`read_at(&self, offset, buf)`) carry no cursor, so one source is shared across threads by `&self`. There is no write method anywhere in this trait or its impls — evidence is read-only by construction, not by convention.

Concrete implementations: a decoded E01 segment set, a partition sub-range, a decrypted BitLocker volume, a VSS store, a file's data stream. All compose without any lock on the hot path.

### `PathSpec`

A self-describing, recursive locator that carries the full open-recipe for an artifact. It round-trips through a report, session, or evidence row via serde, without embedding credentials. Credentials are supplied at resolve time through an injected `CredentialSource`, so a serialized `PathSpec` is safe to log and replay without leaking keys.

### `FsMeta`

Per-node forensic metadata: timestamps (with `TimeResolution` preserving NTFS 100 ns granularity and FAT local-time ambiguity), `allocated`/`deleted` status at the name, metadata, and content allocation layers (the TSK three-layer model), named data streams, `xattr`s, slack, and per-field provenance.

## Crate structure

Three crates, each at a distinct architectural tier:

| Crate | Tier | Role |
|---|---|---|
| `forensic-vfs-core` | KNOWLEDGE (leaf) | Traits + types + adapters — `ImageSource`, `PathSpec`, `FileSystem`, `FsMeta`, `VfsError`, bounds-checked read helpers. Base deps: `thiserror` + optional `serde` only. |
| `forensic-vfs-engine` | ORCHESTRATION | `Vfs::open`, the recursive resolver, the compiled-in registry, concurrent block cache. Depends down on every reader crate. |
| `disk-forensic` / `disk4n6` | CLI / aggregator | Thin report rendering (text / JSON / DFXML / HTML) over the engine. |

`issen` and `4n6mount` consume `forensic-vfs-engine` directly, sharing one detection and dispatch stack.

## Development status

| Phase | Scope | Status |
|---|---|---|
| — | Container decode (E01/VMDK/VHDX/VHD/QCOW2/DMG/raw/ISO), MBR/GPT/APM parsing, live triage (macOS/Linux/Windows), ISO filesystem analysis, acquisition-integrity findings | ✅ Shipped |
| 1 | Extract `forensic-vfs-core`: `ImageSource` + adapters + `PathSpec` + `FileSystem` trait. Non-breaking re-exports during transition. | In development |
| 2 | `forensic-vfs-engine`: `Vfs::open` + registry over existing containers and schemes; per-partition filesystem mounting. | Planned |
| 3 | One issen provider replaces 8 per-format wrapper crates (ADR-0010). | Planned |
| 4 | `4n6mount` migrates onto the engine, dropping its own detect/dispatch. | Planned |
| 5 | Crypto + snapshots + nesting: `CryptoLayer` (BitLocker/LUKS/FileVault), VSS `VolumeSystem`, nested images, `TemporalCohort` snapshots. | Planned |
| 6 | In-tree trait impls per reader crate; shims deleted. | Planned |

Each phase is gated on the Case-001 Szechuan end-to-end ingest producing identical event counts and artifacts to the pre-phase baseline — no silent regressions.

## Key design decisions

**`read_at(&self)` not `read(&mut self, Seek)`.** A positioned read with `&self` composes across threads without a lock. `Seek`'s `&mut self` cursor cannot — issen's parallel ingest would need one handle per worker. The trade-off: `Read + Seek` adapters (for the existing fleet readers that expose only a cursor) use a pool of cursors, one per thread, checked out on demand.

**No write path anywhere.** A write is uncompilable, not undocumented. dfVFS and TSK are read-only by discipline; here it is a type property.

**Compiled-in registry, not `inventory`.** The probe table is a `Vec<Box<dyn Probe>>` initialized once by `default_registry()`; `inventory`/`linkme` introduce linker-section coupling and are harder to test in isolation. Per-reader Cargo features (`default = ["all-readers"]`) keep Cargo feature-unification from silently reshaping the graph.

**`forensic-vfs-core` is a true leaf.** The `findings` and `history` bridges (`forensicnomicon::report` and `state-history-forensic`) are non-default features. A filesystem reader implements the base traits with neither enabled; the engine turns both on. No reader inherits report/serde/json choices it did not ask for, and no dependency cycle is possible.

**Credentials out of band.** A `PathSpec` is a pure address — safe to serialize and log. Credentials (passwords, recovery keys, keyfiles) are supplied at resolve time through an injected `CredentialSource` trait object. dfVFS stores them in a global keychain; this design keeps credentials out of the serialized address entirely.
