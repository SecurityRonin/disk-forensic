# Universal Forensic Virtual File System — Design

- Status: **Draft for review** (design only; no implementation)
- Date: 2026-07-06
- Scope: Turn `disk-forensic` into the fleet's universal forensic VFS — one entry point that opens any disk/partition/container/filesystem format and presents a single **read-only logical filesystem** with full forensic metadata. Realizes ADR-0010.
- Related: ADR-0010 (disk-forensic as the disk-image access abstraction), ADR-0006 (zip-direct/zran backing), `4n6mount` `ForensicFs`, `state-history-forensic` `[H]` functor.
- Review: revised after Gemini adversarial round 1 and **Codex (GPT-5) round 2** (see §13).

---

## Executive Summary

**Decision.** Split the VFS into three crates: a low, near-leaf **trait crate** `forensic-vfs-core` (KNOWLEDGE layer) defining the whole layered contract; a **`forensic-vfs-engine`** crate holding the registry + recursive resolver and depending down on every reader; and the thin **`disk-forensic`/`disk4n6`** CLI on top. `4n6mount` (FUSE) and `issen` (correlation) consume the same engine, replacing their two parallel detect/dispatch implementations. Realizes ADR-0010.

**The single biggest decision** is the **byte-source trait**: a positioned-read `ImageSource: Send + Sync` with `read_at(&self, offset, buf)` and **no seek cursor and no write method at all**. This delivers three fleet requirements at once — (1) parallel reads across a shared read-only stack via `&self` (issen reads in parallel; `Seek`'s `&mut self` cursor cannot), (2) read-only-ness enforced *by construction* (no write API exists to misuse), and (3) clean `dyn` composition (`Send + Sync` are auto traits, so `dyn ImageSource + Send + Sync` is legal where `dyn Read + Seek` is not).

**The concurrency model is `&self`-all-the-way-down** (the fix for round-1's biggest critique): `ImageSource`, `FileSystem`, and the block cache are all `Send + Sync` with `&self` read methods over *sharded interior mutability*, so N workers share one mounted filesystem and one cache without per-thread re-parsing and without a global lock.

**Prior art.** Borrows the recursive **path-spec** from dfVFS (`parent` chain) and Velociraptor (`DelegateAccessor`/`Path`), the **four-layer decomposition** (image→volume-system→filesystem→file) from TSK, **loader/auto-detect + `map`** from dissect, and the **VSS-volume-of-stores** model from libvshadow. It adds Rust read-only-by-construction, snapshots as first-class sub-volumes tied to `state-history-forensic`, an explicit **crypto/translation layer** (BitLocker/LUKS/FileVault), and one unified metadata + `forensicnomicon::report` findings model across every layer.

**Dependency-direction resolution.** Filesystem/parser crates depend **only** on `forensic-vfs-core` (a genuine leaf — the findings/temporal bridges are behind non-default features so a reader doesn't inherit `forensicnomicon`, round-2 fix), never on container/partition crates — the fleet rule holds *for real*. The god-crate risk is removed by putting the aggregating registry in `forensic-vfs-engine` (an orchestration crate, allowed to depend down on all readers), leaving `disk-forensic` a thin CLI. The registry is a compiled-in dispatch table (not `inventory`), with **explicit per-reader features** (`default = ["all-readers"]`) so Cargo feature-unification can't silently reshape the graph.

**The resolver is a per-node transform *graph*, not a linear stack** (round-2's escalated fix): at each `DynSource` the engine probes container / volume-system / crypto / filesystem interpretations under a bounded policy, because real evidence composes out of order — whole-disk LUKS *before* partitioning, BitLocker *inside* a partition, APFS encryption *inside* the container's volume metadata. A single fixed lane would miss valid evidence or mount the wrong view.

---

## 1. The layered model

Six *transform kinds*, each a trait in `forensic-vfs-core`. They are **not a fixed lane** — the resolver (§3) applies them as a graph: every transform consumes an `ImageSource` and yields another `ImageSource` (container decode, crypto decrypt, sub-range) or a terminal `FileSystem`. Order is discovered per node by probing, because crypto/volume/container nest in any order on real evidence.

```
PathSpec (locator, recursive)         forensic-vfs-core  [KNOWLEDGE]
   │ resolves (graph walk, §3)
   ▼
ImageSource   ── the universal edge: raw addressable bytes ──────────────┐
   ├── ContainerDecoder :  E01/VMDK/VHDX/QCOW2/DMG/AFF4/AD1  → ImageSource │  (any of these
   ├── VolumeSystem     :  MBR/GPT/APM/VSS/APFS-container    → ImageSource │   transforms may
   ├── CryptoLayer      :  BitLocker/LUKS/FileVault          → ImageSource │   apply, in any
   └── FileSystem       :  NTFS/ext4/HFS+/APFS/ISO/UDF/FAT   → FsNode tree ─┘   order, per node)
                                     │
                                     ▼
                        FsNode (File | Directory) + forensic metadata
```

Example nesting orders the graph handles that a fixed lane would not: `E01 → GPT → BitLocker → NTFS` (crypto after volume), `raw → LUKS → LVM → ext4` (crypto before volume), `E01 → APFS-container(encrypted volume) → APFS` (crypto is container/volume metadata, not a separate FDE step).

### 1.1 Byte source — `ImageSource`

The load-bearing trait. Positioned reads only; `Send + Sync`; no write, no seek-cursor state.

```rust
/// A read-only, randomly-addressable byte stream: a decoded container, a
/// partition window, a decrypted volume, a VSS store, a file's data, or a byte
/// range of any of them.
///
/// Positioned reads (`read_at`) carry no cursor, so one source is shared across
/// threads by `&self`. There is deliberately NO write method anywhere in this
/// trait or its object — evidence is read-only *by construction*.
pub trait ImageSource: Send + Sync {
    /// Logical size in bytes of this stream.
    fn len(&self) -> u64;
    fn is_empty(&self) -> bool { self.len() == 0 }

    /// Fill `buf` starting at byte `offset`. Returns bytes read (0 at/after EOF).
    /// Never panics; a short read past EOF returns the available prefix length.
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<usize, VfsError>;

    /// Optional: allocated-extent map, so callers skip zero/sparse runs on
    /// TB-scale images. Default = one dense extent covering `[0, len)`.
    fn extents(&self) -> Extents { Extents::dense(self.len()) }

    /// Optional zero-copy fast path. Returns a guard that Derefs to the bytes and
    /// holds any cache/mmap lifetime, so the borrow is always sound (round-1 fix:
    /// a bare `&[u8]` tied to `&self` is unsound over an LRU cache). `None` when
    /// the backing cannot lend a contiguous view (caller uses `read_at`).
    fn view(&self, offset: u64, len: usize) -> Option<SourceView<'_>> { let _ = (offset, len); None }
}

/// A borrowed, contiguous view that owns whatever guard keeps it alive
/// (an mmap borrow, or an `Arc<[u8]>` cache block). `Deref<Target=[u8]>`.
pub struct SourceView<'a> { /* enum: Mmap(&'a [u8]) | Block(Arc<[u8]>, Range) */ }

    /// Stable identity for cache keying + lineage. Assigned by the engine when a
    /// source is created; a SubRange/decrypted/overlay source records its parent
    /// so the block cache and view budget account by lineage, not by accident of
    /// equal offsets (round-2 fix: cache coherence across derived sources).
    fn source_id(&self) -> SourceId;

    /// The object-safe shared handle used at every composition seam.
```

```rust
pub type DynSource = std::sync::Arc<dyn ImageSource>;
```

**Source identity & view budget.** Every `ImageSource` has an engine-assigned `SourceId` with a `parent: Option<SourceId>` lineage. Block-cache keys are `(SourceId, block_no)` on the *base* source of a lineage, so a `SubRange`/decrypted/VSS-overlay source shares the parent's cached blocks instead of double-caching. Outstanding `SourceView` guards pin `Arc<[u8]>` blocks; the cache budgets **pinned bytes separately from resident bytes** and refuses to evict a pinned block — so `view()` cannot silently blow the cap, and a leaked guard shows up as pinned-budget pressure, not corruption (round-2 fix).

`Arc<dyn ImageSource>` (not `Box`): a child layer keeps a handle to its parent *and* the same parent backs several children (every partition shares the disk source; every VSS store shares the base volume). `Arc` gives shared ownership with `Send + Sync`; `read_at(&self)` means no cursor lock on the hot path. **Object-safety holds** — no generic methods, no `Self`-by-value, receiver is `&self`; `dyn ImageSource + Send + Sync` compiles (`Send`/`Sync` are auto traits).

**Bridging the existing `Read + Seek` world.** Fleet readers today expose `Read + Seek` (ewf/vmdk/…); 4n6mount's FS crates consume `Read + Seek`. Adapters in `forensic-vfs-core`:

```rust
/// Wrap a raw FILE as an ImageSource using positioned OS reads (pread /
/// FileExt::read_at / seek_read) — NOT a Mutex<Seek> (round-1 fix: a single
/// Mutex at the bottom of the stack serializes every worker). Parallel-safe.
pub struct FileSource(std::fs::File, u64 /*len*/);
impl ImageSource for FileSource { /* read_at → FileExt::read_at, no lock */ }

/// Wrap a legacy Read+Seek reader that lacks positioned reads. Uses a POOL of
/// cursors (one per thread, checked out on demand), not a single Mutex, so
/// parallel reads scale until the pool is exhausted. A reader with native
/// positioned reads should implement ImageSource directly and skip this.
pub struct SeekPoolSource<R: Read + Seek + Send> { pool: Vec<Mutex<R>>, len: u64 }
impl<R: Read + Seek + Send> ImageSource for SeekPoolSource<R> { /* checkout+read+seek */ }

/// A single-owner Read+Seek *view* over a DynSource, for the legacy
/// `analyse(&mut R)` / `build_filesystem(R)` call sites during migration.
pub struct SourceCursor { src: DynSource, base: u64, len: u64, pos: u64 }
impl Read for SourceCursor { /* read_at + advance */ }
impl Seek for SourceCursor { /* clamp within [base, base+len) */ }

/// A byte window `[base, base+len)` of a parent source, itself an ImageSource.
/// How a partition / VSS store / embedded image / decrypted volume is addressed.
pub struct SubRange { parent: DynSource, base: u64, len: u64 }
impl ImageSource for SubRange { /* read_at offsets by base, clamps to len */ }
```

### 1.2 Volume system → volume

```rust
/// A partitioning/volume scheme over one ImageSource: MBR, GPT, APM, or a
/// snapshot store-set (VSS, APFS container). `&self` throughout (Sync).
pub trait VolumeSystem: Send + Sync {
    fn scheme(&self) -> VolumeScheme;             // Mbr | Gpt | Apm | Vss | ApfsContainer | Lvm | …
    fn volumes(&self) -> &[VolumeDesc];
    /// Byte source for one volume (a SubRange of the parent, or a snapshot-
    /// materialized source). Read-only.
    fn open_volume(&self, index: usize) -> Result<DynSource, VfsError>;
    fn findings(&self) -> &[forensicnomicon::report::Finding] { &[] }
}

pub struct VolumeDesc {
    pub index: usize,
    pub kind: VolumeKind,          // Partition | ShadowStore | Snapshot | Unallocated
    pub start: u64, pub len: u64,  // in parent address space
    pub type_hint: Option<String>, // GUID/type name/label
    pub label: Option<String>,
    /// Set for snapshot/shadow volumes: point-in-time clock provenance,
    /// bridging to state-history-forensic.
    pub epoch: Option<state_history_forensic::EpochTag>,
}
```

VSS and the APFS container are *volume systems* whose `volumes()` are stores/snapshots — the libvshadow `volume → store[]` model — not special cases bolted onto NTFS/APFS. `open_volume` on a shadow store returns a source that reconstructs the point-in-time volume, which a normal `FileSystem` mounts unchanged.

### 1.2b Crypto / translation layer — `CryptoLayer`

Full-disk encryption (BitLocker, LUKS, FileVault/CoreStorage/APFS-encrypted) is a **distinct layer** between volume and filesystem — round-1 fix; dfVFS models these as `BDE`/`LUKSDE`/`CS` layers and the original design wrongly omitted them.

```rust
/// A cryptographic translation over one ImageSource: consumes credentials +
/// ciphertext sectors, presents a decrypted ImageSource. Detection is by
/// on-disk header magic (BitLocker `-FVE-FS-`, LUKS `LUKS\xba\xbe`, …).
pub trait CryptoLayer: Send + Sync {
    fn scheme(&self) -> CryptoScheme;   // Bitlocker | Luks1 | Luks2 | FileVault | ApfsEncrypted
    /// Present the decrypted volume. Errs `NeedCredentials` if keys are absent,
    /// `Decode` (loud, with the header bytes) on a bad key / unsupported cipher.
    fn open(&self, creds: &dyn CredentialSource) -> Result<DynSource, VfsError>;
    fn findings(&self) -> &[forensicnomicon::report::Finding] { &[] }
}
```

Credentials are **not** stored in the `PathSpec` (round-1 fix, §2); they are supplied at resolve time through an injected `CredentialSource` (a password/recovery-key/keyfile provider), so a `PathSpec` remains a pure address that is safe to serialize.

### 1.3 Filesystem and logical node

The filesystem navigation surface is the **existing `4n6mount::ForensicFs`**, relocated into `forensic-vfs-core` (§9), **made `Sync` with `&self` reads over interior mutability** (round-1 fix — the original `&mut self` forced one-handle-per-worker and per-thread MFT re-parsing), and given iterator-based directory/extent access (round-1 fix — eager `Vec` returns OOM on huge dirs / fragmented files).

```rust
/// One mounted, read-only filesystem. Inode-addressed; `&self` reads share one
/// handle across workers; internal caches use sharded interior mutability
/// (dashmap / sharded RwLock), NOT `&mut self`.
///
/// LOCK-ORDER CONTRACT (round-2 fix): a returned iterator/stream MUST NOT hold
/// any cache/inode/map lock across a `next()` yield — it holds owned batch state
/// and an `Arc<dyn FileSystem>` (see DirStream/ExtentStream), so callers may call
/// `meta`/`read_at`/`open_nested` while iterating without deadlock. The global
/// lock order is: source-cache < block-cache < snapshot-diff-map < fs-inode-cache.
pub trait FileSystem: Send + Sync {
    fn kind(&self) -> FsKind;
    fn root(&self) -> FileId;
    fn sector_sizes(&self) -> SectorSizes;         // logical/physical sector + cluster/block, per-layer provenance
    fn timestamp_zone(&self) -> TimeZonePolicy;    // UTC | LocalUnknown | Local(offset) — FAT/exFAT are volume-local

    /// Owned, `'static`, spawn-friendly streams (round-2 fix: a `Box<dyn Iterator
    /// + '_>` borrowing `&self` can't cross a thread boundary and forbids non-Send
    /// guards). The stream holds an `Arc<dyn FileSystem>` + a resumable cursor.
    fn read_dir(&self, ino: FileId) -> Result<DirStream, VfsError>;
    fn extents(&self, ino: FileId, stream: StreamId) -> Result<ExtentStream, VfsError>;

    fn lookup(&self, parent: FileId, name: &[u8]) -> Result<Option<FileId>, VfsError>;
    fn meta(&self, ino: FileId) -> Result<FsMeta, VfsError>;
    fn read_at(&self, ino: FileId, stream: StreamId, off: u64, buf: &mut [u8]) -> Result<usize, VfsError>;
    fn read_link(&self, ino: FileId, cap: usize) -> Result<Vec<u8>, VfsError>;   // cap bounds a hostile symlink

    // Forensic surface (default-empty). Bulk enumerations are STREAMS or take a
    // cap in OpenOptions (round-2 fix: no unbounded attacker-driven Vec):
    fn data_streams(&self, ino: FileId) -> Result<Vec<StreamInfo>, VfsError> { let _=ino; Ok(vec![]) }
    fn hardlinks(&self, ino: FileId) -> Result<Vec<HardLink>, VfsError> { let _=ino; Ok(vec![]) } // capped
    fn deleted(&self) -> Result<NodeStream, VfsError>;        // streamed, not Vec
    fn unallocated(&self) -> Result<ExtentStream, VfsError>;  // streamed, not Vec
    fn slack(&self, ino: FileId, stream: StreamId) -> Result<Option<ByteRun>, VfsError> { let _=(ino,stream); Ok(None) }
    fn findings(&self) -> Result<Vec<forensicnomicon::report::Finding>, VfsError> { Ok(vec![]) }
    fn fs_info(&self) -> serde_json::Value { serde_json::Value::Null }  // caps: bounded depth/bytes in the impl
}

/// Owned resumable streams — hold `Arc<dyn FileSystem>` + cursor, no borrow of &self,
/// no lock across `next()`. `Send`, `'static`, safe to move to a worker thread.
pub struct DirStream    { fs: Arc<dyn FileSystem>, cursor: DirCursor }
pub struct ExtentStream { fs: Arc<dyn FileSystem>, cursor: ExtentCursor }
pub struct NodeStream   { fs: Arc<dyn FileSystem>, cursor: NodeCursor }
impl Iterator for DirStream    { type Item = Result<DirEntry, VfsError>;  /* … */ }
impl Iterator for ExtentStream { type Item = Result<RunInfo, VfsError>;   /* … */ }
```

**`FileId` — filesystem-specific stable identity** (round-2 fix — a bare `u64` inode is wrong for non-NTFS). The address domain matches each FS's real identity primitive:

```rust
#[non_exhaustive]
pub enum FileId {
    NtfsRef { entry: u64, seq: u16 },      // MFT reference: record + sequence
    ExtInode { ino: u64, gen: u32 },       // ext2/3/4 inode + generation
    ApfsOid { oid: u64, xid: u64 },        // APFS object id + transaction id
    FatDirEntry { cluster: u32, index: u16 }, // FAT/exFAT: physical dir-entry address (no stable inode)
    IsoExtent { block: u32 },              // ISO 9660 path-table / extent address
    Opaque(u64),                           // filesystems with a plain inode
}
```

The unified **forensic metadata** record (TSK's name-layer vs meta-layer split, ADS/residency/provenance — **without** the eager run-list):

```rust
pub struct FsMeta {
    pub ino: u64,                       // metadata address (MFT ref / inode)
    pub kind: NodeKind,                 // File | Dir | Symlink | Device | Other
    pub allocated: Allocation,          // Allocated | Deleted | Orphan  (name vs meta layer)
    pub size: u64,
    pub nlink: u32,
    pub uid: Option<u32>, pub gid: Option<u32>, pub mode: Option<u32>,
    /// MAC(B) with per-timestamp source + resolution provenance. `None` = not
    /// present in this FS (forensically distinct from an epoch-zero value).
    pub times: MacbTimes,
    pub streams: Vec<StreamInfo>,       // default $DATA + ADS / resource forks (metadata only, no runs)
    pub residency: ResidencyKind,       // Resident { inline_len } | NonResident  (runs via extents())
    pub link_target: Option<Vec<u8>>,
}

pub struct MacbTimes {
    pub modified: Option<TimeStamp>, pub accessed: Option<TimeStamp>,
    pub changed:  Option<TimeStamp>,  // metadata-change (ctime)
    pub born:     Option<TimeStamp>,  // creation (crtime)
}
pub struct TimeStamp {
    pub unix_nanos: i128,
    pub source: TimeSource,             // SI | FN | InodeTable | DirEntry | …
    pub resolution: TimeResolution,     // WinFileTime(100ns) | Nanos | Micros | Seconds | TwoSeconds(FAT)
}

pub struct StreamInfo { pub id: StreamId, pub name: Option<Vec<u8>>, pub size: u64,
                        pub residency: ResidencyKind, pub kind: StreamKind }
/// Stream taxonomy (round-2 fix — not every named stream is an NTFS ADS). Carries
/// capability, so a consumer knows what it's reading rather than flattening all
/// streams into one enum.
pub enum StreamKind { NtfsData, NtfsAds, HfsResourceFork, ApfsNamed, Xattr, SyntheticSlack }
pub enum StreamId { Default, Named(u16), ResourceFork, Xattr(u16), Slack }
pub enum ResidencyKind { Resident { inline_len: u32 }, NonResident }

/// A data run with RUN-LEVEL allocation provenance (round-2 fix — a deleted file
/// can have partly-reallocated clusters; an allocated file can have sparse holes).
/// TSK distinguishes name/metadata/content allocation independently; so do we.
pub struct RunInfo { pub run: ByteRun, pub alloc: RunAlloc }
pub struct ByteRun { pub image_offset: u64, pub len: u64, pub flags: RunFlags } // Sparse|Encrypted|Compressed|Filler
pub enum RunAlloc { Allocated, Unallocated, Overwritten, Unknown }

pub struct HardLink { pub parent: FileId, pub name: Vec<u8> }
pub enum TimeZonePolicy { Utc, LocalUnknown, Local { minutes_east: i16 } }
pub struct SectorSizes { pub logical: u32, pub physical: u32, pub cluster_or_block: u32 }
```

`TimeResolution::WinFileTime` preserves NTFS's native 100 ns granularity (round-1 fix). `TimeZonePolicy` records that FAT/exFAT timestamps are volume-local (round-2 fix — a UTC assumption silently shifts FAT MAC times).

**`FsMeta.allocated` is the *name/metadata* layer status; run allocation is separate** (`RunInfo.alloc`), so "deleted file, clusters still intact" vs "deleted file, clusters reallocated" is representable — the TSK three-layer (name / meta / content) allocation model.

### 1.4 Trait objects vs generics — the seam decision

| Seam | Choice | Why |
|---|---|---|
| Byte source between layers | **`dyn` (`Arc<dyn ImageSource>`)** | Heterogeneous, runtime-decided stack (E01→GPT→BitLocker→NTFS vs raw→MBR→ext4). Monomorphizing every combination is a combinatorial code-size blowup; erasure is correct. `read_at` is coarse (KBs/call), so virtual dispatch is negligible. |
| Inside a reader crate | **generics** | ewf/ntfs/… parse with `impl ImageSource`/concrete types internally; monomorphized hot loops, zero dispatch. Erasure only at the crate boundary. |
| `FileSystem` object | **`Arc<dyn FileSystem>`, `Send + Sync`, `&self`** | One shared handle across workers (round-1 fix — `Send`-only + `&mut self` re-parsed the MFT per thread). Internal caches use sharded interior mutability. |
| Path spec | **enum, not trait** | Closed, serializable, matchable; new layer = new variant (`#[non_exhaustive]` minor bump). A Rust enum beats dfVFS subclasses (exhaustive resolve). |

---

## 2. The path/locator model — `PathSpec`

A recursive, self-describing chain (dfVFS `parent` + Velociraptor `DelegateAccessor`). Each node names one layer, its location within that layer, and its parent. It is the cache key, the reproducibility record, and what a report cites. **It carries no credentials** (round-1 fix — an address, not a keychain).

```rust
#[non_exhaustive]
pub struct PathSpec { pub layer: Layer, pub parent: Option<Box<PathSpec>> }

#[non_exhaustive]
pub enum Layer {
    Os { path: PathBuf },                              // base; only parentless layer
    Range { start: u64, len: u64 },                    // byte window (dfVFS DATA_RANGE)
    Container { format: ContainerFormat },             // decode; Auto = sniffed
    Volume { scheme: VolumeScheme, index: usize, guid: Option<Guid> },
    Crypto { scheme: CryptoScheme },                   // FDE translation (creds supplied out-of-band)
    Snapshot { store: SnapshotRef },                   // VSS store idx / APFS xid
    Fs { kind: FsKind, at: NodeAddr },
    Stream { id: StreamId },                            // ADS / resource fork of the addressed node
}

pub enum NodeAddr {
    Path(Vec<Vec<u8>>),          // raw path components (bytes — FS names aren't UTF-8)
    File(FileId),                // FS-specific stable id (§1.3): NtfsRef{seq}, ExtInode{gen}, ApfsOid{xid}, …
    Both { path: Vec<Vec<u8>>, id: FileId },
}
```

**Identity & cache key.** `PathSpec` derives `Hash + Eq` on the *structured* enum — identity is the enum, **not** a stringification (round-1 fix — raw path bytes can contain the delimiter, colliding cache keys). **Two text forms** (round-2 fix — a report string that can't round-trip is a trap):
- **Canonical parseable URI** — every byte outside a strict unreserved set is percent-encoded (**including `/` and `%`** inside a path component), so `PathSpec ⇄ String` is byte-for-byte lossless and tooling can re-open a spec pasted from a report. Round-trip is a test-enforced invariant.
- **Human `Display`** — lossy, readable, explicitly non-parseable (`os:/evidence/DC01.E01 | ewf | gpt#1 | ntfs:/Windows/System32/config/SYSTEM`).

- **By-id vs by-path stability.** `NodeAddr::File(FileId)` uses each FS's real identity primitive (NTFS ref+seq, ext inode+generation, APFS oid+xid, FAT physical dir-entry, ISO extent) so a reallocated/reused slot is never confused with the original; `Both` records the path observed at resolve time for context but resolves by id. This is how deleted/orphan nodes (no path) are cited. A `Snapshot { store }` ancestor puts the node in that snapshot's address domain, so the same `FileId` in two snapshots is two distinct specs.
- **ADS / resource forks**: a trailing `Stream { id }` node.
- **Snapshots**: a `Snapshot { store }` node; the whole snapshot set of a volume is a `TemporalCohort` (§5).
- **Serde**: `PathSpec` is `Serialize`/`Deserialize` (no credentials to leak), so a finding, a 4n6mount session, and an issen evidence row persist the exact open-recipe and re-resolve deterministically.
- **Credentials** flow through the resolve call (`Vfs::open_with`'s `CredentialSource`), never the spec.

---

## 3. Auto-detection and the universal `open()`

One entry point; a recursive resolver drives detection layer by layer.

```rust
/// The engine handle. Holds the source cache + credential provider for one
/// evidence item; cheap to clone (Arc inside). Process-safe (no global state).
pub struct Vfs { /* Arc<Inner>: source cache keyed by PathSpec (Hash/Eq) */ }

impl Vfs {
    pub fn open(path: &Path) -> Result<Evidence, VfsError>;
    pub fn open_with(path: &Path, opts: OpenOptions) -> Result<Evidence, VfsError>;
    pub fn resolve(&self, spec: &PathSpec) -> Result<Resolved, VfsError>;
    pub fn source(&self, spec: &PathSpec) -> Result<DynSource, VfsError>;
    pub fn filesystem(&self, spec: &PathSpec) -> Result<Arc<dyn FileSystem>, VfsError>;
    /// Treat a file's data stream as a fresh base source and detect (nested image).
    pub fn open_nested(&self, node: &PathSpec) -> Result<Evidence, VfsError>;
}

pub struct Evidence {
    pub root: PathSpec,
    pub tree: LayerTree,
    pub findings: Vec<forensicnomicon::report::Finding>,
}
```

**The resolver is a graph walk, not a lane** (round-2's escalated fix). At each `DynSource` node the engine runs *all four* transform-kind probers (container / volume-system / crypto / filesystem) and follows the matches, bounded by `Budget`:

```
resolve(source, budget):
  budget.tick()                                   # depth/source/byte caps, cycle-set (§5)
  matches := probe_all(source)                    # container? volume? crypto? filesystem?
  for m in matches by (Confidence desc, registry order):
     ImageSource-producing (container/crypto):    resolve(m.open(source), budget)   # nested
     VolumeSystem:  for each volume/store v:       resolve(vs.open_volume(v), budget)
     FileSystem:    mount; a file inside is resolved lazily via open_nested
  if matches empty:  Unknown leaf (typed, sniff bytes attached)
```

This lets crypto sit before *or* after the volume system (whole-disk LUKS vs BitLocker-in-a-partition) and lets APFS encryption be container/volume metadata rather than a forced separate step.

**Bounded probing** (round-2 fix — one header+footer window misses GPT's backup header, VSS, UDF, damaged media):

1. **Sniff** — each decoder gets `fn probe(&dyn ProbeReader, &ProbeBudget) -> Confidence`. `ProbeReader` permits *bounded random reads at multiple offsets* (GPT primary LBA1 + backup last-LBA; ISO PVD at 32768; APFS/VSS structures) and **records every byte range touched**, so the engine caches exactly those windows and re-serves them to sibling probers — bounded, no unbounded re-reads. `ProbeBudget` hard-caps bytes/seeks/time. `Confidence = No | Maybe | Yes { how }`.
2. **Confirm** — the winning decoder's `open()` fully validates. A probe-`Yes`/`Maybe` that fails to open is a **hard, loud `Decode` error** carrying the offending bytes (§8), **never** a silent downgrade to raw.

**Degradation policy (round-1 fix — the silent-RawStream trap).**
- A layer degrades to a `RawStream` / `Unknown` leaf **only when NO prober returns `Yes` or `Maybe`** (genuinely unrecognized) — and even then the leaf is explicitly typed `Unknown` and carries the sniff bytes as a finding, so an analyst never mistakes it for an empty partition.
- A prober returning `Yes`/`Maybe` that then **fails to open is `VfsError::Decode`** (loud, non-zero, bytes attached), propagated for that node — not swallowed.
- A **required decoder not compiled in** (should not happen — batteries-included) is `VfsError::Unsupported { layer, scheme }`, loud.

**Ambiguity (round-1 fix — never guess on a `Yes`/`Yes` collision).** Two probers both `Yes` ⇒ `VfsError::Ambiguous { candidates }` by default; the analyst disambiguates via `OpenOptions::force_layer`. An opt-in `OpenOptions::auto_pick` (off by default) restores first-match with a prominent `VFS-DETECT-AMBIGUOUS` finding, for batch pipelines that accept the risk.

**Bootstrap vs degrade.** `Vfs::open` failing to read the base or decode a *chosen* container is a `Bootstrap`/`Decode` error (non-zero, named, bytes attached) — never an empty `Evidence`. Empty `Evidence` is returned **only** for a genuinely clean, empty, unpartitioned source.

---

## 4. Registry / plugin model

**Decision: a compiled-in dispatch table in `forensic-vfs-engine`, not `inventory`.** Batteries-included (CLAUDE.md): every capability compiled into one static binary; the dependency graph must be auditable (`cargo deny`, no hidden global constructors). `inventory`/`linkme` register via link-time ctors — invisible, order-nondeterministic, awkward under `--all-features`. A plain table is explicit, greppable, deterministic. **The registry lives in `forensic-vfs-engine`, not `disk-forensic`** (round-1 fix — keeps `disk-forensic` a thin CLI and lets any tool/test use the engine without a circular dep through the binary crate).

```rust
// forensic-vfs-core — contracts a plugin implements (leaf, no reader deps):
pub trait ContainerDecoder: Send + Sync {
    fn format(&self) -> ContainerFormat;
    fn probe(&self, w: &SniffWindow) -> Confidence;
    fn open(&self, src: DynSource) -> Result<DynSource, VfsError>;
}
pub trait VolumeSystemProbe: Send + Sync { fn scheme(&self)->VolumeScheme; fn probe(&self,w:&SniffWindow)->Confidence; fn open(&self,src:DynSource)->Result<Box<dyn VolumeSystem>,VfsError>; }
pub trait CryptoProbe:       Send + Sync { fn scheme(&self)->CryptoScheme; fn probe(&self,w:&SniffWindow)->Confidence; fn open(&self,src:DynSource)->Result<Box<dyn CryptoLayer>,VfsError>; }
pub trait FileSystemProbe:   Send + Sync { fn kind(&self)->FsKind;         fn probe(&self,w:&SniffWindow)->Confidence; fn open(&self,src:DynSource)->Result<Arc<dyn FileSystem>,VfsError>; }

pub struct Registry {
    containers: Vec<Box<dyn ContainerDecoder>>,
    volume_systems: Vec<Box<dyn VolumeSystemProbe>>,
    crypto: Vec<Box<dyn CryptoProbe>>,
    filesystems: Vec<Box<dyn FileSystemProbe>>,
}
```

```rust
// forensic-vfs-engine — the ONE aggregator that depends down on every reader.
// Each `impl` is a thin ~15-line shim adapting a fleet crate to the trait.
pub fn default_registry() -> Registry {
    Registry::new()
        .container(EwfDecoder).container(VmdkDecoder).container(VhdxDecoder)
        .container(VhdDecoder).container(Qcow2Decoder).container(DmgDecoder)
        .container(Aff4Decoder).container(Ad1Decoder).container(DarDecoder)
        .volume_system(GptProbe).volume_system(MbrProbe).volume_system(ApmProbe)
        .volume_system(VssProbe).volume_system(ApfsContainerProbe)
        .crypto(BitlockerProbe).crypto(LuksProbe).crypto(FileVaultProbe)
        .filesystem(NtfsProbe).filesystem(Ext4Probe).filesystem(HfsplusProbe)
        .filesystem(ApfsProbe).filesystem(Iso9660Probe).filesystem(UdfProbe)
        .filesystem(FatProbe).filesystem(ExfatProbe)
}
```

**Dependency-direction resolution (the fleet-rule tension), no fig leaf.**
- `forensic-vfs-core` is a **true leaf** (round-2 fix — it must not force `forensicnomicon` onto every reader). The core crate defines **only** the primitive traits/types (`ImageSource`, `FileSystem`, `FileId`, `FsMeta`, `PathSpec`, `VfsError`, bounds helpers) and depends on **nothing but `thiserror` + optional `serde`**. The two bridges are **non-default features**: `findings` (pulls `forensicnomicon::report`, adds the `findings()`/`Finding` surface) and `history` (pulls `state-history-forensic`, adds `EpochTag`/`TemporalCohort`). A filesystem reader implements the base traits with neither feature; the engine turns both on. No cycle is possible (arrows point only down) *and* no reader inherits the report/serde/json feature choices it didn't ask for (Cargo feature-unification containment).
- **Engine features are explicit** (round-2 fix): `forensic-vfs-engine` declares `default = ["all-readers"]` plus per-reader `reader-ntfs`, `reader-ewf`, … CI tests `--no-default-features`, each `reader-*` alone, and `all-readers`, so enabling the engine can't silently flip a reader's own defaults.
- **Reader/analyzer crates** implement the `forensic-vfs-core` traits and depend **only down** on it. NTFS still never imports EWF — it implements `FileSystemProbe`/`FileSystem` over an `Arc<dyn ImageSource>`. The rule holds because the *wiring* lives in the engine, not the FS crate; and a FS crate can be unit-tested against `forensic-vfs-core` alone (no engine, no god-crate).
- **`forensic-vfs-engine`** is the orchestration aggregator (issen's role, scoped to disk access): the one crate depending down on all readers. **`disk-forensic`/`disk4n6`** is a thin CLI over the engine. This removes round-1's "god-crate / circular-test-dep" objection.

**In-tree vs shim.** Prefer each reader ship its own trait impl behind a `vfs` feature (so `ntfs-forensic` hands back a ready `Arc<dyn FileSystem>`); until then the shim lives in `forensic-vfs-engine`.

---

## 5. Nesting & recursion

The path-spec chain *is* the recursion; the engine walks it with guards.

- **Image-in-partition / FS-in-file.** A `Volume` whose bytes sniff as a container re-enters `resolve`. A *file* inside a filesystem is resolved lazily via `Vfs::open_nested(node_spec)` — a nested disk image is browsable without pre-extraction.
- **Snapshots as first-class sub-volumes.** VSS/APFS stores are `VolumeSystem::volumes()` of `VolumeKind::ShadowStore` (§1.2), each carrying an `EpochTag`. The set of a volume's snapshots is exactly a `state_history_forensic::TemporalCohort<Disk>` — the `[H]` functor lifts the base volume to its time-indexed cohort. `open_volume(store_i)` materializes the point-in-time source; mounting it yields the filesystem as of that snapshot, addressable by a `Snapshot { store }` node. libvshadow made first-class and typed.
- **Cycle & depth safety.** Every `resolve` carries a `Budget { depth, sources_open, bytes_mapped }`. Hard caps (safe defaults: depth ≤ 16, open sources ≤ 1024): a container/zip bomb (a VHD that contains itself) hits the depth cap and surfaces `VfsError::Budget` + a finding, not a stack overflow/OOM. The set of visited `PathSpec`s (by `Hash`/`Eq`) breaks structural cycles.

---

## 6. Forensic soundness by construction

- **Read-only in the type system.** `ImageSource` has no write method; `FileSystem` reads are `&self`. There is *no* API — not even unsafe in the default surface — that writes to a source. **`4n6mount`'s `rw/` overlay is a copy-on-write layer *above* the VFS** (a separate `MemoryFs` diff keyed by inode; a write allocates a shadow node, reads fall through to the immutable `ImageSource`), never a write-through. The evidence path stays provably immutable because the only writable object is the CoW diff, a distinct type the `ImageSource` trait cannot reach.
- **`&mut self` cannot mutate evidence.** The FS trait's reads are `&self`; any interior mutability (caches) is over *derived* state, never the backing `ImageSource` (which exposes no writer). A malicious FS impl still cannot write the source — there is no method to call.
- **Metadata fidelity.** `FsMeta` carries the name/meta allocation split (`Allocated | Deleted | Orphan`), per-timestamp `TimeSource`+`TimeResolution` (incl. `WinFileTime`), ADS/resource-fork `StreamInfo`, hardlink enumeration (`hardlinks()`), and non-resident layout + slack via `extents()`/`slack()` (lazily, not eager). Matches TSK's `TSK_FS_META`/`TSK_FS_ATTR` fidelity while adding provenance the references lack.
- **Unallocated/orphan in the logical tree.** The engine synthesizes stable virtual, namespaced views (mirroring 4n6mount's overlay dirs): `<deleted>/`, `<orphans>/`, `<unallocated>` (a synthetic `ImageSource` over `unallocated()` runs, carveable), per-snapshot `<snapshots>/<epoch>/`. Views addressed by path-spec, never colliding with real filenames.

---

## 7. Performance & huge-image reality

- **Concurrency is `&self`-all-the-way-down.** `ImageSource`/`FileSystem`/cache are `Send + Sync`; N workers share one mounted FS and one cache — no per-thread MFT re-parse, no global lock (round-1's central fix).
- **Concurrent block cache.** One cache per base `ImageSource`, a **sharded / clock-sweep concurrent cache** (design target: `moka`-style or a hand-rolled sharded-LRU), *not* a single-mutex LRU (round-1 fix — a naive LRU write-locks on every hit and throttles all IO). Keyed `(source_id, block_no)`, fixed 64 KiB–1 MiB blocks, size-capped, populated by `read_at`. `view()` returns an `Arc<[u8]>` block guard, so a lent slice never dangles.
- **Positioned OS reads at the bottom.** `FileSource` uses `pread`/`FileExt::read_at`/`seek_read` — no `Mutex<File>` (round-1 fix). Legacy `Read+Seek`-only readers use a *pool* of cursors (`SeekPoolSource`), scaling to the pool size, not serialized on one lock; porting ewf/qcow2 to native positioned reads is migration-prioritized.
- **Snapshot materialization.** A VSS store source overlays base+diff; it carries **its own block cache + a materialized diff-extent map** so a `read_at` is one map lookup + one cached read, not a per-read diff scan (round-1 fix — naive per-read overlay is slow on snapshot-heavy timelines).
- **Sparse/zero runs.** `extents()` lets carving/hashing skip unallocated runs on TB images; container readers (qcow2/vmdk/vhdx) report real allocated extents.
- **Lazy everything.** Mounts parse superblock/MFT lazily; `read_dir`/`extents()` are iterators (no full-Vec buffering — round-1 OOM fix).
- **zip-direct / zran backing (ADR-0006).** The base `ImageSource` may be issen-unpack's bounded-RAM DEFLATE reader; disk-forensic supplies structure, issen-unpack supplies bytes.

---

## 8. Error model

Panic-free (Paranoid Gatekeeper). One error type, no swallowing, bootstrap-vs-degrade split, unrecognized-value rule.

```rust
#[non_exhaustive]
pub enum VfsError {
    Io { op: &'static str, source: std::io::Error },
    Decode { layer: &'static str, offset: u64, detail: String, bytes: SmallHex },   // probe-Yes then fail
    Unrecognized { at: &'static str, offset: u64, bytes: SmallHex },                // no prober matched
    Ambiguous { candidates: Vec<&'static str> },                                    // >1 Yes, no auto_pick
    Bootstrap { stage: &'static str, detail: String },                             // ALWAYS loud
    Unsupported { layer: &'static str, scheme: String },                           // capability not compiled in
    Budget { cap: &'static str, limit: u64 },
    NeedCredentials { scheme: &'static str, target: String },
    OutOfRange { what: &'static str, offset: u64, len: u64, bound: u64 },
}
```

- **Fail-loud bootstrap vs degrade-per-node** (§3): base/decode failure is loud; only a *genuinely unrecognized* per-node source degrades to `Unknown` (typed, bytes attached).
- **Show the unrecognized value.** Every `Unrecognized`/`Decode` carries the actual bytes (hex) + offset + layer.
- **Bounded readers.** All integer/offset/length reads go through `forensic-vfs-core` bounds-checked helpers (out-of-range ⇒ `OutOfRange`, never panic). Length/count fields range-checked before allocation; per-image allocation capped.
- **No `unwrap`/`expect`/`panic!` in production**; `unsafe_code = forbid` in `forensic-vfs-core`/`forensic-vfs-engine`/`disk-forensic` (readers that mmap keep bounded `deny` + per-site allow).

---

## 9. Integration & migration

### 9.1 Crate structure

- **New leaf `forensic-vfs-core`** (repo `forensic-vfs`, KNOWLEDGE). Traits + types + adapters (`ImageSource`, `SourceView`, `SourceId`, `FileSource`, `SeekPoolSource`, `SubRange`, `SourceCursor`, `VolumeSystem`, `CryptoLayer`, `FileSystem`, `FileId`, `FsMeta`, `PathSpec`, `Registry` traits, `ProbeReader`, `VfsError`, bounds-checked read helpers). Base deps: **`thiserror` + optional `serde` only**; `findings` feature → `forensicnomicon`, `history` feature → `state-history-forensic` (round-2 fix — a reader depends on none of these). **This is ADR-0010's "sector-source trait moved down."** `4n6mount::ForensicFs` relocates here (renamed `FileSystem`, `&self`/`Sync`, `FileId`, upgraded metadata); 4n6mount re-exports for a transition window.
- **New `forensic-vfs-engine`** (ORCHESTRATION). `Vfs`, `default_registry()`, the resolver + shims + concurrent cache. Depends down on every reader crate. This is the god-crate-avoidance split.
- **`disk-forensic`/`disk4n6`** becomes a thin CLI over `forensic-vfs-engine` (report rendering: text/JSON/DFXML/HTML). Its current partition/report code moves behind `VolumeSystem`/`Finding` producers. Not a `-core`/`-forensic` split (it is a binary/aggregator, not a single-format reader).
- **Reader crates** add trait impls behind a `vfs` feature incrementally; shim in the engine until then.

### 9.2 4n6mount maps onto the trait

- `detect.rs` + `build_filesystem` are **replaced** by `Vfs::open`/`Vfs::filesystem` — one detection engine, not two. `fusefs.rs` maps FUSE ops onto `FileSystem` verbatim (`lookup`, `metadata`→`getattr`, `read_dir`→`readdir`, `read_at`→`read`, `read_link`→`readlink`), now `&self` so FUSE's concurrent request handlers share one FS.
- The `DiskOverlay` virtual dirs become the §6 synthetic views, defined once in the VFS and rendered by both FUSE and issen.
- Nested mounts become `Vfs::open_nested`.

### 9.3 issen collapses its 8 wrappers (ADR-0010)

- Delete `issen-{ewf,vmdk,vhd,vhdx,qcow2,aff4,dd,iso}` (~3,200 lines). One `DiskCollectionProvider` calls `Vfs::open` + walks the logical tree for triage; backing supplied by issen-unpack (zip-direct). Parsers still receive `&[u8]`/`SourceCursor` per artifact — the medium-agnostic PARSER contract is unchanged.
- A source's snapshot cohort (`TemporalCohort<Disk>`) flows into issen's `[H]` correlation.

### 9.4 Phasing — each step gated on the Case-001 Szechuan ingest (no regression)

1. **Extract `forensic-vfs-core`.** `ImageSource`+adapters+`PathSpec`+relocate `ForensicFs`→`FileSystem` (`&self`). Non-breaking re-exports. *Gate: fleet compiles; 4n6mount tests green.*
2. **`forensic-vfs-engine`.** `Vfs::open` + registry over existing containers/schemes; add per-partition FS mounting (reuse 4n6mount FS impls). *Gate: engine opens all four Case-001 legs; inventory matches baseline.*
3. **One issen provider.** Replace the 8 wrappers. *Gate: `issen ingest DC01.E01 DESKTOP.E01` identical event counts + artifacts to baseline.*
4. **4n6mount onto the engine.** Swap `detect`/`build_filesystem`. *Gate: mount + read + deleted-list parity on E01 legs.*
5. **Crypto + snapshots + nesting.** `CryptoLayer` (BitLocker/LUKS), VSS `VolumeSystem`, `open_nested`, `TemporalCohort`. *Gate: VSS stores enumerate; a nested VHD browses; a BitLocker volume opens with a supplied key.*
6. **In-tree trait impls + delete shims** as each reader publishes its `vfs` feature.

---

## 10. What's novel vs prior art (capabilities, not self-grades)

Borrowed, deliberately: recursive path-spec (dfVFS/Velociraptor), image→VS→FS→file layering + `img_info` read-callback (TSK), loader auto-detect + `map` (dissect), VSS-volume-of-stores + crypto layers (libvshadow / dfVFS BDE/LUKSDE), `trait SeekAndRead`/blanket-impl object-safety pattern (Rust `vfs`).

Distinct capabilities here:
- **Read-only by construction, not convention.** The byte-source trait has no write method; immutability is a type property, not a documented promise. dfVFS/TSK/dissect are read-only by discipline; here a write is uncompilable.
- **`&self` positioned-read parallel core.** `read_at(&self)` + `Send+Sync` + a concurrent cache gives lock-free-hot-path parallel reads over one shared stack — the Python references are single-reader-per-handle; TSK/libbfio are `Seek`-cursor based.
- **Snapshots as typed first-class sub-volumes** bound to `state-history-forensic::TemporalCohort<H>` — a snapshot is a `Volume` with an `EpochTag`, so time-travel composes with the same navigation and correlation.
- **One unified metadata + findings model** across container/volume/crypto/filesystem: every layer emits `forensicnomicon::report::Finding`; `FsMeta` carries per-timestamp source/resolution provenance and the name/meta allocation split in one record.
- **Self-describing locator + serde, credentials out-of-band.** A `PathSpec` carries its whole open-recipe and round-trips through a report, session, or evidence row, while credentials stay out of the serialized address (fixing dfVFS's global-keychain footgun without leaking keys into reports).
- **One detection engine for the whole fleet** (4n6mount, issen, disk4n6 share `Vfs`), replacing three parallel detect/dispatch implementations.

---

## 11. ADR-style decisions

- **D1** — Byte source is positioned-read `ImageSource: Send+Sync`, not `Read+Seek`. Parallel-safe, read-only-by-construction, `dyn`-clean.
- **D2** — `dyn` at composition seams, generics inside crates.
- **D3** — `PathSpec` is a `#[non_exhaustive]` enum chain; identity via `Hash/Eq`, human form percent-encoded; **credentials out-of-band**.
- **D4** — Compiled-in `Registry` table (not `inventory`), living in `forensic-vfs-engine`.
- **D5** — `forensic-vfs-core` is a new KNOWLEDGE leaf; `4n6mount::ForensicFs` relocates into it as `FileSystem` (`&self`/`Sync`).
- **D6** — Engine (`forensic-vfs-engine`) aggregates; `disk-forensic` is a thin CLI; readers depend only on the leaf. Preserves PARSER-never-imports-CONTAINER *and* avoids a god-crate.
- **D7** — Snapshots are `VolumeSystem` volumes with `EpochTag`; FDE is a distinct `CryptoLayer`.
- **D8** — 4n6mount's `rw/` is a CoW layer above the VFS, never write-through.
- **D9** — `FileSystem`/`ImageSource`/cache are `&self` + interior mutability; no per-thread handle duplication.
- **D10** — Ambiguous `Yes`/`Yes` sniff is a hard error by default; `RawStream` only for genuinely-unrecognized nodes.
- **D11** — The resolver is a **per-node transform graph**, not a fixed layer lane; crypto/volume/container compose in any order (round-2).
- **D12** — Node identity is a filesystem-specific `FileId` (NTFS ref+seq / ext inode+gen / APFS oid+xid / FAT dir-entry / ISO extent), not a bare `u64`; `PathSpec` has a lossless canonical URI *and* a lossy human `Display` (round-2).
- **D13** — `forensic-vfs-core` is a **true leaf**; `forensicnomicon`/`state-history-forensic` are `findings`/`history` non-default features; the engine has explicit per-reader features. Bulk enumerations stream or take an explicit cap (round-2).

---

## 12. Open questions & risks

- **Sharded-cache & FS interior mutability complexity.** `&self` FS with a concurrent inode/cache store (dashmap / sharded RwLock) is more complex than `&mut self`; each FS reader must be written for it. *Risk: a reader that can't be made cheaply `Sync` (heavy stateful parser) forces a per-handle fallback — measure per FS.*
- **`SeekPoolSource` pool sizing.** A cursor pool bounds parallelism to pool size and holds N open handles; porting the hot readers (ewf/qcow2) to native `read_at` is the real fix and must lead the migration.
- **Snapshot diff-map memory.** The materialized diff-extent map + per-store cache costs memory per open snapshot; opening a whole VSS cohort at once must cap concurrently-materialized stores.
- **`CredentialSource` UX.** Supplying BitLocker/LUKS keys at resolve time (not in the spec) means the caller must re-supply on every re-open of a serialized `PathSpec`; the provider abstraction must make that ergonomic (keyring/prompt/file) without ever persisting the key beside the spec.
- **Crypto correctness is Tier-1-only.** BitLocker/LUKS/FileVault must validate against an independent oracle (dislocker / cryptsetup / `hdiutil`) on real encrypted volumes — never a self-encoded round-trip (LZNT1-trap rule). Use audited RustCrypto primitives; refuse (loud) rather than fabricate on an unsupported cipher.
- **UDF / hybrid optical & multi-view volumes.** ISO+UDF hybrids and El-Torito nested FAT don't fit "one volume system → one FS"; a volume may need to yield *multiple* filesystem views of the same bytes. Deferred, flagged.
- **`forensic-vfs-core` API churn.** As the leaf every reader depends on, expect several `#[non_exhaustive]` minor bumps before it settles; publish only when the Case-001 gate passes.
- **Registry ordering vs ambiguity.** Documented detection order + the hard-error-on-tie default is safe; `auto_pick` batch mode must log every ambiguous pick.
- **Graph-resolver explosion.** Running all four prober kinds at every node with lazy nested resolution is more work than a fixed lane; the `Budget` caps + confidence-ordered short-circuit must bound it, and mount-time vs resolve-time laziness (don't mount every partition eagerly) must be measured on a 130-partition GPT.
- **Lock-order & Sync-FS reality.** The lock-order contract + owned streams prevent deadlock *by contract*, but each FS reader must honor it; a `loom`/stress test of concurrent walk-while-read per FS is required before claiming it holds.
- **FAT/exFAT chain fidelity.** `FileId::FatDirEntry` addresses a file, but cluster-chain reconstruction, orphan/cross-linked chains, and FAT-vs-directory size disagreements need first-class diagnostics (a `fat` provenance extension), not just generic extents — deferred, flagged.
- **`FileId` in serialized specs.** APFS `xid`/ext `generation` change across snapshots/versions; a persisted spec's `FileId` is valid only within its snapshot address domain — the resolver must reject a stale-domain id loudly rather than resolve the wrong file.

---

## 13. Adversarial review log

**Reviewers.** Codex (GPT-5) was requested but rate-limited at review time (usage cap until 12:23 local); the adversarial passes were run with **Gemini 3.1 Pro (High)** and **Grok (xAI)** as independent hostile critics via the `external-llms` skill. Recorded honestly: this is a substitution, not the requested reviewer. Codex re-run tracked as a follow-up.

### Round 1 — Gemini 3.1 Pro (High)

| # | Critique | Resolution |
|---|---|---|
| 1 | `as_slice(&self) -> Option<&[u8]>` unsound over an LRU cache (borrow tied to `&self`, but cache access mutates/locks). | **Accepted.** Replaced with `view() -> Option<SourceView<'_>>`, a guard owning an `Arc<[u8]>` block or an mmap borrow (§1.1). |
| 2 | `FileSystem` `&mut self` reads force one-handle-per-worker + per-thread MFT re-parse; contradicts "lock-free parallel." | **Accepted (central fix).** `FileSystem: Send+Sync`, all reads `&self` over sharded interior mutability (§1.3, §1.4, §7, D9). |
| 3 | `SeekAdapter(Mutex<R>)` serializes all workers on one lock. | **Accepted.** `FileSource` uses `pread`/`FileExt::read_at` (no lock); legacy readers use `SeekPoolSource` (cursor pool) (§1.1, §7). |
| 4 | Naive single-mutex LRU block cache = global IO throttle. | **Accepted.** Concurrent sharded/clock-sweep cache (moka-style) (§7). |
| 5 | `FsMeta.runs: Vec<ByteRun>` eagerly loaded → OOM on fragmented files. | **Accepted.** Runs removed from `FsMeta`; `extents()` iterator on demand (§1.3). |
| 6 | Credentials in `PathSpec` + serde is a lose-lose (leak keys or lose them). | **Accepted.** Credentials removed from `PathSpec`; supplied via `CredentialSource` at resolve time (§1.2b, §2, D3). |
| 7 | `comparable` string cache key collides (path bytes contain the delimiter). | **Accepted.** Identity via derived `Hash/Eq` on the enum; human `Display` percent-encodes (§2). |
| 8 | `read_dir -> Vec` OOMs on WinSxS-scale dirs. | **Accepted.** `read_dir -> DirIter` streaming iterator (§1.3). |
| 9 | No full-disk-encryption layer (BitLocker/LUKS/FileVault). | **Accepted.** New `CryptoLayer` between volume and FS (§1.2b, layer diagram, registry, phasing). |
| 10 | Silent degrade-to-`RawStream` on a prober-Yes-then-fail hides a populated partition. | **Accepted.** `Yes`/`Maybe`-then-fail ⇒ hard `Decode` error; `RawStream` only when NO prober matched, typed `Unknown` + bytes (§3). |
| 11 | Missing NTFS 100 ns (`WinFileTime`) resolution → tamper signal lost. | **Accepted.** Added `TimeResolution::WinFileTime` (§1.3). |
| 12 | No hardlink enumeration despite `nlink`. | **Accepted.** `FileSystem::hardlinks(ino)` added (§1.3). |
| 13 | Deterministic first-match on a `Yes`/`Yes` tie silently picks wrong FS. | **Accepted with nuance.** Hard `VfsError::Ambiguous` by default; opt-in `auto_pick` for batch, always with a finding (§3, D10). |
| 14 | Shims-in-`disk-forensic` = god-crate + circular test dep (fig leaf). | **Accepted.** Registry/engine split into `forensic-vfs-engine`; `disk-forensic` thin CLI; readers unit-test against the leaf alone (§4, §9.1, D6). |

**Biggest risk Gemini escalated:** conflation of thread-concurrency with data-mutability (the `&mut self` + `Mutex` serialization). Resolved by the `&self`-all-the-way-down model (D9) + positioned OS reads (§7). Residual risk tracked in §12 (making each FS reader cheaply `Sync`).

### Round 2 — Codex (GPT-5), on the round-1-revised doc

Codex became available and ran as the requested reviewer, tasked to find what round 1 *missed* or what its fixes *broke*.

| # | Critique | Resolution |
|---|---|---|
| 1 | Fixed layer order (`VS → Crypto → FS`) is fiction: whole-disk LUKS precedes partitioning; BitLocker sits inside a partition; APFS-encryption is container/volume metadata. | **Accepted (escalated).** Resolver reframed as a **per-node transform graph** — probe all four kinds at each `DynSource`, follow matches in any order (§1 diagram, §3, D11). |
| 2 | `&self`+`Sync` FS lets `DirIter`/`ExtentIter` hold shard guards across `next()`; caller then locks another shard → deadlock. | **Accepted.** Lock-order contract added: streams hold **no lock across `next()`**; documented global lock order (§1.3). |
| 3 | `Box<dyn Iterator + Send + '_>` borrowing `&self` isn't spawn-friendly and forbids non-Send guards. | **Accepted.** Replaced with **owned `DirStream`/`ExtentStream`/`NodeStream`** holding `Arc<dyn FileSystem>` + a `'static` cursor (§1.3). |
| 4 | Cache coherence across derived sources (SubRange/decrypted/VSS) undefined; `SourceView` pins blocks invisibly. | **Accepted.** `SourceId` + parent lineage; base-source cache keys; pinned bytes budgeted separately from resident (§1.1). |
| 5 | `forensic-vfs-core` depending on `forensicnomicon` makes it a policy crate, leaking report/serde into every reader. | **Accepted.** Core is a **true leaf**; `findings`/`history` are non-default features (§4, §9.1, D13). |
| 6 | Batteries-included registry vs per-reader `vfs` features → Cargo feature-unification hazard. | **Accepted.** Explicit engine features (`default=["all-readers"]`, per-reader `reader-*`) + CI matrix (§4). |
| 7 | `Inode{ino,seq}` only fits NTFS; ext/APFS/FAT/ISO need their own identity; snapshot id must be in the address. | **Accepted.** `FileId` enum with FS-specific variants; snapshot ancestor scopes the address domain (§1.3, §2, D12). |
| 8 | Percent-encoded `Display` underspecified → can't round-trip. | **Accepted.** Two forms: lossless canonical URI (percent-encode `/` and `%` too, round-trip test) + lossy human `Display` (§2, D12). |
| 9 | One header+footer window misses GPT backup, VSS, UDF, damaged media. | **Accepted.** `probe(&dyn ProbeReader, &ProbeBudget)` — bounded random reads at multiple offsets, records ranges touched (§3). |
| 10 | Round-1 missed other unbounded `Vec`s: `deleted`/`unallocated`/`data_streams`/`hardlinks`/`read_link`/`findings`/`fs_info`. | **Accepted.** `deleted`/`unallocated` stream; `read_link`/`hardlinks` take caps; JSON bounded (§1.3, §8). |
| 11 | Allocation status conflated file-level vs run-level (deleted file, reallocated clusters). | **Accepted.** `RunInfo.alloc` (Allocated/Unallocated/Overwritten/Unknown) separate from `FsMeta.allocated`; TSK name/meta/content split (§1.3, §6). |
| 12 | Still-real gaps: FAT/exFAT chains, stream-kind taxonomy, timezone/localtime, block-size provenance. | **Partially accepted.** `StreamKind` taxonomy, `TimeZonePolicy`, `SectorSizes` added (§1.3); FAT chain diagnostics scoped as a deferred `fat` provenance extension (§12). |

**Biggest residual risk Codex escalated:** the resolver was still drawn as a linear stack; real evidence is a graph of competing interpretations, translations, snapshots, and views. **Resolved** by the graph-walk resolver (D11, §3); the remaining risk (graph explosion / mount-time laziness / per-FS `Sync` correctness) is tracked in §12.

### Round 3 (optional follow-up)

A third pass (Grok for an X/social-grounded independent voice, or a Codex re-run on this round-2 revision) is a candidate before implementation, focused on the graph-resolver budget model and the per-FS `Sync` `loom` validation. Not run here.
