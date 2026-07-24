# 5. Logical file containers get their own `logical::open` and a typed refusal from `container::open`

Date: 2026-07-24
Status: Accepted

## Context

Some evidence is a **file tree**, not a raw sector-level disk: AccessData **AD1**
(FTK "Custom Content Image"), **AFF4-Logical** (`aff4:FileImage`), and **DAR**
(Denis Corbin Disk ARchiver) archives. These have no partition table and no block
device underneath — there is nothing for `analyse_disk` to seek over. Shoehorning
a file archive into the raw-disk `Read + Seek` contract would either fabricate a
bogus disk reader or silently mislead the caller.

The constitution's container abstraction rule is explicit: keep the raw-disk vs
logical distinction honest at the type level; `container::open` on a logical
container must return a typed error pointing at `logical::open`, never a bogus
disk reader.

## Decision

Split the two contracts:

- **Raw disks** → `container::open` returns `OpenedImage` with a `Read + Seek`
  reader (ADR 1).
- **Logical file trees** → `disk_forensic::logical::open` (`src/logical.rs`)
  returns entries (`LogicalEntry { path, is_dir, size }`) plus `read_file(index)`,
  with backends for AD1 (`ad1-core`), AFF4-Logical (`aff4`), and DAR (`dar-core`).

When `container::open` is handed a logical container it refuses with a typed
`OpenError::LogicalContainer` whose message names `disk_forensic::logical::open`
(`src/container.rs`). There is no silent wrong-output path.

## Consequences

- The type system enforces the distinction: a logical container can never be read
  as garbage sectors, and a caller is routed to the correct entry point.
- New logical backends (DAR was added at 0.10.0, commit `363d946`) slot into
  `logical::open` without touching the raw-disk path.
- The two modules share nothing but the crate — each contract stays minimal and
  honest to what its evidence actually is.
