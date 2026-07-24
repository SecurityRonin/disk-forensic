# 4. Prefer our own pure-Rust readers over C-backed third-party crates (DMG, QCOW2)

Date: 2026-07-24
Status: Accepted

## Context

Two container decoders were initially wired to third-party crates that dragged in
liabilities:

- **DMG** via `udif`, which pulled C-based `lzfse` / `bzip2` / `lzma` codecs —
  breaking the pure-Rust / no-C posture and adding a C-FFI attack surface that the
  compiler cannot see into (the worst kind of `unsafe` liability under the
  constitution's `unsafe` law).
- **QCOW2** via the third-party `qcow`, which pulled an ancient `zstd` that
  conflicted with versions used across the rest of the fleet.

The fleet's binding rule is *prefer our own (SecurityRonin) crates over
third-party ones* whenever an equivalent exists or can be made to exist, and
`disk-forensic` must stay `forbid(unsafe)` (ADR 3).

## Decision

Depend on the fleet's own pure-Rust readers:

- **DMG** → `dmg-core` (package `dmg-core`, imported as `dmg`), a pure-Rust
  DMG/UDIF reader implementing ADC / zlib / bzip2 / LZFSE / LZMA with no C
  dependencies (migration in commit `a9fea9d`).
- **QCOW2** → `qcow2-core` (package `qcow2-core`, imported as `qcow2`).

The same principle governs the other container readers: `ewf`, `vmdk-core`,
`vhdx-core`, and `aff4` are all fleet crates. The one built-in decoder that stays
in-repo is VHD (`src/vhd.rs`) — fixed + dynamic Virtual PC images.

Where a package name differs from the desired import path, the dependency renames
via `package = "…"` so consumers write the natural `use qcow2::…` / `use dmg::…`.

## Consequences

- The whole container-decode stack is pure Rust with no C toolchain dependency,
  preserving the `forbid(unsafe)` posture end to end.
- Version conflicts from third-party transitive dependencies (the ancient `zstd`)
  are removed.
- Fixing or extending a decoder happens in a fleet crate we control, and every
  other fleet consumer benefits from the same reader.
