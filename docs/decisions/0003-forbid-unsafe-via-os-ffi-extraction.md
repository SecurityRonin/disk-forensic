# 3. `forbid(unsafe_code)` in the orchestrator — push all OS FFI down into `livedisk-core`

Date: 2026-07-24
Status: Accepted

## Context

Live triage needs native, per-OS device enumeration — macOS IOKit, Linux sysfs,
Windows `DeviceIoControl` — which is inherently `unsafe` FFI. `disk-forensic` also
parses attacker-controllable disk images, where the fleet's "Paranoid Gatekeeper"
standard wants the strongest provable memory-safety posture.

The constitution's `unsafe` law prefers `forbid(unsafe_code)` as a *provable,
badge-able* "zero places a crafted input can corrupt memory," and only downgrades
to `deny` + bounded per-site `#[allow]` when a real benefit forces it. A crate
that mixes orchestration with raw OS FFI could not wear `forbid`.

## Decision

Keep `disk-forensic` at `#![forbid(unsafe_code)]` (`Cargo.toml`
`[lints.rust] unsafe_code = "forbid"`). Every OS-specific FFI lives in a separate
crate, `livedisk-core` (imported as `livedisk`), and its forensic sibling
`livedisk-forensic`. `disk-forensic` is pure orchestration and contains no
`unsafe` code; the enumeration and acquisition-integrity findings are consumed
across the crate boundary as plain data.

## Consequences

- `disk-forensic` earns the honest `forbid(unsafe)` posture — the unsafe surface
  is quarantined to `livedisk-core`, where it is audited on its own terms.
- Live triage still ships in the single `disk4n6` binary (batteries-included);
  the split is about *where* the FFI lives, not whether it ships.
- The container-decode path relies on the fleet readers (`ewf`, `vmdk-core`,
  `qcow2-core`, `vhdx-core`, `dmg-core`, `aff4`) for their own bounds-checked,
  fuzzed parsing; `disk-forensic` adds `cargo fuzz` targets over its own
  detect/dispatch seam (`fuzz/fuzz_targets/{sniff,container_open,analyse_disk}.rs`).
