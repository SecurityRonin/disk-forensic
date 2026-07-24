# 8. Declared MSRV tracks the pinned toolchain (application, not published-library, policy)

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy separates the *dev toolchain* (pinned to current stable in
`rust-toolchain.toml`) from the *declared MSRV* (`rust-version` in `Cargo.toml`),
and sets the declared MSRV by repo **role**: published libraries keep a low,
CI-verified floor (1.75/1.80) as a compatibility promise; applications and
binaries declare MSRV equal to the pinned toolchain, because nothing pins a
library dependency against them and it matches exactly what they test.

`disk-forensic` ships the `disk4n6` binary — it is an application. A dependency
bump (commit `afb8de4`, "raise MSRV to 1.88") and later dependency needs pushed
the effective floor upward, and the batteries-included default means capability is
never sacrificed to preserve a low MSRV.

## Decision

Treat `disk-forensic` as an **application** for MSRV: declare
`rust-version = "1.96"` in `Cargo.toml`, matching the pin in `rust-toolchain.toml`
(`channel = "1.96.0"`). The declared MSRV rises with the pinned toolchain and with
whatever the batteries-included dependency graph requires; there is no obligation
to hold a low library floor, because `disk-forensic` is run, not linked as a
low-MSRV building block.

## Consequences

- The declared MSRV is honest — it equals what CI builds and tests with.
- Release cross-builds must install the *pinned* toolchain version, not a floating
  `stable`, or the cross-target lands on the wrong toolchain (the `E0463` gotcha);
  `release.yml` pins to `1.96.0` (commit `01f6155`).
- Bumping the fleet toolchain bumps this crate's MSRV in the same deliberate pass —
  the low-MSRV floor is preserved only in the `*-core` reader libraries this crate
  consumes, not here.
