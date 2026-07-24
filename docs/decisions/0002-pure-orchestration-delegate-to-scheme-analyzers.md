# 2. Pure orchestration — detect the scheme, delegate every real parse to a sibling analyzer

Date: 2026-07-24
Status: Accepted

## Context

MBR, GPT, and Apple Partition Map are three distinct volume-system formats, each
deserving deep, focused forensic parsing (boot-code fingerprinting, CRC32
reconciliation, gap/slack carving). Folding all three parsers plus every
container decoder into one crate would produce a monolith that is hard to test,
hard to reuse, and impossible to depend on piecewise.

The fleet already publishes focused, dependency-light sibling crates for each
scheme, and the constitution's dependency rules place volume-system parsing below
orchestration.

## Decision

`disk-forensic` is **pure orchestration**. It classifies the scheme from the boot
area using `forensicnomicon::partition_schemes::detect_scheme` and dispatches to a
focused sibling that does the real parse (`src/lib.rs::analyse_disk`):

- MBR/GPT → `mbr-partition-forensic` (the parser's own GPT detection is
  authoritative for the `Mbr` vs `Gpt` label).
- APM → `apm-partition-forensic`.
- ISO 9660 optical media → `iso9660-forensic` (a filesystem, not a partitioned
  disk).

The dependency direction is strictly **down**: `disk-forensic` depends on the
`*-partition-forensic` analyzers, the container readers, and the `forensicnomicon`
knowledge leaf; none of them depend back on it. `disk-forensic` contains no
partition-parsing algorithm of its own.

`disk-forensic` depends on the *published* registry crates
(`mbr-partition-forensic = "0.6.1"`, `gpt-partition-forensic = "0.6.0"`,
`apm-partition-forensic = "0.6.0"`, `iso9660-forensic = "0.7.0"`), not path deps —
per the "prefer the published registry crate over a path dependency" rule.

## Consequences

- Each scheme parser is independently testable, publishable, and reusable — a
  caller who already knows the scheme can depend on the sibling directly.
- `disk-forensic`'s own surface stays small: detect, dispatch, normalize, render.
- The `*-partition-forensic` crates followed the reader/analyzer split (each is a
  `*-partition-core` reader plus a `*-partition-forensic` analyzer), so the
  version bumps to `0.6.x` reflect that restructure upstream.
- An unrecognized scheme returns `Error::UnknownScheme` rather than mis-parsing.
