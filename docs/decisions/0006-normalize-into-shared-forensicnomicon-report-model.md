# 6. Normalize every scheme's native analysis into the shared `forensicnomicon::report` model

Date: 2026-07-24
Status: Accepted

## Context

Each analyzer `disk-forensic` orchestrates emits its own native type —
`MbrAnalysis`, `ApmAnalysis`, VMDK container findings, ISO 9660 provenance — with
its own severity scale and its own anomaly vocabulary. Rendering these directly
would force `disk4n6` (and any future GUI) to grow N bespoke renderers, and would
make cross-scheme correlation impossible.

The fleet standardized on a single normalized reporting vocabulary
(`forensicnomicon::report`): every analyzer emits `Finding` / `Provenance` /
`TimelineEvent` so orchestration renders them uniformly. It is the union of the
analyzers' data, not a flattening.

## Decision

Convert every scheme's native analysis into the shared
`forensicnomicon::report::Report` (`src/normalize.rs`, rendered by `src/report.rs`).
The conversion goes through the `Observation` trait so the mapping (severity,
category, note, evidence, MITRE, confidence) lives in `forensicnomicon` and the
producing analyzer, not duplicated in `disk-forensic`. Container-level findings
(e.g. `vmdk-forensic`'s redundant-GD / dangling-pointer / provenance anomalies)
are carried on `OpenedImage.findings` so they aggregate into the same report
alongside the partition and ISO filesystem findings.

Findings are observations, never legal conclusions — MITRE/threat narration uses
"consistent with," per the fleet reporting conventions.

## Consequences

- `disk4n6` renders one uniform findings / provenance / timeline view across MBR,
  GPT, APM, ISO, and container-level anomalies, in text or (`--features serde`)
  JSON.
- The CLI's exit code is derived structurally: `0` when clean, `1` when any
  anomaly is present (`DiskReport::has_anomalies`), so it drops into a triage
  pipeline.
- New analyzers join the report by implementing `Observation` upstream; no
  renderer change is needed here.
