# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.11.6](https://github.com/SecurityRonin/disk-forensic/compare/disk-forensic-v0.11.5...disk-forensic-v0.11.6) - 2026-08-08

### Fixed

- commit the refreshed Cargo.lock
- satisfy the function-coverage gate, and lint the Linux-only test target
- *(supply-chain)* trust safe-read as ours
- *(vhd)* bound the BAT by the file before allocating; adopt canonical lints

### Other

- Merge main, taking its Cargo.lock and supply-chain records

## [0.11.5](https://github.com/SecurityRonin/disk-forensic/compare/disk-forensic-v0.11.4...disk-forensic-v0.11.5) - 2026-08-06

### Fixed

- *(supply-chain)* vet records for the crates the lru fix resolved

## [0.11.4](https://github.com/SecurityRonin/disk-forensic/compare/disk-forensic-v0.11.3...disk-forensic-v0.11.4) - 2026-08-05

### Fixed

- *(supply-chain)* trust our own crates instead of exempting them

## [0.11.3](https://github.com/SecurityRonin/disk-forensic/compare/disk-forensic-v0.11.2...disk-forensic-v0.11.3) - 2026-08-04

### Fixed

- *(deps)* widen ewf 0.3 -> 0.4 — caret-trapped below the maintained line (layer-1 freshness)

## [0.11.2](https://github.com/SecurityRonin/disk-forensic/compare/disk-forensic-v0.11.1...disk-forensic-v0.11.2) - 2026-07-26

### Documentation

- *(msrv)* correct rust-toolchain.toml comment — disk-forensic is a published library, not an app

### Other

- Merge pull request #3 from SecurityRonin/chore/msrv-true-floor

## [0.11.1](https://github.com/SecurityRonin/disk-forensic/compare/disk-forensic-v0.11.0...disk-forensic-v0.11.1) - 2026-07-25

### Added

- *(container)* peel compression-wrapped images via archive-core (Phase D)

### Documentation

- reverse-write PRD + ADRs; mkdocs excludes governance docs (fleet standard)
- correct disk-forensic↔forensic-vfs boundary to current state
- reconcile disk-forensic umbrella/audit artifacts to the *Open model; retire the superseded umbrella copy
- consolidate shared VFS architecture into forensic-vfs; slim disk-forensic docs to its own role + fix format-list gaps
- *(architecture)* engine is a separate published repo, not 'being relocated'
- *(architecture)* dedupe VFS design — slim to consumer view, point to forensic-vfs
- *(design)* replace misaligned ASCII diagram with Mermaid (renders inline)

### Fixed

- *(vet)* declare own crates first-party so version bumps don't break supply-chain audit
- *(ci)* green the four failing jobs (advisories, docs, windows test, coverage)
- *(ci)* depend on published archive-core registry crate, not sibling path

### Other

- *(deps)* archive-core detour->archive-layer rename (peel_archive/Peel)
- *(container)* relocate try_peel onto archive_core::peel_detour
