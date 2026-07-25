# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
