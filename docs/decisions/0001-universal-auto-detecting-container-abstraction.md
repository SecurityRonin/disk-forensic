# 1. One auto-detecting container entry point (`container::open`), sniffed by content not extension

Date: 2026-07-24
Status: Accepted

## Context

Evidence arrives in many disk-image wrappers — raw/`dd`, E01/EWF, VMDK, VHDX,
VHD, QCOW2, DMG, physical AFF4 — and analysts routinely receive files with wrong
or missing extensions (a `.vmdk` renamed `.bin`). A tool that asks the caller to
name the format up front pushes a decision onto the human that the bytes already
answer, and a caller who picks the wrong decoder gets silently wrong output.

The fleet constitution (`ronin-issen/CLAUDE.md` → "VFS & Universal Container
Abstraction") makes this binding: *a consumer that reads an evidence image MUST
NOT know one container format from another* — it asks the abstraction to open the
path and gets back a uniform byte source; only the abstraction knows E01 from
VMDK. `disk-forensic` is the crate that owns that raw-disk entry point for the
fleet (`issen`, `4n6mount`, and `disk4n6` share it).

## Decision

Expose a single `container::open(path) -> Result<OpenedImage, OpenError>`
(`src/container.rs`). It sniffs the container magic (`container::sniff` /
`container::detect`, sourced from the `forensicnomicon` knowledge modules — the
single source of truth for magics), decodes the wrapper, and returns a uniform
`OpenedImage { format, size, reader: Box<dyn ReadSeek>, findings }`. The caller
never names a format.

- Detection is by content, never by file extension.
- The decoded view is a `Box<dyn ReadSeek>` (`Read + Seek`, blanket-impl'd), so a
  decoded EWF/VMDK/QCOW2 reader and a plain raw `File` box into the same type.
- Before container detection, a compression-wrapped image (`evidence.dd.gz`) is
  transparently peeled via `archive-core` so the wrapper underneath is detected
  normally (the Phase-D "peel detour", commit `c9fe22c`).
- A corrupt or unsupported-variant container fails **loud** with a typed
  `OpenError::Decode(format, msg)` — never silent wrong output.

## Consequences

- The zero-config path is the correct one: a caller cannot pick the wrong decoder
  because there is no decoder to pick (Secure by Default).
- Adding a new container format benefits every consumer at once, and a consumer
  that special-cases one format (an `if ewf { … }` branch) is the smell this
  design exists to catch.
- `container::sniff` / `container::detect` remain public for callers that want the
  classification without decoding.
- New wrapper formats that `sniff` can recognize but whose decoder is not yet
  wired surface as `OpenError::Unsupported(format)` — a defensive, named arm, not
  a silent pass-through.
