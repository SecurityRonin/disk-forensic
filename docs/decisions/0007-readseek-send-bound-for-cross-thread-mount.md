# 7. `ReadSeek: Send` — the decoded disk must cross thread boundaries

Date: 2026-07-24
Status: Accepted

## Context

`container::open` hands back the decoded disk as a `Box<dyn ReadSeek>`. Consumers
such as `4n6mount` run the filesystem walk on a background mount thread (FUSE /
Dokan), so the decoded disk — or a partition slice of it — has to move across a
thread boundary. The original `ReadSeek` was `Read + Seek` only, which made the
boxed trait object non-`Send` and blocked that hand-off.

The constitution notes the honest gap that `disk-forensic`'s `ReadSeek` lacked a
`Send` bound, requiring a worker-thread seam in consumers until it was added.

## Decision

Bound the trait `Send`: `pub trait ReadSeek: Read + Seek + Send {}` with the
blanket impl `impl<T: Read + Seek + Send> ReadSeek for T {}` (`src/container.rs`).
Every decoder's reader and a plain `File` already satisfy `Send`, so they box into
`Box<dyn ReadSeek + Send>` unchanged. This shipped as a deliberate breaking change
(commit `8870d14`, `feat!`).

## Consequences

- A consumer can hand the decoded disk to a background mount thread with no
  wrapper seam.
- It is a breaking API change (the trait's bound tightened), so it rode a minor
  version bump rather than a patch.
- Any exotic reader that is `!Send` would no longer satisfy `ReadSeek`; in
  practice every fleet decoder and `std::fs::File` are `Send`, so nothing in the
  stack is excluded.
