# disk-forensic — umbrella hub instructions

`disk-forensic` is the **orchestrator + registry** for the forensic-vfs umbrella:
every container, partition-scheme, crypto/FDE, filesystem, and archive/logical
reader that implements a forensic-vfs contract. Two docs here are the canonical map
of that umbrella and MUST stay in lockstep with reality:

- **`docs/validation-inventory.md`** — the per-repo index: contract, VFS-wiring
  status (✅ merged / 🔶 on-branch / ❌ missing), and links to each repo's own
  `validation.md` + `tests/data/README.md`.
- **`docs/assets/umbrella-architecture.svg`** — the two-path architecture diagram
  (physical stack ‖ logical archives → engine → consumers).

## Umbrella-registration requirement (binding)

**Every reader under the umbrella must be registered in BOTH docs above.** When a
reader is added, wired to its contract, or published:

1. Add/update its row in the `docs/validation-inventory.md` category table **and**
   the VFS-contract-wiring-status table (move ❌→🔶→✅ as it merges/publishes).
2. Reflect it in `docs/assets/umbrella-architecture.svg` (its contract band; mark
   engine-only formats with no fleet crate as dashed-amber gaps).
3. A reader that is published but not registered here is a **map defect** — the
   umbrella doc silently under-claims coverage. Treat it like a dangling link.

## The sweep quality gate (binding — no member publishes until ALL hold)

When bringing a reader onto forensic-vfs and (re)publishing it, the full fleet gate
must pass — verified **CI-green on the pushed commit**, never a local gate alone:

- **CI all green:** fmt · `clippy -D warnings` · test (OS-matrix, `--all-features`) ·
  **MSRV job** · **coverage 100%** · **`cargo deny`** · **gitleaks** · **fuzz-smoke**.
  Env-gated oracle/corpus jobs must **skip-clean** when real images are absent —
  a corpus job that fails-red on CI is a CI-design bug to fix, not an accepted red.
- **Supply-chain:** third-party Actions **SHA-pinned** (documented toolchain/renovate
  exceptions only).
- **`renovate.json`** present: `rangeStrategy: "bump"` + `lockFileMaintenance`, grouped, scoped.
- **Clone-reproducible provenance** (`docs/validation.md`, 6 fields per Tier-1
  oracle: what+author · download URL · md5/sha256 · license · env var · exact
  `cargo test` cmd). Re-mint is never Tier-1.
- **README + docs** to the SecurityRonin standard; docs site live.
- **Registered** in this hub's inventory + diagram (above).

## Pre-publish action for disk-forensic itself

Before publishing `disk-forensic`: re-run the wiring audit, update the inventory +
regenerate/render-verify the diagram, and `mkdocs build --strict` — a stale umbrella
map is a publish blocker (see `docs/validation-inventory.md` → Maintenance).
