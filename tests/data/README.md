# Test data provenance

Fixtures consumed by the integration tests in `tests/`. Each entry records where
the artifact came from so correctness is not self-referential.

## Logical containers

| File | MD5 | Format | Producer | Contents | Consumed by |
|---|---|---|---|---|---|
| `v11_hello.dar` | `cd01c1a72e8831a8bb7aed0593123801` | DAR format 11.3 (`"0;3"`) | `dar` 2.8.5 (SourceForge release) | `files/hello.txt` = `"hello corpus\n"` (13 B) | `tests/dar_logical_tests.rs` |

`v11_hello.dar` is copied verbatim from the `dar-core` reader crate's own corpus
(`dar-forensic/tests/data/`), where its full build recipe and md5 manifest live.
It is a real `dar`-produced archive, not synthetic — the reader is validated
against the same bytes its author checked. Source project:
<https://sourceforge.net/projects/dar/files/dar/>.

AD1 and AFF4-Logical fixtures for `tests/ad1_logical_tests.rs` are **not**
committed here: they are minted in-test by each reader crate's spec-faithful
builder (`ad1::testfix`, `aff4::testutil`), whose ground truth comes from
independent `flate2` + RustCrypto, so those trees are reproduced fresh per run.

## Physical containers and partition maps

`apm.bin`, `df.dmg`, `df.iso`, `df.qcow2`, `df.vhd` / `df-fixed.vhd` /
`df-dynamic.vhd`, `df.vhdx`, `df.vmdk`, `ntfs.vmdk`, and
`gpt_130_partitions.E01` are small synthetic images built to exercise the
container decoders and MBR/GPT/APM partition parsers. They predate this manifest;
their build recipes are being backfilled — track under the repo's test-data
provenance issue.
