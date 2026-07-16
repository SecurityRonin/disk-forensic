# Publication & Talk Venues — the forensic-VFS paper

**Recommendation:** submit the universal-reader / forensic-VFS work to **DFRWS as
a full research paper with SoK framing** (EU 2027 in Edinburgh once its CFP opens,
or the next USA/APAC deadline), and give a **FOSDEM Open Source Digital Forensics
devroom** talk for community reach. Avoid vendor summits (Magnet), where issen is
a competitor. The rest of this page ranks the venues and records the DFRWS format
and deadlines.

## The paper's angle (SoK framing)

Forensic evidence acquisition is a fragmented zoo of one-off readers — E01, VMDK,
QCOW2, VHDX, GPT/MBR/APM, BitLocker/LUKS/FileVault, NTFS/ext4/APFS/XFS/…, zip/tar/7z.
The contribution: **systematize the whole domain onto four navigation contracts** —
`ImageSource` · `VolumeSystem` · `CryptoLayer` · `FileSystem` — and show it collapses
to that taxonomy, backed by a **reproducible open-source reference implementation**
(the published crates + Tier-1 validation). That's taxonomy + new viewpoint +
evidence: a Systematization-of-Knowledge contribution.

## Ranked venues

| Rank | Venue | Type | Fit | Status |
|---|---|---|---|---|
| 1 | **DFRWS** (EU / USA / APAC) | Peer-reviewed paper (FSI:DI, Elsevier) | Best — neutral, artifact-friendly, taxonomy welcome | see below |
| 2 | **FOSDEM — Open Source Digital Forensics devroom** | Community talk | Huge neutral OSS audience; "open alternative to commercial suites" story | CFP active (Brussels, early Feb) |
| 3 | **SANS DFIR Summit** | Practitioner talk | Neutral, reputable, examiner reach | 2026 CFP closed (~Jul 13); target **2027** |
| 4 | **OSDFCon** (Sleuth Kit/Autopsy lineage) | Community-voted talk | Reputable OSS-DFIR, but cadence irregular | no confirmed 2026 edition |
| — | **Magnet Summit** | Vendor conference | ❌ **Not viable** — issen competes with Magnet; a vendor won't platform a rival | avoid |

## DFRWS specifics

- **No dedicated “SoK” *track*.** DFRWS's five standing categories are research
  papers · presentations/demos · posters · workshops · panels. The explicit
  “Systematization of Knowledge” solicitation was **DFRWS USA 2026-specific** (26th
  anniversary). Elsewhere, submit the systematization as a **Full Research Paper** —
  SoK is a framing, not a checkbox.
- **Full paper format:** ≤10 single-spaced two-column pages (10pt, 1in margins) +
  ≤1 page refs/appendix (=11 total), PDF, blinded, Harvard/IEEE refs, **in-person**
  presentation required. Proceedings = Elsevier special issue of *FSI: Digital
  Investigation*.
- **DFRWS EU 2027** — 30 March – 2 April 2027, **Edinburgh** (Craiglockhart campus,
  Edinburgh Napier University). **CFP deadline not published yet** (EasyChair link
  "to come"); by historical cadence expect the paper deadline ~Oct–Nov 2026.
- **DFRWS USA 2026** — 25–30 July 2026, George Mason U, Arlington VA; named the SoK
  category, but its paper deadline has passed for 2026.

## Recommendation

Target **DFRWS as a full research paper with SoK framing** (EU 2027 in Edinburgh
once its CFP opens, or the next USA/APAC deadline), and give a **FOSDEM OSDF
devroom** talk for open-source community reach. Avoid vendor summits (Magnet).

_Verify all dates on the official [DFRWS events page](https://dfrws.org/event/) — CFPs were being finalized as of July 2026._
