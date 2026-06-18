//! Proportional partition-layout bar — the `disk4n6 list` visual, modelled on
//! GParted / Partition Wizard: a single fixed-width row where each partition
//! occupies a slice of columns proportional to its size, unallocated gaps
//! included, followed by a legend keying each slice to its partition.
//!
//! The column maths is the load-bearing part and is pure/testable: segment sizes
//! map to integer column counts via the **largest-remainder method**, so the
//! slices always sum to exactly the bar width regardless of rounding, and any
//! non-empty partition gets at least one visible column when space allows.
//! Colour is a presentation choice passed in by the caller (TTY → true), keeping
//! this function deterministic under test.

use core::fmt::Write as _;

use super::{human_size, PhysicalDisk};

/// One drawable slice of a disk: a partition, or an unallocated gap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Segment {
    /// Size in bytes (governs the slice width).
    pub size_bytes: u64,
    /// 1-based partition index for the legend; `None` for an unallocated gap.
    pub index: Option<usize>,
    /// Legend label (partition name + type, or "free").
    pub label: String,
}

/// Decompose a disk into ordered drawable [`Segment`]s: each partition in
/// on-disk order, with unallocated gaps (including leading and trailing free
/// space) inserted where partitions do not cover the device.
pub(super) fn segments(disk: &PhysicalDisk) -> Vec<Segment> {
    let mut sorted: Vec<&super::Partition> = disk.partitions.iter().collect();
    sorted.sort_by_key(|p| p.start_offset);

    let mut segs = Vec::with_capacity(sorted.len() * 2 + 1);
    let mut cursor = 0u64;
    for (i, p) in sorted.iter().enumerate() {
        if p.start_offset > cursor {
            segs.push(Segment {
                size_bytes: p.start_offset - cursor,
                index: None,
                label: "free".to_string(),
            });
        }
        let ty = p.partition_type.as_deref().unwrap_or("-");
        segs.push(Segment {
            size_bytes: p.size_bytes,
            index: Some(i + 1),
            label: format!("{}  {ty}", p.name),
        });
        cursor = cursor.max(p.start_offset.saturating_add(p.size_bytes));
    }
    if disk.size_bytes > cursor {
        segs.push(Segment {
            size_bytes: disk.size_bytes - cursor,
            index: None,
            label: "free".to_string(),
        });
    }
    segs
}

/// Allocate `total` columns across `weights` by the largest-remainder method:
/// the returned widths sum to exactly `total` (when `total > 0` and the weights
/// are not all zero), proportional to each weight, with every non-zero weight
/// guaranteed at least one column when `total` is large enough to afford it.
pub(super) fn allocate_widths(weights: &[u64], total: usize) -> Vec<usize> {
    let n = weights.len();
    let sum: u128 = weights.iter().map(|&w| u128::from(w)).sum();
    if n == 0 || total == 0 || sum == 0 {
        return vec![0; n];
    }

    // Largest-remainder (Hare): floor each share, then hand the leftover columns
    // to the largest fractional remainders so the widths sum to exactly `total`.
    let mut widths = vec![0usize; n];
    let mut remainders = vec![0u128; n];
    let mut allocated = 0usize;
    for (i, &w) in weights.iter().enumerate() {
        let exact = u128::from(w) * total as u128;
        widths[i] = (exact / sum) as usize;
        remainders[i] = exact % sum;
        allocated += widths[i];
    }
    let mut order: Vec<usize> = (0..n).collect();
    order.sort_by(|&a, &b| remainders[b].cmp(&remainders[a]));
    let mut leftover = total - allocated;
    for &i in &order {
        if leftover == 0 {
            break;
        }
        widths[i] += 1;
        leftover -= 1;
    }

    // Guarantee a visible sliver for any non-empty segment that rounded to zero,
    // borrowing a column from the currently-widest segment.
    for i in 0..n {
        if weights[i] > 0 && widths[i] == 0 {
            if let Some(j) = (0..n).filter(|&j| widths[j] > 1).max_by_key(|&j| widths[j]) {
                widths[j] -= 1;
                widths[i] += 1;
            }
        }
    }
    widths
}

/// Render the proportional bar plus legend for one disk. `width` is the bar's
/// inner column count; `color` selects ANSI-coloured solid blocks (TTY) versus
/// ASCII glyphs (pipe-safe).
pub fn render_disk_bar(disk: &PhysicalDisk, width: usize, color: bool) -> String {
    // ANSI 256-colour codes and the pipe-safe ASCII glyphs that stand in for them
    // when stdout is not a terminal — partition `index - 1` selects from each,
    // so the bar slice and its legend swatch always agree.
    const PALETTE: [u8; 8] = [39, 208, 46, 201, 226, 51, 129, 214];
    const GLYPHS: [char; 8] = ['#', '=', '+', '*', 'o', '~', 'x', '%'];
    const FREE_ANSI: u8 = 240;
    const FREE_GLYPH: char = '.';

    let segs = segments(disk);
    let weights: Vec<u64> = segs.iter().map(|s| s.size_bytes).collect();
    let widths = allocate_widths(&weights, width);

    // ── Bar ──────────────────────────────────────────────────────────────────
    let mut out = String::new();
    out.push('[');
    for (seg, &w) in segs.iter().zip(&widths) {
        if w == 0 {
            continue;
        }
        match seg.index {
            Some(idx) => {
                let slot = (idx - 1) % PALETTE.len();
                if color {
                    let _ = write!(out, "\x1b[38;5;{}m{}\x1b[0m", PALETTE[slot], "█".repeat(w));
                } else {
                    out.extend(std::iter::repeat_n(GLYPHS[slot], w));
                }
            }
            None => {
                if color {
                    let _ = write!(out, "\x1b[38;5;{FREE_ANSI}m{}\x1b[0m", "░".repeat(w));
                } else {
                    out.extend(std::iter::repeat_n(FREE_GLYPH, w));
                }
            }
        }
    }
    out.push(']');
    out.push('\n');

    // ── Legend ───────────────────────────────────────────────────────────────
    let total = disk.size_bytes.max(1);
    for seg in &segs {
        let pct = seg.size_bytes as f64 * 100.0 / total as f64;
        match seg.index {
            Some(idx) => {
                let slot = (idx - 1) % PALETTE.len();
                let swatch = if color {
                    format!("\x1b[38;5;{}m█\x1b[0m", PALETTE[slot])
                } else {
                    GLYPHS[slot].to_string()
                };
                let _ = writeln!(
                    out,
                    " {swatch} {idx:>2}  {:<28} {:>10}  {pct:>4.1}%",
                    seg.label,
                    human_size(seg.size_bytes),
                );
            }
            None => {
                let swatch = if color {
                    format!("\x1b[38;5;{FREE_ANSI}m░\x1b[0m")
                } else {
                    FREE_GLYPH.to_string()
                };
                let _ = writeln!(
                    out,
                    " {swatch}  -  {:<28} {:>10}  {pct:>4.1}%",
                    "free (unallocated)",
                    human_size(seg.size_bytes),
                );
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::live::Partition;

    fn part(name: &str, start: u64, size: u64, ty: &str) -> Partition {
        Partition {
            device_path: format!("/dev/{name}"),
            name: name.to_string(),
            start_offset: start,
            size_bytes: size,
            partition_type: Some(ty.to_string()),
            mount_point: None,
            filesystem: None,
            label: None,
        }
    }

    fn disk(size: u64, partitions: Vec<Partition>) -> PhysicalDisk {
        PhysicalDisk {
            device_path: "/dev/disk0".into(),
            name: "disk0".into(),
            size_bytes: size,
            logical_sector_size: 512,
            physical_sector_size: 512,
            model: None,
            serial: None,
            removable: false,
            read_only: false,
            synthesized: false,
            partitions,
        }
    }

    #[test]
    fn allocate_widths_sums_to_total() {
        let w = allocate_widths(&[1, 1, 1], 64);
        assert_eq!(w.iter().sum::<usize>(), 64);
        // Even thirds of 64 → 22/21/21 (largest remainder), never 63 or 65.
        assert_eq!(w, vec![22, 21, 21]);
    }

    #[test]
    fn allocate_widths_is_proportional() {
        let w = allocate_widths(&[900, 100], 100);
        assert_eq!(w, vec![90, 10]);
    }

    #[test]
    fn allocate_widths_gives_tiny_segment_at_least_one_column() {
        // A 1-byte partition next to a 1 TB one still gets a visible sliver.
        let w = allocate_widths(&[1_000_000_000_000, 1], 50);
        assert_eq!(w.iter().sum::<usize>(), 50);
        assert!(w[1] >= 1, "tiny segment must be visible: {w:?}");
    }

    #[test]
    fn allocate_widths_handles_all_zero_and_empty() {
        assert_eq!(allocate_widths(&[], 10), Vec::<usize>::new());
        assert_eq!(allocate_widths(&[0, 0], 10).iter().sum::<usize>(), 0);
    }

    #[test]
    fn segments_inserts_unallocated_gaps() {
        // 100-byte disk: part at [10,30), part at [40,50), leaving free gaps at
        // [0,10), [30,40), [60,100).
        let d = disk(100, vec![part("p1", 10, 20, "A"), part("p2", 40, 20, "B")]);
        let segs = segments(&d);
        // free, p1, free, p2, free
        assert_eq!(segs.len(), 5);
        assert_eq!(segs[0].index, None);
        assert_eq!(segs[0].size_bytes, 10);
        assert_eq!(segs[1].index, Some(1));
        assert_eq!(segs[1].size_bytes, 20);
        assert_eq!(segs[2].index, None); // [30,40)
        assert_eq!(segs[2].size_bytes, 10);
        assert_eq!(segs[3].index, Some(2));
        assert_eq!(segs[4].index, None); // [60,100)
        assert_eq!(segs[4].size_bytes, 40);
        assert!(segs.last().unwrap().label.contains("free"));
    }

    #[test]
    fn segments_no_gap_when_fully_covered() {
        let d = disk(50, vec![part("p1", 0, 25, "A"), part("p2", 25, 25, "B")]);
        let segs = segments(&d);
        assert_eq!(segs.len(), 2);
        assert!(segs.iter().all(|s| s.index.is_some()));
    }

    #[test]
    fn render_bar_ascii_has_exact_width_and_legend() {
        let d = disk(
            100,
            vec![part("p1", 0, 50, "TypeA"), part("p2", 50, 50, "TypeB")],
        );
        let out = render_disk_bar(&d, 40, false);
        let bar_line = out.lines().next().unwrap();
        // The bracketed bar's inner content is exactly `width` columns.
        let inner: String = bar_line
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        assert_eq!(inner.chars().count(), 40);
        // Legend names both partitions with sizes.
        assert!(out.contains("p1"));
        assert!(out.contains("p2"));
        assert!(out.contains("TypeA"));
        assert!(out.contains(&human_size(50)));
    }

    #[test]
    fn render_bar_color_emits_ansi_escapes() {
        let d = disk(100, vec![part("p1", 0, 100, "T")]);
        let out = render_disk_bar(&d, 20, true);
        assert!(out.contains("\x1b["), "color mode must emit ANSI escapes");
    }
}
