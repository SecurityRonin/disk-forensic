//! `disk4n6` — analyse a disk image or live device, or list the host's disks.
//!
//! Usage:
//!   disk4n6 <image|device>        # human-readable report
//!   disk4n6 --json <image|device> # JSON (requires the `serde` feature)
//!   disk4n6 list [--json]         # enumerate live disks/partitions
//!
//! `<image>` is an evidence file (raw or E01/VMDK/VHDX/VHD/QCOW2/DMG/ISO);
//! `<device>` is a live block device (`/dev/disk0`, `/dev/sda`,
//! `\\.\PhysicalDrive0`). `list` shows every disk on the running machine with a
//! proportional partition-layout bar, like a partition manager.

use std::fs::File;
use std::io::{IsTerminal, Seek, SeekFrom};
use std::process::ExitCode;

use disk_forensic::container::{self, ReadSeek};

/// Inner width of the `list` proportional bars.
const BAR_WIDTH: usize = 56;
const USAGE: &str = "usage: disk4n6 [--json] <image|device>\n       disk4n6 list [--json]";

/// A parsed command line.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    /// Enumerate live disks.
    List { json: bool },
    /// Analyse an image file or live device.
    Analyze { path: String, json: bool },
    /// Show usage and exit (no/`-h`/ambiguous args).
    Usage,
}

/// Parse argv (excluding argv[0]) into a [`Command`]. `list` as the first
/// positional selects enumeration; otherwise the first positional is the
/// image/device to analyse. `--json` is accepted in any position.
fn parse_args(args: impl Iterator<Item = String>) -> Command {
    unimplemented!("RED: parse_args")
}

fn main() -> ExitCode {
    match parse_args(std::env::args().skip(1)) {
        Command::Usage => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
        Command::List { json } => run_list(json),
        Command::Analyze { path, json } => run_analyze(&path, json),
    }
}

/// `disk4n6 list` — enumerate the host's disks and render the unified view.
fn run_list(json: bool) -> ExitCode {
    let disks = match disk_forensic::live::enumerate() {
        Ok(d) => d,
        Err(e) => {
            eprintln!("disk4n6: {e}");
            return ExitCode::FAILURE;
        }
    };

    if json {
        #[cfg(feature = "serde")]
        {
            match serde_json::to_string_pretty(&disks) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    eprintln!("disk4n6: JSON error: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        #[cfg(not(feature = "serde"))]
        {
            eprintln!("disk4n6: --json requires the `serde` feature");
            return ExitCode::from(2);
        }
    } else {
        let color = std::io::stdout().is_terminal();
        print!(
            "{}",
            disk_forensic::live::render_listing(&disks, BAR_WIDTH, color)
        );
    }
    ExitCode::SUCCESS
}

/// Dispatch `disk4n6 <path>` to the live-device or image-file flow.
fn run_analyze(path: &str, json: bool) -> ExitCode {
    if is_device_path(path) {
        analyse_device(path, json)
    } else {
        analyse_image(path, json)
    }
}

/// A live block-device node rather than an evidence file.
fn is_device_path(path: &str) -> bool {
    path.starts_with("/dev/") || path.starts_with(r"\\.\")
}

/// Analyse a live block device: open it, size it via seek (block devices report
/// a zero `metadata().len()`), and run the partition analysis. Treats the device
/// as raw — no container sniffing.
fn analyse_device(path: &str, json: bool) -> ExitCode {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("disk4n6: {path}: permission denied — re-run with sudo / as Administrator");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("disk4n6: cannot open {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let size = match file.seek(SeekFrom::End(0)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("disk4n6: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Err(e) = file.seek(SeekFrom::Start(0)) {
        eprintln!("disk4n6: {path}: {e}");
        return ExitCode::FAILURE;
    }
    let mut reader: Box<dyn ReadSeek> = Box::new(file);
    report_disk(path, &mut reader, size, json, Vec::new())
}

/// Analyse an evidence file: sniff/decode its container, route ISO 9660 to the
/// filesystem analyzer, otherwise run the partition analysis.
fn analyse_image(path: &str, json: bool) -> ExitCode {
    let mut opened = match container::open(std::path::Path::new(path)) {
        Ok(o) => o,
        Err(container::OpenError::Unsupported(fmt)) => {
            eprintln!(
                "disk4n6: {path}: {fmt:?} container decoding is not yet supported — decode it to \
                 a raw image first"
            );
            return ExitCode::from(2);
        }
        Err(e) => {
            eprintln!("disk4n6: cannot open {path}: {e}");
            return ExitCode::from(2);
        }
    };

    if opened.format == container::ContainerFormat::Iso {
        return analyse_filesystem(path, &mut opened.reader, json);
    }

    let findings = std::mem::take(&mut opened.findings);
    report_disk(path, &mut opened.reader, opened.size, json, findings)
}

/// Render a disk (partition) analysis from a `Read + Seek` source, folding in any
/// container-level findings. Shared by the image and live-device paths.
fn report_disk(
    label: &str,
    reader: &mut Box<dyn ReadSeek>,
    size: u64,
    json: bool,
    extra_findings: Vec<forensicnomicon::report::Finding>,
) -> ExitCode {
    let report = match disk_forensic::analyse_disk(reader, size) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("disk4n6: {label}: {e}");
            return ExitCode::FAILURE;
        }
    };

    if json {
        #[cfg(feature = "serde")]
        {
            let _ = &extra_findings;
            match serde_json::to_string_pretty(&report) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    eprintln!("disk4n6: JSON error: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        #[cfg(not(feature = "serde"))]
        {
            let _ = &extra_findings;
            eprintln!("disk4n6: --json requires the `serde` feature");
            return ExitCode::from(2);
        }
    } else {
        println!("Scheme: {:?}\n", report.scheme());
        print!("{}", disk_forensic::report::text_report(&report));
        println!();
        let mut normalized = disk_forensic::normalize::report(&report);
        normalized.findings.extend(extra_findings);
        print!("{}", disk_forensic::report::render(&normalized));
    }

    if report.has_anomalies() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Analyse an optical (ISO 9660) filesystem image and render its report.
fn analyse_filesystem(path: &str, reader: &mut Box<dyn ReadSeek>, json: bool) -> ExitCode {
    let analysis = match iso9660_forensic::analyse(reader) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("disk4n6: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    if json {
        #[cfg(feature = "serde")]
        {
            match serde_json::to_string_pretty(&analysis) {
                Ok(s) => println!("{s}"),
                Err(e) => {
                    eprintln!("disk4n6: JSON error: {e}");
                    return ExitCode::FAILURE;
                }
            }
        }
        #[cfg(not(feature = "serde"))]
        {
            eprintln!("disk4n6: --json requires the `serde` feature");
            return ExitCode::from(2);
        }
    } else {
        println!("Filesystem: ISO 9660\n");
        print!(
            "{}",
            disk_forensic::report::render(&disk_forensic::normalize::iso_report(&analysis))
        );
    }

    if analysis.anomalies.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Command {
        parse_args(args.iter().map(|s| (*s).to_string()))
    }

    #[test]
    fn parse_list_subcommand() {
        assert_eq!(parse(&["list"]), Command::List { json: false });
        assert_eq!(parse(&["list", "--json"]), Command::List { json: true });
        assert_eq!(parse(&["--json", "list"]), Command::List { json: true });
    }

    #[test]
    fn parse_analyze_path() {
        assert_eq!(
            parse(&["evidence.E01"]),
            Command::Analyze {
                path: "evidence.E01".into(),
                json: false
            }
        );
        assert_eq!(
            parse(&["--json", "/dev/disk0"]),
            Command::Analyze {
                path: "/dev/disk0".into(),
                json: true
            }
        );
    }

    #[test]
    fn parse_usage_on_empty_or_help() {
        assert_eq!(parse(&[]), Command::Usage);
        assert_eq!(parse(&["-h"]), Command::Usage);
        assert_eq!(parse(&["--help"]), Command::Usage);
    }

    #[test]
    fn is_device_path_detects_unix_and_windows_nodes() {
        assert!(is_device_path("/dev/disk0"));
        assert!(is_device_path("/dev/sda"));
        assert!(is_device_path(r"\\.\PhysicalDrive0"));
        assert!(!is_device_path("evidence.E01"));
        assert!(!is_device_path("./image.raw"));
    }
}
