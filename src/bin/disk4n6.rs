//! `disk4n6` — list the host's disks, or analyse a disk image / live device.
//!
//! Usage:
//!   disk4n6                          # list live disks (default)
//!   disk4n6 [--json] <image|device>  # analyse an image or device
//!   disk4n6 --json                   # list as JSON
//!
//! With no argument, disk4n6 enumerates every physical disk on the running
//! machine with a proportional partition-layout bar, like a partition manager.
//! `<image>` is an evidence file (raw or E01/VMDK/VHDX/VHD/QCOW2/DMG/ISO);
//! `<device>` is a live block device (`/dev/disk0`, `/dev/sda`,
//! `\\.\PhysicalDrive0`).

use std::io::IsTerminal;
use std::process::ExitCode;

use disk_forensic::container::{self, ReadSeek};

/// Inner width of the proportional bars.
const BAR_WIDTH: usize = 56;
const USAGE: &str = "usage: disk4n6 [--json]                  # list live disks\n       \
                     disk4n6 [--json] <image|device>   # analyse an image or device";

/// A parsed command line.
#[derive(Debug, PartialEq, Eq)]
enum Command {
    /// Enumerate live disks (the no-argument default).
    List { json: bool },
    /// Analyse an image file or live device.
    Analyze { path: String, json: bool },
    /// Show usage and exit (`-h`/`--help`).
    Usage,
    /// Print the version and exit (`-V`/`--version`).
    Version,
}

/// Parse argv (excluding `argv[0]`) into a [`Command`]. With no positional
/// argument it defaults to listing the host's disks; otherwise the first
/// positional is the image/device to analyse. `--json` is accepted in any
/// position; `-h`/`--help` shows usage.
fn parse_args(args: impl Iterator<Item = String>) -> Command {
    let mut json = false;
    let mut help = false;
    let mut version = false;
    let mut path: Option<String> = None;
    for arg in args {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => help = true,
            "-V" | "--version" => version = true,
            _ if path.is_none() => path = Some(arg),
            _ => {}
        }
    }
    if help {
        return Command::Usage;
    }
    if version {
        return Command::Version;
    }
    match path {
        Some(path) => Command::Analyze { path, json },
        None => Command::List { json },
    }
}

fn main() -> ExitCode {
    match parse_args(std::env::args().skip(1)) {
        Command::Usage => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
        Command::Version => {
            println!("disk4n6 {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Command::List { json } => run_list(json),
        Command::Analyze { path, json } => run_analyze(&path, json),
    }
}

/// `disk4n6 list` — enumerate the host's disks and render the unified view.
fn run_list(json: bool) -> ExitCode {
    let disks = match livedisk::enumerate() {
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
        print!("{}", livedisk::render_listing(&disks, BAR_WIDTH, color));
        print_acquisition_findings(&disks);
    }
    ExitCode::SUCCESS
}

/// Append per-disk acquisition-integrity findings (mounted, writable, removable,
/// 512e/4Kn, synthesized) from `livedisk-forensic` beneath the listing.
fn print_acquisition_findings(disks: &[livedisk::PhysicalDisk]) {
    let mut header_written = false;
    for d in disks {
        for f in livedisk_forensic::analyse(d) {
            if !header_written {
                println!("Acquisition-integrity findings:");
                header_written = true;
            }
            let sev = f.severity.map(|s| format!("[{s}] ")).unwrap_or_default();
            println!("  {}  {sev}{}: {}", d.name, f.code, f.note);
        }
    }
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
    let (file, size) = match livedisk::open_device(std::path::Path::new(path)) {
        Ok(d) => d,
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            eprintln!("disk4n6: {path}: permission denied — re-run with sudo / as Administrator");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("disk4n6: cannot open {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let mut reader: Box<dyn ReadSeek> = Box::new(file);
    // Acquisition-target findings for the specific device being imaged — notably
    // LIVE-WRITABLE (HIGH) when the target is writable, i.e. no hardware
    // write-blocker is engaged. Looked up by device path; absence is non-fatal.
    let target_findings = livedisk::enumerate()
        .map(|disks| target_findings_for(disks, path))
        .unwrap_or_default();
    report_disk(path, &mut reader, size, json, target_findings)
}

/// Resolve the acquisition-target findings for the device at `path` from the
/// enumerated live disks. Split out as a pure lookup so it is unit-testable
/// without a real device (a matched disk drives `analyse_target`); an
/// unmatched path yields no findings.
fn target_findings_for(
    disks: Vec<livedisk::PhysicalDisk>,
    path: &str,
) -> Vec<forensicnomicon::report::Finding> {
    disks
        .into_iter()
        .find(|d| d.device_path == path)
        .map(|d| livedisk_forensic::analyse_target(&d))
        .unwrap_or_default()
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
        Err(container::OpenError::LogicalContainer(fmt)) => {
            eprintln!(
                "disk4n6: {path}: {fmt:?} is a logical file container (a file tree), not a raw \
                 disk image — it has no partitions to analyse"
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
        // Proportional partition bar — the same visual `list` draws, now over an
        // image's analyzed layout so evidence files get an at-a-glance view too.
        println!();
        let color = std::io::stdout().is_terminal();
        let disk = disk_forensic::layout::from_report(&report, label, size);
        print!("{}", livedisk::render_disk_bar(&disk, BAR_WIDTH, color));
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
    fn parse_no_args_defaults_to_list() {
        assert_eq!(parse(&[]), Command::List { json: false });
        assert_eq!(parse(&["--json"]), Command::List { json: true });
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
        // "list" is no longer a subcommand — it's treated as a path to analyse.
        assert_eq!(
            parse(&["list"]),
            Command::Analyze {
                path: "list".into(),
                json: false
            }
        );
    }

    #[test]
    fn parse_usage_only_on_help() {
        assert_eq!(parse(&["-h"]), Command::Usage);
        assert_eq!(parse(&["--help"]), Command::Usage);
    }

    #[test]
    fn parse_version_flag() {
        assert_eq!(parse(&["-V"]), Command::Version);
        assert_eq!(parse(&["--version"]), Command::Version);
    }

    #[test]
    fn is_device_path_detects_unix_and_windows_nodes() {
        assert!(is_device_path("/dev/disk0"));
        assert!(is_device_path("/dev/sda"));
        assert!(is_device_path(r"\\.\PhysicalDrive0"));
        assert!(!is_device_path("evidence.E01"));
        assert!(!is_device_path("./image.raw"));
    }

    fn synthetic_disk(device_path: &str, read_only: bool) -> livedisk::PhysicalDisk {
        livedisk::PhysicalDisk {
            device_path: device_path.to_string(),
            name: "testdisk".to_string(),
            size_bytes: 1024 * 1024,
            logical_sector_size: 512,
            physical_sector_size: 512,
            model: None,
            serial: None,
            removable: false,
            read_only,
            synthesized: false,
            partitions: Vec::new(),
        }
    }

    #[test]
    fn target_findings_for_analyses_the_matching_writable_device() {
        // A writable acquisition target matched by path surfaces the
        // LIVE-WRITABLE finding (no write-blocker engaged).
        let disks = vec![synthetic_disk("/dev/testdisk", false)];
        let findings = target_findings_for(disks, "/dev/testdisk");
        assert!(
            !findings.is_empty(),
            "a writable matched target should surface findings"
        );
    }

    #[test]
    fn target_findings_for_yields_nothing_when_no_device_matches() {
        let disks = vec![synthetic_disk("/dev/testdisk", false)];
        assert!(target_findings_for(disks, "/dev/other").is_empty());
    }
}
