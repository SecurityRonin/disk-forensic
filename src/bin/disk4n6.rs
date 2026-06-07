//! `disk4n6` — auto-detect a disk's partitioning scheme and analyse it.
//!
//! Usage:
//!   disk4n6 <image>          # human-readable report
//!   disk4n6 --json <image>   # JSON (requires the `serde` feature)

use std::process::ExitCode;

/// Analyse an optical (ISO 9660) filesystem image and render its report.
fn analyse_filesystem(
    path: &str,
    reader: &mut Box<dyn disk_forensic::container::ReadSeek>,
    json: bool,
) -> ExitCode {
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

fn main() -> ExitCode {
    let mut json = false;
    let mut path: Option<String> = None;
    for arg in std::env::args().skip(1) {
        match arg.as_str() {
            "--json" => json = true,
            "-h" | "--help" => {
                eprintln!("usage: disk4n6 [--json] <image>");
                return ExitCode::from(2);
            }
            _ => path = Some(arg),
        }
    }
    let Some(path) = path else {
        eprintln!("usage: disk4n6 [--json] <image>");
        return ExitCode::from(2);
    };

    // Sniff + decode the container (raw passes through; E01 is decoded; other
    // recognized containers report "decode first" and exit).
    let mut opened = match disk_forensic::container::open(std::path::Path::new(&path)) {
        Ok(o) => o,
        Err(disk_forensic::container::OpenError::Unsupported(fmt)) => {
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

    // Optical (ISO 9660) images are filesystems, not partitioned disks — route
    // them to the filesystem analyzer and render the same normalized report.
    if opened.format == disk_forensic::container::ContainerFormat::Iso {
        return analyse_filesystem(&path, &mut opened.reader, json);
    }

    let report = match disk_forensic::analyse_disk(&mut opened.reader, opened.size) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("disk4n6: {path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    if json {
        #[cfg(feature = "serde")]
        {
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
            eprintln!("disk4n6: --json requires the `serde` feature");
            return ExitCode::from(2);
        }
    } else {
        println!("Scheme: {:?}\n", report.scheme());
        print!("{}", disk_forensic::report::text_report(&report));
        println!();
        // Unified cross-scheme findings view (the normalized report model).
        print!(
            "{}",
            disk_forensic::report::render(&disk_forensic::normalize::report(&report))
        );
    }

    if report.has_anomalies() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
