//! `disk4n6` — auto-detect a disk's partitioning scheme and analyse it.
//!
//! Usage:
//!   disk4n6 <image>          # human-readable report
//!   disk4n6 --json <image>   # JSON (requires the `serde` feature)

use std::fs::File;
use std::process::ExitCode;

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

    let mut file = match File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("disk4n6: cannot open {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let size = file.metadata().map(|m| m.len()).unwrap_or(0);

    let report = match disk_forensic::analyse_disk(&mut file, size) {
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
    }

    if report.has_anomalies() {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}
