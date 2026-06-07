//! End-to-end tests for the `disk-forensic` binary.

mod common;
use common::{build_gpt, build_mbr};
use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_disk4n6"))
}

const APM_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/apm.bin");

fn write_tmp(tag: &str, bytes: &[u8]) -> PathBuf {
    let p = std::env::temp_dir().join(format!("df_e2e_{}_{tag}.img", std::process::id()));
    std::fs::write(&p, bytes).unwrap();
    p
}

#[test]
fn unsupported_container_is_reported_not_misparsed() {
    // A not-yet-decodable container (AFF4) must be recognized and reported, not
    // blindly fed to the partition parsers. (E01/VMDK are now decoded.)
    let mut data = vec![0u8; 1024];
    data[..4].copy_from_slice(&[0x50, 0x4B, 0x03, 0x04]); // ZIP/AFF4 "PK\x03\x04"
    let p = write_tmp("aff4", &data);
    let out = bin().arg(&p).output().unwrap();
    assert_eq!(
        out.status.code(),
        Some(2),
        "container is a usage-class error"
    );
    assert!(
        String::from_utf8_lossy(&out.stderr)
            .to_lowercase()
            .contains("container"),
        "stderr should name it a container: {:?}",
        String::from_utf8_lossy(&out.stderr)
    );
    let _ = std::fs::remove_file(&p);
}

#[test]
fn analyses_apm_image() {
    let out = bin().arg(APM_FIXTURE).output().unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    assert!(s.contains("APM Forensic Analysis"), "{s}");
}

#[test]
fn analyses_mbr_image() {
    let p = write_tmp("mbr", &build_mbr());
    let out = bin().arg(&p).output().unwrap();
    assert!(String::from_utf8_lossy(&out.stdout).contains("MBR Forensic Analysis"));
    let _ = std::fs::remove_file(&p);
}

#[test]
fn analyses_gpt_image() {
    let p = write_tmp("gpt", &build_gpt());
    let out = bin().arg(&p).output().unwrap();
    let s = String::from_utf8_lossy(&out.stdout);
    // Protective-MBR cross-check AND the full GPT report from gpt-forensic.
    assert!(s.contains("GPT cross-check"), "{s}");
    assert!(s.contains("GPT Forensic Analysis"), "{s}");
    assert!(s.contains("GPT SHA-256:"), "{s}");
    let _ = std::fs::remove_file(&p);
}

#[test]
fn unknown_scheme_exits_failure() {
    let p = write_tmp("zero", &vec![0u8; 4096]);
    let out = bin().arg(&p).output().unwrap();
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("unrecognised"));
    let _ = std::fs::remove_file(&p);
}

#[test]
fn no_args_prints_usage() {
    let out = bin().output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage"));
}

#[test]
fn help_flag_prints_usage() {
    let out = bin().arg("--help").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
}

#[test]
fn missing_file_errors() {
    let out = bin().arg("/nonexistent/nope.img").output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("cannot open"));
}

#[cfg(feature = "serde")]
#[test]
fn json_output_emits_scheme() {
    let out = bin().args(["--json", APM_FIXTURE]).output().unwrap();
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("Apm"));
}
