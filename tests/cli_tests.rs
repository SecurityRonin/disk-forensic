//! End-to-end tests for the `disk-forensic` binary.

mod common;
use common::{build_gpt, build_mbr};
use std::path::PathBuf;
use std::process::Command;

fn bin() -> Command {
    Command::new(env!("CARGO_BIN_EXE_disk-forensic"))
}

const APM_FIXTURE: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/data/apm.bin");

fn write_tmp(tag: &str, bytes: &[u8]) -> PathBuf {
    let p = std::env::temp_dir().join(format!("df_e2e_{}_{tag}.img", std::process::id()));
    std::fs::write(&p, bytes).unwrap();
    p
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
    assert!(String::from_utf8_lossy(&out.stdout).contains("GPT cross-check"));
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
