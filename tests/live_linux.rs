//! Deterministic Linux live-enumeration test via a loopback block device.
//!
//! Rather than spinning up a full VM/QEMU, attach a crafted GPT image as a
//! `/dev/loopN` device (`losetup -P`) so it appears in `/sys/block`, then assert
//! `disk4n6 list` enumerates it. This validates the real sysfs backend against a
//! known device on the Linux CI runner (where passwordless `sudo` is available);
//! it auto-skips anywhere `sudo losetup` is not usable, so local `cargo test`
//! stays green.

#![allow(clippy::unwrap_used, clippy::expect_used)]
#![cfg(target_os = "linux")]

mod common;
use common::build_gpt;
use std::process::Command;

/// Passwordless `sudo losetup` available (true on GitHub's Ubuntu runners).
fn sudo_losetup_available() -> bool {
    Command::new("sudo")
        .args(["-n", "losetup", "--version"])
        .output()
        .is_ok_and(|o| o.status.success())
}

#[test]
fn list_enumerates_a_loopback_device() {
    if !sudo_losetup_available() {
        eprintln!("skipping: passwordless `sudo losetup` not available");
        return;
    }

    let img = std::env::temp_dir().join(format!("df_loop_{}.img", std::process::id()));
    std::fs::write(&img, build_gpt()).expect("write GPT image");

    let attach = Command::new("sudo")
        .args(["losetup", "--find", "--show", "-P"])
        .arg(&img)
        .output()
        .expect("run losetup");
    assert!(
        attach.status.success(),
        "losetup failed: {}",
        String::from_utf8_lossy(&attach.stderr)
    );
    let dev = String::from_utf8_lossy(&attach.stdout).trim().to_string(); // /dev/loopN
    let name = dev.trim_start_matches("/dev/").to_string();

    // No argument → default listing.
    let listing = Command::new(env!("CARGO_BIN_EXE_disk4n6"))
        .output()
        .expect("run disk4n6 (default list)");
    let stdout = String::from_utf8_lossy(&listing.stdout).into_owned();

    // Detach and clean up before asserting, so a failure does not leak the device.
    let _ = Command::new("sudo")
        .args(["losetup", "-d"])
        .arg(&dev)
        .output();
    let _ = std::fs::remove_file(&img);

    assert!(
        listing.status.success(),
        "list exited {:?}: {}",
        listing.status.code(),
        String::from_utf8_lossy(&listing.stderr)
    );
    assert!(
        stdout.contains(&name),
        "expected the loopback device {name} in the listing:\n{stdout}"
    );
}
