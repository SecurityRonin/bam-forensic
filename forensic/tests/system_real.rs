//! Tier-1 end-to-end validation of the `bam4n6` binary against a real Windows 10 1709 `SYSTEM`
//! hive — exercises the `winreg-core` control-set / `UserSettings` navigation and per-value decode
//! that the pure library does not. Env-gated on `BAM_TEST_SYSTEM_HIVE`.
//!
//! Ground truth is `regipy`'s `system.bam` plugin (`BAMPlugin`), which reads the same hive and
//! reports **55 entries** across the `bam\UserSettings` and `bam\State\UserSettings` variants of
//! `ControlSet001` — including SID `S-1-5-90-0-1`'s `\Device\HarddiskVolume2\Windows\System32\
//! dwm.exe` last executing at `2020-04-19T09:09:35.73…Z`. See `core/tests/data/README.md` for
//! provenance and how to obtain the hive.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::process::Command;

fn run(args: &[&str], hive: &str) -> String {
    let mut a = args.to_vec();
    a.push(hive);
    let out = Command::new(env!("CARGO_BIN_EXE_bam4n6"))
        .args(&a)
        .output()
        .expect("run bam4n6");
    assert!(out.status.success(), "bam4n6 failed: {:?}", out.status);
    String::from_utf8_lossy(&out.stdout).into_owned()
}

#[test]
fn bam4n6_matches_the_regipy_oracle_on_a_real_system_hive() {
    let Ok(hive) = std::env::var("BAM_TEST_SYSTEM_HIVE") else {
        eprintln!(
            "SKIP: set BAM_TEST_SYSTEM_HIVE to a real Win10 1709 SYSTEM hive (regipy corpus)"
        );
        return;
    };

    // Summary: regipy's BAMPlugin reports 55 entries across 2 SIDs on this hive.
    let summary = run(&[], &hive);
    assert!(
        summary.contains("55 execution records across 2 user SID(s)"),
        "unexpected summary; got: {summary}"
    );

    // --list reproduces the specific (SID, path, last-execution) rows the oracle reports.
    let listing = run(&["--list"], &hive);
    // The two SIDs regipy found.
    assert!(
        listing.contains("SID S-1-5-90-0-1"),
        "missing SID; got: {listing}"
    );
    assert!(
        listing.contains("SID S-1-5-21-2595688666-2948619230-3055395256-1001"),
        "missing SID; got: {listing}"
    );
    // dwm.exe under S-1-5-90-0-1 last executed 2020-04-19T09:09:35.7318159Z
    // (raw FILETIME 132317609757318159), matching the regipy validation case.
    assert!(
        listing.contains(
            "2020-04-19T09:09:35.7318159Z  \\Device\\HarddiskVolume2\\Windows\\System32\\dwm.exe"
        ),
        "missing dwm.exe last-execution row; got: {listing}"
    );
}
