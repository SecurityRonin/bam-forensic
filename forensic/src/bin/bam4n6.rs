//! `bam4n6` — read a Windows `SYSTEM` hive's Background/Desktop Activity Moderator (BAM/DAM) and
//! print, per user `SID`, the last-execution time of every executable, plus graded findings.
//!
//! The decoding + analysis live in the `bam_forensic` / `bam_core` libraries; this binary only
//! wires `winreg-core` (open the hive, walk `Services\bam\State\UserSettings\{SID}` and the
//! `bam\UserSettings` / `dam` variants across control sets, read each value) to
//! [`bam_core::decode_entry`] and [`bam_forensic::audit`], then renders the result.
#![forbid(unsafe_code)]

use std::io::Cursor;
use std::process::ExitCode;

use bam_core::{decode_entry, BamEntry};
use bam_forensic::{audit, BamAnomaly};
use forensicnomicon::report::Observation;
use winreg_core::hive::Hive;
use winreg_core::key::filetime_to_datetime;

/// The per-`SID` `UserSettings` sub-paths BAM/DAM records live under, within one control set.
/// Newer builds use the `State\UserSettings` layout; early Windows 10 1709 used
/// `UserSettings` directly. A hive may populate one or both — walk every variant (as RegRipper's
/// `bam.pl` and `regipy`'s `system.bam` do), so no records are missed.
const USER_SETTINGS_PATHS: &[&str] = &[
    r"Services\bam\State\UserSettings",
    r"Services\bam\UserSettings",
    r"Services\dam\State\UserSettings",
    r"Services\dam\UserSettings",
];

/// Per-`SID` metadata value names that are not execution records (4-byte `REG_DWORD`s). BAM's
/// documented schema reserves these two names; skip them by name so they are never mistaken for
/// an executable path.
const METADATA_VALUE_NAMES: &[&str] = &["SequenceNumber", "Version"];

/// One decoded record with the `SID` it belongs to (for grouping in `--list`).
struct Record {
    sid: String,
    entry: BamEntry,
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let list = args.iter().any(|a| a == "--list");
    let Some(hive_path) = args.iter().find(|a| !a.starts_with("--")) else {
        eprintln!(
            "usage: bam4n6 <SYSTEM-hive> [--list]   (--list dumps every record, grouped by SID)"
        );
        return ExitCode::from(2);
    };

    match run(hive_path) {
        Ok(records) => {
            print_report(&records, list);
            ExitCode::SUCCESS
        }
        Err(msg) => {
            eprintln!("bam4n6: {hive_path}: {msg}");
            ExitCode::FAILURE
        }
    }
}

/// Open the hive and collect every BAM/DAM record across control sets and path variants. Returns
/// a human message on any failure (the binary reports it and exits non-zero).
fn run(hive_path: &str) -> Result<Vec<Record>, String> {
    let hive = Hive::from_path(std::path::Path::new(hive_path)).map_err(|e| format!("{e}"))?;
    collect_records(&hive)
}

/// Walk `ControlSet001`/`ControlSet002` × every `UserSettings` variant, and under each `{SID}`
/// decode every value into a [`Record`].
fn collect_records(hive: &Hive<Cursor<Vec<u8>>>) -> Result<Vec<Record>, String> {
    let mut records = Vec::new();
    for cs in ["ControlSet001", "ControlSet002"] {
        for sub in USER_SETTINGS_PATHS {
            let path = format!("{cs}\\{sub}");
            let Some(user_settings) = hive.open_key(&path).map_err(|e| format!("{e}"))? else {
                continue;
            };
            for sid_key in user_settings.subkeys().map_err(|e| format!("{e}"))? {
                let sid = sid_key.name();
                for value in sid_key.values().map_err(|e| format!("{e}"))? {
                    let name = value.name();
                    if METADATA_VALUE_NAMES
                        .iter()
                        .any(|m| m.eq_ignore_ascii_case(&name))
                    {
                        continue;
                    }
                    let data = value.raw_data().map_err(|e| format!("{e}"))?;
                    if let Some(entry) = decode_entry(&name, &data) {
                        records.push(Record {
                            sid: sid.clone(),
                            entry,
                        });
                    }
                }
            }
        }
    }
    Ok(records)
}

fn print_report(records: &[Record], list: bool) {
    let sid_count = records
        .iter()
        .map(|r| r.sid.as_str())
        .collect::<std::collections::BTreeSet<_>>()
        .len();
    println!(
        "BAM/DAM: {} execution records across {} user SID(s)",
        records.len(),
        sid_count
    );

    let entries: Vec<BamEntry> = records.iter().map(|r| r.entry.clone()).collect();
    let anomalies = audit(&entries);
    if anomalies.is_empty() {
        println!("Findings: none");
    } else {
        println!("Findings ({}):", anomalies.len());
        for a in &anomalies {
            let sev = a
                .severity()
                .map_or_else(|| "INFO".to_string(), |s| format!("{s:?}").to_uppercase());
            println!("  [{sev}] {}  {}", a.code(), subject_path(a));
            println!("    {}", a.note());
        }
    }

    if list {
        let mut by_sid: std::collections::BTreeMap<&str, Vec<&Record>> =
            std::collections::BTreeMap::new();
        for r in records {
            by_sid.entry(r.sid.as_str()).or_default().push(r);
        }
        for (sid, recs) in by_sid {
            println!("\nSID {sid} ({} records):", recs.len());
            for r in recs {
                let when = filetime_to_datetime(r.entry.last_executed_filetime)
                    .map_or_else(|| "-".to_string(), |t| t.to_string());
                println!("  {when}  {}", r.entry.path);
            }
        }
    }
}

/// The path a finding points at (for the one-line summary).
fn subject_path(a: &BamAnomaly) -> &str {
    match a {
        BamAnomaly::SystemBinaryRelocated { path, .. }
        | BamAnomaly::SuspiciousPath { path, .. } => path,
    }
}
