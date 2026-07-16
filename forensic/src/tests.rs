//! Unit tests for the BAM analyzer: device-path normalization, the audit heuristics, and the
//! `Observation` mapping. The whole-hive path is validated Tier-1 against a real Windows 10 1709
//! `SYSTEM` hive + the `regipy` BAM oracle in `tests/system_real.rs`.
#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::*;

fn entry(path: &str) -> BamEntry {
    BamEntry {
        path: path.to_string(),
        last_executed_filetime: 132_317_609_757_318_159,
    }
}

// ── device-path normalization ───────────────────────────────────────────────

#[test]
fn normalize_strips_the_device_volume_prefix() {
    assert_eq!(
        normalize_device_path(r"\Device\HarddiskVolume2\Windows\System32\dwm.exe"),
        r"\Windows\System32\dwm.exe"
    );
    // Multi-digit volume numbers strip correctly (return starts at the volume's backslash).
    assert_eq!(
        normalize_device_path(r"\Device\HarddiskVolume12\Users\a\x.exe"),
        r"\Users\a\x.exe"
    );
}

#[test]
fn normalize_leaves_a_non_device_path_unchanged() {
    // An AppX package-family name has no device prefix.
    assert_eq!(
        normalize_device_path("Microsoft.Windows.Cortana_cw5n1h2txyewy"),
        "Microsoft.Windows.Cortana_cw5n1h2txyewy"
    );
    assert_eq!(
        normalize_device_path(r"C:\Windows\x.exe"),
        r"C:\Windows\x.exe"
    );
}

#[test]
fn normalize_is_panic_free_on_edge_inputs() {
    // Prefix present but no trailing backslash after the volume number → unchanged.
    assert_eq!(
        normalize_device_path(r"\Device\HarddiskVolume2"),
        r"\Device\HarddiskVolume2"
    );
    // Shorter than the prefix → unchanged (bounds-checked, no panic).
    assert_eq!(normalize_device_path(r"\Dev"), r"\Dev");
    assert_eq!(normalize_device_path(""), "");
    // A multibyte char inside the prefix window must not panic.
    assert_eq!(normalize_device_path("\\Device\\Härd"), "\\Device\\Härd");
}

#[test]
fn base_name_takes_the_last_component() {
    assert_eq!(base_name(r"\Windows\System32\dwm.exe"), "dwm.exe");
    assert_eq!(base_name("bare.exe"), "bare.exe");
}

// ── audit heuristics ────────────────────────────────────────────────────────

#[test]
fn system_binary_at_non_system_path_flags_masquerading() {
    let a = audit(&[entry(r"\Device\HarddiskVolume1\Temp\svchost.exe")]);
    assert!(a.iter().any(|x| matches!(
        x,
        BamAnomaly::SystemBinaryRelocated { name, path }
            if name == "SVCHOST.EXE" && path == r"\Device\HarddiskVolume1\Temp\svchost.exe"
    )));
}

#[test]
fn system_binary_in_system32_is_not_flagged() {
    let a = audit(&[entry(
        r"\Device\HarddiskVolume2\Windows\System32\svchost.exe",
    )]);
    assert!(
        !a.iter()
            .any(|x| matches!(x, BamAnomaly::SystemBinaryRelocated { .. })),
        "a System32 svchost must not be flagged: {a:?}"
    );
}

#[test]
fn suspicious_path_is_flagged_after_stripping_the_device_prefix() {
    let a = audit(&[entry(
        r"\Device\HarddiskVolume2\Users\a\AppData\Local\Temp\dropper.exe",
    )]);
    match a
        .into_iter()
        .find(|x| matches!(x, BamAnomaly::SuspiciousPath { .. }))
    {
        Some(BamAnomaly::SuspiciousPath { name, path }) => {
            assert_eq!(name, "dropper.exe");
            // The finding preserves the verbatim device path BAM recorded.
            assert_eq!(
                path,
                r"\Device\HarddiskVolume2\Users\a\AppData\Local\Temp\dropper.exe"
            );
        }
        other => panic!("expected SuspiciousPath, got {other:?}"),
    }
}

#[test]
fn benign_entry_and_appx_name_are_quiet() {
    let a = audit(&[
        entry(r"\Device\HarddiskVolume2\Program Files\App\app.exe"),
        entry("Microsoft.Windows.Cortana_cw5n1h2txyewy"),
        // Edge path that hits the normalize find-None branch — no finding either.
        entry(r"\Device\HarddiskVolume2"),
    ]);
    assert!(a.is_empty(), "benign inventory should be quiet: {a:?}");
}

// ── Observation mapping ─────────────────────────────────────────────────────

#[test]
fn observation_maps_all_fields_for_both_variants() {
    let reloc = BamAnomaly::SystemBinaryRelocated {
        name: "SVCHOST.EXE".to_string(),
        path: r"\Device\HarddiskVolume1\Temp\svchost.exe".to_string(),
    };
    assert_eq!(reloc.severity(), Some(Severity::High));
    assert_eq!(reloc.category(), Category::Concealment);
    assert_eq!(reloc.code(), "BAM-SYSTEM-BINARY-RELOCATED");
    assert_eq!(reloc.mitre(), &["T1036.005"]);
    assert!(reloc.note().contains("masquerading"));
    let subs = reloc.subjects();
    assert_eq!(subs.len(), 1);
    assert_eq!(subs[0].scheme, "filesystem");
    assert_eq!(subs[0].label.as_deref(), Some("SVCHOST.EXE"));
    let _ = to_finding(&reloc, "SYSTEM");

    let susp = BamAnomaly::SuspiciousPath {
        name: "x.exe".to_string(),
        path: r"\Device\HarddiskVolume2\Users\a\Temp\x.exe".to_string(),
    };
    assert_eq!(susp.severity(), Some(Severity::Medium));
    assert_eq!(susp.category(), Category::Threat);
    assert_eq!(susp.code(), "BAM-SUSPICIOUS-PATH");
    assert_eq!(susp.mitre(), &["T1204"]);
    assert!(susp.note().contains("suspicious execution"));
    assert_eq!(
        susp.subjects()[0].id,
        r"\Device\HarddiskVolume2\Users\a\Temp\x.exe"
    );
    let _ = to_finding(&susp, "SYSTEM");
}
