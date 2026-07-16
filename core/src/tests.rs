//! Unit tests for the pure BAM/DAM value decoder. Synthetic `(name, bytes)` inputs exercise the
//! `FILETIME` decode, the too-short / empty / padding paths, and real-shaped BAM records (a
//! 24-byte value from a Windows 10 hive: 8-byte `FILETIME` + 16 bytes padding). The whole-hive
//! path is validated Tier-1 against a real `SYSTEM` hive + the `regipy` BAM oracle in
//! `../../forensic/tests/system_real.rs`.

use super::*;

/// Build a real-shaped BAM value: an 8-byte little-endian `FILETIME` followed by `pad` NUL bytes
/// (Windows 10 writes 16 trailing bytes, for a 24-byte value).
fn value(filetime: u64, pad: usize) -> Vec<u8> {
    let mut v = filetime.to_le_bytes().to_vec();
    v.extend(std::iter::repeat(0u8).take(pad));
    v
}

#[test]
fn decodes_path_and_filetime_from_a_real_shaped_value() {
    // dwm.exe from the Win10 1709 CFReDS-style hive: raw FILETIME 132_317_609_757_318_159,
    // 24-byte value (8-byte time + 16 padding) — the exact shape BAM writes.
    let name = r"\Device\HarddiskVolume2\Windows\System32\dwm.exe";
    let e = decode_entry(name, &value(132_317_609_757_318_159, 16)).expect("decodes");
    assert_eq!(e.path, name);
    assert_eq!(e.last_executed_filetime, 132_317_609_757_318_159);
}

#[test]
fn filetime_is_little_endian() {
    // 0x0807_0605_0403_0201 stored LE as 01 02 03 04 05 06 07 08.
    let data = [1u8, 2, 3, 4, 5, 6, 7, 8];
    let e = decode_entry("x.exe", &data).expect("decodes");
    assert_eq!(e.last_executed_filetime, 0x0807_0605_0403_0201);
}

#[test]
fn exactly_eight_bytes_decodes_with_no_padding() {
    let e = decode_entry("x.exe", &42u64.to_le_bytes()).expect("decodes");
    assert_eq!(e.last_executed_filetime, 42);
    assert_eq!(e.path, "x.exe");
}

#[test]
fn padding_beyond_eight_bytes_is_ignored() {
    // Junk in the padding must not affect the decoded time or path.
    let mut data = 7u64.to_le_bytes().to_vec();
    data.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef, 0xff, 0xff]);
    let e = decode_entry("app.exe", &data).expect("decodes");
    assert_eq!(e.last_executed_filetime, 7);
}

#[test]
fn appx_package_family_name_is_kept_verbatim() {
    // Store apps appear under their package-family name, not a \Device path.
    let name = "Microsoft.Windows.Cortana_cw5n1h2txyewy";
    let e = decode_entry(name, &value(132_024_836_358_171_779, 16)).expect("decodes");
    assert_eq!(e.path, name);
}

#[test]
fn too_short_data_is_none() {
    // The 4-byte SequenceNumber / Version REG_DWORD metadata values are shorter than a FILETIME.
    assert_eq!(decode_entry("SequenceNumber", &[9, 0, 0, 0]), None);
    assert_eq!(decode_entry("Version", &[1, 0, 0, 0]), None);
    // Seven bytes is still one short.
    assert_eq!(decode_entry("x.exe", &[0, 0, 0, 0, 0, 0, 0]), None);
}

#[test]
fn empty_data_is_none() {
    assert_eq!(decode_entry("x.exe", &[]), None);
}

#[test]
fn empty_name_is_none() {
    // The unnamed/default value is not an executable record.
    assert_eq!(decode_entry("", &value(1, 16)), None);
}

#[test]
fn bam_entry_default_is_empty() {
    let d = BamEntry::default();
    assert!(d.path.is_empty());
    assert_eq!(d.last_executed_filetime, 0);
}
