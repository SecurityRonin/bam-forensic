//! Fuzz target: run the analyzer over arbitrary bytes as a BAM record.
//! Invariant: `audit` (and the device-path normalization it does) never panics on any path,
//! including non-UTF-8-derived, multibyte, and truncated `\Device\HarddiskVolumeN` strings.
#![no_main]
use bam_forensic::{audit, BamEntry};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let path = String::from_utf8_lossy(data).into_owned();
    let filetime = data
        .get(..8)
        .and_then(|b| b.try_into().ok())
        .map_or(0, u64::from_le_bytes);
    let _ = audit(&[BamEntry {
        path,
        last_executed_filetime: filetime,
    }]);
});
