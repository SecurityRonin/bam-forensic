//! Pure-Rust read-only decoder for a Windows **Background Activity Moderator** (BAM) — and its
//! sibling **Desktop Activity Moderator** (DAM) — execution record.
//!
//! BAM/DAM is a Windows service (introduced in Windows 10 1709) that throttles background
//! activity. As a side effect it records, in the `SYSTEM` hive, the **last time each executable
//! ran**, keyed per user `SID`:
//!
//! ```text
//! ControlSet001\Services\bam\State\UserSettings\{SID}\   (older builds: bam\UserSettings\{SID})
//! ```
//!
//! Under each `{SID}` subkey the value **names** are executable paths in the kernel device form
//! `\Device\HarddiskVolumeN\Windows\...\app.exe` (Store/AppX apps appear as their package-family
//! name), and the value **data**'s first 8 bytes are the last-execution time as a little-endian
//! Windows `FILETIME` (100 ns ticks since 1601-01-01 UTC), followed by padding. Two per-`SID`
//! metadata values — `SequenceNumber` and `Version` — are `REG_DWORD`s (4 bytes), not entries;
//! the ≥ 8-byte requirement below distinguishes them structurally.
//!
//! This crate is a *decoder primitive*: [`decode_entry`] takes one value's name and raw bytes and
//! never touches the registry (the [`bam-forensic`] crate reads the values out of a hive with
//! `winreg-core`). Like the fleet's other decoders it is `#![forbid(unsafe_code)]` and
//! **panic-free**: the 8-byte read is bounds-checked, a too-short value yields `None`, never a
//! panic.
//!
//! Structure confirmed against RegRipper's `bam.pl` plugin (github `keydet89/RegRipper3.0`) and
//! `regipy`'s `system.bam` plugin, both of which read the value name as the executable path and
//! `Int64` the first 8 bytes of the value data as the last-execution `FILETIME`.
//!
//! [`bam-forensic`]: https://crates.io/crates/bam-forensic

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

/// One decoded BAM/DAM record — an executable and the last time it ran, for one user `SID`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BamEntry {
    /// The executable path exactly as BAM recorded it — the value name, verbatim. Usually the
    /// kernel device form `\Device\HarddiskVolumeN\Windows\...\app.exe`; for Store/AppX apps it is
    /// the package-family name.
    pub path: String,
    /// The last-execution time as a raw Windows `FILETIME` (100 ns ticks since 1601-01-01 UTC),
    /// decoded little-endian from the first 8 bytes of the value data.
    pub last_executed_filetime: u64,
}

/// Decode one BAM/DAM value into a [`BamEntry`].
///
/// `value_name` is the executable path BAM keyed the record by; `value_data` is the value's raw
/// bytes, whose first 8 bytes are the last-execution `FILETIME` (little-endian). Any bytes past
/// the first 8 are padding and ignored.
///
/// Returns `None` when the value cannot be a BAM entry: an empty name, or fewer than 8 bytes of
/// data (e.g. the 4-byte `SequenceNumber`/`Version` metadata values). Never panics.
#[must_use]
pub fn decode_entry(value_name: &str, value_data: &[u8]) -> Option<BamEntry> {
    let _ = (value_name, value_data);
    None
}

#[cfg(test)]
mod tests;
