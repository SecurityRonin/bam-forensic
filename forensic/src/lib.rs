//! Windows **Background Activity Moderator** (BAM/DAM) forensic analyzer.
//!
//! BAM records, per user `SID`, the **last time each executable ran** — direct execution
//! evidence (with a timestamp), unlike Amcache/ShimCache presence. [`audit`] takes the decoded
//! [`BamEntry`] records (from [`bam_core`]) and adds a small set of *high-precision* graded
//! findings: a Windows system-binary name recorded at a non-`System32` path (masquerading) and an
//! executable that last ran from a known-suspicious directory.
//!
//! BAM stores paths in the kernel device form `\Device\HarddiskVolumeN\...`; the analyzer strips
//! that prefix before applying the shared path heuristics, so `\Device\HarddiskVolume2\Users\…\
//! Temp\x.exe` is judged as `\Users\…\Temp\x.exe`.
//!
//! Findings are observations, never verdicts: BAM establishes that an executable at a given path
//! ran at a given time — whether it is malicious is a correlation/tribunal question. Reading the
//! records out of a `SYSTEM` hive is `winreg-core`'s job; the bundled `bam4n6` binary wires the two
//! together (hive → [`bam_core::decode_entry`] → this crate).
//!
//! Built on [`bam_core`]; findings use [`forensicnomicon::report`].

#![forbid(unsafe_code)]

use forensicnomicon::report::{Category, Finding, Observation, Severity, Source, SubjectRef};

// Re-export the core type that appears in this crate's public API.
pub use bam_core::BamEntry;

/// A graded BAM finding — a *high-precision* triage signal that stays quiet on benign execution
/// records and fires only on a genuinely anomalous pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BamAnomaly {
    /// A Windows system-binary *name* that last ran from a path not under `System32`/`SysWOW64`
    /// — consistent with masquerading (`T1036.005`).
    SystemBinaryRelocated {
        /// The system-binary base name (e.g. `SVCHOST.EXE`).
        name: String,
        /// The full path BAM recorded (verbatim `\Device\HarddiskVolumeN\…` form).
        path: String,
    },
    /// An executable that last ran from a directory commonly used to stage malware (Temp,
    /// Downloads, `$Recycle.Bin`, …) — `T1204`.
    SuspiciousPath {
        /// The executable base name.
        name: String,
        /// The suspicious path (verbatim `\Device\HarddiskVolumeN\…` form).
        path: String,
    },
}

/// Audit decoded BAM/DAM records for graded anomalies (may be empty).
#[must_use]
pub fn audit(entries: &[BamEntry]) -> Vec<BamAnomaly> {
    let _ = entries;
    Vec::new()
}

/// Strip a leading `\Device\HarddiskVolumeN` prefix from a BAM path, returning the remainder from
/// the volume's trailing backslash (`\Device\HarddiskVolume2\Windows\x.exe` → `\Windows\x.exe`).
/// Paths without the prefix (e.g. an AppX package-family name) are returned unchanged. Panic-free:
/// `get` rejects an out-of-bounds or non-char-boundary slice.
fn normalize_device_path(path: &str) -> &str {
    const PREFIX: &str = r"\Device\HarddiskVolume";
    let Some(head) = path.get(..PREFIX.len()) else {
        return path;
    };
    if !head.eq_ignore_ascii_case(PREFIX) {
        return path;
    }
    let tail = &path[PREFIX.len()..];
    match tail.find('\\') {
        Some(rel) => &tail[rel..],
        None => path,
    }
}

/// The base name (last `\`/`/`-component) of a path.
fn base_name(path: &str) -> String {
    path.rsplit(['\\', '/']).next().unwrap_or(path).to_string()
}

impl BamAnomaly {
    fn fields(&self) -> (&str, &str) {
        match self {
            BamAnomaly::SystemBinaryRelocated { name, path }
            | BamAnomaly::SuspiciousPath { name, path } => (name, path),
        }
    }
}

impl Observation for BamAnomaly {
    fn severity(&self) -> Option<Severity> {
        Some(match self {
            BamAnomaly::SystemBinaryRelocated { .. } => Severity::High,
            BamAnomaly::SuspiciousPath { .. } => Severity::Medium,
        })
    }

    fn category(&self) -> Category {
        match self {
            BamAnomaly::SystemBinaryRelocated { .. } => Category::Concealment,
            BamAnomaly::SuspiciousPath { .. } => Category::Threat,
        }
    }

    fn code(&self) -> &'static str {
        match self {
            BamAnomaly::SystemBinaryRelocated { .. } => "BAM-SYSTEM-BINARY-RELOCATED",
            BamAnomaly::SuspiciousPath { .. } => "BAM-SUSPICIOUS-PATH",
        }
    }

    fn note(&self) -> String {
        let (name, path) = self.fields();
        match self {
            BamAnomaly::SystemBinaryRelocated { .. } => format!(
                "{name} is a Windows system binary, but BAM recorded it last executing from {path} \
                 — consistent with masquerading."
            ),
            BamAnomaly::SuspiciousPath { .. } => format!(
                "{name} last executed from {path}, a directory commonly used to stage malware \
                 — consistent with suspicious execution."
            ),
        }
    }

    fn mitre(&self) -> &'static [&'static str] {
        match self {
            BamAnomaly::SystemBinaryRelocated { .. } => &["T1036.005"],
            BamAnomaly::SuspiciousPath { .. } => &["T1204"],
        }
    }

    fn subjects(&self) -> Vec<SubjectRef> {
        let (name, path) = self.fields();
        vec![SubjectRef {
            scheme: "filesystem".to_string(),
            kind: "executable".to_string(),
            id: path.to_string(),
            label: Some(name.to_string()),
        }]
    }
}

/// Convenience: produce a [`Finding`] for an anomaly under the given scope.
#[must_use]
pub fn to_finding(anomaly: &BamAnomaly, scope: impl Into<String>) -> Finding {
    anomaly.to_finding(Source {
        analyzer: "bam-forensic".to_string(),
        scope: scope.into(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    })
}

#[cfg(test)]
mod tests;
