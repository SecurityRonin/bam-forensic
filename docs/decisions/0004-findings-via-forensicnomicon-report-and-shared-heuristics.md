# 4. Grade findings through forensicnomicon::report and shared heuristics

Date: 2026-07-24
Status: Accepted

## Context

The analyzer must emit anomalies (masquerading, staging-directory execution) in a
form Issen/disk4n6 and a future GUI can render uniformly, rather than a bespoke
`BamAnalysis` type. The fleet's reporting model (`ronin-issen/CLAUDE.md`, "The
Reporting Model — `forensicnomicon::report`") defines a single normalized
finding vocabulary every analyzer emits via `impl Observation`. Two of the
judgments BAM needs — "is this a Windows system-binary name?" and "is this path a
common staging directory?" — are reference facts shared fleet-wide; embedding
private copies would fork that knowledge and let it drift
(knowledge-as-code principle).

## Decision

Model each anomaly as a `BamAnomaly` enum and `impl forensicnomicon::report::
Observation` for it, mapping to canonical severity/category/code/note/MITRE
(`forensic/src/lib.rs`). Published contract codes are scheme-prefixed
SCREAMING-KEBAB — `BAM-SYSTEM-BINARY-RELOCATED` (High, `Category::Concealment`,
`T1036.005`) and `BAM-SUSPICIOUS-PATH` (Medium, `Category::Threat`, `T1204`).
The two classification decisions delegate to the shared catalog:
`forensicnomicon::processes::is_system32_binary` and
`forensicnomicon::heuristics::paths::is_suspicious_exec_path`. BAM stores kernel
device paths, so `normalize_device_path` strips the `\Device\HarddiskVolumeN`
prefix before the shared path heuristic runs, while the finding keeps the
verbatim recorded path. Notes use "consistent with", never a verdict.

## Consequences

- BAM findings aggregate into one `forensicnomicon::report::Report` alongside
  every other analyzer, with no adapter.
- The system-binary list and staging-directory list update once, fleet-wide, in
  `forensicnomicon`; BAM picks them up on a version bump and stays a full-featured
  dependency (`forensicnomicon = "1"`, batteries-included — no feature gate on the
  decode/enrichment path).
- The two shipped codes are a published contract; new variants must take new
  codes, never redefine these.
- Findings are observations, not conclusions — the analyst/tribunal decides
  intent; the analyzer only reports that a binary at a path ran at a time.
