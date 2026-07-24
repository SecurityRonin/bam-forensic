# 3. Reuse winreg-core for SYSTEM-hive parsing

Date: 2026-07-24
Status: Accepted

## Context

The `bam4n6` binary must open a `SYSTEM` hive and navigate the REGF structure
(`ControlSet00N\Services\bam\State\UserSettings\{SID}`), read subkeys and value
data. A general REGF parser is a substantial, security-sensitive piece of code
(it parses attacker-controllable evidence). The fleet already publishes one:
`winreg-core` (the reader crate of the `winreg-forensic` repo). The binding
"Dependency Preference — prefer our own crates" rule (`ronin-issen/CLAUDE.md`)
requires using a SecurityRonin crate over a third-party one when an equivalent
exists, and preferring the *published registry* version over a path dependency.

## Decision

Depend on the published `winreg-core = "0.2"` from crates.io for all hive I/O
(`Cargo.toml` `[workspace.dependencies]`, with the comment "Generic REGF hive
parser — BAM lives in the SYSTEM hive, so the binary walks it with
winreg-core"). The binary uses `winreg_core::hive::Hive::from_path`,
`open_key`, `subkeys`, `values`, `raw_data`, and the `winreg_core::key::
filetime_to_datetime` helper to render timestamps (`forensic/src/bin/bam4n6.rs`).
No hand-rolled REGF reader and no third-party hive crate are introduced.

## Consequences

- BAM inherits `winreg-core`'s fuzzing, panic-free posture, and maintenance;
  bam-forensic adds no new REGF-parsing attack surface.
- A registry (not `path`) dependency keeps the repo decoupled from local checkout
  layout and matches what external consumers of `bam-forensic` resolve.
- `winreg-core`'s release cadence gates BAM: a REGF bug fix arrives via a version
  bump rather than a local edit.
- `filetime_to_datetime` for human-readable `--list` output is reused from
  `winreg-core`, so timestamp rendering is not re-implemented here.
