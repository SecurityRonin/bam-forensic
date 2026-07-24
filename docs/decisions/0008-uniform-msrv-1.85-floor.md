# 8. Uniform 1.85 MSRV floor

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy (`CLAUDE.core.md`, "Rust MSRV & Toolchain Policy";
`CLAUDE.personal.md`) separates the pinned dev toolchain from the declared,
downstream-facing MSRV: apps declare MSRV = the pinned toolchain, while
**published libraries keep a low, CI-verified floor** (1.75/1.80). bam-forensic
is a mixed repo — `bam-core` and `bam-forensic` are published libraries, and
`bam-forensic` also ships the `bam4n6` binary. The dev toolchain is pinned to
`1.96.0` (`rust-toolchain.toml`). Both direct fleet dependencies declare a `1.75`
floor (`forensicnomicon` and `winreg-core`).

## Decision

Declare a single `rust-version = "1.85"` for the whole workspace via
`[workspace.package]` (`Cargo.toml`), inherited by both members. This is below
the `1.96.0` dev pin (so it is a real, CI-verifiable compatibility promise, not a
restatement of the toolchain) and above the `1.75` floor of the direct deps.

## Consequences

- The library crates promise `1.85`, not the fleet's low `1.75`/`1.80` library
  floor — a deliberate deviation that narrows the crates.io audience slightly
  versus a `forensicnomicon`-matching `1.75`.
- Because the pin (`1.96.0`) and the declared MSRV (`1.85`) differ, a CI MSRV job
  must build on `1.85` to keep the promise honest.
- **Rationale reconstructed from structure; original intent not recovered in
  available history.** The chosen `1.85` exceeds both direct dependencies'
  declared `1.75` floors, so it is most consistent with a transitive dependency
  (of `forensicnomicon 1.6.0` or `winreg-core 0.2.0`) requiring `1.85`; the
  10-commit git history carries no commit message stating the driver, and no
  authoritative source was confirmed in this pass. If the true floor is lower,
  the library crates could be lowered toward the fleet `1.75` standard and
  CI-verified.
