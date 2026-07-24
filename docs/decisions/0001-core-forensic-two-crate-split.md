# 1. Two-crate core/forensic workspace split

Date: 2026-07-24
Status: Accepted

## Context

bam-forensic reads one Windows artifact family — the Background/Desktop Activity
Moderator (BAM/DAM) last-execution record in the `SYSTEM` hive. The fleet's
crate-structure standard (`ronin-issen/CLAUDE.md`, "Crate-structure standard —
reader/analyzer split") mandates that a single-format repo be a **Pattern A**
workspace named `<x>-forensic` with exactly two members: a `<x>-core` reader and
a `<x>-forensic` analyzer. A monolithic crate would force a downstream Rust tool
that only wants to decode a BAM value to also compile the anomaly grader and the
`forensicnomicon::report` surface, and would couple the medium-agnostic decoder
to the CLI.

## Decision

Ship a Cargo workspace (`Cargo.toml` `members = ["core", "forensic"]`) with two
published crates:

- **`bam-core`** — the pure decoder. `decode_entry(value_name, value_data) ->
  Option<BamEntry>` and the `BamEntry` type; no findings, no registry I/O
  (`core/src/lib.rs`).
- **`bam-forensic`** — the analyzer. `audit(&[BamEntry]) -> Vec<BamAnomaly>`
  emitting graded `forensicnomicon` findings, plus the `bam4n6` binary
  (`forensic/src/lib.rs`, `forensic/src/bin/bam4n6.rs`).

The bare `bam` crate name is not contested by a popular third party, so the
import path stays `bam_core` (no `[lib] name` remap is used; `forensic/Cargo.toml`
imports `bam_core`). Shared package metadata (edition, rust-version, license,
authors, repository) is hoisted to `[workspace.package]`; `version` is *not*
hoisted so the two crates version independently.

## Consequences

- A downstream consumer links `bam-core` alone for decoding, or `bam-forensic`
  for graded analysis; the decoder carries no dependency on the report model.
- The two crates release independently via release-plz (`release-plz.toml`,
  `git_tag_name = "<crate>-vX.Y.Z"`), so a decoder-only bump does not force an
  analyzer release.
- The `bam4n6` CLI is bundled as a `bin` inside `bam-forensic` rather than a
  separate `-cli` crate, because the single-format repo has one front-end and the
  hive-walking glue is thin (ADR 0002).
