# 5. forbid(unsafe), panic-free by lint, fuzzed

Date: 2026-07-24
Status: Accepted

## Context

Every byte bam-forensic touches is attacker-controllable: a `SYSTEM` hive and the
BAM value data inside it. A crafted value (a truncated data blob, a lying length,
a malformed name) must never crash the tool or produce silently wrong output. The
fleet's "Paranoid Gatekeeper" standard and the global unsafe-exception law
(`ronin-issen/CLAUDE.md`; `CLAUDE.core.md`) require `unsafe_code = "forbid"` as
the default and goal, the panic-free lint recipe on untrusted-input parsers, and
a `cargo-fuzz` target per parsed structure. Unlike the mmap readers (ewf,
memory-forensic), bam-core needs no `unsafe` — it does no memory-mapping and
parses from `&[u8]` — so it can hold the strongest posture.

## Decision

Set `unsafe_code = "forbid"` at the workspace root (`Cargo.toml`
`[workspace.lints.rust]`), inherited by both crates and re-asserted with
`#![forbid(unsafe_code)]` at the top of `core/src/lib.rs`, `forensic/src/lib.rs`,
and `bam4n6.rs`. Deny `clippy::unwrap_used` and `expect_used` in production; tests
opt out via `clippy.toml` (`allow-unwrap-in-tests`). The 8-byte `FILETIME` read
is bounds-checked (`value_data.get(..8)?`), a too-short value returns `None`
(`core/src/lib.rs`), and `normalize_device_path` uses `get`/`find` so an
out-of-bounds or non-char-boundary slice cannot panic (`forensic/src/lib.rs`).
Two fuzz targets exercise the decode and audit pipelines
(`fuzz/fuzz_targets/fuzz_parse.rs`, `fuzz_forensic.rs`). The README carries the
`unsafe forbidden` badge accordingly.

## Consequences

- Malformed evidence degrades to `None`/an empty finding set, never a crash or a
  raw-pointer path.
- The crate qualifies for the genuine `unsafe forbidden` badge (not the
  `deny` + bounded-allow form the mmap crates must use).
- The static lints occasionally require more verbose bounds-checked code than a
  quick `unwrap`; this is accepted as the cost of the posture.
- Robustness is claimed as "panic-free by lint" (the static half) beside
  "input-fuzzed" (the measured half), per the fleet's robustness-wording rule —
  never a bare "panic-free" absolute.
