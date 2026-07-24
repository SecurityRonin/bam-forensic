# 2. bam-core is a hive-free decoder primitive; the CLI owns registry I/O

Date: 2026-07-24
Status: Accepted

## Context

A BAM record is a single registry value: the value **name** is an executable
path (`\Device\HarddiskVolumeN\Windows\…\app.exe`), and the value **data**'s
first 8 bytes are the last-execution `FILETIME`. Reading those values out of a
`SYSTEM` hive is a REGF-parsing job. The fleet's layer architecture makes PARSER
crates **medium-agnostic** — they "accept `Path` or `&[u8]` — never import
CONTAINER, FILESYSTEM, PAGING, OS STRUCTURE, or LOG FORMAT crates"
(`ronin-issen/CLAUDE.md`, dependency rules). If `bam-core` opened the hive
itself it would bind the decoder to one acquisition path (a hive file on disk)
and pull the whole REGF reader into every consumer.

## Decision

`bam-core` never touches the registry. `decode_entry(value_name: &str,
value_data: &[u8]) -> Option<BamEntry>` takes one already-extracted value's name
and raw bytes and returns the decoded record (`core/src/lib.rs`). It has an empty
`[dependencies]` table (`core/Cargo.toml`).

Hive I/O lives one layer up, in the `bam4n6` binary: it opens the hive with
`winreg_core::hive::Hive`, walks the `UserSettings` subkeys, reads each value's
name and `raw_data()`, and feeds them to `bam_core::decode_entry`
(`forensic/src/bin/bam4n6.rs`, `collect_records`). The `bam-forensic` library's
`audit` likewise operates on already-decoded `&[BamEntry]`, not on a hive.

## Consequences

- The decoder is reusable over any source of BAM values — a hive file, a bytes
  buffer carved from memory, or values pulled by another tool — with no image or
  registry dependency.
- The same decoder is fuzzed in isolation (`fuzz/fuzz_targets/fuzz_parse.rs`)
  without needing a hive fixture.
- The registry-format knowledge and its dependency (`winreg-core`) are confined
  to the binary (ADR 0003); `bam-core` stays a zero-dependency leaf.
- A caller wanting per-SID grouping must carry the SID alongside the entry (the
  CLI's `Record` struct does this) because a `BamEntry` deliberately holds only
  the path and timestamp, not the key it came from.
