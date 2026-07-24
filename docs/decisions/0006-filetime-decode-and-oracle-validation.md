# 6. FILETIME decode (first 8 LE bytes), structural metadata rejection, oracle validation

Date: 2026-07-24
Status: Accepted

## Context

A BAM value's data begins with the last-execution time and is followed by
padding; the per-SID `SequenceNumber` and `Version` values are 4-byte
`REG_DWORD` metadata, not execution records. The decoder must extract the
timestamp with the correct offset and endianness and must not mistake a metadata
value for a record. Deriving a binary layout from memory is how wrong offsets and
inverted byte order ship green (the fleet's Research-First / Doer-Checker
disciplines), so the layout and the result both need an independent oracle.

## Decision

Decode the last-execution time as the **little-endian `u64` of the first 8 bytes**
of the value data, treating any trailing bytes as padding
(`u64::from_le_bytes` over `value_data.get(..8)?` in `core/src/lib.rs`); expose
it as a raw `FILETIME` (`BamEntry.last_executed_filetime`, 100 ns ticks since
1601-01-01 UTC) and defer human rendering to `winreg-core`. Reject non-records
**structurally**: a value with fewer than 8 bytes returns `None`, which excludes
the 4-byte `SequenceNumber`/`Version` metadata by construction; the CLI
additionally skips those two names defensively (ADR 0007). The layout is
grounded in RegRipper's `bam.pl` and `regipy`'s `system.bam`, both of which read
the value name as the path and `Int64` the first 8 bytes as the `FILETIME`
(`core/src/lib.rs` module docs). Correctness is validated Tier-1 against a real
Windows 10 1709 `SYSTEM` hive (the `regipy` corpus), cross-checked against
`regipy`'s `BAMPlugin` as an independent oracle: same record count (55), same
SIDs (2), same last-execution instants (`docs/validation.md`, `README.md`,
`core/tests/data/README.md`).

## Consequences

- The decoder emits the full 100 ns `FILETIME` precision; consumers choose their
  own rendering (the CLI uses `winreg-core`'s converter).
- Metadata rejection is a property of the 8-byte minimum, not a hardcoded value
  list, so it holds for any future 4-byte metadata value.
- The independent oracle (not a self-authored fixture) is the trust anchor; the
  reconciliation is documented in `docs/validation.md`.
