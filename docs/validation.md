# Validation

`bam-forensic` is validated against a **real Windows 10 1709 `SYSTEM` hive**, cross-checked with an
independent oracle — **regipy**'s `system.bam` plugin (`BAMPlugin`) — and corroborated by
RegRipper's `bam.pl`.

## Tier-1 (real data + independent oracle)

| Hive | Keys walked | Records (regipy vs. bam-forensic) |
|---|---|---|
| Windows 10 1709 `SYSTEM` | `ControlSet001\…\bam\UserSettings\{SID}` + `bam\State\UserSettings\{SID}` | **55**, across 2 user SIDs — agree exactly |

regipy and `bam-forensic` agree on the record count (55) and on every decoded field. A sample the
Rust reader reproduces against the oracle:

| SID | Decoded path | Last-execution `FILETIME` |
|---|---|---|
| `S-1-5-90-0-1` | `\Device\HarddiskVolume2\Windows\System32\dwm.exe` | `132317609757318159` (2020-04-19T09:09:35.73Z) |

The end-to-end test (`forensic/tests/system_real.rs`) drives the real `bam4n6` binary over the hive
via `winreg-core` and reconciles its output against the regipy count; it is env-gated on
`BAM_TEST_SYSTEM_HIVE` and skips cleanly when the (non-committed) hive is absent. Provenance and how
to obtain the hive are in `core/tests/data/README.md`.

## Value layout

Under `…\bam[\State]\UserSettings\{SID}`, each value keys one executable:

- **Value name** — the program path, kept **verbatim** (usually an NT device path,
  `\Device\HarddiskVolumeN\…\foo.exe`; `bam-forensic` normalizes the device prefix for display and
  path heuristics, never mutating the recorded name).
- **Value data** — an **8-byte little-endian `FILETIME`** (last execution). Windows 10 writes 16
  trailing bytes of padding (a 24-byte value); `bam-core` reads the leading 8 bytes and ignores the
  rest. A value shorter than 8 bytes decodes to `None` (bounds-checked, never a panic).

Structure confirmed against RegRipper's `bam.pl` (`keydet89/RegRipper3.0`) and regipy's `system.bam`
plugin — both read the value name as the executable path and the first 8 bytes as the last-run
`FILETIME`, matching `bam-core`'s decode.
