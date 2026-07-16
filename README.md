# bam-forensic

[![CI](https://github.com/SecurityRonin/bam-forensic/actions/workflows/ci.yml/badge.svg)](https://github.com/SecurityRonin/bam-forensic/actions)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Sponsor](https://img.shields.io/badge/sponsor-h4x0r-ea4aaa?logo=github-sponsors)](https://github.com/sponsors/h4x0r)

**Prove *when* a program last ran on a Windows box — per user — straight from the `SYSTEM` hive, on any OS.** A panic-free-by-construction reader for the Background/Desktop Activity Moderator (BAM/DAM) last-execution record, plus an analyzer that flags masquerading and staging-directory execution.

## Run it

```console
$ cargo install bam-forensic          # installs the bam4n6 binary
$ bam4n6 /path/to/SYSTEM
BAM/DAM: 55 execution records across 2 user SID(s)
Findings (1):
  [MEDIUM] BAM-SUSPICIOUS-PATH  \Device\HarddiskVolume2\Users\tony\AppData\Local\Temp\…\dotnet-runtime-3.0.0-preview4-win-x64.exe
    dotnet-runtime-…-win-x64.exe last executed from …\Temp\…, a directory commonly used to stage malware — consistent with suspicious execution.
```

`--list` dumps every record grouped by SID, with each executable's last-execution time:

```console
$ bam4n6 --list /path/to/SYSTEM
SID S-1-5-90-0-1 (2 records):
  2020-04-19T09:09:35.7318159Z  \Device\HarddiskVolume2\Windows\System32\dwm.exe
  …
```

## What it decodes

BAM/DAM (`SYSTEM\ControlSet00N\Services\bam` and `…\dam`, Windows 10 1709+) records the **last time each executable ran**, keyed per user `SID`:

- Under `bam\State\UserSettings\{SID}` (and the early-1709 `bam\UserSettings\{SID}` variant), each value **name** is an executable path in the kernel device form `\Device\HarddiskVolumeN\Windows\…\app.exe` (Store/AppX apps appear as their package-family name), and the value **data**'s first 8 bytes are the last-execution `FILETIME` (little-endian). `bam4n6` walks every path variant across `ControlSet001`/`002`, so no records are missed.
- The per-SID `SequenceNumber` and `Version` `REG_DWORD`s are metadata, not records, and are excluded.

> **BAM is direct execution evidence with a timestamp** — unlike Amcache/ShimCache *presence*. Findings are observations ("consistent with …"), never verdicts.

## Layers

- **`bam-core`** — `decode_entry(value_name, value_data) -> Option<BamEntry>`. A pure decoder with no hive I/O: value name → path, first 8 bytes → last-execution `FILETIME`. `#![forbid(unsafe_code)]`, panic-free by lint.
- **`bam-forensic`** — `audit(&[BamEntry]) -> Vec<BamAnomaly>` (graded `forensicnomicon` findings; device-path-aware) and the `bam4n6` CLI, which does the `winreg-core` hive walking.

## Validation

Tier-1 against a **real Windows 10 1709 `SYSTEM` hive** (the `regipy` test corpus), cross-checked against **`regipy`'s `BAMPlugin`** as an independent oracle:

| | regipy `BAMPlugin` | `bam4n6` |
|---|---|---|
| Execution records | 55 | 55 |
| Populated SIDs | 2 | 2 |
| `dwm.exe` (SID `S-1-5-90-0-1`) | `2020-04-19T09:09:35.731816Z` | `2020-04-19T09:09:35.7318159Z` |

Same count, same rows, same last-execution instant (`bam4n6` shows full 100 ns `FILETIME` precision). Structure confirmed against RegRipper's `bam.pl` (`keydet89/RegRipper3.0`) and `regipy`'s `system.bam`. See `core/tests/data/README.md`.

## Findings

| Code | Severity | MITRE | Fires when |
|---|---|---|---|
| `BAM-SYSTEM-BINARY-RELOCATED` | High | T1036.005 | A Windows system-binary name that last ran from a non-`System32` path (masquerading). |
| `BAM-SUSPICIOUS-PATH` | Medium | T1204 | An executable that last ran from a common staging directory (Temp, Downloads, `$Recycle.Bin`, …). |

---

[Privacy Policy](https://securityronin.github.io/bam-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/bam-forensic/terms/) · © 2026 Security Ronin Ltd
