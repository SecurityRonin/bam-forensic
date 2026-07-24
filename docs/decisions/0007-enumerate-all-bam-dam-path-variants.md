# 7. Enumerate every BAM/DAM UserSettings variant across both control sets

Date: 2026-07-24
Status: Accepted

## Context

Where the per-SID records live has drifted across Windows builds and there are
two sibling services. Early Windows 10 1709 stored them under
`Services\bam\UserSettings\{SID}`; later builds moved them under
`Services\bam\State\UserSettings\{SID}`. The Desktop Activity Moderator (`dam`)
mirrors both layouts. A hive also carries more than one control set
(`ControlSet001`, `ControlSet002`). Reading only the modern `bam\State` path in a
single control set would silently miss records on older images or on the
non-current control set — a fail-loud-vs-degrade-to-empty hazard where missing
evidence is indistinguishable from a clean box.

## Decision

The CLI walks the full cross-product: `{ControlSet001, ControlSet002}` ×
`{bam\State\UserSettings, bam\UserSettings, dam\State\UserSettings,
dam\UserSettings}`, skipping any path that does not exist and decoding every
value under each `{SID}` subkey (`forensic/src/bin/bam4n6.rs`,
`USER_SETTINGS_PATHS` and `collect_records`). This mirrors what RegRipper's
`bam.pl` and `regipy`'s `system.bam` enumerate. Per-SID metadata values are
excluded by name (`METADATA_VALUE_NAMES = ["SequenceNumber", "Version"]`,
case-insensitive) as a defensive complement to the structural ≥ 8-byte rejection
in the decoder (ADR 0006).

## Consequences

- No records are missed on early-1709 hives, on the `dam` service, or on a
  non-current control set; coverage does not depend on which control set was
  active at acquisition.
- A missing path is a normal `continue`, not an error — legitimate because the
  bootstrap (opening the hive) already succeeded; a genuine hive-open failure
  still surfaces loudly and exits non-zero (`run`/`main`).
- Metadata is rejected two ways (by name here, by size in the decoder), so
  neither path alone can leak a `SequenceNumber`/`Version` as a fake executable.
