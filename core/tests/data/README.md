# bam-core test data — provenance

The pure decoder (`bam_core::decode_entry`) is validated by **synthetic `(name, bytes)` unit
tests** (`core/src/tests.rs`) that reproduce the exact on-disk shape of a real BAM value — an
8-byte little-endian `FILETIME` followed by 16 padding bytes (a 24-byte value). The whole-hive
navigation is validated **Tier-1 against a real Windows 10 hive and an independent oracle**, below.

No hive is committed (SYSTEM hives are large); the integration test is env-gated and reads the
hive in place.

## Tier-1 real-data validation

| | |
|---|---|
| **Hive** | `SYSTEM_WIN_10_1709` — a Windows 10 build 1709 `SYSTEM` registry hive (14.8 MB decompressed, valid `regf`). Windows 10 1709 is the build that introduced BAM. |
| **Source** | `regipy` test corpus — <https://github.com/mkorman90/regipy> `regipy_tests/data/SYSTEM_WIN_10_1709.xz` (the same hive `regipy`'s own BAM validation case uses). |
| **`.xz` MD5** | `7fa6140253be17ece7c03fe16f87d02a` |
| **Oracle** | `regipy`'s `regipy.plugins.system.bam.BAMPlugin` — reads the value name as the executable path and `Int64ul`-decodes the first 8 bytes of the value data as the last-execution `FILETIME`, across both `Services\bam\UserSettings` and `Services\bam\State\UserSettings` under each control set. |

### Ground truth (regipy `BAMPlugin`) vs `bam4n6`

- **55 execution records** across 2 populated SIDs (`S-1-5-21-2595688666-2948619230-3055395256-1001`
  = 53, `S-1-5-90-0-1` = 2), all under `ControlSet001` (24 in `bam\UserSettings` + 31 in
  `bam\State\UserSettings`; `dam` and `ControlSet002` absent on this hive). The `SequenceNumber`
  and `Version` per-SID `REG_DWORD`s are metadata, not records — both the oracle and `bam4n6`
  exclude them.
- Sample row reproduced byte-for-byte: SID `S-1-5-90-0-1`,
  `\Device\HarddiskVolume2\Windows\System32\dwm.exe`, raw `FILETIME` `132317609757318159` →
  `2020-04-19T09:09:35.7318159Z` (`regipy` reports `2020-04-19T09:09:35.731816+00:00` — the same
  instant at microsecond precision).

`bam4n6` reproduces the oracle's count and rows exactly (`forensic/tests/system_real.rs`, gated on
`BAM_TEST_SYSTEM_HIVE`).

### Reproducing the hive locally

```console
$ curl -sL https://raw.githubusercontent.com/mkorman90/regipy/master/regipy_tests/data/SYSTEM_WIN_10_1709.xz \
    -o /tmp/bam-hive/SYSTEM_WIN_10_1709.xz
$ xz -dk /tmp/bam-hive/SYSTEM_WIN_10_1709.xz && mv /tmp/bam-hive/SYSTEM_WIN_10_1709 /tmp/bam-hive/SYSTEM
$ BAM_TEST_SYSTEM_HIVE=/tmp/bam-hive/SYSTEM cargo test -p bam-forensic --test system_real
```

The NIST CFReDS "Data Leakage" `SYSTEM` hive used by sibling crates is **Windows 7**, which
predates BAM (no `Services\bam` key), so it cannot serve as a BAM corpus.
