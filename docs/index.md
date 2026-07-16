# bam-forensic

Read a Windows **`SYSTEM`** hive — the **Background/Desktop Activity Moderator** (BAM/DAM) record
of *when each program last ran, per user* — on any OS.

BAM (a Windows service since Windows 10 1709) records, under
`ControlSet001\Services\bam\State\UserSettings\{SID}\` (older builds:
`bam\UserSettings\{SID}`), one value per executable: the **value name is the program path**, and the
**value data is an 8-byte little-endian `FILETIME`** of its last execution.

`bam-core` is the pure decoder (`decode_entry(value_name, value_data) -> Option<BamEntry>`);
`bam-forensic` walks the hive's control set and per-user `UserSettings`, adds graded findings
(system-binary masquerade, staging-directory execution), and ships the **`bam4n6`** CLI.

```console
$ cargo install bam-forensic
$ bam4n6 /path/to/SYSTEM
```

See the [project README](https://github.com/SecurityRonin/bam-forensic) for full usage and the
findings table, and [Validation](validation.md) for how correctness is established.
