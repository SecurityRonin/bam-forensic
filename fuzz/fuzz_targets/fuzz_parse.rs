//! Fuzz target: feed arbitrary bytes as a BAM/DAM value to the decoder.
//! Invariant: `decode_entry` never panics — a too-short or malformed value yields `None`, and the
//! 8-byte FILETIME read is bounds-checked. The value name is fuzzed alongside the data (the first
//! byte splits the input into a name prefix and the value bytes).
#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Split the input so both the value name and the value bytes are exercised.
    let split = data
        .first()
        .map_or(0, |b| (*b as usize) % (data.len().max(1)));
    let name = String::from_utf8_lossy(&data[..split.min(data.len())]);
    let _ = bam_core::decode_entry(&name, data);
    // Also the trivial fixed-name path the docs describe.
    let _ = bam_core::decode_entry("x", data);
});
