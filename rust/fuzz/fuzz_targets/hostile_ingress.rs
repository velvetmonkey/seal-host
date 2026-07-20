#![no_main]
// SPDX-License-Identifier: Apache-2.0

use libfuzzer_sys::fuzz_target;
use seal_host_rs::limits::{check_json_limits, read_bounded_frame};
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    let _ = check_json_limits(data);

    // Keep the fuzzer's own memory use bounded while exercising frame drains,
    // newline boundaries, and every possible hostile byte sequence.
    let mut reader = Cursor::new(data);
    let mut retained = Vec::new();
    while reader.position() < data.len() as u64 {
        let before = reader.position();
        let _ = read_bounded_frame(&mut reader, &mut retained, 4096);
        assert!(retained.len() <= 4096);
        assert!(reader.position() > before);
    }
});
