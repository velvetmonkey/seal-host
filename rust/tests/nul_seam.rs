// SPDX-License-Identifier: Apache-2.0
//! Executable check for the FFI seam's documented interior-NUL safety.

use seal_host_rs::lean::LeanHost;

#[test]
fn literal_interior_nul_crosses_the_full_inbound_seam() {
    // The literal 0x00 is byte 48, inside the key "arguments". Its prefix
    // stops mid-token and classifies as passthrough; only the full byte
    // sequence exposes the repeated "a" key to the raw-wire guard.
    let line =
        "{\"method\":\"tools/call\",\"params\":{\"name\":\"x\",\"arg\0uments\":{\"a\":1,\"a\":2}}}";

    let host = LeanHost::new();
    assert_eq!(line.as_bytes()[48], 0);
    assert_eq!(
        host.classify(&line[..48])
            .expect("classify seam should remain healthy"),
        0
    );
    assert_eq!(
        host.classify(line)
            .expect("classify seam should remain healthy"),
        2
    );
}
