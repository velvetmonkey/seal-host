// SPDX-License-Identifier: Apache-2.0
//! Property-based differential conformance harness on the FFI seam.
//!
//! The Rust transport does not parse wire lines for routing — Lean's
//! `seal_host_classify` (the SealV2-gated `Host.classifyLine`) is the single
//! routing authority. What Rust DOES parse with serde_json elsewhere
//! (config summary, approval records, evidence files) must never disagree
//! with Lean in a direction that could bypass mediation. This harness pins
//! the seam property:
//!
//!   For every input line, mirror-routing the line in Rust (serde_json
//!   parse + method == "tools/call") must never classify a line as
//!   NOT-tools/call when Lean classifies it as a mediated act, and never
//!   classify it as tools/call when Lean says passthrough. I.e. the Rust
//!   wire view and the Lean canonical view agree on WHAT IS MEDIATED;
//!   where Lean is stricter (canonical gate), Lean's judgment is `2`
//!   (block), which is also mediation — fail-closed, never bypass.

mod common {
    use std::ffi::c_void;
    use std::os::raw::{c_char, c_uint};
    use std::sync::Once;

    type LeanObj = *mut c_void;

    extern "C" {
        fn lean_initialize_runtime_module();
        fn lean_io_mark_end_initialization();
        fn seal_ffi_initialize(builtin: u8, world: LeanObj) -> LeanObj;
        fn seal_lean_mk_string(s: *const c_char, n: usize) -> LeanObj;
        fn seal_host_classify(line: LeanObj) -> c_uint;
    }

    static INIT: Once = Once::new();

    pub fn lean_classify(line: &str) -> u32 {
        INIT.call_once(|| unsafe {
            lean_initialize_runtime_module();
            let _ = seal_ffi_initialize(1, 1usize as LeanObj);
            lean_io_mark_end_initialization();
        });
        unsafe {
            let s = seal_lean_mk_string(line.as_ptr() as *const c_char, line.len());
            seal_host_classify(s)
        }
    }
}

/// The Rust wire-parser mirror of V1 routing: JSON object with
/// method == "tools/call" and params.name a string.
fn rust_routes_as_tools_call(line: &str) -> bool {
    // ASCII-only trim, byte-faithful to Lean's `trimAscii` routing view.
    let trimmed = line.trim_matches(|c: char| c.is_ascii_whitespace());
    let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return false;
    };
    v.get("method").and_then(|m| m.as_str()) == Some("tools/call")
        && v.get("params").and_then(|p| p.get("name")).and_then(|n| n.as_str()).is_some()
}

fn check_agreement(line: &str) {
    let lean = common::lean_classify(line); // 0 passthrough, 1 act, 2 block
    let rust = rust_routes_as_tools_call(line);
    if rust {
        // Rust sees a tools/call: Lean must mediate it (act or canonical
        // block) — Lean saying "passthrough" would be a bypass.
        assert_ne!(
            lean, 0,
            "BYPASS: Rust routes as tools/call but Lean passes through: {line:?}"
        );
    } else {
        // Rust does not see a tools/call: Lean must agree it is not a
        // mediated act. (Lean block of a non-tools/call cannot happen by
        // construction; assert anyway.)
        assert_eq!(
            lean, 0,
            "DISAGREEMENT: Lean mediates what Rust would not route: {line:?}"
        );
    }
}

#[test]
fn corpus_agreement() {
    let cases = [
        // canonical tools/call
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.execute","arguments":{"sql":"drop"}}}"#,
        // tools/call with escape — Lean blocks (2), Rust still routes: agree (mediated)
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.execute","arguments":{"sql":"a\tb"}}}"#,
        // not tools/call
        r#"{"jsonrpc":"2.0","id":1,"method":"initialize"}"#,
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/list"}"#,
        // malformed
        "not json at all",
        "",
        "{",
        r#"{"method":"tools/call"}"#, // no params.name -> neither routes
        r#"{"method":"tools/call","params":{"name":42}}"#, // name not a string
        // unicode + duplicate keys (Lean canonical gate blocks; Rust routes -> mediated, OK)
        r#"{"method":"tools/call","params":{"name":"x","arguments":{"a":1,"a":2}}}"#,
        r#"{"method":"tools/call","params":{"name":"héllo","arguments":{}}}"#,
        // leading/trailing whitespace
        "  {\"method\":\"tools/call\",\"params\":{\"name\":\"x\"}}  ",
    ];
    for line in cases {
        check_agreement(line);
    }
}

#[cfg(test)]
mod props {
    use super::*;
    use proptest::prelude::*;

    fn json_ish() -> impl Strategy<Value = String> {
        prop_oneof![
            // arbitrary printable noise
            "[ -~]{0,80}",
            // JSON-shaped with arbitrary method
            ("[a-z/]{1,12}", "[a-zA-Z0-9._-]{1,16}").prop_map(|(m, n)| {
                format!(r#"{{"jsonrpc":"2.0","id":1,"method":"{m}","params":{{"name":"{n}","arguments":{{}}}}}}"#)
            }),
            // tools/call with arbitrary argument string (may contain escapes)
            any::<String>().prop_map(|s| {
                format!(
                    r#"{{"method":"tools/call","params":{{"name":"t","arguments":{{"v":{}}}}}}}"#,
                    serde_json::to_string(&s).unwrap()
                )
            }),
            // tools/call with arbitrary number
            any::<f64>().prop_map(|x| {
                format!(r#"{{"method":"tools/call","params":{{"name":"t","arguments":{{"v":{x}}}}}}}"#)
            }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]
        #[test]
        fn no_routing_bypass(line in json_ish()) {
            check_agreement(&line);
        }
    }
}
