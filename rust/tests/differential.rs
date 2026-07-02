// SPDX-License-Identifier: Apache-2.0
//! Property-based differential conformance harness on the FFI seam.
//!
//! The Rust transport does not parse wire lines for routing — Lean's
//! `seal_host_classify` (the SealV2-gated `Host.classifyLine`) is the single
//! routing authority. What Rust DOES parse with serde_json elsewhere
//! (config summary, approval records, evidence files) must never disagree
//! with Lean in a direction that could bypass mediation. This harness pins
//! two seams:
//!
//! 1. ROUTING AGREEMENT — for every input line (including every obfuscation
//!    disguise), mirror-routing the line in Rust (serde_json parse + method
//!    == "tools/call") must agree with Lean's classify on WHAT IS MEDIATED.
//!    Lean emits 0 (passthrough) or 1 (mediated act) — nothing else; where
//!    the SealV2 canonical gate is stricter than V1 routing, that shows up
//!    inside `step` as a deny, which is still mediation.
//!
//! 2. BLOCK-ON-ERROR — the routing functions the binary actually runs
//!    (`seal_host_rs::route`, no test-local mirror) are total and can only
//!    produce `Forward` from an exact parse of kernel output with an exact
//!    route literal. Every seam error, garbage value, or mutation lands in
//!    Block/Refuse/SeamFailure.

use seal_host_rs::lean::{LeanHost, SeamError};
use seal_host_rs::route::{route_of_classify, route_of_step_output, ClassifyRoute, Route};
use std::sync::OnceLock;

fn host() -> &'static LeanHost {
    static HOST: OnceLock<LeanHost> = OnceLock::new();
    HOST.get_or_init(LeanHost::new)
}

fn lean_classify(line: &str) -> u32 {
    host().classify(line).expect("classify seam healthy in tests")
}

/// The Rust wire-parser mirror of V1 routing: JSON object with
/// method == "tools/call" and params.name a string. This is the DELIBERATE
/// independent view the differential compares against Lean — it exists only
/// here, never in the binary.
fn rust_routes_as_tools_call(line: &str) -> bool {
    // ASCII-only trim, byte-faithful to Lean's `trimAscii` routing view.
    let trimmed = line.trim_matches(|c: char| c.is_ascii_whitespace());
    let Ok(v) = serde_json::from_str::<serde_json::Value>(trimmed) else {
        return false;
    };
    v.get("method").and_then(|m| m.as_str()) == Some("tools/call")
        && v.get("params").and_then(|p| p.get("name")).and_then(|n| n.as_str()).is_some()
}

// NOTE on failure style: libleanshared bundles its own LLVM libunwind and
// its `_Unwind_*` exports shadow libgcc at load, so a Rust `panic!` in any
// process linking Lean ABORTS instead of unwinding (fail-closed, but
// unshrinkable). Checks therefore return `Result` and property tests use
// `prop_assert!`; corpus tests panic once at the end with the full failure
// list.

/// Exact agreement: the V1 Rust wire view and the Lean canonical routing
/// view route identically. Holds on the curated corpus; see
/// `known_lean_stricter_cases` for the documented exceptions.
fn check_agreement(line: &str) -> Result<(), String> {
    let lean = lean_classify(line); // 0 passthrough, 1 mediated act
    let rust = rust_routes_as_tools_call(line);
    if lean > 1 {
        return Err(format!("classify outside 0/1 contract: {lean} for {line:?}"));
    }
    if (lean == 1) != rust {
        return Err(format!("ROUTING DISAGREEMENT (lean={lean}, rust={rust}): {line:?}"));
    }
    Ok(())
}

/// The load-bearing direction: a BYPASS is a line the Rust wire view reads
/// as a tools/call that Lean nevertheless passes through unmediated to the
/// child. Lean being STRICTER (mediating a line serde cannot even parse) is
/// fail-closed and allowed.
fn check_no_bypass(line: &str) -> Result<(), String> {
    let lean = lean_classify(line);
    let rust = rust_routes_as_tools_call(line);
    if lean > 1 {
        return Err(format!("classify outside 0/1 contract: {lean} for {line:?}"));
    }
    if rust && lean == 0 {
        return Err(format!("BYPASS: rust routes as tools/call, lean passes through: {line:?}"));
    }
    Ok(())
}

fn assert_all<'a>(lines: impl IntoIterator<Item = &'a str>, check: fn(&str) -> Result<(), String>) {
    let failures: Vec<String> =
        lines.into_iter().filter_map(|l| check(l).err()).collect();
    if !failures.is_empty() {
        panic!("{} failure(s):\n{}", failures.len(), failures.join("\n"));
    }
}

/// The obfuscation_probe.mjs disguise set (trailing newline/space/tab,
/// leading space, casing, CRLF, surrounding whitespace), applied to an
/// arbitrary fragment.
fn disguises(s: &str) -> Vec<String> {
    let mixed: String = s
        .chars()
        .enumerate()
        .map(|(i, c)| if i % 2 == 0 { c.to_ascii_uppercase() } else { c.to_ascii_lowercase() })
        .collect();
    vec![
        s.to_string(),
        format!("{s}\n"),
        format!("{s} "),
        format!(" {s}"),
        format!("{s}\t"),
        s.to_ascii_uppercase(),
        mixed,
        format!("{s}\r\n"),
        format!("  {s}  "),
    ]
}

fn tools_call_line(method: &str, name: &str, sql: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":{},"params":{{"name":{},"arguments":{{"sql":{}}}}}}}"#,
        serde_json::to_string(method).unwrap(),
        serde_json::to_string(name).unwrap(),
        serde_json::to_string(sql).unwrap(),
    )
}

#[test]
fn corpus_agreement() {
    let cases = [
        // canonical tools/call
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"db.execute","arguments":{"sql":"drop"}}}"#,
        // tools/call with escape — non-canonical but still mediated (1); Rust routes: agree
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
        // unicode + duplicate keys (Lean canonical gate blocks inside step; routing still agrees)
        r#"{"method":"tools/call","params":{"name":"x","arguments":{"a":1,"a":2}}}"#,
        r#"{"method":"tools/call","params":{"name":"héllo","arguments":{}}}"#,
        // duplicate METHOD keys — last-wins must agree between serde and Lean
        r#"{"method":"initialize","method":"tools/call","params":{"name":"x"}}"#,
        r#"{"method":"tools/call","method":"initialize","params":{"name":"x"}}"#,
        // leading/trailing whitespace
        "  {\"method\":\"tools/call\",\"params\":{\"name\":\"x\"}}  ",
        // \u-escaped method — decodes to tools/call in any correct JSON parser
        r#"{"method":"tools/call","params":{"name":"x"}}"#,
        // interior NUL via escape
        "{\"method\":\"tools/call\",\"params\":{\"name\":\"a\\u0000b\"}}",
        // UTF-8 BOM prefix: not ASCII whitespace, so strict parsers reject →
        // passthrough on both sides (see RUST_BRIDGE.md, A-strict-child)
        "\u{FEFF}{\"method\":\"tools/call\",\"params\":{\"name\":\"x\"}}",
        // number edge cases
        r#"{"method":"tools/call","params":{"name":"x","arguments":{"v":18446744073709551615}}}"#,
        r#"{"method":"tools/call","params":{"name":"x","arguments":{"v":-0.0}}}"#,
    ];
    assert_all(cases, check_agreement);
}

/// Documented representational differences where Lean is STRICTER than the
/// serde view — it mediates lines serde cannot parse at all. This is the
/// fail-closed direction (more mediation, never less); the differential pins
/// it so a silent flip to the bypass direction cannot pass.
#[test]
fn known_lean_stricter_cases() {
    // serde_json rejects numbers beyond f64 range (whole parse fails);
    // Lean's JsonNumber is arbitrary-precision and parses fine → mediated.
    let overflow =
        r#"{"method":"tools/call","params":{"name":"x","arguments":{"v":1e309}}}"#;
    let lean = lean_classify(overflow);
    let rust = rust_routes_as_tools_call(overflow);
    assert_eq!(lean, 1, "Lean must mediate the overflow-number call");
    assert!(!rust, "serde is expected to reject the overflow number");
    // And the load-bearing direction holds regardless.
    assert_all([overflow], check_no_bypass);
}

#[test]
fn corpus_agreement_obfuscation_disguises() {
    // Disguises applied to the WHOLE LINE: framing noise around a mediated
    // call must never flip it to passthrough on one side only.
    let base = tools_call_line("tools/call", "db.execute", "drop table x");
    let mut lines: Vec<String> = disguises(&base);
    // Disguises applied to the METHOD: only the exact "tools/call" bytes are
    // a tools/call; "TOOLS/CALL", "tools/call\n" etc. must be passthrough on
    // BOTH sides (never mediated on one and forwarded on the other).
    for m in disguises("tools/call") {
        lines.push(tools_call_line(&m, "db.execute", "drop table x"));
    }
    // Disguises applied to the TOOL NAME and to an ARGUMENT value: these stay
    // mediated (method is exact); agreement must hold on every variant.
    for n in disguises("db.execute") {
        lines.push(tools_call_line("tools/call", &n, "drop table x"));
    }
    for a in disguises("delete_all") {
        lines.push(tools_call_line("tools/call", "db.execute", &a));
    }
    // Raw control characters INSIDE a JSON string are invalid JSON — both
    // parsers must reject (passthrough), never one-sided.
    lines.push("{\"method\":\"tools\n/call\",\"params\":{\"name\":\"x\"}}".to_string());
    lines.push("{\"method\":\"tools/call\",\"params\":{\"name\":\"a\rb\"}}".to_string());
    assert_all(lines.iter().map(String::as_str), check_agreement);
}

#[test]
fn corpus_agreement_pathological_shapes() {
    // Deep nesting (well under parser recursion limits, far over anything
    // a sane client sends).
    let deep = format!(
        r#"{{"method":"tools/call","params":{{"name":"x","arguments":{{"v":{}{}}}}}}}"#,
        "[".repeat(100),
        "]".repeat(100)
    );
    // A large line (256 KiB of payload) — size must not change routing.
    let big = tools_call_line("tools/call", "db.execute", &"x".repeat(256 * 1024));
    let big_pass = tools_call_line("tools/list", "db.execute", &"x".repeat(256 * 1024));
    assert_all([deep.as_str(), big.as_str(), big_pass.as_str()], check_agreement);
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
            // arbitrary method AND name as full unicode strings, escaped
            (any::<String>(), any::<String>()).prop_map(|(m, n)| {
                format!(
                    r#"{{"method":{},"params":{{"name":{}}}}}"#,
                    serde_json::to_string(&m).unwrap(),
                    serde_json::to_string(&n).unwrap()
                )
            }),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]
        #[test]
        fn no_routing_bypass(line in json_ish()) {
            // Exact agreement everywhere the generators reach; the curated
            // known-stricter cases (number overflow) are not generatable
            // here (numbers come from finite f64 Display).
            let checked = check_agreement(&line);
            prop_assert!(checked.is_ok(), "{}", checked.unwrap_err());
        }
    }

    // ---- Block-on-error: the binary's own routing functions are total and
    // ---- fail closed. These are the SAME functions main.rs runs.

    fn seam_errors() -> impl Strategy<Value = SeamError> {
        prop_oneof![
            Just(SeamError::Panic),
            Just(SeamError::PoisonedLock),
            Just(SeamError::NotAString),
            Just(SeamError::InvalidUtf8),
        ]
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4000))]

        /// Forward is derivable ONLY from an exact parse with an exact route
        /// literal — arbitrary strings (mostly garbage, sometimes valid JSON)
        /// can never forward otherwise.
        #[test]
        fn step_output_never_forwards_garbage(s in any::<String>()) {
            if let Route::Forward { .. } = route_of_step_output(Ok(s.clone())) {
                let v: serde_json::Value = serde_json::from_str(&s)
                    .expect("Forward from unparseable output");
                let route = v["route"].as_str().expect("Forward without route string");
                prop_assert!(route == "forward" || route == "passthrough",
                    "Forward from route={route:?}");
            }
        }

        /// JSON-shaped outputs with an arbitrary route value: Forward iff the
        /// literal; block requires a response string; everything else is
        /// SeamFailure (which never forwards).
        #[test]
        fn step_output_route_literal_only(route in any::<String>(), resp in proptest::option::of(any::<String>())) {
            let mut obj = serde_json::json!({ "route": route });
            if let Some(r) = &resp {
                obj["response"] = serde_json::json!(r);
            }
            let out = route_of_step_output(Ok(obj.to_string()));
            match out {
                Route::Forward { .. } =>
                    prop_assert!(route == "forward" || route == "passthrough"),
                Route::Block { .. } =>
                    prop_assert!(route == "block" && resp.is_some()),
                Route::SeamFailure { .. } => {}
            }
        }

        /// Every seam error refuses; no error value routes.
        #[test]
        fn seam_error_never_forwards(e in seam_errors()) {
            let step_refused =
                matches!(route_of_step_output(Err(e.clone())), Route::SeamFailure { .. });
            prop_assert!(step_refused);
            let classify_refused =
                matches!(route_of_classify(Err(e)), ClassifyRoute::Refuse);
            prop_assert!(classify_refused);
        }

        /// Classify forwards on the literal 0 ONLY; mediates on the literal 1
        /// ONLY; every other value refuses.
        #[test]
        fn classify_literal_only(c in any::<u32>()) {
            let r = route_of_classify(Ok(c));
            match c {
                0 => prop_assert!(matches!(r, ClassifyRoute::Passthrough)),
                1 => prop_assert!(matches!(r, ClassifyRoute::Mediate)),
                _ => prop_assert!(matches!(r, ClassifyRoute::Refuse)),
            }
        }
    }

    // ---- A3 freshness: fail-closed under arbitrary clocks and records.

    use seal_host_rs::a3::A3Filter;
    use seal_host_rs::providers::ApprovalRecord;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(2000))]

        /// A replayed nonce never survives, whatever the clock does.
        #[test]
        fn replayed_nonce_never_survives(
            target in any::<u64>(),
            issued in any::<u64>(),
            now1 in any::<u64>(),
            now2 in any::<u64>(),
            nonce in "[a-f0-9]{8}",
        ) {
            let mut a3 = A3Filter::new(u64::MAX);
            let rec = || ApprovalRecord {
                target,
                issued_at: Some(issued),
                nonce: Some(nonce.clone()),
            };
            let (first, _) = a3.filter(vec![rec()], now1);
            let (second, _) = a3.filter(vec![rec()], now2);
            // However the freshness checks fall, the nonce is accepted at
            // most once across both polls.
            prop_assert!(first.len() + second.len() <= 1);
        }

        /// Expired and far-future records never survive; no clock value can
        /// panic the filter (saturating arithmetic).
        #[test]
        fn expired_and_future_never_survive(
            ttl in 0u64..10_000_000,
            issued in any::<u64>(),
            now in any::<u64>(),
        ) {
            let mut a3 = A3Filter::new(ttl);
            let (ok, _) = a3.filter(
                vec![ApprovalRecord { target: 1, issued_at: Some(issued), nonce: None }],
                now,
            );
            let expired = now.saturating_sub(issued) > ttl;
            let future = issued > now.saturating_add(5_000);
            if expired || future {
                prop_assert!(ok.is_empty());
            }
        }
    }
}
