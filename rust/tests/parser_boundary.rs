// SPDX-License-Identifier: Apache-2.0
//! Property-test of the serde/Lean parser boundary (RED corpus B2-a).
//!
//! Two parsers judge the same wire bytes: Lean's `Host.classifyLine` (the
//! routing authority) and serde_json (the receipt layer's descriptive view,
//! `decision_receipt::request_parts`). Where Lean mediates a line the serde
//! view cannot fully parse, the host takes the reduced-scope
//! `authorised-unparseable` path (raw line hash only, no structured fields).
//!
//! Until now exactly ONE parseability divergence was pinned, by example,
//! three times over (`1e309`: differential.rs:192, host_path.rs:734,
//! decision_receipt.rs golden vectors). This test maps the WHOLE boundary:
//! a deterministic corpus across the JSON grammar plus randomized probes,
//! each case classified into a named outcome. The map is exhaustive in both
//! directions — a NEW divergence fails the test, and a divergence that
//! silently VANISHES (e.g. serde gaining bigint support) also fails, because
//! the reduced-scope path's trigger set is a security-relevant surface (T1:
//! can an attacker elect the reduced-scope path at will?). This test does
//! not answer T1; it pins T1's evidence base.
//!
//! Outcome classes (see `classify_obs`):
//!   agree-routed              both parse; routed; structured receipt fields
//!   agree-unrouted            neither side routes (incl. both-reject)
//!   reduced-scope-unparseable Lean mediates; serde cannot parse the line
//!   reduced-scope-structural  both parse+route; request_parts refuses the
//!                             shape (argument-less / non-object arguments)
//!   lean-only-routed          Lean mediates a line serde parses as
//!                             NOT-a-tools/call — would be a NEW divergence
//!   BYPASS                    serde routes, Lean passes through — the fatal
//!                             direction; never allowlisted
//!
//! Failure style: Lean-linked binaries abort instead of unwinding (see
//! differential.rs NOTE), so checks return Result / use prop_assert!, and
//! corpus tests panic once at the end with the full failure list.

use seal_host_rs::decision_receipt::request_parts;
use seal_host_rs::lean::LeanHost;
use std::sync::OnceLock;

fn host() -> &'static LeanHost {
    static HOST: OnceLock<LeanHost> = OnceLock::new();
    HOST.get_or_init(LeanHost::new)
}

/// One observation of the boundary: what each parser sees in one line.
#[derive(Debug, PartialEq)]
struct Obs {
    lean: u32,          // 0 passthrough, 1 mediated (routing authority)
    serde_parses: bool, // serde_json::from_str::<Value> succeeds on trim
    routes: bool,       // serde view routes as tools/call (differential.rs mirror)
    parts_ok: bool,     // decision_receipt::request_parts succeeds (product fn)
}

fn observe(line: &str) -> Result<Obs, String> {
    let lean = host()
        .classify(line)
        .map_err(|e| format!("classify seam error on {line:?}: {e:?}"))?;
    let trimmed = line.trim_matches(|c: char| c.is_ascii_whitespace());
    let parsed = serde_json::from_str::<serde_json::Value>(trimmed).ok();
    let routes = parsed
        .as_ref()
        .map(|v| {
            v.get("method").and_then(|m| m.as_str()) == Some("tools/call")
                && v.get("params")
                    .and_then(|p| p.get("name"))
                    .and_then(|n| n.as_str())
                    .is_some()
        })
        .unwrap_or(false);
    Ok(Obs {
        lean,
        serde_parses: parsed.is_some(),
        routes,
        parts_ok: request_parts(line).is_ok(),
    })
}

fn classify_obs(o: &Obs) -> &'static str {
    match (o.lean, o.routes, o.parts_ok, o.serde_parses) {
        (0, true, _, _) => "BYPASS",
        (0, false, _, _) => "agree-unrouted",
        (1, true, true, _) => "agree-routed",
        (1, true, false, _) => "reduced-scope-structural",
        (1, false, _, false) => "reduced-scope-unparseable",
        (1, false, _, true) => "lean-only-routed",
        _ => "classify-contract-violation",
    }
}

// ---- line builders --------------------------------------------------------

/// Full valid envelope with a raw fragment in argument-VALUE position.
fn in_value(frag: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"t","arguments":{{"v":{frag}}}}}}}"#
    )
}

/// Raw fragment as the whole `arguments` value.
fn as_arguments(frag: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"t","arguments":{frag}}}}}"#
    )
}

/// Raw fragment as the whole `params` value.
fn as_params(frag: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{frag}}}"#)
}

/// Raw fragment in the `params.name` position (arguments present, object).
fn as_name(frag: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":{frag},"arguments":{{}}}}}}"#
    )
}

/// Raw fragment in the `method` position (well-formed params).
fn as_method(frag: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":1,"method":{frag},"params":{{"name":"t","arguments":{{}}}}}}"#)
}

/// Arrays nested `depth` deep in argument-value position. The envelope adds
/// 4 object levels around them (serde's default recursion limit is 128 on
/// the TOTAL depth).
fn nested(depth: usize) -> String {
    in_value(&format!("{}0{}", "[".repeat(depth), "]".repeat(depth)))
}

// ---- the deterministic boundary corpus -------------------------------------

struct Case {
    name: &'static str,
    line: String,
    expect: &'static str,
}

fn case(name: &'static str, line: String, expect: &'static str) -> Case {
    Case { name, line, expect }
}

/// The map. `expect` is the PINNED outcome per case; any drift in either
/// direction fails `parser_boundary_map`.
fn boundary_corpus() -> Vec<Case> {
    const AR: &str = "agree-routed";
    const AU: &str = "agree-unrouted";
    const RSU: &str = "reduced-scope-unparseable";
    const RSS: &str = "reduced-scope-structural";
    vec![
        // -- numeric limits in value position
        case("num-overflow-1e309", in_value("1e309"), RSU),
        case("num-overflow-neg-1e309", in_value("-1e309"), RSU),
        case("num-overflow-1e999999", in_value("1e999999"), RSU),
                case("num-overflow-int-400-digits", in_value(&"9".repeat(400)), RSU),
        case("num-u64-max", in_value("18446744073709551615"), AR),
        case("num-2pow64", in_value("18446744073709551616"), AR),
        case("num-neg-zero", in_value("-0"), AR),
        case("num-neg-zero-float", in_value("-0.0"), AR),
        case("num-subnormal-1e-309", in_value("1e-309"), AR),
        case("num-underflow-1e-999999", in_value("1e-999999"), AR),
        case("num-exp-forms", in_value("1E+02"), AR),
        // -- malformed numerics (invalid JSON): both sides should reject
        case("num-leading-zero", in_value("0123"), AU),
        case("num-bare-dot", in_value(".5"), AU),
        case("num-trailing-dot", in_value("5."), AU),
        case("num-bare-exp", in_value("1e"), AU),
        case("num-plus-prefix", in_value("+1"), AU),
        case("num-hex", in_value("0x10"), AU),
        case("num-nan", in_value("NaN"), AU),
        case("num-infinity", in_value("Infinity"), AU),
        // -- overflow OUTSIDE the mediated shape: divergence must not create routing
        case("num-overflow-in-name", as_name("1e309"), AU),
        case(
            "num-overflow-in-initialize",
            r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"v":1e309}}"#.to_string(),
            AU,
        ),
        case("num-overflow-as-method", as_method("1e309"), AU),
        // -- strings: escapes, surrogates, NUL, size
        case(
            "str-escaped-nul",
            in_value(r#""a\u0000b""#),
            AR,
        ),
                case("str-lone-high-surrogate", in_value(r#""\ud800""#), RSU),
                case("str-lone-low-surrogate", in_value(r#""\udc00""#), RSU),
        case("str-surrogate-pair", in_value(r#""\ud83d\ude00""#), AR),
                case("str-reversed-surrogates", in_value(r#""\udc00\ud800""#), RSU),
                case("str-lone-surrogate-in-key", in_value(r#"{"\ud800":1}"#), RSU),
        case("str-raw-nul", in_value("\"a\u{0}b\""), AU),
        case("str-raw-ctrl-0x01", in_value("\"a\u{1}b\""), AU),
        case("str-long-64k", in_value(&format!("\"{}\"", "x".repeat(65536))), AR),
        case(
            "key-long-64k",
            in_value(&format!("{{\"{}\":1}}", "k".repeat(65536))),
            AR,
        ),
        // -- escaped method: t decodes to 't' in any conforming parser.
        //    If either side routes on raw bytes instead of decoded strings,
        //    this case moves class and the map catches it.
        case("method-u-escaped", as_method(r#""\u0074ools/call""#), AR),
        case("name-u-escaped", as_name(r#""\u0074""#), AR),
        // -- structure: duplicates, nesting, framing
        case("dup-keys-arguments", in_value(r#"{"a":1,"a":2}"#), AR),
        case(
            "dup-method-last-tools-call",
            r#"{"method":"initialize","method":"tools/call","params":{"name":"t","arguments":{}}}"#
                .to_string(),
            AR,
        ),
        case(
            "dup-method-last-initialize",
            r#"{"method":"tools/call","method":"initialize","params":{"name":"t","arguments":{}}}"#
                .to_string(),
            AU,
        ),
        case("nesting-100", nested(100), AR),
        case("nesting-123", nested(123), AR),
        case("nesting-124", nested(124), AR),
        case("nesting-125", nested(125), RSU), // total 128, first serde-reject
        case("nesting-200", nested(200), RSU),
        case("nesting-300", nested(300), RSU),
        case("bom-prefix", format!("\u{FEFF}{}", in_value("1")), AU),
        case("trailing-garbage", format!("{} x", in_value("1")), AU),
        case("two-docs-one-line", format!("{}{}", in_value("1"), "{}"), AU),
        case("leading-ws", format!("   {}", in_value("1")), AR),
        // -- the reduced-scope STRUCTURAL family (both parse; request_parts refuses)
        case(
            "argument-less-call",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"t"}}"#.to_string(),
            RSS,
        ),
        case("arguments-array", as_arguments("[1,2]"), RSS),
        case("arguments-string", as_arguments("\"drop\""), RSS),
        case("arguments-number", as_arguments("1"), RSS),
        case("arguments-null", as_arguments("null"), RSS),
        case("arguments-bool", as_arguments("true"), RSS),
        // -- shapes that route on NEITHER side
        case("name-number", as_name("42"), AU),
        case("name-null", as_name("null"), AU),
        case("params-string", as_params("\"x\""), AU),
        case("params-array", as_params("[]"), AU),
        case(
            "params-missing",
            r#"{"jsonrpc":"2.0","id":1,"method":"tools/call"}"#.to_string(),
            AU,
        ),
        // -- sanity anchors
        case("canonical-call", in_value("1"), AR),
        case("empty-line", String::new(), AU),
        case("not-json", "not json at all".to_string(), AU),
    ]
}

#[test]
fn parser_boundary_map() {
    let mut failures: Vec<String> = Vec::new();
    for c in boundary_corpus() {
        match observe(&c.line) {
            Err(e) => failures.push(format!("[{}] OBSERVE ERROR: {e}", c.name)),
            Ok(obs) => {
                let got = classify_obs(&obs);
                if got != c.expect {
                    failures.push(format!(
                        "[{}] expected {}, got {} ({obs:?})",
                        c.name, c.expect, got
                    ));
                }
            }
        }
    }
    if !failures.is_empty() {
        panic!(
            "parser boundary drifted — {} case(s):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

#[cfg(test)]
mod props {
    use super::*;
    use proptest::prelude::*;

    /// Adversarial JSON fragments spanning the grammar categories the
    /// deterministic map probes — but with randomized parameters, so the
    /// property reaches shapes the fixed table does not enumerate.
    fn fragment() -> impl Strategy<Value = String> {
        prop_oneof![
            // arbitrary finite/edge floats rendered as JSON
            any::<f64>().prop_map(|x| if x.is_finite() { format!("{x:?}") } else { "0".into() }),
            // oversized integer literals (serde rejects > f64 range as a whole)
            (1usize..500).prop_map(|n| "9".repeat(n)),
            // decimal exponent literals, some out of f64 range
            (any::<i32>(), -400i32..400).prop_map(|(m, e)| format!("{m}e{e}")),
            // strings with arbitrary escapes incl. lone/paired surrogates
            (0u32..0x11000, 0u32..0x11000).prop_map(|(a, b)| {
                format!(r#""\u{a:04x}\u{b:04x}""#)
            }),
            // arbitrary unicode string values (serde escapes them safely)
            any::<String>().prop_map(|s| serde_json::to_string(&s).unwrap()),
            // arrays nested to a randomized depth straddling serde's limit 128
            (100usize..140).prop_map(|d| format!("{}0{}", "[".repeat(d), "]".repeat(d))),
            // literal keywords and near-keywords
            prop_oneof![
                Just("null".to_string()),
                Just("true".to_string()),
                Just("NaN".to_string()),
                Just("Infinity".to_string()),
                Just("undefined".to_string()),
            ],
        ]
    }

    /// A line built from a fragment placed in one of several positions in the
    /// tools/call envelope (or as raw noise).
    fn probe_line() -> impl Strategy<Value = String> {
        (0usize..6, fragment()).prop_map(|(slot, frag)| match slot {
            0 => in_value(&frag),
            1 => as_arguments(&frag),
            2 => as_params(&frag),
            3 => as_name(&frag),
            4 => as_method(&frag),
            _ => frag, // bare fragment as the whole line
        })
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(4000))]

        /// The load-bearing invariant over the WHOLE generated grammar: no
        /// input may land in the fatal `BYPASS` class (serde routes it as a
        /// tools/call that Lean passes through unmediated) nor in
        /// `lean-only-routed` (Lean mediates a line serde parses as a
        /// different method — an as-yet-unseen divergence) nor violate the
        /// classify 0/1 contract. Divergence is ALLOWED, but only into the two
        /// named reduced-scope classes the map already documents.
        #[test]
        fn no_bypass_no_new_divergence(line in probe_line()) {
            let obs = observe(&line).map_err(|e| TestCaseError::fail(e))?;
            let class = classify_obs(&obs);
            prop_assert!(
                class == "agree-routed"
                    || class == "agree-unrouted"
                    || class == "reduced-scope-unparseable"
                    || class == "reduced-scope-structural",
                "unexpected boundary class {class} for {line:?} ({obs:?})"
            );
        }
    }
}
