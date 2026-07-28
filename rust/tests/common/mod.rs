// SPDX-License-Identifier: Apache-2.0
//! Shared wire-line builders + the deterministic parser-boundary corpus.
//!
//! Single source for the adversarial line shapes two harnesses exercise:
//! `parser_boundary.rs` (the serde/Lean parser-boundary map, where each case
//! carries a PINNED outcome class) and `three_way.rs` (the three-lane
//! native/wasm/model differential, which reuses the same lines as step
//! inputs). Moving a case here changes both harnesses — that is the point.
//!
//! Each integration-test crate compiles this module independently and uses a
//! subset of it, hence the `dead_code` allowance.

#![allow(dead_code)]

// ---- line builders ----------------------------------------------------------

/// Full valid envelope with a raw fragment in argument-VALUE position.
pub fn in_value(frag: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"t","arguments":{{"v":{frag}}}}}}}"#
    )
}

/// Raw fragment as the whole `arguments` value.
pub fn as_arguments(frag: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"t","arguments":{frag}}}}}"#
    )
}

/// Raw fragment as the whole `params` value.
pub fn as_params(frag: &str) -> String {
    format!(r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{frag}}}"#)
}

/// Raw fragment in the `params.name` position (arguments present, object).
pub fn as_name(frag: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":{frag},"arguments":{{}}}}}}"#
    )
}

/// Raw fragment in the `method` position (well-formed params).
pub fn as_method(frag: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":{frag},"params":{{"name":"t","arguments":{{}}}}}}"#
    )
}

/// Arrays nested `depth` deep in argument-value position. The envelope adds
/// 4 object levels around them (serde's default recursion limit is 128 on
/// the TOTAL depth).
pub fn nested(depth: usize) -> String {
    in_value(&format!("{}0{}", "[".repeat(depth), "]".repeat(depth)))
}

// ---- the deterministic boundary corpus ---------------------------------------

pub struct BoundaryCase {
    pub name: &'static str,
    pub line: String,
    pub expect: &'static str,
}

fn case(name: &'static str, line: String, expect: &'static str) -> BoundaryCase {
    BoundaryCase { name, line, expect }
}

/// The parser-boundary map. `expect` is the PINNED outcome per case (classes
/// documented in `parser_boundary.rs`); any drift in either direction fails
/// `parser_boundary_map`. `three_way.rs` reuses the `line`s as step inputs.
pub fn boundary_corpus() -> Vec<BoundaryCase> {
    const AR: &str = "agree-routed";
    const AU: &str = "agree-unrouted";
    const RSU: &str = "reduced-scope-unparseable";
    const RSS: &str = "reduced-scope-structural";
    // Added 2026-07-25. The raw-wire guards refuse these BEFORE the parse, so
    // there is no serde view to compare against and nothing is forwarded. Not
    // folded into AU: "neither side routes this" and "we refused to look" are
    // different facts, and collapsing them would hide the guard entirely.
    const WR: &str = "wire-refused";
    vec![
        // -- numeric limits in value position
        case("num-overflow-1e309", in_value("1e309"), RSU),
        case("num-overflow-neg-1e309", in_value("-1e309"), RSU),
        case("num-overflow-1e999999", in_value("1e999999"), RSU),
        case(
            "num-overflow-int-400-digits",
            in_value(&"9".repeat(400)),
            WR,
        ),
        case("num-u64-max", in_value("18446744073709551615"), WR),
        case("num-2pow64", in_value("18446744073709551616"), WR),
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
        case("str-escaped-nul", in_value(r#""a\u0000b""#), AR),
        case("str-lone-high-surrogate", in_value(r#""\ud800""#), RSU),
        case("str-lone-low-surrogate", in_value(r#""\udc00""#), RSU),
        case("str-surrogate-pair", in_value(r#""\ud83d\ude00""#), AR),
        case(
            "str-reversed-surrogates",
            in_value(r#""\udc00\ud800""#),
            RSU,
        ),
        case("str-lone-surrogate-in-key", in_value(r#"{"\ud800":1}"#), WR),
        case("str-raw-nul", in_value("\"a\u{0}b\""), AU),
        case("str-raw-ctrl-0x01", in_value("\"a\u{1}b\""), AU),
        case(
            "str-long-64k",
            in_value(&format!("\"{}\"", "x".repeat(65536))),
            AR,
        ),
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
        case("dup-keys-arguments", in_value(r#"{"a":1,"a":2}"#), WR),
        case(
            "dup-method-last-tools-call",
            r#"{"method":"initialize","method":"tools/call","params":{"name":"t","arguments":{}}}"#
                .to_string(),
            WR,
        ),
        case(
            "dup-method-last-initialize",
            r#"{"method":"tools/call","method":"initialize","params":{"name":"t","arguments":{}}}"#
                .to_string(),
            WR,
        ),
        case("nesting-100", nested(100), AR),
        case("nesting-123", nested(123), AR),
        case("nesting-124", nested(124), AR),
        case("nesting-125", nested(125), RSU), // total 128, first serde-reject
        case("nesting-200", nested(200), RSU),
        case("nesting-300", nested(300), RSU),
        case("bom-prefix", format!("\u{FEFF}{}", in_value("1")), AU),
        case("trailing-garbage", format!("{} x", in_value("1")), AU),
        case(
            "two-docs-one-line",
            format!("{}{}", in_value("1"), "{}"),
            AU,
        ),
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
