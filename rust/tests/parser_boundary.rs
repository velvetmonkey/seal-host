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

mod common;

use common::{as_arguments, as_method, as_name, as_params, boundary_corpus, in_value};
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

/// CATEGORY ADDED 2026-07-25: `wire-refused`.
///
/// This map was written when classify had two outcomes. The raw-wire guards
/// added on 2026-07-24 introduced a third, `refuse` (2), for lines whose bytes
/// are ambiguous about which request they are: duplicate object keys, duplicate
/// `method` keys, oversized integers, lone surrogates in keys.
///
/// Without a category for it, every such line fell through to
/// `classify-contract-violation`, which read as "the boundary drifted" when
/// what actually happened is that the boundary got STRICTER in a way this map
/// had no word for.
///
/// `wire-refused` is added rather than folding these into an existing bucket
/// because it is a materially different outcome: nothing is forwarded, and the
/// refusal happens BEFORE the parse, so no comparison against serde's view is
/// even meaningful. Collapsing it into `agree-unrouted` would hide the
/// distinction between "neither side routes this" and "we refused to look".
fn classify_obs(o: &Obs) -> &'static str {
    match (o.lean, o.routes, o.parts_ok, o.serde_parses) {
        (0, true, _, _) => "BYPASS",
        (0, false, _, _) => "agree-unrouted",
        (1, true, true, _) => "agree-routed",
        (1, true, false, _) => "reduced-scope-structural",
        (1, false, _, false) => "reduced-scope-unparseable",
        (1, false, _, true) => "lean-only-routed",
        (2, _, _, _) => "wire-refused",
        _ => "classify-contract-violation",
    }
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
            any::<f64>().prop_map(|x| if x.is_finite() {
                format!("{x:?}")
            } else {
                "0".into()
            }),
            // oversized integer literals (serde rejects > f64 range as a whole)
            (1usize..500).prop_map(|n| "9".repeat(n)),
            // decimal exponent literals, some out of f64 range
            (any::<i32>(), -400i32..400).prop_map(|(m, e)| format!("{m}e{e}")),
            // strings with arbitrary escapes incl. lone/paired surrogates
            (0u32..0x11000, 0u32..0x11000)
                .prop_map(|(a, b)| { format!(r#""\u{a:04x}\u{b:04x}""#) }),
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
        /// classify contract. Divergence is ALLOWED, but only into the named
        /// reduced-scope classes the map documents, plus `wire-refused`.
        ///
        /// `wire-refused` admitted 2026-07-25. It is the STRICTEST outcome:
        /// the raw-wire guards refuse the line before the parse and nothing is
        /// forwarded. Excluding it would fail this property on exactly the
        /// inputs the guards were added to stop, which is backwards.
        ///
        /// This allowlist is deliberately NOT "anything but BYPASS". `BYPASS`
        /// and `lean-only-routed` stay excluded, and so does
        /// `classify-contract-violation`, so a genuinely new outcome still
        /// fails here rather than being quietly absorbed.
        #[test]
        fn no_bypass_no_new_divergence(line in probe_line()) {
            let obs = observe(&line).map_err(TestCaseError::fail)?;
            let class = classify_obs(&obs);
            prop_assert!(
                class == "agree-routed"
                    || class == "agree-unrouted"
                    || class == "reduced-scope-unparseable"
                    || class == "reduced-scope-structural"
                    || class == "wire-refused",
                "unexpected boundary class {class} for {line:?} ({obs:?})"
            );
        }
    }
}
