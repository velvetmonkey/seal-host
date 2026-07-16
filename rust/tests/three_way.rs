// SPDX-License-Identifier: Apache-2.0
//! THREE-WAY property differential: native `libsealffi.so` ≡ pinned
//! `seal.wasm` ≡ interpreted Lean model, on generated + adversarial corpora.
//!
//! Lane C in the assurance ledger is the TRUSTED-COMPILE gap: the theorems
//! bind the Lean MODEL; the shipped artifacts are that model compiled twice
//! (Lean → C → native `.so`; Lean → C → emscripten wasm). No proof discharges
//! "the compile is faithful for all inputs" — that is verified-compiler
//! territory. This harness is the strongest evidence money can buy short of
//! that proof: for every generated step input, all three lanes must agree
//! BYTE-FOR-BYTE on the security-relevant output (route, block response with
//! its deny target, audit certificate), and the SHA-256 audit chain heads
//! must agree per session segment.
//!
//! HONESTY: this is differential EVIDENCE over the cases tried — "no known
//! divergence under N cases, re-checked every CI run" — never a universal
//! binary≡model proof. The banner prints the artifact identities, the seed
//! and the per-family case counts so the claim is exactly reproducible. A
//! divergence found here is a REAL BUG in a trusted compile or in the seam;
//! report it, never paper over it.
//!
//! Lanes:
//!   native — in-process `LeanHost::init/step` against the freshly built
//!            `.lake/build/lib/libsealffi.so` this test binary links;
//!   wasm   — `scripts/three_way_wasm_lane.mjs` driving the PINNED artifact
//!            `wasm-spike/verified/seal.wasm` (sha256 checked against
//!            `PINNED_WASM_SHA256` below; never rebuilt here);
//!   model  — `scripts/three_way_model_lane.lean` running the REAL
//!            `Ffi.modelStep` in the Lean interpreter under `lake env lean`.
//!
//! Corpus protocol (shared by all three lanes): one compact-JSON step input
//! per line; the literal control line `#REINIT` starts a FRESH session every
//! `SEGMENT` cases (steps are stateful — order matters and is identical in
//! all lanes) and emits no output. Failure reproduction is therefore bounded
//! to one segment; the corpus and all outputs are persisted on failure.
//!
//! Init coverage: the model lane cannot execute the Ed25519 config-signature
//! extern (interpreter), so three-way agreement covers post-init step
//! behavior; init agreement (accept + byte-equal summary, and tamper ⇒
//! reject) is asserted native≡wasm two-way in `init_agreement_two_way`.
//! There is no classify export in the wasm build, so classify agreement is
//! covered (a) by the step surface itself (`route == "passthrough"` iff
//! `classifyLine` passes the line through — same function, Ffi.lean) and
//! (b) by the per-case native invariant `classify == 0 ⇔ route ==
//! "passthrough"` asserted inside the native runner.
//!
//! Volume knobs (case counts are the FUZZ counts; the curated families are
//! always included on top):
//!   SEAL_THREE_WAY_CASES       fuzz cases for `three_way_agreement`
//!                              (default 256 — local smoke; CI sets more)
//!   SEAL_THREE_WAY_SOAK_CASES  fuzz cases for the #[ignore] soak
//!                              (default 100_000)
//!   SEAL_THREE_WAY_SEED        u64 generator seed (default fixed; printed)
//!   SEAL_SKIP_THREE_WAY=1      loud skip (missing lanes otherwise FAIL)
//!
//! Soak:  cargo test --test three_way -- --ignored --nocapture
//!
//! Failure style: Lean-linked binaries abort instead of unwinding (see
//! differential.rs NOTE), so checks collect failures and panic ONCE at the
//! end, after persisting the repro artifacts.

mod common;

use common::{as_arguments, as_method, as_name, as_params, boundary_corpus, in_value, nested};
use seal_host_rs::lean::LeanHost;
use seal_host_rs::route::{route_of_step_output, Route};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// Pinned wasm artifact under test. Authority: wasm-spike/verified/PROVENANCE.txt
/// (rebuilt for the pathological-number fail-closed fix from mcp-seal-dev
/// 6bbadbc7, Lean v4.28.0, emscripten 6.0.0). This harness NEVER rebuilds the
/// wasm; a hash mismatch is a preflight failure.
const PINNED_WASM_SHA256: &str = "ff1bfd68d7be51b6a395f94dfc46b2fb27ed11dc5833af6a84675f42f9730546";

const DEFAULT_SEED: u64 = 0x5EA1_C0DE_2026_0716;
/// Fresh session every SEGMENT cases — bounds failure repro to one segment.
const SEGMENT: usize = 64;
const NOW: u64 = 1000;
/// Fragment size cap for the default corpus: the model lane is interpreted
/// and hashes every judged line in pure Lean; megabyte lines belong in the
/// curated corpus (which has two 64 KiB cases), not in volume fuzz.
const FRAG_CAP: usize = 2048;

fn host() -> &'static LeanHost {
    static HOST: OnceLock<LeanHost> = OnceLock::new();
    HOST.get_or_init(LeanHost::new)
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("rust/ has a parent")
        .to_path_buf()
}

// ---- deterministic generator ------------------------------------------------
// SplitMix64 — owned PRNG instead of proptest: the whole corpus runs ONCE per
// lane (batch protocol), so shrinking cannot work, and an owned seed makes
// "all three lanes saw identical bytes" plus seed-replay trivial.

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
    fn pick<'a, T>(&mut self, xs: &'a [T]) -> &'a T {
        &xs[self.below(xs.len() as u64) as usize]
    }
}

// ---- step-input construction --------------------------------------------------

/// The evidence carried by one step input. Compact JSON, identical bytes to
/// every lane (the corpus file is the single source).
fn step_input_full(
    line: &str,
    now: u64,
    approvals: serde_json::Value,
    votes: &str,
    grants: &str,
    forecasts: &str,
) -> String {
    serde_json::json!({
        "line": line,
        "now": now,
        "approvals": approvals,
        "votes": votes,
        "grants": grants,
        "forecasts": forecasts,
    })
    .to_string()
}

fn step_input(line: &str) -> String {
    step_input_full(line, NOW, serde_json::json!([]), "", "", "")
}

fn guarded_call(sql: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"db.execute","arguments":{{"database":"prod","sql":{}}}}}}}"#,
        serde_json::to_string(sql).unwrap()
    )
}

fn tools_call_line(method: &str, name: &str, sql: &str) -> String {
    format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":{},"params":{{"name":{},"arguments":{{"sql":{}}}}}}}"#,
        serde_json::to_string(method).unwrap(),
        serde_json::to_string(name).unwrap(),
        serde_json::to_string(sql).unwrap(),
    )
}

/// The obfuscation disguise set (differential.rs mirror), deterministic.
fn disguises(s: &str) -> Vec<String> {
    let mixed: String = s
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if i % 2 == 0 {
                c.to_ascii_uppercase()
            } else {
                c.to_ascii_lowercase()
            }
        })
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

// ---- fuzz fragment/line generators (PRNG port of parser_boundary's proptest
// ---- strategies, plus structural mutation) -----------------------------------

fn json_escape_u(c: u32) -> String {
    // "\uXXXX" — built from parts so the escape survives every tooling layer.
    format!("{}u{:04x}", '\\', c)
}

fn fragment(rng: &mut Rng) -> String {
    match rng.below(8) {
        // arbitrary f64 from raw bits, rendered as JSON if finite
        0 => {
            let x = f64::from_bits(rng.next());
            if x.is_finite() {
                format!("{x:?}")
            } else {
                "0".into()
            }
        }
        // oversized integer literals
        1 => "9".repeat(1 + rng.below(500) as usize),
        // decimal exponent literals, some out of f64 range
        2 => format!("{}e{}", rng.next() as i32, (rng.below(800) as i64) - 400),
        // PATHOLOGICAL decimal exponents — 7..20 digits, straddling the kernel's
        // Nat.pow abort threshold. Pre-fix these ABORTED the native .so and the
        // interpreter while the wasm passed through (the Lane C divergence);
        // post-fix every lane fails closed to `block` identically. The corpus is
        // no longer clamped away from this region — it exercises it on purpose.
        6 => {
            let digits = (7 + rng.below(14)) as usize;
            let sign = if rng.below(2) == 0 { "" } else { "-" };
            format!("1e{sign}{}", "9".repeat(digits))
        }
        // "\uXXXX\uXXXX" escapes incl. lone/paired surrogates
        3 => format!(
            "\"{}{}\"",
            json_escape_u(rng.below(0x11000) as u32),
            json_escape_u(rng.below(0x11000) as u32)
        ),
        // arbitrary unicode string values (serde-escaped, so valid JSON)
        4 => {
            let n = rng.below(64);
            let s: String = (0..n)
                .map(|_| char::from_u32(rng.below(0x11000) as u32).unwrap_or('\u{FFFD}'))
                .collect();
            serde_json::to_string(&s).unwrap()
        }
        // arrays nested to a depth straddling serde's recursion limit 128
        5 => {
            let d = (100 + rng.below(40)) as usize;
            format!("{}0{}", "[".repeat(d), "]".repeat(d))
        }
        // keywords and near-keywords
        _ => rng
            .pick(&["null", "true", "false", "NaN", "Infinity", "undefined"])
            .to_string(),
    }
}

/// A wire line built from a fragment placed in one of the envelope slots
/// (or bare) — the same six positions parser_boundary probes.
fn fuzz_position_line(rng: &mut Rng) -> String {
    let mut frag = fragment(rng);
    if frag.len() > FRAG_CAP {
        let mut cut = FRAG_CAP;
        while !frag.is_char_boundary(cut) {
            cut -= 1;
        }
        frag.truncate(cut);
    }
    match rng.below(6) {
        0 => in_value(&frag),
        1 => as_arguments(&frag),
        2 => as_params(&frag),
        3 => as_name(&frag),
        4 => as_method(&frag),
        _ => frag,
    }
}

/// Structural mutation of a valid line: char-boundary flip / insert / delete /
/// truncate / splice (lines must stay valid UTF-8 — Lean strings).
fn mutate_line(rng: &mut Rng, base: &str, other: &str) -> String {
    let chars: Vec<char> = base.chars().collect();
    if chars.is_empty() {
        return base.to_string();
    }
    let i = rng.below(chars.len() as u64) as usize;
    let printable = (0x20 + rng.below(0x5f) as u8) as char;
    match rng.below(5) {
        // flip one char to a random printable
        0 => {
            let mut c = chars.clone();
            c[i] = printable;
            c.into_iter().collect()
        }
        // insert a random printable
        1 => {
            let mut c = chars.clone();
            c.insert(i, printable);
            c.into_iter().collect()
        }
        // delete one char
        2 => {
            let mut c = chars.clone();
            c.remove(i);
            c.into_iter().collect()
        }
        // truncate
        3 => chars[..i].iter().collect(),
        // splice: prefix of base + suffix of other
        _ => {
            let o: Vec<char> = other.chars().collect();
            let j = if o.is_empty() {
                0
            } else {
                rng.below(o.len() as u64) as usize
            };
            chars[..i].iter().chain(o[j..].iter()).collect()
        }
    }
}

/// Adversarial approvals arrays: wrong target, expired / future issuedAt,
/// missing fields, garbage extra fields, non-object entries.
fn fuzz_approvals(rng: &mut Rng, live_target: Option<&str>) -> serde_json::Value {
    let hex_target = |rng: &mut Rng| -> String {
        (0..64)
            .map(|_| char::from_digit(rng.below(16) as u32, 16).unwrap())
            .collect()
    };
    let n = rng.below(3) + 1;
    let entries: Vec<serde_json::Value> = (0..n)
        .map(|_| match rng.below(6) {
            // well-formed but wrong (random) target
            0 => serde_json::json!({"target": hex_target(rng), "issuedAt": NOW}),
            // expired
            1 => serde_json::json!({"target": live_target.map(str::to_string).unwrap_or_else(|| hex_target(rng)), "issuedAt": 0}),
            // far future
            2 => serde_json::json!({"target": live_target.map(str::to_string).unwrap_or_else(|| hex_target(rng)), "issuedAt": u64::MAX}),
            // missing issuedAt
            3 => serde_json::json!({"target": hex_target(rng)}),
            // garbage fields
            4 => serde_json::json!({"target": hex_target(rng), "issuedAt": NOW, "nonce": rng.next(), "extra": [1,2,3]}),
            // non-object entry
            _ => serde_json::json!(rng.next()),
        })
        .collect();
    serde_json::Value::Array(entries)
}

/// Fuzzed raw evidence-file text (votes / grants / forecasts) — this
/// differentials the `Host.Evidence` text parsers across both compiles.
fn fuzz_evidence_text(rng: &mut Rng) -> String {
    let n = rng.below(4);
    (0..n)
        .map(|_| match rng.below(4) {
            0 => format!(
                "{{\"voter\":\"v{}\",\"epoch\":{}}}",
                rng.below(9),
                rng.below(5)
            ),
            1 => format!("{{\"grant\":\"g{}\"}}", rng.below(9)),
            2 => "not json".to_string(),
            _ => fragment(rng).chars().take(64).collect(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

// ---- corpus ---------------------------------------------------------------------

struct Case {
    category: &'static str,
    /// The inner wire line, when the step input carries one we control
    /// (used for the native classify⇔route invariant).
    inner: Option<String>,
    step: String,
}

enum CorpusLine {
    Reinit,
    Case(Case),
}

fn case(category: &'static str, line: String) -> Case {
    Case {
        category,
        step: step_input(&line),
        inner: Some(line),
    }
}

/// All curated families (always included) + `fuzz_n` generated cases.
/// Returns the corpus (with `#REINIT` markers) and per-family counts.
fn build_corpus(
    rng: &mut Rng,
    fuzz_n: usize,
    live_targets: &[String],
) -> (Vec<CorpusLine>, BTreeMap<&'static str, usize>) {
    let mut cases: Vec<Case> = Vec::new();

    // -- curated: the full parser-boundary map (shared source with
    // parser_boundary.rs — one corpus, two harnesses)
    for c in boundary_corpus() {
        cases.push(case("curated-boundary", c.line));
    }

    // -- curated: obfuscation disguises over whole-line / method / name / arg
    let base = tools_call_line("tools/call", "db.execute", "drop table x");
    for d in disguises(&base) {
        cases.push(case("curated-disguise", d));
    }
    for m in disguises("tools/call") {
        cases.push(case(
            "curated-disguise",
            tools_call_line(&m, "db.execute", "drop table x"),
        ));
    }
    for n in disguises("db.execute") {
        cases.push(case(
            "curated-disguise",
            tools_call_line("tools/call", &n, "drop table x"),
        ));
    }
    for a in disguises("delete_all") {
        cases.push(case(
            "curated-disguise",
            tools_call_line("tools/call", "db.execute", &a),
        ));
    }

    // -- curated: approved-forward — the same destructive call with a live
    // approval target derived from a native probe (two-pass; see
    // `derive_live_targets`). All lanes must agree on the deny target bytes
    // (probed earlier) AND on the forward here.
    for (i, t) in live_targets.iter().enumerate() {
        let line = guarded_call(&format!("drop table t{i}"));
        cases.push(Case {
            category: "curated-approved-forward",
            step: step_input_full(
                &line,
                NOW,
                serde_json::json!([{ "target": t, "issuedAt": NOW }]),
                "",
                "",
                "",
            ),
            inner: Some(line),
        });
    }

    // -- fuzz families, split over fuzz_n
    let n_pos = fuzz_n * 40 / 100;
    let n_mut = fuzz_n * 25 / 100;
    let n_step = fuzz_n * 20 / 100;
    let n_env = fuzz_n * 5 / 100;
    let n_disg = fuzz_n - n_pos - n_mut - n_step - n_env;

    for _ in 0..n_pos {
        cases.push(case("fuzz-fragment-position", fuzz_position_line(rng)));
    }

    // NOTE: no extreme-exponent numerics (1e999999) in the mutation pool — the
    // wasm lane pays ~4.5 s/case on those (a measured wasm-only resource
    // asymmetry; native ≈13 ms, interpreter ≈ms, outputs byte-identical — see
    // the Lane C report). The curated boundary corpus still carries ONE such
    // case per run for coverage; the volume fuzz must stay cheap per case.
    let mutation_pool: Vec<String> = vec![
        guarded_call("drop table customers"),
        tools_call_line("tools/call", "db.execute", "delete from ledger"),
        r#"{"jsonrpc":"2.0","id":7,"method":"initialize"}"#.to_string(),
        r#"{"jsonrpc":"2.0","id":8,"method":"tools/list"}"#.to_string(),
        in_value("1"),
        nested(110),
        in_value("1e309"),
        in_value(&"9".repeat(400)),
        in_value("18446744073709551615"),
        in_value(r#"{"a":1,"a":2}"#),
        as_name("null"),
        format!("   {}", in_value("1")),
    ];
    for _ in 0..n_mut {
        let base = rng.pick(&mutation_pool).clone();
        let other = rng.pick(&mutation_pool).clone();
        cases.push(case(
            "fuzz-structural-mutation",
            mutate_line(rng, &base, &other),
        ));
    }

    // step-level variation: now / adversarial approvals / fuzzed evidence text
    for _ in 0..n_step {
        let line = match rng.below(3) {
            0 => guarded_call(&format!("drop table t{}", rng.below(1000))),
            1 => fuzz_position_line(rng),
            _ => r#"{"jsonrpc":"2.0","id":9,"method":"tools/list"}"#.to_string(),
        };
        let random_now = rng.next();
        let now = *rng.pick(&[0u64, NOW, NOW + 119, NOW + 121, u64::MAX, random_now]);
        let live = if live_targets.is_empty() {
            None
        } else {
            Some(rng.pick(live_targets).as_str())
        };
        let approvals = fuzz_approvals(rng, live);
        let votes = fuzz_evidence_text(rng);
        let grants = fuzz_evidence_text(rng);
        let forecasts = fuzz_evidence_text(rng);
        cases.push(Case {
            category: "fuzz-step-evidence",
            inner: Some(line.clone()),
            step: step_input_full(&line, now, approvals, &votes, &grants, &forecasts),
        });
    }

    // hostile step-input ENVELOPES (the step JSON itself malformed / wrong
    // shapes) — stepImpl's own error path, must fail identically in all lanes
    for _ in 0..n_env {
        let step = match rng.below(4) {
            0 => "not a step input".to_string(),
            1 => format!(
                "{{\"line\":{}}}",
                fragment(rng).chars().take(64).collect::<String>()
            ),
            2 => {
                // valid JSON, wrong field types
                serde_json::json!({"line": rng.next(), "now": "soon", "approvals": {"a": 1}})
                    .to_string()
            }
            _ => {
                let mut s = step_input(&guarded_call("drop t"));
                let cut = 1 + rng.below(s.len() as u64 - 1) as usize;
                s = s.chars().take(cut).collect();
                s
            }
        };
        // must stay one physical line for the JSONL corpus protocol
        let step: String = step.replace(['\n', '\r'], " ");
        cases.push(Case {
            category: "fuzz-step-envelope",
            inner: None,
            step,
        });
    }

    // randomized disguise stacking on guarded calls
    for _ in 0..n_disg {
        let sql = format!("drop table t{}", rng.below(1000));
        let mut line = guarded_call(&sql);
        for _ in 0..(1 + rng.below(3)) {
            let ds = disguises(&line);
            line = ds[rng.below(ds.len() as u64) as usize].clone();
        }
        cases.push(case("fuzz-disguise-stack", line));
    }

    // deterministic shuffle so families interleave across segments (state
    // interaction), then #REINIT every SEGMENT cases
    for i in (1..cases.len()).rev() {
        let j = rng.below((i + 1) as u64) as usize;
        cases.swap(i, j);
    }

    let mut counts: BTreeMap<&'static str, usize> = BTreeMap::new();
    let mut corpus: Vec<CorpusLine> = Vec::with_capacity(cases.len() + cases.len() / SEGMENT + 1);
    for (i, c) in cases.into_iter().enumerate() {
        if i % SEGMENT == 0 && i > 0 {
            corpus.push(CorpusLine::Reinit);
        }
        // NO exponent clamp: the fail-closed number guard (Seal.JsonUtil.
        // wireNumbersSafe, in Host.classifyLine) now REFUSES a pathological
        // numeric literal in EVERY lane, so the previously-aborting region
        // (7+ digit exponents, generated on purpose by `fragment`) yields
        // byte-identical `block` across native/wasm/model instead of the old
        // native-abort/wasm-passthrough divergence. The corpus exercises that
        // region directly — that is the point of un-clamping.
        *counts.entry(c.category).or_insert(0) += 1;
        corpus.push(CorpusLine::Case(c));
    }
    (corpus, counts)
}

// ---- envelope -------------------------------------------------------------------

/// Deterministic Ed25519 envelope: fixed-seed dalek key (Ed25519 signing is
/// deterministic — no rand), pubkey = hex of the raw 32-byte key (the same
/// format the bridge derives from the SPKI DER tail). The payload is the
/// bridge's guarded db.execute policy; the SAME payload string feeds all
/// three lanes, so config-derived audit fields agree.
fn mint_envelope(workdir: &Path) -> (String, String, String) {
    use ed25519_dalek::{Signer, SigningKey};
    let approvals_file = workdir.join("approvals.ndjson");
    fs::write(&approvals_file, "").expect("write approvals control file");
    let payload = format!(
        r#"{{"epoch":1,"safety":{{"approval":{{"control_file":{},"ttl_seconds":120}},"tools":[{{"name":"db.execute","mode":"guarded","match":{{"type":"contains_any_ci","arg":"sql","needles":["drop","delete","truncate"]}},"target":[{{"literal":"db"}},{{"arg":"database"}},{{"literal":"write"}},{{"arg":"sql"}}]}}]}}}}"#,
        serde_json::to_string(&approvals_file.to_string_lossy()).unwrap()
    );
    let key = SigningKey::from_bytes(&[0x42u8; 32]);
    let pubkey_hex = hex::encode(key.verifying_key().to_bytes());
    let signature_hex = hex::encode(key.sign(payload.as_bytes()).to_bytes());
    let envelope = format!(
        r#"{{"payload":{},"signature":"{}"}}"#,
        serde_json::to_string(&payload).unwrap(),
        signature_hex
    );
    (envelope, payload, pubkey_hex)
}

// ---- lane runners -----------------------------------------------------------------

/// Native lane, in-process. Also asserts the per-case native invariants:
/// classify == 0 ⇔ route == "passthrough" (routing subsumption for the
/// classify surface wasm does not export) and `route_of_step_output` (the
/// binary's routing fn) only Forwards on the exact forward literal.
fn run_native(
    corpus: &[CorpusLine],
    envelope: &str,
    pk: &str,
    failures: &mut Vec<String>,
) -> Vec<String> {
    let h = host();
    let init = |failures: &mut Vec<String>| match h.init(envelope, pk) {
        Ok(out) if out.contains("\"ok\":true") => {}
        Ok(out) => failures.push(format!("native init rejected: {out}")),
        Err(e) => failures.push(format!("native init seam error: {e}")),
    };
    init(failures);
    let mut outs = Vec::new();
    for (idx, cl) in corpus.iter().enumerate() {
        match cl {
            CorpusLine::Reinit => init(failures),
            CorpusLine::Case(c) => {
                // Corpus-protocol trim: the step input is the corpus line
                // after ASCII-whitespace trim, identical in all three lanes
                // (the wasm/model file readers trim; the in-process lane must
                // see the same bytes — first caught as a phantom "divergence"
                // on a whitespace-tailed fuzz-step-envelope case).
                let step = c
                    .step
                    .trim_matches(|ch: char| matches!(ch, ' ' | '\t' | '\r' | '\n'));
                let out = match h.step(step) {
                    Ok(o) => o,
                    Err(e) => {
                        // surfaces as a three-way divergence, never a skip
                        format!("{{\"seam_error\":\"{e}\"}}")
                    }
                };
                // invariant: the binary's routing fn only Forwards on the literal
                let route = route_of_step_output(Ok(out.clone()));
                if matches!(route, Route::Forward { .. }) && !out.contains("\"route\":\"forward\"")
                {
                    failures.push(format!(
                        "[corpus {idx}] route_of_step_output Forwarded without the forward literal: {out}"
                    ));
                }
                // invariant: classify == 0 ⇔ step route == passthrough
                if let Some(inner) = &c.inner {
                    match h.classify(inner) {
                        Ok(cls) => {
                            let is_pass = out == r#"{"route":"passthrough"}"#;
                            if (cls == 0) != is_pass {
                                failures.push(format!(
                                    "[corpus {idx}] classify/step disagree: classify={cls}, step={out} for line {inner:?}"
                                ));
                            }
                        }
                        Err(e) => failures.push(format!(
                            "[corpus {idx}] classify seam error: {e} for line {inner:?}"
                        )),
                    }
                }
                outs.push(out);
            }
        }
    }
    outs
}

fn read_lane_output(path: &Path) -> Vec<String> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(str::to_string)
        .collect()
}

fn run_wasm(
    root: &Path,
    envelope_file: &Path,
    pk: &str,
    corpus_file: &Path,
    out_file: &Path,
) -> Result<(), String> {
    let st = Command::new("node")
        .arg(root.join("scripts/three_way_wasm_lane.mjs"))
        .arg(envelope_file)
        .arg(pk)
        .arg(corpus_file)
        .arg(out_file)
        .current_dir(root)
        .status()
        .map_err(|e| format!("spawn node: {e}"))?;
    if !st.success() {
        return Err(format!("wasm lane exited {st}"));
    }
    Ok(())
}

fn run_model(
    root: &Path,
    payload_file: &Path,
    corpus_file: &Path,
    out_file: &Path,
) -> Result<(), String> {
    let st = Command::new("lake")
        .args(["env", "lean", "scripts/three_way_model_lane.lean"])
        .env("SEAL_CONF_PAYLOAD", payload_file)
        .env("SEAL_CONF_CORPUS", corpus_file)
        .env("SEAL_CONF_OUT", out_file)
        .current_dir(root)
        .status()
        .map_err(|e| format!("spawn lake: {e}"))?;
    if !st.success() {
        return Err(format!("model lane exited {st}"));
    }
    Ok(())
}

// ---- audit-chain commitment (mirror of scripts/seal_log.mjs / the bridge) ---------

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn chain_head(audits: &[&str]) -> String {
    let genesis = sha256_hex(b"seal-verifiable-record/genesis/v1");
    audits.iter().fold(genesis, |prev, payload| {
        let mut h = Sha256::new();
        h.update(prev.as_bytes());
        h.update([0x1f]);
        h.update(payload.as_bytes());
        hex::encode(h.finalize())
    })
}

fn audit_of(line: &str) -> Option<String> {
    serde_json::from_str::<serde_json::Value>(line)
        .ok()
        .and_then(|v| v.get("audit").and_then(|a| a.as_str()).map(str::to_string))
}

// ---- probe: derive live approval targets from the native lane ---------------------

/// Two-pass forward derivation (the bridge's STEP 1, generalized): block k
/// probe calls on the NATIVE lane, extract the 64-hex approval target from
/// each block response. The corpus then carries the same calls WITH a live
/// approval — every lane must agree on both the deny target bytes (the
/// blocked probes are re-run as part of the corpus via curated-disguise and
/// forward cases) and the resulting forward.
fn derive_live_targets(
    envelope: &str,
    pk: &str,
    k: usize,
    failures: &mut Vec<String>,
) -> Vec<String> {
    let h = host();
    match h.init(envelope, pk) {
        Ok(out) if out.contains("\"ok\":true") => {}
        other => {
            failures.push(format!("probe init failed: {other:?}"));
            return Vec::new();
        }
    }
    let mut targets = Vec::new();
    for i in 0..k {
        let step = step_input(&guarded_call(&format!("drop table t{i}")));
        match h.step(&step) {
            Ok(out) => {
                let response = serde_json::from_str::<serde_json::Value>(&out)
                    .ok()
                    .and_then(|v| {
                        v.get("response")
                            .and_then(|r| r.as_str())
                            .map(str::to_string)
                    })
                    .unwrap_or_default();
                match response.find("approval required: ") {
                    Some(pos) => {
                        let t: String = response[pos + "approval required: ".len()..]
                            .chars()
                            .take(64)
                            .collect();
                        if t.len() == 64
                            && t.chars()
                                .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
                        {
                            targets.push(t);
                        } else {
                            failures.push(format!("probe {i}: malformed approval target {t:?}"));
                        }
                    }
                    None => failures.push(format!("probe {i}: no approval target in {out}")),
                }
            }
            Err(e) => failures.push(format!("probe {i}: seam error {e}")),
        }
    }
    targets
}

// ---- preflight --------------------------------------------------------------------

fn preflight(root: &Path) -> Result<Vec<String>, String> {
    let mut banner = Vec::new();
    let wasm_path = root.join("wasm-spike/verified/seal.wasm");
    let wasm_bytes = fs::read(&wasm_path)
        .map_err(|e| format!("cannot read pinned wasm {}: {e}", wasm_path.display()))?;
    let got = sha256_hex(&wasm_bytes);
    if got != PINNED_WASM_SHA256 {
        return Err(format!(
            "seal.wasm sha256 mismatch: pinned {PINNED_WASM_SHA256}, on disk {got} — refusing to run \
             against an unpinned artifact (authority: wasm-spike/verified/PROVENANCE.txt)"
        ));
    }
    banner.push(format!(
        "wasm artifact : {} (sha256 {got}, pin OK)",
        wasm_path.display()
    ));
    if !root.join("wasm-spike/verified/seal.js").exists() {
        return Err("wasm-spike/verified/seal.js missing".into());
    }
    for (tool, args) in [("node", vec!["--version"]), ("lake", vec!["--version"])] {
        let out = Command::new(tool).args(&args).output().map_err(|e| {
            format!(
                "{tool} unavailable: {e} — the three-way differential needs node + lake; \
                                  set SEAL_SKIP_THREE_WAY=1 to skip LOUDLY"
            )
        })?;
        banner.push(format!(
            "{tool:<14}: {}",
            String::from_utf8_lossy(&out.stdout)
                .lines()
                .next()
                .unwrap_or("?")
        ));
    }
    match seal_host_rs::lean::loaded_ffi_path() {
        Some(p) => banner.push(format!("native .so    : {}", p.display())),
        None => banner.push("native .so    : <dladdr unavailable>".to_string()),
    }
    Ok(banner)
}

// ---- the harness -------------------------------------------------------------------

fn env_u64(key: &str, default: u64) -> u64 {
    std::env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn run_three_way(fuzz_n: usize) {
    if std::env::var("SEAL_SKIP_THREE_WAY").as_deref() == Ok("1") {
        eprintln!(
            "three_way: SKIPPED via SEAL_SKIP_THREE_WAY=1 — the three-way differential DID NOT RUN; \
             no agreement claim is made for this build"
        );
        return;
    }
    let root = repo_root();
    let seed = env_u64("SEAL_THREE_WAY_SEED", DEFAULT_SEED);
    let mut failures: Vec<String> = Vec::new();

    // preflight — a missing lane is a FAILURE (never a silent skip)
    let banner = match preflight(&root) {
        Ok(b) => b,
        Err(e) => panic!("three_way preflight failed: {e}"),
    };

    // workdir persists on failure for reproduction
    let workdir =
        std::env::temp_dir().join(format!("seal-three-way-{}-{seed:x}", std::process::id()));
    fs::create_dir_all(&workdir).expect("create workdir");

    let (envelope, payload, pk) = mint_envelope(&workdir);
    let envelope_file = workdir.join("envelope.json");
    let payload_file = workdir.join("payload.json");
    fs::write(&envelope_file, &envelope).unwrap();
    fs::write(&payload_file, &payload).unwrap();
    // pk persisted so a kept workdir is directly replayable against the lane
    // runners (repro/frisk):
    //   node scripts/three_way_wasm_lane.mjs <wd>/envelope.json $(cat <wd>/pk.txt) <wd>/corpus.jsonl out
    fs::write(workdir.join("pk.txt"), &pk).unwrap();

    // two-pass forward derivation on the native lane
    let live_targets = derive_live_targets(&envelope, &pk, 3, &mut failures);

    let mut rng = Rng(seed);
    let (corpus, counts) = build_corpus(&mut rng, fuzz_n, &live_targets);
    let n_cases = corpus
        .iter()
        .filter(|c| matches!(c, CorpusLine::Case(_)))
        .count();
    let n_reinits = corpus.len() - n_cases;

    println!("==============================================================================");
    println!(" THREE-WAY DIFFERENTIAL — native libsealffi.so ≡ seal.wasm ≡ Lean model");
    println!("==============================================================================");
    for b in &banner {
        println!(" {b}");
    }
    println!(" seed          : {seed:#x} (SEAL_THREE_WAY_SEED)");
    println!(" cases         : {n_cases} total ({n_reinits} #REINIT segment boundaries, SEGMENT={SEGMENT})");
    for (fam, n) in &counts {
        println!("   {fam:<28}: {n}");
    }
    println!(" HONESTY       : differential EVIDENCE over the cases tried — never a");
    println!("                 universal binary≡model proof (Lane C stays a trusted compile;");
    println!("                 see docs/CONFORMANCE-BRIDGE.md and the Lane C boundary statement)");
    println!("==============================================================================");

    // write the shared corpus file
    let corpus_file = workdir.join("corpus.jsonl");
    {
        let mut buf = String::new();
        for cl in &corpus {
            match cl {
                CorpusLine::Reinit => buf.push_str("#REINIT\n"),
                CorpusLine::Case(c) => {
                    buf.push_str(&c.step);
                    buf.push('\n');
                }
            }
        }
        fs::write(&corpus_file, buf).expect("write corpus");
    }

    // run the three lanes (wall time printed — the case-count budget is set
    // from these honest numbers, not estimates)
    let t = std::time::Instant::now();
    let native = run_native(&corpus, &envelope, &pk, &mut failures);
    let t_native = t.elapsed();
    let wasm_out = workdir.join("wasm.out.jsonl");
    let model_out = workdir.join("model.out.jsonl");
    let t = std::time::Instant::now();
    if let Err(e) = run_wasm(&root, &envelope_file, &pk, &corpus_file, &wasm_out) {
        failures.push(format!("wasm lane failed: {e}"));
    }
    let t_wasm = t.elapsed();
    let t = std::time::Instant::now();
    if let Err(e) = run_model(&root, &payload_file, &corpus_file, &model_out) {
        failures.push(format!("model lane failed: {e}"));
    }
    let t_model = t.elapsed();
    println!(
        " lane time     : native {:.1}s, wasm {:.1}s, model {:.1}s",
        t_native.as_secs_f64(),
        t_wasm.as_secs_f64(),
        t_model.as_secs_f64()
    );
    let wasm = read_lane_output(&wasm_out);
    let model = read_lane_output(&model_out);

    // native init ≡ wasm init two-way (byte-equal summary + tamper ⇒ reject)
    init_agreement_two_way(&root, &workdir, &envelope, &payload, &pk, &mut failures);

    // compare
    if native.len() != n_cases || wasm.len() != n_cases || model.len() != n_cases {
        failures.push(format!(
            "line count mismatch: cases={n_cases} native={} wasm={} model={}",
            native.len(),
            wasm.len(),
            model.len()
        ));
    } else {
        let cases: Vec<&Case> = corpus
            .iter()
            .filter_map(|cl| match cl {
                CorpusLine::Case(c) => Some(c),
                CorpusLine::Reinit => None,
            })
            .collect();
        let mut divergences = 0usize;
        for i in 0..n_cases {
            if native[i] != model[i] || wasm[i] != model[i] {
                divergences += 1;
                if divergences <= 10 {
                    let c = cases[i];
                    let mut msg = String::new();
                    let _ = writeln!(msg, "DIVERGENCE at case {i} [{}]:", c.category);
                    let _ = writeln!(msg, "  step  : {}", c.step);
                    let _ = writeln!(msg, "  native: {}", native[i]);
                    let _ = writeln!(msg, "  wasm  : {}", wasm[i]);
                    let _ = writeln!(msg, "  model : {}", model[i]);
                    // which security field differs
                    let field = |a: &str, b: &str| -> &'static str {
                        let pa: serde_json::Value = serde_json::from_str(a).unwrap_or_default();
                        let pb: serde_json::Value = serde_json::from_str(b).unwrap_or_default();
                        if pa.get("route") != pb.get("route") {
                            "ROUTE"
                        } else if pa.get("response") != pb.get("response") {
                            "RESPONSE (deny target)"
                        } else if pa.get("audit") != pb.get("audit") {
                            "AUDIT"
                        } else {
                            "OTHER (whitespace/field order/error text)"
                        }
                    };
                    if native[i] != model[i] {
                        let _ = writeln!(
                            msg,
                            "  native-vs-model differs in: {}",
                            field(&native[i], &model[i])
                        );
                    }
                    if wasm[i] != model[i] {
                        let _ = writeln!(
                            msg,
                            "  wasm-vs-model differs in: {}",
                            field(&wasm[i], &model[i])
                        );
                    }
                    failures.push(msg);
                }
            }
        }
        if divergences > 10 {
            failures.push(format!(
                "... and {} more divergences (first 10 shown)",
                divergences - 10
            ));
        }

        if divergences == 0 {
            // audit chain heads per segment (independent, order-sensitive commitment)
            let mut seg_start = 0usize;
            let mut seg_idx = 0usize;
            let mut boundaries: Vec<usize> = Vec::new();
            {
                let mut count = 0usize;
                for cl in &corpus {
                    match cl {
                        CorpusLine::Reinit => boundaries.push(count),
                        CorpusLine::Case(_) => count += 1,
                    }
                }
                boundaries.push(n_cases);
            }
            for &end in &boundaries {
                let seg_audits = |lane: &[String]| -> Vec<String> {
                    lane[seg_start..end]
                        .iter()
                        .filter_map(|l| audit_of(l))
                        .collect()
                };
                let (na, wa, ma) = (seg_audits(&native), seg_audits(&wasm), seg_audits(&model));
                let (nh, wh, mh) = (
                    chain_head(&na.iter().map(String::as_str).collect::<Vec<_>>()),
                    chain_head(&wa.iter().map(String::as_str).collect::<Vec<_>>()),
                    chain_head(&ma.iter().map(String::as_str).collect::<Vec<_>>()),
                );
                if nh != mh || wh != mh {
                    failures.push(format!(
                        "segment {seg_idx} chain-head divergence: native {nh} wasm {wh} model {mh}"
                    ));
                }
                seg_start = end;
                seg_idx += 1;
            }

            // liveness: non-vacuity of the corpus + order-sensitive commitment
            let routes: std::collections::BTreeSet<String> = native
                .iter()
                .filter_map(|l| {
                    serde_json::from_str::<serde_json::Value>(l)
                        .ok()
                        .and_then(|v| v.get("route").and_then(|r| r.as_str()).map(str::to_string))
                })
                .collect();
            let mut route_counts: BTreeMap<String, usize> = BTreeMap::new();
            for l in &native {
                let r = serde_json::from_str::<serde_json::Value>(l)
                    .ok()
                    .and_then(|v| v.get("route").and_then(|x| x.as_str()).map(str::to_string))
                    .unwrap_or_else(|| "error/other".to_string());
                *route_counts.entry(r).or_insert(0) += 1;
            }
            for want in ["passthrough", "block", "forward"] {
                if !routes.contains(want) {
                    failures.push(format!("liveness: corpus never exercised route {want:?}"));
                }
            }
            let all_audits_owned: Vec<String> = native.iter().filter_map(|l| audit_of(l)).collect();
            let all_audits: Vec<&str> = all_audits_owned.iter().map(String::as_str).collect();
            if all_audits.len() > 1 {
                let fwd = chain_head(&all_audits);
                let rev: Vec<&str> = all_audits.iter().rev().copied().collect();
                if fwd == chain_head(&rev) {
                    failures.push("liveness: chain head is order-insensitive (comparator would miss a reorder)".into());
                }
            }
            println!(" routes        : {route_counts:?}");
            println!(
                " chain heads   : {} segments, all three lanes agree",
                boundaries.len()
            );
        }
    }

    if failures.is_empty() {
        println!(
            " RESULT        : {n_cases}/{n_cases} cases byte-identical across native/wasm/model"
        );
        println!("                 (evidence over these cases only)");
        if std::env::var("SEAL_THREE_WAY_KEEP").as_deref() == Ok("1") {
            println!(
                " artifacts     : kept in {} (SEAL_THREE_WAY_KEEP=1)",
                workdir.display()
            );
        } else {
            let _ = fs::remove_dir_all(&workdir);
        }
    } else {
        eprintln!(
            "three_way FAILED — repro artifacts kept in {}",
            workdir.display()
        );
        eprintln!(
            "repro: SEAL_THREE_WAY_SEED={seed:#x} SEAL_THREE_WAY_CASES={fuzz_n} cargo test --test three_way -- --nocapture"
        );
        panic!(
            "three-way differential: {} failure(s):\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

/// Native ≡ wasm init agreement (the model lane cannot verify Ed25519 — R6):
/// both accept the minted envelope with a byte-identical summary, and both
/// REJECT a tampered envelope (flipped signature byte).
fn init_agreement_two_way(
    root: &Path,
    workdir: &Path,
    envelope: &str,
    _payload: &str,
    pk: &str,
    failures: &mut Vec<String>,
) {
    let h = host();
    let native_init = match h.init(envelope, pk) {
        Ok(o) => o,
        Err(e) => {
            failures.push(format!("init-agreement: native seam error {e}"));
            return;
        }
    };
    // tamper: flip one hex digit of the signature
    let tampered = {
        let mut v: serde_json::Value = serde_json::from_str(envelope).unwrap();
        let sig = v["signature"].as_str().unwrap().to_string();
        let flipped = if sig.as_bytes()[0] == b'0' { "1" } else { "0" };
        v["signature"] = serde_json::json!(format!("{flipped}{}", &sig[1..]));
        v.to_string()
    };
    match h.init(&tampered, pk) {
        Ok(o) if o.contains("\"ok\":true") => {
            failures.push("init-agreement: NATIVE ACCEPTED a tampered envelope".to_string())
        }
        Ok(_) => {}
        Err(e) => failures.push(format!(
            "init-agreement: native tamper probe seam error {e}"
        )),
    }
    // wasm side via a tiny corpus: init happens in the runner; byte-equality of
    // the init SUMMARY is probed via node -e for both envelopes.
    let probe = |env_text: &str| -> Result<String, String> {
        let env_file = workdir.join("init-probe-envelope.json");
        fs::write(&env_file, env_text).map_err(|e| e.to_string())?;
        let js_path =
            serde_json::to_string(&root.join("wasm-spike/verified/seal.js").to_string_lossy())
                .unwrap();
        let env_path = serde_json::to_string(&env_file.to_string_lossy()).unwrap();
        let pk_json = serde_json::to_string(pk).unwrap();
        // node -e runs CommonJS: require() is available directly.
        let script = format!(
            "const factory = require({js_path});\n\
             factory({{ print() {{}}, printErr() {{}} }}).then((M) => {{\n\
               const env = require(\"node:fs\").readFileSync({env_path}, \"utf8\");\n\
               process.stdout.write(M.ccall(\"seal_init\", \"string\", [\"string\", \"string\"], [env, {pk_json}]));\n\
             }});"
        );
        let out = Command::new("node")
            .arg("-e")
            .arg(script)
            .current_dir(root)
            .output()
            .map_err(|e| e.to_string())?;
        if !out.status.success() {
            return Err(format!(
                "init probe exited {}: {}",
                out.status,
                String::from_utf8_lossy(&out.stderr)
            ));
        }
        Ok(String::from_utf8_lossy(&out.stdout).to_string())
    };
    match probe(envelope) {
        Ok(wasm_init) => {
            if wasm_init != native_init {
                failures.push(format!(
                    "init-agreement: summaries differ\n  native: {native_init}\n  wasm  : {wasm_init}"
                ));
            }
        }
        Err(e) => failures.push(format!("init-agreement: wasm probe failed: {e}")),
    }
    match probe(&tampered) {
        Ok(o) if o.contains("\"ok\":true") => {
            failures.push("init-agreement: WASM ACCEPTED a tampered envelope".to_string())
        }
        Ok(_) => {}
        Err(e) => failures.push(format!("init-agreement: wasm tamper probe failed: {e}")),
    }
    // restore a clean session for anything that runs after
    let _ = h.init(envelope, pk);
}

#[test]
fn three_way_agreement() {
    let n = env_u64("SEAL_THREE_WAY_CASES", 256) as usize;
    run_three_way(n);
}

/// On-demand soak: cargo test --test three_way -- --ignored --nocapture
/// (optionally SEAL_THREE_WAY_SOAK_CASES=N; default 100_000 fuzz cases).
#[test]
#[ignore]
fn three_way_soak() {
    let n = env_u64("SEAL_THREE_WAY_SOAK_CASES", 100_000) as usize;
    run_three_way(n);
}

/// LANE C FIX, regression-pinned. The pathological-number divergence the soak
/// found is CLOSED: a `tools/call` whose argument value is a JSON number with a
/// ~10-digit decimal exponent (which pre-fix aborted the native `.so` and the
/// Lean interpreter via `Nat.pow`, while the emscripten wasm passed through)
/// now fails closed to `block` in ALL THREE lanes, byte-identically. The
/// pre-parse guard `Seal.JsonUtil.wireNumbersSafe` refuses the line before
/// `Json.parse` evaluates `10^exponent`.
///
/// This test asserts the FIXED state, run out-of-process for every lane so a
/// regression that reintroduces the native/interpreter abort is observed (a
/// non-zero exit) rather than taking the test binary down with it. If any lane
/// aborts again, or the three stop agreeing on `block`, the fix regressed —
/// see ~/src/seal-kernel-pathological-number-report-2026-07-16.md.
#[test]
fn pathological_number_fails_closed_all_lanes() {
    if std::env::var("SEAL_SKIP_THREE_WAY").as_deref() == Ok("1") {
        eprintln!("pathological_number_fails_closed: SKIPPED via SEAL_SKIP_THREE_WAY=1");
        return;
    }
    let root = repo_root();
    for tool in ["node", "lake"] {
        if Command::new(tool).arg("--version").output().is_err() {
            eprintln!(
                "pathological_number_fails_closed: SKIPPED — {tool} unavailable (fix documented in the report)"
            );
            return;
        }
    }

    let workdir =
        std::env::temp_dir().join(format!("seal-three-way-finding-{}", std::process::id()));
    fs::create_dir_all(&workdir).expect("create workdir");
    let (envelope, payload, pk) = mint_envelope(&workdir);
    let envelope_file = workdir.join("envelope.json");
    let payload_file = workdir.join("payload.json");
    let corpus_file = workdir.join("corpus.jsonl");
    fs::write(&envelope_file, &envelope).unwrap();
    fs::write(&payload_file, &payload).unwrap();

    // the pre-fix aborting input: a well-formed tools/call, arg value 1E<10 nines>
    let line = format!(
        r#"{{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{{"name":"t","arguments":{{"v":1E{}}}}}}}"#,
        "9".repeat(10)
    );
    let step = step_input(&line);
    fs::write(&corpus_file, format!("{step}\n")).unwrap();

    // native, OUT OF PROCESS via kernel_oracle (same .so) — a regression abort
    // is an observable exit status, not a SIGABRT of this test binary.
    let native = Command::new(env!("CARGO_BIN_EXE_kernel_oracle"))
        .arg(&envelope_file)
        .arg(&pk)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            use std::io::Write as _;
            child
                .stdin
                .take()
                .unwrap()
                .write_all(format!("{step}\n").as_bytes())?;
            child.wait_with_output()
        })
        .expect("spawn kernel_oracle");
    let native_out = String::from_utf8_lossy(&native.stdout).trim().to_string();

    // model lane (Lean interpreter), out of process
    let model_out_file = workdir.join("model.out");
    let model_status = Command::new("lake")
        .args(["env", "lean", "scripts/three_way_model_lane.lean"])
        .env("SEAL_CONF_PAYLOAD", &payload_file)
        .env("SEAL_CONF_CORPUS", &corpus_file)
        .env("SEAL_CONF_OUT", &model_out_file)
        .current_dir(&root)
        .status()
        .expect("spawn lake");
    let model_out = fs::read_to_string(&model_out_file)
        .unwrap_or_default()
        .trim()
        .to_string();

    // wasm lane, out of process
    let wasm_out_file = workdir.join("wasm.out");
    let wasm_ok = run_wasm(&root, &envelope_file, &pk, &corpus_file, &wasm_out_file).is_ok();
    let wasm_out = fs::read_to_string(&wasm_out_file)
        .unwrap_or_default()
        .trim()
        .to_string();

    println!(
        "pathological_number_fails_closed:\n  native_exit_ok={} model_exit_ok={} wasm_ok={wasm_ok}\n  native={native_out}\n  model ={model_out}\n  wasm  ={wasm_out}",
        native.status.success(),
        model_status.success()
    );

    let _ = fs::remove_dir_all(&workdir);

    // no lane aborts any more
    assert!(
        native.status.success(),
        "native .so aborted on the pathological number — the fail-closed guard regressed"
    );
    assert!(
        model_status.success(),
        "model lane aborted on the pathological number — the fail-closed guard regressed"
    );
    assert!(wasm_ok, "wasm lane failed on the pathological number");

    // all three fail CLOSED, byte-identically, to a block (never passthrough)
    let route = |s: &str| -> String {
        serde_json::from_str::<serde_json::Value>(s)
            .ok()
            .and_then(|v| v.get("route").and_then(|r| r.as_str()).map(str::to_string))
            .unwrap_or_default()
    };
    assert_eq!(
        route(&native_out),
        "block",
        "native did not fail closed to block: {native_out}"
    );
    assert_eq!(
        native_out, model_out,
        "native vs model diverge on the pathological number (fix must be byte-identical)"
    );
    assert_eq!(
        native_out, wasm_out,
        "native vs wasm diverge on the pathological number (fix must be byte-identical)"
    );
}
