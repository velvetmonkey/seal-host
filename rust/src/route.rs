// SPDX-License-Identifier: Apache-2.0
//! The ONLY translation from kernel output to transport action. Pure, total
//! functions: every possible seam result maps to exactly one action, and
//! `Route::Forward` is constructible ONLY from a successfully parsed kernel
//! step output whose `route` is literally `"forward"` (with, for a block, a
//! present response string). Everything else — seam errors, unparseable
//! output, missing/unknown routes, non-string fields — lands in
//! `SeamFailure`, which never forwards.
//!
//! `main.rs` and the conformance tests call these SAME functions, so there
//! is no test-mirror differential: the property the tests pin is the code
//! that runs.
//!
//! This module is the PINNED half of the Lane C seam split (see the
//! `lean.rs` module docs): pure and total, so the routing-preservation
//! property is testable directly — exhaustively over the `SeamError`
//! variants (`differential.rs::every_seam_error_variant_fails_closed`,
//! compile-breaking on a new variant) and property-based over arbitrary
//! kernel output strings (`step_output_route_literal_only`,
//! `step_output_never_forwards_garbage`, `classify_literal_only`). The
//! marshalling that PRODUCES the `Result` these functions consume stays
//! trusted glue in `lean.rs`.

use crate::lean::SeamError;
use serde_json::Value;

/// Transport action for one mediated line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Route {
    /// Kernel verdict allows the bytes through (step route `forward`). The
    /// only variant that may write wire bytes to the child.
    Forward { audit: Option<String> },
    /// Kernel verdict blocks: `response` (kernel-authored, newline-terminated)
    /// goes to the client; nothing goes to the child.
    Block {
        response: String,
        audit: Option<String>,
    },
    /// Broken or ambiguous seam: nothing goes to the child; the static
    /// `seam_error_response` goes to the client.
    SeamFailure { reason: String },
}

/// Routing action for the pre-step classify fast path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClassifyRoute {
    /// Literal `Ok(0)` from a healthy seam: not a tools/call; forward the
    /// wire bytes untouched (Lean's own routing verdict).
    Passthrough,
    /// Literal `Ok(1)`: mediated act — must go through `seal_host_step`.
    Mediate,
    /// Anything else (seam error or a value outside the kernel's 0/1
    /// contract): refuse — never forward, respond with the seam error.
    Refuse,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VersionGateRoute {
    Continue,
    Reject { response: String },
    SeamFailure { reason: String },
}

/// Total mapping from the classify seam result. Only the exact healthy
/// values route; garbage and errors refuse.
pub fn route_of_classify(c: Result<u32, SeamError>) -> ClassifyRoute {
    match c {
        Ok(0) => ClassifyRoute::Passthrough,
        Ok(1) => ClassifyRoute::Mediate,
        Ok(_) | Err(_) => ClassifyRoute::Refuse,
    }
}

/// Total fail-closed mapping of the kernel's opaque M.7 output. This function
/// contains no MCP metadata or version predicate: only the exact kernel route
/// literal can continue, and Rust emits only a kernel-supplied rejection.
pub fn route_of_version_gate(out: Result<String, SeamError>) -> VersionGateRoute {
    let failure = |reason| VersionGateRoute::SeamFailure { reason };
    let text = match out {
        Ok(text) => text,
        Err(error) => return failure(format!("version-gate seam error: {error}")),
    };
    let value: Value = match serde_json::from_str(&text) {
        Ok(value) => value,
        Err(error) => return failure(format!("version-gate output unparseable: {error}")),
    };
    match value.get("route").and_then(Value::as_str) {
        Some("continue") => VersionGateRoute::Continue,
        Some("reject") => match value.get("response").and_then(Value::as_str) {
            Some(response) => VersionGateRoute::Reject {
                response: response.to_owned(),
            },
            None => failure("version-gate rejection without response".to_owned()),
        },
        Some(other) => failure(format!("unknown version-gate route: {other}")),
        None => failure("missing version-gate route".to_owned()),
    }
}

/// Total mapping from the step seam result. Forward requires an exact parse
/// of the kernel's output with an exact route literal; a block requires the
/// kernel's response string to be present (a block with nothing to tell the
/// client is a malformed verdict, not a verdict).
pub fn route_of_step_output(out: Result<String, SeamError>) -> Route {
    let text = match out {
        Ok(t) => t,
        Err(e) => {
            return Route::SeamFailure {
                reason: format!("seam error: {e}"),
            }
        }
    };
    let v: Value = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            return Route::SeamFailure {
                reason: format!("step output unparseable: {e}"),
            }
        }
    };
    let audit = v["audit"].as_str().map(str::to_owned);
    // Step-level "passthrough" is NOT a forward. The host calls step only on
    // lines classify already gated to mediate, and the kernel re-runs the same
    // pure classifyLine on the identical string — so a step output carrying
    // route "passthrough" cannot come from the deployed flow (Ffi.lean emits
    // it only from the classify-passthrough branch). An impossible route is a
    // broken seam, and a broken seam never forwards.
    match v["route"].as_str() {
        Some("forward") => Route::Forward { audit },
        Some("block") => match v["response"].as_str() {
            Some(r) => Route::Block {
                response: r.to_owned(),
                audit,
            },
            None => Route::SeamFailure {
                reason: "block verdict without response".to_owned(),
            },
        },
        Some(other) => Route::SeamFailure {
            reason: format!("unknown route: {other}"),
        },
        None => Route::SeamFailure {
            reason: "missing route".to_owned(),
        },
    }
}

/// The ONLY host-authored bytes that ever reach the client: a static
/// JSON-RPC error emitted when the mediation seam fails mid-request, so the
/// client is not left hanging. `id` is null because recovering the request
/// id would mean re-parsing raw input — the parser differential this host
/// forbids. Named in RUST_BRIDGE.md.
pub const SEAM_ERROR_RESPONSE: &str = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32603,\"message\":\"seal-host: mediation seam failure; request blocked\"}}\n";

/// A hard pre-parse refusal for a numeric literal on which the exact Lean
/// reader and a downstream IEEE-754 binary64 reader disagree. Constructed
/// through serde so an attacker-controlled literal can never break framing.
pub fn numeric_agreement_refusal_response(literal: &str) -> String {
    serde_json::json!({
        "jsonrpc": "2.0",
        "id": serde_json::Value::Null,
        "error": {
            "code": -32600,
            "message": format!(
                "seal-host: request refused — unsafe numeric literal {literal}"
            )
        }
    })
    .to_string()
        + "\n"
}

/// Stable response for any hostile-boundary resource-limit refusal. The
/// detailed, non-secret limit name is emitted once on stderr; the wire shape
/// remains constant and never reflects attacker-controlled bytes.
pub const RESOURCE_LIMIT_RESPONSE: &str = "{\"jsonrpc\":\"2.0\",\"id\":null,\"error\":{\"code\":-32001,\"message\":\"seal-host: resource limit exceeded; request blocked\"}}\n";
