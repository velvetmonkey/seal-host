// SPDX-License-Identifier: Apache-2.0
//! MCP adapter revision capability and per-session selection.
//!
//! The supported set is discovery information. The effect envelope continues
//! to sign one scalar: the revision selected by the received entry-call shape
//! for the child session that mediated that call.

use crate::envelope_v23::{AdapterClaim, MCP_ADAPTER_TYPE};
use serde_json::Value;

pub const MCP_LEGACY_ADAPTER_REVISION: &str = "2025-06-18";
pub const MCP_CURRENT_ADAPTER_REVISION: &str = "2026-07-28";

/// Discovery-facing supported set. A cooperating MCP server may serialize
/// these strings as `result.supportedVersions` in its own `server/discover`
/// response. The transparent host never injects or amends that response.
pub const MCP_DISCOVERY_SUPPORTED_REVISIONS: [&str; 2] =
    [MCP_LEGACY_ADAPTER_REVISION, MCP_CURRENT_ADAPTER_REVISION];

/// Scalar semantics actually selected for one mediated child session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McpAdapterRevision {
    Legacy2025_06_18,
    Current2026_07_28,
}

impl McpAdapterRevision {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Legacy2025_06_18 => MCP_LEGACY_ADAPTER_REVISION,
            Self::Current2026_07_28 => MCP_CURRENT_ADAPTER_REVISION,
        }
    }

    pub fn adapter_claim(self) -> AdapterClaim {
        AdapterClaim {
            kind: MCP_ADAPTER_TYPE.into(),
            version: self.as_str().into(),
        }
    }
}

/// M.2a's ruled policy. There is deliberately no translation variant and no
/// client-facing/child-facing revision pair: this host neither rewrites child
/// bytes nor claims to translate them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum McpMixedVersionPolicy {
    TransparentDualEra,
}

pub const MCP_MIXED_VERSION_POLICY: McpMixedVersionPolicy =
    McpMixedVersionPolicy::TransparentDualEra;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum McpRevisionSelection {
    #[default]
    Undetermined,
    Selected(McpAdapterRevision),
    ConflictingEntryCalls,
}

/// Derives the revision fact from the received session entry-call shape.
///
/// Only the method name is observed here. M.7 owns validation of each
/// request's `protocolVersion` and `clientCapabilities`, plus its JSON-RPC
/// error mapping. A mediated call before either entry shape, or after both
/// incompatible shapes, has no honest scalar and is refused rather than
/// silently falling back to the legacy revision.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct McpRevisionSession {
    selection: McpRevisionSelection,
}

impl McpRevisionSession {
    pub fn observe_received_call(&mut self, line: &str) {
        let Ok(request) = serde_json::from_str::<Value>(line) else {
            return;
        };
        let observed = match request.get("method").and_then(Value::as_str) {
            Some("initialize") => Some(McpAdapterRevision::Legacy2025_06_18),
            Some("server/discover") => Some(McpAdapterRevision::Current2026_07_28),
            _ => None,
        };
        let Some(observed) = observed else {
            return;
        };
        self.selection = match self.selection {
            McpRevisionSelection::Undetermined => McpRevisionSelection::Selected(observed),
            McpRevisionSelection::Selected(selected) if selected == observed => {
                McpRevisionSelection::Selected(selected)
            }
            McpRevisionSelection::Selected(_) | McpRevisionSelection::ConflictingEntryCalls => {
                McpRevisionSelection::ConflictingEntryCalls
            }
        };
    }

    pub fn actual_revision(self) -> Result<McpAdapterRevision, &'static str> {
        match self.selection {
            McpRevisionSelection::Selected(revision) => Ok(revision),
            McpRevisionSelection::Undetermined => Err(
                "MCP adapter revision is undetermined: no initialize or server/discover entry call was received",
            ),
            McpRevisionSelection::ConflictingEntryCalls => Err(
                "MCP adapter revision is ambiguous: both initialize and server/discover entry calls were received",
            ),
        }
    }

    /// Lossless M.2 state input for the Lean-owned M.7 gate. Rust never
    /// compares request metadata with this value.
    pub fn version_gate_input(self) -> &'static str {
        match self.selection {
            McpRevisionSelection::Undetermined => "",
            McpRevisionSelection::Selected(revision) => revision.as_str(),
            McpRevisionSelection::ConflictingEntryCalls => "conflicting-entry-calls",
        }
    }
}
