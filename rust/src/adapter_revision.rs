// SPDX-License-Identifier: Apache-2.0
//! MCP adapter revision capability and per-session selection.
//!
//! The supported set is discovery information. The effect envelope continues
//! to sign one scalar: the revision selected by the received entry-call shape
//! for the child session that mediated that call.
//!
//! The selection TRANSITION is not implemented here. It is the kernel-owned
//! fold `seal_host_mcp_revision_observe` (Ffi.lean `McpRevisionSelection.observe`
//! — the same fold the wasm build runs), reached through the seam this host
//! already links. This module only carries the opaque selection string between
//! calls and maps it fail-closed onto the signed adapter claim. The retired
//! serde_json twin of the fold survives solely as the reference comparand in
//! `tests/m2_observe_differential.rs`.

use crate::envelope_v23::{AdapterClaim, MCP_ADAPTER_TYPE};
use crate::lean::{LeanHost, SeamError};

pub const MCP_LEGACY_ADAPTER_REVISION: &str = "2025-06-18";
pub const MCP_CURRENT_ADAPTER_REVISION: &str = "2026-07-28";

/// The kernel's `McpRevisionSelection.gateInput` conflict sentinel, verbatim.
const MCP_CONFLICTING_ENTRY_CALLS: &str = "conflicting-entry-calls";

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

/// Carries the revision fact derived from the received session entry-call
/// shape — derived by the kernel, per observed line, never re-derived here.
///
/// Only the method name is observed. M.7 owns validation of each request's
/// `protocolVersion` and `clientCapabilities`, plus its JSON-RPC error
/// mapping. A mediated call before either entry shape, or after both
/// incompatible shapes, has no honest scalar and is refused rather than
/// silently falling back to the legacy revision.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct McpRevisionSession {
    /// Gate-input encoding, kernel-owned domain: `""` while undetermined,
    /// the selected revision string, or the conflict sentinel. Written only
    /// from `seal_host_mcp_revision_observe` results.
    selection: String,
}

impl McpRevisionSession {
    /// Fold one line into the selection through the kernel. On a seam error
    /// the selection is left unchanged; the caller must refuse the line
    /// (fail-closed, like every other seam failure).
    pub fn observe_received_call(&mut self, host: &LeanHost, line: &str) -> Result<(), SeamError> {
        self.selection = host.mcp_revision_observe(line, &self.selection)?;
        Ok(())
    }

    pub fn actual_revision(&self) -> Result<McpAdapterRevision, &'static str> {
        match self.selection.as_str() {
            MCP_LEGACY_ADAPTER_REVISION => Ok(McpAdapterRevision::Legacy2025_06_18),
            MCP_CURRENT_ADAPTER_REVISION => Ok(McpAdapterRevision::Current2026_07_28),
            "" => Err(
                "MCP adapter revision is undetermined: no initialize or server/discover entry call was received",
            ),
            MCP_CONFLICTING_ENTRY_CALLS => Err(
                "MCP adapter revision is ambiguous: both initialize and server/discover entry calls were received",
            ),
            _ => Err(
                "MCP adapter revision is unrecognized: the kernel selected a revision outside the ruled dual-era set",
            ),
        }
    }

    /// Lossless M.2 state input for the Lean-owned M.7 gate. Rust never
    /// compares request metadata with this value.
    pub fn version_gate_input(&self) -> &str {
        &self.selection
    }
}
