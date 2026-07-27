// SPDX-License-Identifier: Apache-2.0
//! Config-driven, signed reachability inventory.
//!
//! v0 does not claim that a deployment declaration is the world.  Every
//! incompletely enumerated category becomes a concrete UNKNOWN record and the
//! report refuses to calculate a coverage percentage.

use crate::decision_receipt::sha256_hex;
use crate::providers::verify_ed25519_signature;
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

pub const INVENTORY_VERSION: &str = "seal-reachability-inventory/v0";
pub const REPORT_VERSION: &str = "seal-reachability-report/v0";
pub const SIGNED_PAYLOAD_VERSION: &str = "seal-signed-payload/v1";

pub const REQUIRED_CATEGORIES: [&str; 7] = [
    "tool_handles",
    "transport",
    "subprocess_shell",
    "outbound_network",
    "filesystem",
    "scheduled_execution",
    "in_process_handles",
];

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Inventory {
    pub seal_reachability_inventory: String,
    pub deployment: String,
    pub agent: String,
    pub evidence_sources: Vec<EvidenceSourceInput>,
    pub broker: BrokerInput,
    pub declared_paths: Vec<DeclaredPath>,
    pub category_enumeration: Vec<CategoryEnumeration>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EvidenceSourceInput {
    pub path: String,
    pub description: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerInput {
    pub policy_path: String,
    pub route: String,
    pub conditional_on: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeclaredPath {
    pub id: String,
    pub category: String,
    pub mechanism: String,
    pub route: RouteDeclaration,
    pub reason: String,
    #[serde(default)]
    pub conditional_on: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum RouteDeclaration {
    ThroughSeal,
    Direct,
    Unknown,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CategoryEnumeration {
    pub category: String,
    pub method: String,
    pub complete: bool,
    #[serde(default)]
    pub unknown_id: Option<String>,
    #[serde(default)]
    pub unknown_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReachabilityReport {
    pub seal_reachability_report: String,
    pub deployment: String,
    pub agent: String,
    pub generated_at_unix_ms: u64,
    pub inventory_sha256: String,
    pub evidence_sources: Vec<EvidenceSource>,
    pub denominator: Denominator,
    pub summary: Summary,
    pub paths: Vec<PathRecord>,
    pub category_enumeration: Vec<CategoryReport>,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EvidenceSource {
    pub path: String,
    pub description: String,
    pub sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Denominator {
    pub sound: bool,
    pub basis: String,
    pub statement: String,
    pub coverage_percent: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Summary {
    pub enumerated_path_records: usize,
    pub brokered: usize,
    pub unbrokered: usize,
    pub unknown: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct PathRecord {
    pub id: String,
    pub category: String,
    pub mechanism: String,
    pub classification: Classification,
    pub reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conditional_on: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Classification {
    Brokered,
    Unbrokered,
    Unknown,
}

impl Classification {
    fn as_str(self) -> &'static str {
        match self {
            Self::Brokered => "BROKERED",
            Self::Unbrokered => "UNBROKERED",
            Self::Unknown => "UNKNOWN",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CategoryReport {
    pub category: String,
    pub method: String,
    pub complete: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedEnvelope {
    pub seal_signed_payload: String,
    pub kind: String,
    pub algorithm: String,
    pub payload: String,
    pub payload_sha256: String,
    pub public_key: String,
    pub key_id: String,
    pub signature: String,
}

fn nonempty(value: &str, field: &str) -> Result<(), String> {
    if value.trim().is_empty() {
        Err(format!("{field} must not be empty"))
    } else {
        Ok(())
    }
}

fn read_source(base: &Path, source: &str) -> Result<(PathBuf, Vec<u8>), String> {
    let path = base.join(source);
    let bytes = std::fs::read(&path)
        .map_err(|e| format!("cannot read evidence source {}: {e}", path.display()))?;
    Ok((path, bytes))
}

fn tool_names(policy: &Value) -> Result<Vec<String>, String> {
    let tools = policy
        .pointer("/safety/tools")
        .and_then(Value::as_array)
        .ok_or("broker policy lacks safety.tools array")?;
    let mut names = BTreeSet::new();
    for tool in tools {
        let unconditionally_denied = tool.get("mode").and_then(Value::as_str) == Some("deny")
            && tool.pointer("/match/type").and_then(Value::as_str) == Some("always");
        if unconditionally_denied {
            continue;
        }
        let name = tool
            .get("name")
            .and_then(Value::as_str)
            .ok_or("broker policy tool lacks string name")?;
        nonempty(name, "broker policy tool name")?;
        if !names.insert(name.to_owned()) {
            return Err(format!("duplicate broker policy tool name: {name}"));
        }
    }
    Ok(names.into_iter().collect())
}

pub fn build_report(
    inventory_path: &Path,
    inventory_bytes: &[u8],
    generated_at_unix_ms: u64,
) -> Result<ReachabilityReport, String> {
    let inventory: Inventory = serde_json::from_slice(inventory_bytes)
        .map_err(|e| format!("bad reachability inventory JSON: {e}"))?;
    if inventory.seal_reachability_inventory != INVENTORY_VERSION {
        return Err(format!(
            "unsupported inventory version: {}",
            inventory.seal_reachability_inventory
        ));
    }
    nonempty(&inventory.deployment, "deployment")?;
    nonempty(&inventory.agent, "agent")?;
    nonempty(&inventory.broker.route, "broker route")?;
    nonempty(&inventory.broker.conditional_on, "broker conditional_on")?;

    let base = inventory_path.parent().unwrap_or_else(|| Path::new("."));
    let mut sources = Vec::new();
    for source in &inventory.evidence_sources {
        nonempty(&source.description, "evidence source description")?;
        let (_, bytes) = read_source(base, &source.path)?;
        sources.push(EvidenceSource {
            path: source.path.clone(),
            description: source.description.clone(),
            sha256: sha256_hex(&bytes),
        });
    }

    let (_, policy_bytes) = read_source(base, &inventory.broker.policy_path)?;
    let policy: Value = serde_json::from_slice(&policy_bytes)
        .map_err(|e| format!("bad broker policy JSON: {e}"))?;
    if !sources
        .iter()
        .any(|source| source.path == inventory.broker.policy_path)
    {
        sources.push(EvidenceSource {
            path: inventory.broker.policy_path.clone(),
            description: "seal broker policy used to enumerate mediated tool names".into(),
            sha256: sha256_hex(&policy_bytes),
        });
    }

    let mut categories = BTreeMap::new();
    for category in inventory.category_enumeration {
        if !REQUIRED_CATEGORIES.contains(&category.category.as_str()) {
            return Err(format!(
                "unknown reachability category: {}",
                category.category
            ));
        }
        nonempty(&category.method, "category enumeration method")?;
        if categories
            .insert(category.category.clone(), category)
            .is_some()
        {
            return Err("duplicate category_enumeration entry".into());
        }
    }
    for required in REQUIRED_CATEGORIES {
        if !categories.contains_key(required) {
            return Err(format!(
                "missing required category_enumeration entry: {required}"
            ));
        }
    }

    let mut paths = Vec::new();
    for name in tool_names(&policy)? {
        paths.push(PathRecord {
            id: format!("seal-tool:{name}"),
            category: "tool_handles".into(),
            mechanism: format!("{name} via {}", inventory.broker.route),
            classification: Classification::Brokered,
            reason: "tool name is present in the configured seal policy and routed through seal"
                .into(),
            conditional_on: Some(inventory.broker.conditional_on.clone()),
        });
    }

    for path in inventory.declared_paths {
        if !REQUIRED_CATEGORIES.contains(&path.category.as_str()) {
            return Err(format!(
                "declared path {} has unknown category {}",
                path.id, path.category
            ));
        }
        nonempty(&path.id, "declared path id")?;
        nonempty(&path.mechanism, "declared path mechanism")?;
        nonempty(&path.reason, "declared path reason")?;
        let classification = match path.route {
            RouteDeclaration::ThroughSeal => Classification::Brokered,
            RouteDeclaration::Direct => Classification::Unbrokered,
            RouteDeclaration::Unknown => Classification::Unknown,
        };
        paths.push(PathRecord {
            id: path.id,
            category: path.category,
            mechanism: path.mechanism,
            classification,
            reason: path.reason,
            conditional_on: path.conditional_on,
        });
    }

    let mut category_reports = Vec::new();
    for required in REQUIRED_CATEGORIES {
        let category = categories
            .remove(required)
            .expect("required category checked above");
        if !category.complete {
            let unknown_id = category
                .unknown_id
                .ok_or_else(|| format!("incomplete category {required} requires unknown_id"))?;
            let unknown_reason = category
                .unknown_reason
                .ok_or_else(|| format!("incomplete category {required} requires unknown_reason"))?;
            nonempty(&unknown_id, "category unknown_id")?;
            nonempty(&unknown_reason, "category unknown_reason")?;
            paths.push(PathRecord {
                id: unknown_id,
                category: required.into(),
                mechanism: format!("unenumerated remainder of {required}"),
                classification: Classification::Unknown,
                reason: unknown_reason,
                conditional_on: None,
            });
        } else if category.unknown_id.is_some() || category.unknown_reason.is_some() {
            return Err(format!(
                "complete category {required} must not declare an UNKNOWN sentinel"
            ));
        }
        category_reports.push(CategoryReport {
            category: required.into(),
            method: category.method,
            complete: category.complete,
        });
    }

    let mut ids = BTreeSet::new();
    for path in &paths {
        if !ids.insert(path.id.clone()) {
            return Err(format!("duplicate path id: {}", path.id));
        }
    }
    paths.sort_by(|a, b| a.id.cmp(&b.id));
    sources.sort_by(|a, b| a.path.cmp(&b.path));

    let brokered = paths
        .iter()
        .filter(|path| path.classification == Classification::Brokered)
        .count();
    let unbrokered = paths
        .iter()
        .filter(|path| path.classification == Classification::Unbrokered)
        .count();
    let unknown = paths
        .iter()
        .filter(|path| path.classification == Classification::Unknown)
        .count();

    let mut limitations = inventory.limitations;
    limitations.push(
        "UNKNOWN sentinels are one record each but may stand for zero, one, or many actual paths."
            .into(),
    );
    limitations.push(
        "v0 trusts deployment declarations and file snapshots; it does not inspect a live process, \
         namespace, credentials, network policy, or in-process object graph."
            .into(),
    );

    Ok(ReachabilityReport {
        seal_reachability_report: REPORT_VERSION.into(),
        deployment: inventory.deployment,
        agent: inventory.agent,
        generated_at_unix_ms,
        inventory_sha256: sha256_hex(inventory_bytes),
        evidence_sources: sources,
        denominator: Denominator {
            sound: false,
            basis: "declared paths, seal policy tool names, and one named UNKNOWN sentinel per incomplete category".into(),
            statement: "NOT TOTAL REACHABILITY: v0 cannot prove the declaration is complete, and each UNKNOWN sentinel may compress multiple paths.".into(),
            coverage_percent: None,
        },
        summary: Summary {
            enumerated_path_records: paths.len(),
            brokered,
            unbrokered,
            unknown,
        },
        paths,
        category_enumeration: category_reports,
        limitations,
    })
}

pub fn sign_report(
    report: &ReachabilityReport,
    signing_key: &SigningKey,
) -> Result<SignedEnvelope, String> {
    let payload =
        serde_json::to_string(report).map_err(|e| format!("cannot serialize report: {e}"))?;
    let public_key = signing_key.verifying_key().to_bytes();
    Ok(SignedEnvelope {
        seal_signed_payload: SIGNED_PAYLOAD_VERSION.into(),
        kind: REPORT_VERSION.into(),
        algorithm: "Ed25519".into(),
        payload_sha256: sha256_hex(payload.as_bytes()),
        signature: hex::encode(signing_key.sign(payload.as_bytes()).to_bytes()),
        key_id: sha256_hex(&public_key),
        public_key: hex::encode(public_key),
        payload,
    })
}

pub fn verify_envelope(
    envelope: &SignedEnvelope,
    expected_public_key_hex: Option<&str>,
) -> Result<ReachabilityReport, String> {
    if envelope.seal_signed_payload != SIGNED_PAYLOAD_VERSION {
        return Err("unsupported signed payload envelope".into());
    }
    if envelope.kind != REPORT_VERSION || envelope.algorithm != "Ed25519" {
        return Err("signed envelope kind or algorithm mismatch".into());
    }
    if sha256_hex(envelope.payload.as_bytes()) != envelope.payload_sha256 {
        return Err("payload_sha256 mismatch".into());
    }
    let key_bytes: [u8; 32] = hex::decode(&envelope.public_key)
        .map_err(|e| format!("bad embedded public key hex: {e}"))?
        .try_into()
        .map_err(|_| "embedded public key must be 32 bytes".to_string())?;
    let key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| format!("bad embedded public key: {e}"))?;
    if let Some(expected) = expected_public_key_hex {
        let expected_bytes =
            hex::decode(expected).map_err(|e| format!("bad expected public key hex: {e}"))?;
        if expected_bytes != key_bytes {
            return Err("embedded public key does not match expected trust anchor".into());
        }
    }
    if sha256_hex(&key_bytes) != envelope.key_id {
        return Err("key_id mismatch".into());
    }
    if !verify_ed25519_signature(&key, envelope.payload.as_bytes(), &envelope.signature) {
        return Err("Ed25519 signature verification failed".into());
    }
    let report: ReachabilityReport = serde_json::from_str(&envelope.payload)
        .map_err(|e| format!("bad signed report payload: {e}"))?;
    if report.seal_reachability_report != REPORT_VERSION {
        return Err("signed report version mismatch".into());
    }
    if report.denominator.sound || report.denominator.coverage_percent.is_some() {
        return Err("v0 report must not assert a sound denominator or coverage percentage".into());
    }
    let counts = Summary {
        enumerated_path_records: report.paths.len(),
        brokered: report
            .paths
            .iter()
            .filter(|p| p.classification == Classification::Brokered)
            .count(),
        unbrokered: report
            .paths
            .iter()
            .filter(|p| p.classification == Classification::Unbrokered)
            .count(),
        unknown: report
            .paths
            .iter()
            .filter(|p| p.classification == Classification::Unknown)
            .count(),
    };
    if counts != report.summary {
        return Err("signed report summary does not match its path records".into());
    }
    Ok(report)
}

pub fn render_report(report: &ReachabilityReport, envelope: &SignedEnvelope) -> String {
    let mut out = String::new();
    out.push_str("SEAL UNBROKERED REACHABILITY REPORT v0\n");
    out.push_str(&format!("Deployment: {}\n", report.deployment));
    out.push_str(&format!("Agent: {}\n", report.agent));
    out.push_str(&format!(
        "This agent has {} enumerated path records.\n",
        report.summary.enumerated_path_records
    ));
    out.push_str(&format!(
        "TOTAL agent reachability: UNKNOWN — {}\n",
        report.denominator.statement
    ));
    out.push_str("Coverage: NOT COMPUTED (the denominator is not proven sound).\n");

    for classification in [
        Classification::Brokered,
        Classification::Unbrokered,
        Classification::Unknown,
    ] {
        let records: Vec<_> = report
            .paths
            .iter()
            .filter(|path| path.classification == classification)
            .collect();
        out.push_str(&format!(
            "\n{} ({}):\n",
            classification.as_str(),
            records.len()
        ));
        for path in records {
            out.push_str(&format!(
                "  - {} [{}]: {} — {}\n",
                path.id, path.category, path.mechanism, path.reason
            ));
        }
    }

    let conditional: Vec<_> = report
        .paths
        .iter()
        .filter(|path| path.conditional_on.is_some())
        .collect();
    out.push_str(&format!("\nCONDITIONAL ({}):\n", conditional.len()));
    for path in conditional {
        out.push_str(&format!(
            "  - {} is {} CONDITIONAL ON {}; seal cannot verify this condition.\n",
            path.id,
            path.classification.as_str(),
            path.conditional_on.as_deref().unwrap_or_default()
        ));
    }

    out.push_str("\nCATEGORY ENUMERATION:\n");
    for category in &report.category_enumeration {
        out.push_str(&format!(
            "  - {}: {} ({})\n",
            category.category,
            category.method,
            if category.complete {
                "declared complete; not independently proven"
            } else {
                "INCOMPLETE; named UNKNOWN emitted"
            }
        ));
    }

    out.push_str("\nv0 DOES NOT:\n");
    for limitation in &report.limitations {
        out.push_str(&format!("  - {limitation}\n"));
    }
    out.push_str("\nSIGNATURE:\n");
    out.push_str("  algorithm: Ed25519 over the exact UTF-8 payload bytes\n");
    out.push_str(&format!("  key_id: {}\n", envelope.key_id));
    out.push_str(&format!("  payload_sha256: {}\n", envelope.payload_sha256));
    out.push_str(&format!("  signature: {}\n", envelope.signature));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inventory(extra: &str) -> String {
        format!(
            r#"{{
  "seal_reachability_inventory":"seal-reachability-inventory/v0",
  "deployment":"test",
  "agent":"test-agent",
  "evidence_sources":[],
  "broker":{{
    "policy_path":"policy.json",
    "route":"seal stdio",
    "conditional_on":"the runtime holds no direct credential"
  }},
  "declared_paths":[
    {{"id":"transport","category":"transport","mechanism":"stdio","route":"THROUGH_SEAL","reason":"routed through seal"}}{extra}
  ],
  "category_enumeration":[
    {{"category":"tool_handles","method":"policy","complete":false,"unknown_id":"unknown-tools","unknown_reason":"child manifest unavailable"}},
    {{"category":"transport","method":"config","complete":true}},
    {{"category":"subprocess_shell","method":"declaration","complete":false,"unknown_id":"unknown-shell","unknown_reason":"runtime not inspected"}},
    {{"category":"outbound_network","method":"declaration","complete":false,"unknown_id":"unknown-net","unknown_reason":"namespace not inspected"}},
    {{"category":"filesystem","method":"declaration","complete":false,"unknown_id":"unknown-fs","unknown_reason":"mount namespace not inspected"}},
    {{"category":"scheduled_execution","method":"declaration","complete":false,"unknown_id":"unknown-scheduler","unknown_reason":"scheduler state not inspected"}},
    {{"category":"in_process_handles","method":"declaration","complete":false,"unknown_id":"unknown-handles","unknown_reason":"object graph not inspected"}}
  ],
  "limitations":["does not inspect live runtime"]
}}"#
        )
    }

    fn fixture(extra: &str) -> (PathBuf, Vec<u8>) {
        let dir = std::env::temp_dir().join(format!(
            "seal-reachability-test-{}-{}",
            std::process::id(),
            std::thread::current().name().unwrap_or("unnamed")
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            dir.join("policy.json"),
            r#"{"safety":{"tools":[{"name":"db.execute"},{"name":"approve","mode":"deny","match":{"type":"always"}}]}}"#,
        )
        .unwrap();
        (dir.join("inventory.json"), inventory(extra).into_bytes())
    }

    #[test]
    fn incomplete_categories_are_visible_unknown_denominator_members() {
        let (path, bytes) = fixture("");
        let report = build_report(&path, &bytes, 1).unwrap();
        assert!(!report.denominator.sound);
        assert_eq!(report.denominator.coverage_percent, None);
        assert_eq!(report.summary.unknown, 6);
        assert!(!report
            .paths
            .iter()
            .any(|path| path.id == "seal-tool:approve"));
        assert!(report
            .paths
            .iter()
            .any(|path| path.id == "unknown-handles"
                && path.classification == Classification::Unknown));
    }

    #[test]
    fn negative_control_direct_handle_is_unbrokered_not_omitted() {
        let extra = r#",{"id":"negative-control.echo","category":"tool_handles","mechanism":"direct echo handle","route":"DIRECT","reason":"bypasses seal"}"#;
        let (path, bytes) = fixture(extra);
        let report = build_report(&path, &bytes, 1).unwrap();
        assert!(report.paths.iter().any(|path| {
            path.id == "negative-control.echo" && path.classification == Classification::Unbrokered
        }));
    }

    #[test]
    fn exact_payload_signature_verifies_and_tamper_fails() {
        let (path, bytes) = fixture("");
        let report = build_report(&path, &bytes, 1).unwrap();
        let key = SigningKey::from_bytes(&[23; 32]);
        let mut envelope = sign_report(&report, &key).unwrap();
        let expected = hex::encode(key.verifying_key().to_bytes());
        verify_envelope(&envelope, Some(&expected)).unwrap();
        envelope.payload.push(' ');
        assert!(verify_envelope(&envelope, Some(&expected)).is_err());
    }
}
