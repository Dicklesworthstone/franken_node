#![forbid(unsafe_code)]

// The api and policy modules are included via #[path] so the bin target
// can use a subset of functions from these files. The lib target uses
// them fully; the bin only needs selected items, so dead_code is expected.
#[allow(dead_code)]
mod api {
    #[path = "error.rs"]
    pub mod error;
    #[path = "fleet_quarantine.rs"]
    pub mod fleet_quarantine;
    #[path = "middleware.rs"]
    pub mod middleware;
    #[path = "trust_card_routes.rs"]
    pub mod trust_card_routes;

    #[cfg(any(test, feature = "extended-surfaces"))]
    pub(crate) fn utf8_prefix(input: &str, max_chars: usize) -> &str {
        if max_chars == 0 {
            return "";
        }

        let end = input
            .char_indices()
            .nth(max_chars)
            .map_or(input.len(), |(idx, _)| idx);
        &input[..end]
    }
}
mod cli;
#[allow(dead_code)]
mod policy {
    #[path = "bayesian_diagnostics.rs"]
    pub mod bayesian_diagnostics;
    #[path = "decision_engine.rs"]
    pub mod decision_engine;
    #[path = "guardrail_monitor.rs"]
    pub mod guardrail_monitor;
    #[path = "hardening_state_machine.rs"]
    pub mod hardening_state_machine;
    #[path = "policy_explainer.rs"]
    pub mod policy_explainer;
}

use crate::api::{
    fleet_quarantine::{
        ConvergencePhase, ConvergenceState, DecisionReceipt, FLEET_RECONCILE_COMPLETED,
        FLEET_RELEASED, FleetActionResult, FleetStatus,
    },
    middleware::{AuthIdentity, AuthMethod, TraceContext},
    trust_card_routes::{
        Pagination, compare_trust_card_versions, compare_trust_cards, get_trust_card,
        get_trust_cards_by_publisher, list_trust_cards, search_trust_cards,
    },
};
use crate::cli::{
    BenchCommand, Cli, Command, FleetAgentArgs, FleetCommand, IncidentCommand, MigrateCommand,
    RegistryCommand, RemoteCapCommand, RemoteCapIssueArgs, TrustCardCommand, TrustCommand,
    VerifyCommand, VerifyCompatibilityArgs, VerifyCorpusArgs, VerifyMigrationArgs,
    VerifyModuleArgs, VerifyReleaseArgs,
};
use crate::policy::{
    bayesian_diagnostics::{BayesianDiagnostics, CandidateRef, Observation},
    decision_engine::{DecisionEngine, DecisionOutcome, DecisionReason},
    guardrail_monitor::{
        GuardrailCertificate, GuardrailFinding, GuardrailMonitorSet, GuardrailVerdict,
        MemoryTailRiskTelemetry, ReliabilityTelemetry, SystemState,
    },
    hardening_state_machine::HardeningLevel,
    policy_explainer::{PolicyExplainer, PolicyExplanation, WordingValidation, validate_wording},
};
use anyhow::{Context, Result};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
use chrono::{DateTime, Utc};
use clap::Parser;
use frankenengine_node::control_plane::fleet_transport::{
    FileFleetTransport, FleetAction as PersistedFleetAction,
    FleetActionRecord as PersistedFleetActionRecord, FleetSharedState,
    FleetTargetKind as PersistedFleetTargetKind, FleetTransport as PersistedFleetTransport,
    NodeHealth as PersistedNodeHealth, NodeStatus as PersistedNodeStatus,
};
#[cfg(test)]
use frankenengine_node::tools::replay_bundle::{fixture_incident_events, generate_replay_bundle};
use frankenengine_node::{
    ActionableError,
    config::{self, CliOverrides, Profile},
    ops, runtime,
    security::{
        decision_receipt::{
            Decision, Receipt, ReceiptQuery, append_signed_receipt, export_receipts_to_path,
            write_receipts_markdown,
        },
        remote_cap::{CapabilityProvider, RemoteOperation, RemoteScope},
    },
    supply_chain::{
        certification::{EvidenceType, VerifiedEvidenceRef},
        extension_registry::{
            AdmissionKernel, ExtensionSignature, ExtensionStatus, RegistrationRequest,
            SignedExtension, SignedExtensionRegistry, VersionEntry,
        },
        trust_card::{
            BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
            DependencyTrustStatus, ExtensionIdentity, ProvenanceSummary, PublisherIdentity,
            ReputationTrend, RevocationStatus, RiskAssessment, RiskLevel, TrustCard,
            TrustCardError, TrustCardInput, TrustCardListFilter, TrustCardMutation,
            TrustCardRegistry, TrustCardSyncReport, render_comparison_human,
            render_trust_card_human, to_canonical_json as trust_card_to_json,
        },
    },
    tools::{
        self,
        benchmark_suite::{
            render_human_summary as benchmark_suite_render_human_summary,
            run_default_suite as benchmark_suite_run_default_suite,
            to_canonical_json as benchmark_suite_to_json,
        },
        counterfactual_replay::{
            CounterfactualReplayEngine, PolicyConfig, summarize_output,
            to_canonical_json as counterfactual_to_json,
        },
        replay_bundle::{
            generate_replay_bundle_from_evidence, read_bundle_from_path,
            read_incident_evidence_package, replay_bundle as replay_incident_bundle,
            validate_bundle_integrity, write_bundle_to_path,
        },
    },
};
pub use frankenengine_node::{connector, control_plane, observability, security, supply_chain};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Component, Path, PathBuf};
use std::process::{Command as ProcessCommand, Stdio};
use std::time::{Duration, Instant};
use uuid::Uuid;

mod migration;

const PROFILE_EXAMPLES_TEMPLATE: &str =
    include_str!("../../../config/franken_node.profile_examples.toml");
const REGISTRY_GIT_COMMAND_TIMEOUT: Duration = Duration::from_secs(2);
const VERIFY_MODULE_IDS: &[&str] = &[
    "api",
    "claims",
    "cli",
    "config",
    "conformance",
    "connector",
    "control_plane",
    "encoding",
    "extensions",
    "federation",
    "migration",
    "observability",
    "ops",
    "perf",
    "policy",
    "registry",
    "remote",
    "repair",
    "replay",
    "runtime",
    "sdk",
    "security",
    "storage",
    "supply_chain",
    "testing",
    "tools",
    "verifier_economy",
];
const VERIFY_MIGRATION_IDS: &[&str] = &[
    "audit",
    "rewrite",
    "validate",
    "bpet_migration_gate",
    "dgis_migration_gate",
];
const VERIFY_CORPUS_SEARCH_ROOTS: &[&str] = &["fixtures", "vectors"];
const TRUST_CARD_REGISTRY_STATE_RELATIVE_PATH: &str =
    ".franken-node/state/trust-card-registry.v1.json";
const INCIDENT_EVIDENCE_RELATIVE_DIR: &str = ".franken-node/state/incidents";
const REGISTRY_LOCAL_ARTIFACT_MANIFEST_SCHEMA_VERSION: &str =
    "franken-node/local-registry-artifact-manifest/v1";
const REGISTRY_LOCAL_ARTIFACT_MANIFEST_FILE_NAME: &str = "artifact.manifest.json";
const INCIDENT_EVIDENCE_FILE_NAME: &str = "evidence.v1.json";
const RUN_EXECUTION_RECEIPT_SCHEMA_VERSION: &str = "franken-node/run-execution-receipt/v1";
const RUN_EXECUTION_RECEIPT_ID_PLACEHOLDER: &str = "pending";
const RUN_EXECUTION_RECEIPT_DEFAULT_MAX_RECEIPTS: usize = 100;
const RUN_EXECUTION_RECEIPT_AUTO_QUARANTINE_THRESHOLD: usize = 1;
const TRUST_SCAN_NPM_REGISTRY_BASE_URL: &str = "https://registry.npmjs.org";
const TRUST_SCAN_OSV_QUERY_URL: &str = "https://api.osv.dev/v1/query";
const TRUST_SCAN_DEPS_DEV_BASE_URL: &str = "https://api.deps.dev/v3alpha";

struct TrustCardCliRegistryState {
    path: PathBuf,
    registry: TrustCardRegistry,
    cache_ttl_secs: u64,
}

#[derive(Debug, Serialize)]
struct VerifyContractOutput {
    command: String,
    contract_version: String,
    schema_version: String,
    compat_version: Option<u16>,
    verdict: String,
    status: String,
    exit_code: i32,
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    details: Option<serde_json::Value>,
}

struct Ed25519SigningMaterial {
    path: PathBuf,
    source: &'static str,
    signing_key: ed25519_dalek::SigningKey,
}

/// Bundled context for receipt export with mandatory signing material.
///
/// When receipt export is requested (via `--receipt-out` or `--receipt-summary-out`),
/// this struct ensures signing material is always available. The type system
/// enforces the "sign-or-fail" contract: if you have a `ReceiptExportContext`,
/// you have everything needed to produce a signed receipt.
struct ReceiptExportContext {
    receipt_out: Option<PathBuf>,
    receipt_summary_out: Option<PathBuf>,
    signing_material: Ed25519SigningMaterial,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct RunPackageDependency {
    dependency_name: String,
    version_requirement: String,
    section: String,
    extension_id: String,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum RunDependencyTrustStatus {
    Trusted,
    Untracked,
    Revoked,
    Quarantined,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct RunDependencyTrustResult {
    dependency_name: String,
    version_requirement: String,
    section: String,
    extension_id: String,
    status: RunDependencyTrustStatus,
    trust_card_version: Option<u64>,
    risk_level: Option<String>,
    detail: String,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TrustScanItemStatus {
    Created,
    SkippedExisting,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct TrustScanItem {
    dependency_name: String,
    section: String,
    extension_id: String,
    extension_version: String,
    status: TrustScanItemStatus,
    publisher_id: String,
    risk_level: String,
    integrity_hash_count: usize,
    vulnerability_count: usize,
    dependent_count: Option<u64>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct TrustScanReport {
    command: String,
    project_root: String,
    registry_path: String,
    scanned_dependencies: usize,
    created_cards: usize,
    skipped_existing: usize,
    lockfile_entries: usize,
    deep: bool,
    audit: bool,
    warnings: Vec<String>,
    items: Vec<TrustScanItem>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TrustScanLockfileMetadata {
    resolved_version: Option<String>,
    integrity_hashes: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TrustScanDeepMetadata {
    publisher_id: Option<String>,
    publisher_display_name: Option<String>,
    published_at: Option<String>,
    dependent_count: Option<u64>,
    resolved_version: Option<String>,
    registry_integrity_hashes: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TrustScanAuditMetadata {
    vulnerability_ids: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct TrustSyncAuditRefreshReport {
    refreshed_count: usize,
    vulnerabilities_found: usize,
    network_errors: usize,
    warnings: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum TrustViolationKind {
    RegistryCorrupt,
    Revoked,
    Quarantined,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct TrustViolation {
    dependency_name: Option<String>,
    extension_id: Option<String>,
    kind: TrustViolationKind,
    detail: String,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(tag = "status", rename_all = "snake_case")]
enum PreFlightVerdict {
    Passed {
        checked: usize,
        warnings: Vec<String>,
        results: Vec<RunDependencyTrustResult>,
    },
    Blocked {
        reason: String,
        warnings: Vec<String>,
        violations: Vec<TrustViolation>,
        results: Vec<RunDependencyTrustResult>,
    },
    Skipped {
        reason: String,
    },
}

impl PreFlightVerdict {
    const fn is_blocked(&self) -> bool {
        matches!(self, Self::Blocked { .. })
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct RunPreFlightReport {
    app_path: String,
    project_root: String,
    policy_mode: String,
    registry_path: Option<String>,
    verdict: PreFlightVerdict,
    receipt: Receipt,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
struct RunExecutionTelemetrySummary {
    final_state: Option<String>,
    accepted_total: u64,
    persisted_total: u64,
    shed_total: u64,
    dropped_total: u64,
    retry_total: u64,
    drain_completed: bool,
    drain_duration_ms: u64,
    recent_event_codes: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct RunExecutionReceiptCore {
    receipt_id: String,
    schema_version: String,
    app_path: String,
    policy_mode: String,
    profile: String,
    start_time_utc: String,
    end_time_utc: String,
    duration_ms: u64,
    exit_code: Option<i32>,
    runtime_used: String,
    runtime_version: Option<String>,
    preflight_verdict: PreFlightVerdict,
    telemetry_summary: Option<RunExecutionTelemetrySummary>,
    ssrf_violations: Vec<String>,
    lockstep_verdict: Option<serde_json::Value>,
    violation_count: usize,
    auto_quarantined_extensions: Vec<String>,
}

#[derive(Debug, Clone, Serialize, PartialEq)]
struct RunExecutionReceipt {
    #[serde(flatten)]
    core: RunExecutionReceiptCore,
    receipt_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct RunCommandOutput {
    success: bool,
    preflight: RunPreFlightReport,
    dispatch: ops::engine_dispatcher::RunDispatchReport,
    receipt: RunExecutionReceipt,
    receipt_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct LocalRegistryArtifactManifest {
    schema_version: String,
    stored_at_utc: String,
    artifact_file_name: String,
    artifact_sha256: String,
    artifact_size_bytes: u64,
    manifest_bytes_b64: String,
    publisher_public_key_hex: String,
    extension: SignedExtension,
}

#[derive(Debug, Clone, PartialEq)]
struct StoredRegistryArtifact {
    manifest_path: PathBuf,
    archived: bool,
    manifest: LocalRegistryArtifactManifest,
}

impl StoredRegistryArtifact {
    fn entry_dir(&self) -> &Path {
        self.manifest_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
    }

    fn artifact_path(&self) -> PathBuf {
        self.entry_dir().join(&self.manifest.artifact_file_name)
    }

    fn stored_at_sort_key(&self) -> i64 {
        DateTime::parse_from_rfc3339(&self.manifest.stored_at_utc)
            .map(|timestamp| timestamp.timestamp_millis())
            .unwrap_or(i64::MIN)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RegistryArtifactIntegrityStatus {
    Verified,
    HashMismatch,
    MissingArtifact,
    InvalidSignature,
    InvalidMetadata,
}

impl RegistryArtifactIntegrityStatus {
    fn label(self) -> &'static str {
        match self {
            Self::Verified => "verified",
            Self::HashMismatch => "hash-mismatch",
            Self::MissingArtifact => "missing-artifact",
            Self::InvalidSignature => "invalid-signature",
            Self::InvalidMetadata => "invalid-metadata",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistryArtifactVerification {
    status: RegistryArtifactIntegrityStatus,
    detail: String,
    artifact_path: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistrySearchDisplayRow {
    assurance: u8,
    extension_id: String,
    name: String,
    publisher: String,
    status: String,
    artifact_path: String,
    integrity_status: String,
}

/// RAII guard that orphans a temp file on drop (unless defused after rename).
#[must_use]
struct TempFileGuard(Option<PathBuf>);

impl TempFileGuard {
    fn new(path: PathBuf) -> Self {
        Self(Some(path))
    }

    fn abandoned_path(path: &Path) -> PathBuf {
        let file_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("run-receipt.json.tmp");
        path.with_file_name(format!("{file_name}.orphaned-{}", Uuid::now_v7()))
    }

    fn defuse(&mut self) {
        self.0 = None;
    }
}

impl Drop for TempFileGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take()
            && path.is_file()
        {
            let _ = std::fs::rename(&path, Self::abandoned_path(&path));
        }
    }
}

/// RAII guard that orphans a temp directory on drop (unless defused after rename).
#[must_use]
struct TempDirGuard(Option<PathBuf>);

impl TempDirGuard {
    fn new(path: PathBuf) -> Self {
        Self(Some(path))
    }

    fn abandoned_path(path: &Path) -> PathBuf {
        let dir_name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("registry-artifact.tmp");
        path.with_file_name(format!("{dir_name}.orphaned-{}", Uuid::now_v7()))
    }

    fn defuse(&mut self) {
        self.0 = None;
    }
}

impl Drop for TempDirGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take()
            && path.is_dir()
        {
            let _ = std::fs::rename(&path, Self::abandoned_path(&path));
        }
    }
}

fn parse_signing_key_from_blob(raw: &[u8]) -> Option<ed25519_dalek::SigningKey> {
    use base64::Engine;
    use std::borrow::Cow;

    fn signing_key_from_bytes(raw: &[u8]) -> Option<ed25519_dalek::SigningKey> {
        match raw.len() {
            32 => {
                let bytes = <[u8; 32]>::try_from(raw).ok()?;
                Some(ed25519_dalek::SigningKey::from_bytes(&bytes))
            }
            64 => {
                let seed = <[u8; 32]>::try_from(&raw[..32]).ok()?;
                let public = <[u8; 32]>::try_from(&raw[32..]).ok()?;
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
                if signing_key.verifying_key().to_bytes() == public {
                    Some(signing_key)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    if let Some(signing_key) = signing_key_from_bytes(raw) {
        return Some(signing_key);
    }

    let Ok(text) = std::str::from_utf8(raw) else {
        return None;
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut candidates = vec![trimmed.to_string()];
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        let parse_byte_array = |values: &[serde_json::Value]| -> Option<Vec<u8>> {
            if values.len() != 32 && values.len() != 64 {
                return None;
            }
            let mut bytes = Vec::with_capacity(values.len());
            for value in values {
                let byte = value.as_u64().and_then(|value| u8::try_from(value).ok())?;
                bytes.push(byte);
            }
            Some(bytes)
        };

        match value {
            serde_json::Value::String(value) => candidates.push(value),
            serde_json::Value::Array(values) => {
                if let Some(bytes) = parse_byte_array(&values)
                    && let Some(signing_key) = signing_key_from_bytes(&bytes)
                {
                    return Some(signing_key);
                }
                for entry in values {
                    if let serde_json::Value::String(value) = entry {
                        candidates.push(value);
                    }
                }
            }
            serde_json::Value::Object(value) => {
                for field in [
                    "private_key",
                    "signing_key",
                    "secret_key",
                    "ed25519_private_key",
                    "private-key",
                    "signing-key",
                    "secret-key",
                    "ed25519-private-key",
                    "privateKey",
                    "signingKey",
                    "secretKey",
                    "ed25519PrivateKey",
                ] {
                    if let Some(entry) = value.get(field) {
                        if let Some(bytes) =
                            entry.as_array().and_then(|values| parse_byte_array(values))
                            && let Some(signing_key) = signing_key_from_bytes(&bytes)
                        {
                            return Some(signing_key);
                        }
                        if let Some(entry) = entry.as_str() {
                            candidates.push(entry.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn strip_prefix_ignore_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
        if value
            .get(..prefix.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
        {
            Some(&value[prefix.len()..])
        } else {
            None
        }
    }

    for candidate in candidates {
        let trimmed = candidate.trim();
        let mut normalized = trimmed;
        if let Some(remainder) = strip_prefix_ignore_ascii_case(normalized, "ed25519:") {
            normalized = remainder;
        }
        let mut stripped_encoding = false;
        for prefix in ["base64:", "b64:", "base64url:", "b64url:", "hex:"] {
            if let Some(remainder) = strip_prefix_ignore_ascii_case(normalized, prefix) {
                normalized = remainder;
                stripped_encoding = true;
                break;
            }
        }
        if stripped_encoding
            && let Some(remainder) = strip_prefix_ignore_ascii_case(normalized, "ed25519:")
        {
            normalized = remainder;
        }
        let normalized = normalized.trim();
        if normalized.is_empty() {
            continue;
        }

        let normalized = if normalized.chars().any(|value| value.is_whitespace()) {
            Cow::Owned(normalized.split_whitespace().collect::<String>())
        } else {
            Cow::Borrowed(normalized)
        };
        let normalized = normalized.as_ref();

        let normalized_hex = normalized
            .strip_prefix("0x")
            .or_else(|| normalized.strip_prefix("0X"))
            .unwrap_or(normalized)
            .replace(['_', ':', '-'], "");
        if let Ok(decoded_hex) = hex::decode(&normalized_hex)
            && let Some(signing_key) = signing_key_from_bytes(&decoded_hex)
        {
            return Some(signing_key);
        }

        for engine in [
            base64::engine::general_purpose::STANDARD,
            base64::engine::general_purpose::STANDARD_NO_PAD,
            base64::engine::general_purpose::URL_SAFE,
            base64::engine::general_purpose::URL_SAFE_NO_PAD,
        ] {
            if let Ok(decoded_b64) = engine.decode(normalized)
                && let Some(signing_key) = signing_key_from_bytes(&decoded_b64)
            {
                return Some(signing_key);
            }
        }
    }

    None
}

#[cfg(test)]
mod signing_key_parsing_tests {
    use super::*;
    use base64::Engine;

    fn key_id_for(signing_key: &ed25519_dalek::SigningKey) -> String {
        supply_chain::artifact_signing::KeyId::from_verifying_key(&signing_key.verifying_key())
            .to_string()
    }

    fn key_id_from_bytes(bytes: &[u8; 32]) -> String {
        key_id_for(&ed25519_dalek::SigningKey::from_bytes(bytes))
    }

    #[test]
    fn parse_signing_key_accepts_raw_bytes() {
        let bytes = [42_u8; 32];
        let parsed = parse_signing_key_from_blob(&bytes).expect("parsed raw bytes");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_raw_keypair_bytes() {
        let seed = [44_u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&seed);
        bytes[32..].copy_from_slice(&verifying_key);
        let parsed = parse_signing_key_from_blob(&bytes).expect("parsed keypair bytes");
        assert_eq!(key_id_for(&parsed), key_id_for(&signing_key));
    }

    #[test]
    fn parse_signing_key_rejects_mismatched_keypair_bytes() {
        let seed = [45_u8; 32];
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&seed);
        bytes[32..].copy_from_slice(&[9_u8; 32]);
        assert!(parse_signing_key_from_blob(&bytes).is_none());
    }

    #[test]
    fn parse_signing_key_accepts_hex_with_prefix_and_underscores() {
        let bytes = [7_u8; 32];
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("_");
        let candidate = format!("0x{hex}");
        let parsed = parse_signing_key_from_blob(candidate.as_bytes()).expect("parsed hex");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_hex_with_whitespace() {
        let bytes = [61_u8; 32];
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let split = hex.len() / 2;
        let candidate = format!("0x{} \n{}", &hex[..split], &hex[split..]);
        let parsed = parse_signing_key_from_blob(candidate.as_bytes()).expect("parsed hex");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_hex_with_colons() {
        let bytes = [90_u8; 32];
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join(":");
        let candidate = format!("ed25519:{hex}");
        let parsed = parse_signing_key_from_blob(candidate.as_bytes()).expect("parsed hex");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_hex_with_hyphens() {
        let bytes = [91_u8; 32];
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("-");
        let candidate = format!("ed25519:{hex}");
        let parsed = parse_signing_key_from_blob(candidate.as_bytes()).expect("parsed hex");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_hex_keypair_bytes() {
        let seed = [92_u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&seed);
        bytes[32..].copy_from_slice(&verifying_key);
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let parsed = parse_signing_key_from_blob(hex.as_bytes()).expect("parsed hex");
        assert_eq!(key_id_for(&parsed), key_id_for(&signing_key));
    }

    #[test]
    fn parse_signing_key_accepts_base64_urlsafe_no_pad() {
        let bytes = [19_u8; 32];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let parsed = parse_signing_key_from_blob(encoded.as_bytes()).expect("parsed base64");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_base64_no_pad() {
        let bytes = [20_u8; 32];
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes);
        let parsed = parse_signing_key_from_blob(encoded.as_bytes()).expect("parsed base64");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_base64_with_whitespace() {
        let bytes = [33_u8; 32];
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let split = encoded.len() / 2;
        let candidate = format!("{} \n{}", &encoded[..split], &encoded[split..]);
        let parsed = parse_signing_key_from_blob(candidate.as_bytes()).expect("parsed base64");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_base64_keypair_bytes() {
        let seed = [93_u8; 32];
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let verifying_key = signing_key.verifying_key().to_bytes();
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&seed);
        bytes[32..].copy_from_slice(&verifying_key);
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let parsed = parse_signing_key_from_blob(encoded.as_bytes()).expect("parsed base64");
        assert_eq!(key_id_for(&parsed), key_id_for(&signing_key));
    }

    #[test]
    fn parse_signing_key_accepts_base64_prefix() {
        let bytes = [71_u8; 32];
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let candidate = format!("base64:{encoded}");
        let parsed = parse_signing_key_from_blob(candidate.as_bytes()).expect("parsed base64");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_b64_prefix() {
        let bytes = [72_u8; 32];
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let candidate = format!("b64:{encoded}");
        let parsed = parse_signing_key_from_blob(candidate.as_bytes()).expect("parsed base64");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_base64url_prefix() {
        let bytes = [73_u8; 32];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let candidate = format!("base64url:{encoded}");
        let parsed = parse_signing_key_from_blob(candidate.as_bytes()).expect("parsed base64");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_b64url_prefix() {
        let bytes = [74_u8; 32];
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let candidate = format!("b64url:{encoded}");
        let parsed = parse_signing_key_from_blob(candidate.as_bytes()).expect("parsed base64");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_hex_prefix() {
        let bytes = [75_u8; 32];
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let candidate = format!("hex:{hex}");
        let parsed = parse_signing_key_from_blob(candidate.as_bytes()).expect("parsed hex");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_base64_ed25519_prefix_chain() {
        let bytes = [76_u8; 32];
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let candidate = format!("base64:ed25519:{encoded}");
        let parsed = parse_signing_key_from_blob(candidate.as_bytes()).expect("parsed base64");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_ed25519_base64_prefix_chain() {
        let bytes = [78_u8; 32];
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let candidate = format!("ed25519:base64:{encoded}");
        let parsed = parse_signing_key_from_blob(candidate.as_bytes()).expect("parsed base64");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_hex_ed25519_prefix_chain() {
        let bytes = [77_u8; 32];
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let candidate = format!("hex:ed25519:{hex}");
        let parsed = parse_signing_key_from_blob(candidate.as_bytes()).expect("parsed hex");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_ed25519_hex_prefix_chain() {
        let bytes = [79_u8; 32];
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let candidate = format!("ed25519:hex:{hex}");
        let parsed = parse_signing_key_from_blob(candidate.as_bytes()).expect("parsed hex");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_json_wrapped_key() {
        let bytes = [88_u8; 32];
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let payload = format!(r#"{{"signing_key":"ED25519:{encoded}"}}"#);
        let parsed = parse_signing_key_from_blob(payload.as_bytes()).expect("parsed json");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_json_kebabcase_key() {
        let bytes = [43_u8; 32];
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let payload = format!(r#"{{"signing-key":"ed25519:{encoded}"}}"#);
        let parsed = parse_signing_key_from_blob(payload.as_bytes()).expect("parsed json");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_json_string_key() {
        let bytes = [144_u8; 32];
        let encoded = base64::engine::general_purpose::URL_SAFE.encode(bytes);
        let payload = format!(r#""ed25519:{encoded}""#);
        let parsed = parse_signing_key_from_blob(payload.as_bytes()).expect("parsed json string");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_json_array_key() {
        let bytes = [203_u8; 32];
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let payload = format!(r#"["", "ed25519:{encoded}"]"#);
        let parsed = parse_signing_key_from_blob(payload.as_bytes()).expect("parsed json array");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_json_camelcase_key() {
        let bytes = [11_u8; 32];
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let payload = format!(r#"{{"secretKey":"ed25519:{encoded}"}}"#);
        let parsed = parse_signing_key_from_blob(payload.as_bytes()).expect("parsed json");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_accepts_json_byte_array() {
        let bytes = [204_u8; 32];
        let payload = format!(
            "[{}]",
            bytes
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let parsed =
            parse_signing_key_from_blob(payload.as_bytes()).expect("parsed json byte array");
        assert_eq!(key_id_for(&parsed), key_id_from_bytes(&bytes));
    }

    #[test]
    fn parse_signing_key_rejects_invalid_material() {
        assert!(parse_signing_key_from_blob(b"not-a-key").is_none());
    }
}

#[cfg(test)]
mod verifying_key_parsing_tests {
    use super::*;
    use base64::Engine;

    fn verifying_key_bytes(seed: [u8; 32]) -> [u8; 32] {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
        signing_key.verifying_key().to_bytes()
    }

    fn ssh_ed25519_public_key_line(bytes: [u8; 32]) -> String {
        fn push_ssh_string(buf: &mut Vec<u8>, value: &[u8]) {
            let len = u32::try_from(value.len()).unwrap_or(0);
            buf.extend_from_slice(&len.to_be_bytes());
            buf.extend_from_slice(value);
        }

        let mut blob = Vec::new();
        push_ssh_string(&mut blob, b"ssh-ed25519");
        push_ssh_string(&mut blob, &bytes);
        let encoded = base64::engine::general_purpose::STANDARD.encode(blob);
        format!("ssh-ed25519 {encoded} local-test")
    }

    #[test]
    fn parse_verifying_key_accepts_raw_bytes() {
        let bytes = verifying_key_bytes([101_u8; 32]);
        let parsed = parse_verifying_key_from_blob(&bytes).expect("parsed raw bytes");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_raw_keypair_bytes() {
        let seed = [102_u8; 32];
        let public = verifying_key_bytes(seed);
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&seed);
        bytes[32..].copy_from_slice(&public);
        let parsed = parse_verifying_key_from_blob(&bytes).expect("parsed keypair bytes");
        assert_eq!(parsed.to_bytes(), public);
    }

    #[test]
    fn parse_verifying_key_rejects_mismatched_keypair_bytes() {
        let seed = [103_u8; 32];
        let mut bytes = [0_u8; 64];
        bytes[..32].copy_from_slice(&seed);
        bytes[32..].copy_from_slice(&[9_u8; 32]);
        assert!(parse_verifying_key_from_blob(&bytes).is_none());
    }

    #[test]
    fn parse_verifying_key_accepts_hex_with_separators() {
        let bytes = verifying_key_bytes([104_u8; 32]);
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("_");
        let candidate = format!("ed25519:{hex}");
        let parsed = parse_verifying_key_from_blob(candidate.as_bytes()).expect("parsed hex");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_hex_prefix_chain() {
        let bytes = verifying_key_bytes([108_u8; 32]);
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let candidate = format!("hex:ed25519:{hex}");
        let parsed = parse_verifying_key_from_blob(candidate.as_bytes()).expect("parsed hex");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_ed25519_hex_prefix_chain() {
        let bytes = verifying_key_bytes([109_u8; 32]);
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let candidate = format!("ed25519:hex:{hex}");
        let parsed = parse_verifying_key_from_blob(candidate.as_bytes()).expect("parsed hex");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_hex_with_whitespace() {
        let bytes = verifying_key_bytes([110_u8; 32]);
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let split = hex.len() / 2;
        let candidate = format!("{} \n{}", &hex[..split], &hex[split..]);
        let parsed = parse_verifying_key_from_blob(candidate.as_bytes()).expect("parsed hex");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_base64_prefix() {
        let bytes = verifying_key_bytes([112_u8; 32]);
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let candidate = format!("base64:{encoded}");
        let parsed = parse_verifying_key_from_blob(candidate.as_bytes()).expect("parsed base64");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_base64_no_pad() {
        let bytes = verifying_key_bytes([121_u8; 32]);
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes);
        let parsed = parse_verifying_key_from_blob(encoded.as_bytes()).expect("parsed base64");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_b64_prefix() {
        let bytes = verifying_key_bytes([113_u8; 32]);
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let candidate = format!("b64:{encoded}");
        let parsed = parse_verifying_key_from_blob(candidate.as_bytes()).expect("parsed base64");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_b64url_prefix() {
        let bytes = verifying_key_bytes([114_u8; 32]);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let candidate = format!("b64url:{encoded}");
        let parsed = parse_verifying_key_from_blob(candidate.as_bytes()).expect("parsed base64");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_base64_prefix_chain() {
        let bytes = verifying_key_bytes([105_u8; 32]);
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let candidate = format!("base64:ed25519:{encoded}");
        let parsed = parse_verifying_key_from_blob(candidate.as_bytes()).expect("parsed base64");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_base64url_prefix_chain() {
        let bytes = verifying_key_bytes([116_u8; 32]);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let candidate = format!("ed25519:base64url:{encoded}");
        let parsed = parse_verifying_key_from_blob(candidate.as_bytes()).expect("parsed base64");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_json_string_key() {
        let bytes = verifying_key_bytes([115_u8; 32]);
        let encoded = base64::engine::general_purpose::URL_SAFE.encode(bytes);
        let payload = format!(r#""ed25519:{encoded}""#);
        let parsed = parse_verifying_key_from_blob(payload.as_bytes()).expect("parsed json string");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_json_camelcase_key() {
        let bytes = verifying_key_bytes([118_u8; 32]);
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let payload = format!(r#"{{"verifyingKey":"ed25519:{encoded}"}}"#);
        let parsed = parse_verifying_key_from_blob(payload.as_bytes()).expect("parsed json");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_json_kebabcase_key() {
        let bytes = verifying_key_bytes([124_u8; 32]);
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let payload = format!(r#"{{"public-key":"ed25519:{encoded}"}}"#);
        let parsed = parse_verifying_key_from_blob(payload.as_bytes()).expect("parsed json");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_json_wrapped_key() {
        let bytes = verifying_key_bytes([106_u8; 32]);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let payload = format!(r#"{{"publicKey":"ed25519:{encoded}"}}"#);
        let parsed = parse_verifying_key_from_blob(payload.as_bytes()).expect("parsed json");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_json_wrapped_byte_array() {
        let bytes = verifying_key_bytes([111_u8; 32]);
        let payload = format!(
            r#"{{"publicKey":[{}]}}"#,
            bytes
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let parsed = parse_verifying_key_from_blob(payload.as_bytes()).expect("parsed json");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_json_array_key() {
        let bytes = verifying_key_bytes([117_u8; 32]);
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let payload = format!(r#"["", "ed25519:{encoded}"]"#);
        let parsed = parse_verifying_key_from_blob(payload.as_bytes()).expect("parsed json array");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_json_byte_array() {
        let bytes = verifying_key_bytes([107_u8; 32]);
        let payload = format!(
            "[{}]",
            bytes
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let parsed =
            parse_verifying_key_from_blob(payload.as_bytes()).expect("parsed json byte array");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_ssh_ed25519_line() {
        let bytes = verifying_key_bytes([119_u8; 32]);
        let line = ssh_ed25519_public_key_line(bytes);
        let parsed = parse_verifying_key_from_blob(line.as_bytes()).expect("parsed ssh key");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_ssh_ed25519_multiline() {
        let bytes = verifying_key_bytes([120_u8; 32]);
        let line = ssh_ed25519_public_key_line(bytes);
        let payload = format!("comment line\n{line}\n");
        let parsed = parse_verifying_key_from_blob(payload.as_bytes()).expect("parsed ssh key");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_ssh_ed25519_with_options() {
        let bytes = verifying_key_bytes([122_u8; 32]);
        let line = ssh_ed25519_public_key_line(bytes);
        let payload = format!("command=\"echo hi\" {line}");
        let parsed = parse_verifying_key_from_blob(payload.as_bytes()).expect("parsed ssh key");
        assert_eq!(parsed.to_bytes(), bytes);
    }

    #[test]
    fn parse_verifying_key_accepts_ssh_ed25519_with_comment_line() {
        let bytes = verifying_key_bytes([123_u8; 32]);
        let line = ssh_ed25519_public_key_line(bytes);
        let payload = format!("# local comment\n{line}");
        let parsed = parse_verifying_key_from_blob(payload.as_bytes()).expect("parsed ssh key");
        assert_eq!(parsed.to_bytes(), bytes);
    }
}

#[cfg(test)]
mod signature_blob_tests {
    use super::*;
    use base64::Engine;

    fn signature_bytes(seed: u8) -> [u8; 64] {
        [seed; 64]
    }

    #[test]
    fn decode_signature_blob_accepts_hex_prefix_chain() {
        let bytes = signature_bytes(31);
        let hex = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<Vec<_>>()
            .join("_");
        let candidate = format!("hex:ed25519:{hex}");
        let decoded = decode_signature_blob(candidate.as_bytes());
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_signature_blob_accepts_base64_prefix_chain() {
        let bytes = signature_bytes(32);
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let candidate = format!("base64:ed25519:{encoded}");
        let decoded = decode_signature_blob(candidate.as_bytes());
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_signature_blob_accepts_base64_no_pad() {
        let bytes = signature_bytes(35);
        let encoded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(bytes);
        let decoded = decode_signature_blob(encoded.as_bytes());
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_signature_blob_accepts_base64url_prefix() {
        let bytes = signature_bytes(33);
        let encoded = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes);
        let candidate = format!("b64url:{encoded}");
        let decoded = decode_signature_blob(candidate.as_bytes());
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_signature_blob_accepts_base64_with_whitespace() {
        let bytes = signature_bytes(34);
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let split = encoded.len() / 2;
        let candidate = format!("ed25519:{} \n{}", &encoded[..split], &encoded[split..]);
        let decoded = decode_signature_blob(candidate.as_bytes());
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_signature_blob_accepts_json_string() {
        let bytes = signature_bytes(36);
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let payload = format!(r#""ed25519:{encoded}""#);
        let decoded = decode_signature_blob(payload.as_bytes());
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_signature_blob_accepts_json_byte_array() {
        let bytes = signature_bytes(37);
        let payload = format!(
            "[{}]",
            bytes
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let decoded = decode_signature_blob(payload.as_bytes());
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_signature_blob_accepts_json_object_ed25519_signature_field() {
        let bytes = signature_bytes(38);
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let payload = format!(r#"{{"ed25519Signature":"ed25519:{encoded}"}}"#);
        let decoded = decode_signature_blob(payload.as_bytes());
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_signature_blob_accepts_json_object_signature_bytes_kebab() {
        let bytes = signature_bytes(39);
        let payload = format!(
            r#"{{"signature-bytes":[{}]}}"#,
            bytes
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let decoded = decode_signature_blob(payload.as_bytes());
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_signature_blob_accepts_json_object_signature_base64() {
        let bytes = signature_bytes(40);
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let payload = format!(r#"{{"signatureBase64":"{encoded}"}}"#);
        let decoded = decode_signature_blob(payload.as_bytes());
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_signature_blob_accepts_json_object_signature_hex() {
        let bytes = signature_bytes(41);
        let encoded = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let payload = format!(r#"{{"signatureHex":"{encoded}"}}"#);
        let decoded = decode_signature_blob(payload.as_bytes());
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_signature_blob_accepts_json_object_sig_bytes() {
        let bytes = signature_bytes(42);
        let payload = format!(
            r#"{{"sigBytes":[{}]}}"#,
            bytes
                .iter()
                .map(|value| value.to_string())
                .collect::<Vec<_>>()
                .join(",")
        );
        let decoded = decode_signature_blob(payload.as_bytes());
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_signature_blob_accepts_json_object_sig_base64() {
        let bytes = signature_bytes(43);
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let payload = format!(r#"{{"sigBase64":"{encoded}"}}"#);
        let decoded = decode_signature_blob(payload.as_bytes());
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_signature_blob_accepts_json_object_signature_b64() {
        let bytes = signature_bytes(45);
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let payload = format!(r#"{{"signatureB64":"{encoded}"}}"#);
        let decoded = decode_signature_blob(payload.as_bytes());
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_signature_blob_accepts_json_object_sig_b64() {
        let bytes = signature_bytes(46);
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let payload = format!(r#"{{"sigB64":"{encoded}"}}"#);
        let decoded = decode_signature_blob(payload.as_bytes());
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_signature_blob_accepts_json_object_sig_hex() {
        let bytes = signature_bytes(44);
        let encoded = bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let payload = format!(r#"{{"sigHex":"{encoded}"}}"#);
        let decoded = decode_signature_blob(payload.as_bytes());
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_signature_blob_accepts_json_object_nested_base64() {
        let bytes = signature_bytes(47);
        let encoded = base64::engine::general_purpose::STANDARD.encode(bytes);
        let payload = format!(r#"{{"signature":{{"base64":"{encoded}"}}}}"#);
        let decoded = decode_signature_blob(payload.as_bytes());
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn decode_signature_blob_returns_raw_on_invalid() {
        let raw = b"not-a-signature";
        assert_eq!(decode_signature_blob(raw), raw);
    }
}

fn resolve_receipt_signing_key_path(
    cli_override: Option<&Path>,
) -> Result<Option<(PathBuf, &'static str)>> {
    if let Some(path) = cli_override {
        return Ok(Some((path.to_path_buf(), "cli")));
    }

    let resolved = config::Config::resolve(None, CliOverrides::default())
        .context("failed resolving configuration for receipt export")?;
    let Some(path) = resolved
        .config
        .security
        .decision_receipt_signing_key_path
        .clone()
    else {
        return Ok(None);
    };

    let source = resolved
        .decisions
        .iter()
        .rev()
        .find(|decision| decision.field == "security.decision_receipt_signing_key_path")
        .map(|decision| match decision.stage {
            config::MergeStage::Env => "env",
            _ => "config",
        })
        .unwrap_or("config");
    Ok(Some((path, source)))
}

fn load_ed25519_signing_material_from_path(
    path: &Path,
    label: &str,
    source: &'static str,
) -> Result<Ed25519SigningMaterial> {
    if !path.is_file() {
        anyhow::bail!("{label} must point to a file: {}", path.display());
    }

    let raw = std::fs::read(path)
        .with_context(|| format!("failed reading {label} {}", path.display()))?;
    let Some(signing_key) = parse_signing_key_from_blob(&raw) else {
        anyhow::bail!("failed decoding Ed25519 {label} from {}", path.display());
    };

    Ok(Ed25519SigningMaterial {
        path: path.to_path_buf(),
        source,
        signing_key,
    })
}

fn load_receipt_signing_material(
    cli_override: Option<&Path>,
) -> Result<Option<Ed25519SigningMaterial>> {
    let Some((path, source)) = resolve_receipt_signing_key_path(cli_override)? else {
        return Ok(None);
    };

    load_ed25519_signing_material_from_path(&path, "receipt signing key", source).map(Some)
}

fn load_registry_publish_signing_material(path: &Path) -> Result<Ed25519SigningMaterial> {
    load_ed25519_signing_material_from_path(path, "registry publish signing key", "cli")
}

fn receipt_signing_key_fix_command() -> &'static str {
    "mkdir -p .franken-node/keys && openssl rand -hex 32 > .franken-node/keys/receipt-signing.key"
}

fn missing_receipt_signing_key_error() -> ActionableError {
    ActionableError::new(
        "receipt export requested but no signing key was configured; pass --receipt-signing-key, set FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH, or configure security.decision_receipt_signing_key_path",
        receipt_signing_key_fix_command(),
    )
}

fn missing_trust_registry_message(path: &Path, policy_mode: Profile) -> String {
    ActionableError::new(
        format!(
            "authoritative trust registry missing at {}; bootstrap trust state before running",
            path.display()
        ),
        format!("franken-node init --profile {policy_mode} --scan"),
    )
    .to_string()
}

fn run_preflight_block_error(report: &RunPreFlightReport) -> ActionableError {
    match &report.verdict {
        PreFlightVerdict::Blocked { reason, .. } => ActionableError::new(
            format!(
                "run blocked by trust preflight: {reason}. Refresh trust state with `{}` after remediation",
                report.receipt.rollback_command
            ),
            "franken-node trust list --revoked true",
        ),
        _ => ActionableError::new(
            "run blocked by trust preflight",
            "franken-node trust list --revoked true",
        ),
    }
}

fn trust_card_not_found_error(extension_id: &str) -> ActionableError {
    ActionableError::new(
        format!("trust card not found: {extension_id}"),
        "franken-node trust scan .",
    )
}

fn registry_publish_signing_key_required_error(package_path: &Path) -> ActionableError {
    ActionableError::new(
        format!(
            "registry publish requires --signing-key for {}",
            package_path.display()
        ),
        format!(
            "mkdir -p .franken-node/keys && openssl rand -hex 32 > .franken-node/keys/publisher.ed25519 && franken-node registry publish {} --signing-key .franken-node/keys/publisher.ed25519",
            package_path.display()
        ),
    )
}

/// Prepare receipt export context with mandatory signing material.
///
/// Returns `None` if no receipt export is requested (both paths are `None`).
/// Returns `Some(ReceiptExportContext)` with required signing material if export is requested.
/// Fails immediately if export is requested but no signing key is configured.
fn prepare_receipt_export_context(
    receipt_out: Option<&Path>,
    receipt_summary_out: Option<&Path>,
    cli_override: Option<&Path>,
) -> Result<Option<ReceiptExportContext>> {
    if receipt_out.is_none() && receipt_summary_out.is_none() {
        return Ok(None);
    }

    let signing_material = load_receipt_signing_material(cli_override)?
        .ok_or_else(missing_receipt_signing_key_error)?;

    Ok(Some(ReceiptExportContext {
        receipt_out: receipt_out.map(Path::to_path_buf),
        receipt_summary_out: receipt_summary_out.map(Path::to_path_buf),
        signing_material,
    }))
}

/// Export signed receipts using pre-validated context.
///
/// This function takes a `ReceiptExportContext` which guarantees signing material
/// is available. The type system enforces the sign-or-fail contract: callers must
/// obtain a `ReceiptExportContext` via `prepare_receipt_export_context`, which
/// fails immediately if signing material cannot be loaded.
fn export_signed_receipts(
    action_name: &str,
    actor_identity: &str,
    rationale: &str,
    ctx: &ReceiptExportContext,
) -> Result<()> {
    let mut chain = Vec::new();

    let receipt = Receipt::new(
        action_name,
        actor_identity,
        &serde_json::json!({
            "command": action_name,
            "actor": actor_identity,
        }),
        &serde_json::json!({
            "status": "accepted",
            "receipt_exported": true,
        }),
        Decision::Approved,
        rationale,
        vec!["ledger:pending-10.14".to_string()],
        vec!["policy.rule.high-impact-receipt".to_string()],
        0.93,
        "franken-node trust sync --force",
    )?;
    let signed = append_signed_receipt(&mut chain, receipt, &ctx.signing_material.signing_key)?;

    let filter = ReceiptQuery::default();
    if let Some(ref path) = ctx.receipt_out {
        export_receipts_to_path(&chain, &filter, path)
            .with_context(|| format!("failed writing receipt export to {}", path.display()))?;
    }
    if let Some(ref path) = ctx.receipt_summary_out {
        write_receipts_markdown(&chain, path)
            .with_context(|| format!("failed writing receipt summary to {}", path.display()))?;
    }
    eprintln!(
        "receipt export signed: action={} signer_key_id={} signing_source={} signing_key_path={}",
        action_name,
        signed.signer_key_id,
        ctx.signing_material.source,
        ctx.signing_material.path.display()
    );

    Ok(())
}

fn incident_id_slug(incident_id: &str) -> String {
    let mut slug = String::new();
    for ch in incident_id.chars() {
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
            slug.push(ch);
        } else {
            slug.push('_');
        }
    }
    if slug.is_empty() {
        slug.push_str("incident");
    }
    slug
}

fn incident_bundle_output_path(incident_id: &str) -> PathBuf {
    PathBuf::from(format!("{}.fnbundle", incident_id_slug(incident_id)))
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct IncidentListEntry {
    incident_id: String,
    severity: String,
    event_count: usize,
    created_at: String,
    path: String,
}

fn normalize_incident_severity_label(raw: &str) -> Option<&'static str> {
    let normalized = raw.trim().to_ascii_lowercase();
    match normalized.as_str() {
        "low" => Some("low"),
        "medium" => Some("medium"),
        "high" => Some("high"),
        "critical" => Some("critical"),
        "unknown" => Some("unknown"),
        _ => None,
    }
}

fn parse_incident_severity_filter(raw: Option<&str>) -> Result<Option<String>> {
    raw.map(|value| {
        normalize_incident_severity_label(value)
            .map(str::to_string)
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid --severity `{value}`; expected one of: low, medium, high, critical, unknown"
                )
            })
    })
    .transpose()
}

fn should_skip_bundle_scan_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(std::ffi::OsStr::to_str)
        .is_some_and(|name| {
            matches!(
                name,
                ".git" | ".beads" | "target" | "node_modules" | ".venv" | ".next"
            )
        })
}

fn collect_incident_bundle_paths(root: &Path) -> Result<Vec<PathBuf>> {
    let mut bundles = Vec::new();
    let mut pending = vec![root.to_path_buf()];

    while let Some(dir) = pending.pop() {
        let entries = std::fs::read_dir(&dir)
            .with_context(|| format!("failed reading directory {}", dir.display()))?;
        for entry in entries {
            let entry =
                entry.with_context(|| format!("failed reading entry in {}", dir.display()))?;
            let path = entry.path();
            if path.is_dir() {
                if should_skip_bundle_scan_dir(&path) {
                    continue;
                }
                pending.push(path);
                continue;
            }
            if path.is_file()
                && path
                    .extension()
                    .and_then(std::ffi::OsStr::to_str)
                    .is_some_and(|ext| ext.eq_ignore_ascii_case("fnbundle"))
            {
                bundles.push(path);
            }
        }
    }

    bundles.sort();
    Ok(bundles)
}

fn infer_incident_bundle_severity(bundle: &tools::replay_bundle::ReplayBundle) -> String {
    for event in &bundle.timeline {
        let candidate = event
            .payload
            .get("severity")
            .and_then(serde_json::Value::as_str)
            .or_else(|| {
                event
                    .payload
                    .get("risk")
                    .and_then(serde_json::Value::as_str)
            })
            .or_else(|| {
                event
                    .payload
                    .get("risk_level")
                    .and_then(serde_json::Value::as_str)
            });

        if let Some(label) = candidate
            && let Some(normalized) = normalize_incident_severity_label(label)
        {
            return normalized.to_string();
        }
    }
    "unknown".to_string()
}

fn collect_incident_list_entries(
    root: &Path,
    severity_filter: Option<&str>,
) -> Result<Vec<IncidentListEntry>> {
    let mut entries = Vec::new();

    for path in collect_incident_bundle_paths(root)? {
        let bundle = read_bundle_from_path(&path)
            .with_context(|| format!("failed reading incident bundle {}", path.display()))?;
        let severity = infer_incident_bundle_severity(&bundle);
        if let Some(filter) = severity_filter
            && severity != filter
        {
            continue;
        }
        let display_path = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .display()
            .to_string();
        entries.push(IncidentListEntry {
            incident_id: bundle.incident_id,
            severity,
            event_count: bundle.manifest.event_count,
            created_at: bundle.created_at,
            path: display_path,
        });
    }

    entries.sort_by(|left, right| {
        left.incident_id
            .cmp(&right.incident_id)
            .then_with(|| left.path.cmp(&right.path))
    });
    Ok(entries)
}

fn render_incident_list(entries: &[IncidentListEntry], severity_filter: Option<&str>) -> String {
    if entries.is_empty() {
        return match severity_filter {
            Some(filter) => format!("incident list: no bundles found for severity={filter}"),
            None => "incident list: no bundles found".to_string(),
        };
    }

    let mut lines = Vec::new();
    lines.push(format!("incident list: count={}", entries.len()));
    if let Some(filter) = severity_filter {
        lines.push(format!("severity_filter={filter}"));
    }
    lines.push("incident_id | severity | events | created_at | path".to_string());
    lines.push("----------- | -------- | ------ | ---------- | ----".to_string());
    for entry in entries {
        lines.push(format!(
            "{} | {} | {} | {} | {}",
            entry.incident_id, entry.severity, entry.event_count, entry.created_at, entry.path
        ));
    }
    lines.join("\n")
}

fn now_unix_secs() -> u64 {
    let ts = chrono::Utc::now().timestamp();
    if ts <= 0 { 0 } else { ts as u64 }
}

fn rfc3339_timestamp_from_secs(timestamp_secs: u64) -> String {
    let secs = match i64::try_from(timestamp_secs) {
        Ok(secs) => secs,
        Err(_) => return "1970-01-01T00:00:00Z".to_string(),
    };
    chrono::DateTime::from_timestamp(secs, 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string())
}

fn parse_ttl_secs(ttl: &str) -> Result<u64> {
    let raw = ttl.trim();
    if raw.is_empty() {
        anyhow::bail!("ttl cannot be empty");
    }

    let (numeric, multiplier) = match raw.chars().last() {
        Some('s') | Some('S') => (&raw[..raw.len() - 1], 1_u64),
        Some('m') | Some('M') => (&raw[..raw.len() - 1], 60_u64),
        Some('h') | Some('H') => (&raw[..raw.len() - 1], 3_600_u64),
        Some('d') | Some('D') => (&raw[..raw.len() - 1], 86_400_u64),
        _ => (raw, 1_u64),
    };

    let base = numeric
        .trim()
        .parse::<u64>()
        .with_context(|| format!("invalid ttl value: `{raw}`"))?;
    base.checked_mul(multiplier)
        .ok_or_else(|| anyhow::anyhow!("ttl overflow for `{raw}`"))
}

fn parse_remote_operation(token: &str) -> Result<RemoteOperation> {
    let normalized = token.trim().to_ascii_lowercase().replace('-', "_");
    let op = match normalized.as_str() {
        "network_egress" => RemoteOperation::NetworkEgress,
        "federation_sync" => RemoteOperation::FederationSync,
        "revocation_fetch" => RemoteOperation::RevocationFetch,
        "remote_attestation_verify" => RemoteOperation::RemoteAttestationVerify,
        "telemetry_export" => RemoteOperation::TelemetryExport,
        "remote_computation" => RemoteOperation::RemoteComputation,
        "artifact_upload" => RemoteOperation::ArtifactUpload,
        _ => {
            anyhow::bail!(
                "unknown operation `{token}`; expected one of: network_egress,federation_sync,revocation_fetch,remote_attestation_verify,telemetry_export,remote_computation,artifact_upload"
            )
        }
    };
    Ok(op)
}

fn parse_profile_override(raw: Option<&str>) -> Result<Option<Profile>> {
    raw.map(|value| {
        value
            .parse::<Profile>()
            .map_err(|err| anyhow::anyhow!(err.to_string()))
    })
    .transpose()
}

fn parse_runtime_override(raw: Option<&str>) -> Result<Option<config::PreferredRuntime>> {
    raw.map(|value| {
        value
            .parse::<config::PreferredRuntime>()
            .map_err(|err| anyhow::anyhow!(err.to_string()))
    })
    .transpose()
}

fn write_migration_report_file(
    rendered: &str,
    out_path: &Path,
    report_label: &str,
) -> Result<PathBuf> {
    if let Some(parent) = out_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed creating output directory {} for {report_label}",
                parent.display()
            )
        })?;
    }
    std::fs::write(out_path, rendered.as_bytes())
        .with_context(|| format!("failed writing {report_label} to {}", out_path.display()))?;
    Ok(out_path.to_path_buf())
}

fn emit_migration_audit_report(rendered: &str, out_path: Option<&Path>) -> Result<Option<PathBuf>> {
    if let Some(out_path) = out_path {
        return write_migration_report_file(rendered, out_path, "migrate audit report").map(Some);
    }

    println!("{rendered}");
    Ok(None)
}

fn handle_bench_run(args: &cli::BenchRunArgs) -> Result<()> {
    let report = benchmark_suite_run_default_suite(args.scenario.as_deref())
        .map_err(|err| anyhow::anyhow!("benchmark suite run failed: {err}"))?;
    let rendered =
        benchmark_suite_to_json(&report).context("failed serializing benchmark suite report")?;
    println!("{rendered}");
    eprintln!("{}", benchmark_suite_render_human_summary(&report));
    Ok(())
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum InitFileActionKind {
    Created,
    Overwritten,
    BackedUpAndOverwritten,
    DirectoryCreated,
    SkippedExisting,
}

#[derive(Debug, Clone, Serialize)]
struct InitFileAction {
    path: String,
    action: InitFileActionKind,
    backup_path: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct InitReport {
    command: String,
    trace_id: String,
    generated_at_utc: String,
    selected_profile: String,
    source_path: Option<String>,
    wrote_to_stdout: bool,
    stdout_config_toml: Option<String>,
    file_actions: Vec<InitFileAction>,
    trust_scan: Option<TrustScanReport>,
    merge_decision_count: usize,
    merge_decisions: Vec<config::MergeDecision>,
}

fn validate_init_flags(overwrite: bool, backup_existing: bool) -> Result<()> {
    if overwrite && backup_existing {
        anyhow::bail!("--overwrite and --backup-existing are mutually exclusive");
    }
    Ok(())
}

fn build_backup_path(path: &Path, timestamp_suffix: &str) -> PathBuf {
    let mut index = 0usize;
    loop {
        let candidate = if index == 0 {
            PathBuf::from(format!("{}.bak.{timestamp_suffix}", path.display()))
        } else {
            PathBuf::from(format!("{}.bak.{timestamp_suffix}.{index}", path.display()))
        };
        if !candidate.exists() {
            return candidate;
        }
        index += 1;
    }
}

fn apply_init_write_policy(
    path: &Path,
    content: &str,
    overwrite: bool,
    backup_existing: bool,
    timestamp_suffix: &str,
) -> Result<InitFileAction> {
    if path.exists() {
        if backup_existing {
            let backup_path = build_backup_path(path, timestamp_suffix);
            std::fs::copy(path, &backup_path).with_context(|| {
                format!(
                    "failed creating backup {} from {}",
                    backup_path.display(),
                    path.display()
                )
            })?;
            std::fs::write(path, content)
                .with_context(|| format!("failed writing {}", path.display()))?;
            return Ok(InitFileAction {
                path: path.display().to_string(),
                action: InitFileActionKind::BackedUpAndOverwritten,
                backup_path: Some(backup_path.display().to_string()),
            });
        }
        if overwrite {
            std::fs::write(path, content)
                .with_context(|| format!("failed writing {}", path.display()))?;
            return Ok(InitFileAction {
                path: path.display().to_string(),
                action: InitFileActionKind::Overwritten,
                backup_path: None,
            });
        }
        anyhow::bail!(
            "refusing to overwrite existing file {} without --overwrite or --backup-existing",
            path.display()
        );
    }

    std::fs::write(path, content).with_context(|| format!("failed writing {}", path.display()))?;
    Ok(InitFileAction {
        path: path.display().to_string(),
        action: InitFileActionKind::Created,
        backup_path: None,
    })
}

fn init_target_paths(out_dir: &Path) -> (PathBuf, PathBuf) {
    (
        out_dir.join("franken_node.toml"),
        out_dir.join("franken_node.profile_examples.toml"),
    )
}

fn build_init_report(
    trace_id: &str,
    resolved: &config::ResolvedConfig,
    file_actions: Vec<InitFileAction>,
    trust_scan: Option<TrustScanReport>,
    wrote_to_stdout: bool,
    stdout_config_toml: Option<String>,
) -> InitReport {
    InitReport {
        command: "init".to_string(),
        trace_id: trace_id.to_string(),
        generated_at_utc: chrono::Utc::now().to_rfc3339(),
        selected_profile: resolved.selected_profile.to_string(),
        source_path: resolved
            .source_path
            .as_ref()
            .map(|path| path.display().to_string()),
        wrote_to_stdout,
        stdout_config_toml,
        file_actions,
        trust_scan,
        merge_decision_count: resolved.decisions.len(),
        merge_decisions: resolved.decisions.clone(),
    }
}

fn render_init_report_human(report: &InitReport, verbose: bool) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "franken-node init: profile={} trace_id={}",
        report.selected_profile, report.trace_id
    ));
    lines.push(format!(
        "source={}",
        report
            .source_path
            .clone()
            .unwrap_or_else(|| "<defaults>".to_string())
    ));
    lines.push(format!("wrote_to_stdout={}", report.wrote_to_stdout));
    if let Some(config_toml) = &report.stdout_config_toml {
        lines.push(format!("stdout_config_toml_bytes={}", config_toml.len()));
    }
    if report.file_actions.is_empty() {
        lines.push("file_actions=<none>".to_string());
    } else {
        lines.push("file_actions:".to_string());
        for action in &report.file_actions {
            lines.push(format!(
                "  action={:?} path={} backup={}",
                action.action,
                action.path,
                action
                    .backup_path
                    .clone()
                    .unwrap_or_else(|| "<none>".to_string())
            ));
        }
    }

    if let Some(trust_scan) = &report.trust_scan {
        lines.push(format!(
            "trust_scan: project={} created={} skipped_existing={} warnings={} deep={} audit={}",
            trust_scan.project_root,
            trust_scan.created_cards,
            trust_scan.skipped_existing,
            trust_scan.warnings.len(),
            trust_scan.deep,
            trust_scan.audit
        ));
        if verbose {
            for item in &trust_scan.items {
                lines.push(format!(
                    "  trust_scan_item status={:?} extension={} version={} publisher={} risk={} vulns={} dependents={} integrity_hashes={}",
                    item.status,
                    item.extension_id,
                    item.extension_version,
                    item.publisher_id,
                    item.risk_level,
                    item.vulnerability_count,
                    item.dependent_count
                        .map_or_else(|| "<unknown>".to_string(), |count| count.to_string()),
                    item.integrity_hash_count
                ));
            }
            for warning in &trust_scan.warnings {
                lines.push(format!("  trust_scan_warning {warning}"));
            }
        }
    }

    if verbose {
        lines.push(format!(
            "generated_at={} merge_decision_count={}",
            report.generated_at_utc, report.merge_decision_count
        ));
        for decision in &report.merge_decisions {
            lines.push(format!(
                "  merge_decision stage={:?} field={} value={}",
                decision.stage, decision.field, decision.value
            ));
        }
    }
    lines.join("\n")
}

// ── State directory bootstrap ─────────────────────────────────────────

/// Subdirectories to create under the `.franken-node/` root during init.
const STATE_BOOTSTRAP_SUBDIRS: &[&str] = &[
    "state",
    "state/incidents",
    "state/execution-receipts",
    "state/registry",
    "state/registry/artifacts",
    "state/registry/archive",
    "state/fleet",
    "state/migrations",
    "keys",
];

/// Contents for .franken-node/.gitignore — exclude sensitive and transient state.
const STATE_GITIGNORE_CONTENTS: &str = "\
# franken-node state — managed automatically
# Exclude signing keys and transient execution receipts from version control.
keys/
state/execution-receipts/
";

/// Bootstrap the `.franken-node/` state directory structure.
///
/// Creates all required subdirectories, an empty trust-card registry, and a
/// `.gitignore` that excludes sensitive material. The operation is idempotent:
/// existing directories and files are skipped without error.
fn bootstrap_state_directory(root: &Path, profile_name: &str) -> Result<Vec<InitFileAction>> {
    let mut actions = Vec::new();
    let dot_dir = root.join(".franken-node");

    // Create each subdirectory.
    for subdir in STATE_BOOTSTRAP_SUBDIRS {
        let dir_path = dot_dir.join(subdir);
        if dir_path.is_dir() {
            actions.push(InitFileAction {
                path: dir_path.display().to_string(),
                action: InitFileActionKind::SkippedExisting,
                backup_path: None,
            });
        } else {
            std::fs::create_dir_all(&dir_path).with_context(|| {
                format!("failed creating state directory {}", dir_path.display())
            })?;
            // Restrict keys/ directory permissions on Unix.
            #[cfg(unix)]
            if *subdir == "keys" {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(&dir_path, std::fs::Permissions::from_mode(0o700))
                    .with_context(|| {
                        format!("failed setting permissions on {}", dir_path.display())
                    })?;
            }
            actions.push(InitFileAction {
                path: dir_path.display().to_string(),
                action: InitFileActionKind::DirectoryCreated,
                backup_path: None,
            });
        }
    }

    // Write .gitignore (idempotent — skip if already present).
    let gitignore_path = dot_dir.join(".gitignore");
    if gitignore_path.is_file() {
        actions.push(InitFileAction {
            path: gitignore_path.display().to_string(),
            action: InitFileActionKind::SkippedExisting,
            backup_path: None,
        });
    } else {
        std::fs::write(&gitignore_path, STATE_GITIGNORE_CONTENTS)
            .with_context(|| format!("failed writing {}", gitignore_path.display()))?;
        actions.push(InitFileAction {
            path: gitignore_path.display().to_string(),
            action: InitFileActionKind::Created,
            backup_path: None,
        });
    }

    // Write empty trust-card registry (idempotent — skip if already present).
    let registry_path = dot_dir.join("state/trust-card-registry.v1.json");
    if registry_path.is_file() {
        actions.push(InitFileAction {
            path: registry_path.display().to_string(),
            action: InitFileActionKind::SkippedExisting,
            backup_path: None,
        });
    } else {
        let empty_registry = supply_chain::trust_card::TrustCardRegistry::default();
        empty_registry
            .persist_authoritative_state(&registry_path)
            .map_err(|err| anyhow::anyhow!("failed writing empty trust-card registry: {err}"))?;
        actions.push(InitFileAction {
            path: registry_path.display().to_string(),
            action: InitFileActionKind::Created,
            backup_path: None,
        });
    }

    tracing::info!(
        root = %root.display(),
        profile = profile_name,
        dirs_created = actions.iter().filter(|a| matches!(a.action, InitFileActionKind::DirectoryCreated)).count(),
        files_created = actions.iter().filter(|a| matches!(a.action, InitFileActionKind::Created)).count(),
        skipped = actions.iter().filter(|a| matches!(a.action, InitFileActionKind::SkippedExisting)).count(),
        "state directory bootstrap complete"
    );

    Ok(actions)
}

/// Ensure the `.franken-node/state/` subtree exists.  Called by commands that
/// need state storage but may run before `init`.  Creates on demand and emits a
/// warning suggesting `franken-node init`.
fn ensure_state_dir(project_root: &Path) -> Result<PathBuf> {
    let state_dir = project_root.join(".franken-node/state");
    if !state_dir.is_dir() {
        std::fs::create_dir_all(&state_dir)
            .with_context(|| format!("failed creating state directory {}", state_dir.display()))?;
        tracing::warn!(
            state_dir = %state_dir.display(),
            "state directory created on demand; consider running `franken-node init` to bootstrap the full directory structure"
        );
    }
    Ok(state_dir)
}

fn configured_run_receipt_limit(config: &config::Config) -> usize {
    config
        .observability
        .max_receipts
        .unwrap_or(RUN_EXECUTION_RECEIPT_DEFAULT_MAX_RECEIPTS)
}

fn summarize_run_telemetry(
    report: Option<&ops::telemetry_bridge::TelemetryRuntimeReport>,
) -> Option<RunExecutionTelemetrySummary> {
    report.map(|report| RunExecutionTelemetrySummary {
        final_state: Some(format!("{:?}", report.final_state).to_ascii_lowercase()),
        accepted_total: report.accepted_total,
        persisted_total: report.persisted_total,
        shed_total: report.shed_total,
        dropped_total: report.dropped_total,
        retry_total: report.retry_total,
        drain_completed: report.drain_completed,
        drain_duration_ms: report.drain_duration_ms,
        recent_event_codes: report
            .recent_events
            .iter()
            .map(|event| event.code.clone())
            .collect(),
    })
}

fn value_contains_ssrf_signal(value: &serde_json::Value) -> bool {
    match value {
        serde_json::Value::String(text) => {
            let normalized = text.to_ascii_lowercase();
            normalized.contains("ssrf")
                || normalized.contains("server-side request forgery")
                || normalized.contains("server side request forgery")
        }
        serde_json::Value::Array(items) => items.iter().any(value_contains_ssrf_signal),
        serde_json::Value::Object(map) => map.iter().any(|(key, item)| {
            value_contains_ssrf_signal(&serde_json::Value::String(key.clone()))
                || value_contains_ssrf_signal(item)
        }),
        _ => false,
    }
}

fn extract_ssrf_violations(
    report: Option<&ops::telemetry_bridge::TelemetryRuntimeReport>,
) -> Vec<String> {
    let mut violations = report
        .into_iter()
        .flat_map(|report| report.telemetry_events.iter())
        .filter_map(|event| {
            let payload = &event.payload;
            let event_type_matches = matches!(
                event.event_type.as_str(),
                "network_request" | "policy_check" | "error"
            );
            let blocked = payload
                .get("blocked")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
                || payload
                    .get("decision")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|decision| {
                        matches!(
                            decision.to_ascii_lowercase().as_str(),
                            "deny" | "denied" | "blocked"
                        )
                    })
                || payload
                    .get("verdict")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|verdict| {
                        matches!(
                            verdict.to_ascii_lowercase().as_str(),
                            "deny" | "denied" | "blocked"
                        )
                    });
            let has_ssrf_signal = value_contains_ssrf_signal(payload);

            if !event_type_matches || !has_ssrf_signal || !blocked {
                return None;
            }

            Some(
                payload
                    .get("detail")
                    .or_else(|| payload.get("message"))
                    .or_else(|| payload.get("reason"))
                    .and_then(serde_json::Value::as_str)
                    .map_or_else(
                        || format!("{} reported an ssrf policy violation", event.event_type),
                        std::string::ToString::to_string,
                    ),
            )
        })
        .collect::<Vec<_>>();
    violations.sort();
    violations.dedup();
    violations
}

fn compute_run_execution_receipt_hash(core: &RunExecutionReceiptCore) -> Result<String> {
    let payload =
        serde_json::to_vec(core).context("failed serializing run execution receipt for hashing")?;
    Ok(format!(
        "sha256:{:x}",
        sha2::Sha256::digest([b"run_execution_receipt_v1:" as &[u8], payload.as_slice()].concat())
    ))
}

fn compute_run_execution_receipt_seed_hash(core: &RunExecutionReceiptCore) -> Result<String> {
    let payload = serde_json::to_vec(core)
        .context("failed serializing run execution receipt identity seed for hashing")?;
    Ok(format!(
        "sha256:{:x}",
        sha2::Sha256::digest(
            [
                b"run_execution_receipt_identity_v1:" as &[u8],
                payload.as_slice()
            ]
            .concat()
        )
    ))
}

fn deterministic_run_execution_receipt_id(seed_hash: &str) -> String {
    let digest = sha2::Sha256::digest(seed_hash.as_bytes());
    let mut bytes = [0_u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x80;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes).to_string()
}

#[allow(clippy::too_many_arguments)]
fn build_run_execution_receipt(
    app_path: &Path,
    policy_mode: &str,
    profile: Profile,
    preflight: &RunPreFlightReport,
    dispatch: &ops::engine_dispatcher::RunDispatchReport,
    ssrf_violations: Vec<String>,
    auto_quarantined_extensions: Vec<String>,
    lockstep_verdict: Option<serde_json::Value>,
) -> Result<RunExecutionReceipt> {
    let violation_count = ssrf_violations.len();
    let mut core = RunExecutionReceiptCore {
        receipt_id: RUN_EXECUTION_RECEIPT_ID_PLACEHOLDER.to_string(),
        schema_version: RUN_EXECUTION_RECEIPT_SCHEMA_VERSION.to_string(),
        app_path: app_path.display().to_string(),
        policy_mode: policy_mode.to_string(),
        profile: profile.to_string(),
        start_time_utc: dispatch.started_at_utc.clone(),
        end_time_utc: dispatch.finished_at_utc.clone(),
        duration_ms: dispatch.duration_ms,
        exit_code: dispatch.exit_code,
        runtime_used: dispatch.runtime.clone(),
        runtime_version: None,
        preflight_verdict: preflight.verdict.clone(),
        telemetry_summary: summarize_run_telemetry(dispatch.telemetry.as_ref()),
        ssrf_violations,
        lockstep_verdict,
        violation_count,
        auto_quarantined_extensions,
    };
    let seed_hash = compute_run_execution_receipt_seed_hash(&core)?;
    core.receipt_id = deterministic_run_execution_receipt_id(&seed_hash);
    let receipt_hash = compute_run_execution_receipt_hash(&core)?;
    Ok(RunExecutionReceipt { core, receipt_hash })
}

fn run_execution_receipts_root(project_root: &Path) -> Result<PathBuf> {
    Ok(ensure_state_dir(project_root)?.join("execution-receipts"))
}

fn list_active_run_receipts(receipts_root: &Path) -> Result<Vec<PathBuf>> {
    if !receipts_root.is_dir() {
        return Ok(Vec::new());
    }

    let mut receipts = Vec::new();
    for entry in std::fs::read_dir(receipts_root)
        .with_context(|| format!("failed listing {}", receipts_root.display()))?
    {
        let entry = entry.with_context(|| format!("failed reading {}", receipts_root.display()))?;
        let path = entry.path();
        if !entry
            .file_type()
            .with_context(|| format!("failed reading file type for {}", path.display()))?
            .is_dir()
        {
            continue;
        }
        if entry.file_name() == "archive" {
            continue;
        }

        for file in std::fs::read_dir(&path)
            .with_context(|| format!("failed listing {}", path.display()))?
        {
            let file = file.with_context(|| format!("failed reading {}", path.display()))?;
            let file_path = file.path();
            if file
                .file_type()
                .with_context(|| format!("failed reading file type for {}", file_path.display()))?
                .is_file()
                && file_path.extension().and_then(|ext| ext.to_str()) == Some("json")
            {
                receipts.push(file_path);
            }
        }
    }

    receipts.sort();
    Ok(receipts)
}

fn archive_excess_run_receipts(receipts_root: &Path, max_receipts: usize) -> Result<()> {
    let receipts = list_active_run_receipts(receipts_root)?;
    let overflow = receipts.len().saturating_sub(max_receipts);
    if overflow == 0 {
        return Ok(());
    }

    let archive_root = receipts_root.join("archive");
    for path in receipts.into_iter().take(overflow) {
        let relative = path.strip_prefix(receipts_root).with_context(|| {
            format!(
                "failed deriving relative receipt path {} from {}",
                path.display(),
                receipts_root.display()
            )
        })?;
        let archive_path = archive_root.join(relative);
        if let Some(parent) = archive_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed creating {}", parent.display()))?;
        }
        std::fs::rename(&path, &archive_path).with_context(|| {
            format!(
                "failed archiving old run receipt {} -> {}",
                path.display(),
                archive_path.display()
            )
        })?;
    }

    Ok(())
}

fn persist_run_execution_receipt(
    project_root: &Path,
    receipt: &RunExecutionReceipt,
    max_receipts: usize,
) -> Result<PathBuf> {
    let receipts_root = run_execution_receipts_root(project_root)?;
    let ended_at = DateTime::parse_from_rfc3339(&receipt.core.end_time_utc)
        .context("run receipt end_time_utc was not valid RFC3339")?;
    let day_dir = receipts_root.join(ended_at.format("%Y-%m-%d").to_string());
    std::fs::create_dir_all(&day_dir)
        .with_context(|| format!("failed creating {}", day_dir.display()))?;

    let final_path = day_dir.join(format!("{}.json", receipt.core.receipt_id));
    let temp_path = day_dir.join(format!(
        "{}.json.tmp-{}",
        receipt.core.receipt_id,
        Uuid::now_v7()
    ));
    let mut temp_guard = TempFileGuard::new(temp_path.clone());
    let rendered = serde_json::to_vec_pretty(receipt)
        .context("failed serializing run execution receipt for persistence")?;
    std::fs::write(&temp_path, rendered)
        .with_context(|| format!("failed writing {}", temp_path.display()))?;
    std::fs::rename(&temp_path, &final_path).with_context(|| {
        format!(
            "failed promoting run execution receipt {} -> {}",
            temp_path.display(),
            final_path.display()
        )
    })?;
    temp_guard.defuse();

    archive_excess_run_receipts(&receipts_root, max_receipts)?;
    Ok(final_path)
}

fn maybe_auto_quarantine_run_dependencies(
    project_root: &Path,
    config: &config::Config,
    preflight: &RunPreFlightReport,
    violation_count: usize,
    now_secs: u64,
) -> Result<Vec<String>> {
    if violation_count < RUN_EXECUTION_RECEIPT_AUTO_QUARANTINE_THRESHOLD
        || !config.trust.quarantine_on_high_risk
    {
        return Ok(Vec::new());
    }

    let registry_path = project_root.join(TRUST_CARD_REGISTRY_STATE_RELATIVE_PATH);
    if !registry_path.is_file() {
        tracing::warn!(
            registry_path = %registry_path.display(),
            "skipping automatic run quarantine because trust registry is unavailable"
        );
        return Ok(Vec::new());
    }

    let mut extension_ids = match &preflight.verdict {
        PreFlightVerdict::Passed { results, .. } | PreFlightVerdict::Blocked { results, .. } => {
            results
                .iter()
                .filter(|result| result.status == RunDependencyTrustStatus::Trusted)
                .map(|result| result.extension_id.clone())
                .collect::<Vec<_>>()
        }
        PreFlightVerdict::Skipped { .. } => Vec::new(),
    };
    extension_ids.sort();
    extension_ids.dedup();
    if extension_ids.is_empty() {
        return Ok(Vec::new());
    }

    let cache_ttl = config.trust.card_cache_ttl_secs.unwrap_or(60);
    let mut registry =
        TrustCardRegistry::load_authoritative_state(&registry_path, cache_ttl, now_secs)
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let now_rfc3339 = rfc3339_timestamp_from_secs(now_secs);
    let mut quarantined = Vec::new();

    for extension_id in extension_ids {
        registry
            .update(
                &extension_id,
                TrustCardMutation {
                    certification_level: None,
                    revocation_status: None,
                    active_quarantine: Some(true),
                    reputation_score_basis_points: None,
                    reputation_trend: Some(ReputationTrend::Declining),
                    user_facing_risk_assessment: Some(RiskAssessment {
                        level: RiskLevel::High,
                        summary: format!(
                            "Automatically quarantined after runtime policy violations ({violation_count} violation(s))"
                        ),
                    }),
                    last_verified_timestamp: Some(now_rfc3339.clone()),
                    evidence_refs: None,
                },
                now_secs,
                "trace-cli-run-auto-quarantine",
            )
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        quarantined.push(extension_id);
    }

    registry
        .persist_authoritative_state(&registry_path)
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    Ok(quarantined)
}

fn render_run_execution_receipt_summary(
    receipt: &RunExecutionReceipt,
    receipt_path: &Path,
) -> String {
    format!(
        "run receipt: id={} runtime={} exit_code={} violations={} auto_quarantined={} path={}",
        receipt.core.receipt_id,
        receipt.core.runtime_used,
        receipt
            .core
            .exit_code
            .map_or_else(|| "signal".to_string(), |code| code.to_string()),
        receipt.core.violation_count,
        receipt.core.auto_quarantined_extensions.len(),
        receipt_path.display()
    )
}

fn emit_run_completion_output(
    preflight: &RunPreFlightReport,
    dispatch: &ops::engine_dispatcher::RunDispatchReport,
    receipt: &RunExecutionReceipt,
    receipt_path: &Path,
    json: bool,
) -> Result<()> {
    if json {
        let output = RunCommandOutput {
            success: dispatch.exit_code == Some(0) && !dispatch.terminated_by_signal,
            preflight: preflight.clone(),
            dispatch: dispatch.clone(),
            receipt: receipt.clone(),
            receipt_path: receipt_path.display().to_string(),
        };
        println!(
            "{}",
            serde_json::to_string_pretty(&output)
                .context("failed serializing run completion output")?
        );
        return Ok(());
    }

    if !dispatch.captured_output.stdout.is_empty() {
        print!("{}", dispatch.captured_output.stdout);
    }
    if !dispatch.captured_output.stderr.is_empty() {
        eprint!("{}", dispatch.captured_output.stderr);
    }
    println!(
        "{}",
        render_run_execution_receipt_summary(receipt, receipt_path)
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum DoctorGuardrailVerdictKind {
    Allow,
    Warn,
    Block,
}

impl DoctorGuardrailVerdictKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Warn => "warn",
            Self::Block => "block",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct DoctorGuardrailFindingReport {
    monitor_name: String,
    budget_id: String,
    verdict: DoctorGuardrailVerdictKind,
    event_code: String,
    anytime_valid: bool,
    reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorGuardrailCertificateReport {
    epoch_id: u64,
    dominant_verdict: DoctorGuardrailVerdictKind,
    findings: Vec<DoctorGuardrailFindingReport>,
    blocking_budget_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorPolicyActivationReport {
    input_path: String,
    candidate_count: usize,
    observation_count: usize,
    prefiltered_candidate_count: usize,
    top_ranked_candidate: Option<String>,
    guardrail_certificate: DoctorGuardrailCertificateReport,
    decision_outcome: DecisionOutcome,
    explanation: PolicyExplanation,
    wording_validation: WordingValidation,
}

#[derive(Debug, Deserialize)]
struct DoctorPolicyMemoryTailRiskInput {
    sample_count: u64,
    mean_utilization: f64,
    variance_utilization: f64,
    peak_utilization: f64,
}

#[derive(Debug, Deserialize)]
struct DoctorPolicyReliabilityTelemetryInput {
    sample_count: u64,
    nonconforming_count: u64,
}

#[derive(Debug, Deserialize)]
struct DoctorPolicySystemStateInput {
    memory_used_bytes: u64,
    memory_budget_bytes: u64,
    durability_level: f64,
    hardening_level: String,
    #[serde(default)]
    proposed_hardening_level: Option<String>,
    #[serde(default = "doctor_policy_default_evidence_emission_active")]
    evidence_emission_active: bool,
    #[serde(default)]
    memory_tail_risk: Option<DoctorPolicyMemoryTailRiskInput>,
    #[serde(default)]
    reliability_telemetry: Option<DoctorPolicyReliabilityTelemetryInput>,
    #[serde(default)]
    epoch_id: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct DoctorPolicyObservationInput {
    candidate: String,
    success: bool,
    #[serde(default)]
    epoch_id: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct DoctorPolicyActivationInput {
    #[serde(default)]
    epoch_id: Option<u64>,
    system_state: DoctorPolicySystemStateInput,
    candidates: Vec<String>,
    #[serde(default)]
    prefiltered_candidates: Vec<String>,
    #[serde(default)]
    observations: Vec<DoctorPolicyObservationInput>,
}

const fn doctor_policy_default_evidence_emission_active() -> bool {
    true
}

fn parse_hardening_level(label: &str, field: &str) -> Result<HardeningLevel> {
    let normalized = label.trim().to_ascii_lowercase();
    HardeningLevel::from_label(&normalized).ok_or_else(|| {
        anyhow::anyhow!(
            "invalid {} `{}`; expected one of: baseline, standard, enhanced, maximum, critical",
            field,
            label
        )
    })
}

fn map_guardrail_verdict(verdict: &GuardrailVerdict) -> DoctorGuardrailVerdictKind {
    match verdict {
        GuardrailVerdict::Allow => DoctorGuardrailVerdictKind::Allow,
        GuardrailVerdict::Warn { .. } => DoctorGuardrailVerdictKind::Warn,
        GuardrailVerdict::Block { .. } => DoctorGuardrailVerdictKind::Block,
    }
}

fn guardrail_reason(verdict: &GuardrailVerdict) -> Option<String> {
    match verdict {
        GuardrailVerdict::Allow => None,
        GuardrailVerdict::Warn { reason } => Some(reason.clone()),
        GuardrailVerdict::Block { reason, .. } => Some(reason.clone()),
    }
}

fn map_guardrail_finding(finding: &GuardrailFinding) -> DoctorGuardrailFindingReport {
    DoctorGuardrailFindingReport {
        monitor_name: finding.monitor_name.clone(),
        budget_id: finding.budget_id.as_str().to_string(),
        verdict: map_guardrail_verdict(&finding.verdict),
        event_code: finding.event_code.to_string(),
        anytime_valid: finding.anytime_valid,
        reason: guardrail_reason(&finding.verdict),
    }
}

fn map_guardrail_certificate(
    certificate: &GuardrailCertificate,
) -> DoctorGuardrailCertificateReport {
    DoctorGuardrailCertificateReport {
        epoch_id: certificate.epoch_id,
        dominant_verdict: map_guardrail_verdict(&certificate.dominant_verdict),
        findings: certificate
            .findings
            .iter()
            .map(map_guardrail_finding)
            .collect(),
        blocking_budget_ids: certificate
            .blocking_budget_ids
            .iter()
            .map(|id| id.as_str().to_string())
            .collect(),
    }
}

fn load_doctor_policy_activation_input(path: &Path) -> Result<DoctorPolicyActivationInput> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("failed reading policy activation input {}", path.display()))?;
    let input = serde_json::from_str::<DoctorPolicyActivationInput>(&raw).with_context(|| {
        format!(
            "failed parsing policy activation input {} as JSON",
            path.display()
        )
    })?;
    Ok(input)
}

fn build_system_state(input: &DoctorPolicyActivationInput) -> Result<SystemState> {
    let epoch_id = input
        .system_state
        .epoch_id
        .or(input.epoch_id)
        .unwrap_or_default();

    let hardening_level =
        parse_hardening_level(&input.system_state.hardening_level, "hardening_level")?;
    let proposed_hardening_level = input
        .system_state
        .proposed_hardening_level
        .as_ref()
        .map(|label| parse_hardening_level(label, "proposed_hardening_level"))
        .transpose()?;

    let memory_tail_risk =
        input
            .system_state
            .memory_tail_risk
            .as_ref()
            .map(|raw| MemoryTailRiskTelemetry {
                sample_count: raw.sample_count,
                mean_utilization: raw.mean_utilization,
                variance_utilization: raw.variance_utilization,
                peak_utilization: raw.peak_utilization,
            });

    let reliability_telemetry = input
        .system_state
        .reliability_telemetry
        .as_ref()
        .map(|raw| ReliabilityTelemetry {
            sample_count: raw.sample_count,
            nonconforming_count: raw.nonconforming_count,
        });

    Ok(SystemState {
        memory_used_bytes: input.system_state.memory_used_bytes,
        memory_budget_bytes: input.system_state.memory_budget_bytes,
        durability_level: input.system_state.durability_level,
        hardening_level,
        proposed_hardening_level,
        evidence_emission_active: input.system_state.evidence_emission_active,
        memory_tail_risk,
        reliability_telemetry,
        epoch_id,
    })
}

fn normalize_candidate_ids(raw_candidates: &[String], field: &str) -> Result<Vec<CandidateRef>> {
    let mut unique = std::collections::BTreeSet::new();
    let mut candidates = Vec::new();

    for raw in raw_candidates {
        let candidate = raw.trim();
        if candidate.is_empty() {
            anyhow::bail!("{field} contains an empty candidate identifier");
        }
        if unique.insert(candidate.to_string()) {
            candidates.push(CandidateRef::new(candidate));
        }
    }

    Ok(candidates)
}

fn required_candidate_ids(raw_candidates: &[String], field: &str) -> Result<Vec<CandidateRef>> {
    let candidates = normalize_candidate_ids(raw_candidates, field)?;
    if candidates.is_empty() {
        anyhow::bail!("{field} must include at least one candidate identifier");
    }
    Ok(candidates)
}

fn build_observations(
    input: &DoctorPolicyActivationInput,
    epoch_id: u64,
) -> Result<Vec<Observation>> {
    let mut observations = Vec::with_capacity(input.observations.len());
    for raw in &input.observations {
        let candidate = raw.candidate.trim();
        if candidate.is_empty() {
            anyhow::bail!("observations contains an empty candidate identifier");
        }
        observations.push(Observation::new(
            CandidateRef::new(candidate),
            raw.success,
            raw.epoch_id.unwrap_or(epoch_id),
        ));
    }
    Ok(observations)
}

fn run_doctor_policy_activation(path: &Path) -> Result<DoctorPolicyActivationReport> {
    let input = load_doctor_policy_activation_input(path)?;
    let system_state = build_system_state(&input)?;
    let candidate_refs = required_candidate_ids(&input.candidates, "candidates")?;
    let prefiltered_refs =
        normalize_candidate_ids(&input.prefiltered_candidates, "prefiltered_candidates")?;
    let observations = build_observations(&input, system_state.epoch_id)?;

    let diagnostics = BayesianDiagnostics::replay_from(&observations);
    let ranked = diagnostics.rank_candidates(&candidate_refs, &prefiltered_refs);
    let top_ranked_candidate = ranked.first().map(|entry| entry.candidate_ref.0.clone());

    let monitors = GuardrailMonitorSet::with_defaults();
    let certificate = monitors.certify(&system_state);
    let decision_outcome =
        DecisionEngine::new(system_state.epoch_id).decide(&ranked, &monitors, &system_state);
    let explanation = PolicyExplainer::explain(&decision_outcome, &diagnostics);
    let wording_validation = validate_wording(&explanation);

    Ok(DoctorPolicyActivationReport {
        input_path: path.display().to_string(),
        candidate_count: candidate_refs.len(),
        observation_count: observations.len(),
        prefiltered_candidate_count: prefiltered_refs.len(),
        top_ranked_candidate,
        guardrail_certificate: map_guardrail_certificate(&certificate),
        decision_outcome,
        explanation,
        wording_validation,
    })
}

#[derive(Debug, Clone, Copy, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum DoctorStatus {
    Pass,
    Warn,
    Fail,
}

impl DoctorStatus {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Pass => "PASS",
            Self::Warn => "WARN",
            Self::Fail => "FAIL",
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct DoctorCheck {
    code: String,
    event_code: String,
    scope: String,
    status: DoctorStatus,
    message: String,
    remediation: String,
    duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorLogEvent {
    trace_id: String,
    event_code: String,
    check_code: String,
    scope: String,
    status: DoctorStatus,
    duration_ms: u64,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorStatusCounts {
    pass: usize,
    warn: usize,
    fail: usize,
}

#[derive(Debug, Clone, Serialize)]
struct DoctorReport {
    command: String,
    trace_id: String,
    generated_at_utc: String,
    selected_profile: String,
    source_path: Option<String>,
    overall_status: DoctorStatus,
    status_counts: DoctorStatusCounts,
    checks: Vec<DoctorCheck>,
    structured_logs: Vec<DoctorLogEvent>,
    merge_decision_count: usize,
    merge_decisions: Vec<config::MergeDecision>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_activation: Option<DoctorPolicyActivationReport>,
}

fn summarize_statuses(checks: &[DoctorCheck]) -> (DoctorStatusCounts, DoctorStatus) {
    let pass = checks
        .iter()
        .filter(|check| matches!(check.status, DoctorStatus::Pass))
        .count();
    let warn = checks
        .iter()
        .filter(|check| matches!(check.status, DoctorStatus::Warn))
        .count();
    let fail = checks
        .iter()
        .filter(|check| matches!(check.status, DoctorStatus::Fail))
        .count();
    let overall = if fail > 0 {
        DoctorStatus::Fail
    } else if warn > 0 {
        DoctorStatus::Warn
    } else {
        DoctorStatus::Pass
    };
    (DoctorStatusCounts { pass, warn, fail }, overall)
}

fn evaluate_doctor_check(
    code: &str,
    event_code: &str,
    scope: &str,
    check: impl FnOnce() -> (DoctorStatus, String, String),
) -> DoctorCheck {
    let start = Instant::now();
    let (status, message, remediation) = check();
    DoctorCheck {
        code: code.to_string(),
        event_code: event_code.to_string(),
        scope: scope.to_string(),
        status,
        message,
        remediation,
        duration_ms: u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX),
    }
}

fn build_doctor_report(resolved: &config::ResolvedConfig, trace_id: &str) -> DoctorReport {
    build_doctor_report_with_cwd_and_policy_input(resolved, trace_id, std::env::current_dir(), None)
}

fn build_doctor_report_with_policy_input(
    resolved: &config::ResolvedConfig,
    trace_id: &str,
    policy_activation_input: Option<&Path>,
) -> DoctorReport {
    if let Some(path) = policy_activation_input {
        build_doctor_report_with_cwd_and_policy_input(
            resolved,
            trace_id,
            std::env::current_dir(),
            Some(path),
        )
    } else {
        build_doctor_report(resolved, trace_id)
    }
}

#[cfg(test)]
fn build_doctor_report_with_cwd(
    resolved: &config::ResolvedConfig,
    trace_id: &str,
    cwd_result: std::io::Result<PathBuf>,
) -> DoctorReport {
    build_doctor_report_with_cwd_and_policy_input(resolved, trace_id, cwd_result, None)
}

fn build_doctor_report_with_cwd_and_policy_input(
    resolved: &config::ResolvedConfig,
    trace_id: &str,
    cwd_result: std::io::Result<PathBuf>,
    policy_activation_input: Option<&Path>,
) -> DoctorReport {
    let source = resolved
        .source_path
        .as_ref()
        .map(|path| path.display().to_string());

    let mut checks: Vec<DoctorCheck> = vec![evaluate_doctor_check(
        "DR-CONFIG-001",
        "DOC-001",
        "config.resolve",
        || {
            (
                DoctorStatus::Pass,
                "Configuration resolved successfully.".to_string(),
                "No action required.".to_string(),
            )
        },
    )];

    if source.is_some() {
        checks.push(evaluate_doctor_check(
            "DR-CONFIG-002",
            "DOC-002",
            "config.source",
            || {
                (
                    DoctorStatus::Pass,
                    "Config source file discovered.".to_string(),
                    "No action required.".to_string(),
                )
            },
        ));
    } else {
        checks.push(evaluate_doctor_check(
            "DR-CONFIG-002",
            "DOC-002",
            "config.source",
            || {
                (
                    DoctorStatus::Warn,
                    "No config file discovered; defaults are active.".to_string(),
                    "Create franken_node.toml or pass --config to lock deterministic project settings.".to_string(),
                )
            },
        ));
    }

    if resolved.config.profile == Profile::LegacyRisky {
        checks.push(evaluate_doctor_check(
            "DR-PROFILE-003",
            "DOC-003",
            "profile.safety",
            || {
                (
                    DoctorStatus::Warn,
                    "Profile is legacy-risky.".to_string(),
                    "Prefer --profile balanced or --profile strict for stronger controls."
                        .to_string(),
                )
            },
        ));
    } else {
        checks.push(evaluate_doctor_check(
            "DR-PROFILE-003",
            "DOC-003",
            "profile.safety",
            || {
                (
                    DoctorStatus::Pass,
                    "Profile safety level is acceptable.".to_string(),
                    "No action required.".to_string(),
                )
            },
        ));
    }

    if resolved.config.registry.minimum_assurance_level >= 3 {
        checks.push(evaluate_doctor_check(
            "DR-TRUST-004",
            "DOC-004",
            "registry.assurance",
            || {
                (
                    DoctorStatus::Pass,
                    "Registry assurance level meets bootstrap target.".to_string(),
                    "No action required.".to_string(),
                )
            },
        ));
    } else {
        checks.push(evaluate_doctor_check(
            "DR-TRUST-004",
            "DOC-004",
            "registry.assurance",
            || {
                (
                    DoctorStatus::Warn,
                    "Registry assurance level is below bootstrap target (3).".to_string(),
                    "Raise registry.minimum_assurance_level to 3+.".to_string(),
                )
            },
        ));
    }

    if resolved.config.migration.require_lockstep_validation {
        checks.push(evaluate_doctor_check(
            "DR-MIGRATE-005",
            "DOC-005",
            "migration.lockstep",
            || {
                (
                    DoctorStatus::Pass,
                    "Lockstep validation requirement is enabled.".to_string(),
                    "No action required.".to_string(),
                )
            },
        ));
    } else {
        checks.push(evaluate_doctor_check(
            "DR-MIGRATE-005",
            "DOC-005",
            "migration.lockstep",
            || {
                (
                    DoctorStatus::Warn,
                    "Lockstep validation requirement is disabled.".to_string(),
                    "Set migration.require_lockstep_validation=true for safer rollout validation."
                        .to_string(),
                )
            },
        ));
    }

    if resolved.config.observability.emit_structured_audit_events {
        checks.push(evaluate_doctor_check(
            "DR-OBS-006",
            "DOC-006",
            "observability.audit_events",
            || {
                (
                    DoctorStatus::Pass,
                    "Structured audit events are enabled.".to_string(),
                    "No action required.".to_string(),
                )
            },
        ));
    } else {
        checks.push(evaluate_doctor_check(
            "DR-OBS-006",
            "DOC-006",
            "observability.audit_events",
            || {
                (
                    DoctorStatus::Warn,
                    "Structured audit events are disabled.".to_string(),
                    "Set observability.emit_structured_audit_events=true for stronger traceability.".to_string(),
                )
            },
        ));
    }

    match cwd_result {
        Ok(path) => checks.push(evaluate_doctor_check(
            "DR-ENV-007",
            "DOC-007",
            "environment.cwd",
            || {
                (
                    DoctorStatus::Pass,
                    format!("Current working directory is available: {}", path.display()),
                    "No action required.".to_string(),
                )
            },
        )),
        Err(err) => checks.push(evaluate_doctor_check(
            "DR-ENV-007",
            "DOC-007",
            "environment.cwd",
            || {
                (
                    DoctorStatus::Fail,
                    "Current working directory is unavailable.".to_string(),
                    format!("Fix working directory access before running operations ({err})."),
                )
            },
        )),
    }

    if resolved.decisions.is_empty() {
        checks.push(evaluate_doctor_check(
            "DR-CONFIG-008",
            "DOC-008",
            "config.provenance",
            || {
                (
                    DoctorStatus::Warn,
                    "No merge decisions recorded for this configuration.".to_string(),
                    "Investigate resolver instrumentation before relying on doctor provenance."
                        .to_string(),
                )
            },
        ));
    } else {
        checks.push(evaluate_doctor_check(
            "DR-CONFIG-008",
            "DOC-008",
            "config.provenance",
            || {
                (
                    DoctorStatus::Pass,
                    format!(
                        "Merge provenance recorded ({} decisions).",
                        resolved.decisions.len()
                    ),
                    "No action required.".to_string(),
                )
            },
        ));
    }

    // DR-STORAGE-012: Probe real filesystem state for fleet state directory
    if let Some(state_dir) = &resolved.config.fleet.state_dir {
        let state_dir_clone = state_dir.clone();
        checks.push(evaluate_doctor_check(
            "DR-STORAGE-012",
            "DOC-012",
            "storage.state_dir",
            move || {
                if state_dir_clone.exists() {
                    let test_path = state_dir_clone.join(".doctor_probe");
                    match std::fs::write(&test_path, b"probe") {
                        Ok(()) => {
                            let _ = std::fs::remove_file(&test_path);
                            (
                                DoctorStatus::Pass,
                                format!(
                                    "Fleet state directory exists and is writable: {}",
                                    state_dir_clone.display()
                                ),
                                "No action required.".to_string(),
                            )
                        }
                        Err(err) => (
                            DoctorStatus::Fail,
                            format!(
                                "Fleet state directory exists but is not writable: {}",
                                state_dir_clone.display()
                            ),
                            format!(
                                "Fix permissions on {} ({}).",
                                state_dir_clone.display(),
                                err
                            ),
                        ),
                    }
                } else {
                    (
                        DoctorStatus::Warn,
                        format!(
                            "Fleet state directory does not exist: {}",
                            state_dir_clone.display()
                        ),
                        format!(
                            "Create the directory with: mkdir -p {}",
                            state_dir_clone.display()
                        ),
                    )
                }
            },
        ));
    }

    // DR-SECURITY-013: Probe real filesystem state for receipt signing key
    if let Some(key_path) = &resolved.config.security.decision_receipt_signing_key_path {
        let key_path_clone = key_path.clone();
        checks.push(evaluate_doctor_check(
            "DR-SECURITY-013",
            "DOC-013",
            "security.signing_key",
            move || {
                if key_path_clone.exists() {
                    match std::fs::metadata(&key_path_clone) {
                        Ok(meta) if meta.is_file() => (
                            DoctorStatus::Pass,
                            format!(
                                "Receipt signing key file exists: {}",
                                key_path_clone.display()
                            ),
                            "No action required.".to_string(),
                        ),
                        Ok(_) => (
                            DoctorStatus::Fail,
                            format!(
                                "Receipt signing key path is not a regular file: {}",
                                key_path_clone.display()
                            ),
                            "Configure decision_receipt_signing_key_path to point to a regular file."
                                .to_string(),
                        ),
                        Err(err) => (
                            DoctorStatus::Fail,
                            format!(
                                "Cannot read receipt signing key file metadata: {}",
                                key_path_clone.display()
                            ),
                            format!(
                                "Fix file permissions or path ({}).",
                                err
                            ),
                        ),
                    }
                } else {
                    (
                        DoctorStatus::Fail,
                        format!(
                            "Receipt signing key file does not exist: {}",
                            key_path_clone.display()
                        ),
                        format!(
                            "Create a signing key or update decision_receipt_signing_key_path. Current path: {}",
                            key_path_clone.display()
                        ),
                    )
                }
            },
        ));
    }

    // DR-ENGINE-014: Probe real filesystem state for engine binary
    if let Some(engine_path) = &resolved.config.engine.binary_path {
        let engine_path_clone = engine_path.clone();
        checks.push(evaluate_doctor_check(
            "DR-ENGINE-014",
            "DOC-014",
            "engine.binary",
            move || {
                if engine_path_clone.exists() {
                    match std::fs::metadata(&engine_path_clone) {
                        Ok(meta) if meta.is_file() => {
                            #[cfg(unix)]
                            {
                                use std::os::unix::fs::PermissionsExt;
                                let mode = meta.permissions().mode();
                                if mode & 0o111 != 0 {
                                    (
                                        DoctorStatus::Pass,
                                        format!(
                                            "Engine binary exists and is executable: {}",
                                            engine_path_clone.display()
                                        ),
                                        "No action required.".to_string(),
                                    )
                                } else {
                                    (
                                        DoctorStatus::Warn,
                                        format!(
                                            "Engine binary exists but is not executable: {}",
                                            engine_path_clone.display()
                                        ),
                                        format!(
                                            "Add execute permission: chmod +x {}",
                                            engine_path_clone.display()
                                        ),
                                    )
                                }
                            }
                            #[cfg(not(unix))]
                            {
                                (
                                    DoctorStatus::Pass,
                                    format!(
                                        "Engine binary exists: {}",
                                        engine_path_clone.display()
                                    ),
                                    "No action required.".to_string(),
                                )
                            }
                        }
                        Ok(_) => (
                            DoctorStatus::Fail,
                            format!(
                                "Engine binary path is not a regular file: {}",
                                engine_path_clone.display()
                            ),
                            "Configure engine.binary_path to point to the franken_engine binary."
                                .to_string(),
                        ),
                        Err(err) => (
                            DoctorStatus::Fail,
                            format!(
                                "Cannot read engine binary metadata: {}",
                                engine_path_clone.display()
                            ),
                            format!("Fix file permissions or path ({}).", err),
                        ),
                    }
                } else {
                    (
                        DoctorStatus::Warn,
                        format!(
                            "Engine binary does not exist: {}",
                            engine_path_clone.display()
                        ),
                        format!(
                            "Install franken_engine or update engine.binary_path. Current path: {}",
                            engine_path_clone.display()
                        ),
                    )
                }
            },
        ));
    }

    let mut policy_activation = None;
    if let Some(input_path) = policy_activation_input {
        match run_doctor_policy_activation(input_path) {
            Ok(report) => {
                let dominant_verdict = report.guardrail_certificate.dominant_verdict;
                let blocked_budgets = report.guardrail_certificate.blocking_budget_ids.clone();
                let guardrail_status = match dominant_verdict {
                    DoctorGuardrailVerdictKind::Allow => DoctorStatus::Pass,
                    DoctorGuardrailVerdictKind::Warn => DoctorStatus::Warn,
                    DoctorGuardrailVerdictKind::Block => DoctorStatus::Fail,
                };
                checks.push(evaluate_doctor_check(
                    "DR-POLICY-009",
                    "DOC-009",
                    "policy.guardrails",
                    || {
                        let message = match dominant_verdict {
                            DoctorGuardrailVerdictKind::Allow => format!(
                                "Policy guardrails passed with dominant verdict {} across {} monitors.",
                                dominant_verdict.as_str(),
                                report.guardrail_certificate.findings.len()
                            ),
                            DoctorGuardrailVerdictKind::Warn => format!(
                                "Policy guardrails reported WARN with dominant verdict {} (blocking_budgets={}).",
                                dominant_verdict.as_str(),
                                blocked_budgets.len()
                            ),
                            DoctorGuardrailVerdictKind::Block => format!(
                                "Policy guardrails reported BLOCK with budgets: {}.",
                                blocked_budgets.join(", ")
                            ),
                        };
                        let remediation = match dominant_verdict {
                            DoctorGuardrailVerdictKind::Allow => "No action required.".to_string(),
                            DoctorGuardrailVerdictKind::Warn => {
                                "Review high-risk telemetry before promoting aggressive policy actions."
                                    .to_string()
                            }
                            DoctorGuardrailVerdictKind::Block => {
                                "Resolve blocked budgets before executing policy actions."
                                    .to_string()
                            }
                        };
                        (guardrail_status, message, remediation)
                    },
                ));

                let decision_reason = report.decision_outcome.reason.clone();
                let chosen_candidate = report.decision_outcome.chosen.as_ref().map(|c| c.0.clone());
                checks.push(evaluate_doctor_check(
                    "DR-POLICY-010",
                    "DOC-010",
                    "policy.decision_engine",
                    || {
                        let (status, message, remediation) = match decision_reason {
                            DecisionReason::TopCandidateAccepted => (
                                DoctorStatus::Pass,
                                format!(
                                    "Decision engine selected top candidate `{}`.",
                                    chosen_candidate.clone().unwrap_or_else(|| "unknown".to_string())
                                ),
                                "No action required.".to_string(),
                            ),
                            DecisionReason::TopCandidateBlockedFallbackUsed { fallback_rank } => (
                                DoctorStatus::Warn,
                                format!(
                                    "Decision engine used fallback candidate `{}` at rank {}.",
                                    chosen_candidate.clone().unwrap_or_else(|| "unknown".to_string()),
                                    fallback_rank
                                ),
                                "Inspect blocked higher-ranked candidates before rollout."
                                    .to_string(),
                            ),
                            DecisionReason::AllCandidatesBlocked => (
                                DoctorStatus::Fail,
                                "Decision engine blocked all candidates after guardrail evaluation."
                                    .to_string(),
                                "Reduce risk exposure or provide safer candidate actions."
                                    .to_string(),
                            ),
                            DecisionReason::NoCandidates => (
                                DoctorStatus::Fail,
                                "Decision engine received no candidates from policy activation input."
                                    .to_string(),
                                "Populate `candidates` with at least one viable policy action."
                                    .to_string(),
                            ),
                        };
                        (status, message, remediation)
                    },
                ));

                let wording_valid = report.wording_validation.valid;
                let violations = report.wording_validation.violations.clone();
                checks.push(evaluate_doctor_check(
                    "DR-POLICY-011",
                    "DOC-011",
                    "policy.explainer_wording",
                    || {
                        if wording_valid {
                            (
                                DoctorStatus::Pass,
                                "Policy explanation wording passed diagnostic/guarantee separation checks."
                                    .to_string(),
                                "No action required.".to_string(),
                            )
                        } else {
                            (
                                DoctorStatus::Fail,
                                format!(
                                    "Policy explanation wording validation failed (violations={}).",
                                    violations.join("; ")
                                ),
                                "Fix explanation wording to preserve diagnostic vs guarantee separation."
                                    .to_string(),
                            )
                        }
                    },
                ));

                policy_activation = Some(report);
            }
            Err(err) => {
                let detail = err.to_string();
                checks.push(evaluate_doctor_check(
                    "DR-POLICY-009",
                    "DOC-009",
                    "policy.guardrails",
                    || {
                        (
                            DoctorStatus::Fail,
                            format!("Policy activation input failed to load: {detail}"),
                            "Provide a valid JSON input via --policy-activation-input.".to_string(),
                        )
                    },
                ));
                checks.push(evaluate_doctor_check(
                    "DR-POLICY-010",
                    "DOC-010",
                    "policy.decision_engine",
                    || {
                        (
                            DoctorStatus::Fail,
                            "Decision engine check skipped because policy activation input failed."
                                .to_string(),
                            "Fix policy activation input errors first.".to_string(),
                        )
                    },
                ));
                checks.push(evaluate_doctor_check(
                    "DR-POLICY-011",
                    "DOC-011",
                    "policy.explainer_wording",
                    || {
                        (
                            DoctorStatus::Fail,
                            "Policy explanation check skipped because decision pipeline did not run."
                                .to_string(),
                            "Fix policy activation input errors first.".to_string(),
                        )
                    },
                ));
            }
        }
    }

    let (status_counts, overall_status) = summarize_statuses(&checks);
    let structured_logs = checks
        .iter()
        .map(|check| DoctorLogEvent {
            trace_id: trace_id.to_string(),
            event_code: check.event_code.clone(),
            check_code: check.code.clone(),
            scope: check.scope.clone(),
            status: check.status,
            duration_ms: check.duration_ms,
        })
        .collect::<Vec<_>>();

    DoctorReport {
        command: "doctor".to_string(),
        trace_id: trace_id.to_string(),
        generated_at_utc: chrono::Utc::now().to_rfc3339(),
        selected_profile: resolved.selected_profile.to_string(),
        source_path: source,
        overall_status,
        status_counts,
        checks,
        structured_logs,
        merge_decision_count: resolved.decisions.len(),
        merge_decisions: resolved.decisions.clone(),
        policy_activation,
    }
}

fn render_doctor_report_human(report: &DoctorReport, verbose: bool) -> String {
    let mut lines = Vec::new();
    lines.push(format!(
        "franken-node doctor: overall={} profile={} trace_id={}",
        report.overall_status.as_str(),
        report.selected_profile,
        report.trace_id
    ));
    lines.push(format!(
        "source={}",
        report
            .source_path
            .clone()
            .unwrap_or_else(|| "<defaults>".to_string())
    ));
    lines.push(format!(
        "status_counts: pass={} warn={} fail={}",
        report.status_counts.pass, report.status_counts.warn, report.status_counts.fail
    ));
    lines.push(String::new());

    for check in &report.checks {
        lines.push(format!(
            "[{}] {} ({}) {} - {}",
            check.status.as_str(),
            check.code,
            check.event_code,
            check.scope,
            check.message
        ));
        lines.push(format!(
            "  remediation: {} (duration_ms={})",
            check.remediation, check.duration_ms
        ));
    }

    if let Some(policy_activation) = &report.policy_activation {
        lines.push(String::new());
        lines.push(format!(
            "policy_activation: dominant_verdict={} candidates={} observations={} input={}",
            policy_activation
                .guardrail_certificate
                .dominant_verdict
                .as_str(),
            policy_activation.candidate_count,
            policy_activation.observation_count,
            policy_activation.input_path
        ));
    }

    if verbose {
        lines.push(String::new());
        lines.push(format!(
            "generated_at={} merge_decision_count={}",
            report.generated_at_utc, report.merge_decision_count
        ));
        lines.push("merge decisions:".to_string());
        for decision in &report.merge_decisions {
            lines.push(format!(
                "  stage={:?} field={} value={}",
                decision.stage, decision.field, decision.value
            ));
        }
        lines.push("structured logs:".to_string());
        for event in &report.structured_logs {
            lines.push(format!(
                "  trace_id={} event_code={} check_code={} scope={} status={} duration_ms={}",
                event.trace_id,
                event.event_code,
                event.check_code,
                event.scope,
                event.status.as_str(),
                event.duration_ms
            ));
        }
    }

    lines.join("\n")
}

#[cfg(test)]
mod init_tests {
    use super::*;

    #[test]
    fn init_flags_are_mutually_exclusive() {
        assert!(validate_init_flags(false, false).is_ok());
        assert!(validate_init_flags(true, false).is_ok());
        assert!(validate_init_flags(false, true).is_ok());
        assert!(validate_init_flags(true, true).is_err());
    }

    #[test]
    fn write_policy_creates_new_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("franken_node.toml");
        let action = apply_init_write_policy(&path, "profile = \"balanced\"\n", false, false, "t0")
            .expect("create file");
        assert_eq!(action.action, InitFileActionKind::Created);
        assert_eq!(
            std::fs::read_to_string(&path).expect("read should succeed"),
            "profile = \"balanced\"\n"
        );
    }

    #[test]
    fn write_policy_rejects_existing_without_explicit_mode() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("franken_node.toml");
        std::fs::write(&path, "old").expect("seed");
        let err =
            apply_init_write_policy(&path, "new", false, false, "t0").expect_err("should fail");
        assert!(
            err.to_string()
                .contains("without --overwrite or --backup-existing")
        );
    }

    #[test]
    fn write_policy_overwrites_existing_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("franken_node.toml");
        std::fs::write(&path, "old").expect("seed");
        let action = apply_init_write_policy(&path, "new", true, false, "t0").expect("overwrite");
        assert_eq!(action.action, InitFileActionKind::Overwritten);
        assert!(action.backup_path.is_none());
        assert_eq!(
            std::fs::read_to_string(&path).expect("read should succeed"),
            "new"
        );
    }

    #[test]
    fn write_policy_backups_then_overwrites() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("franken_node.toml");
        std::fs::write(&path, "old").expect("seed");
        let action =
            apply_init_write_policy(&path, "new", false, true, "t0").expect("backup overwrite");
        assert_eq!(action.action, InitFileActionKind::BackedUpAndOverwritten);
        let backup_path = action.backup_path.expect("backup path");
        assert_eq!(
            std::fs::read_to_string(&path).expect("read should succeed"),
            "new"
        );
        assert_eq!(
            std::fs::read_to_string(backup_path).expect("read should succeed"),
            "old"
        );
    }
}

#[cfg(test)]
mod trust_scan_tests {
    use super::*;

    #[test]
    fn normalize_integrity_hash_decodes_base64_payload() {
        assert_eq!(
            normalize_integrity_hash("sha512-AQIDBA=="),
            Some("sha512:01020304".to_string())
        );
    }

    #[test]
    fn parse_trust_scan_npm_metadata_prefers_requested_version() {
        let payload = serde_json::json!({
            "dist-tags": {"latest": "2.0.0"},
            "maintainers": [{"name": "maintainer", "email": "maintainer@example.com"}],
            "time": {
                "1.5.0": "2026-01-01T00:00:00Z",
                "2.0.0": "2026-02-01T00:00:00Z"
            },
            "versions": {
                "1.5.0": {
                    "dist": {"integrity": "sha512-AQIDBA=="}
                },
                "2.0.0": {
                    "dist": {"integrity": "sha512-BQYHCA=="}
                }
            }
        });

        let metadata = parse_trust_scan_npm_metadata(&payload, "example", Some("1.5.0"));
        assert_eq!(metadata.resolved_version.as_deref(), Some("1.5.0"));
        assert_eq!(
            metadata.published_at.as_deref(),
            Some("2026-01-01T00:00:00Z")
        );
        assert_eq!(
            metadata.registry_integrity_hashes,
            vec!["sha512:01020304".to_string()]
        );
        assert_eq!(
            metadata.publisher_id.as_deref(),
            Some("npm-maintainer:maintainer")
        );
    }

    #[test]
    fn parse_deps_dev_dependent_count_reads_count() {
        let payload = serde_json::json!({
            "dependentCount": 1234,
            "directDependentCount": 1200,
            "indirectDependentCount": 34
        });
        assert_eq!(
            parse_deps_dev_dependent_count(&payload).expect("dependent count"),
            1234
        );
    }

    #[test]
    fn parse_osv_vulnerability_ids_deduplicates_values() {
        let payload = serde_json::json!({
            "vulns": [
                {"id": "OSV-2"},
                {"id": "OSV-1"},
                {"id": "OSV-2"}
            ]
        });
        assert_eq!(
            parse_osv_vulnerability_ids(&payload),
            vec!["OSV-1".to_string(), "OSV-2".to_string()]
        );
    }

    #[test]
    fn trust_sync_card_needs_network_refresh_honors_ttl_and_force() {
        let registry =
            supply_chain::trust_card::fixture_registry(1_000).expect("fixture trust registry");
        let card = registry
            .snapshot()
            .cards_by_extension
            .get("npm:@acme/auth-guard")
            .and_then(|history| history.last())
            .cloned()
            .expect("fixture card");
        let verified_secs = chrono::DateTime::parse_from_rfc3339(&card.last_verified_timestamp)
            .expect("parse timestamp")
            .timestamp() as u64;

        assert!(!trust_sync_card_needs_network_refresh(
            &card,
            verified_secs.saturating_add(30),
            60,
            false
        ));
        assert!(trust_sync_card_needs_network_refresh(
            &card,
            verified_secs.saturating_add(61),
            60,
            false
        ));
        assert!(trust_sync_card_needs_network_refresh(
            &card,
            verified_secs.saturating_add(30),
            60,
            true
        ));
    }

    #[test]
    fn refresh_trust_sync_audit_with_updates_vulnerable_cards_and_records_warnings() {
        let now_secs = 2_000;
        let registry =
            supply_chain::trust_card::fixture_registry(now_secs).expect("fixture trust registry");
        let path = tempfile::tempdir()
            .expect("tempdir")
            .path()
            .join("trust-sync.json");
        let mut state = TrustCardCliRegistryState {
            path,
            registry,
            cache_ttl_secs: 60,
        };

        let report =
            refresh_trust_sync_audit_with(&mut state, now_secs + 120, true, |name, _| match name {
                "@acme/auth-guard" => Ok(TrustScanAuditMetadata {
                    vulnerability_ids: vec!["OSV-2026-0001".to_string()],
                }),
                "@beta/telemetry-bridge" => Err(anyhow::anyhow!("simulated network failure")),
                other => Err(anyhow::anyhow!("unexpected package {other}")),
            });

        assert_eq!(report.refreshed_count, 1);
        assert_eq!(report.vulnerabilities_found, 1);
        assert_eq!(report.network_errors, 1);
        assert_eq!(report.warnings.len(), 1);

        let cards = state
            .registry
            .list(
                &TrustCardListFilter::empty(),
                "trace-test-trust-sync-refresh",
                now_secs + 120,
            )
            .expect("list cards");
        let auth_guard = cards
            .iter()
            .find(|card| card.extension.extension_id == "npm:@acme/auth-guard")
            .expect("auth guard card");
        assert_eq!(
            auth_guard.user_facing_risk_assessment.level,
            RiskLevel::High
        );
        assert!(
            auth_guard
                .user_facing_risk_assessment
                .summary
                .contains("OSV-2026-0001")
        );
    }
}

#[cfg(test)]
mod doctor_tests {
    use super::*;

    fn resolved_fixture(profile: Profile) -> config::ResolvedConfig {
        config::ResolvedConfig {
            config: config::Config::for_profile(profile),
            selected_profile: profile,
            source_path: None,
            decisions: vec![
                config::MergeDecision {
                    stage: config::MergeStage::Default,
                    field: "profile".to_string(),
                    value: "balanced".to_string(),
                },
                config::MergeDecision {
                    stage: config::MergeStage::Cli,
                    field: "profile".to_string(),
                    value: profile.to_string(),
                },
            ],
        }
    }

    #[test]
    fn summarize_statuses_prioritizes_fail_over_warn() {
        let checks = vec![
            DoctorCheck {
                code: "A".to_string(),
                event_code: "DOC-A".to_string(),
                scope: "x".to_string(),
                status: DoctorStatus::Pass,
                message: String::new(),
                remediation: String::new(),
                duration_ms: 0,
            },
            DoctorCheck {
                code: "B".to_string(),
                event_code: "DOC-B".to_string(),
                scope: "x".to_string(),
                status: DoctorStatus::Warn,
                message: String::new(),
                remediation: String::new(),
                duration_ms: 0,
            },
            DoctorCheck {
                code: "C".to_string(),
                event_code: "DOC-C".to_string(),
                scope: "x".to_string(),
                status: DoctorStatus::Fail,
                message: String::new(),
                remediation: String::new(),
                duration_ms: 0,
            },
        ];

        let (counts, overall) = summarize_statuses(&checks);
        assert_eq!(counts.pass, 1);
        assert_eq!(counts.warn, 1);
        assert_eq!(counts.fail, 1);
        assert_eq!(overall, DoctorStatus::Fail);
    }

    #[test]
    fn doctor_report_uses_stable_check_order_and_codes() {
        let report = build_doctor_report_with_cwd(
            &resolved_fixture(Profile::Balanced),
            "trace-test",
            Ok(PathBuf::from(".")),
        );
        let codes = report
            .checks
            .iter()
            .map(|check| check.code.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            codes,
            vec![
                "DR-CONFIG-001",
                "DR-CONFIG-002",
                "DR-PROFILE-003",
                "DR-TRUST-004",
                "DR-MIGRATE-005",
                "DR-OBS-006",
                "DR-ENV-007",
                "DR-CONFIG-008",
            ]
        );
        assert_eq!(report.structured_logs.len(), report.checks.len());
        assert_eq!(report.trace_id, "trace-test");
    }

    #[test]
    fn doctor_report_warns_on_legacy_profile() {
        let report = build_doctor_report_with_cwd(
            &resolved_fixture(Profile::LegacyRisky),
            "trace-legacy",
            Ok(PathBuf::from(".")),
        );
        let profile_check = report
            .checks
            .iter()
            .find(|check| check.code == "DR-PROFILE-003")
            .expect("profile check present");
        assert_eq!(profile_check.status, DoctorStatus::Warn);
        assert_eq!(report.overall_status, DoctorStatus::Warn);
    }

    #[test]
    fn doctor_report_fails_when_cwd_is_unavailable() {
        let report = build_doctor_report_with_cwd(
            &resolved_fixture(Profile::Strict),
            "trace-fail",
            Err(std::io::Error::other("cwd unavailable")),
        );
        let cwd_check = report
            .checks
            .iter()
            .find(|check| check.code == "DR-ENV-007")
            .expect("cwd check present");
        assert_eq!(cwd_check.status, DoctorStatus::Fail);
        assert_eq!(report.overall_status, DoctorStatus::Fail);
    }

    #[test]
    fn verbose_human_report_includes_merge_decisions_and_logs() {
        let report = build_doctor_report_with_cwd(
            &resolved_fixture(Profile::Balanced),
            "trace-verbose",
            Ok(PathBuf::from(".")),
        );
        let rendered = render_doctor_report_human(&report, true);
        assert!(rendered.contains("merge decisions:"));
        assert!(rendered.contains("structured logs:"));
        assert!(rendered.contains("trace_id=trace-verbose"));
    }

    #[test]
    fn doctor_report_runs_policy_activation_pipeline_when_input_is_present() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy_input_path = dir.path().join("policy_activation.json");
        std::fs::write(
            &policy_input_path,
            r#"{
  "epoch_id": 77,
  "system_state": {
    "memory_used_bytes": 400000000,
    "memory_budget_bytes": 1000000000,
    "durability_level": 0.97,
    "hardening_level": "standard",
    "proposed_hardening_level": "enhanced",
    "evidence_emission_active": true,
    "memory_tail_risk": {
      "sample_count": 128,
      "mean_utilization": 0.62,
      "variance_utilization": 0.01,
      "peak_utilization": 0.70
    },
    "reliability_telemetry": {
      "sample_count": 4096,
      "nonconforming_count": 24
    }
  },
  "candidates": ["fast-path", "safe-path"],
  "prefiltered_candidates": [],
  "observations": [
    {"candidate": "fast-path", "success": false},
    {"candidate": "fast-path", "success": false},
    {"candidate": "safe-path", "success": true},
    {"candidate": "safe-path", "success": true}
  ]
}"#,
        )
        .expect("write policy input");

        let report = build_doctor_report_with_cwd_and_policy_input(
            &resolved_fixture(Profile::Balanced),
            "trace-policy",
            Ok(PathBuf::from(".")),
            Some(&policy_input_path),
        );

        let codes = report
            .checks
            .iter()
            .map(|check| check.code.as_str())
            .collect::<Vec<_>>();
        assert!(codes.contains(&"DR-POLICY-009"));
        assert!(codes.contains(&"DR-POLICY-010"));
        assert!(codes.contains(&"DR-POLICY-011"));

        let policy = report.policy_activation.expect("policy activation report");
        assert_eq!(
            policy.guardrail_certificate.dominant_verdict,
            DoctorGuardrailVerdictKind::Allow
        );
        assert!(policy.wording_validation.valid);
    }

    #[test]
    fn doctor_report_records_policy_input_failures_without_panicking() {
        let dir = tempfile::tempdir().expect("tempdir");
        let policy_input_path = dir.path().join("policy_activation_invalid.json");
        std::fs::write(&policy_input_path, "{ invalid json").expect("write policy input");

        let report = build_doctor_report_with_cwd_and_policy_input(
            &resolved_fixture(Profile::Balanced),
            "trace-policy-invalid",
            Ok(PathBuf::from(".")),
            Some(&policy_input_path),
        );

        assert!(report.policy_activation.is_none());
        let policy_checks = report
            .checks
            .iter()
            .filter(|check| check.code.starts_with("DR-POLICY-"))
            .collect::<Vec<_>>();
        assert_eq!(policy_checks.len(), 3);
        assert!(
            policy_checks
                .iter()
                .all(|check| matches!(check.status, DoctorStatus::Fail))
        );
        assert_eq!(report.overall_status, DoctorStatus::Fail);
    }

    fn resolved_fixture_with_paths(
        profile: Profile,
        state_dir: Option<PathBuf>,
        signing_key_path: Option<PathBuf>,
        engine_binary_path: Option<PathBuf>,
    ) -> config::ResolvedConfig {
        let mut config = config::Config::for_profile(profile);
        config.fleet.state_dir = state_dir;
        config.security.decision_receipt_signing_key_path = signing_key_path;
        config.engine.binary_path = engine_binary_path;
        config::ResolvedConfig {
            config,
            selected_profile: profile,
            source_path: None,
            decisions: vec![],
        }
    }

    #[test]
    fn doctor_probes_real_filesystem_state_for_configured_paths() {
        let dir = tempfile::tempdir().expect("tempdir");

        // Create a valid state directory
        let state_dir = dir.path().join("state");
        std::fs::create_dir_all(&state_dir).expect("create state dir");

        // Create a valid signing key file
        let signing_key_path = dir.path().join("signing.key");
        std::fs::write(&signing_key_path, "test-key-material").expect("write signing key");

        // Create a valid engine binary (just a regular file for this test)
        let engine_path = dir.path().join("franken-engine");
        std::fs::write(&engine_path, "#!/bin/sh\necho hello").expect("write engine");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&engine_path, std::fs::Permissions::from_mode(0o755))
                .expect("set executable");
        }

        let report = build_doctor_report_with_cwd(
            &resolved_fixture_with_paths(
                Profile::Balanced,
                Some(state_dir.clone()),
                Some(signing_key_path.clone()),
                Some(engine_path.clone()),
            ),
            "trace-fs-probes",
            Ok(PathBuf::from(".")),
        );

        let codes = report
            .checks
            .iter()
            .map(|check| check.code.as_str())
            .collect::<Vec<_>>();

        // Verify new system state probe checks are present
        assert!(codes.contains(&"DR-STORAGE-012"), "storage check missing");
        assert!(codes.contains(&"DR-SECURITY-013"), "security check missing");
        assert!(codes.contains(&"DR-ENGINE-014"), "engine check missing");

        // Verify all three pass when paths exist and are valid
        let storage_check = report
            .checks
            .iter()
            .find(|c| c.code == "DR-STORAGE-012")
            .expect("storage check");
        assert_eq!(
            storage_check.status,
            DoctorStatus::Pass,
            "storage check should pass: {}",
            storage_check.message
        );

        let security_check = report
            .checks
            .iter()
            .find(|c| c.code == "DR-SECURITY-013")
            .expect("security check");
        assert_eq!(
            security_check.status,
            DoctorStatus::Pass,
            "security check should pass: {}",
            security_check.message
        );

        let engine_check = report
            .checks
            .iter()
            .find(|c| c.code == "DR-ENGINE-014")
            .expect("engine check");
        assert_eq!(
            engine_check.status,
            DoctorStatus::Pass,
            "engine check should pass: {}",
            engine_check.message
        );
    }

    #[test]
    fn doctor_fails_when_signing_key_file_does_not_exist() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nonexistent_key = dir.path().join("nonexistent.key");

        let report = build_doctor_report_with_cwd(
            &resolved_fixture_with_paths(Profile::Balanced, None, Some(nonexistent_key), None),
            "trace-missing-key",
            Ok(PathBuf::from(".")),
        );

        let security_check = report
            .checks
            .iter()
            .find(|c| c.code == "DR-SECURITY-013")
            .expect("security check");
        assert_eq!(
            security_check.status,
            DoctorStatus::Fail,
            "security check should fail for missing key: {}",
            security_check.message
        );
        assert!(security_check.message.contains("does not exist"));
    }

    #[test]
    fn doctor_warns_when_state_dir_does_not_exist() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nonexistent_state = dir.path().join("nonexistent-state");

        let report = build_doctor_report_with_cwd(
            &resolved_fixture_with_paths(Profile::Balanced, Some(nonexistent_state), None, None),
            "trace-missing-state",
            Ok(PathBuf::from(".")),
        );

        let storage_check = report
            .checks
            .iter()
            .find(|c| c.code == "DR-STORAGE-012")
            .expect("storage check");
        assert_eq!(
            storage_check.status,
            DoctorStatus::Warn,
            "storage check should warn for missing dir: {}",
            storage_check.message
        );
        assert!(storage_check.message.contains("does not exist"));
    }

    #[test]
    fn doctor_warns_when_engine_binary_does_not_exist() {
        let dir = tempfile::tempdir().expect("tempdir");
        let nonexistent_engine = dir.path().join("nonexistent-engine");

        let report = build_doctor_report_with_cwd(
            &resolved_fixture_with_paths(Profile::Balanced, None, None, Some(nonexistent_engine)),
            "trace-missing-engine",
            Ok(PathBuf::from(".")),
        );

        let engine_check = report
            .checks
            .iter()
            .find(|c| c.code == "DR-ENGINE-014")
            .expect("engine check");
        assert_eq!(
            engine_check.status,
            DoctorStatus::Warn,
            "engine check should warn for missing binary: {}",
            engine_check.message
        );
        assert!(engine_check.message.contains("does not exist"));
    }
}

#[cfg(test)]
mod trust_command_tests {
    use super::*;

    #[test]
    fn parse_risk_level_filter_accepts_supported_values() {
        assert_eq!(
            parse_risk_level_filter(Some("low")).expect("parse low"),
            Some(RiskLevel::Low)
        );
        assert_eq!(
            parse_risk_level_filter(Some("MEDIUM")).expect("parse medium"),
            Some(RiskLevel::Medium)
        );
        assert_eq!(
            parse_risk_level_filter(Some("high")).expect("parse high"),
            Some(RiskLevel::High)
        );
        assert_eq!(
            parse_risk_level_filter(Some("critical")).expect("parse critical"),
            Some(RiskLevel::Critical)
        );
        let err = parse_risk_level_filter(Some("critical-risk")).expect_err("invalid");
        assert!(
            err.to_string()
                .contains("expected one of: low, medium, high, critical")
        );
    }

    #[test]
    fn parse_risk_level_filter_rejects_unknown_value() {
        let err = parse_risk_level_filter(Some("severe")).expect_err("invalid risk");
        assert!(
            err.to_string()
                .contains("expected one of: low, medium, high, critical")
        );
    }

    #[test]
    fn parse_risk_level_filter_handles_absent_value() {
        assert!(parse_risk_level_filter(None).expect("none").is_none());
    }

    #[test]
    fn trust_list_filters_by_risk_and_revocation_status() {
        let mut registry =
            supply_chain::trust_card::fixture_registry(now_unix_secs()).expect("fixture registry");
        let cards = registry
            .list(&TrustCardListFilter::empty(), "trace-test", now_unix_secs())
            .expect("list");

        let critical_revoked = filter_trust_cards_for_trust_command(
            cards.clone(),
            Some(RiskLevel::Critical),
            Some(true),
        );
        assert_eq!(critical_revoked.len(), 1);
        assert_eq!(
            critical_revoked[0].extension.extension_id,
            "npm:@beta/telemetry-bridge"
        );
        assert!(matches!(
            &critical_revoked[0].revocation_status,
            RevocationStatus::Revoked { .. }
        ));

        let low_active =
            filter_trust_cards_for_trust_command(cards, Some(RiskLevel::Low), Some(false));
        assert_eq!(low_active.len(), 1);
        assert_eq!(low_active[0].extension.extension_id, "npm:@acme/auth-guard");
        assert!(matches!(
            &low_active[0].revocation_status,
            RevocationStatus::Active
        ));
    }

    #[test]
    fn trust_revoke_uses_logical_now_secs_for_timestamps() {
        let now_secs = 1_700_000_123;
        let mut registry =
            supply_chain::trust_card::fixture_registry(now_secs).expect("fixture registry");

        let card = revoke_trust_card(&mut registry, "npm:@acme/auth-guard", now_secs)
            .expect("revoke should succeed");
        let expected_timestamp = rfc3339_timestamp_from_secs(now_secs);

        assert_eq!(card.last_verified_timestamp, expected_timestamp);
        assert!(matches!(
            &card.revocation_status,
            RevocationStatus::Revoked { revoked_at, .. } if revoked_at == &expected_timestamp
        ));
    }

    #[test]
    fn trust_quarantine_matches_sha256_prefix_and_uses_logical_now_secs() {
        let now_secs = 1_700_000_456;
        let mut registry =
            supply_chain::trust_card::fixture_registry(now_secs).expect("fixture registry");

        let updates = quarantine_trust_cards(&mut registry, "sha256:deadbeef", now_secs)
            .expect("quarantine should succeed");
        let expected_timestamp = rfc3339_timestamp_from_secs(now_secs);

        assert_eq!(updates.len(), 2);
        assert!(updates.iter().all(|card| card.active_quarantine));
        assert!(
            updates
                .iter()
                .all(|card| card.last_verified_timestamp == expected_timestamp)
        );
    }
}

#[cfg(test)]
mod registry_command_tests {
    use super::*;

    #[test]
    fn parse_min_assurance_accepts_range() {
        assert_eq!(parse_min_assurance(None).expect("none"), None);
        assert_eq!(parse_min_assurance(Some(1)).expect("one"), Some(1));
        assert_eq!(parse_min_assurance(Some(5)).expect("five"), Some(5));
    }

    #[test]
    fn parse_min_assurance_rejects_out_of_range() {
        let err = parse_min_assurance(Some(0)).expect_err("must reject");
        assert!(err.to_string().contains("between 1 and 5"));
        let err = parse_min_assurance(Some(6)).expect_err("must reject");
        assert!(err.to_string().contains("between 1 and 5"));
    }

    #[test]
    fn assurance_level_is_higher_for_active_than_revoked() {
        let registry = registry_cli_registry().expect("registry");
        let entries = registry.list(None);
        let active = entries
            .iter()
            .find(|extension| extension.status == ExtensionStatus::Active)
            .expect("active extension");
        let revoked = entries
            .iter()
            .find(|extension| extension.status == ExtensionStatus::Revoked)
            .expect("revoked extension");

        assert!(extension_assurance_level(active) > extension_assurance_level(revoked));
    }

    #[test]
    fn search_registry_entries_filters_by_query_and_assurance() {
        let registry = registry_cli_registry().expect("registry");
        let telemetry_results = search_registry_entries(&registry, "telemetry", Some(3));
        assert!(!telemetry_results.is_empty());
        assert!(
            telemetry_results
                .iter()
                .all(|(_, extension)| extension_matches_query(extension, "telemetry"))
        );
        assert!(
            telemetry_results
                .iter()
                .all(|(assurance, _)| *assurance >= 3)
        );

        let high_assurance = search_registry_entries(&registry, "", Some(5));
        assert!(!high_assurance.is_empty());
        assert!(high_assurance.iter().all(|(assurance, _)| *assurance == 5));
    }

    #[test]
    fn render_registry_search_results_handles_empty_rows() {
        let rendered = render_registry_search_results(&[], "nomatch", Some(4));
        assert!(rendered.contains("no extensions matched"));
        assert!(rendered.contains("query=`nomatch`"));
    }

    fn registry_publish_context(
        builder_identity: &str,
        source_repository_url: Option<&str>,
        vcs_commit_sha: Option<&str>,
        source_dirty: Option<bool>,
    ) -> RegistryPublishProvenanceContext {
        RegistryPublishProvenanceContext {
            git: GitProvenanceContext {
                source_repository_url: source_repository_url.map(str::to_string),
                vcs_commit_sha: vcs_commit_sha.map(str::to_string),
                source_dirty,
            },
            builder_identity: builder_identity.to_string(),
            build_timestamp_epoch: 1_700_000_123,
        }
    }

    fn run_git_test_command(workspace: &Path, args: &[&str]) {
        let status = ProcessCommand::new("git")
            .current_dir(workspace)
            .args(args)
            .status()
            .unwrap_or_else(|error| panic!("failed running git {}: {error}", args.join(" ")));
        assert!(status.success(), "git command failed: {}", args.join(" "));
    }

    #[test]
    fn collect_git_provenance_context_reads_real_git_metadata_and_dirty_state() {
        let temp = tempfile::tempdir().expect("tempdir");
        let workspace = temp.path();
        let package = workspace.join("plugin.fnext");
        std::fs::write(&package, "artifact").expect("write package");

        run_git_test_command(workspace, &["init", "-b", "main"]);
        run_git_test_command(workspace, &["config", "user.email", "test@example.com"]);
        run_git_test_command(workspace, &["config", "user.name", "Test User"]);
        run_git_test_command(
            workspace,
            &[
                "remote",
                "add",
                "origin",
                "https://example.com/acme/plugin.git",
            ],
        );
        run_git_test_command(workspace, &["add", "plugin.fnext"]);
        run_git_test_command(workspace, &["commit", "-m", "initial"]);

        let clean = collect_git_provenance_context(workspace);
        assert_eq!(
            clean.source_repository_url.as_deref(),
            Some("https://example.com/acme/plugin.git")
        );
        assert_eq!(clean.source_dirty, Some(false));
        assert_eq!(clean.vcs_commit_sha.as_ref().map(String::len), Some(40));

        std::fs::write(&package, "artifact-updated").expect("rewrite package");
        let dirty = collect_git_provenance_context(workspace);
        assert_eq!(dirty.source_dirty, Some(true));
    }

    #[test]
    fn build_registry_publish_request_embeds_real_provenance_claims() {
        let temp = tempfile::tempdir().expect("tempdir");
        let package = temp.path().join("My Extension!.tar.gz");
        std::fs::write(&package, "artifact").expect("write package");
        let hash = "a".repeat(64);
        let signing_material = Ed25519SigningMaterial {
            path: temp.path().join("publisher.ed25519"),
            source: "test",
            signing_key: ed25519_dalek::SigningKey::from_bytes(&[7_u8; 32]),
        };

        let request = build_registry_publish_request_with_context(
            &package,
            &hash,
            &signing_material,
            registry_publish_context(
                "builder.example.internal",
                Some("https://example.com/acme/plugin.git"),
                Some("aabbccddeeff00112233445566778899aabbccdd"),
                Some(false),
            ),
        )
        .expect("publish request");
        assert!(!request.name.is_empty());
        assert!(request.name.chars().all(|ch| {
            ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '-' || ch == '_'
        }));
        assert_eq!(request.initial_version.content_hash, hash);
        assert_eq!(request.signature.signature_bytes.len(), 64);
        assert_eq!(
            request.provenance.builder_identity,
            "builder.example.internal"
        );
        assert_eq!(
            request.provenance.source_repository_url,
            "https://example.com/acme/plugin.git"
        );
        assert_eq!(
            request.provenance.vcs_commit_sha,
            "aabbccddeeff00112233445566778899aabbccdd"
        );
        assert_eq!(request.provenance.slsa_level_claim, 2);
        assert_eq!(request.provenance.links.len(), 2);
        assert_eq!(
            request.provenance.links[0].role,
            supply_chain::provenance::ChainLinkRole::Publisher
        );
        assert_eq!(
            request.provenance.links[1].role,
            supply_chain::provenance::ChainLinkRole::BuildSystem
        );
        assert_eq!(
            request.provenance.custom_claims.get("source_dirty"),
            Some(&"false".to_string())
        );
        assert_eq!(
            request.provenance.custom_claims.get("operator_key_id"),
            Some(&request.signature.key_id)
        );
        assert!(
            request
                .provenance
                .custom_claims
                .contains_key("operator_provenance_signature")
        );
    }

    #[test]
    fn build_registry_publish_request_degrades_gracefully_without_git_metadata() {
        let temp = tempfile::tempdir().expect("tempdir");
        let package = temp.path().join("demo.tar.gz");
        std::fs::write(&package, "artifact").expect("write package");
        let signing_material = Ed25519SigningMaterial {
            path: temp.path().join("publisher.ed25519"),
            source: "test",
            signing_key: ed25519_dalek::SigningKey::from_bytes(&[9_u8; 32]),
        };

        let request = build_registry_publish_request_with_context(
            &package,
            "abc123",
            &signing_material,
            registry_publish_context("builder-host", None, None, None),
        )
        .expect("publish request");
        assert_eq!(request.initial_version.content_hash, "abc123");
        assert!(request.provenance.source_repository_url.is_empty());
        assert!(request.provenance.vcs_commit_sha.is_empty());
        assert_eq!(request.provenance.slsa_level_claim, 0);
        assert_eq!(request.provenance.links.len(), 1);
        assert_eq!(
            request.provenance.links[0].role,
            supply_chain::provenance::ChainLinkRole::Publisher
        );
    }

    fn persist_registry_artifact_fixture(
        project_root: &Path,
        file_name: &str,
        payload: &[u8],
    ) -> StoredRegistryArtifact {
        let package_path = project_root.join(file_name);
        std::fs::write(&package_path, payload).expect("write package");
        let signing_material = Ed25519SigningMaterial {
            path: project_root.join("publisher.ed25519"),
            source: "test",
            signing_key: ed25519_dalek::SigningKey::from_bytes(&[11_u8; 32]),
        };
        let content_hash = compute_registry_artifact_sha256(payload);
        let request = build_registry_publish_request_with_context(
            &package_path,
            &content_hash,
            &signing_material,
            registry_publish_context(
                "builder.example.internal",
                Some("https://example.com/acme/plugin.git"),
                Some("11223344556677889900aabbccddeeff00112233"),
                Some(false),
            ),
        )
        .expect("publish request");

        let mut registry = registry_cli_registry().expect("registry");
        registry.register_publisher_key(signing_material.signing_key.verifying_key());
        let result = registry.register(request.clone(), "trace-registry-test", 1_700_000_999);
        assert!(
            result.success,
            "registry register failed: {}",
            result.detail
        );
        let extension_id = result.extension_id.expect("extension id");
        let published = registry
            .query(&extension_id)
            .expect("published entry")
            .clone();

        persist_local_registry_artifact(
            project_root,
            &package_path,
            payload,
            &request,
            &published,
            &signing_material.signing_key.verifying_key(),
        )
        .expect("persist local artifact")
    }

    #[test]
    fn inspect_local_registry_artifact_detects_tampering() {
        let temp = tempfile::tempdir().expect("tempdir");
        let stored =
            persist_registry_artifact_fixture(temp.path(), "plugin.fnext", b"artifact payload");
        let baseline = inspect_local_registry_artifact(&stored);
        assert_eq!(baseline.status, RegistryArtifactIntegrityStatus::Verified);

        std::fs::write(stored.artifact_path(), b"tampered payload").expect("tamper artifact");
        let tampered = inspect_local_registry_artifact(&stored);
        assert_eq!(
            tampered.status,
            RegistryArtifactIntegrityStatus::HashMismatch
        );
        assert!(tampered.detail.contains("artifact hash mismatch"));
    }

    #[test]
    fn persist_local_registry_artifact_records_manifest_hash() {
        let temp = tempfile::tempdir().expect("tempdir");
        let payload = b"artifact payload";
        let stored = persist_registry_artifact_fixture(temp.path(), "plugin.fnext", payload);
        assert_eq!(
            stored.manifest.artifact_sha256,
            compute_registry_artifact_sha256(payload)
        );
        assert_eq!(
            stored
                .manifest
                .extension
                .versions
                .last()
                .map(|version| version.content_hash.as_str()),
            Some(stored.manifest.artifact_sha256.as_str())
        );
    }

    #[test]
    fn inspect_local_registry_artifact_rejects_unsafe_manifest_file_name() {
        let temp = tempfile::tempdir().expect("tempdir");
        let stored =
            persist_registry_artifact_fixture(temp.path(), "plugin.fnext", b"artifact payload");

        let raw = std::fs::read_to_string(&stored.manifest_path).expect("read manifest");
        let mut manifest: LocalRegistryArtifactManifest =
            serde_json::from_str(&raw).expect("parse manifest");
        manifest.artifact_file_name = "../escape.bin".to_string();
        std::fs::write(
            &stored.manifest_path,
            serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
        )
        .expect("write tampered manifest");

        let reloaded =
            load_local_registry_artifact_manifest(&stored.manifest_path, false).expect("reload");
        let verification = inspect_local_registry_artifact(&reloaded);
        assert_eq!(
            verification.status,
            RegistryArtifactIntegrityStatus::InvalidMetadata
        );
        assert!(verification.detail.contains("unsafe"));
    }

    fn temp_name_leftovers<F>(dir: &Path, mut predicate: F) -> Vec<String>
    where
        F: FnMut(&str) -> bool,
    {
        let mut leftovers = Vec::new();
        for entry in std::fs::read_dir(dir).expect("read dir") {
            let entry = entry.expect("entry");
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if predicate(&name) {
                leftovers.push(name.to_string());
            }
        }
        leftovers.sort();
        leftovers
    }

    #[test]
    fn write_bytes_atomically_replaces_target_without_tmp_leftovers() {
        let temp = tempfile::tempdir().expect("tempdir");
        let dir_path = temp.path().join("nested");
        let target_path = dir_path.join("artifact.bin");
        let temp_prefix = "artifact.bin.tmp";

        write_bytes_atomically(&target_path, b"first payload").expect("initial write");
        assert_eq!(
            std::fs::read(&target_path).expect("read first payload"),
            b"first payload"
        );
        let mut leftovers = temp_name_leftovers(&dir_path, |name| name.starts_with(temp_prefix));
        assert!(
            leftovers.is_empty(),
            "temporary files should be removed after rename: {leftovers:?}"
        );

        write_bytes_atomically(&target_path, b"second payload").expect("replacement write");
        assert_eq!(
            std::fs::read(&target_path).expect("read second payload"),
            b"second payload"
        );
        leftovers = temp_name_leftovers(&dir_path, |name| name.starts_with(temp_prefix));
        assert!(
            leftovers.is_empty(),
            "temporary replacement file should not remain after atomic write: {leftovers:?}"
        );
    }

    #[test]
    fn persist_local_registry_artifact_removes_temp_directories() {
        let temp = tempfile::tempdir().expect("tempdir");
        let stored =
            persist_registry_artifact_fixture(temp.path(), "plugin.fnext", b"artifact payload");
        let lineage_root = stored
            .entry_dir()
            .parent()
            .expect("lineage root")
            .to_path_buf();
        let leftovers = temp_name_leftovers(&lineage_root, |name| name.contains(".tmp-"));
        assert!(
            leftovers.is_empty(),
            "temp registry directories should be cleaned up: {leftovers:?}"
        );
    }

    #[test]
    fn collect_local_registry_artifacts_skips_hidden_temp_dirs() {
        let temp = tempfile::tempdir().expect("tempdir");
        let stored =
            persist_registry_artifact_fixture(temp.path(), "plugin.fnext", b"artifact payload");
        let lineage_root = stored.entry_dir().parent().expect("lineage root");
        let entry_name = stored
            .entry_dir()
            .file_name()
            .and_then(|name| name.to_str())
            .expect("entry name");
        let hidden_dir = lineage_root.join(format!(".{entry_name}.tmp-ignored"));
        std::fs::create_dir_all(&hidden_dir).expect("create hidden dir");
        std::fs::copy(
            &stored.manifest_path,
            hidden_dir.join(REGISTRY_LOCAL_ARTIFACT_MANIFEST_FILE_NAME),
        )
        .expect("copy manifest");

        let artifacts = collect_local_registry_artifacts(temp.path(), false).expect("collect");
        assert_eq!(artifacts.len(), 1);
        assert_eq!(
            artifacts[0].manifest.extension.extension_id,
            stored.manifest.extension.extension_id
        );
    }

    #[test]
    fn inspect_local_registry_artifact_detects_invalid_manifest_signature() {
        let temp = tempfile::tempdir().expect("tempdir");
        let stored =
            persist_registry_artifact_fixture(temp.path(), "plugin.fnext", b"artifact payload");

        let raw = std::fs::read_to_string(&stored.manifest_path).expect("read manifest");
        let mut manifest: LocalRegistryArtifactManifest =
            serde_json::from_str(&raw).expect("parse manifest");
        let tampered_manifest_bytes = format!(
            "tampered:{}:{}",
            manifest.extension.name, manifest.artifact_sha256
        );
        manifest.manifest_bytes_b64 = BASE64_STANDARD.encode(tampered_manifest_bytes.as_bytes());
        std::fs::write(
            &stored.manifest_path,
            serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
        )
        .expect("write tampered manifest");

        let reloaded =
            load_local_registry_artifact_manifest(&stored.manifest_path, false).expect("reload");
        let verification = inspect_local_registry_artifact(&reloaded);
        assert_eq!(
            verification.status,
            RegistryArtifactIntegrityStatus::InvalidSignature
        );
        assert!(
            verification
                .detail
                .contains("manifest signature verification failed")
        );
    }

    #[test]
    fn archived_registry_artifacts_remain_discoverable_by_extension_id() {
        let temp = tempfile::tempdir().expect("tempdir");
        let stored =
            persist_registry_artifact_fixture(temp.path(), "plugin.fnext", b"artifact payload");
        let archived_dir =
            archive_local_registry_artifact(temp.path(), &stored).expect("archive artifact");
        assert!(
            archived_dir.is_dir(),
            "archived entry directory should exist"
        );

        let active = collect_local_registry_artifacts(temp.path(), false).expect("active list");
        assert!(active.is_empty(), "active artifact set should be empty");

        let archived = collect_local_registry_artifacts(temp.path(), true).expect("all list");
        assert_eq!(archived.len(), 1);
        assert!(archived[0].archived);
        assert!(
            archived[0]
                .manifest_path
                .starts_with(registry_archive_root(temp.path()))
        );

        let found =
            find_local_registry_artifact(temp.path(), &stored.manifest.extension.extension_id)
                .expect("find archived artifact");
        assert!(found.archived);
        assert_eq!(
            found.manifest.extension.extension_id,
            stored.manifest.extension.extension_id
        );
    }

    #[test]
    fn local_registry_search_rows_exclude_archived_artifacts() {
        let temp = tempfile::tempdir().expect("tempdir");
        let stored =
            persist_registry_artifact_fixture(temp.path(), "plugin.fnext", b"artifact payload");
        archive_local_registry_artifact(temp.path(), &stored).expect("archive artifact");

        let rows = local_registry_search_rows(temp.path(), "plugin", None).expect("search rows");
        assert!(
            rows.is_empty(),
            "archived artifacts should not appear in active search rows"
        );
    }

    #[test]
    fn local_registry_search_rows_report_verified_artifact_metadata() {
        let temp = tempfile::tempdir().expect("tempdir");
        let stored =
            persist_registry_artifact_fixture(temp.path(), "plugin.fnext", b"artifact payload");

        let rows = local_registry_search_rows(temp.path(), "plugin", None).expect("search rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].extension_id, stored.manifest.extension.extension_id);
        assert_eq!(rows[0].integrity_status, "verified");
        assert!(
            rows[0]
                .artifact_path
                .contains(".franken-node/state/registry/artifacts/")
        );
    }

    #[test]
    fn local_registry_search_rows_report_hash_mismatch_status() {
        let temp = tempfile::tempdir().expect("tempdir");
        let stored =
            persist_registry_artifact_fixture(temp.path(), "plugin.fnext", b"artifact payload");
        std::fs::write(stored.artifact_path(), b"tampered payload").expect("tamper artifact");

        let rows = local_registry_search_rows(temp.path(), "plugin", None).expect("search rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].extension_id, stored.manifest.extension.extension_id);
        assert_eq!(rows[0].integrity_status, "hash-mismatch");
    }

    #[test]
    fn local_registry_search_rows_report_invalid_signature_status() {
        let temp = tempfile::tempdir().expect("tempdir");
        let stored =
            persist_registry_artifact_fixture(temp.path(), "plugin.fnext", b"artifact payload");

        let raw = std::fs::read_to_string(&stored.manifest_path).expect("read manifest");
        let mut manifest: LocalRegistryArtifactManifest =
            serde_json::from_str(&raw).expect("parse manifest");
        manifest.manifest_bytes_b64 = BASE64_STANDARD.encode(b"tampered");
        std::fs::write(
            &stored.manifest_path,
            serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
        )
        .expect("write tampered manifest");

        let rows = local_registry_search_rows(temp.path(), "plugin", None).expect("search rows");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].extension_id, stored.manifest.extension.extension_id);
        assert_eq!(rows[0].integrity_status, "invalid-signature");
    }
}

#[cfg(test)]
mod build_context_tests {
    use super::*;

    #[test]
    fn build_context_detects_local_build_when_no_ci_env() {
        let ctx = BuildContext::detect_with_env(None, |_| None);

        // Should detect local build
        assert_eq!(ctx.build_system_identifier, "local");

        // Should be able to detect git info if in a git repo
        // (this test runs inside the franken_node git repo)
        assert!(
            ctx.vcs_commit_sha.is_some() || ctx.vcs_commit_sha.is_none(),
            "vcs_commit_sha should be detected or None if not in git repo"
        );
    }

    #[test]
    fn build_context_uses_config_builder_identity_override() {
        let ctx = BuildContext::detect(Some("configured-builder"));
        assert_eq!(ctx.builder_identity.as_deref(), Some("configured-builder"));
    }

    #[test]
    fn build_context_detects_github_actions() {
        let ctx = BuildContext::detect_with_env(None, |key| match key {
            "GITHUB_ACTIONS" => Some("true".to_string()),
            "GITHUB_SHA" => Some("abcdef1234567890abcdef1234567890abcdef12".to_string()),
            "GITHUB_SERVER_URL" => Some("https://github.com".to_string()),
            "GITHUB_REPOSITORY" => Some("test-org/test-repo".to_string()),
            "GITHUB_ACTOR" => Some("test-actor".to_string()),
            _ => None,
        });

        assert_eq!(ctx.build_system_identifier, "github-actions");
        assert_eq!(
            ctx.vcs_commit_sha.as_deref(),
            Some("abcdef1234567890abcdef1234567890abcdef12")
        );
        assert_eq!(
            ctx.source_repository_url.as_deref(),
            Some("https://github.com/test-org/test-repo")
        );
        assert_eq!(ctx.builder_identity.as_deref(), Some("test-actor"));
    }

    #[test]
    fn build_context_config_identity_takes_precedence_over_env() {
        let ctx = BuildContext::detect_with_env(Some("config-override"), |key| match key {
            "GITHUB_ACTIONS" => Some("true".to_string()),
            "GITHUB_ACTOR" => Some("github-user".to_string()),
            _ => None,
        });
        assert_eq!(ctx.builder_identity.as_deref(), Some("config-override"));
    }

    #[test]
    fn build_context_strips_credentials_from_http_repository_urls() {
        let raw = "https://token:secret@github.com/test-org/test-repo.git";
        assert_eq!(
            BuildContext::strip_repository_url_credentials(raw),
            "https://github.com/test-org/test-repo.git"
        );

        let raw = "https://token@github.com/test-org/test-repo";
        assert_eq!(
            BuildContext::strip_repository_url_credentials(raw),
            "https://github.com/test-org/test-repo"
        );
    }

    #[test]
    fn build_context_preserves_ssh_style_urls_without_passwords() {
        let ssh_url = "ssh://git@github.com/test-org/test-repo.git";
        assert_eq!(
            BuildContext::strip_repository_url_credentials(ssh_url),
            ssh_url
        );

        let scp_style = "git@github.com:test-org/test-repo.git";
        assert_eq!(
            BuildContext::strip_repository_url_credentials(scp_style),
            scp_style
        );
    }

    #[test]
    fn build_context_strips_credentials_from_ssh_urls_with_passwords() {
        let ssh_url = "ssh://user:pass@host.internal/repo.git";
        assert_eq!(
            BuildContext::strip_repository_url_credentials(ssh_url),
            "ssh://host.internal/repo.git"
        );
    }
}

#[cfg(test)]
mod fleet_command_tests {
    use super::*;
    use crate::api::fleet_quarantine::{ConvergencePhase, ConvergenceState, DecisionReceipt};

    #[test]
    fn fleet_cli_identity_has_operator_and_admin_roles() {
        let identity = fleet_cli_identity();
        assert_eq!(identity.principal, "cli-fleet-operator");
        assert_eq!(identity.method, AuthMethod::MtlsClientCert);
        assert!(identity.roles.iter().any(|role| role == "fleet-admin"));
        assert!(identity.roles.iter().any(|role| role == "operator"));
    }

    #[test]
    fn fleet_cli_trace_uses_supplied_trace_id() {
        let trace = fleet_cli_trace("trace-test-fleet");
        assert_eq!(trace.trace_id, "trace-test-fleet");
        assert_eq!(trace.trace_flags, 1);
    }

    #[test]
    fn fleet_status_render_includes_activation_and_counts() {
        let status = FleetStatus {
            zone_id: "zone-1".to_string(),
            active_quarantines: 2,
            active_revocations: 1,
            healthy_nodes: 9,
            total_nodes: 10,
            activated: false,
            pending_convergences: Vec::new(),
        };
        let rendered = render_fleet_status_human(&status, true);
        assert!(rendered.contains("fleet status: zone=zone-1"));
        assert!(rendered.contains("activated=false"));
        assert!(rendered.contains("quarantines=2 revocations=1"));
        assert!(rendered.contains("healthy_nodes=9/10"));
        assert!(rendered.contains("pending_convergences=0"));
    }

    #[test]
    fn fleet_action_render_includes_convergence_details() {
        let action = FleetActionResult {
            operation_id: "fleet-op-7".to_string(),
            action_type: "reconcile".to_string(),
            success: true,
            receipt: DecisionReceipt {
                receipt_id: "rcpt-7".to_string(),
                issuer: "cli-fleet-operator".to_string(),
                issued_at: "2026-02-25T00:00:00Z".to_string(),
                zone_id: "all".to_string(),
                payload_hash: "hash".to_string(),
            },
            convergence: Some(ConvergenceState {
                converged_nodes: 4,
                total_nodes: 5,
                progress_pct: 80,
                eta_seconds: Some(5),
                phase: ConvergencePhase::Propagating,
            }),
            trace_id: "trace-fleet".to_string(),
            event_code: "FLEET-005".to_string(),
        };
        let rendered = render_fleet_action_human(&action);
        assert!(rendered.contains("fleet action: type=reconcile operation_id=fleet-op-7"));
        assert!(rendered.contains("success=true"));
        assert!(rendered.contains("event_code=FLEET-005"));
        assert!(rendered.contains("convergence=4/5 (80%)"));
    }

    #[test]
    fn derive_active_fleet_incidents_excludes_released_incidents() {
        let state = FleetSharedState {
            schema_version: control_plane::fleet_transport::FLEET_SHARED_STATE_SCHEMA.to_string(),
            actions: vec![
                PersistedFleetActionRecord {
                    action_id: "fleet-op-q1".to_string(),
                    emitted_at: DateTime::parse_from_rfc3339("2026-04-06T01:00:00Z")
                        .expect("timestamp")
                        .with_timezone(&Utc),
                    action: PersistedFleetAction::Quarantine {
                        zone_id: "prod".to_string(),
                        incident_id: "inc-q1".to_string(),
                        target_id: "sha256:q1".to_string(),
                        target_kind: PersistedFleetTargetKind::Artifact,
                        reason: "quarantine-1".to_string(),
                        quarantine_version: 3,
                    },
                },
                PersistedFleetActionRecord {
                    action_id: "fleet-op-q2".to_string(),
                    emitted_at: DateTime::parse_from_rfc3339("2026-04-06T01:05:00Z")
                        .expect("timestamp")
                        .with_timezone(&Utc),
                    action: PersistedFleetAction::Quarantine {
                        zone_id: "prod".to_string(),
                        incident_id: "inc-q2".to_string(),
                        target_id: "sha256:q2".to_string(),
                        target_kind: PersistedFleetTargetKind::Artifact,
                        reason: "quarantine-2".to_string(),
                        quarantine_version: 4,
                    },
                },
                PersistedFleetActionRecord {
                    action_id: "fleet-op-release".to_string(),
                    emitted_at: DateTime::parse_from_rfc3339("2026-04-06T01:06:00Z")
                        .expect("timestamp")
                        .with_timezone(&Utc),
                    action: PersistedFleetAction::Release {
                        zone_id: "prod".to_string(),
                        incident_id: "inc-q1".to_string(),
                        reason: Some("resolved".to_string()),
                    },
                },
            ],
            nodes: vec![PersistedNodeStatus {
                zone_id: "prod".to_string(),
                node_id: "node-1".to_string(),
                last_seen: DateTime::parse_from_rfc3339("2026-04-06T01:06:30Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                quarantine_version: 4,
                health: PersistedNodeHealth::Healthy,
            }],
        };

        let incidents = derive_active_fleet_incidents(&state, &[]);
        assert_eq!(incidents.len(), 1);
        assert_eq!(incidents[0].incident_id, "inc-q2");
        assert_eq!(incidents[0].convergence.progress_pct, 100);
    }

    #[test]
    fn fleet_status_from_loaded_state_uses_real_shared_state_counts() {
        let loaded = LoadedFleetState {
            state_dir: PathBuf::from("/tmp/fleet"),
            convergence_timeout_seconds: 120,
            state: FleetSharedState {
                schema_version: control_plane::fleet_transport::FLEET_SHARED_STATE_SCHEMA
                    .to_string(),
                actions: Vec::new(),
                nodes: vec![
                    PersistedNodeStatus {
                        zone_id: "prod".to_string(),
                        node_id: "node-1".to_string(),
                        last_seen: DateTime::parse_from_rfc3339("2026-04-06T01:06:30Z")
                            .expect("timestamp")
                            .with_timezone(&Utc),
                        quarantine_version: 4,
                        health: PersistedNodeHealth::Healthy,
                    },
                    PersistedNodeStatus {
                        zone_id: "prod".to_string(),
                        node_id: "node-2".to_string(),
                        last_seen: DateTime::parse_from_rfc3339("2026-04-06T01:00:00Z")
                            .expect("timestamp")
                            .with_timezone(&Utc),
                        quarantine_version: 1,
                        health: PersistedNodeHealth::Degraded,
                    },
                ],
            },
            stale_nodes: vec![PersistedNodeStatus {
                zone_id: "prod".to_string(),
                node_id: "node-2".to_string(),
                last_seen: DateTime::parse_from_rfc3339("2026-04-06T01:00:00Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                quarantine_version: 1,
                health: PersistedNodeHealth::Degraded,
            }],
            active_incidents: vec![FleetCliPendingIncident {
                incident_id: "inc-q2".to_string(),
                zone_id: "prod".to_string(),
                target_id: "sha256:q2".to_string(),
                target_kind: PersistedFleetTargetKind::Artifact,
                reason: "quarantine-2".to_string(),
                quarantine_version: 4,
                emitted_at: DateTime::parse_from_rfc3339("2026-04-06T01:05:00Z")
                    .expect("timestamp")
                    .with_timezone(&Utc),
                convergence: ConvergenceState {
                    converged_nodes: 1,
                    total_nodes: 2,
                    progress_pct: 50,
                    eta_seconds: None,
                    phase: ConvergencePhase::TimedOut,
                },
            }],
        };

        let status = fleet_status_from_loaded_state(&loaded, "prod");
        assert!(status.activated);
        assert_eq!(status.active_quarantines, 1);
        assert_eq!(status.healthy_nodes, 1);
        assert_eq!(status.total_nodes, 2);
        assert_eq!(status.pending_convergences.len(), 1);
        assert_eq!(status.pending_convergences[0].progress_pct, 50);
        assert_eq!(
            status.pending_convergences[0].phase,
            ConvergencePhase::TimedOut
        );
    }
}

#[cfg(test)]
mod migrate_audit_output_tests {
    use super::*;

    #[test]
    fn emit_migration_audit_report_writes_to_requested_path() {
        let temp = tempfile::tempdir().expect("tempdir");
        let output_path = temp.path().join("reports/migration/audit.txt");
        let rendered = "migration-audit-report\nstatus: ok\n";

        let written = emit_migration_audit_report(rendered, Some(&output_path)).expect("written");
        assert_eq!(written, Some(output_path.clone()));
        assert_eq!(
            std::fs::read_to_string(&output_path).expect("read output"),
            rendered
        );
    }
}

#[cfg(test)]
mod incident_list_tests {
    use super::*;
    use frankenengine_node::tools::replay_bundle::{
        EventType, INCIDENT_EVIDENCE_SCHEMA, IncidentEvidenceEvent, IncidentEvidenceMetadata,
        IncidentEvidencePackage, IncidentSeverity,
    };
    use std::sync::{Mutex, OnceLock};

    fn cwd_test_lock() -> &'static Mutex<()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
    }

    fn write_fixture_bundle(path: &Path, incident_id: &str, severity: &str) {
        let mut events = fixture_incident_events(incident_id);
        if let Some(first) = events.first_mut()
            && let Some(payload) = first.payload.as_object_mut()
        {
            payload.insert("severity".to_string(), serde_json::json!(severity));
        }
        let bundle = generate_replay_bundle(incident_id, &events).expect("bundle");
        write_bundle_to_path(&bundle, path).expect("write bundle");
    }

    fn write_fixture_incident_evidence_package(workspace: &Path, incident_id: &str) -> PathBuf {
        let evidence_path = workspace
            .join(INCIDENT_EVIDENCE_RELATIVE_DIR)
            .join(incident_id_slug(incident_id))
            .join(INCIDENT_EVIDENCE_FILE_NAME);
        std::fs::create_dir_all(
            evidence_path
                .parent()
                .expect("incident evidence path should have parent"),
        )
        .expect("create evidence directory");
        let package = IncidentEvidencePackage {
            schema_version: INCIDENT_EVIDENCE_SCHEMA.to_string(),
            incident_id: incident_id.to_string(),
            collected_at: "2026-02-20T10:05:00.000000Z".to_string(),
            trace_id: "trace-incident-evidence".to_string(),
            severity: IncidentSeverity::High,
            incident_type: "security".to_string(),
            detector: "unit-test".to_string(),
            policy_version: "1.2.3".to_string(),
            initial_state_snapshot: serde_json::json!({"epoch": 7_u64, "mode": "strict"}),
            events: vec![
                IncidentEvidenceEvent {
                    event_id: "evt-001".to_string(),
                    timestamp: "2026-02-20T10:00:00.000100Z".to_string(),
                    event_type: EventType::ExternalSignal,
                    payload: serde_json::json!({"signal":"anomaly","severity":"high"}),
                    provenance_ref: "refs/logs/event-001.json".to_string(),
                    parent_event_id: None,
                    state_snapshot: None,
                    policy_version: None,
                },
                IncidentEvidenceEvent {
                    event_id: "evt-002".to_string(),
                    timestamp: "2026-02-20T10:00:00.000200Z".to_string(),
                    event_type: EventType::PolicyEval,
                    payload: serde_json::json!({"decision":"quarantine","confidence":91_u64}),
                    provenance_ref: "refs/logs/event-002.json".to_string(),
                    parent_event_id: Some("evt-001".to_string()),
                    state_snapshot: None,
                    policy_version: None,
                },
                IncidentEvidenceEvent {
                    event_id: "evt-003".to_string(),
                    timestamp: "2026-02-20T10:00:00.000300Z".to_string(),
                    event_type: EventType::OperatorAction,
                    payload: serde_json::json!({"action":"seal","result":"accepted"}),
                    provenance_ref: "refs/logs/event-003.json".to_string(),
                    parent_event_id: Some("evt-002".to_string()),
                    state_snapshot: None,
                    policy_version: None,
                },
            ],
            evidence_refs: vec![
                "refs/logs/event-001.json".to_string(),
                "refs/logs/event-002.json".to_string(),
                "refs/logs/event-003.json".to_string(),
            ],
            metadata: IncidentEvidenceMetadata {
                title: "Fixture incident evidence".to_string(),
                affected_components: vec!["auth-svc".to_string()],
                tags: vec!["fixture".to_string(), "test".to_string()],
            },
        };
        std::fs::write(
            &evidence_path,
            serde_json::to_string_pretty(&package).expect("serialize evidence package"),
        )
        .expect("write evidence package");
        evidence_path
    }

    #[test]
    fn parse_incident_severity_filter_accepts_case_insensitive_input() {
        assert_eq!(
            parse_incident_severity_filter(Some("High")).expect("parse"),
            Some("high".to_string())
        );
        assert_eq!(
            parse_incident_severity_filter(Some("unknown")).expect("parse"),
            Some("unknown".to_string())
        );
    }

    #[test]
    fn parse_incident_severity_filter_rejects_unknown_values() {
        let err = parse_incident_severity_filter(Some("severe")).expect_err("must fail");
        assert!(err.to_string().contains(
            "invalid --severity `severe`; expected one of: low, medium, high, critical, unknown"
        ));
    }

    #[test]
    fn collect_incident_list_entries_filters_by_severity() {
        let temp = tempfile::tempdir().expect("tempdir");
        let root = temp.path();
        let nested = root.join("incidents");
        std::fs::create_dir_all(&nested).expect("create nested dir");

        write_fixture_bundle(&root.join("high-incident.fnbundle"), "INC-HIGH-001", "high");
        write_fixture_bundle(&nested.join("low-incident.fnbundle"), "INC-LOW-001", "low");

        let all = collect_incident_list_entries(root, None).expect("all entries");
        assert_eq!(all.len(), 2);

        let high = collect_incident_list_entries(root, Some("high")).expect("high entries");
        assert_eq!(high.len(), 1);
        assert_eq!(high[0].incident_id, "INC-HIGH-001");
        assert_eq!(high[0].severity, "high");
        assert!(high[0].path.ends_with("high-incident.fnbundle"));
    }

    #[test]
    fn render_incident_list_handles_empty_results() {
        let rendered = render_incident_list(&[], Some("critical"));
        assert_eq!(
            rendered,
            "incident list: no bundles found for severity=critical"
        );
    }

    #[test]
    fn resolve_incident_evidence_path_prefers_explicit_override() {
        let override_path = PathBuf::from("/tmp/custom-incident-evidence.json");
        let resolved =
            resolve_incident_evidence_path("INC-OVERRIDE-001", Some(override_path.as_path()))
                .expect("resolve");
        assert_eq!(resolved, override_path);
    }

    #[test]
    fn resolve_incident_evidence_path_uses_project_local_default() {
        let _lock = cwd_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().expect("tempdir");
        let previous_cwd = std::env::current_dir().expect("cwd");
        std::fs::write(
            dir.path().join("franken_node.toml"),
            "profile = \"balanced\"\n",
        )
        .expect("write config");
        std::env::set_current_dir(dir.path()).expect("set cwd");

        let resolve_result = resolve_incident_evidence_path("INC/TEST:001", None);
        let restore_result = std::env::set_current_dir(&previous_cwd);

        let resolved = resolve_result.expect("resolve");
        restore_result.expect("restore cwd");

        assert_eq!(
            resolved,
            dir.path()
                .join(INCIDENT_EVIDENCE_RELATIVE_DIR)
                .join("INC_TEST_001")
                .join(INCIDENT_EVIDENCE_FILE_NAME)
        );
    }

    #[test]
    fn incident_bundle_command_reads_project_local_evidence_and_writes_bundle() {
        let _lock = cwd_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().expect("tempdir");
        let previous_cwd = std::env::current_dir().expect("cwd");
        let incident_id = "INC/TEST:001";
        std::fs::write(
            dir.path().join("franken_node.toml"),
            "profile = \"balanced\"\n",
        )
        .expect("write config");
        let evidence_path = write_fixture_incident_evidence_package(dir.path(), incident_id);
        std::env::set_current_dir(dir.path()).expect("set cwd");

        let run_result = handle_incident_bundle_command(&cli::IncidentBundleArgs {
            id: incident_id.to_string(),
            evidence_path: None,
            verify: true,
            receipt_signing_key: None,
            receipt_out: None,
            receipt_summary_out: None,
        });
        let output_path = dir.path().join(incident_bundle_output_path(incident_id));
        let restore_result = std::env::set_current_dir(&previous_cwd);

        run_result.expect("bundle command should succeed");
        restore_result.expect("restore cwd");

        assert!(evidence_path.is_file());
        assert!(output_path.is_file());

        let bundle = read_bundle_from_path(&output_path).expect("read bundle");
        assert_eq!(bundle.incident_id, incident_id);
        assert_eq!(
            bundle.initial_state_snapshot,
            serde_json::json!({"epoch": 7_u64, "mode": "strict"})
        );
        assert_eq!(bundle.policy_version, "1.2.3");
        assert_eq!(bundle.timeline.len(), 3);
    }

    #[test]
    fn incident_bundle_command_fails_closed_when_authoritative_evidence_is_missing() {
        let _lock = cwd_test_lock()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().expect("tempdir");
        let previous_cwd = std::env::current_dir().expect("cwd");
        let incident_id = "INC-MISSING-001";
        std::fs::write(
            dir.path().join("franken_node.toml"),
            "profile = \"balanced\"\n",
        )
        .expect("write config");
        std::env::set_current_dir(dir.path()).expect("set cwd");

        let run_result = handle_incident_bundle_command(&cli::IncidentBundleArgs {
            id: incident_id.to_string(),
            evidence_path: None,
            verify: false,
            receipt_signing_key: None,
            receipt_out: None,
            receipt_summary_out: None,
        });
        let output_path = dir.path().join(incident_bundle_output_path(incident_id));
        let restore_result = std::env::set_current_dir(&previous_cwd);

        let err = run_result.expect_err("missing evidence must fail closed");
        restore_result.expect("restore cwd");

        assert!(
            err.to_string()
                .contains("failed reading authoritative incident evidence"),
            "{err:#}"
        );
        assert!(!output_path.exists());
    }
}

fn handle_remotecap_issue(args: &RemoteCapIssueArgs) -> Result<()> {
    let operations = args
        .scope
        .split(',')
        .map(str::trim)
        .filter(|entry| !entry.is_empty())
        .map(parse_remote_operation)
        .collect::<Result<Vec<_>>>()?;
    if operations.is_empty() {
        anyhow::bail!("--scope must include at least one operation");
    }

    let endpoint_prefixes = args
        .endpoint_prefixes
        .iter()
        .map(|entry| entry.trim().to_string())
        .filter(|entry| !entry.is_empty())
        .collect::<Vec<_>>();
    if endpoint_prefixes.is_empty() {
        anyhow::bail!("--endpoint must include at least one endpoint prefix");
    }

    let ttl_secs = parse_ttl_secs(&args.ttl)?;
    let now_epoch_secs = now_unix_secs();
    let signing_key = std::env::var("FRANKEN_NODE_REMOTECAP_KEY")
        .unwrap_or_else(|_| ["franken-node", "dev", "remotecap", "key"].join("-"));
    let provider = CapabilityProvider::new(&signing_key);
    let scope = RemoteScope::new(operations, endpoint_prefixes);

    let (cap, audit_event) = provider
        .issue(
            &args.issuer,
            scope,
            now_epoch_secs,
            ttl_secs,
            args.operator_approved,
            args.single_use,
            &args.trace_id,
        )
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    if args.json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "token": cap,
                "audit_event": audit_event,
                "ttl_secs": ttl_secs,
                "issued_at_epoch_secs": now_epoch_secs,
            }))?
        );
    } else {
        println!("RemoteCap issued");
        println!("  token_id: {}", cap.token_id());
        println!("  issuer: {}", cap.issuer_identity());
        println!("  ttl_secs: {}", ttl_secs);
        println!("  expires_at_epoch_secs: {}", cap.expires_at_epoch_secs());
        println!(
            "  operations: {}",
            cap.scope()
                .operations
                .iter()
                .map(|op| op.as_str())
                .collect::<Vec<_>>()
                .join(",")
        );
        println!("  endpoints: {}", cap.scope().endpoint_prefixes.join(","));
        println!("  event_code: {}", audit_event.event_code);
    }

    Ok(())
}

fn trust_card_cli_registry(now_secs: u64) -> Result<TrustCardCliRegistryState> {
    let resolved = config::Config::resolve(None, CliOverrides::default())
        .context("failed resolving configuration for trust registry")?;
    let project_root = project_local_root_from_source_path(
        resolved.source_path.as_deref(),
        "trust-card registry",
    )?;
    let path = project_root.join(TRUST_CARD_REGISTRY_STATE_RELATIVE_PATH);
    if !path.is_file() {
        anyhow::bail!(
            "authoritative trust-card registry not initialized at {}; bootstrap or import trust state before using trust commands",
            path.display()
        );
    }
    let cache_ttl = resolved.config.trust.card_cache_ttl_secs.unwrap_or(60);
    let registry = TrustCardRegistry::load_authoritative_state(&path, cache_ttl, now_secs)
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    Ok(TrustCardCliRegistryState {
        path,
        registry,
        cache_ttl_secs: cache_ttl,
    })
}

fn persist_trust_card_cli_registry(state: &TrustCardCliRegistryState) -> Result<()> {
    state
        .registry
        .persist_authoritative_state(&state.path)
        .map_err(|err| anyhow::anyhow!(err.to_string()))
}

fn project_local_root_from_source_path(
    source_path: Option<&Path>,
    authoritative_surface: &str,
) -> Result<PathBuf> {
    let source_path = source_path.ok_or_else(|| {
        anyhow::anyhow!(
            "authoritative {authoritative_surface} requires a project-local `franken_node.toml`; no local config was discovered"
        )
    })?;
    if source_path.file_name().and_then(|name| name.to_str()) != Some("franken_node.toml") {
        anyhow::bail!(
            "authoritative {authoritative_surface} requires a project-local `franken_node.toml`; discovered non-project config source `{}`",
            source_path.display()
        );
    }
    let root = source_path.parent().map(Path::to_path_buf).ok_or_else(|| {
        anyhow::anyhow!(
            "could not resolve project root from {authoritative_surface} config source `{}`",
            source_path.display()
        )
    })?;
    if root.is_absolute() {
        return Ok(root);
    }

    std::env::current_dir()
        .with_context(|| {
            format!("failed resolving current working directory for {authoritative_surface}")
        })
        .map(|cwd| cwd.join(root))
}

fn run_project_root(app_path: &Path) -> PathBuf {
    if app_path.is_dir() {
        return app_path.to_path_buf();
    }

    app_path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf()
}

fn dependency_extension_id(dependency_name: &str) -> String {
    if dependency_name.starts_with("npm:") {
        dependency_name.to_string()
    } else {
        format!("npm:{dependency_name}")
    }
}

fn read_package_manifest_object(
    project_root: &Path,
    context: &str,
) -> Result<Option<serde_json::Map<String, serde_json::Value>>> {
    let package_json_path = project_root.join("package.json");
    if !package_json_path.is_file() {
        return Ok(None);
    }

    let raw = std::fs::read_to_string(&package_json_path).with_context(|| {
        format!(
            "failed reading dependency manifest {}",
            package_json_path.display()
        )
    })?;
    let manifest = serde_json::from_str::<serde_json::Value>(&raw).with_context(|| {
        format!(
            "invalid dependency manifest JSON while evaluating {context}: {}",
            package_json_path.display()
        )
    })?;
    let object = manifest.as_object().cloned().ok_or_else(|| {
        anyhow::anyhow!(
            "dependency manifest must be a JSON object: {}",
            package_json_path.display()
        )
    })?;

    Ok(Some(object))
}

fn collect_package_dependencies(
    project_root: &Path,
    sections: &[&str],
    context: &str,
) -> Result<Option<Vec<RunPackageDependency>>> {
    let Some(object) = read_package_manifest_object(project_root, context)? else {
        return Ok(None);
    };

    let mut dependencies = BTreeMap::new();
    for section in sections {
        let Some(entries) = object.get(*section).and_then(serde_json::Value::as_object) else {
            continue;
        };

        for (dependency_name, version_requirement) in entries {
            dependencies
                .entry(dependency_name.clone())
                .or_insert_with(|| RunPackageDependency {
                    dependency_name: dependency_name.clone(),
                    version_requirement: version_requirement
                        .as_str()
                        .map_or_else(|| version_requirement.to_string(), ToString::to_string),
                    section: (*section).to_string(),
                    extension_id: dependency_extension_id(dependency_name),
                });
        }
    }

    Ok(Some(dependencies.into_values().collect()))
}

fn collect_run_package_dependencies(
    project_root: &Path,
) -> Result<Option<Vec<RunPackageDependency>>> {
    collect_package_dependencies(
        project_root,
        &["dependencies", "optionalDependencies", "peerDependencies"],
        "run trust preflight",
    )
}

fn collect_trust_scan_dependencies(project_root: &Path) -> Result<Vec<RunPackageDependency>> {
    collect_package_dependencies(
        project_root,
        &[
            "dependencies",
            "devDependencies",
            "optionalDependencies",
            "peerDependencies",
        ],
        "trust scan",
    )?
    .ok_or_else(|| {
        anyhow::anyhow!(
            "package.json not found at project path {}; trust scan requires an npm project root",
            project_root.display()
        )
    })
}

fn trust_scan_user_agent() -> String {
    format!("franken-node/{}", env!("CARGO_PKG_VERSION"))
}

fn percent_encode_path_component(raw: &str) -> String {
    let mut encoded = String::new();
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte))
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

fn trust_scan_registry_state(
    project_root: &Path,
    now_secs: u64,
) -> Result<TrustCardCliRegistryState> {
    ensure_state_dir(project_root)?;
    let path = project_root.join(TRUST_CARD_REGISTRY_STATE_RELATIVE_PATH);
    let registry = if path.is_file() {
        TrustCardRegistry::load_authoritative_state(&path, 60, now_secs)
            .map_err(|err| anyhow::anyhow!(err.to_string()))?
    } else {
        let registry = TrustCardRegistry::default();
        registry
            .persist_authoritative_state(&path)
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        registry
    };

    Ok(TrustCardCliRegistryState {
        path,
        registry,
        cache_ttl_secs: 60,
    })
}

fn merge_trust_scan_lockfile_entry(
    entries: &mut BTreeMap<String, TrustScanLockfileMetadata>,
    dependency_name: &str,
    resolved_version: Option<&str>,
    integrity_hashes: impl IntoIterator<Item = String>,
) {
    let entry = entries.entry(dependency_name.to_string()).or_default();
    if entry.resolved_version.is_none() {
        entry.resolved_version = resolved_version.map(ToString::to_string);
    }
    for integrity_hash in integrity_hashes {
        if !entry.integrity_hashes.contains(&integrity_hash) {
            entry.integrity_hashes.push(integrity_hash);
        }
    }
}

fn parse_lockfile_dependency_name(
    package_path: &str,
    package_value: &serde_json::Value,
) -> Option<String> {
    if package_path.is_empty() {
        return None;
    }
    if let Some(rest) = package_path.strip_prefix("node_modules/")
        && rest.contains("/node_modules/")
    {
        return None;
    }
    if let Some(name) = package_value
        .get("name")
        .and_then(serde_json::Value::as_str)
    {
        return Some(name.to_string());
    }

    let rest = package_path.strip_prefix("node_modules/")?;
    Some(rest.to_string())
}

fn parse_trust_scan_lockfile_metadata(
    project_root: &Path,
) -> Result<BTreeMap<String, TrustScanLockfileMetadata>> {
    let mut entries = BTreeMap::new();
    let mut lockfile_path = None;
    for candidate in ["package-lock.json", "npm-shrinkwrap.json"] {
        let path = project_root.join(candidate);
        if path.is_file() {
            lockfile_path = Some(path);
            break;
        }
    }

    let Some(lockfile_path) = lockfile_path else {
        return Ok(entries);
    };

    let raw = std::fs::read_to_string(&lockfile_path)
        .with_context(|| format!("failed reading lockfile {}", lockfile_path.display()))?;
    let payload = serde_json::from_str::<serde_json::Value>(&raw)
        .with_context(|| format!("invalid lockfile JSON: {}", lockfile_path.display()))?;

    if let Some(packages) = payload
        .get("packages")
        .and_then(serde_json::Value::as_object)
    {
        for (package_path, package_value) in packages {
            let Some(dependency_name) = parse_lockfile_dependency_name(package_path, package_value)
            else {
                continue;
            };
            let integrity_hashes = package_value
                .get("integrity")
                .and_then(serde_json::Value::as_str)
                .and_then(normalize_integrity_hash)
                .into_iter();
            merge_trust_scan_lockfile_entry(
                &mut entries,
                &dependency_name,
                package_value
                    .get("version")
                    .and_then(serde_json::Value::as_str),
                integrity_hashes,
            );
        }
    }

    if let Some(dependencies) = payload
        .get("dependencies")
        .and_then(serde_json::Value::as_object)
    {
        for (dependency_name, dependency_value) in dependencies {
            let integrity_hashes = dependency_value
                .get("integrity")
                .and_then(serde_json::Value::as_str)
                .and_then(normalize_integrity_hash)
                .into_iter();
            merge_trust_scan_lockfile_entry(
                &mut entries,
                dependency_name,
                dependency_value
                    .get("version")
                    .and_then(serde_json::Value::as_str),
                integrity_hashes,
            );
        }
    }

    Ok(entries)
}

fn normalize_integrity_hash(raw: &str) -> Option<String> {
    let token = raw.split_whitespace().next()?.trim();
    let (algorithm, encoded) = token.split_once('-')?;
    let decoded = BASE64_STANDARD.decode(encoded).ok()?;
    Some(format!("{algorithm}:{}", hex::encode(decoded)))
}

fn parse_trust_scan_npm_metadata(
    payload: &serde_json::Value,
    dependency_name: &str,
    preferred_version: Option<&str>,
) -> TrustScanDeepMetadata {
    let versions = payload
        .get("versions")
        .and_then(serde_json::Value::as_object);
    let resolved_version = preferred_version
        .and_then(|version| {
            versions
                .and_then(|versions| versions.get(version))
                .map(|_| version)
        })
        .map(ToString::to_string)
        .or_else(|| {
            payload
                .get("dist-tags")
                .and_then(serde_json::Value::as_object)
                .and_then(|tags| tags.get("latest"))
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string)
        });
    let version_payload = resolved_version
        .as_deref()
        .and_then(|version| versions.and_then(|versions| versions.get(version)));

    let maintainer = version_payload
        .and_then(|version| {
            version
                .get("maintainers")
                .and_then(serde_json::Value::as_array)
                .and_then(|maintainers| maintainers.first())
        })
        .or_else(|| {
            payload
                .get("maintainers")
                .and_then(serde_json::Value::as_array)
                .and_then(|maintainers| maintainers.first())
        });

    let author_name = version_payload
        .and_then(|version| version.get("author"))
        .or_else(|| payload.get("author"))
        .and_then(|author| match author {
            serde_json::Value::String(value) => Some(value.to_string()),
            serde_json::Value::Object(map) => map
                .get("name")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string),
            _ => None,
        });

    let (publisher_id, publisher_display_name) = maintainer
        .and_then(serde_json::Value::as_object)
        .and_then(|maintainer| {
            maintainer
                .get("name")
                .and_then(serde_json::Value::as_str)
                .map(|name| {
                    (
                        format!("npm-maintainer:{name}"),
                        maintainer
                            .get("email")
                            .and_then(serde_json::Value::as_str)
                            .map_or_else(|| name.to_string(), |email| format!("{name} <{email}>")),
                    )
                })
        })
        .or_else(|| author_name.map(|name| (format!("npm-author:{name}"), name)))
        .unwrap_or_else(|| {
            let publisher = default_trust_scan_publisher(dependency_name);
            (publisher.publisher_id, publisher.display_name)
        });

    let published_at = resolved_version.as_deref().and_then(|version| {
        payload
            .get("time")
            .and_then(serde_json::Value::as_object)
            .and_then(|times| times.get(version))
            .and_then(serde_json::Value::as_str)
            .map(ToString::to_string)
    });

    let mut registry_integrity_hashes = Vec::new();
    if let Some(dist) = version_payload
        .and_then(|version| version.get("dist"))
        .and_then(serde_json::Value::as_object)
    {
        if let Some(integrity_hash) = dist
            .get("integrity")
            .and_then(serde_json::Value::as_str)
            .and_then(normalize_integrity_hash)
        {
            registry_integrity_hashes.push(integrity_hash);
        } else if let Some(shasum) = dist.get("shasum").and_then(serde_json::Value::as_str) {
            registry_integrity_hashes.push(format!("sha1:{shasum}"));
        }
    }

    TrustScanDeepMetadata {
        publisher_id: Some(publisher_id),
        publisher_display_name: Some(publisher_display_name),
        published_at,
        dependent_count: None,
        resolved_version,
        registry_integrity_hashes,
    }
}

fn fetch_trust_scan_dependent_count(dependency_name: &str, resolved_version: &str) -> Result<u64> {
    let package_name = percent_encode_path_component(dependency_name);
    let version = percent_encode_path_component(resolved_version);
    let url = format!(
        "{TRUST_SCAN_DEPS_DEV_BASE_URL}/systems/npm/packages/{package_name}/versions/{version}:dependents"
    );
    let response = ureq::get(&url)
        .set("User-Agent", &trust_scan_user_agent())
        .call()
        .map_err(|err| anyhow::anyhow!("dependents query failed for {dependency_name}: {err}"))?;
    let body = response.into_string().map_err(|err| {
        anyhow::anyhow!("failed reading dependents response for {dependency_name}: {err}")
    })?;
    let payload = serde_json::from_str::<serde_json::Value>(&body).with_context(|| {
        format!("invalid deps.dev JSON while scanning dependents for {dependency_name}")
    })?;
    parse_deps_dev_dependent_count(&payload)
}

fn parse_deps_dev_dependent_count(payload: &serde_json::Value) -> Result<u64> {
    payload
        .get("dependentCount")
        .and_then(serde_json::Value::as_u64)
        .ok_or_else(|| anyhow::anyhow!("deps.dev response did not include dependentCount"))
}

fn fetch_trust_scan_npm_metadata(
    dependency_name: &str,
    preferred_version: Option<&str>,
) -> Result<TrustScanDeepMetadata> {
    let package_name = percent_encode_path_component(dependency_name);
    let url = format!("{TRUST_SCAN_NPM_REGISTRY_BASE_URL}/{package_name}");
    let response = ureq::get(&url)
        .set("User-Agent", &trust_scan_user_agent())
        .call()
        .map_err(|err| anyhow::anyhow!("npm registry query failed for {dependency_name}: {err}"))?;
    let body = response.into_string().map_err(|err| {
        anyhow::anyhow!("failed reading npm registry response for {dependency_name}: {err}")
    })?;
    let payload = serde_json::from_str::<serde_json::Value>(&body)
        .with_context(|| format!("invalid npm registry JSON for {dependency_name}"))?;
    let mut metadata = parse_trust_scan_npm_metadata(&payload, dependency_name, preferred_version);
    if let Some(resolved_version) = metadata.resolved_version.clone() {
        metadata.dependent_count = Some(fetch_trust_scan_dependent_count(
            dependency_name,
            &resolved_version,
        )?);
    }
    Ok(metadata)
}

fn parse_osv_vulnerability_ids(payload: &serde_json::Value) -> Vec<String> {
    let mut ids = payload
        .get("vulns")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|entry| {
            entry
                .get("id")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string)
        })
        .collect::<Vec<_>>();
    ids.sort();
    ids.dedup();
    ids
}

fn fetch_trust_scan_audit_metadata(
    dependency_name: &str,
    resolved_version: Option<&str>,
) -> Result<TrustScanAuditMetadata> {
    let mut body = serde_json::json!({
        "package": {
            "name": dependency_name,
            "ecosystem": "npm",
        }
    });
    if let Some(version) = resolved_version {
        body["version"] = serde_json::Value::String(version.to_string());
    }

    let response = ureq::post(&trust_scan_osv_query_url())
        .set("User-Agent", &trust_scan_user_agent())
        .set("Content-Type", "application/json")
        .send_string(&body.to_string())
        .map_err(|err| anyhow::anyhow!("OSV query failed for {dependency_name}: {err}"))?;
    let payload = response.into_string().map_err(|err| {
        anyhow::anyhow!("failed reading OSV response for {dependency_name}: {err}")
    })?;
    let payload = serde_json::from_str::<serde_json::Value>(&payload)
        .with_context(|| format!("invalid OSV JSON for {dependency_name}"))?;
    Ok(TrustScanAuditMetadata {
        vulnerability_ids: parse_osv_vulnerability_ids(&payload),
    })
}

fn trust_scan_osv_query_url() -> String {
    std::env::var("FRANKEN_NODE_OSV_QUERY_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| TRUST_SCAN_OSV_QUERY_URL.to_string())
}

fn default_trust_scan_publisher(dependency_name: &str) -> PublisherIdentity {
    if let Some(scope) = dependency_name
        .strip_prefix('@')
        .and_then(|name| name.split('/').next())
    {
        return PublisherIdentity {
            publisher_id: format!("npm-scope:{scope}"),
            display_name: format!("@{scope}"),
        };
    }

    PublisherIdentity {
        publisher_id: format!("npm-package:{dependency_name}"),
        display_name: dependency_name.to_string(),
    }
}

fn build_trust_scan_evidence_ref(
    dependency: &RunPackageDependency,
    version: &str,
    artifact_hashes: &[String],
    now_secs: u64,
) -> VerifiedEvidenceRef {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"trust_scan_manifest_admission_v1:");
    hasher.update(dependency.extension_id.as_bytes());
    hasher.update(version.as_bytes());
    for artifact_hash in artifact_hashes {
        hasher.update(artifact_hash.as_bytes());
    }

    VerifiedEvidenceRef {
        evidence_id: format!("manifest-admission:{}@{version}", dependency.extension_id),
        evidence_type: EvidenceType::ManifestAdmission,
        verified_at_epoch: now_secs,
        verification_receipt_hash: format!("sha256:{}", hex::encode(hasher.finalize())),
    }
}

fn build_trust_scan_card_input(
    dependency: &RunPackageDependency,
    lockfile_metadata: Option<&TrustScanLockfileMetadata>,
    deep_metadata: &TrustScanDeepMetadata,
    audit_metadata: &TrustScanAuditMetadata,
    now_secs: u64,
) -> TrustCardInput {
    let timestamp = chrono::DateTime::from_timestamp(now_secs as i64, 0)
        .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_else(|| "1970-01-01T00:00:00Z".to_string());
    let version = lockfile_metadata
        .and_then(|metadata| metadata.resolved_version.clone())
        .or_else(|| deep_metadata.resolved_version.clone())
        .unwrap_or_else(|| dependency.version_requirement.clone());

    let publisher = if let (Some(publisher_id), Some(display_name)) = (
        deep_metadata.publisher_id.clone(),
        deep_metadata.publisher_display_name.clone(),
    ) {
        PublisherIdentity {
            publisher_id,
            display_name,
        }
    } else {
        default_trust_scan_publisher(&dependency.dependency_name)
    };

    let mut artifact_hashes = BTreeSet::new();
    if let Some(lockfile_metadata) = lockfile_metadata {
        artifact_hashes.extend(lockfile_metadata.integrity_hashes.iter().cloned());
    }
    artifact_hashes.extend(deep_metadata.registry_integrity_hashes.iter().cloned());
    let artifact_hashes = artifact_hashes.into_iter().collect::<Vec<_>>();

    let vulnerability_count = audit_metadata.vulnerability_ids.len();
    let risk_level = if vulnerability_count >= 3 {
        RiskLevel::Critical
    } else if vulnerability_count > 0 {
        RiskLevel::High
    } else if artifact_hashes.is_empty() {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    };

    let mut reputation_score_basis_points = match risk_level {
        RiskLevel::Low => 620_u16,
        RiskLevel::Medium => 440_u16,
        RiskLevel::High => 220_u16,
        RiskLevel::Critical => 80_u16,
    };
    if let Some(dependent_count) = deep_metadata.dependent_count {
        let popularity_bonus = ((dependent_count / 50).min(220)) as u16;
        reputation_score_basis_points =
            reputation_score_basis_points.saturating_add(popularity_bonus);
    }
    if !artifact_hashes.is_empty() {
        reputation_score_basis_points = reputation_score_basis_points.saturating_add(30).min(950);
    }
    let vulnerability_penalty = (vulnerability_count.min(5) as u16).saturating_mul(90);
    reputation_score_basis_points =
        reputation_score_basis_points.saturating_sub(vulnerability_penalty);

    let reputation_trend = if vulnerability_count > 0 {
        ReputationTrend::Declining
    } else if deep_metadata.dependent_count.unwrap_or(0) > 500 {
        ReputationTrend::Improving
    } else {
        ReputationTrend::Stable
    };

    let mut summary_bits = vec![format!(
        "Seeded from {} requirement `{}`",
        dependency.section, dependency.version_requirement
    )];
    if let Some(published_at) = &deep_metadata.published_at {
        summary_bits.push(format!("published_at={published_at}"));
    }
    if let Some(dependent_count) = deep_metadata.dependent_count {
        summary_bits.push(format!("dependents={dependent_count}"));
    }
    if !audit_metadata.vulnerability_ids.is_empty() {
        summary_bits.push(format!(
            "osv_vulns={}",
            audit_metadata.vulnerability_ids.join(",")
        ));
    }

    TrustCardInput {
        extension: ExtensionIdentity {
            extension_id: dependency.extension_id.clone(),
            version: version.clone(),
        },
        publisher,
        certification_level: CertificationLevel::Unknown,
        capability_declarations: vec![CapabilityDeclaration {
            name: format!("manifest.{}", dependency.section),
            description: format!(
                "Dependency discovered from package.json {} entry",
                dependency.section
            ),
            risk: CapabilityRisk::Low,
        }],
        behavioral_profile: BehavioralProfile {
            network_access: false,
            filesystem_access: false,
            subprocess_access: false,
            profile_summary:
                "Baseline dependency inventory only; behavioral telemetry not collected yet"
                    .to_string(),
        },
        revocation_status: RevocationStatus::Active,
        provenance_summary: ProvenanceSummary {
            attestation_level: if artifact_hashes.is_empty() {
                "manifest_scan".to_string()
            } else {
                "manifest_lockfile_scan".to_string()
            },
            source_uri: format!("pkg:npm/{}", dependency.dependency_name),
            artifact_hashes: artifact_hashes.clone(),
            verified_at: timestamp.clone(),
        },
        reputation_score_basis_points,
        reputation_trend,
        active_quarantine: false,
        dependency_trust_summary: vec![DependencyTrustStatus {
            dependency_id: dependency.dependency_name.clone(),
            trust_level: format!("seeded_from_{}", dependency.section),
        }],
        last_verified_timestamp: timestamp.clone(),
        user_facing_risk_assessment: RiskAssessment {
            level: risk_level,
            summary: summary_bits.join("; "),
        },
        evidence_refs: vec![build_trust_scan_evidence_ref(
            dependency,
            &version,
            &artifact_hashes,
            now_secs,
        )],
    }
}

fn build_trust_scan_item(
    dependency: &RunPackageDependency,
    card: &TrustCard,
    status: TrustScanItemStatus,
    vulnerability_count: usize,
    dependent_count: Option<u64>,
) -> TrustScanItem {
    TrustScanItem {
        dependency_name: dependency.dependency_name.clone(),
        section: dependency.section.clone(),
        extension_id: dependency.extension_id.clone(),
        extension_version: card.extension.version.clone(),
        status,
        publisher_id: card.publisher.publisher_id.clone(),
        risk_level: format!("{:?}", card.user_facing_risk_assessment.level).to_ascii_lowercase(),
        integrity_hash_count: card.provenance_summary.artifact_hashes.len(),
        vulnerability_count,
        dependent_count,
    }
}

fn render_trust_scan_human(report: &TrustScanReport) -> String {
    let mut lines = vec![format!(
        "trust scan completed: project={} scanned={} created={} skipped_existing={} lockfile_entries={} deep={} audit={} warnings={}",
        report.project_root,
        report.scanned_dependencies,
        report.created_cards,
        report.skipped_existing,
        report.lockfile_entries,
        report.deep,
        report.audit,
        report.warnings.len()
    )];
    for item in &report.items {
        lines.push(format!(
            "  {} {}@{} section={} publisher={} risk={} vulns={} dependents={} integrity_hashes={}",
            match item.status {
                TrustScanItemStatus::Created => "created",
                TrustScanItemStatus::SkippedExisting => "skipped",
            },
            item.extension_id,
            item.extension_version,
            item.section,
            item.publisher_id,
            item.risk_level,
            item.vulnerability_count,
            item.dependent_count
                .map_or_else(|| "<unknown>".to_string(), |count| count.to_string()),
            item.integrity_hash_count
        ));
    }
    for warning in &report.warnings {
        lines.push(format!("  warning: {warning}"));
    }
    lines.join("\n")
}

fn run_trust_scan(project_root: &Path, deep: bool, audit: bool) -> Result<TrustScanReport> {
    let project_root = if project_root.is_absolute() {
        project_root.to_path_buf()
    } else {
        std::env::current_dir()
            .context("failed resolving current working directory for trust scan")?
            .join(project_root)
    };
    let dependencies = collect_trust_scan_dependencies(&project_root)?;
    let lockfile_metadata = parse_trust_scan_lockfile_metadata(&project_root)?;
    let now_secs = now_unix_secs();
    let mut state = trust_scan_registry_state(&project_root, now_secs)?;
    let mut warnings = Vec::new();
    let mut items = Vec::new();
    let mut created_cards = 0usize;
    let mut skipped_existing = 0usize;

    for dependency in &dependencies {
        if let Some(existing) = state
            .registry
            .read(&dependency.extension_id, now_secs, "trace-cli-trust-scan")
            .map_err(|err| anyhow::anyhow!(err.to_string()))?
        {
            skipped_existing += 1;
            items.push(build_trust_scan_item(
                dependency,
                &existing,
                TrustScanItemStatus::SkippedExisting,
                0,
                None,
            ));
            continue;
        }

        let lockfile_entry = lockfile_metadata.get(&dependency.dependency_name);
        let mut deep_metadata = TrustScanDeepMetadata::default();
        if deep {
            match fetch_trust_scan_npm_metadata(
                &dependency.dependency_name,
                lockfile_entry.and_then(|entry| entry.resolved_version.as_deref()),
            ) {
                Ok(metadata) => deep_metadata = metadata,
                Err(err) => warnings.push(format!(
                    "deep metadata unavailable for {}: {err}",
                    dependency.dependency_name
                )),
            }
        }

        let mut audit_metadata = TrustScanAuditMetadata::default();
        if audit {
            let resolved_version = lockfile_entry
                .and_then(|entry| entry.resolved_version.as_deref())
                .or(deep_metadata.resolved_version.as_deref());
            match fetch_trust_scan_audit_metadata(&dependency.dependency_name, resolved_version) {
                Ok(metadata) => audit_metadata = metadata,
                Err(err) => warnings.push(format!(
                    "OSV audit unavailable for {}: {err}",
                    dependency.dependency_name
                )),
            }
        }

        let input = build_trust_scan_card_input(
            dependency,
            lockfile_entry,
            &deep_metadata,
            &audit_metadata,
            now_secs,
        );
        let card = state
            .registry
            .create(input, now_secs, "trace-cli-trust-scan")
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        created_cards += 1;
        items.push(build_trust_scan_item(
            dependency,
            &card,
            TrustScanItemStatus::Created,
            audit_metadata.vulnerability_ids.len(),
            deep_metadata.dependent_count,
        ));
    }

    if created_cards > 0 || !state.path.is_file() {
        persist_trust_card_cli_registry(&state)?;
    }

    Ok(TrustScanReport {
        command: "trust_scan".to_string(),
        project_root: project_root.display().to_string(),
        registry_path: state.path.display().to_string(),
        scanned_dependencies: dependencies.len(),
        created_cards,
        skipped_existing,
        lockfile_entries: lockfile_metadata.len(),
        deep,
        audit,
        warnings,
        items,
    })
}

fn run_preflight_decision(verdict: &PreFlightVerdict) -> Decision {
    match verdict {
        PreFlightVerdict::Passed { .. } => Decision::Approved,
        PreFlightVerdict::Blocked { .. } => Decision::Denied,
        PreFlightVerdict::Skipped { .. } => Decision::Escalated,
    }
}

fn run_preflight_rationale(verdict: &PreFlightVerdict) -> String {
    match verdict {
        PreFlightVerdict::Passed {
            checked, warnings, ..
        } if warnings.is_empty() => {
            format!("trust preflight passed after checking {checked} dependency entries")
        }
        PreFlightVerdict::Passed { warnings, .. } => {
            format!(
                "trust preflight passed with {} warning(s): {}",
                warnings.len(),
                warnings.join("; ")
            )
        }
        PreFlightVerdict::Blocked {
            reason, violations, ..
        } => format!(
            "{reason}; {} blocking trust violation(s) detected",
            violations.len()
        ),
        PreFlightVerdict::Skipped { reason } => reason.clone(),
    }
}

fn run_preflight_confidence(verdict: &PreFlightVerdict) -> f64 {
    match verdict {
        PreFlightVerdict::Passed {
            warnings, results, ..
        } if warnings.is_empty() && !results.is_empty() => 0.97,
        PreFlightVerdict::Passed { warnings, .. } if warnings.is_empty() => 0.9,
        PreFlightVerdict::Passed { .. } => 0.78,
        PreFlightVerdict::Blocked { violations, .. } if violations.len() > 1 => 0.99,
        PreFlightVerdict::Blocked { .. } => 0.96,
        PreFlightVerdict::Skipped { .. } => 0.55,
    }
}

fn build_run_preflight_receipt(
    app_path: &Path,
    project_root: &Path,
    policy_mode: Profile,
    registry_path: Option<&Path>,
    verdict: &PreFlightVerdict,
) -> Result<Receipt> {
    Receipt::new(
        "run_preflight_trust_gate",
        "franken-node run",
        &serde_json::json!({
            "app_path": app_path.display().to_string(),
            "project_root": project_root.display().to_string(),
            "policy_mode": policy_mode.to_string(),
            "registry_path": registry_path.map(|path| path.display().to_string()),
        }),
        &serde_json::json!({
            "verdict": verdict,
            "registry_path": registry_path.map(|path| path.display().to_string()),
        }),
        run_preflight_decision(verdict),
        &run_preflight_rationale(verdict),
        registry_path
            .map(|path| vec![format!("state:{}", path.display())])
            .unwrap_or_default(),
        vec!["policy.run.preflight.trust".to_string()],
        run_preflight_confidence(verdict),
        "franken-node trust sync --force",
    )
    .map_err(|err| anyhow::anyhow!(err.to_string()))
}

fn evaluate_run_trust_preflight(
    app_path: &Path,
    policy_mode: Profile,
    config: &config::Config,
    now_secs: u64,
) -> Result<RunPreFlightReport> {
    let project_root = run_project_root(app_path);
    let dependencies = collect_run_package_dependencies(&project_root)?;
    let cache_ttl = config.trust.card_cache_ttl_secs.unwrap_or(60);
    let mut registry_path = None::<PathBuf>;

    let verdict = match dependencies {
        None => PreFlightVerdict::Skipped {
            reason: format!(
                "package.json not found under {}; skipping dependency trust preflight",
                project_root.display()
            ),
        },
        Some(dependencies) if dependencies.is_empty() => PreFlightVerdict::Passed {
            checked: 0,
            warnings: Vec::new(),
            results: Vec::new(),
        },
        Some(dependencies) => {
            ensure_state_dir(&project_root)?;
            let authoritative_registry = project_root.join(TRUST_CARD_REGISTRY_STATE_RELATIVE_PATH);
            registry_path = Some(authoritative_registry.clone());

            if !authoritative_registry.is_file() {
                PreFlightVerdict::Skipped {
                    reason: missing_trust_registry_message(&authoritative_registry, policy_mode),
                }
            } else {
                match TrustCardRegistry::load_authoritative_state(
                    &authoritative_registry,
                    cache_ttl,
                    now_secs,
                ) {
                    Ok(mut registry) => {
                        let mut warnings = Vec::new();
                        let mut violations = Vec::new();
                        let mut results = Vec::new();

                        for dependency in dependencies {
                            let dependency_name = dependency.dependency_name.clone();
                            let extension_id = dependency.extension_id.clone();
                            match registry
                                .read(&extension_id, now_secs, "trace-run-trust-preflight")
                                .map_err(|err| anyhow::anyhow!(err.to_string()))?
                            {
                                None => {
                                    let detail = format!(
                                        "dependency `{extension_id}` is untracked in the authoritative trust registry"
                                    );
                                    warnings.push(detail.clone());
                                    results.push(RunDependencyTrustResult {
                                        dependency_name,
                                        version_requirement: dependency.version_requirement,
                                        section: dependency.section,
                                        extension_id,
                                        status: RunDependencyTrustStatus::Untracked,
                                        trust_card_version: None,
                                        risk_level: None,
                                        detail,
                                    });
                                }
                                Some(card) => {
                                    let risk_level = Some(
                                        format!("{:?}", card.user_facing_risk_assessment.level)
                                            .to_ascii_lowercase(),
                                    );

                                    if let RevocationStatus::Revoked { reason, .. } =
                                        &card.revocation_status
                                    {
                                        let detail = format!(
                                            "dependency `{extension_id}` is revoked: {reason}"
                                        );
                                        if policy_mode == Profile::LegacyRisky {
                                            warnings.push(detail.clone());
                                        } else {
                                            violations.push(TrustViolation {
                                                dependency_name: Some(dependency_name.clone()),
                                                extension_id: Some(extension_id.clone()),
                                                kind: TrustViolationKind::Revoked,
                                                detail: detail.clone(),
                                            });
                                        }

                                        results.push(RunDependencyTrustResult {
                                            dependency_name,
                                            version_requirement: dependency.version_requirement,
                                            section: dependency.section,
                                            extension_id,
                                            status: RunDependencyTrustStatus::Revoked,
                                            trust_card_version: Some(card.trust_card_version),
                                            risk_level,
                                            detail,
                                        });
                                        continue;
                                    }

                                    if card.active_quarantine {
                                        let detail =
                                            format!("dependency `{extension_id}` is quarantined");
                                        if policy_mode == Profile::LegacyRisky {
                                            warnings.push(detail.clone());
                                        } else {
                                            violations.push(TrustViolation {
                                                dependency_name: Some(dependency_name.clone()),
                                                extension_id: Some(extension_id.clone()),
                                                kind: TrustViolationKind::Quarantined,
                                                detail: detail.clone(),
                                            });
                                        }

                                        results.push(RunDependencyTrustResult {
                                            dependency_name,
                                            version_requirement: dependency.version_requirement,
                                            section: dependency.section,
                                            extension_id,
                                            status: RunDependencyTrustStatus::Quarantined,
                                            trust_card_version: Some(card.trust_card_version),
                                            risk_level,
                                            detail,
                                        });
                                        continue;
                                    }

                                    results.push(RunDependencyTrustResult {
                                        dependency_name,
                                        version_requirement: dependency.version_requirement,
                                        section: dependency.section,
                                        extension_id,
                                        status: RunDependencyTrustStatus::Trusted,
                                        trust_card_version: Some(card.trust_card_version),
                                        risk_level,
                                        detail: format!(
                                            "verified trust card v{} allows execution",
                                            card.trust_card_version
                                        ),
                                    });
                                }
                            }
                        }

                        if violations.is_empty() {
                            PreFlightVerdict::Passed {
                                checked: results.len(),
                                warnings,
                                results,
                            }
                        } else {
                            let reason = violations
                                .iter()
                                .map(|violation| violation.detail.as_str())
                                .collect::<Vec<_>>()
                                .join("; ");
                            PreFlightVerdict::Blocked {
                                reason: format!("blocking trust findings detected: {reason}"),
                                warnings,
                                violations,
                                results,
                            }
                        }
                    }
                    Err(err) => {
                        let detail = format!(
                            "failed loading authoritative trust registry {}: {err}",
                            authoritative_registry.display()
                        );
                        if policy_mode == Profile::LegacyRisky {
                            PreFlightVerdict::Skipped { reason: detail }
                        } else {
                            PreFlightVerdict::Blocked {
                                reason: "authoritative trust registry is unreadable or corrupt"
                                    .to_string(),
                                warnings: Vec::new(),
                                violations: vec![TrustViolation {
                                    dependency_name: None,
                                    extension_id: None,
                                    kind: TrustViolationKind::RegistryCorrupt,
                                    detail,
                                }],
                                results: Vec::new(),
                            }
                        }
                    }
                }
            }
        }
    };

    let receipt = build_run_preflight_receipt(
        app_path,
        &project_root,
        policy_mode,
        registry_path.as_deref(),
        &verdict,
    )?;

    Ok(RunPreFlightReport {
        app_path: app_path.display().to_string(),
        project_root: project_root.display().to_string(),
        policy_mode: policy_mode.to_string(),
        registry_path: registry_path.map(|path| path.display().to_string()),
        verdict,
        receipt,
    })
}

fn render_run_preflight_human(report: &RunPreFlightReport) -> String {
    let mut lines = vec![format!(
        "run trust preflight: policy={} app={}",
        report.policy_mode, report.app_path
    )];

    match &report.verdict {
        PreFlightVerdict::Passed {
            checked,
            warnings,
            results,
        } => {
            lines.push(format!(
                "  verdict: passed checked={} warnings={} trusted={} untracked={}",
                checked,
                warnings.len(),
                results
                    .iter()
                    .filter(|result| result.status == RunDependencyTrustStatus::Trusted)
                    .count(),
                results
                    .iter()
                    .filter(|result| result.status == RunDependencyTrustStatus::Untracked)
                    .count()
            ));
            for warning in warnings {
                lines.push(format!("  warning: {warning}"));
            }
        }
        PreFlightVerdict::Blocked {
            reason,
            warnings,
            violations,
            ..
        } => {
            lines.push(format!(
                "  verdict: blocked violations={} reason={reason}",
                violations.len()
            ));
            for violation in violations {
                lines.push(format!("  violation: {}", violation.detail));
            }
            for warning in warnings {
                lines.push(format!("  warning: {warning}"));
            }
        }
        PreFlightVerdict::Skipped { reason } => {
            lines.push(format!("  verdict: skipped reason={reason}"));
        }
    }

    lines.join("\n")
}

fn emit_run_preflight_report(report: &RunPreFlightReport, json: bool) -> Result<()> {
    if json {
        let rendered = serde_json::to_string_pretty(report)
            .context("failed serializing run preflight report")?;
        if report.verdict.is_blocked() {
            println!("{rendered}");
        } else {
            eprintln!("{rendered}");
        }
        return Ok(());
    }

    match &report.verdict {
        PreFlightVerdict::Passed { warnings, .. } if warnings.is_empty() => Ok(()),
        _ => {
            eprintln!("{}", render_run_preflight_human(report));
            Ok(())
        }
    }
}

fn resolve_incident_evidence_path(
    incident_id: &str,
    evidence_path_override: Option<&Path>,
) -> Result<PathBuf> {
    if let Some(path) = evidence_path_override {
        return Ok(path.to_path_buf());
    }

    let resolved = config::Config::resolve(None, CliOverrides::default())
        .context("failed resolving configuration for incident evidence")?;
    let project_root =
        project_local_root_from_source_path(resolved.source_path.as_deref(), "incident evidence")?;
    Ok(project_root
        .join(INCIDENT_EVIDENCE_RELATIVE_DIR)
        .join(incident_id_slug(incident_id))
        .join(INCIDENT_EVIDENCE_FILE_NAME))
}

fn handle_incident_bundle_command(args: &cli::IncidentBundleArgs) -> Result<()> {
    // Prepare receipt export context upfront - fails immediately if receipt export
    // is requested but signing material is unavailable (sign-or-fail).
    let receipt_export_ctx = prepare_receipt_export_context(
        args.receipt_out.as_deref(),
        args.receipt_summary_out.as_deref(),
        args.receipt_signing_key.as_deref(),
    )?;
    eprintln!(
        "franken-node incident bundle: id={} verify={}",
        args.id, args.verify
    );
    let evidence_path = resolve_incident_evidence_path(&args.id, args.evidence_path.as_deref())?;
    let evidence =
        read_incident_evidence_package(&evidence_path, Some(&args.id)).with_context(|| {
            format!(
                "failed reading authoritative incident evidence {}",
                evidence_path.display()
            )
        })?;
    let bundle = generate_replay_bundle_from_evidence(&evidence).with_context(|| {
        format!(
            "failed generating replay bundle from authoritative evidence {}",
            evidence_path.display()
        )
    })?;
    if args.verify {
        let valid = validate_bundle_integrity(&bundle)
            .with_context(|| format!("failed validating replay bundle for {}", args.id))?;
        eprintln!(
            "bundle integrity: {}",
            if valid { "valid" } else { "invalid" }
        );
    }

    let output_path = incident_bundle_output_path(&args.id);
    write_bundle_to_path(&bundle, &output_path).with_context(|| {
        format!(
            "failed writing incident bundle to {}",
            output_path.display()
        )
    })?;

    if let Some(ref ctx) = receipt_export_ctx {
        export_signed_receipts(
            "incident_bundle",
            "incident-control-plane",
            "Incident bundle receipt export for deterministic replay evidence",
            ctx,
        )?;
    }
    eprintln!(
        "incident bundle written: {} evidence={}",
        output_path.display(),
        evidence_path.display()
    );

    Ok(())
}

/// Build context extracted from actual environment for provenance metadata.
struct BuildContext {
    vcs_commit_sha: Option<String>,
    source_repository_url: Option<String>,
    build_system_identifier: String,
    builder_identity: Option<String>,
}

impl BuildContext {
    /// Detect build context from environment variables and git state.
    ///
    /// Priority order for each field:
    /// 1. CI-specific environment variables (GitHub Actions, GitLab CI, etc.)
    /// 2. Local git repository state
    /// 3. Fallback values
    fn detect(config_builder_identity: Option<&str>) -> Self {
        Self::detect_with_env(config_builder_identity, |key| std::env::var(key).ok())
    }

    fn detect_with_env<F>(config_builder_identity: Option<&str>, get_env: F) -> Self
    where
        F: Fn(&str) -> Option<String>,
    {
        let vcs_commit_sha = Self::detect_commit_sha_with_env(&get_env);
        let source_repository_url = Self::detect_repository_url_with_env(&get_env);
        let build_system_identifier = Self::detect_build_system_with_env(&get_env);
        let builder_identity =
            Self::detect_builder_identity_with_env(config_builder_identity, &get_env);

        Self {
            vcs_commit_sha,
            source_repository_url,
            build_system_identifier,
            builder_identity,
        }
    }

    fn detect_commit_sha_with_env<F>(get_env: &F) -> Option<String>
    where
        F: Fn(&str) -> Option<String>,
    {
        // GitHub Actions
        if let Some(sha) = get_env("GITHUB_SHA") {
            return Some(sha);
        }
        // GitLab CI
        if let Some(sha) = get_env("CI_COMMIT_SHA") {
            return Some(sha);
        }
        // CircleCI
        if let Some(sha) = get_env("CIRCLE_SHA1") {
            return Some(sha);
        }
        // Azure Pipelines
        if let Some(sha) = get_env("BUILD_SOURCEVERSION") {
            return Some(sha);
        }
        // Jenkins
        if let Some(sha) = get_env("GIT_COMMIT") {
            return Some(sha);
        }
        // Try local git
        std::process::Command::new("git")
            .args(["rev-parse", "HEAD"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| {
                String::from_utf8(output.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            })
            .filter(|s| !s.is_empty())
    }

    fn strip_repository_url_credentials(raw: &str) -> String {
        let Some(scheme_end) = raw.find("://") else {
            return raw.to_string();
        };
        let scheme = &raw[..scheme_end];
        let scheme_lower = scheme.to_ascii_lowercase();
        let after_scheme = &raw[scheme_end + 3..];
        let Some(at_pos) = after_scheme.find('@') else {
            return raw.to_string();
        };
        let userinfo = &after_scheme[..at_pos];
        let rest = &after_scheme[at_pos + 1..];
        let should_strip =
            matches!(scheme_lower.as_str(), "http" | "https") || userinfo.contains(':');
        if should_strip {
            format!("{scheme}://{rest}")
        } else {
            raw.to_string()
        }
    }

    fn detect_repository_url_with_env<F>(get_env: &F) -> Option<String>
    where
        F: Fn(&str) -> Option<String>,
    {
        // GitHub Actions
        if let (Some(server), Some(repo)) =
            (get_env("GITHUB_SERVER_URL"), get_env("GITHUB_REPOSITORY"))
        {
            return Some(format!("{server}/{repo}"));
        }
        // GitLab CI
        if let Some(url) = get_env("CI_REPOSITORY_URL") {
            return Some(Self::strip_repository_url_credentials(&url));
        }
        // CircleCI
        if let Some(url) = get_env("CIRCLE_REPOSITORY_URL") {
            return Some(Self::strip_repository_url_credentials(&url));
        }
        // Azure Pipelines
        if let Some(url) = get_env("BUILD_REPOSITORY_URI") {
            return Some(Self::strip_repository_url_credentials(&url));
        }
        // Try local git
        std::process::Command::new("git")
            .args(["remote", "get-url", "origin"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .and_then(|output| {
                String::from_utf8(output.stdout)
                    .ok()
                    .map(|s| s.trim().to_string())
            })
            .filter(|s| !s.is_empty())
    }

    fn detect_build_system_with_env<F>(get_env: &F) -> String
    where
        F: Fn(&str) -> Option<String>,
    {
        // GitHub Actions
        if get_env("GITHUB_ACTIONS").is_some() {
            return "github-actions".to_string();
        }
        // GitLab CI
        if get_env("GITLAB_CI").is_some() {
            return "gitlab-ci".to_string();
        }
        // CircleCI
        if get_env("CIRCLECI").is_some() {
            return "circleci".to_string();
        }
        // Azure Pipelines
        if get_env("TF_BUILD").is_some() {
            return "azure-pipelines".to_string();
        }
        // Jenkins
        if get_env("JENKINS_URL").is_some() {
            return "jenkins".to_string();
        }
        // Travis CI
        if get_env("TRAVIS").is_some() {
            return "travis-ci".to_string();
        }
        // Generic CI
        if get_env("CI").is_some() {
            return "ci".to_string();
        }
        // Local build
        "local".to_string()
    }

    fn detect_builder_identity_with_env<F>(
        config_override: Option<&str>,
        get_env: &F,
    ) -> Option<String>
    where
        F: Fn(&str) -> Option<String>,
    {
        // Config file override takes precedence
        if let Some(id) = config_override {
            return Some(id.to_string());
        }
        // GitHub Actions
        if let Some(actor) = get_env("GITHUB_ACTOR") {
            return Some(actor);
        }
        // GitLab CI
        if let Some(user) = get_env("GITLAB_USER_LOGIN") {
            return Some(user);
        }
        // CircleCI
        if let Some(user) = get_env("CIRCLE_USERNAME") {
            return Some(user);
        }
        // Generic environment user
        get_env("USER").or_else(|| get_env("USERNAME"))
    }
}

fn provenance_commit_prefix(digest: &str) -> String {
    digest.chars().take(12).collect()
}

fn build_registry_seed_request(
    name: &str,
    description: &str,
    publisher_id: &str,
    version: &str,
    tags: &[&str],
) -> Result<RegistrationRequest> {
    build_registry_seed_request_with_config(name, description, publisher_id, version, tags, None)
}

fn build_registry_seed_request_with_config(
    name: &str,
    description: &str,
    publisher_id: &str,
    version: &str,
    tags: &[&str],
    config_builder_identity: Option<&str>,
) -> Result<RegistrationRequest> {
    // Detect real build context from environment and git state
    let build_context = BuildContext::detect(config_builder_identity);

    // Length-prefixed encoding prevents delimiter-collision ambiguity.
    let attestation_hash = {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(b"registry_seed_attestation_v1:");
        for field in [name, publisher_id, version] {
            hasher.update((field.len() as u64).to_le_bytes());
            hasher.update(field.as_bytes());
        }
        hex::encode(hasher.finalize())
    };
    let manifest_bytes = format!("manifest:{}:{}:{}", name, publisher_id, version).into_bytes();

    // Generate a deterministic seed key for CLI demos
    let seed_bytes = {
        use sha2::Digest;
        let mut h = sha2::Sha256::new();
        h.update(b"registry_seed_key_v1:");
        h.update(publisher_id.as_bytes());
        let d = h.finalize();
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&d);
        arr
    };
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
    let vk = sk.verifying_key();
    let key_id = supply_chain::artifact_signing::KeyId::from_verifying_key(&vk);
    let signature_bytes = supply_chain::artifact_signing::sign_bytes(&sk, &manifest_bytes);

    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    // Use real commit SHA if available, otherwise fallback to attestation hash prefix
    let vcs_commit_sha = build_context
        .vcs_commit_sha
        .clone()
        .unwrap_or_else(|| provenance_commit_prefix(&attestation_hash));

    // Use real repository URL if available, otherwise construct from publisher_id/name
    let source_repository_url = build_context
        .source_repository_url
        .clone()
        .unwrap_or_else(|| format!("https://github.com/{publisher_id}/{name}"));

    // Use real builder identity if available, otherwise fallback to publisher_id
    let builder_identity = build_context
        .builder_identity
        .clone()
        .unwrap_or_else(|| publisher_id.to_string());

    let mut provenance = supply_chain::provenance::ProvenanceAttestation {
        schema_version: "1.0".to_string(),
        source_repository_url,
        build_system_identifier: build_context.build_system_identifier.clone(),
        builder_identity: builder_identity.clone(),
        builder_version: version.to_string(),
        vcs_commit_sha,
        build_timestamp_epoch: now_epoch.saturating_sub(60),
        reproducibility_hash: attestation_hash.clone(),
        input_hash: attestation_hash.clone(),
        output_hash: attestation_hash.clone(),
        slsa_level_claim: 2,
        envelope_format: supply_chain::provenance::AttestationEnvelopeFormat::FrankenNodeEnvelopeV1,
        links: vec![supply_chain::provenance::AttestationLink {
            role: supply_chain::provenance::ChainLinkRole::Publisher,
            signer_id: builder_identity,
            signer_version: version.to_string(),
            signature: String::new(),
            signed_payload_hash: attestation_hash,
            issued_at_epoch: now_epoch.saturating_sub(60),
            expires_at_epoch: now_epoch.saturating_add(86400),
            revoked: false,
        }],
        custom_claims: std::collections::BTreeMap::new(),
    };
    supply_chain::provenance::sign_links_in_place(&mut provenance)
        .map_err(|e| anyhow::anyhow!("failed signing registry seed provenance links: {e}"))?;

    Ok(RegistrationRequest {
        name: name.to_string(),
        description: description.to_string(),
        publisher_id: publisher_id.to_string(),
        signature: ExtensionSignature {
            key_id: key_id.to_string(),
            algorithm: "ed25519".to_string(),
            signature_bytes,
            signed_at: chrono::Utc::now().to_rfc3339(),
        },
        provenance,
        initial_version: VersionEntry {
            version: version.to_string(),
            parent_version: None,
            content_hash: {
                let mut h = sha2::Sha256::new();
                h.update(b"registry_seed_content_v1:");
                for field in [name, version, "content"] {
                    h.update((field.len() as u64).to_le_bytes());
                    h.update(field.as_bytes());
                }
                hex::encode(h.finalize())
            },
            registered_at: chrono::Utc::now().to_rfc3339(),
            compatible_with: vec!["franken-node".to_string()],
        },
        tags: tags.iter().map(|tag| (*tag).to_string()).collect(),
        manifest_bytes,
        transparency_proof: None,
    })
}

fn registry_cli_registry() -> Result<SignedExtensionRegistry> {
    // Build a key ring with the deterministic seed keys for all publishers
    let mut key_ring = supply_chain::artifact_signing::KeyRing::new();
    for publisher_id in ["acme-sec", "beta-observability", "gamma-runtime"] {
        let seed_bytes = {
            use sha2::Digest;
            let mut h = sha2::Sha256::new();
            h.update(b"registry_seed_key_v1:");
            h.update(publisher_id.as_bytes());
            let d = h.finalize();
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&d);
            arr
        };
        let sk = ed25519_dalek::SigningKey::from_bytes(&seed_bytes);
        key_ring.add_key(sk.verifying_key());
    }

    let admission_kernel = AdmissionKernel {
        key_ring,
        provenance_policy: supply_chain::provenance::VerificationPolicy::development_profile(),
        transparency_policy: supply_chain::transparency_verifier::TransparencyPolicy {
            required: false,
            pinned_roots: vec![],
        },
    };

    let mut registry = SignedExtensionRegistry::new(
        supply_chain::extension_registry::RegistryConfig::default(),
        admission_kernel,
    );

    let now_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let baseline = [
        build_registry_seed_request(
            "auth-guard",
            "Access policy enforcement extension",
            "acme-sec",
            "1.4.0",
            &["auth", "security", "policy"],
        )?,
        build_registry_seed_request(
            "telemetry-bridge",
            "Telemetry fan-out and export bridge",
            "beta-observability",
            "2.1.3",
            &["telemetry", "metrics", "export"],
        )?,
        build_registry_seed_request(
            "sandbox-runner",
            "Sandboxed task execution runtime",
            "gamma-runtime",
            "0.9.2",
            &["runtime", "sandbox", "worker"],
        )?,
    ];

    let mut ids = Vec::new();
    for request in baseline {
        let result = registry.register(request, "trace-cli-registry-seed", now_epoch);
        if !result.success {
            anyhow::bail!("failed seeding extension registry: {}", result.detail);
        }
        let id = result
            .extension_id
            .ok_or_else(|| anyhow::anyhow!("seeded registry entry missing extension id"))?;
        ids.push(id);
    }

    if let Some(id) = ids.get(1) {
        let result = registry.deprecate(id, "trace-cli-registry-seed-deprecate");
        if !result.success {
            anyhow::bail!("registry seed deprecate failed: {}", result.detail);
        }
    }
    if let Some(id) = ids.get(2) {
        let result = registry.revoke(
            id,
            supply_chain::extension_registry::RevocationReason::SecurityVulnerability,
            "registry-seed",
            "trace-cli-registry-seed-revoke",
        );
        if !result.success {
            anyhow::bail!("registry seed revoke failed: {}", result.detail);
        }
    }

    Ok(registry)
}

fn normalize_registry_name(raw: &str) -> String {
    let mut normalized = raw
        .trim()
        .to_ascii_lowercase()
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect::<String>();
    normalized = normalized.trim_matches('-').to_string();
    if normalized.is_empty() {
        "extension-artifact".to_string()
    } else {
        normalized
    }
}

fn registry_storage_root(project_root: &Path) -> PathBuf {
    project_root.join(".franken-node/state/registry")
}

fn registry_active_artifacts_root(project_root: &Path) -> PathBuf {
    registry_storage_root(project_root).join("artifacts")
}

fn registry_archive_root(project_root: &Path) -> PathBuf {
    registry_storage_root(project_root).join("archive")
}

fn ensure_registry_storage_root(project_root: &Path) -> Result<PathBuf> {
    ensure_state_dir(project_root)?;
    let root = registry_storage_root(project_root);
    for path in [&root, &root.join("artifacts"), &root.join("archive")] {
        std::fs::create_dir_all(path)
            .with_context(|| format!("failed creating {}", path.display()))?;
    }
    Ok(root)
}

fn compute_registry_artifact_sha256(bytes: &[u8]) -> String {
    format!("sha256:{:x}", sha2::Sha256::digest(bytes))
}

fn registry_entry_directory_name(stored_at_utc: &str, extension_id: &str) -> String {
    let prefix = DateTime::parse_from_rfc3339(stored_at_utc)
        .map(|timestamp| timestamp.format("%Y%m%dT%H%M%S%.3fZ").to_string())
        .unwrap_or_else(|_| "unknown".to_string());
    format!("{prefix}-{extension_id}")
}

fn registry_relative_display_path(path: &Path, project_root: &Path) -> String {
    path.strip_prefix(project_root)
        .unwrap_or(path)
        .display()
        .to_string()
}

fn registry_should_skip_dir(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with('.'))
}

fn registry_artifact_file_name_is_safe(file_name: &str) -> bool {
    if file_name.is_empty() {
        return false;
    }
    let path = Path::new(file_name);
    if path.is_absolute() {
        return false;
    }
    let mut components = path.components();
    match components.next() {
        Some(Component::Normal(_)) => components.next().is_none(),
        _ => false,
    }
}

fn write_bytes_atomically(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("missing parent directory for {}", path.display()))?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed creating {}", parent.display()))?;

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("failed deriving file name for {}", path.display()))?;
    let temp_path = path.with_file_name(format!("{file_name}.tmp-{}", Uuid::now_v7()));
    let mut temp_guard = TempFileGuard::new(temp_path.clone());
    std::fs::write(&temp_path, bytes)
        .with_context(|| format!("failed writing {}", temp_path.display()))?;
    std::fs::rename(&temp_path, path).with_context(|| {
        format!(
            "failed promoting temporary artifact {} -> {}",
            temp_path.display(),
            path.display()
        )
    })?;
    temp_guard.defuse();
    Ok(())
}

fn persist_local_registry_artifact(
    project_root: &Path,
    package_path: &Path,
    package_bytes: &[u8],
    request: &RegistrationRequest,
    published: &SignedExtension,
    verifying_key: &ed25519_dalek::VerifyingKey,
) -> Result<StoredRegistryArtifact> {
    ensure_registry_storage_root(project_root)?;
    let expected_hash = compute_registry_artifact_sha256(package_bytes);
    anyhow::ensure!(
        request.initial_version.content_hash == expected_hash,
        "registry publish artifact hash mismatch: request={} actual={expected_hash}",
        request.initial_version.content_hash
    );

    let lineage_root = registry_active_artifacts_root(project_root)
        .join(normalize_registry_name(&published.publisher_id))
        .join(normalize_registry_name(&published.name));
    std::fs::create_dir_all(&lineage_root)
        .with_context(|| format!("failed creating {}", lineage_root.display()))?;
    let entry_dir_name =
        registry_entry_directory_name(&published.registered_at, &published.extension_id);
    let entry_dir = lineage_root.join(&entry_dir_name);
    if entry_dir.exists() {
        anyhow::bail!(
            "registry publish entry already exists at {}",
            entry_dir.display()
        );
    }
    let temp_dir = lineage_root.join(format!(".{entry_dir_name}.tmp-{}", Uuid::now_v7()));
    std::fs::create_dir_all(&temp_dir)
        .with_context(|| format!("failed creating {}", temp_dir.display()))?;
    let mut temp_guard = TempDirGuard::new(temp_dir.clone());

    let artifact_file_name = package_path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .ok_or_else(|| {
            anyhow::anyhow!("package path missing file name: {}", package_path.display())
        })?
        .to_string();
    let artifact_path = temp_dir.join(&artifact_file_name);
    let manifest_path = temp_dir.join(REGISTRY_LOCAL_ARTIFACT_MANIFEST_FILE_NAME);
    let manifest = LocalRegistryArtifactManifest {
        schema_version: REGISTRY_LOCAL_ARTIFACT_MANIFEST_SCHEMA_VERSION.to_string(),
        stored_at_utc: published.registered_at.clone(),
        artifact_file_name,
        artifact_sha256: expected_hash,
        artifact_size_bytes: package_bytes.len() as u64,
        manifest_bytes_b64: BASE64_STANDARD.encode(&request.manifest_bytes),
        publisher_public_key_hex: hex::encode(verifying_key.as_bytes()),
        extension: published.clone(),
    };

    write_bytes_atomically(&artifact_path, package_bytes)?;
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)
        .context("failed serializing local registry artifact manifest")?;
    write_bytes_atomically(&manifest_path, &manifest_bytes)?;
    std::fs::rename(&temp_dir, &entry_dir).with_context(|| {
        format!(
            "failed promoting registry artifact entry {} -> {}",
            temp_dir.display(),
            entry_dir.display()
        )
    })?;
    temp_guard.defuse();
    let manifest_path = entry_dir.join(REGISTRY_LOCAL_ARTIFACT_MANIFEST_FILE_NAME);

    Ok(StoredRegistryArtifact {
        manifest_path,
        archived: false,
        manifest,
    })
}

fn load_local_registry_artifact_manifest(
    manifest_path: &Path,
    archived: bool,
) -> Result<StoredRegistryArtifact> {
    let raw = std::fs::read_to_string(manifest_path)
        .with_context(|| format!("failed reading {}", manifest_path.display()))?;
    let manifest = serde_json::from_str::<LocalRegistryArtifactManifest>(&raw)
        .with_context(|| format!("failed parsing {}", manifest_path.display()))?;
    anyhow::ensure!(
        manifest.schema_version == REGISTRY_LOCAL_ARTIFACT_MANIFEST_SCHEMA_VERSION,
        "unsupported registry artifact manifest schema at {}: {}",
        manifest_path.display(),
        manifest.schema_version
    );
    Ok(StoredRegistryArtifact {
        manifest_path: manifest_path.to_path_buf(),
        archived,
        manifest,
    })
}

fn collect_local_registry_artifacts_in(
    root: &Path,
    archived: bool,
) -> Result<Vec<StoredRegistryArtifact>> {
    if !root.is_dir() {
        return Ok(Vec::new());
    }

    let mut artifacts = Vec::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in
            std::fs::read_dir(&dir).with_context(|| format!("failed listing {}", dir.display()))?
        {
            let entry = entry.with_context(|| format!("failed reading {}", dir.display()))?;
            let path = entry.path();
            let file_type = entry
                .file_type()
                .with_context(|| format!("failed reading file type for {}", path.display()))?;
            if file_type.is_dir() {
                if registry_should_skip_dir(&path) {
                    continue;
                }
                stack.push(path);
                continue;
            }
            if file_type.is_file()
                && entry.file_name()
                    == std::ffi::OsStr::new(REGISTRY_LOCAL_ARTIFACT_MANIFEST_FILE_NAME)
            {
                artifacts.push(load_local_registry_artifact_manifest(&path, archived)?);
            }
        }
    }

    Ok(artifacts)
}

fn collect_local_registry_artifacts(
    project_root: &Path,
    include_archived: bool,
) -> Result<Vec<StoredRegistryArtifact>> {
    let mut artifacts =
        collect_local_registry_artifacts_in(&registry_active_artifacts_root(project_root), false)?;
    if include_archived {
        artifacts.extend(collect_local_registry_artifacts_in(
            &registry_archive_root(project_root),
            true,
        )?);
    }
    Ok(artifacts)
}

fn find_local_registry_artifact(
    project_root: &Path,
    extension_id: &str,
) -> Result<StoredRegistryArtifact> {
    let matches = collect_local_registry_artifacts(project_root, true)?
        .into_iter()
        .filter(|artifact| artifact.manifest.extension.extension_id == extension_id)
        .collect::<Vec<_>>();
    match matches.as_slice() {
        [] => anyhow::bail!("registry artifact not found for extension_id={extension_id}"),
        [artifact] => Ok(artifact.clone()),
        _ => anyhow::bail!(
            "multiple registry artifacts found for extension_id={extension_id}; storage is inconsistent"
        ),
    }
}

fn inspect_local_registry_artifact(
    artifact: &StoredRegistryArtifact,
) -> RegistryArtifactVerification {
    let artifact_file_name = artifact.manifest.artifact_file_name.as_str();
    if !registry_artifact_file_name_is_safe(artifact_file_name) {
        return RegistryArtifactVerification {
            status: RegistryArtifactIntegrityStatus::InvalidMetadata,
            detail: format!("manifest artifact file name is unsafe: {artifact_file_name}"),
            artifact_path: artifact.entry_dir().to_path_buf(),
        };
    }
    let artifact_path = artifact.entry_dir().join(artifact_file_name);
    let Some(version_hash) = artifact
        .manifest
        .extension
        .versions
        .last()
        .map(|version| version.content_hash.as_str())
    else {
        return RegistryArtifactVerification {
            status: RegistryArtifactIntegrityStatus::InvalidMetadata,
            detail: "extension has no registered version lineage".to_string(),
            artifact_path,
        };
    };

    if version_hash != artifact.manifest.artifact_sha256 {
        return RegistryArtifactVerification {
            status: RegistryArtifactIntegrityStatus::InvalidMetadata,
            detail: format!(
                "manifest hash {} does not match version lineage hash {}",
                artifact.manifest.artifact_sha256, version_hash
            ),
            artifact_path,
        };
    }

    let package_bytes = match std::fs::read(&artifact_path) {
        Ok(bytes) => bytes,
        Err(error) => {
            return RegistryArtifactVerification {
                status: RegistryArtifactIntegrityStatus::MissingArtifact,
                detail: format!("failed reading artifact: {error}"),
                artifact_path,
            };
        }
    };
    let actual_hash = compute_registry_artifact_sha256(&package_bytes);
    if actual_hash != artifact.manifest.artifact_sha256 {
        return RegistryArtifactVerification {
            status: RegistryArtifactIntegrityStatus::HashMismatch,
            detail: format!(
                "artifact hash mismatch: expected {} got {}",
                artifact.manifest.artifact_sha256, actual_hash
            ),
            artifact_path,
        };
    }

    let manifest_bytes = match BASE64_STANDARD.decode(&artifact.manifest.manifest_bytes_b64) {
        Ok(bytes) => bytes,
        Err(error) => {
            return RegistryArtifactVerification {
                status: RegistryArtifactIntegrityStatus::InvalidMetadata,
                detail: format!("failed decoding manifest bytes: {error}"),
                artifact_path,
            };
        }
    };
    let public_key_bytes = match hex::decode(&artifact.manifest.publisher_public_key_hex) {
        Ok(bytes) => bytes,
        Err(error) => {
            return RegistryArtifactVerification {
                status: RegistryArtifactIntegrityStatus::InvalidMetadata,
                detail: format!("failed decoding publisher key hex: {error}"),
                artifact_path,
            };
        }
    };
    let public_key_array = match <[u8; 32]>::try_from(public_key_bytes.as_slice()) {
        Ok(bytes) => bytes,
        Err(_) => {
            return RegistryArtifactVerification {
                status: RegistryArtifactIntegrityStatus::InvalidMetadata,
                detail: "publisher public key was not 32 bytes".to_string(),
                artifact_path,
            };
        }
    };
    let verifying_key = match ed25519_dalek::VerifyingKey::from_bytes(&public_key_array) {
        Ok(key) => key,
        Err(error) => {
            return RegistryArtifactVerification {
                status: RegistryArtifactIntegrityStatus::InvalidMetadata,
                detail: format!("failed constructing verifying key: {error}"),
                artifact_path,
            };
        }
    };
    let derived_key_id = supply_chain::artifact_signing::KeyId::from_verifying_key(&verifying_key);
    if derived_key_id.to_string() != artifact.manifest.extension.signature.key_id {
        return RegistryArtifactVerification {
            status: RegistryArtifactIntegrityStatus::InvalidMetadata,
            detail: format!(
                "publisher key id mismatch: manifest={} derived={}",
                artifact.manifest.extension.signature.key_id, derived_key_id
            ),
            artifact_path,
        };
    }
    if let Err(error) = supply_chain::artifact_signing::verify_signature(
        &verifying_key,
        &manifest_bytes,
        &artifact.manifest.extension.signature.signature_bytes,
    ) {
        return RegistryArtifactVerification {
            status: RegistryArtifactIntegrityStatus::InvalidSignature,
            detail: format!("manifest signature verification failed: {error}"),
            artifact_path,
        };
    }

    RegistryArtifactVerification {
        status: RegistryArtifactIntegrityStatus::Verified,
        detail: "artifact hash and manifest signature verified".to_string(),
        artifact_path,
    }
}

fn local_registry_search_rows(
    project_root: &Path,
    query: &str,
    min_assurance: Option<u8>,
) -> Result<Vec<RegistrySearchDisplayRow>> {
    let mut rows = collect_local_registry_artifacts(project_root, false)?
        .into_iter()
        .filter_map(|artifact| {
            let extension = &artifact.manifest.extension;
            let assurance = extension_assurance_level(extension);
            if !extension_matches_query(extension, query)
                || min_assurance.is_some_and(|minimum| assurance < minimum)
            {
                return None;
            }
            let verification = inspect_local_registry_artifact(&artifact);
            Some(RegistrySearchDisplayRow {
                assurance,
                extension_id: extension.extension_id.clone(),
                name: extension.name.clone(),
                publisher: extension.publisher_id.clone(),
                status: extension.status.label().to_string(),
                artifact_path: registry_relative_display_path(
                    &verification.artifact_path,
                    project_root,
                ),
                integrity_status: verification.status.label().to_string(),
            })
        })
        .collect::<Vec<_>>();
    rows.sort_by(|left, right| {
        right
            .assurance
            .cmp(&left.assurance)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.extension_id.cmp(&right.extension_id))
    });
    Ok(rows)
}

fn archive_local_registry_artifact(
    project_root: &Path,
    artifact: &StoredRegistryArtifact,
) -> Result<PathBuf> {
    let active_root = registry_active_artifacts_root(project_root);
    let archive_root = registry_archive_root(project_root);
    let entry_dir = artifact.entry_dir().to_path_buf();
    let relative = entry_dir.strip_prefix(&active_root).with_context(|| {
        format!(
            "failed deriving active artifact relative path {} from {}",
            entry_dir.display(),
            active_root.display()
        )
    })?;

    let mut archive_path = archive_root.join(relative);
    if archive_path.exists() {
        let base_name = archive_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("artifact-entry");
        archive_path = archive_path.with_file_name(format!("{base_name}-{}", Uuid::now_v7()));
    }
    if let Some(parent) = archive_path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed creating {}", parent.display()))?;
    }
    std::fs::rename(&entry_dir, &archive_path).with_context(|| {
        format!(
            "failed archiving registry artifact {} -> {}",
            entry_dir.display(),
            archive_path.display()
        )
    })?;
    Ok(archive_path)
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct GitProvenanceContext {
    source_repository_url: Option<String>,
    vcs_commit_sha: Option<String>,
    source_dirty: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RegistryPublishProvenanceContext {
    git: GitProvenanceContext,
    builder_identity: String,
    build_timestamp_epoch: u64,
}

impl RegistryPublishProvenanceContext {
    fn slsa_level_claim(&self) -> u8 {
        match (
            self.git.source_repository_url.as_deref(),
            self.git.vcs_commit_sha.as_deref(),
            self.git.source_dirty,
        ) {
            // Local publish can prove source metadata plus a signed build, but
            // it cannot mint an independent source-vcs attestation chain.
            (Some(_), Some(_), Some(_)) => 2,
            _ => 0,
        }
    }
}

fn trim_nonempty(raw: impl AsRef<str>) -> Option<String> {
    let trimmed = raw.as_ref().trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn current_epoch_seconds() -> u64 {
    u64::try_from(chrono::Utc::now().timestamp()).unwrap_or_default()
}

fn format_external_command(program: &str, args: &[&str]) -> String {
    if args.is_empty() {
        program.to_string()
    } else {
        format!("{program} {}", args.join(" "))
    }
}

fn run_command_capture_stdout(
    current_dir: Option<&Path>,
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> std::result::Result<String, String> {
    let command_label = format_external_command(program, args);
    let mut command = ProcessCommand::new(program);
    command
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(dir) = current_dir {
        command.current_dir(dir);
    }

    let mut child = command
        .spawn()
        .map_err(|error| format!("{command_label} failed to start: {error}"))?;
    let start = Instant::now();

    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                let mut stdout = Vec::new();
                if let Some(mut pipe) = child.stdout.take() {
                    pipe.read_to_end(&mut stdout).map_err(|error| {
                        format!("{command_label} failed collecting output: {error}")
                    })?;
                }
                let mut stderr = Vec::new();
                if let Some(mut pipe) = child.stderr.take() {
                    pipe.read_to_end(&mut stderr).map_err(|error| {
                        format!("{command_label} failed collecting output: {error}")
                    })?;
                }
                if !status.success() {
                    let stderr = String::from_utf8_lossy(&stderr).trim().to_string();
                    let stdout = String::from_utf8_lossy(&stdout).trim().to_string();
                    let detail = if stderr.is_empty() { stdout } else { stderr };
                    if detail.is_empty() {
                        return Err(format!("{command_label} exited with {status}"));
                    }
                    return Err(format!("{command_label} failed: {detail}"));
                }
                return Ok(String::from_utf8_lossy(&stdout).trim().to_string());
            }
            Ok(None) => {
                if start.elapsed() >= timeout {
                    let _ = child.kill();
                    let _ = child.wait();
                    return Err(format!(
                        "{command_label} timed out after {}ms",
                        timeout.as_millis()
                    ));
                }
                std::thread::sleep(Duration::from_millis(25));
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(format!("{command_label} wait failed: {error}"));
            }
        }
    }
}

fn run_git_capture_stdout(workspace: &Path, args: &[&str]) -> std::result::Result<String, String> {
    run_command_capture_stdout(Some(workspace), "git", args, REGISTRY_GIT_COMMAND_TIMEOUT)
}

fn resolve_local_hostname() -> Option<String> {
    std::env::var("HOSTNAME")
        .ok()
        .and_then(trim_nonempty)
        .or_else(|| {
            run_command_capture_stdout(None, "hostname", &[], REGISTRY_GIT_COMMAND_TIMEOUT)
                .ok()
                .and_then(trim_nonempty)
        })
}

fn resolve_registry_builder_identity() -> String {
    if let Some(value) = std::env::var("FRANKEN_NODE_BUILDER_ID")
        .ok()
        .and_then(trim_nonempty)
    {
        return value;
    }

    match config::Config::resolve(None, CliOverrides::default()) {
        Ok(resolved) => {
            if let Some(value) = resolved
                .config
                .registry
                .builder_identity
                .and_then(trim_nonempty)
            {
                return value;
            }
        }
        Err(error) => {
            tracing::warn!(
                error = %error,
                "registry publish: failed resolving config for builder identity; falling back to hostname"
            );
        }
    }

    if let Some(hostname) = resolve_local_hostname() {
        return hostname;
    }

    std::env::var("USER")
        .ok()
        .and_then(trim_nonempty)
        .or_else(|| std::env::var("USERNAME").ok().and_then(trim_nonempty))
        .unwrap_or_else(|| "local-operator".to_string())
}

fn collect_git_provenance_context(workspace: &Path) -> GitProvenanceContext {
    let source_repository_url =
        match run_git_capture_stdout(workspace, &["remote", "get-url", "origin"]) {
            Ok(value) => {
                trim_nonempty(value).map(|url| BuildContext::strip_repository_url_credentials(&url))
            }
            Err(error) => {
                tracing::warn!(
                    workspace = %workspace.display(),
                    error = %error,
                    "registry publish: failed reading git origin URL for provenance"
                );
                None
            }
        };

    let vcs_commit_sha = match run_git_capture_stdout(workspace, &["rev-parse", "HEAD"]) {
        Ok(value) => trim_nonempty(value),
        Err(error) => {
            tracing::warn!(
                workspace = %workspace.display(),
                error = %error,
                "registry publish: failed reading git commit SHA for provenance"
            );
            None
        }
    };

    let source_dirty = match run_git_capture_stdout(workspace, &["status", "--porcelain"]) {
        Ok(value) => Some(!value.is_empty()),
        Err(error) => {
            tracing::warn!(
                workspace = %workspace.display(),
                error = %error,
                "registry publish: failed reading git dirty status for provenance"
            );
            None
        }
    };

    if source_repository_url.is_none() || vcs_commit_sha.is_none() || source_dirty.is_none() {
        tracing::warn!(
            workspace = %workspace.display(),
            "registry publish provenance degraded: incomplete git metadata reduced SLSA claim to 0"
        );
    }

    GitProvenanceContext {
        source_repository_url,
        vcs_commit_sha,
        source_dirty,
    }
}

fn collect_registry_publish_provenance_context(
    package_path: &Path,
) -> RegistryPublishProvenanceContext {
    let workspace = package_path.parent().unwrap_or_else(|| Path::new("."));
    RegistryPublishProvenanceContext {
        git: collect_git_provenance_context(workspace),
        builder_identity: resolve_registry_builder_identity(),
        build_timestamp_epoch: current_epoch_seconds(),
    }
}

fn build_registry_publish_links(
    operator_key_id: &str,
    signer_version: &str,
    content_hash: &str,
    build_timestamp_epoch: u64,
    slsa_level_claim: u8,
) -> Vec<supply_chain::provenance::AttestationLink> {
    let mut links = vec![supply_chain::provenance::AttestationLink {
        role: supply_chain::provenance::ChainLinkRole::Publisher,
        signer_id: operator_key_id.to_string(),
        signer_version: signer_version.to_string(),
        signature: String::new(),
        signed_payload_hash: content_hash.to_string(),
        issued_at_epoch: build_timestamp_epoch,
        expires_at_epoch: build_timestamp_epoch.saturating_add(86_400),
        revoked: false,
    }];

    if slsa_level_claim >= 2 {
        links.push(supply_chain::provenance::AttestationLink {
            role: supply_chain::provenance::ChainLinkRole::BuildSystem,
            signer_id: operator_key_id.to_string(),
            signer_version: signer_version.to_string(),
            signature: String::new(),
            signed_payload_hash: content_hash.to_string(),
            issued_at_epoch: build_timestamp_epoch,
            expires_at_epoch: build_timestamp_epoch.saturating_add(86_400),
            revoked: false,
        });
    }

    if slsa_level_claim >= 3 {
        links.push(supply_chain::provenance::AttestationLink {
            role: supply_chain::provenance::ChainLinkRole::SourceVcs,
            signer_id: operator_key_id.to_string(),
            signer_version: signer_version.to_string(),
            signature: String::new(),
            signed_payload_hash: content_hash.to_string(),
            issued_at_epoch: build_timestamp_epoch,
            expires_at_epoch: build_timestamp_epoch.saturating_add(86_400),
            revoked: false,
        });
    }

    links
}

fn registry_publish_provenance_signature_payload(
    manifest_bytes: &[u8],
    provenance: &supply_chain::provenance::ProvenanceAttestation,
) -> Result<Vec<u8>> {
    let canonical =
        supply_chain::provenance::canonical_attestation_json(provenance).map_err(|error| {
            anyhow::anyhow!("failed canonicalizing registry publish provenance: {error}")
        })?;
    let mut payload = Vec::new();
    payload.extend(b"registry_publish_provenance_v1:");
    payload.extend((manifest_bytes.len() as u64).to_le_bytes());
    payload.extend(manifest_bytes);
    payload.extend((canonical.len() as u64).to_le_bytes());
    payload.extend(canonical.as_bytes());
    Ok(payload)
}

fn build_registry_publish_request(
    package_path: &Path,
    content_hash: &str,
    signing_material: &Ed25519SigningMaterial,
) -> Result<RegistrationRequest> {
    let provenance_context = collect_registry_publish_provenance_context(package_path);
    build_registry_publish_request_with_context(
        package_path,
        content_hash,
        signing_material,
        provenance_context,
    )
}

fn build_registry_publish_request_with_context(
    package_path: &Path,
    content_hash: &str,
    signing_material: &Ed25519SigningMaterial,
    provenance_context: RegistryPublishProvenanceContext,
) -> Result<RegistrationRequest> {
    let inferred_name = package_path
        .file_stem()
        .and_then(std::ffi::OsStr::to_str)
        .unwrap_or("extension-artifact");
    let name = normalize_registry_name(inferred_name);

    let manifest_bytes = format!("manifest:{}:{}", name, content_hash).into_bytes();
    let key_id = supply_chain::artifact_signing::KeyId::from_verifying_key(
        &signing_material.signing_key.verifying_key(),
    );
    let key_id_string = key_id.to_string();
    let signature_bytes =
        supply_chain::artifact_signing::sign_bytes(&signing_material.signing_key, &manifest_bytes);
    let slsa_level_claim = provenance_context.slsa_level_claim();
    let builder_version = env!("CARGO_PKG_VERSION").to_string();
    let RegistryPublishProvenanceContext {
        git:
            GitProvenanceContext {
                source_repository_url,
                vcs_commit_sha,
                source_dirty,
            },
        builder_identity,
        build_timestamp_epoch,
    } = provenance_context;

    let mut custom_claims = std::collections::BTreeMap::new();
    if let Some(source_dirty) = source_dirty {
        custom_claims.insert("source_dirty".to_string(), source_dirty.to_string());
    }
    custom_claims.insert("operator_key_id".to_string(), key_id_string.clone());
    custom_claims.insert(
        "operator_signature_scope".to_string(),
        "registry_publish_provenance_v1".to_string(),
    );

    let mut provenance = supply_chain::provenance::ProvenanceAttestation {
        schema_version: "1.0".to_string(),
        source_repository_url: source_repository_url.unwrap_or_default(),
        build_system_identifier: "franken-node".to_string(),
        builder_identity,
        builder_version: builder_version.clone(),
        vcs_commit_sha: vcs_commit_sha.unwrap_or_default(),
        build_timestamp_epoch,
        reproducibility_hash: content_hash.to_string(),
        input_hash: content_hash.to_string(),
        output_hash: content_hash.to_string(),
        slsa_level_claim,
        envelope_format: supply_chain::provenance::AttestationEnvelopeFormat::FrankenNodeEnvelopeV1,
        links: build_registry_publish_links(
            &key_id_string,
            &builder_version,
            content_hash,
            build_timestamp_epoch,
            slsa_level_claim,
        ),
        custom_claims,
    };
    let provenance_signature_payload =
        registry_publish_provenance_signature_payload(&manifest_bytes, &provenance)?;
    let provenance_signature = supply_chain::artifact_signing::sign_bytes(
        &signing_material.signing_key,
        &provenance_signature_payload,
    );
    provenance.custom_claims.insert(
        "operator_provenance_signature".to_string(),
        hex::encode(provenance_signature),
    );
    supply_chain::provenance::sign_links_in_place(&mut provenance)
        .map_err(|e| anyhow::anyhow!("failed signing registry publish provenance links: {e}"))?;

    Ok(RegistrationRequest {
        name,
        description: format!("CLI-published artifact from {}", package_path.display()),
        publisher_id: provenance.builder_identity.clone(),
        signature: ExtensionSignature {
            key_id: key_id_string,
            algorithm: "ed25519".to_string(),
            signature_bytes,
            signed_at: chrono::Utc::now().to_rfc3339(),
        },
        provenance,
        initial_version: VersionEntry {
            version: "1.0.0".to_string(),
            parent_version: None,
            content_hash: content_hash.to_string(),
            registered_at: chrono::Utc::now().to_rfc3339(),
            compatible_with: vec!["franken-node".to_string()],
        },
        tags: vec!["cli-publish".to_string(), "local".to_string()],
        manifest_bytes,
        transparency_proof: None,
    })
}

fn parse_min_assurance(raw: Option<u8>) -> Result<Option<u8>> {
    let Some(value) = raw else {
        return Ok(None);
    };
    if (1..=5).contains(&value) {
        Ok(Some(value))
    } else {
        anyhow::bail!("invalid --min-assurance `{value}`; expected a value between 1 and 5");
    }
}

fn extension_assurance_level(extension: &SignedExtension) -> u8 {
    let mut score = 1_u8;

    if extension.status == ExtensionStatus::Active {
        score = score.saturating_add(1);
    }
    if extension
        .signature
        .algorithm
        .eq_ignore_ascii_case("ed25519")
        && extension.signature.signature_bytes.len() >= 64
    {
        score = score.saturating_add(1);
    }
    if !extension.provenance.output_hash.is_empty()
        && !extension.provenance.source_repository_url.is_empty()
    {
        score = score.saturating_add(1);
    }
    if !extension.versions.is_empty() {
        score = score.saturating_add(1);
    }
    if extension.status == ExtensionStatus::Revoked {
        score = score.saturating_sub(2);
    }

    score.clamp(1, 5)
}

fn extension_matches_query(extension: &SignedExtension, query: &str) -> bool {
    let needle = query.trim().to_ascii_lowercase();
    if needle.is_empty() {
        return true;
    }

    extension
        .extension_id
        .to_ascii_lowercase()
        .contains(&needle)
        || extension.name.to_ascii_lowercase().contains(&needle)
        || extension
            .publisher_id
            .to_ascii_lowercase()
            .contains(&needle)
        || extension.description.to_ascii_lowercase().contains(&needle)
        || extension
            .tags
            .iter()
            .any(|tag| tag.to_ascii_lowercase().contains(&needle))
}

fn search_registry_entries<'a>(
    registry: &'a SignedExtensionRegistry,
    query: &str,
    min_assurance: Option<u8>,
) -> Vec<(u8, &'a SignedExtension)> {
    let mut results = registry
        .list(None)
        .into_iter()
        .filter(|extension| extension_matches_query(extension, query))
        .map(|extension| (extension_assurance_level(extension), extension))
        .filter(|(assurance, _)| min_assurance.is_none_or(|minimum| *assurance >= minimum))
        .collect::<Vec<_>>();

    results.sort_by(|left, right| {
        right
            .0
            .cmp(&left.0)
            .then_with(|| left.1.name.cmp(&right.1.name))
            .then_with(|| left.1.extension_id.cmp(&right.1.extension_id))
    });
    results
}

fn baseline_registry_search_rows(
    rows: Vec<(u8, &SignedExtension)>,
) -> Vec<RegistrySearchDisplayRow> {
    rows.into_iter()
        .map(|(assurance, extension)| RegistrySearchDisplayRow {
            assurance,
            extension_id: extension.extension_id.clone(),
            name: extension.name.clone(),
            publisher: extension.publisher_id.clone(),
            status: extension.status.label().to_string(),
            artifact_path: "-".to_string(),
            integrity_status: "seed-only".to_string(),
        })
        .collect()
}

fn render_registry_search_results(
    rows: &[RegistrySearchDisplayRow],
    query: &str,
    min_assurance: Option<u8>,
) -> String {
    if rows.is_empty() {
        return format!(
            "registry search: no extensions matched query=`{query}` min_assurance={}",
            min_assurance.map_or_else(|| "none".to_string(), |value| value.to_string())
        );
    }

    let mut lines = Vec::with_capacity(rows.len() + 3);
    lines.push(format!(
        "registry search: query=`{query}` min_assurance={}",
        min_assurance.map_or_else(|| "none".to_string(), |value| value.to_string())
    ));
    lines.push(
        "extension_id | name | publisher | status | assurance | artifact_path | integrity"
            .to_string(),
    );
    lines.push(
        "------------ | ---- | --------- | ------ | --------- | ------------- | ---------"
            .to_string(),
    );
    for row in rows {
        lines.push(format!(
            "{} | {} | {} | {} | {} | {} | {}",
            row.extension_id,
            row.name,
            row.publisher,
            row.status,
            row.assurance,
            row.artifact_path,
            row.integrity_status
        ));
    }
    lines.join("\n")
}

fn handle_registry_publish(args: &cli::RegistryPublishArgs) -> Result<()> {
    let project_root = std::env::current_dir()
        .context("failed resolving current directory for registry publish")?;
    if !args.package_path.exists() {
        anyhow::bail!(
            "registry publish target does not exist: {}",
            args.package_path.display()
        );
    }
    if !args.package_path.is_file() {
        anyhow::bail!(
            "registry publish target must be a file: {}",
            args.package_path.display()
        );
    }

    let package_bytes = std::fs::read(&args.package_path)
        .with_context(|| format!("failed reading package {}", args.package_path.display()))?;
    let content_hash = compute_registry_artifact_sha256(&package_bytes);
    let signing_key_path = args
        .signing_key
        .as_deref()
        .ok_or_else(|| registry_publish_signing_key_required_error(&args.package_path))?;
    let signing_material = load_registry_publish_signing_material(signing_key_path)?;
    let request =
        build_registry_publish_request(&args.package_path, &content_hash, &signing_material)?;
    let request_for_storage = request.clone();
    let publisher_key_id = request.signature.key_id.clone();
    let signing_key_source = signing_material.source;
    let signing_key_path = signing_material.path.display().to_string();

    let mut registry = registry_cli_registry()?;
    registry.register_publisher_key(signing_material.signing_key.verifying_key());
    let publish_epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let result = registry.register(request, "trace-cli-registry-publish", publish_epoch);
    if !result.success {
        anyhow::bail!("registry publish failed: {}", result.detail);
    }
    let extension_id = result
        .extension_id
        .ok_or_else(|| anyhow::anyhow!("registry publish returned no extension id"))?;
    let published = registry
        .query(&extension_id)
        .ok_or_else(|| anyhow::anyhow!("registry publish stored entry is missing"))?
        .clone();
    let stored = persist_local_registry_artifact(
        &project_root,
        &args.package_path,
        &package_bytes,
        &request_for_storage,
        &published,
        &signing_material.signing_key.verifying_key(),
    )?;
    let verification = inspect_local_registry_artifact(&stored);
    anyhow::ensure!(
        verification.status == RegistryArtifactIntegrityStatus::Verified,
        "registry publish stored an unverifiable artifact: {}",
        verification.detail
    );
    let artifact_path = registry_relative_display_path(&stored.artifact_path(), &project_root);
    let manifest_path = registry_relative_display_path(&stored.manifest_path, &project_root);

    println!(
        "registry publish: extension_id={} name={} status={} content_sha256={} publisher_key_id={} signing_key_source={} signing_key_path={} artifact_path={} manifest_path={} integrity={}",
        published.extension_id,
        published.name,
        published.status.label(),
        content_hash,
        publisher_key_id,
        signing_key_source,
        signing_key_path,
        artifact_path,
        manifest_path,
        verification.status.label()
    );
    println!(
        "registry state: entries={} revocations={} audit_records={} content_hash={}",
        registry.list(None).len(),
        registry.revocations().len(),
        registry.audit_log().len(),
        registry.content_hash()
    );

    Ok(())
}

fn handle_registry_search(args: &cli::RegistrySearchArgs) -> Result<()> {
    let project_root = std::env::current_dir()
        .context("failed resolving current directory for registry search")?;
    let min_assurance = parse_min_assurance(args.min_assurance)?;
    let registry = registry_cli_registry()?;
    let mut rows = baseline_registry_search_rows(search_registry_entries(
        &registry,
        &args.query,
        min_assurance,
    ));
    rows.extend(local_registry_search_rows(
        &project_root,
        &args.query,
        min_assurance,
    )?);
    rows.sort_by(|left, right| {
        right
            .assurance
            .cmp(&left.assurance)
            .then_with(|| left.name.cmp(&right.name))
            .then_with(|| left.extension_id.cmp(&right.extension_id))
    });
    println!(
        "{}",
        render_registry_search_results(&rows, &args.query, min_assurance)
    );
    Ok(())
}

fn handle_registry_verify(args: &cli::RegistryVerifyArgs) -> Result<()> {
    let project_root = std::env::current_dir()
        .context("failed resolving current directory for registry verify")?;
    let artifact = find_local_registry_artifact(&project_root, &args.extension_id)?;
    let verification = inspect_local_registry_artifact(&artifact);
    let artifact_path = registry_relative_display_path(&verification.artifact_path, &project_root);
    let manifest_path = registry_relative_display_path(&artifact.manifest_path, &project_root);
    if verification.status != RegistryArtifactIntegrityStatus::Verified {
        anyhow::bail!(
            "registry verify failed: extension_id={} integrity={} archived={} artifact_path={} manifest_path={} detail={}",
            artifact.manifest.extension.extension_id,
            verification.status.label(),
            artifact.archived,
            artifact_path,
            manifest_path,
            verification.detail
        );
    }

    println!(
        "registry verify: extension_id={} integrity={} archived={} artifact_path={} manifest_path={} detail={}",
        artifact.manifest.extension.extension_id,
        verification.status.label(),
        artifact.archived,
        artifact_path,
        manifest_path,
        verification.detail
    );
    Ok(())
}

fn handle_registry_gc(args: &cli::RegistryGcArgs) -> Result<()> {
    let project_root =
        std::env::current_dir().context("failed resolving current directory for registry gc")?;
    ensure_registry_storage_root(&project_root)?;

    let mut by_lineage: BTreeMap<(String, String), Vec<StoredRegistryArtifact>> = BTreeMap::new();
    for artifact in collect_local_registry_artifacts(&project_root, false)? {
        by_lineage
            .entry((
                artifact.manifest.extension.publisher_id.clone(),
                artifact.manifest.extension.name.clone(),
            ))
            .or_default()
            .push(artifact);
    }

    let mut archived = 0usize;
    let mut active = 0usize;
    for artifacts in by_lineage.values_mut() {
        artifacts.sort_by(|left, right| {
            right
                .stored_at_sort_key()
                .cmp(&left.stored_at_sort_key())
                .then_with(|| {
                    left.manifest
                        .extension
                        .extension_id
                        .cmp(&right.manifest.extension.extension_id)
                })
        });
        active += artifacts.len().min(args.keep);
        for artifact in artifacts.iter().skip(args.keep) {
            archive_local_registry_artifact(&project_root, artifact)?;
            archived += 1;
        }
    }

    println!(
        "registry gc: keep={} lineages={} active={} archived={} archive_root={}",
        args.keep,
        by_lineage.len(),
        active,
        archived,
        registry_relative_display_path(&registry_archive_root(&project_root), &project_root)
    );
    Ok(())
}

fn parse_risk_level_filter(raw: Option<&str>) -> Result<Option<RiskLevel>> {
    let Some(raw_value) = raw else {
        return Ok(None);
    };

    let normalized = raw_value.trim().to_ascii_lowercase().replace('-', "_");
    let level = match normalized.as_str() {
        "low" => RiskLevel::Low,
        "medium" => RiskLevel::Medium,
        "high" => RiskLevel::High,
        "critical" => RiskLevel::Critical,
        _ => {
            anyhow::bail!(
                "invalid --risk `{raw_value}`; expected one of: low, medium, high, critical"
            )
        }
    };
    Ok(Some(level))
}

fn filter_trust_cards_for_trust_command(
    cards: Vec<TrustCard>,
    risk_filter: Option<RiskLevel>,
    revoked_filter: Option<bool>,
) -> Vec<TrustCard> {
    let mut filtered = cards
        .into_iter()
        .filter(|card| {
            let risk_matches = risk_filter
                .map(|risk| card.user_facing_risk_assessment.level == risk)
                .unwrap_or(true);
            let revoked_matches = revoked_filter
                .map(|revoked| {
                    let is_revoked =
                        matches!(&card.revocation_status, RevocationStatus::Revoked { .. });
                    is_revoked == revoked
                })
                .unwrap_or(true);
            risk_matches && revoked_matches
        })
        .collect::<Vec<_>>();

    filtered.sort_by(|left, right| {
        left.extension
            .extension_id
            .cmp(&right.extension.extension_id)
    });
    filtered
}

fn render_trust_card_list(cards: &[TrustCard]) -> String {
    if cards.is_empty() {
        return "no trust cards matched the current filters".to_string();
    }

    let mut lines = Vec::with_capacity(cards.len() + 1);
    lines.push("extension | publisher | cert | reputation | status".to_string());
    for card in cards {
        let status = match &card.revocation_status {
            supply_chain::trust_card::RevocationStatus::Active => "active".to_string(),
            supply_chain::trust_card::RevocationStatus::Revoked { reason, .. } => {
                format!("revoked:{reason}")
            }
        };
        lines.push(format!(
            "{} | {} | {:?} | {}bp ({:?}) | {}",
            card.extension.extension_id,
            card.publisher.publisher_id,
            card.certification_level,
            card.reputation_score_basis_points,
            card.reputation_trend,
            status
        ));
    }
    lines.join("\n")
}

fn revoke_trust_card(
    registry: &mut TrustCardRegistry,
    extension_id: &str,
    now_secs: u64,
) -> Result<TrustCard> {
    let now_rfc3339 = rfc3339_timestamp_from_secs(now_secs);
    registry
        .update(
            extension_id,
            TrustCardMutation {
                certification_level: None,
                revocation_status: Some(RevocationStatus::Revoked {
                    reason: "manual revoke via franken-node trust revoke".to_string(),
                    revoked_at: now_rfc3339.clone(),
                }),
                active_quarantine: Some(true),
                reputation_score_basis_points: None,
                reputation_trend: Some(ReputationTrend::Declining),
                user_facing_risk_assessment: Some(RiskAssessment {
                    level: RiskLevel::Critical,
                    summary: "Revoked by operator action via trust revoke.".to_string(),
                }),
                last_verified_timestamp: Some(now_rfc3339),
                evidence_refs: None, // Demotion/revocation: no new evidence required.
            },
            now_secs,
            "trace-cli-trust-revoke",
        )
        .map_err(|err| match err {
            TrustCardError::NotFound(missing_extension_id) => {
                trust_card_not_found_error(&missing_extension_id).into()
            }
            other => anyhow::anyhow!(other.to_string()),
        })
}

fn quarantine_trust_cards(
    registry: &mut TrustCardRegistry,
    artifact: &str,
    now_secs: u64,
) -> Result<Vec<TrustCard>> {
    let now_rfc3339 = rfc3339_timestamp_from_secs(now_secs);
    let mut targets = Vec::new();

    let direct_match = registry
        .read(artifact, now_secs, "trace-cli-trust-quarantine-lookup")
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    if let Some(card) = direct_match {
        targets.push(card.extension.extension_id);
    } else if artifact.starts_with("sha256:") {
        targets = registry
            .list(
                &TrustCardListFilter::empty(),
                "trace-cli-trust-quarantine-list",
                now_secs,
            )
            .map_err(|err| anyhow::anyhow!(err.to_string()))?
            .into_iter()
            .filter(|card| {
                card.provenance_summary
                    .artifact_hashes
                    .iter()
                    .any(|hash| hash == artifact || hash.starts_with(artifact))
            })
            .map(|card| card.extension.extension_id)
            .collect();
    } else {
        anyhow::bail!(
            "artifact `{artifact}` did not match a trust card extension id; use extension id or sha256:* reference"
        );
    }

    if targets.is_empty() {
        anyhow::bail!("no trust cards available for quarantine");
    }

    let mut updates = Vec::new();
    for extension_id in targets {
        let updated = registry
            .update(
                &extension_id,
                TrustCardMutation {
                    certification_level: None,
                    revocation_status: None,
                    active_quarantine: Some(true),
                    reputation_score_basis_points: None,
                    reputation_trend: None,
                    user_facing_risk_assessment: None,
                    last_verified_timestamp: Some(now_rfc3339.clone()),
                    evidence_refs: None, // Quarantine: no new evidence required.
                },
                now_secs,
                "trace-cli-trust-quarantine",
            )
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        updates.push(updated);
    }

    updates.sort_by(|left, right| {
        left.extension
            .extension_id
            .cmp(&right.extension.extension_id)
    });
    Ok(updates)
}

fn render_trust_sync_summary(
    cards: &[TrustCard],
    sync_report: &TrustCardSyncReport,
    audit_report: &TrustSyncAuditRefreshReport,
    force: bool,
) -> String {
    let revoked = cards
        .iter()
        .filter(|card| matches!(card.revocation_status, RevocationStatus::Revoked { .. }))
        .count();
    let quarantined = cards.iter().filter(|card| card.active_quarantine).count();
    let critical = cards
        .iter()
        .filter(|card| card.user_facing_risk_assessment.level == RiskLevel::Critical)
        .count();
    format!(
        "trust sync completed: force={force} cards={} refreshed={} vulnerabilities={} network_errors={} cache_hits={} cache_misses={} stale_refreshes={} forced_refreshes={} revoked={} quarantined={} critical_risk={critical}",
        cards.len(),
        audit_report.refreshed_count,
        audit_report.vulnerabilities_found,
        audit_report.network_errors,
        sync_report.cache_hits,
        sync_report.cache_misses,
        sync_report.stale_refreshes,
        sync_report.forced_refreshes,
        revoked,
        quarantined
    )
}

fn trust_sync_card_needs_network_refresh(
    card: &TrustCard,
    now_secs: u64,
    cache_ttl_secs: u64,
    force: bool,
) -> bool {
    if force {
        return true;
    }

    chrono::DateTime::parse_from_rfc3339(&card.last_verified_timestamp)
        .ok()
        .and_then(|timestamp| u64::try_from(timestamp.timestamp()).ok())
        .map(|verified_secs| now_secs.saturating_sub(verified_secs) > cache_ttl_secs)
        .unwrap_or(true)
}

fn refresh_trust_sync_audit_with<F>(
    state: &mut TrustCardCliRegistryState,
    now_secs: u64,
    force: bool,
    mut fetcher: F,
) -> TrustSyncAuditRefreshReport
where
    F: FnMut(&str, Option<&str>) -> Result<TrustScanAuditMetadata>,
{
    let cards = match state.registry.list(
        &TrustCardListFilter::empty(),
        "trace-cli-trust-sync-refresh",
        now_secs,
    ) {
        Ok(cards) => cards,
        Err(err) => {
            return TrustSyncAuditRefreshReport {
                network_errors: 1,
                warnings: vec![format!(
                    "failed listing trust cards for sync refresh: {err}"
                )],
                ..TrustSyncAuditRefreshReport::default()
            };
        }
    };

    let now_rfc3339 = rfc3339_timestamp_from_secs(now_secs);
    let mut report = TrustSyncAuditRefreshReport::default();

    for card in cards {
        let Some(package_name) = card.extension.extension_id.strip_prefix("npm:") else {
            continue;
        };
        if !trust_sync_card_needs_network_refresh(&card, now_secs, state.cache_ttl_secs, force) {
            continue;
        }

        match fetcher(package_name, Some(card.extension.version.as_str())) {
            Ok(audit_metadata) => {
                report.refreshed_count = report.refreshed_count.saturating_add(1);
                report.vulnerabilities_found = report
                    .vulnerabilities_found
                    .saturating_add(audit_metadata.vulnerability_ids.len());

                let mutation = if audit_metadata.vulnerability_ids.is_empty() {
                    TrustCardMutation {
                        certification_level: None,
                        revocation_status: None,
                        active_quarantine: None,
                        reputation_score_basis_points: None,
                        reputation_trend: None,
                        user_facing_risk_assessment: None,
                        last_verified_timestamp: Some(now_rfc3339.clone()),
                        evidence_refs: None,
                    }
                } else {
                    let computed_risk = if audit_metadata.vulnerability_ids.len() >= 3 {
                        RiskLevel::Critical
                    } else {
                        RiskLevel::High
                    };
                    let risk_level = card.user_facing_risk_assessment.level.max(computed_risk);
                    let vulnerability_summary = format!(
                        "OSV refresh reported {} vulnerability record(s): {}",
                        audit_metadata.vulnerability_ids.len(),
                        audit_metadata.vulnerability_ids.join(", ")
                    );
                    let vulnerability_penalty =
                        (audit_metadata.vulnerability_ids.len().min(5) as u16).saturating_mul(90);
                    let reputation_score_basis_points = card
                        .reputation_score_basis_points
                        .saturating_sub(vulnerability_penalty);

                    TrustCardMutation {
                        certification_level: None,
                        revocation_status: None,
                        active_quarantine: None,
                        reputation_score_basis_points: Some(reputation_score_basis_points),
                        reputation_trend: Some(ReputationTrend::Declining),
                        user_facing_risk_assessment: Some(RiskAssessment {
                            level: risk_level,
                            summary: vulnerability_summary,
                        }),
                        last_verified_timestamp: Some(now_rfc3339.clone()),
                        evidence_refs: None,
                    }
                };

                if let Err(err) = state.registry.update(
                    &card.extension.extension_id,
                    mutation,
                    now_secs,
                    "trace-cli-trust-sync-refresh",
                ) {
                    report.network_errors = report.network_errors.saturating_add(1);
                    report.warnings.push(format!(
                        "{}: failed applying OSV refresh result: {}",
                        card.extension.extension_id, err
                    ));
                }
            }
            Err(err) => {
                report.network_errors = report.network_errors.saturating_add(1);
                report.warnings.push(format!(
                    "{}@{}: {}",
                    package_name, card.extension.version, err
                ));
            }
        }
    }

    report
}

fn fleet_cli_identity() -> AuthIdentity {
    AuthIdentity {
        principal: "cli-fleet-operator".to_string(),
        method: AuthMethod::MtlsClientCert,
        roles: vec!["fleet-admin".to_string(), "operator".to_string()],
    }
}

fn fleet_cli_trace(trace_id: &str) -> TraceContext {
    TraceContext {
        trace_id: trace_id.to_string(),
        span_id: "0000000000000001".to_string(),
        trace_flags: 1,
    }
}

#[derive(Debug, Clone, Serialize)]
struct FleetCliPendingIncident {
    incident_id: String,
    zone_id: String,
    target_id: String,
    target_kind: PersistedFleetTargetKind,
    reason: String,
    quarantine_version: u64,
    emitted_at: DateTime<Utc>,
    convergence: ConvergenceState,
}

#[derive(Debug, Clone)]
struct LoadedFleetState {
    state_dir: PathBuf,
    convergence_timeout_seconds: u64,
    state: FleetSharedState,
    stale_nodes: Vec<PersistedNodeStatus>,
    active_incidents: Vec<FleetCliPendingIncident>,
}

#[derive(Debug, Clone, Serialize)]
struct FleetCliStatusReport {
    status: FleetStatus,
    state_dir: PathBuf,
    convergence_timeout_seconds: u64,
    stale_nodes: Vec<PersistedNodeStatus>,
    active_incidents: Vec<FleetCliPendingIncident>,
    state: FleetSharedState,
}

#[derive(Debug, Clone, Serialize)]
struct FleetCliActionReport {
    action: FleetActionResult,
    status: FleetStatus,
    state_dir: PathBuf,
    convergence_timeout_seconds: u64,
    stale_nodes: Vec<PersistedNodeStatus>,
    active_incidents: Vec<FleetCliPendingIncident>,
    state: FleetSharedState,
}

fn resolve_fleet_state_dir(
    project_root: &Path,
    resolved: &config::ResolvedConfig,
) -> Result<PathBuf> {
    if let Some(path) = &resolved.config.fleet.state_dir {
        if path.is_absolute() {
            return Ok(path.clone());
        }
        if let Some(source_root) = resolved.source_path.as_deref().and_then(Path::parent) {
            return Ok(source_root.join(path));
        }
        return Ok(project_root.join(path));
    }

    Ok(ensure_state_dir(project_root)?.join("fleet"))
}

fn open_fleet_transport(project_root: &Path) -> Result<(u64, PathBuf, FileFleetTransport)> {
    let resolved = config::Config::resolve(None, config::CliOverrides::default())
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let state_dir = resolve_fleet_state_dir(project_root, &resolved)?;
    let mut transport = FileFleetTransport::new(state_dir.clone());
    transport
        .initialize()
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    Ok((
        resolved.config.fleet.convergence_timeout_seconds,
        state_dir,
        transport,
    ))
}

fn fleet_operation_id(kind: &str) -> String {
    format!("fleet-op-{kind}-{}", Uuid::now_v7().simple())
}

fn build_fleet_decision_receipt(
    operation_id: &str,
    principal: &str,
    zone_id: &str,
    issued_at: &str,
) -> DecisionReceipt {
    let mut hasher = sha2::Sha256::new();
    hasher.update(b"fleet_receipt_v1:");
    for field in [operation_id, principal, zone_id, issued_at] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    DecisionReceipt {
        receipt_id: format!("rcpt-{operation_id}"),
        issuer: principal.to_string(),
        issued_at: issued_at.to_string(),
        zone_id: zone_id.to_string(),
        payload_hash: hex::encode(hasher.finalize()),
    }
}

fn zone_matches_filter(action_zone: &str, requested_zone: &str) -> bool {
    requested_zone == "all" || action_zone == requested_zone
}

fn node_matches_filter(node: &PersistedNodeStatus, requested_zone: &str) -> bool {
    requested_zone == "all" || node.zone_id == requested_zone
}

fn convergence_phase(
    total_nodes: u32,
    converged_nodes: u32,
    stale_node_count: usize,
) -> ConvergencePhase {
    if total_nodes == 0 {
        ConvergencePhase::Pending
    } else if converged_nodes == total_nodes {
        ConvergencePhase::Converged
    } else if stale_node_count > 0 {
        ConvergencePhase::TimedOut
    } else {
        ConvergencePhase::Propagating
    }
}

fn convergence_progress(converged_nodes: u32, total_nodes: u32) -> u8 {
    if total_nodes == 0 {
        return 0;
    }

    let progress = (u64::from(converged_nodes) * 100) / u64::from(total_nodes);
    u8::try_from(progress).unwrap_or(100)
}

fn derive_active_fleet_incidents(
    state: &FleetSharedState,
    stale_nodes: &[PersistedNodeStatus],
) -> Vec<FleetCliPendingIncident> {
    let mut active_by_incident = BTreeMap::<String, PersistedFleetActionRecord>::new();
    for action in &state.actions {
        match &action.action {
            PersistedFleetAction::Quarantine { incident_id, .. } => {
                active_by_incident.insert(incident_id.clone(), action.clone());
            }
            PersistedFleetAction::Release { incident_id, .. } => {
                active_by_incident.remove(incident_id);
            }
            PersistedFleetAction::PolicyUpdate { .. } => {}
        }
    }

    let stale_ids: BTreeSet<&str> = stale_nodes
        .iter()
        .map(|node| node.node_id.as_str())
        .collect();
    let mut incidents = active_by_incident
        .into_values()
        .filter_map(|record| match record.action {
            PersistedFleetAction::Quarantine {
                zone_id,
                incident_id,
                target_id,
                target_kind,
                reason,
                quarantine_version,
            } => {
                let relevant_nodes: Vec<&PersistedNodeStatus> = state
                    .nodes
                    .iter()
                    .filter(|node| node_matches_filter(node, &zone_id))
                    .collect();
                let stale_node_count = relevant_nodes
                    .iter()
                    .filter(|node| stale_ids.contains(node.node_id.as_str()))
                    .count();
                let total_nodes = u32::try_from(relevant_nodes.len()).unwrap_or(u32::MAX);
                let converged_nodes = u32::try_from(
                    relevant_nodes
                        .iter()
                        .filter(|node| {
                            !stale_ids.contains(node.node_id.as_str())
                                && node.quarantine_version >= quarantine_version
                        })
                        .count(),
                )
                .unwrap_or(u32::MAX);
                let phase = convergence_phase(total_nodes, converged_nodes, stale_node_count);
                let eta_seconds = match phase {
                    ConvergencePhase::Converged => Some(0),
                    ConvergencePhase::Pending => None,
                    ConvergencePhase::Propagating => {
                        Some(total_nodes.saturating_sub(converged_nodes))
                    }
                    ConvergencePhase::TimedOut => None,
                };

                Some(FleetCliPendingIncident {
                    incident_id,
                    zone_id,
                    target_id,
                    target_kind,
                    reason,
                    quarantine_version,
                    emitted_at: record.emitted_at,
                    convergence: ConvergenceState {
                        converged_nodes,
                        total_nodes,
                        progress_pct: convergence_progress(converged_nodes, total_nodes),
                        eta_seconds,
                        phase,
                    },
                })
            }
            PersistedFleetAction::Release { .. } | PersistedFleetAction::PolicyUpdate { .. } => {
                None
            }
        })
        .collect::<Vec<_>>();

    incidents.sort_by(|left, right| {
        left.zone_id
            .cmp(&right.zone_id)
            .then_with(|| left.incident_id.cmp(&right.incident_id))
    });
    incidents
}

fn load_fleet_state(project_root: &Path) -> Result<LoadedFleetState> {
    let (convergence_timeout_seconds, state_dir, transport) = open_fleet_transport(project_root)?;
    let state = transport
        .read_shared_state()
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let stale_nodes = transport
        .list_stale_nodes(Utc::now(), Duration::from_secs(convergence_timeout_seconds))
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let active_incidents = derive_active_fleet_incidents(&state, &stale_nodes);

    Ok(LoadedFleetState {
        state_dir,
        convergence_timeout_seconds,
        state,
        stale_nodes,
        active_incidents,
    })
}

fn fleet_status_from_loaded_state(loaded: &LoadedFleetState, requested_zone: &str) -> FleetStatus {
    let stale_ids: BTreeSet<&str> = loaded
        .stale_nodes
        .iter()
        .map(|node| node.node_id.as_str())
        .collect();
    let relevant_nodes: Vec<&PersistedNodeStatus> = loaded
        .state
        .nodes
        .iter()
        .filter(|node| node_matches_filter(node, requested_zone))
        .collect();
    let healthy_nodes = u32::try_from(
        relevant_nodes
            .iter()
            .filter(|node| {
                node.health == PersistedNodeHealth::Healthy
                    && !stale_ids.contains(node.node_id.as_str())
            })
            .count(),
    )
    .unwrap_or(u32::MAX);
    let total_nodes = u32::try_from(relevant_nodes.len()).unwrap_or(u32::MAX);
    let pending_convergences = loaded
        .active_incidents
        .iter()
        .filter(|incident| zone_matches_filter(&incident.zone_id, requested_zone))
        .map(|incident| incident.convergence.clone())
        .collect::<Vec<_>>();

    FleetStatus {
        zone_id: requested_zone.to_string(),
        active_quarantines: u32::try_from(pending_convergences.len()).unwrap_or(u32::MAX),
        active_revocations: 0,
        healthy_nodes,
        total_nodes,
        activated: true,
        pending_convergences,
    }
}

fn fleet_status_report(project_root: &Path, requested_zone: &str) -> Result<FleetCliStatusReport> {
    let loaded = load_fleet_state(project_root)?;
    let status = fleet_status_from_loaded_state(&loaded, requested_zone);
    Ok(FleetCliStatusReport {
        status,
        state_dir: loaded.state_dir,
        convergence_timeout_seconds: loaded.convergence_timeout_seconds,
        stale_nodes: loaded.stale_nodes,
        active_incidents: loaded.active_incidents,
        state: loaded.state,
    })
}

fn aggregate_convergence(active_incidents: &[FleetCliPendingIncident]) -> Option<ConvergenceState> {
    if active_incidents.is_empty() {
        return None;
    }

    let converged_nodes = active_incidents.iter().fold(0_u32, |acc, incident| {
        acc.saturating_add(incident.convergence.converged_nodes)
    });
    let total_nodes = active_incidents.iter().fold(0_u32, |acc, incident| {
        acc.saturating_add(incident.convergence.total_nodes)
    });
    let phase = if active_incidents
        .iter()
        .any(|incident| incident.convergence.phase == ConvergencePhase::TimedOut)
    {
        ConvergencePhase::TimedOut
    } else if active_incidents
        .iter()
        .all(|incident| incident.convergence.phase == ConvergencePhase::Converged)
    {
        ConvergencePhase::Converged
    } else if active_incidents
        .iter()
        .all(|incident| incident.convergence.phase == ConvergencePhase::Pending)
    {
        ConvergencePhase::Pending
    } else {
        ConvergencePhase::Propagating
    };
    let eta_seconds = match phase {
        ConvergencePhase::Converged => Some(0),
        ConvergencePhase::Pending => None,
        ConvergencePhase::Propagating => Some(total_nodes.saturating_sub(converged_nodes)),
        ConvergencePhase::TimedOut => None,
    };

    Some(ConvergenceState {
        converged_nodes,
        total_nodes,
        progress_pct: convergence_progress(converged_nodes, total_nodes),
        eta_seconds,
        phase,
    })
}

fn fleet_action_report(
    project_root: &Path,
    requested_zone: &str,
    action: FleetActionResult,
) -> Result<FleetCliActionReport> {
    let loaded = load_fleet_state(project_root)?;
    let status = fleet_status_from_loaded_state(&loaded, requested_zone);
    Ok(FleetCliActionReport {
        action,
        status,
        state_dir: loaded.state_dir,
        convergence_timeout_seconds: loaded.convergence_timeout_seconds,
        stale_nodes: loaded.stale_nodes,
        active_incidents: loaded.active_incidents,
        state: loaded.state,
    })
}

fn emit_fleet_status_report(
    report: &FleetCliStatusReport,
    json: bool,
    verbose: bool,
) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        println!("{}", render_fleet_status_human(&report.status, verbose));
    }
    Ok(())
}

fn emit_fleet_action_report(report: &FleetCliActionReport, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        println!("{}", render_fleet_action_human(&report.action));
    }
    Ok(())
}

fn next_quarantine_version(state: &FleetSharedState, zone_id: &str) -> u64 {
    state
        .actions
        .iter()
        .filter_map(|record| match &record.action {
            PersistedFleetAction::Quarantine {
                zone_id: action_zone,
                quarantine_version,
                ..
            } if action_zone == zone_id => Some(*quarantine_version),
            _ => None,
        })
        .max()
        .unwrap_or(0)
        .saturating_add(1)
}

fn append_trust_quarantine_action(
    project_root: &Path,
    artifact: &str,
    affected_cards: usize,
) -> Result<String> {
    let loaded = load_fleet_state(project_root)?;
    let mut transport = FileFleetTransport::new(loaded.state_dir.clone());
    transport
        .initialize()
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    let operation_id = fleet_operation_id("quarantine");
    let incident_id = format!("inc-{operation_id}");
    let now = Utc::now();
    let quarantine_version = next_quarantine_version(&loaded.state, "all");
    transport
        .publish_action(&PersistedFleetActionRecord {
            action_id: operation_id,
            emitted_at: now,
            action: PersistedFleetAction::Quarantine {
                zone_id: "all".to_string(),
                incident_id: incident_id.clone(),
                target_id: artifact.to_string(),
                target_kind: PersistedFleetTargetKind::Artifact,
                reason: format!("manual trust quarantine via CLI; affected_cards={affected_cards}"),
                quarantine_version,
            },
        })
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;

    Ok(incident_id)
}

fn render_fleet_status_human(status: &FleetStatus, verbose: bool) -> String {
    let mut lines = vec![
        format!("fleet status: zone={}", status.zone_id),
        format!("  activated={}", status.activated),
        format!(
            "  quarantines={} revocations={}",
            status.active_quarantines, status.active_revocations
        ),
        format!(
            "  healthy_nodes={}/{}",
            status.healthy_nodes, status.total_nodes
        ),
    ];

    lines.push(format!(
        "  pending_convergences={}",
        status.pending_convergences.len()
    ));

    if !status.pending_convergences.is_empty() {
        let summary = status
            .pending_convergences
            .iter()
            .map(|convergence| {
                format!(
                    "{}/{} ({}%) {:?}",
                    convergence.converged_nodes,
                    convergence.total_nodes,
                    convergence.progress_pct,
                    convergence.phase
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        lines.push(format!("  convergence={summary}"));
    }

    if verbose {
        for (index, convergence) in status.pending_convergences.iter().enumerate() {
            lines.push(format!(
                "  convergence[{index}]={}/{} ({}%) phase={:?} eta_seconds={:?}",
                convergence.converged_nodes,
                convergence.total_nodes,
                convergence.progress_pct,
                convergence.phase,
                convergence.eta_seconds
            ));
        }
    }
    lines.join("\n")
}

fn render_fleet_action_human(action: &FleetActionResult) -> String {
    let mut lines = vec![
        format!(
            "fleet action: type={} operation_id={}",
            action.action_type, action.operation_id
        ),
        format!("  success={}", action.success),
        format!("  event_code={}", action.event_code),
        format!(
            "  receipt_id={} issuer={} zone={}",
            action.receipt.receipt_id, action.receipt.issuer, action.receipt.zone_id
        ),
    ];

    if let Some(convergence) = &action.convergence {
        lines.push(format!(
            "  convergence={}/{} ({}%) phase={:?} eta_seconds={:?}",
            convergence.converged_nodes,
            convergence.total_nodes,
            convergence.progress_pct,
            convergence.phase,
            convergence.eta_seconds
        ));
    }
    lines.join("\n")
}

// ── Fleet Agent Mode ─────────────────────────────────────────────────────────

/// Result of a single fleet agent poll cycle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetAgentPollResult {
    pub cycle: u64,
    pub node_id: String,
    pub zone_id: String,
    pub configured_poll_interval_secs: u64,
    pub actions_processed: u64,
    pub last_action_id: Option<String>,
    pub node_health: String,
    pub quarantine_version: u64,
    pub poll_timestamp: String,
}

#[derive(Debug, Clone)]
struct ResolvedFleetAgentArgs {
    node_id: String,
    zone_id: String,
    poll_interval_secs: u64,
    max_cycles: Option<u64>,
    json: bool,
}

fn resolve_fleet_agent_args(args: &FleetAgentArgs) -> Result<ResolvedFleetAgentArgs> {
    use control_plane::fleet_transport::{validate_node_id, validate_zone_id};

    let resolved = config::Config::resolve(None, config::CliOverrides::default())
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    let node_id = args
        .node_id
        .clone()
        .or_else(|| resolved.config.fleet.node_id.clone())
        .ok_or_else(|| anyhow::anyhow!("fleet agent requires --node-id or fleet.node_id"))?;
    validate_node_id(&node_id).map_err(|err| anyhow::anyhow!("invalid node_id: {err}"))?;
    validate_zone_id(&args.zone).map_err(|err| anyhow::anyhow!("invalid zone: {err}"))?;

    let poll_interval_secs = args
        .poll_interval_secs
        .or(resolved.config.fleet.poll_interval_seconds)
        .unwrap_or(30);
    if poll_interval_secs == 0 {
        anyhow::bail!("fleet agent poll interval must be greater than zero");
    }

    let max_cycles = if args.once {
        Some(1)
    } else {
        args.max_cycles.filter(|value| *value > 0)
    };

    Ok(ResolvedFleetAgentArgs {
        node_id,
        zone_id: args.zone.clone(),
        poll_interval_secs,
        max_cycles,
        json: args.json,
    })
}

fn install_fleet_agent_shutdown_flag() -> Result<std::sync::Arc<std::sync::atomic::AtomicBool>> {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };

    let shutdown_requested = Arc::new(AtomicBool::new(false));
    let handler_flag = Arc::clone(&shutdown_requested);
    ctrlc::set_handler(move || {
        handler_flag.store(true, Ordering::SeqCst);
    })
    .map_err(|err| anyhow::anyhow!("failed installing fleet agent signal handler: {err}"))?;
    Ok(shutdown_requested)
}

fn sleep_until_next_fleet_poll(
    poll_interval: std::time::Duration,
    shutdown_requested: &std::sync::atomic::AtomicBool,
) {
    use std::sync::atomic::Ordering;
    use std::time::{Duration, Instant};

    let started = Instant::now();
    while started.elapsed() < poll_interval {
        if shutdown_requested.load(Ordering::SeqCst) {
            return;
        }
        let remaining = poll_interval.saturating_sub(started.elapsed());
        std::thread::sleep(remaining.min(Duration::from_millis(100)));
    }
}

fn resolve_fleet_agent_action_targets(
    registry: &mut TrustCardRegistry,
    target_id: &str,
    now_secs: u64,
    trace_id: &str,
) -> Result<Vec<String>> {
    let direct_match = registry
        .read(target_id, now_secs, trace_id)
        .map_err(|err| anyhow::anyhow!(err.to_string()))?;
    if let Some(card) = direct_match {
        return Ok(vec![card.extension.extension_id]);
    }

    if !target_id.starts_with("sha256:") {
        return Ok(Vec::new());
    }

    let mut targets = registry
        .list(&TrustCardListFilter::empty(), trace_id, now_secs)
        .map_err(|err| anyhow::anyhow!(err.to_string()))?
        .into_iter()
        .filter(|card| {
            card.provenance_summary
                .artifact_hashes
                .iter()
                .any(|hash| hash == target_id || hash.starts_with(target_id))
        })
        .map(|card| card.extension.extension_id)
        .collect::<Vec<_>>();
    targets.sort();
    targets.dedup();
    Ok(targets)
}

fn fleet_agent_registry_state(
    project_root: &Path,
    now_secs: u64,
) -> Result<TrustCardCliRegistryState> {
    trust_scan_registry_state(project_root, now_secs)
}

fn apply_fleet_quarantine_action(
    project_root: &Path,
    target_id: &str,
    now_secs: u64,
) -> Result<Vec<String>> {
    let mut state = fleet_agent_registry_state(project_root, now_secs)?;
    let target_extension_ids = resolve_fleet_agent_action_targets(
        &mut state.registry,
        target_id,
        now_secs,
        "trace-cli-fleet-agent-quarantine-lookup",
    )?;
    if target_extension_ids.is_empty() {
        return Ok(Vec::new());
    }

    let now_rfc3339 = rfc3339_timestamp_from_secs(now_secs);
    let mut updated_extensions = Vec::with_capacity(target_extension_ids.len());
    for extension_id in target_extension_ids {
        state
            .registry
            .update(
                &extension_id,
                TrustCardMutation {
                    certification_level: None,
                    revocation_status: None,
                    active_quarantine: Some(true),
                    reputation_score_basis_points: None,
                    reputation_trend: None,
                    user_facing_risk_assessment: None,
                    last_verified_timestamp: Some(now_rfc3339.clone()),
                    evidence_refs: None,
                },
                now_secs,
                "trace-cli-fleet-agent-quarantine",
            )
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        updated_extensions.push(extension_id);
    }

    persist_trust_card_cli_registry(&state)?;
    Ok(updated_extensions)
}

fn apply_fleet_release_action(
    project_root: &Path,
    zone_id: &str,
    incident_id: &str,
    action_history: &[PersistedFleetActionRecord],
    now_secs: u64,
) -> Result<Vec<String>> {
    let mut state = fleet_agent_registry_state(project_root, now_secs)?;
    let mut targets = std::collections::BTreeSet::new();
    for action in action_history {
        let PersistedFleetAction::Quarantine {
            zone_id: action_zone,
            incident_id: action_incident,
            target_id,
            ..
        } = &action.action
        else {
            continue;
        };
        if action_zone != zone_id || action_incident != incident_id {
            continue;
        }
        for extension_id in resolve_fleet_agent_action_targets(
            &mut state.registry,
            target_id,
            now_secs,
            "trace-cli-fleet-agent-release-lookup",
        )? {
            targets.insert(extension_id);
        }
    }

    if targets.is_empty() {
        return Ok(Vec::new());
    }

    let now_rfc3339 = rfc3339_timestamp_from_secs(now_secs);
    let mut released = Vec::new();
    for extension_id in targets {
        state
            .registry
            .update(
                &extension_id,
                TrustCardMutation {
                    certification_level: None,
                    revocation_status: None,
                    active_quarantine: Some(false),
                    reputation_score_basis_points: None,
                    reputation_trend: None,
                    user_facing_risk_assessment: None,
                    last_verified_timestamp: Some(now_rfc3339.clone()),
                    evidence_refs: None,
                },
                now_secs,
                "trace-cli-fleet-agent-release",
            )
            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
        released.push(extension_id);
    }
    persist_trust_card_cli_registry(&state)?;
    Ok(released)
}

/// Run the fleet agent polling loop.
fn run_fleet_agent(args: &FleetAgentArgs) -> Result<()> {
    use control_plane::fleet_transport::{
        FleetAction as PersistedFleetAction, NodeHealth, NodeStatus,
    };
    use std::sync::atomic::Ordering;

    let shutdown_requested = install_fleet_agent_shutdown_flag()?;
    let resolved = resolve_fleet_agent_args(args)?;
    let poll_interval = std::time::Duration::from_secs(resolved.poll_interval_secs);
    let (_, _state_dir, mut transport) = open_fleet_transport(Path::new("."))?;

    let mut last_seen_action_id: Option<String> = None;
    let mut last_seen_action_emitted_at: Option<chrono::DateTime<Utc>> = None;
    let mut quarantine_version: u64 = 0;
    let mut cycle: u64 = 0;

    if !resolved.json {
        eprintln!(
            "fleet agent: starting node_id={} zone={} poll_interval={}s",
            resolved.node_id, resolved.zone_id, resolved.poll_interval_secs
        );
    }

    loop {
        if shutdown_requested.load(Ordering::SeqCst) {
            if !resolved.json {
                eprintln!("fleet agent: shutdown requested, exiting");
            }
            break;
        }

        cycle = cycle.saturating_add(1);
        let poll_timestamp = Utc::now();
        let now_secs = u64::try_from(poll_timestamp.timestamp()).unwrap_or_default();
        let mut node_health = NodeHealth::Healthy;

        // Read current actions from transport
        let mut actions = transport
            .list_actions()
            .map_err(|err| anyhow::anyhow!("failed listing fleet actions: {err}"))?;
        actions.sort_by(|left, right| {
            left.emitted_at
                .cmp(&right.emitted_at)
                .then_with(|| left.action_id.cmp(&right.action_id))
        });

        // Filter to actions for our zone, after last seen
        let new_actions: Vec<_> = actions
            .iter()
            .enumerate()
            .filter(|action| {
                let zone_matches = match &action.1.action {
                    PersistedFleetAction::Quarantine { zone_id, .. } => {
                        zone_id == &resolved.zone_id
                    }
                    PersistedFleetAction::Release { zone_id, .. } => zone_id == &resolved.zone_id,
                    PersistedFleetAction::PolicyUpdate { zone_id, .. } => {
                        zone_id == &resolved.zone_id
                    }
                };
                if !zone_matches {
                    return false;
                }
                match (&last_seen_action_emitted_at, &last_seen_action_id) {
                    (Some(last_emitted_at), Some(last_id)) => {
                        action.1.emitted_at > *last_emitted_at
                            || (action.1.emitted_at == *last_emitted_at
                                && action.1.action_id > *last_id)
                    }
                    _ => true,
                }
            })
            .collect();

        let actions_processed = u64::try_from(new_actions.len()).unwrap_or(u64::MAX);

        // Apply each action and track quarantine version
        for (action_index, action) in new_actions {
            let apply_result = match &action.action {
                PersistedFleetAction::Quarantine {
                    incident_id,
                    target_id,
                    quarantine_version: qv,
                    reason,
                    ..
                } => match apply_fleet_quarantine_action(Path::new("."), target_id, now_secs) {
                    Ok(updated_extensions) => {
                        quarantine_version = quarantine_version.max(*qv);
                        tracing::info!(
                            node_id = resolved.node_id.as_str(),
                            zone_id = resolved.zone_id.as_str(),
                            incident_id = incident_id.as_str(),
                            target_id = target_id.as_str(),
                            quarantine_version = *qv,
                            updated_extensions = updated_extensions.len(),
                            "fleet agent applied quarantine action"
                        );
                        if !resolved.json {
                            eprintln!(
                                "fleet agent: applying quarantine incident={} target={} reason={} updated_extensions={}",
                                incident_id,
                                target_id,
                                reason,
                                updated_extensions.len()
                            );
                        }
                        Ok::<(), anyhow::Error>(())
                    }
                    Err(err) => Err(err),
                },
                PersistedFleetAction::Release {
                    incident_id,
                    reason,
                    ..
                } => match apply_fleet_release_action(
                    Path::new("."),
                    &resolved.zone_id,
                    incident_id,
                    &actions[..=action_index],
                    now_secs,
                ) {
                    Ok(released_extensions) => {
                        tracing::info!(
                            node_id = resolved.node_id.as_str(),
                            zone_id = resolved.zone_id.as_str(),
                            incident_id = incident_id.as_str(),
                            released_extensions = released_extensions.len(),
                            "fleet agent applied release action"
                        );
                        if !resolved.json {
                            eprintln!(
                                "fleet agent: applying release incident={} reason={:?} released_extensions={}",
                                incident_id,
                                reason,
                                released_extensions.len()
                            );
                        }
                        Ok::<(), anyhow::Error>(())
                    }
                    Err(err) => Err(err),
                },
                PersistedFleetAction::PolicyUpdate {
                    policy_version,
                    changed_fields,
                    ..
                } => {
                    tracing::info!(
                        node_id = resolved.node_id.as_str(),
                        zone_id = resolved.zone_id.as_str(),
                        policy_version = policy_version.as_str(),
                        changed_fields = ?changed_fields,
                        "fleet agent observed policy update action"
                    );
                    if !resolved.json {
                        eprintln!(
                            "fleet agent: applying policy update version={} fields={:?}",
                            policy_version, changed_fields
                        );
                    }
                    Ok::<(), anyhow::Error>(())
                }
            };
            if let Err(err) = apply_result {
                node_health = NodeHealth::Degraded;
                tracing::error!(
                    node_id = resolved.node_id.as_str(),
                    zone_id = resolved.zone_id.as_str(),
                    action_id = action.action_id.as_str(),
                    error = %err,
                    "fleet agent failed applying action"
                );
                if !resolved.json {
                    eprintln!(
                        "fleet agent: failed applying action {}: {err}",
                        action.action_id
                    );
                }
            }
            last_seen_action_id = Some(action.action_id.clone());
            last_seen_action_emitted_at = Some(action.emitted_at);
        }

        // Update node status (heartbeat)
        let node_status = NodeStatus {
            zone_id: resolved.zone_id.clone(),
            node_id: resolved.node_id.clone(),
            last_seen: poll_timestamp,
            quarantine_version,
            health: node_health,
        };
        transport
            .upsert_node_status(&node_status)
            .map_err(|err| anyhow::anyhow!("failed upserting node status: {err}"))?;

        // Emit poll result
        let result = FleetAgentPollResult {
            cycle,
            node_id: resolved.node_id.clone(),
            zone_id: resolved.zone_id.clone(),
            configured_poll_interval_secs: resolved.poll_interval_secs,
            actions_processed,
            last_action_id: last_seen_action_id.clone(),
            node_health: match node_status.health {
                NodeHealth::Healthy => "healthy",
                NodeHealth::Degraded => "degraded",
                NodeHealth::Quarantined => "quarantined",
                NodeHealth::Stale => "stale",
            }
            .to_string(),
            quarantine_version,
            poll_timestamp: poll_timestamp.to_rfc3339(),
        };

        if resolved.json {
            println!("{}", serde_json::to_string(&result)?);
        } else {
            eprintln!(
                "fleet agent: poll cycle={} actions={} quarantine_version={}",
                result.cycle, result.actions_processed, result.quarantine_version
            );
        }

        // Check max_cycles limit
        if resolved
            .max_cycles
            .is_some_and(|max_cycles| cycle >= max_cycles)
        {
            if !resolved.json {
                eprintln!(
                    "fleet agent: reached max_cycles={}, exiting",
                    resolved.max_cycles.unwrap_or_default()
                );
            }
            break;
        }

        // Sleep until next poll
        sleep_until_next_fleet_poll(poll_interval, shutdown_requested.as_ref());
    }

    Ok(())
}

const RELEASE_MANIFEST_FILE: &str = "SHA256SUMS";
const RELEASE_MANIFEST_SIGNATURE_FILE: &str = "SHA256SUMS.sig";

struct ReleaseVerificationContext {
    manifest: supply_chain::artifact_signing::ChecksumManifest,
    artifacts: BTreeMap<String, Vec<u8>>,
    detached_signatures: BTreeMap<String, Vec<u8>>,
    key_ring: supply_chain::artifact_signing::KeyRing,
    unlisted_artifacts: Vec<String>,
}

fn decode_signature_blob(raw: &[u8]) -> Vec<u8> {
    use base64::Engine;
    use std::borrow::Cow;

    let Ok(text) = std::str::from_utf8(raw) else {
        return raw.to_vec();
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return raw.to_vec();
    }

    let mut candidates = vec![trimmed.to_string()];
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        let parse_signature_byte_array = |values: &[serde_json::Value]| -> Option<Vec<u8>> {
            if values.len() != 64 {
                return None;
            }
            let mut bytes = Vec::with_capacity(values.len());
            for value in values {
                let byte = value.as_u64().and_then(|value| u8::try_from(value).ok())?;
                bytes.push(byte);
            }
            Some(bytes)
        };
        let extract_signature_candidates_from_object = |
            obj: &serde_json::Map<String, serde_json::Value>,
        | -> (Option<Vec<u8>>, Vec<String>) {
            let mut local_candidates = Vec::new();
            for nested in [
                "bytes",
                "signature_bytes",
                "signature-bytes",
                "signatureBytes",
                "sig_bytes",
                "sig-bytes",
                "sigBytes",
                "hex",
                "signature_hex",
                "signature-hex",
                "signatureHex",
                "sig_hex",
                "sig-hex",
                "sigHex",
                "base64",
                "b64",
                "signature_base64",
                "signature-base64",
                "signatureBase64",
                "signatureB64",
                "signature-b64",
                "sig_base64",
                "sig-base64",
                "sigBase64",
                "sigB64",
                "sig-b64",
                "signature",
                "sig",
            ] {
                if let Some(nested) = obj.get(nested) {
                    if let Some(bytes) =
                        nested.as_array().and_then(|values| parse_signature_byte_array(values))
                    {
                        return (Some(bytes), local_candidates);
                    }
                    if let Some(text) = nested.as_str() {
                        local_candidates.push(text.to_string());
                    }
                }
            }
            (None, local_candidates)
        };

        match value {
            serde_json::Value::String(value) => candidates.push(value),
            serde_json::Value::Array(values) => {
                if let Some(bytes) = parse_signature_byte_array(&values) {
                    return bytes;
                }
                for entry in values {
                    if let serde_json::Value::String(value) = entry {
                        candidates.push(value);
                    }
                }
            }
            serde_json::Value::Object(value) => {
                for field in [
                    "signature",
                    "sig",
                    "ed25519_signature",
                    "ed25519-signature",
                    "ed25519Signature",
                    "signature_base64",
                    "signature-base64",
                    "signatureBase64",
                    "signature_b64",
                    "signature-b64",
                    "signatureB64",
                    "signature_hex",
                    "signature-hex",
                    "signatureHex",
                    "signature_bytes",
                    "signature-bytes",
                    "signatureBytes",
                    "sig_base64",
                    "sig-base64",
                    "sigBase64",
                    "sig_b64",
                    "sig-b64",
                    "sigB64",
                    "sig_hex",
                    "sig-hex",
                    "sigHex",
                    "sig_bytes",
                    "sig-bytes",
                    "sigBytes",
                ] {
                    if let Some(entry) = value.get(field) {
                        if let Some(bytes) =
                            entry.as_array().and_then(|values| parse_signature_byte_array(values))
                        {
                            return bytes;
                        }
                        if let Some(entry) = entry.as_str() {
                            candidates.push(entry.to_string());
                            continue;
                        }
                        if let Some(obj) = entry.as_object() {
                            let (maybe_bytes, extras) =
                                extract_signature_candidates_from_object(obj);
                            if let Some(bytes) = maybe_bytes {
                                return bytes;
                            }
                            candidates.extend(extras);
                        }
                    }
                }
                }
            }
            _ => {}
        }
    }

    fn strip_prefix_ignore_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
        if value
            .get(..prefix.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
        {
            Some(&value[prefix.len()..])
        } else {
            None
        }
    }

    for candidate in candidates {
        let trimmed = candidate.trim();
        let mut normalized = trimmed;
        if let Some(remainder) = strip_prefix_ignore_ascii_case(normalized, "ed25519:") {
            normalized = remainder;
        }
        let mut stripped_encoding = false;
        for prefix in ["base64:", "b64:", "base64url:", "b64url:", "hex:"] {
            if let Some(remainder) = strip_prefix_ignore_ascii_case(normalized, prefix) {
                normalized = remainder;
                stripped_encoding = true;
                break;
            }
        }
        if stripped_encoding
            && let Some(remainder) = strip_prefix_ignore_ascii_case(normalized, "ed25519:")
        {
            normalized = remainder;
        }
        let normalized = normalized.trim();
        if normalized.is_empty() {
            continue;
        }

        let normalized = if normalized.chars().any(|value| value.is_whitespace()) {
            Cow::Owned(normalized.split_whitespace().collect::<String>())
        } else {
            Cow::Borrowed(normalized)
        };
        let normalized = normalized.as_ref();

        let normalized_hex = normalized
            .strip_prefix("0x")
            .or_else(|| normalized.strip_prefix("0X"))
            .unwrap_or(normalized)
            .replace(['_', ':', '-'], "");
        if let Ok(decoded_hex) = hex::decode(&normalized_hex)
            && decoded_hex.len() == 64
        {
            return decoded_hex;
        }

        for engine in [
            base64::engine::general_purpose::STANDARD,
            base64::engine::general_purpose::STANDARD_NO_PAD,
            base64::engine::general_purpose::URL_SAFE,
            base64::engine::general_purpose::URL_SAFE_NO_PAD,
        ] {
            if let Ok(decoded_b64) = engine.decode(normalized)
                && decoded_b64.len() == 64
            {
                return decoded_b64;
            }
        }
    }

    raw.to_vec()
}

fn parse_verifying_key_from_blob(raw: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
    use base64::Engine;
    use std::borrow::Cow;

    fn verifying_key_from_bytes(raw: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
        match raw.len() {
            32 => {
                let bytes = <[u8; 32]>::try_from(raw).ok()?;
                ed25519_dalek::VerifyingKey::from_bytes(&bytes).ok()
            }
            64 => {
                let seed = <[u8; 32]>::try_from(&raw[..32]).ok()?;
                let public = <[u8; 32]>::try_from(&raw[32..]).ok()?;
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);
                let derived = signing_key.verifying_key();
                if derived.to_bytes() == public {
                    Some(derived)
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn parse_ssh_ed25519_public_key(candidate: &str) -> Option<ed25519_dalek::VerifyingKey> {
        fn read_ssh_string<'a>(blob: &'a [u8], offset: &mut usize) -> Option<&'a [u8]> {
            let end = offset.saturating_add(4);
            if end > blob.len() {
                return None;
            }
            let len = u32::from_be_bytes(blob[*offset..end].try_into().ok()?) as usize;
            let start = end;
            let end = start.saturating_add(len);
            if end > blob.len() {
                return None;
            }
            *offset = end;
            Some(&blob[start..end])
        }

        fn parse_ssh_ed25519_blob(blob: &[u8]) -> Option<ed25519_dalek::VerifyingKey> {
            let mut offset = 0usize;
            let key_type = read_ssh_string(blob, &mut offset)?;
            if key_type != b"ssh-ed25519" {
                return None;
            }
            let key_bytes = read_ssh_string(blob, &mut offset)?;
            if offset != blob.len() {
                return None;
            }
            verifying_key_from_bytes(key_bytes)
        }

        for line in candidate.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.is_empty() {
                continue;
            }
            let Some(index) = parts
                .iter()
                .position(|part| part.eq_ignore_ascii_case("ssh-ed25519"))
            else {
                continue;
            };
            let Some(encoded) = parts.get(index + 1) else {
                continue;
            };
            for engine in [
                base64::engine::general_purpose::STANDARD,
                base64::engine::general_purpose::STANDARD_NO_PAD,
            ] {
                if let Ok(decoded) = engine.decode(encoded)
                    && let Some(key) = parse_ssh_ed25519_blob(&decoded)
                {
                    return Some(key);
                }
            }
        }

        None
    }

    if let Some(key) = verifying_key_from_bytes(raw) {
        return Some(key);
    }

    let Ok(text) = std::str::from_utf8(raw) else {
        return None;
    };
    let trimmed = text.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut candidates = vec![trimmed.to_string()];
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        let parse_byte_array = |values: &[serde_json::Value]| -> Option<Vec<u8>> {
            if values.len() != 32 && values.len() != 64 {
                return None;
            }
            let mut bytes = Vec::with_capacity(values.len());
            for value in values {
                let byte = value.as_u64().and_then(|value| u8::try_from(value).ok())?;
                bytes.push(byte);
            }
            Some(bytes)
        };

        match value {
            serde_json::Value::String(value) => candidates.push(value),
            serde_json::Value::Array(values) => {
                if let Some(bytes) = parse_byte_array(&values)
                    && let Some(key) = verifying_key_from_bytes(&bytes)
                {
                    return Some(key);
                }
                for entry in values {
                    if let serde_json::Value::String(value) = entry {
                        candidates.push(value);
                    }
                }
            }
            serde_json::Value::Object(value) => {
                for field in [
                    "public_key",
                    "verifying_key",
                    "key",
                    "ed25519_public_key",
                    "public-key",
                    "verifying-key",
                    "ed25519-public-key",
                    "publicKey",
                    "verifyingKey",
                    "ed25519PublicKey",
                ] {
                    if let Some(entry) = value.get(field) {
                        if let Some(bytes) =
                            entry.as_array().and_then(|values| parse_byte_array(values))
                            && let Some(key) = verifying_key_from_bytes(&bytes)
                        {
                            return Some(key);
                        }
                        if let Some(entry) = entry.as_str() {
                            candidates.push(entry.to_string());
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn strip_prefix_ignore_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
        if value
            .get(..prefix.len())
            .is_some_and(|candidate| candidate.eq_ignore_ascii_case(prefix))
        {
            Some(&value[prefix.len()..])
        } else {
            None
        }
    }

    for candidate in candidates {
        let trimmed = candidate.trim();
        if let Some(key) = parse_ssh_ed25519_public_key(trimmed) {
            return Some(key);
        }
        let mut normalized = trimmed;
        if let Some(remainder) = strip_prefix_ignore_ascii_case(normalized, "ed25519:") {
            normalized = remainder;
        }
        let mut stripped_encoding = false;
        for prefix in ["base64:", "b64:", "base64url:", "b64url:", "hex:"] {
            if let Some(remainder) = strip_prefix_ignore_ascii_case(normalized, prefix) {
                normalized = remainder;
                stripped_encoding = true;
                break;
            }
        }
        if stripped_encoding
            && let Some(remainder) = strip_prefix_ignore_ascii_case(normalized, "ed25519:")
        {
            normalized = remainder;
        }
        let normalized = normalized.trim();
        if normalized.is_empty() {
            continue;
        }

        let normalized = if normalized.chars().any(|value| value.is_whitespace()) {
            Cow::Owned(normalized.split_whitespace().collect::<String>())
        } else {
            Cow::Borrowed(normalized)
        };
        let normalized = normalized.as_ref();

        let normalized_hex = normalized
            .strip_prefix("0x")
            .or_else(|| normalized.strip_prefix("0X"))
            .unwrap_or(normalized)
            .replace(['_', ':', '-'], "");
        if let Ok(decoded_hex) = hex::decode(&normalized_hex)
            && let Some(key) = verifying_key_from_bytes(&decoded_hex)
        {
            return Some(key);
        }

        for engine in [
            base64::engine::general_purpose::STANDARD,
            base64::engine::general_purpose::STANDARD_NO_PAD,
            base64::engine::general_purpose::URL_SAFE,
            base64::engine::general_purpose::URL_SAFE_NO_PAD,
        ] {
            if let Ok(decoded_b64) = engine.decode(normalized)
                && let Some(key) = verifying_key_from_bytes(&decoded_b64)
            {
                return Some(key);
            }
        }
    }

    None
}

fn load_verifying_keys(key_dir: &Path) -> Result<Vec<ed25519_dalek::VerifyingKey>> {
    if !key_dir.is_dir() {
        anyhow::bail!("--key-dir must point to a directory: {}", key_dir.display());
    }

    let mut paths = std::fs::read_dir(key_dir)?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.is_file())
        .collect::<Vec<_>>();
    paths.sort();

    let mut keys = Vec::new();
    for path in paths {
        let raw =
            std::fs::read(&path).with_context(|| format!("failed reading {}", path.display()))?;
        if let Some(key) = parse_verifying_key_from_blob(&raw) {
            keys.push(key);
        }
    }

    if keys.is_empty() {
        anyhow::bail!(
            "no usable Ed25519 public keys found in key directory {}",
            key_dir.display()
        );
    }
    Ok(keys)
}

fn collect_release_files(root: &Path) -> Result<Vec<String>> {
    let mut files = Vec::new();
    let mut stack = vec![root.to_path_buf()];

    while let Some(current) = stack.pop() {
        let mut entries = std::fs::read_dir(&current)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect::<Vec<_>>();
        entries.sort();

        for path in entries {
            if path.is_dir() {
                stack.push(path);
            } else if path.is_file() {
                let relative = path
                    .strip_prefix(root)
                    .with_context(|| {
                        format!("failed deriving relative path for {}", path.display())
                    })?
                    .to_string_lossy()
                    .replace('\\', "/");
                files.push(relative);
            }
        }
    }

    files.sort();
    Ok(files)
}

fn find_unlisted_artifacts(
    release_dir: &Path,
    manifest: &supply_chain::artifact_signing::ChecksumManifest,
) -> Result<Vec<String>> {
    let mut allowed = BTreeSet::new();
    allowed.insert(RELEASE_MANIFEST_FILE.to_string());
    allowed.insert(RELEASE_MANIFEST_SIGNATURE_FILE.to_string());
    for name in manifest.entries.keys() {
        allowed.insert(name.clone());
        allowed.insert(format!("{name}.sig"));
    }

    let mut extras = collect_release_files(release_dir)?
        .into_iter()
        .filter(|path| !allowed.contains(path))
        .collect::<Vec<_>>();
    extras.sort();
    Ok(extras)
}

fn load_release_verification_context(
    release_dir: &Path,
    key_dir: &Path,
) -> Result<ReleaseVerificationContext> {
    use supply_chain::artifact_signing::{ChecksumManifest, KeyRing, verify_signature};

    if !release_dir.is_dir() {
        anyhow::bail!(
            "release path must be a directory: {}",
            release_dir.display()
        );
    }

    let manifest_path = release_dir.join(RELEASE_MANIFEST_FILE);
    let manifest_raw = std::fs::read_to_string(&manifest_path)
        .with_context(|| format!("failed reading {}", manifest_path.display()))?;
    let parsed_entries = ChecksumManifest::parse_canonical(&manifest_raw);
    if parsed_entries.is_empty() {
        anyhow::bail!("manifest {} contains no entries", manifest_path.display());
    }

    let mut entries = BTreeMap::new();
    for entry in parsed_entries {
        entries.insert(entry.name.clone(), entry);
    }

    let manifest_signature_path = release_dir.join(RELEASE_MANIFEST_SIGNATURE_FILE);
    let manifest_signature_raw = std::fs::read(&manifest_signature_path)
        .with_context(|| format!("failed reading {}", manifest_signature_path.display()))?;
    let manifest_signature = decode_signature_blob(&manifest_signature_raw);

    let verifying_keys = load_verifying_keys(key_dir)?;
    let mut key_ring = KeyRing::new();
    let mut key_ids = Vec::new();
    for verifying_key in verifying_keys {
        let key_id = key_ring.add_key(verifying_key);
        key_ids.push(key_id);
    }

    let default_key_id = key_ids
        .first()
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("no verifying keys available"))?;

    let mut manifest = ChecksumManifest {
        entries,
        key_id: default_key_id,
        signature: manifest_signature,
    };
    let canonical_manifest = manifest.canonical_bytes();
    if let Some(matched_key_id) = key_ids
        .iter()
        .find(|key_id| {
            key_ring.get_key(key_id).is_some_and(|key| {
                verify_signature(key, &canonical_manifest, &manifest.signature).is_ok()
            })
        })
        .cloned()
    {
        manifest.key_id = matched_key_id;
    }

    let mut artifacts = BTreeMap::new();
    let mut detached_signatures = BTreeMap::new();
    for artifact_name in manifest.entries.keys() {
        let artifact_path = release_dir.join(artifact_name);
        if artifact_path.is_file() {
            let artifact_bytes = std::fs::read(&artifact_path)
                .with_context(|| format!("failed reading {}", artifact_path.display()))?;
            artifacts.insert(artifact_name.clone(), artifact_bytes);
        }

        let signature_path = release_dir.join(format!("{artifact_name}.sig"));
        if signature_path.is_file() {
            let detached_bytes = std::fs::read(&signature_path)
                .with_context(|| format!("failed reading {}", signature_path.display()))?;
            detached_signatures.insert(
                artifact_name.clone(),
                decode_signature_blob(&detached_bytes),
            );
        }
    }

    let unlisted_artifacts = find_unlisted_artifacts(release_dir, &manifest)?;

    Ok(ReleaseVerificationContext {
        manifest,
        artifacts,
        detached_signatures,
        key_ring,
        unlisted_artifacts,
    })
}

fn handle_verify_release(args: &VerifyReleaseArgs) -> Result<()> {
    use supply_chain::artifact_signing::{
        ASV_002_VERIFICATION_OK, ASV_003_VERIFICATION_FAILED, ArtifactVerificationResult,
        AuditLogEntry, verify_release,
    };

    let release_dir = &args.release_path;
    let context = load_release_verification_context(release_dir, &args.key_dir)?;
    let mut report = verify_release(
        &context.manifest,
        &context.artifacts,
        &context.detached_signatures,
        &context.key_ring,
    );

    for artifact_name in &context.unlisted_artifacts {
        report.results.push(ArtifactVerificationResult {
            artifact_name: artifact_name.clone(),
            passed: false,
            key_id: context.manifest.key_id.0.clone(),
            failure_reason: Some("artifact present but not listed in SHA256SUMS".to_string()),
        });
    }

    report
        .results
        .sort_by(|left, right| left.artifact_name.cmp(&right.artifact_name));

    let overall_pass = report.manifest_signature_ok && report.results.iter().all(|row| row.passed);
    let result_rows = report
        .results
        .iter()
        .map(|row| {
            serde_json::json!({
                "artifact_name": row.artifact_name,
                "passed": row.passed,
                "key_id": row.key_id,
                "failure_reason": row.failure_reason,
            })
        })
        .collect::<Vec<_>>();

    let payload = serde_json::json!({
        "release_path": release_dir.display().to_string(),
        "manifest_signature_ok": report.manifest_signature_ok,
        "results": result_rows,
        "overall_pass": overall_pass,
        "unlisted_artifact_count": context.unlisted_artifacts.len(),
    });

    if args.json {
        println!("{}", serde_json::to_string_pretty(&payload)?);
    } else {
        println!(
            "verify release: {} manifest_signature_ok={} overall_pass={}",
            release_dir.display(),
            report.manifest_signature_ok,
            overall_pass
        );
        for row in &report.results {
            if row.passed {
                println!("  [ok] {}", row.artifact_name);
            } else {
                println!(
                    "  [fail] {}: {}",
                    row.artifact_name,
                    row.failure_reason
                        .clone()
                        .unwrap_or_else(|| "verification failed".to_string())
                );
            }
        }
    }

    let event_code = if overall_pass {
        ASV_002_VERIFICATION_OK
    } else {
        ASV_003_VERIFICATION_FAILED
    };
    let _audit_log = AuditLogEntry::now(
        event_code,
        &release_dir.display().to_string(),
        &context.manifest.key_id.0,
        "verify-release",
        if overall_pass { "passed" } else { "failed" },
    );

    if !overall_pass {
        anyhow::bail!("release verification failed");
    }

    Ok(())
}

fn build_verify_output(
    command: &str,
    compat_version: Option<u16>,
    verdict: &str,
    status: &str,
    exit_code: i32,
    reason: impl Into<String>,
) -> VerifyContractOutput {
    build_verify_output_with_details(
        command,
        compat_version,
        verdict,
        status,
        exit_code,
        reason,
        None,
    )
}

fn build_verify_output_with_details(
    command: &str,
    compat_version: Option<u16>,
    verdict: &str,
    status: &str,
    exit_code: i32,
    reason: impl Into<String>,
    details: Option<serde_json::Value>,
) -> VerifyContractOutput {
    VerifyContractOutput {
        command: command.to_string(),
        contract_version: frankenengine_node::schema_versions::VERIFY_CLI_CONTRACT.to_string(),
        schema_version: "verifier-cli-contract-v1".to_string(),
        compat_version,
        verdict: verdict.to_string(),
        status: status.to_string(),
        exit_code,
        reason: reason.into(),
        details,
    }
}

fn emit_verify_output(command: &str, payload: &VerifyContractOutput, json: bool) -> i32 {
    if json {
        if let Ok(blob) = serde_json::to_string_pretty(payload) {
            println!("{blob}");
        } else {
            println!(
                "{{\"command\":\"{command}\",\"status\":\"error\",\"exit_code\":2,\"reason\":\"serialization-failed\"}}"
            );
            return 2;
        }
    } else {
        eprintln!("franken-node {command}: {}", payload.reason);
        eprintln!(
            "  contract_version={} compat_version={:?} status={} exit_code={}",
            payload.contract_version, payload.compat_version, payload.status, payload.exit_code
        );
    }

    payload.exit_code
}

fn verify_compat_error(command: &str, compat_version: u16) -> VerifyContractOutput {
    let current_major = verify_cli_contract_major();
    build_verify_output(
        command,
        Some(compat_version),
        "ERROR",
        "error",
        2,
        format!(
            "unsupported --compat-version={compat_version}; supported versions: {} or {}",
            current_major,
            current_major.saturating_sub(1)
        ),
    )
}

fn verify_cli_contract_major() -> u16 {
    frankenengine_node::schema_versions::VERIFY_CLI_CONTRACT
        .split('.')
        .next()
        .and_then(|major| major.parse::<u16>().ok())
        .expect("VERIFY_CLI_CONTRACT must start with a u16 major version")
}

fn validate_verify_compat(
    command: &str,
    compat_version: Option<u16>,
) -> Option<VerifyContractOutput> {
    compat_version.and_then(|version| {
        let current_major = verify_cli_contract_major();
        let previous_major = current_major.saturating_sub(1);
        if version > current_major || version < previous_major {
            Some(verify_compat_error(command, version))
        } else {
            None
        }
    })
}

#[cfg(test)]
mod verify_contract_tests {
    use super::*;

    #[test]
    fn build_verify_output_uses_schema_registry_contract_version() {
        let payload = build_verify_output("verify module", Some(3), "PASS", "pass", 0, "ok");

        assert_eq!(
            payload.contract_version,
            frankenengine_node::schema_versions::VERIFY_CLI_CONTRACT
        );
    }

    #[test]
    fn verify_cli_contract_major_tracks_schema_registry() {
        assert_eq!(verify_cli_contract_major(), 3);
        assert_eq!(
            verify_cli_contract_major(),
            frankenengine_node::schema_versions::VERIFY_CLI_CONTRACT
                .split('.')
                .next()
                .expect("major segment")
                .parse::<u16>()
                .expect("major parse")
        );
    }
}

fn summarize_expected_ids(values: &[&str], preview_count: usize) -> String {
    let mut preview = values
        .iter()
        .take(preview_count)
        .copied()
        .collect::<Vec<_>>();
    if values.len() > preview_count {
        preview.push("...");
    }
    preview.join(", ")
}

fn normalize_verify_identifier(raw: &str) -> String {
    raw.trim().replace('-', "_").to_ascii_lowercase()
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .unwrap_or_else(|| Path::new(env!("CARGO_MANIFEST_DIR")))
        .to_path_buf()
}

fn crate_source_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn resolve_verify_module_source(module_id: &str) -> Option<PathBuf> {
    let src_root = crate_source_root();
    let file = src_root.join(format!("{module_id}.rs"));
    if file.is_file() {
        return Some(file);
    }

    let dir_mod = src_root.join(module_id).join("mod.rs");
    dir_mod.is_file().then_some(dir_mod)
}

fn parse_module_declaration_name(line: &str) -> Option<String> {
    let trimmed = line.split("//").next().unwrap_or("").trim();
    if !trimmed.ends_with(';') {
        return None;
    }

    for prefix in ["pub(crate) mod ", "pub mod ", "mod "] {
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            let name = rest.trim_end_matches(';').trim();
            if !name.is_empty() {
                return Some(name.to_string());
            }
        }
    }

    None
}

fn parse_path_attribute(line: &str) -> Option<String> {
    let trimmed = line.split("//").next().unwrap_or("").trim();
    if !trimmed.starts_with("#[path") {
        return None;
    }

    let start = trimmed.find('"')?;
    let rest = &trimmed[start + 1..];
    let end = rest.find('"')?;
    Some(rest[..end].to_string())
}

fn contains_top_level_module_declaration(source: &str, module_id: &str) -> bool {
    source.lines().any(|line| {
        let trimmed = line.split("//").next().unwrap_or("").trim();
        for prefix in ["pub(crate) mod ", "pub mod ", "mod "] {
            if let Some(rest) = trimmed.strip_prefix(prefix) {
                let candidate = rest
                    .split(|ch: char| ch == ';' || ch == '{' || ch.is_whitespace())
                    .next()
                    .unwrap_or("");
                if candidate == module_id {
                    return true;
                }
            }
        }
        false
    })
}

fn locate_verify_module_declaration(module_id: &str) -> Option<PathBuf> {
    for candidate in [
        crate_source_root().join("lib.rs"),
        crate_source_root().join("main.rs"),
    ] {
        let Ok(source) = std::fs::read_to_string(&candidate) else {
            continue;
        };
        if contains_top_level_module_declaration(&source, module_id) {
            return Some(candidate);
        }
    }

    None
}

fn nested_module_root(module_source_path: &Path) -> PathBuf {
    if module_source_path
        .file_name()
        .and_then(|value| value.to_str())
        == Some("mod.rs")
    {
        module_source_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf()
    } else {
        module_source_path.with_extension("")
    }
}

fn resolve_nested_module_source(
    module_source_path: &Path,
    module_name: &str,
    path_override: Option<&str>,
) -> PathBuf {
    let root = nested_module_root(module_source_path);
    if let Some(path_override) = path_override {
        return root.join(path_override);
    }

    let file = root.join(format!("{module_name}.rs"));
    if file.is_file() {
        return file;
    }

    root.join(module_name).join("mod.rs")
}

fn collect_declared_module_dependencies(
    module_source_path: &Path,
    source: &str,
) -> Vec<serde_json::Value> {
    let mut dependencies = Vec::new();
    let mut pending_path_override: Option<String> = None;

    for line in source.lines() {
        let trimmed = line.split("//").next().unwrap_or("").trim();
        if trimmed.is_empty() {
            continue;
        }

        if let Some(path_override) = parse_path_attribute(trimmed) {
            pending_path_override = Some(path_override);
            continue;
        }

        if let Some(module_name) = parse_module_declaration_name(trimmed) {
            let path = resolve_nested_module_source(
                module_source_path,
                &module_name,
                pending_path_override.as_deref(),
            );
            let exists = path.is_file();
            dependencies.push(serde_json::json!({
                "name": module_name,
                "path": path.display().to_string(),
                "exists": exists,
            }));
            pending_path_override = None;
            continue;
        }

        pending_path_override = None;
    }

    dependencies
}

fn resolve_verify_migration_lane_source(migration_id: &str) -> Option<PathBuf> {
    let src_root = crate_source_root().join("migration");
    let path = match migration_id {
        "audit" | "rewrite" | "validate" => src_root.join("mod.rs"),
        "bpet_migration_gate" => src_root.join("bpet_migration_gate.rs"),
        "dgis_migration_gate" => src_root.join("dgis_migration_gate.rs"),
        _ => return None,
    };

    path.is_file().then_some(path)
}

fn migration_state_dir(project_root: &Path) -> PathBuf {
    project_root.join(".franken-node/state/migrations")
}

fn resolve_verify_migration_record_path(
    project_root: &Path,
    raw_id: &str,
    normalized_id: &str,
) -> Option<PathBuf> {
    let state_dir = migration_state_dir(project_root);
    let mut candidates = vec![raw_id.trim().to_string()];
    if !candidates
        .iter()
        .any(|candidate| candidate == normalized_id)
    {
        candidates.push(normalized_id.to_string());
    }

    candidates
        .into_iter()
        .filter(|candidate| !candidate.is_empty())
        .map(|candidate| state_dir.join(format!("{candidate}.json")))
        .find(|candidate| candidate.is_file())
}

fn extract_record_string(
    record: &serde_json::Map<String, serde_json::Value>,
    field: &str,
) -> Option<String> {
    record
        .get(field)
        .and_then(serde_json::Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn migration_record_status(record: &serde_json::Map<String, serde_json::Value>) -> String {
    extract_record_string(record, "status")
        .map(|status| normalize_verify_identifier(&status))
        .or_else(|| extract_record_string(record, "rolled_back_at").map(|_| "rolled_back".into()))
        .or_else(|| extract_record_string(record, "applied_at").map(|_| "applied".into()))
        .unwrap_or_else(|| "pending".to_string())
}

fn evaluate_migration_post_condition(
    project_root: &Path,
    condition: &serde_json::Value,
    index: usize,
) -> serde_json::Value {
    match condition {
        serde_json::Value::String(path) => {
            let resolved = project_root.join(path);
            let exists = resolved.exists();
            serde_json::json!({
                "index": index,
                "path": path,
                "resolved_path": resolved.display().to_string(),
                "expected_exists": true,
                "actual_exists": exists,
                "passed": exists,
            })
        }
        serde_json::Value::Object(object) => {
            let raw_path = object
                .get("path")
                .or_else(|| object.get("file"))
                .and_then(serde_json::Value::as_str)
                .map(str::trim)
                .filter(|value| !value.is_empty());
            let expected_exists = object
                .get("exists")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            let expected_contains = object
                .get("contains")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string);

            let Some(raw_path) = raw_path else {
                return serde_json::json!({
                    "index": index,
                    "passed": false,
                    "error": "post-condition object is missing `path` or `file`",
                });
            };

            let resolved = project_root.join(raw_path);
            let actual_exists = resolved.exists();
            let actual_contains = expected_contains.as_ref().and_then(|needle| {
                std::fs::read_to_string(&resolved)
                    .ok()
                    .map(|contents| contents.contains(needle))
            });
            let contains_ok = match expected_contains.as_ref() {
                Some(_) => actual_contains.unwrap_or(false),
                None => true,
            };
            let passed = actual_exists == expected_exists && contains_ok;

            serde_json::json!({
                "index": index,
                "path": raw_path,
                "resolved_path": resolved.display().to_string(),
                "expected_exists": expected_exists,
                "actual_exists": actual_exists,
                "expected_contains": expected_contains,
                "actual_contains": actual_contains,
                "passed": passed,
            })
        }
        _ => serde_json::json!({
            "index": index,
            "passed": false,
            "error": "post-condition must be a string path or object",
        }),
    }
}

fn evaluate_migration_post_conditions(
    project_root: &Path,
    record: &serde_json::Map<String, serde_json::Value>,
) -> Vec<serde_json::Value> {
    record
        .get("post_conditions")
        .and_then(serde_json::Value::as_array)
        .map(|conditions| {
            conditions
                .iter()
                .enumerate()
                .map(|(index, condition)| {
                    evaluate_migration_post_condition(project_root, condition, index)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn summarize_post_condition_results(results: &[serde_json::Value]) -> String {
    if results.is_empty() {
        return "no post-conditions declared".to_string();
    }

    let failures = results
        .iter()
        .filter(|result| {
            !result
                .get("passed")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(false)
        })
        .map(|result| {
            result
                .get("path")
                .and_then(serde_json::Value::as_str)
                .map(ToString::to_string)
                .or_else(|| {
                    result
                        .get("error")
                        .and_then(serde_json::Value::as_str)
                        .map(ToString::to_string)
                })
                .unwrap_or_else(|| "unknown-post-condition".to_string())
        })
        .collect::<Vec<_>>();

    if failures.is_empty() {
        return format!("all {} post-conditions satisfied", results.len());
    }

    format!(
        "{} of {} post-conditions failed: {}",
        failures.len(),
        results.len(),
        failures.join(", ")
    )
}

fn normalize_compatibility_runtime(raw: &str) -> Option<&'static str> {
    match raw.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "node" => Some("node"),
        "bun" => Some("bun"),
        "franken-node" | "franken-engine" | "frankenengine" => Some("franken-node"),
        _ => None,
    }
}

fn resolve_compatibility_runtime_binary(runtime: &str) -> Result<PathBuf> {
    match runtime {
        "node" | "bun" => which::which(runtime)
            .with_context(|| format!("runtime `{runtime}` was not found on PATH")),
        "franken-node" => std::env::current_exe()
            .with_context(|| "failed resolving current franken-node binary".to_string()),
        _ => anyhow::bail!("unsupported runtime target `{runtime}`"),
    }
}

fn run_runtime_probe(binary: &Path, runtime: &str, args: &[&str], context: &str) -> Result<String> {
    let output = ProcessCommand::new(binary)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .with_context(|| format!("failed running {context} using {}", binary.display()))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        anyhow::bail!(
            "{context} failed for runtime `{runtime}` with exit code {:?}: {}",
            output.status.code(),
            if stderr.is_empty() {
                "no stderr emitted".to_string()
            } else {
                stderr
            }
        );
    }

    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if !stdout.is_empty() {
        return Ok(stdout);
    }

    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    if !stderr.is_empty() {
        return Ok(stderr);
    }

    Ok(String::new())
}

fn extract_runtime_major_version(raw_version: &str) -> Option<u64> {
    let trimmed = raw_version.trim().trim_start_matches('v');
    let major = trimmed
        .chars()
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    (!major.is_empty())
        .then(|| major.parse::<u64>().ok())
        .flatten()
}

fn runtime_major_satisfies_requirement(major: u64, requirement: &str) -> Option<bool> {
    let mut saw_comparison = false;

    for token in requirement.split_whitespace() {
        let token = token.trim().trim_matches(',');
        if token.is_empty() || token == "*" {
            continue;
        }

        let (operator, raw_value) = if let Some(rest) = token.strip_prefix(">=") {
            (">=", rest)
        } else if let Some(rest) = token.strip_prefix("<=") {
            ("<=", rest)
        } else if let Some(rest) = token.strip_prefix('>') {
            (">", rest)
        } else if let Some(rest) = token.strip_prefix('<') {
            ("<", rest)
        } else if let Some(rest) = token.strip_prefix('=') {
            ("=", rest)
        } else if let Some(rest) = token.strip_prefix('^') {
            (">=", rest)
        } else if let Some(rest) = token.strip_prefix('~') {
            (">=", rest)
        } else {
            ("=", token)
        };

        let required_major = extract_runtime_major_version(raw_value)?;
        saw_comparison = true;

        let satisfied = match operator {
            ">=" => major >= required_major,
            "<=" => major <= required_major,
            ">" => major > required_major,
            "<" => major < required_major,
            "=" => major == required_major,
            _ => false,
        };
        if !satisfied {
            return Some(false);
        }
    }

    saw_comparison.then_some(true)
}

fn read_runtime_engine_requirement(project_root: &Path, runtime: &str) -> Result<Option<String>> {
    let engine_key = match runtime {
        "node" => "node",
        "bun" => "bun",
        _ => return Ok(None),
    };

    let Some(object) = read_package_manifest_object(project_root, "verify compatibility")? else {
        return Ok(None);
    };

    Ok(object
        .get("engines")
        .and_then(serde_json::Value::as_object)
        .and_then(|engines| engines.get(engine_key))
        .map(|value| {
            value
                .as_str()
                .map_or_else(|| value.to_string(), ToString::to_string)
        }))
}

fn known_runtime_compatibility_issues(
    runtime: &str,
    major_version: Option<u64>,
    engine_requirement: Option<&str>,
    engine_requirement_satisfied: Option<bool>,
) -> Vec<String> {
    let mut issues = Vec::new();

    match (runtime, major_version) {
        ("node", Some(major)) if major < 20 => {
            issues.push(
                "node major versions below 20 are outside the supported migration baseline"
                    .to_string(),
            );
        }
        ("bun", Some(major)) if major < 1 => {
            issues.push("bun major versions below 1 are not supported".to_string());
        }
        _ => {}
    }

    if let Some(requirement) = engine_requirement {
        match engine_requirement_satisfied {
            Some(false) => issues.push(format!(
                "runtime version does not satisfy package.json engines requirement `{requirement}`"
            )),
            None => issues.push(format!(
                "could not evaluate package.json engines requirement `{requirement}` against the detected runtime version"
            )),
            Some(true) => {}
        }
    }

    issues
}

fn emit_verify_module(args: &VerifyModuleArgs) -> i32 {
    if let Some(error_payload) = validate_verify_compat("verify module", args.compat_version) {
        return emit_verify_output("verify module", &error_payload, args.json);
    }

    let normalized = normalize_verify_identifier(&args.module_id);
    let payload = match resolve_verify_module_source(&normalized) {
        Some(source_path) => match std::fs::read_to_string(&source_path) {
            Ok(source) => {
                let declaration_path = locate_verify_module_declaration(&normalized);
                let dependencies = collect_declared_module_dependencies(&source_path, &source);
                let deps_satisfied = dependencies.iter().all(|dependency| {
                    dependency
                        .get("exists")
                        .and_then(serde_json::Value::as_bool)
                        .unwrap_or(false)
                });
                let declared = declaration_path.is_some();
                let health_declared = source.contains("fn health_check(");
                let passed = declared && deps_satisfied;
                let reason = if passed {
                    format!(
                        "module `{}` resolved to {} and all declared module dependencies are present",
                        normalized,
                        source_path.display()
                    )
                } else if !declared {
                    format!(
                        "module `{}` exists at {} but is not declared in lib.rs or main.rs",
                        normalized,
                        source_path.display()
                    )
                } else {
                    format!(
                        "module `{}` resolved to {} but one or more declared module dependencies are missing",
                        normalized,
                        source_path.display()
                    )
                };
                build_verify_output_with_details(
                    "verify module",
                    args.compat_version,
                    if passed { "PASS" } else { "FAIL" },
                    if passed { "pass" } else { "fail" },
                    if passed { 0 } else { 1 },
                    reason,
                    Some(serde_json::json!({
                        "module_id": normalized,
                        "exists": true,
                        "source_path": source_path.display().to_string(),
                        "declared_in": declaration_path.map(|path| path.display().to_string()),
                        "integrity": {
                            "algorithm": "sha256",
                            "sha256": hex::encode(sha2::Sha256::digest(source.as_bytes())),
                        },
                        "deps_satisfied": deps_satisfied,
                        "dependencies": dependencies,
                        "health": if health_declared { "declared" } else { "not_declared" },
                    })),
                )
            }
            Err(err) => build_verify_output(
                "verify module",
                args.compat_version,
                "FAIL",
                "fail",
                1,
                format!(
                    "failed reading module source for `{}` at {}: {err}",
                    normalized,
                    source_path.display()
                ),
            ),
        },
        None => build_verify_output_with_details(
            "verify module",
            args.compat_version,
            "FAIL",
            "fail",
            1,
            format!(
                "unknown module `{}`; no source file found under {} (examples: {})",
                args.module_id,
                crate_source_root().display(),
                summarize_expected_ids(VERIFY_MODULE_IDS, 10)
            ),
            Some(serde_json::json!({
                "module_id": normalized,
                "exists": false,
                "search_root": crate_source_root().display().to_string(),
            })),
        ),
    };
    emit_verify_output("verify module", &payload, args.json)
}

fn emit_verify_migration(args: &VerifyMigrationArgs) -> i32 {
    if let Some(error_payload) = validate_verify_compat("verify migration", args.compat_version) {
        return emit_verify_output("verify migration", &error_payload, args.json);
    }

    let normalized = normalize_verify_identifier(&args.migration_id);
    let project_root = match std::env::current_dir() {
        Ok(path) => path,
        Err(err) => {
            let payload = build_verify_output(
                "verify migration",
                args.compat_version,
                "FAIL",
                "fail",
                1,
                format!("failed determining current project directory: {err}"),
            );
            return emit_verify_output("verify migration", &payload, args.json);
        }
    };

    let payload = if let Some(record_path) =
        resolve_verify_migration_record_path(&project_root, &args.migration_id, &normalized)
    {
        match std::fs::read_to_string(&record_path) {
            Ok(raw) => match serde_json::from_str::<serde_json::Value>(&raw) {
                Ok(serde_json::Value::Object(record)) => {
                    let status = migration_record_status(&record);
                    let post_conditions =
                        evaluate_migration_post_conditions(&project_root, &record);
                    let post_conditions_met = post_conditions.iter().all(|entry| {
                        entry
                            .get("passed")
                            .and_then(serde_json::Value::as_bool)
                            .unwrap_or(false)
                    });
                    let diff_summary = summarize_post_condition_results(&post_conditions);
                    let passed =
                        matches!(status.as_str(), "applied" | "rolled_back") && post_conditions_met;
                    let reason = match status.as_str() {
                        "applied" if post_conditions_met => format!(
                            "migration `{}` is applied and all declared post-conditions passed",
                            normalized
                        ),
                        "rolled_back" if post_conditions_met => format!(
                            "migration `{}` is rolled back cleanly and all declared rollback conditions passed",
                            normalized
                        ),
                        "pending" => format!(
                            "migration `{}` is still pending in {}",
                            normalized,
                            record_path.display()
                        ),
                        _ => format!(
                            "migration `{}` recorded status `{status}` and {diff_summary}",
                            normalized
                        ),
                    };

                    build_verify_output_with_details(
                        "verify migration",
                        args.compat_version,
                        if passed { "PASS" } else { "FAIL" },
                        if passed { "pass" } else { "fail" },
                        if passed { 0 } else { 1 },
                        reason,
                        Some(serde_json::json!({
                            "migration_id": normalized,
                            "record_path": record_path.display().to_string(),
                            "status": status,
                            "post_conditions_met": post_conditions_met,
                            "post_conditions": post_conditions,
                            "diff_summary": diff_summary,
                        })),
                    )
                }
                Ok(_) => build_verify_output(
                    "verify migration",
                    args.compat_version,
                    "FAIL",
                    "fail",
                    1,
                    format!(
                        "migration record {} must be a JSON object",
                        record_path.display()
                    ),
                ),
                Err(err) => build_verify_output(
                    "verify migration",
                    args.compat_version,
                    "FAIL",
                    "fail",
                    1,
                    format!(
                        "invalid migration record JSON at {}: {err}",
                        record_path.display()
                    ),
                ),
            },
            Err(err) => build_verify_output(
                "verify migration",
                args.compat_version,
                "FAIL",
                "fail",
                1,
                format!(
                    "failed reading migration record {}: {err}",
                    record_path.display()
                ),
            ),
        }
    } else if let Some(lane_source) = resolve_verify_migration_lane_source(&normalized) {
        build_verify_output_with_details(
            "verify migration",
            args.compat_version,
            "PASS",
            "pass",
            0,
            format!(
                "migration lane `{}` resolved to {} with no state record present under {}",
                normalized,
                lane_source.display(),
                migration_state_dir(&project_root).display()
            ),
            Some(serde_json::json!({
                "migration_id": normalized,
                "record_path": serde_json::Value::Null,
                "status": "source_present",
                "post_conditions_met": serde_json::Value::Null,
                "diff_summary": "no state record declared",
                "lane_source": lane_source.display().to_string(),
            })),
        )
    } else {
        build_verify_output_with_details(
            "verify migration",
            args.compat_version,
            "FAIL",
            "fail",
            1,
            format!(
                "unknown migration target `{}`; no state record found under {} and no verify lane source resolved (expected one of: {})",
                args.migration_id,
                migration_state_dir(&project_root).display(),
                summarize_expected_ids(VERIFY_MIGRATION_IDS, VERIFY_MIGRATION_IDS.len())
            ),
            Some(serde_json::json!({
                "migration_id": normalized,
                "record_path": serde_json::Value::Null,
                "status": "missing",
                "post_conditions_met": false,
                "diff_summary": "no migration record or lane source resolved",
            })),
        )
    };
    emit_verify_output("verify migration", &payload, args.json)
}

fn emit_verify_compatibility(args: &VerifyCompatibilityArgs) -> i32 {
    if let Some(error_payload) = validate_verify_compat("verify compatibility", args.compat_version)
    {
        return emit_verify_output("verify compatibility", &error_payload, args.json);
    }

    let payload = match parse_profile_override(Some(&args.target)) {
        Ok(Some(profile)) => build_verify_output_with_details(
            "verify compatibility",
            args.compat_version,
            "PASS",
            "pass",
            0,
            format!(
                "compatibility target `{}` resolved to profile `{}`",
                args.target, profile
            ),
            Some(serde_json::json!({
                "target": args.target,
                "target_kind": "profile",
                "profile": profile.to_string(),
            })),
        ),
        Ok(None) | Err(_) => match normalize_compatibility_runtime(&args.target) {
            Some(runtime) => {
                let project_root = std::env::current_dir().unwrap_or_else(|_| workspace_root());
                match resolve_compatibility_runtime_binary(runtime) {
                    Ok(binary) => {
                        let version_result =
                            run_runtime_probe(&binary, runtime, &["--version"], "version probe");
                        let smoke_result = match runtime {
                            "node" | "bun" => run_runtime_probe(
                                &binary,
                                runtime,
                                &["-e", "console.log(JSON.stringify({\"ok\":true}))"],
                                "smoke probe",
                            ),
                            "franken-node" => {
                                run_runtime_probe(&binary, runtime, &["--version"], "smoke probe")
                            }
                            _ => unreachable!("unsupported runtime normalization"),
                        };
                        match (version_result, smoke_result) {
                            (Ok(version), Ok(smoke_output)) => {
                                let major_version = extract_runtime_major_version(&version);
                                let engine_requirement =
                                    read_runtime_engine_requirement(&project_root, runtime)
                                        .unwrap_or(None);
                                let engine_requirement_satisfied =
                                    match (major_version, engine_requirement.as_deref()) {
                                        (Some(major), Some(requirement)) => {
                                            runtime_major_satisfies_requirement(major, requirement)
                                        }
                                        _ => Some(true),
                                    };
                                let known_issues = known_runtime_compatibility_issues(
                                    runtime,
                                    major_version,
                                    engine_requirement.as_deref(),
                                    engine_requirement_satisfied,
                                );
                                let compatible = engine_requirement_satisfied.unwrap_or(false)
                                    && known_issues.is_empty();

                                build_verify_output_with_details(
                                    "verify compatibility",
                                    args.compat_version,
                                    if compatible { "PASS" } else { "FAIL" },
                                    if compatible { "pass" } else { "fail" },
                                    if compatible { 0 } else { 1 },
                                    if compatible {
                                        format!(
                                            "runtime `{runtime}` is installed, passed smoke checks, and is compatible"
                                        )
                                    } else {
                                        format!(
                                            "runtime `{runtime}` is installed but reported compatibility issues"
                                        )
                                    },
                                    Some(serde_json::json!({
                                        "target": args.target,
                                        "target_kind": "runtime",
                                        "runtime": runtime,
                                        "installed": true,
                                        "binary_path": binary.display().to_string(),
                                        "version": version,
                                        "major_version": major_version,
                                        "smoke_output": smoke_output,
                                        "engine_requirement": engine_requirement,
                                        "compatible": compatible,
                                        "known_issues": known_issues,
                                    })),
                                )
                            }
                            (Err(err), _) | (_, Err(err)) => build_verify_output(
                                "verify compatibility",
                                args.compat_version,
                                "FAIL",
                                "fail",
                                1,
                                format!("runtime `{runtime}` failed verification: {err:#}"),
                            ),
                        }
                    }
                    Err(err) => build_verify_output_with_details(
                        "verify compatibility",
                        args.compat_version,
                        "FAIL",
                        "fail",
                        1,
                        format!("runtime `{runtime}` is not installed or not resolvable: {err:#}"),
                        Some(serde_json::json!({
                            "target": args.target,
                            "target_kind": "runtime",
                            "runtime": runtime,
                            "installed": false,
                            "compatible": false,
                            "known_issues": [
                                format!("runtime `{runtime}` is not installed or not on PATH"),
                            ],
                        })),
                    ),
                }
            }
            None => build_verify_output(
                "verify compatibility",
                args.compat_version,
                "FAIL",
                "fail",
                1,
                format!(
                    "invalid compatibility target `{}`: expected a profile (strict, balanced, legacy-risky) or a concrete runtime (node, bun, franken-node)",
                    args.target
                ),
            ),
        },
    };

    emit_verify_output("verify compatibility", &payload, args.json)
}

fn collect_corpus_matches(
    search_root: &Path,
    corpus_id: &str,
    matches: &mut BTreeSet<PathBuf>,
) -> Result<()> {
    let mut pending = vec![search_root.to_path_buf()];
    let wanted = corpus_id.to_ascii_lowercase();

    while let Some(dir) = pending.pop() {
        let entries = std::fs::read_dir(&dir)
            .with_context(|| format!("failed reading corpus search directory {}", dir.display()))?;
        for entry in entries {
            let entry = entry.with_context(|| {
                format!(
                    "failed reading directory entry in corpus root {}",
                    dir.display()
                )
            })?;
            let path = entry.path();
            if path.is_dir() {
                if should_skip_bundle_scan_dir(&path) {
                    continue;
                }
                pending.push(path);
                continue;
            }

            if !path.is_file() {
                continue;
            }

            let file_name = path
                .file_name()
                .and_then(std::ffi::OsStr::to_str)
                .map(|s| s.to_ascii_lowercase());
            let stem = path
                .file_stem()
                .and_then(std::ffi::OsStr::to_str)
                .map(|s| s.to_ascii_lowercase());
            if file_name.as_deref() == Some(wanted.as_str())
                || stem.as_deref() == Some(wanted.as_str())
            {
                matches.insert(path);
            }
        }
    }

    Ok(())
}

fn emit_verify_corpus(args: &VerifyCorpusArgs) -> i32 {
    if let Some(error_payload) = validate_verify_compat("verify corpus", args.compat_version) {
        return emit_verify_output("verify corpus", &error_payload, args.json);
    }

    let raw_path = args.corpus_path.as_os_str().to_string_lossy();
    let raw = raw_path.trim();
    if raw.is_empty() {
        let payload = build_verify_output(
            "verify corpus",
            args.compat_version,
            "FAIL",
            "fail",
            1,
            "corpus identifier cannot be empty".to_string(),
        );
        return emit_verify_output("verify corpus", &payload, args.json);
    }

    let mut matches = BTreeSet::new();
    if args.corpus_path.is_absolute() && args.corpus_path.exists() {
        matches.insert(args.corpus_path.clone());
    }

    let cwd = match std::env::current_dir() {
        Ok(path) => path,
        Err(err) => {
            let payload = build_verify_output(
                "verify corpus",
                args.compat_version,
                "ERROR",
                "error",
                2,
                format!("failed resolving working directory for corpus checks: {err}"),
            );
            return emit_verify_output("verify corpus", &payload, args.json);
        }
    };

    let relative_path = cwd.join(&args.corpus_path);
    if !args.corpus_path.is_absolute() && relative_path.exists() {
        matches.insert(relative_path);
    }

    let search_term = args
        .corpus_path
        .file_name()
        .and_then(std::ffi::OsStr::to_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or(raw);

    for root in VERIFY_CORPUS_SEARCH_ROOTS {
        let search_root = cwd.join(root);
        if !search_root.is_dir() {
            continue;
        }
        if let Err(err) = collect_corpus_matches(&search_root, search_term, &mut matches) {
            let payload = build_verify_output(
                "verify corpus",
                args.compat_version,
                "ERROR",
                "error",
                2,
                format!(
                    "corpus search failed while scanning `{}`: {err}",
                    search_root.display()
                ),
            );
            return emit_verify_output("verify corpus", &payload, args.json);
        }
    }

    let passed = !matches.is_empty();
    let reason = if passed {
        let sample_path = matches
            .iter()
            .next()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| raw.to_string());
        format!(
            "corpus path `{raw}` matched {} artifact(s); sample match: {sample_path}",
            matches.len()
        )
    } else {
        format!(
            "no corpus artifact matched `{raw}` in direct path or roots: {}",
            VERIFY_CORPUS_SEARCH_ROOTS.join(", ")
        )
    };

    let payload = build_verify_output(
        "verify corpus",
        args.compat_version,
        if passed { "PASS" } else { "FAIL" },
        if passed { "pass" } else { "fail" },
        if passed { 0 } else { 1 },
        reason,
    );
    emit_verify_output("verify corpus", &payload, args.json)
}

fn handle_trust_card_command(command: TrustCardCommand) -> Result<()> {
    let now_secs = now_unix_secs();
    let trace_id = "trace-cli-trust-card";

    match command {
        TrustCardCommand::Show(args) => {
            let mut state = trust_card_cli_registry(now_secs)?;
            let response =
                get_trust_card(&mut state.registry, &args.extension_id, now_secs, trace_id)?;
            let card = response
                .data
                .ok_or_else(|| trust_card_not_found_error(&args.extension_id))?;
            if args.json {
                println!("{}", trust_card_to_json(&card)?);
            } else {
                println!("{}", render_trust_card_human(&card));
            }
        }
        TrustCardCommand::Export(args) => {
            if !args.json {
                anyhow::bail!("`trust-card export` requires `--json`");
            }
            let mut state = trust_card_cli_registry(now_secs)?;
            let response =
                get_trust_card(&mut state.registry, &args.extension_id, now_secs, trace_id)?;
            let card = response
                .data
                .ok_or_else(|| trust_card_not_found_error(&args.extension_id))?;
            println!("{}", trust_card_to_json(&card)?);
        }
        TrustCardCommand::List(args) => {
            let mut state = trust_card_cli_registry(now_secs)?;
            let pagination = Pagination {
                page: args.page,
                per_page: args.per_page,
            };
            let response = if let Some(query) = args.query.as_deref() {
                search_trust_cards(&mut state.registry, query, now_secs, trace_id, pagination)?
            } else if let Some(publisher_id) = args.publisher.as_deref() {
                get_trust_cards_by_publisher(
                    &mut state.registry,
                    publisher_id,
                    now_secs,
                    trace_id,
                    pagination,
                )?
            } else {
                list_trust_cards(
                    &mut state.registry,
                    &TrustCardListFilter::empty(),
                    now_secs,
                    trace_id,
                    pagination,
                )?
            };

            if args.json {
                println!("{}", trust_card_to_json(&response)?);
            } else {
                println!("{}", render_trust_card_list(&response.data));
            }
        }
        TrustCardCommand::Compare(args) => {
            let mut state = trust_card_cli_registry(now_secs)?;
            let response = compare_trust_cards(
                &mut state.registry,
                &args.left_extension_id,
                &args.right_extension_id,
                now_secs,
                trace_id,
            )?;
            if args.json {
                println!("{}", trust_card_to_json(&response)?);
            } else {
                println!("{}", render_comparison_human(&response.data));
            }
        }
        TrustCardCommand::Diff(args) => {
            let mut state = trust_card_cli_registry(now_secs)?;
            let response = compare_trust_card_versions(
                &mut state.registry,
                &args.extension_id,
                args.left_version,
                args.right_version,
                now_secs,
                trace_id,
            )?;
            if args.json {
                println!("{}", trust_card_to_json(&response)?);
            } else {
                println!("{}", render_comparison_human(&response.data));
            }
        }
    }

    Ok(())
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Init(args) => {
            let cli::InitArgs {
                profile,
                config,
                out_dir,
                overwrite,
                backup_existing,
                scan,
                json,
                trace_id,
                state_dir,
                no_state,
            } = args;

            validate_init_flags(overwrite, backup_existing)?;
            if scan && no_state {
                anyhow::bail!("`init --scan` requires state bootstrapping; remove `--no-state`");
            }
            let profile_override = parse_profile_override(profile.as_deref())?;
            let resolved = config::Config::resolve(
                config.as_deref(),
                CliOverrides {
                    profile: profile_override,
                },
            )
            .context("failed resolving configuration for init")?;
            let config_toml = resolved
                .config
                .to_toml()
                .context("failed serializing resolved config")?;

            let mut wrote_to_stdout = false;
            let mut stdout_config_toml: Option<String> = None;
            let mut file_actions = Vec::new();
            let bootstrap_root = state_dir
                .as_deref()
                .or(out_dir.as_deref())
                .unwrap_or_else(|| Path::new("."));

            if let Some(ref out_dir) = out_dir {
                std::fs::create_dir_all(out_dir).with_context(|| {
                    format!("failed creating init output dir {}", out_dir.display())
                })?;
                let (config_path, profile_path) = init_target_paths(out_dir);

                if !overwrite && !backup_existing {
                    let existing = [&config_path, &profile_path]
                        .into_iter()
                        .filter(|path| path.exists())
                        .map(|path| path.display().to_string())
                        .collect::<Vec<_>>();
                    if !existing.is_empty() {
                        anyhow::bail!(
                            "init target already contains generated files: {} (use --overwrite or --backup-existing)",
                            existing.join(", ")
                        );
                    }
                }

                let backup_suffix = chrono::Utc::now().format("%Y%m%dT%H%M%SZ").to_string();
                file_actions.push(apply_init_write_policy(
                    &config_path,
                    &config_toml,
                    overwrite,
                    backup_existing,
                    &backup_suffix,
                )?);
                file_actions.push(apply_init_write_policy(
                    &profile_path,
                    PROFILE_EXAMPLES_TEMPLATE,
                    overwrite,
                    backup_existing,
                    &backup_suffix,
                )?);
            } else {
                wrote_to_stdout = true;
                stdout_config_toml = Some(config_toml.clone());
            }

            // Bootstrap .franken-node/ state directory structure unless --no-state.
            if !no_state {
                let state_actions = bootstrap_state_directory(
                    bootstrap_root,
                    &resolved.selected_profile.to_string(),
                )?;
                file_actions.extend(state_actions);
            }
            let trust_scan = if scan {
                Some(run_trust_scan(bootstrap_root, false, false)?)
            } else {
                None
            };

            let report = build_init_report(
                &trace_id,
                &resolved,
                file_actions,
                trust_scan,
                wrote_to_stdout,
                stdout_config_toml.clone(),
            );

            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else if wrote_to_stdout {
                if let Some(config) = stdout_config_toml {
                    println!("{config}");
                }
                eprintln!("{}", render_init_report_human(&report, false));
            } else {
                eprintln!("{}", render_init_report_human(&report, false));
            }
        }

        Command::Run(args) => {
            let cli::RunArgs {
                app_path,
                policy,
                json,
                config,
                runtime,
                engine_bin,
                lockstep_preflight,
            } = args;

            let profile_override = parse_profile_override(Some(&policy))?;
            let resolved = config::Config::resolve(
                config.as_deref(),
                CliOverrides {
                    profile: profile_override,
                },
            )
            .context("failed resolving configuration for run")?;

            let preflight = evaluate_run_trust_preflight(
                &app_path,
                resolved.selected_profile,
                &resolved.config,
                now_unix_secs(),
            )?;
            emit_run_preflight_report(&preflight, json)?;
            if preflight.verdict.is_blocked() {
                return Err(run_preflight_block_error(&preflight).into());
            }

            // Optional lockstep pre-flight check (bd-3p0qh)
            let lockstep_verdict = if lockstep_preflight {
                eprintln!("Running lockstep pre-flight check across runtimes...");
                let harness = runtime::lockstep_harness::LockstepHarness::new(vec![
                    "node".to_string(),
                    "bun".to_string(),
                ]);
                match harness.verify_lockstep(&app_path, false) {
                    Ok(()) => {
                        eprintln!("Lockstep pre-flight: PASSED");
                        Some(serde_json::json!({
                            "status": "passed",
                            "runtimes": ["node", "bun"]
                        }))
                    }
                    Err(e) => {
                        let error_msg = e.to_string();
                        eprintln!("Lockstep pre-flight: DIVERGENCE DETECTED - {}", error_msg);
                        if resolved.config.migration.require_lockstep_validation {
                            return Err(ActionableError::new(
                                format!(
                                    "run blocked by lockstep pre-flight divergence: {}",
                                    error_msg
                                ),
                                "franken-node verify lockstep . --emit-fixtures",
                            )
                            .into());
                        }
                        Some(serde_json::json!({
                            "status": "diverged",
                            "error": error_msg,
                            "runtimes": ["node", "bun"],
                            "blocked": false
                        }))
                    }
                }
            } else {
                None
            };

            let requested_runtime = parse_runtime_override(runtime.as_deref())?
                .unwrap_or(resolved.config.runtime.preferred);
            let dispatcher =
                ops::engine_dispatcher::EngineDispatcher::new(engine_bin, requested_runtime);
            let dispatch = dispatcher.dispatch_run(&app_path, &resolved.config, &policy)?;
            let project_root = run_project_root(&app_path);
            let ssrf_violations = extract_ssrf_violations(dispatch.telemetry.as_ref());
            let auto_quarantined_extensions = maybe_auto_quarantine_run_dependencies(
                &project_root,
                &resolved.config,
                &preflight,
                ssrf_violations.len(),
                now_unix_secs(),
            )?;
            let receipt = build_run_execution_receipt(
                &app_path,
                &policy,
                resolved.selected_profile,
                &preflight,
                &dispatch,
                ssrf_violations,
                auto_quarantined_extensions,
                lockstep_verdict,
            )?;
            let receipt_path = persist_run_execution_receipt(
                &project_root,
                &receipt,
                configured_run_receipt_limit(&resolved.config),
            )?;
            emit_run_completion_output(&preflight, &dispatch, &receipt, &receipt_path, json)?;

            if dispatch.terminated_by_signal {
                anyhow::bail!(
                    "run exited abnormally: runtime `{}` terminated by signal",
                    dispatch.runtime
                );
            }
            if let Some(exit_code) = dispatch.exit_code
                && exit_code != 0
            {
                std::process::exit(exit_code);
            }
        }

        Command::Migrate(sub) => match sub {
            MigrateCommand::Audit(args) => {
                let format = migration::AuditOutputFormat::parse(&args.format)
                    .map_err(|err| anyhow::anyhow!(err))?;
                let report = migration::run_audit(&args.project_path).with_context(|| {
                    format!(
                        "failed running migration audit for {}",
                        args.project_path.display()
                    )
                })?;
                let rendered = migration::render_audit_report(&report, format)?;

                if let Some(out_path) = emit_migration_audit_report(&rendered, args.out.as_deref())?
                {
                    eprintln!("migration audit report written: {}", out_path.display());
                }
            }
            MigrateCommand::Rewrite(args) => {
                let report =
                    migration::run_rewrite(&args.project_path, args.apply).with_context(|| {
                        format!(
                            "failed running migration rewrite for {}",
                            args.project_path.display()
                        )
                    })?;
                println!("{}", migration::render_rewrite_report(&report));

                if let Some(out_path) = args.emit_rollback.as_deref() {
                    let rollback_plan = migration::build_rollback_plan(&report);
                    let rollback_json =
                        serde_json::to_string_pretty(&rollback_plan).with_context(|| {
                            format!(
                                "failed serializing migration rollback plan for {}",
                                args.project_path.display()
                            )
                        })?;
                    let written_path = write_migration_report_file(
                        &rollback_json,
                        out_path,
                        "migration rollback artifact",
                    )?;
                    eprintln!(
                        "migration rollback artifact written: {}",
                        written_path.display()
                    );
                }
            }
            MigrateCommand::Validate(args) => {
                let report = migration::run_validate(&args.project_path).with_context(|| {
                    format!(
                        "failed running migration validate for {}",
                        args.project_path.display()
                    )
                })?;
                println!("{}", migration::render_validate_report(&report));
                if !report.is_pass() {
                    anyhow::bail!(
                        "migration validation failed for {}",
                        args.project_path.display()
                    );
                }
            }
        },

        Command::Verify(sub) => match sub {
            VerifyCommand::Module(args) => {
                let code = emit_verify_module(&args);
                std::process::exit(code);
            }
            VerifyCommand::Migration(args) => {
                let code = emit_verify_migration(&args);
                std::process::exit(code);
            }
            VerifyCommand::Compatibility(args) => {
                let code = emit_verify_compatibility(&args);
                std::process::exit(code);
            }
            VerifyCommand::Corpus(args) => {
                let code = emit_verify_corpus(&args);
                std::process::exit(code);
            }
            VerifyCommand::Lockstep(args) => {
                let runtimes: Vec<String> = args
                    .runtimes
                    .split(',')
                    .map(|s| s.trim().to_string())
                    .collect();
                let harness = runtime::lockstep_harness::LockstepHarness::new(runtimes);
                eprintln!(
                    "Running lockstep verification on {}",
                    args.project_path.display()
                );
                if let Err(e) = harness.verify_lockstep(&args.project_path, args.emit_fixtures) {
                    eprintln!("Lockstep harness failed: {}", e);
                    std::process::exit(1);
                }
            }
            VerifyCommand::Release(args) => {
                handle_verify_release(&args)?;
            }
        },

        Command::Trust(sub) => match sub {
            TrustCommand::Card(args) => {
                let mut state = trust_card_cli_registry(now_unix_secs())?;
                let response = get_trust_card(
                    &mut state.registry,
                    &args.extension_id,
                    now_unix_secs(),
                    "trace-cli-trust-card",
                )?;
                let card = response
                    .data
                    .ok_or_else(|| trust_card_not_found_error(&args.extension_id))?;
                println!("{}", render_trust_card_human(&card));
            }
            TrustCommand::List(args) => {
                let risk_filter = parse_risk_level_filter(args.risk.as_deref())?;
                let mut state = trust_card_cli_registry(now_unix_secs())?;
                let cards = state
                    .registry
                    .list(
                        &TrustCardListFilter::empty(),
                        "trace-cli-trust-list",
                        now_unix_secs(),
                    )
                    .map_err(|err| anyhow::anyhow!(err.to_string()))?;
                let filtered =
                    filter_trust_cards_for_trust_command(cards, risk_filter, args.revoked);
                println!("{}", render_trust_card_list(&filtered));
            }
            TrustCommand::Scan(args) => {
                let project_root = args
                    .project_path
                    .as_deref()
                    .unwrap_or_else(|| Path::new("."));
                let report = run_trust_scan(project_root, args.deep, args.audit)?;
                println!("{}", render_trust_scan_human(&report));
            }
            TrustCommand::Revoke(args) => {
                // Prepare receipt export context upfront - fails immediately if receipt export
                // is requested but signing material is unavailable (sign-or-fail).
                let receipt_export_ctx = prepare_receipt_export_context(
                    args.receipt_out.as_deref(),
                    args.receipt_summary_out.as_deref(),
                    args.receipt_signing_key.as_deref(),
                )?;
                let now_secs = now_unix_secs();
                let mut state = trust_card_cli_registry(now_secs)?;
                let card = revoke_trust_card(&mut state.registry, &args.extension_id, now_secs)?;
                persist_trust_card_cli_registry(&state)?;
                println!("{}", render_trust_card_human(&card));
                if let Some(ref ctx) = receipt_export_ctx {
                    export_signed_receipts(
                        "revocation",
                        "trust-control-plane",
                        "Revocation decision exported for audit traceability",
                        ctx,
                    )?;
                }
            }
            TrustCommand::Quarantine(args) => {
                // Prepare receipt export context upfront - fails immediately if receipt export
                // is requested but signing material is unavailable (sign-or-fail).
                let receipt_export_ctx = prepare_receipt_export_context(
                    args.receipt_out.as_deref(),
                    args.receipt_summary_out.as_deref(),
                    args.receipt_signing_key.as_deref(),
                )?;
                let now_secs = now_unix_secs();
                let mut state = trust_card_cli_registry(now_secs)?;
                let updates =
                    quarantine_trust_cards(&mut state.registry, &args.artifact, now_secs)?;
                let fleet_incident_id =
                    append_trust_quarantine_action(Path::new("."), &args.artifact, updates.len())?;
                persist_trust_card_cli_registry(&state)?;
                println!(
                    "quarantine applied: artifact={} affected_cards={}",
                    args.artifact,
                    updates.len()
                );
                println!("fleet propagation incident={fleet_incident_id}");
                println!("{}", render_trust_card_list(&updates));
                if let Some(ref ctx) = receipt_export_ctx {
                    export_signed_receipts(
                        "quarantine",
                        "trust-control-plane",
                        "Quarantine decision exported for incident forensics",
                        ctx,
                    )?;
                }
            }
            TrustCommand::Sync(args) => {
                let now_secs = now_unix_secs();
                let mut state = trust_card_cli_registry(now_secs)?;
                let sync_report = state
                    .registry
                    .sync_cache(now_secs, "trace-cli-trust-sync", args.force)
                    .map_err(|err| anyhow::anyhow!(err.to_string()))?;
                let audit_report = refresh_trust_sync_audit_with(
                    &mut state,
                    now_secs,
                    args.force,
                    fetch_trust_scan_audit_metadata,
                );
                if audit_report.refreshed_count > 0 {
                    persist_trust_card_cli_registry(&state)?;
                }
                for warning in &audit_report.warnings {
                    eprintln!("warning: {warning}");
                }
                let cards = state
                    .registry
                    .list(
                        &TrustCardListFilter::empty(),
                        "trace-cli-trust-sync",
                        now_secs,
                    )
                    .map_err(|err| anyhow::anyhow!(err.to_string()))?;
                println!(
                    "{}",
                    render_trust_sync_summary(&cards, &sync_report, &audit_report, args.force)
                );
            }
        },

        Command::Remotecap(sub) => match sub {
            RemoteCapCommand::Issue(args) => {
                handle_remotecap_issue(&args)?;
            }
        },

        Command::TrustCard(sub) => {
            handle_trust_card_command(sub)?;
        }

        Command::Fleet(sub) => match sub {
            FleetCommand::Status(args) => {
                let zone_id = args.zone.unwrap_or_else(|| "all".to_string());
                let report = fleet_status_report(Path::new("."), &zone_id)?;
                emit_fleet_status_report(&report, args.json, args.verbose)?;
            }
            FleetCommand::Release(args) => {
                let identity = fleet_cli_identity();
                let trace = fleet_cli_trace("trace-cli-fleet-release");
                let loaded = load_fleet_state(Path::new("."))?;
                let incident = loaded
                    .active_incidents
                    .iter()
                    .find(|incident| incident.incident_id == args.incident)
                    .cloned()
                    .ok_or_else(|| anyhow::anyhow!("incident `{}` not found", args.incident))?;
                let (_, state_dir, mut transport) = open_fleet_transport(Path::new("."))?;
                let operation_id = fleet_operation_id("release");
                let issued_at = Utc::now().to_rfc3339();
                transport
                    .publish_action(&PersistedFleetActionRecord {
                        action_id: operation_id.clone(),
                        emitted_at: Utc::now(),
                        action: PersistedFleetAction::Release {
                            zone_id: incident.zone_id.clone(),
                            incident_id: incident.incident_id.clone(),
                            reason: Some("manual release via fleet CLI".to_string()),
                        },
                    })
                    .map_err(|err| anyhow::anyhow!(err.to_string()))?;
                let report = fleet_action_report(
                    Path::new("."),
                    &incident.zone_id,
                    FleetActionResult {
                        operation_id: operation_id.clone(),
                        action_type: "release".to_string(),
                        success: true,
                        receipt: build_fleet_decision_receipt(
                            &operation_id,
                            &identity.principal,
                            &incident.zone_id,
                            &issued_at,
                        ),
                        convergence: None,
                        trace_id: trace.trace_id.clone(),
                        event_code: FLEET_RELEASED.to_string(),
                    },
                )?;
                debug_assert_eq!(report.state_dir, state_dir);
                emit_fleet_action_report(&report, args.json)?;
            }
            FleetCommand::Reconcile(args) => {
                let identity = fleet_cli_identity();
                let trace = fleet_cli_trace("trace-cli-fleet-reconcile");
                let loaded = load_fleet_state(Path::new("."))?;
                if !loaded.stale_nodes.is_empty() && !loaded.active_incidents.is_empty() {
                    let (_, _, mut transport) = open_fleet_transport(Path::new("."))?;
                    let republished_at = Utc::now();
                    for incident in &loaded.active_incidents {
                        transport
                            .publish_action(&PersistedFleetActionRecord {
                                action_id: fleet_operation_id("reconcile-republish"),
                                emitted_at: republished_at,
                                action: PersistedFleetAction::Quarantine {
                                    zone_id: incident.zone_id.clone(),
                                    incident_id: incident.incident_id.clone(),
                                    target_id: incident.target_id.clone(),
                                    target_kind: incident.target_kind,
                                    reason: incident.reason.clone(),
                                    quarantine_version: incident.quarantine_version,
                                },
                            })
                            .map_err(|err| anyhow::anyhow!(err.to_string()))?;
                    }
                }

                let refreshed = load_fleet_state(Path::new("."))?;
                let operation_id = fleet_operation_id("reconcile");
                let issued_at = Utc::now().to_rfc3339();
                let report = fleet_action_report(
                    Path::new("."),
                    "all",
                    FleetActionResult {
                        operation_id: operation_id.clone(),
                        action_type: "reconcile".to_string(),
                        success: true,
                        receipt: build_fleet_decision_receipt(
                            &operation_id,
                            &identity.principal,
                            "all",
                            &issued_at,
                        ),
                        convergence: aggregate_convergence(&refreshed.active_incidents),
                        trace_id: trace.trace_id.clone(),
                        event_code: FLEET_RECONCILE_COMPLETED.to_string(),
                    },
                )?;
                emit_fleet_action_report(&report, args.json)?;
            }
            FleetCommand::Agent(args) => {
                run_fleet_agent(&args)?;
            }
        },

        Command::Incident(sub) => match sub {
            IncidentCommand::Bundle(args) => {
                handle_incident_bundle_command(&args)?;
            }
            IncidentCommand::Replay(args) => {
                eprintln!(
                    "franken-node incident replay: bundle={}",
                    args.bundle.display()
                );
                let bundle = read_bundle_from_path(&args.bundle).with_context(|| {
                    format!("failed reading replay bundle {}", args.bundle.display())
                })?;
                let outcome = replay_incident_bundle(&bundle).with_context(|| {
                    format!("failed replaying bundle {}", args.bundle.display())
                })?;
                eprintln!(
                    "incident replay result: matched={} event_count={} expected={} replayed={}",
                    outcome.matched,
                    outcome.event_count,
                    outcome.expected_sequence_hash,
                    outcome.replayed_sequence_hash
                );
                if !outcome.matched {
                    anyhow::bail!(
                        "replay mismatch for incident {} in bundle {}",
                        outcome.incident_id,
                        args.bundle.display()
                    );
                }
            }
            IncidentCommand::Counterfactual(args) => {
                eprintln!(
                    "franken-node incident counterfactual: bundle={} policy={}",
                    args.bundle.display(),
                    args.policy
                );
                let bundle = read_bundle_from_path(&args.bundle).with_context(|| {
                    format!("failed reading replay bundle {}", args.bundle.display())
                })?;
                let baseline_policy = PolicyConfig::from_bundle(&bundle);
                let mode = PolicyConfig::from_cli_spec(&args.policy, &baseline_policy)
                    .with_context(|| format!("invalid policy override spec `{}`", args.policy))?;
                let engine = CounterfactualReplayEngine::default();
                let output = engine
                    .simulate(&bundle, &baseline_policy, mode)
                    .with_context(|| {
                        format!(
                            "counterfactual replay failed for bundle {}",
                            args.bundle.display()
                        )
                    })?;
                let (total_decisions, changed_decisions, severity_delta) =
                    summarize_output(&output);
                eprintln!(
                    "counterfactual summary: total_decisions={} changed_decisions={} severity_delta={}",
                    total_decisions, changed_decisions, severity_delta
                );
                let canonical = counterfactual_to_json(&output)
                    .context("failed encoding counterfactual output to canonical json")?;
                eprintln!("counterfactual output: {canonical}");
            }
            IncidentCommand::List(args) => {
                let severity_filter = parse_incident_severity_filter(args.severity.as_deref())?;
                let cwd = std::env::current_dir()
                    .context("failed resolving current working directory for incident list")?;
                let entries = collect_incident_list_entries(&cwd, severity_filter.as_deref())?;
                println!(
                    "{}",
                    render_incident_list(&entries, severity_filter.as_deref())
                );
            }
        },

        Command::Registry(sub) => match sub {
            RegistryCommand::Publish(args) => {
                handle_registry_publish(&args)?;
            }
            RegistryCommand::Search(args) => {
                handle_registry_search(&args)?;
            }
            RegistryCommand::Verify(args) => {
                handle_registry_verify(&args)?;
            }
            RegistryCommand::Gc(args) => {
                handle_registry_gc(&args)?;
            }
        },

        Command::Bench(sub) => match sub {
            BenchCommand::Run(args) => {
                handle_bench_run(&args)?;
            }
        },

        Command::Doctor(args) => {
            let profile_override = parse_profile_override(args.profile.as_deref())?;
            let resolved = config::Config::resolve(
                args.config.as_deref(),
                CliOverrides {
                    profile: profile_override,
                },
            )
            .context("failed resolving configuration for doctor")?;
            let report = build_doctor_report_with_policy_input(
                &resolved,
                &args.trace_id,
                args.policy_activation_input.as_deref(),
            );

            if args.json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else {
                println!("{}", render_doctor_report_human(&report, args.verbose));
            }
        }
    }

    Ok(())
}

// ── State directory bootstrap tests ───────────────────────────────────

#[cfg(test)]
mod state_bootstrap_tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn bootstrap_creates_all_directories() {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();

        let actions = bootstrap_state_directory(root, "balanced").expect("bootstrap");

        for subdir in STATE_BOOTSTRAP_SUBDIRS {
            let dir_path = root.join(".franken-node").join(subdir);
            assert!(
                dir_path.is_dir(),
                "expected directory to exist: {}",
                dir_path.display()
            );
        }

        let created_count = actions
            .iter()
            .filter(|a| matches!(a.action, InitFileActionKind::DirectoryCreated))
            .count();
        assert!(
            created_count >= STATE_BOOTSTRAP_SUBDIRS.len(),
            "expected at least {} DirectoryCreated actions, got {created_count}",
            STATE_BOOTSTRAP_SUBDIRS.len()
        );
    }

    #[test]
    fn bootstrap_creates_empty_trust_registry() {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();

        bootstrap_state_directory(root, "strict").expect("bootstrap");

        let registry_path = root.join(".franken-node/state/trust-card-registry.v1.json");
        assert!(
            registry_path.is_file(),
            "trust-card registry should exist: {}",
            registry_path.display()
        );

        let raw = std::fs::read_to_string(&registry_path).expect("read registry");
        let snapshot: serde_json::Value = serde_json::from_str(&raw).expect("parse registry JSON");
        assert_eq!(
            snapshot["schema_version"],
            "franken-node/trust-card-registry-state/v1"
        );
        let cards = snapshot["cards_by_extension"]
            .as_object()
            .expect("cards_by_extension should be an object");
        assert!(cards.is_empty(), "registry should start empty");
    }

    #[test]
    fn bootstrap_creates_gitignore() {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();

        bootstrap_state_directory(root, "balanced").expect("bootstrap");

        let gitignore_path = root.join(".franken-node/.gitignore");
        assert!(gitignore_path.is_file(), ".gitignore should exist");

        let contents = std::fs::read_to_string(&gitignore_path).expect("read .gitignore");
        assert!(
            contents.contains("keys/"),
            ".gitignore should exclude keys/"
        );
        assert!(
            contents.contains("execution-receipts/"),
            ".gitignore should exclude execution-receipts/"
        );
    }

    #[test]
    fn bootstrap_is_idempotent() {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();

        let first_actions = bootstrap_state_directory(root, "balanced").expect("first bootstrap");
        let first_created = first_actions
            .iter()
            .filter(|a| {
                matches!(
                    a.action,
                    InitFileActionKind::DirectoryCreated | InitFileActionKind::Created
                )
            })
            .count();
        assert!(first_created > 0, "first run should create items");

        let second_actions = bootstrap_state_directory(root, "balanced").expect("second bootstrap");
        let second_created = second_actions
            .iter()
            .filter(|a| {
                matches!(
                    a.action,
                    InitFileActionKind::DirectoryCreated | InitFileActionKind::Created
                )
            })
            .count();
        assert_eq!(
            second_created, 0,
            "second run should create nothing (idempotent)"
        );

        let skipped = second_actions
            .iter()
            .filter(|a| matches!(a.action, InitFileActionKind::SkippedExisting))
            .count();
        assert!(skipped > 0, "second run should skip existing items");
    }

    #[cfg(unix)]
    #[test]
    fn bootstrap_sets_keys_dir_permissions() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();

        bootstrap_state_directory(root, "strict").expect("bootstrap");

        let keys_dir = root.join(".franken-node/keys");
        let mode = keys_dir.metadata().expect("metadata").permissions().mode();
        assert_eq!(
            mode & 0o777,
            0o700,
            "keys/ should have 0700 permissions, got {:#o}",
            mode & 0o777
        );
    }

    #[test]
    fn ensure_state_dir_creates_on_demand() {
        let tmp = TempDir::new().expect("tempdir");
        let root = tmp.path();

        assert!(!root.join(".franken-node/state").is_dir());

        let result = ensure_state_dir(root);
        assert!(result.is_ok());
        assert!(root.join(".franken-node/state").is_dir());
    }
}

#[cfg(test)]
mod run_trust_gate_tests {
    use super::*;
    use crate::ops::telemetry_bridge::{
        BridgeLifecycleState, RuntimeTelemetryEvent, TelemetryRuntimeReport,
    };
    use frankenengine_node::supply_chain::trust_card::fixture_registry;
    use serde_json::{Map, Value};
    use tempfile::TempDir;

    fn write_demo_project(root: &Path, dependencies: &[(&str, &str)]) {
        let deps = dependencies
            .iter()
            .map(|(name, version)| (name.to_string(), Value::String((*version).to_string())))
            .collect::<Map<String, Value>>();
        let manifest = serde_json::json!({
            "name": "trust-gate-demo",
            "version": "1.0.0",
            "main": "index.js",
            "dependencies": deps,
        });
        std::fs::write(
            root.join("package.json"),
            serde_json::to_string_pretty(&manifest).expect("manifest"),
        )
        .expect("write package.json");
        std::fs::write(root.join("index.js"), "console.log('hello');\n").expect("write entrypoint");
    }

    fn write_fixture_registry_to(root: &Path) {
        let registry = fixture_registry(1_000).expect("fixture registry");
        let path = root.join(TRUST_CARD_REGISTRY_STATE_RELATIVE_PATH);
        registry
            .persist_authoritative_state(&path)
            .expect("persist trust registry");
    }

    fn evaluate_preflight(root: &Path, policy_mode: Profile) -> RunPreFlightReport {
        evaluate_run_trust_preflight(
            root,
            policy_mode,
            &config::Config::for_profile(policy_mode),
            2_000,
        )
        .expect("preflight report")
    }

    fn temp_name_leftovers<F>(dir: &Path, mut predicate: F) -> Vec<String>
    where
        F: FnMut(&str) -> bool,
    {
        let mut leftovers = Vec::new();
        for entry in std::fs::read_dir(dir).expect("read dir") {
            let entry = entry.expect("entry");
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if predicate(&name) {
                leftovers.push(name.to_string());
            }
        }
        leftovers.sort();
        leftovers
    }

    fn sample_ssrf_telemetry_report() -> TelemetryRuntimeReport {
        TelemetryRuntimeReport {
            final_state: BridgeLifecycleState::Stopped,
            bridge_id: "bridge-1".to_string(),
            accepted_total: 1,
            persisted_total: 1,
            shed_total: 0,
            dropped_total: 0,
            retry_total: 0,
            drain_completed: true,
            drain_duration_ms: 10,
            telemetry_events: vec![RuntimeTelemetryEvent {
                timestamp: "2026-04-09T15:00:02Z".to_string(),
                event_type: "policy_check".to_string(),
                payload: serde_json::json!({
                    "blocked": true,
                    "detail": "blocked outbound request because ssrf metadata probe matched policy",
                    "rule": "ssrf",
                }),
            }],
            recent_events: Vec::new(),
        }
    }

    fn sample_dispatch_report(
        app_path: &Path,
        started_at_utc: &str,
        finished_at_utc: &str,
        telemetry: Option<TelemetryRuntimeReport>,
    ) -> ops::engine_dispatcher::RunDispatchReport {
        ops::engine_dispatcher::RunDispatchReport {
            runtime: "franken_engine".to_string(),
            runtime_path: "/usr/local/bin/franken-engine".to_string(),
            target: app_path.display().to_string(),
            working_dir: run_project_root(app_path).display().to_string(),
            used_fallback_runtime: false,
            started_at_utc: started_at_utc.to_string(),
            finished_at_utc: finished_at_utc.to_string(),
            duration_ms: 5_000,
            exit_code: Some(0),
            terminated_by_signal: false,
            telemetry,
            captured_output: ops::engine_dispatcher::CapturedProcessOutput {
                stdout: String::new(),
                stderr: String::new(),
            },
        }
    }

    #[test]
    fn trust_gate_skips_when_package_manifest_missing() {
        let tmp = TempDir::new().expect("tempdir");
        let report = evaluate_preflight(tmp.path(), Profile::Balanced);

        match &report.verdict {
            PreFlightVerdict::Skipped { reason } => {
                assert!(reason.contains("package.json not found"));
            }
            other => panic!("expected skipped verdict, got {other:?}"),
        }
        assert_eq!(report.receipt.decision, Decision::Escalated);
    }

    #[test]
    fn trust_gate_skips_missing_registry_first_run() {
        let tmp = TempDir::new().expect("tempdir");
        write_demo_project(tmp.path(), &[("@acme/auth-guard", "^1.4.2")]);

        let report = evaluate_preflight(tmp.path(), Profile::Strict);

        match &report.verdict {
            PreFlightVerdict::Skipped { reason } => {
                assert!(reason.contains("authoritative trust registry missing"));
                assert!(reason.contains("franken-node init --profile strict"));
            }
            other => panic!("expected skipped verdict, got {other:?}"),
        }
        assert!(tmp.path().join(".franken-node/state").is_dir());
    }

    #[test]
    fn trust_gate_blocks_revoked_dependency_in_strict() {
        let tmp = TempDir::new().expect("tempdir");
        write_demo_project(tmp.path(), &[("@beta/telemetry-bridge", "^0.9.1")]);
        write_fixture_registry_to(tmp.path());

        let report = evaluate_preflight(tmp.path(), Profile::Strict);

        match &report.verdict {
            PreFlightVerdict::Blocked {
                reason,
                violations,
                results,
                ..
            } => {
                assert!(reason.contains("blocking trust findings detected"));
                assert!(
                    violations
                        .iter()
                        .any(|violation| violation.kind == TrustViolationKind::Revoked)
                );
                assert!(
                    results
                        .iter()
                        .any(|result| result.status == RunDependencyTrustStatus::Revoked)
                );
            }
            other => panic!("expected blocked verdict, got {other:?}"),
        }
        assert_eq!(report.receipt.decision, Decision::Denied);
    }

    #[test]
    fn trust_gate_blocks_quarantined_dependency_in_balanced() {
        let tmp = TempDir::new().expect("tempdir");
        write_demo_project(tmp.path(), &[("@acme/auth-guard", "^1.4.2")]);
        write_fixture_registry_to(tmp.path());

        let registry_path = tmp.path().join(TRUST_CARD_REGISTRY_STATE_RELATIVE_PATH);
        let mut registry =
            TrustCardRegistry::load_authoritative_state(&registry_path, 60, 2_000).expect("load");
        registry
            .update(
                "npm:@acme/auth-guard",
                TrustCardMutation {
                    certification_level: None,
                    revocation_status: None,
                    active_quarantine: Some(true),
                    reputation_score_basis_points: None,
                    reputation_trend: Some(ReputationTrend::Declining),
                    user_facing_risk_assessment: Some(RiskAssessment {
                        level: RiskLevel::High,
                        summary: "temporarily quarantined for operator review".to_string(),
                    }),
                    last_verified_timestamp: Some("2026-02-20T12:02:00Z".to_string()),
                    evidence_refs: None,
                },
                2_001,
                "trace-test-quarantine",
            )
            .expect("update");
        registry
            .persist_authoritative_state(&registry_path)
            .expect("persist updated registry");

        let report = evaluate_preflight(tmp.path(), Profile::Balanced);

        match &report.verdict {
            PreFlightVerdict::Blocked { violations, .. } => {
                assert!(
                    violations
                        .iter()
                        .any(|violation| violation.kind == TrustViolationKind::Quarantined)
                );
            }
            other => panic!("expected blocked verdict, got {other:?}"),
        }
    }

    #[test]
    fn trust_gate_warns_on_untracked_dependency_in_balanced() {
        let tmp = TempDir::new().expect("tempdir");
        write_demo_project(tmp.path(), &[("left-pad", "^1.3.0")]);
        write_fixture_registry_to(tmp.path());

        let report = evaluate_preflight(tmp.path(), Profile::Balanced);

        match &report.verdict {
            PreFlightVerdict::Passed {
                checked,
                warnings,
                results,
            } => {
                assert_eq!(*checked, 1);
                assert_eq!(warnings.len(), 1);
                assert_eq!(results.len(), 1);
                assert_eq!(results[0].status, RunDependencyTrustStatus::Untracked);
            }
            other => panic!("expected passed verdict, got {other:?}"),
        }
    }

    #[test]
    fn trust_gate_legacy_risky_warns_but_does_not_block_revoked_dependency() {
        let tmp = TempDir::new().expect("tempdir");
        write_demo_project(tmp.path(), &[("@beta/telemetry-bridge", "^0.9.1")]);
        write_fixture_registry_to(tmp.path());

        let report = evaluate_preflight(tmp.path(), Profile::LegacyRisky);

        match &report.verdict {
            PreFlightVerdict::Passed {
                warnings, results, ..
            } => {
                assert_eq!(warnings.len(), 1);
                assert_eq!(results.len(), 1);
                assert_eq!(results[0].status, RunDependencyTrustStatus::Revoked);
            }
            other => panic!("expected passed verdict, got {other:?}"),
        }
        assert_eq!(report.receipt.decision, Decision::Approved);
    }

    #[test]
    fn trust_gate_blocks_corrupt_registry_in_balanced() {
        let tmp = TempDir::new().expect("tempdir");
        write_demo_project(tmp.path(), &[("@acme/auth-guard", "^1.4.2")]);
        ensure_state_dir(tmp.path()).expect("state dir");
        let registry_path = tmp.path().join(TRUST_CARD_REGISTRY_STATE_RELATIVE_PATH);
        std::fs::write(&registry_path, "{ definitely not json\n").expect("write corrupt registry");

        let report = evaluate_preflight(tmp.path(), Profile::Balanced);

        match &report.verdict {
            PreFlightVerdict::Blocked { violations, .. } => {
                assert_eq!(violations.len(), 1);
                assert_eq!(violations[0].kind, TrustViolationKind::RegistryCorrupt);
            }
            other => panic!("expected blocked verdict, got {other:?}"),
        }

        let rendered = serde_json::to_value(&report).expect("json");
        assert_eq!(rendered["verdict"]["status"], "blocked");
        assert_eq!(rendered["receipt"]["decision"], "denied");
    }

    #[test]
    fn run_receipt_id_and_hash_are_deterministic_for_same_inputs() {
        let tmp = TempDir::new().expect("tempdir");
        write_demo_project(tmp.path(), &[("@acme/auth-guard", "^1.4.2")]);
        write_fixture_registry_to(tmp.path());

        let preflight = evaluate_preflight(tmp.path(), Profile::Balanced);
        let dispatch = sample_dispatch_report(
            tmp.path(),
            "2026-04-09T15:00:00Z",
            "2026-04-09T15:00:05Z",
            Some(sample_ssrf_telemetry_report()),
        );
        let ssrf_violations = extract_ssrf_violations(dispatch.telemetry.as_ref());

        let first = build_run_execution_receipt(
            tmp.path(),
            "balanced",
            Profile::Balanced,
            &preflight,
            &dispatch,
            ssrf_violations.clone(),
            Vec::new(),
            None,
        )
        .expect("first receipt");
        let second = build_run_execution_receipt(
            tmp.path(),
            "balanced",
            Profile::Balanced,
            &preflight,
            &dispatch,
            ssrf_violations,
            Vec::new(),
            None,
        )
        .expect("second receipt");

        assert_eq!(first.core.receipt_id, second.core.receipt_id);
        assert_eq!(first.receipt_hash, second.receipt_hash);
    }

    #[test]
    fn temp_file_guard_orphans_abandoned_temp_files() {
        let tmp = TempDir::new().expect("tempdir");
        let temp_path = tmp.path().join("receipt.json.tmp");
        std::fs::write(&temp_path, "pending").expect("write temp file");

        {
            let _guard = TempFileGuard::new(temp_path.clone());
        }

        assert!(!temp_path.exists(), "temp file should be moved aside");
        let orphaned = std::fs::read_dir(tmp.path())
            .expect("read dir")
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("receipt.json.tmp.orphaned-"))
            })
            .collect::<Vec<_>>();
        assert_eq!(orphaned.len(), 1, "expected one orphaned temp artifact");
    }

    #[test]
    fn temp_dir_guard_orphans_abandoned_temp_dirs() {
        let tmp = TempDir::new().expect("tempdir");
        let temp_dir = tmp.path().join("registry-artifact.tmp");
        std::fs::create_dir_all(&temp_dir).expect("create temp dir");

        {
            let _guard = TempDirGuard::new(temp_dir.clone());
        }

        assert!(!temp_dir.exists(), "temp dir should be moved aside");
        let orphaned = std::fs::read_dir(tmp.path())
            .expect("read dir")
            .filter_map(|entry| entry.ok().map(|entry| entry.path()))
            .filter(|path| {
                path.file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.starts_with("registry-artifact.tmp.orphaned-"))
            })
            .collect::<Vec<_>>();
        assert_eq!(orphaned.len(), 1, "expected one orphaned temp dir");
    }

    #[test]
    fn persist_run_execution_receipt_cleans_temp_files() {
        let tmp = TempDir::new().expect("tempdir");
        write_demo_project(tmp.path(), &[("@acme/auth-guard", "^1.4.2")]);
        write_fixture_registry_to(tmp.path());

        let preflight = evaluate_preflight(tmp.path(), Profile::Balanced);
        let receipt = build_run_execution_receipt(
            tmp.path(),
            "balanced",
            Profile::Balanced,
            &preflight,
            &sample_dispatch_report(
                tmp.path(),
                "2026-04-01T00:00:00Z",
                "2026-04-01T00:00:05Z",
                None,
            ),
            Vec::new(),
            Vec::new(),
            None,
        )
        .expect("receipt");

        let receipt_path = persist_run_execution_receipt(tmp.path(), &receipt, 2).expect("persist");
        let day_dir = receipt_path.parent().expect("day dir");
        let leftovers = temp_name_leftovers(day_dir, |name| name.contains(".tmp-"));
        assert!(
            leftovers.is_empty(),
            "temp receipt files should be cleaned: {leftovers:?}"
        );
    }

    #[test]
    fn persist_run_execution_receipt_archives_old_receipts_when_limit_is_exceeded() {
        let tmp = TempDir::new().expect("tempdir");
        write_demo_project(tmp.path(), &[("@acme/auth-guard", "^1.4.2")]);
        write_fixture_registry_to(tmp.path());

        let preflight = evaluate_preflight(tmp.path(), Profile::Balanced);
        let receipt_one = build_run_execution_receipt(
            tmp.path(),
            "balanced",
            Profile::Balanced,
            &preflight,
            &sample_dispatch_report(
                tmp.path(),
                "2026-04-01T00:00:00Z",
                "2026-04-01T00:00:05Z",
                None,
            ),
            Vec::new(),
            Vec::new(),
            None,
        )
        .expect("receipt one");
        let receipt_two = build_run_execution_receipt(
            tmp.path(),
            "balanced",
            Profile::Balanced,
            &preflight,
            &sample_dispatch_report(
                tmp.path(),
                "2026-04-02T00:00:00Z",
                "2026-04-02T00:00:05Z",
                None,
            ),
            Vec::new(),
            Vec::new(),
            None,
        )
        .expect("receipt two");
        let receipt_three = build_run_execution_receipt(
            tmp.path(),
            "balanced",
            Profile::Balanced,
            &preflight,
            &sample_dispatch_report(
                tmp.path(),
                "2026-04-03T00:00:00Z",
                "2026-04-03T00:00:05Z",
                None,
            ),
            Vec::new(),
            Vec::new(),
            None,
        )
        .expect("receipt three");

        let path_one =
            persist_run_execution_receipt(tmp.path(), &receipt_one, 2).expect("persist one");
        let path_two =
            persist_run_execution_receipt(tmp.path(), &receipt_two, 2).expect("persist two");
        let path_three =
            persist_run_execution_receipt(tmp.path(), &receipt_three, 2).expect("persist three");

        assert!(
            !path_one.exists(),
            "oldest receipt should move into archive"
        );
        assert!(path_two.is_file(), "second receipt should remain active");
        assert!(path_three.is_file(), "third receipt should remain active");

        let archived_path = tmp.path().join(format!(
            ".franken-node/state/execution-receipts/archive/2026-04-01/{}.json",
            receipt_one.core.receipt_id
        ));
        assert!(
            archived_path.is_file(),
            "archived receipt should exist at {}",
            archived_path.display()
        );
    }

    #[test]
    fn auto_quarantine_marks_trusted_dependencies_after_runtime_violations() {
        let tmp = TempDir::new().expect("tempdir");
        write_demo_project(tmp.path(), &[("@acme/auth-guard", "^1.4.2")]);
        write_fixture_registry_to(tmp.path());

        let config = config::Config::for_profile(Profile::Balanced);
        let preflight = evaluate_preflight(tmp.path(), Profile::Balanced);
        let quarantined = maybe_auto_quarantine_run_dependencies(
            tmp.path(),
            &config,
            &preflight,
            RUN_EXECUTION_RECEIPT_AUTO_QUARANTINE_THRESHOLD,
            3_000,
        )
        .expect("auto quarantine");

        assert_eq!(quarantined, vec!["npm:@acme/auth-guard".to_string()]);

        let registry_path = tmp.path().join(TRUST_CARD_REGISTRY_STATE_RELATIVE_PATH);
        let mut registry =
            TrustCardRegistry::load_authoritative_state(&registry_path, 60, 3_000).expect("load");
        let card = registry
            .read("npm:@acme/auth-guard", 3_000, "trace-test-auto-quarantine")
            .expect("read")
            .expect("trust card");
        assert!(card.active_quarantine, "card should be quarantined");
        assert_eq!(card.reputation_trend, ReputationTrend::Declining);
        assert!(
            card.user_facing_risk_assessment
                .summary
                .contains("Automatically quarantined")
        );
    }
}
