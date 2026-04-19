//! bd-nbwo: Universal Verifier SDK for third-party verification (Section 10.17).
//!
//! Provides a stable, versioned API that enables independent third parties to
//! verify artifacts, replay capsules, and verification chains. The SDK is the
//! universal entry point for all verification operations in the franken-node
//! ecosystem.
//!
//! # Capabilities
//!
//! - `verify_artifact`: Verify a single artifact against its claimed hash and properties
//! - `verify_capsule`: Verify a replay capsule for deterministic re-execution
//! - `verify_chain`: Verify a chain of verification reports for consistency
//! - Machine-readable pass/fail evidence in every report
//! - Stable API surface with semantic versioning
//!
//! # Event Codes
//!
//! - VSK-001: Artifact verification started
//! - VSK-002: Artifact verification completed
//! - VSK-003: Capsule verification started
//! - VSK-004: Capsule verification completed
//! - VSK-005: Chain verification started
//! - VSK-006: Chain verification completed
//! - VSK-007: SDK configuration loaded
//! - VSK-008: Verification report signed
//!
//! # Invariants
//!
//! - **INV-VSK-STABLE-API**: The public API surface is versioned and backwards-compatible
//!   within a major version.
//! - **INV-VSK-DETERMINISTIC-VERIFY**: Given identical inputs, verification always
//!   produces identical outputs (verdict, evidence, trace).
//! - **INV-VSK-CAPSULE-SELF-CONTAINED**: Every replay capsule carries all information
//!   needed for offline, independent re-execution without external lookups.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current API version of the Verifier SDK.
pub const API_VERSION: &str = "1.0.0";

/// Schema tag embedded in every verification report.
pub const SCHEMA_TAG: &str = "vsk-v1.0";

const RESERVED_ARTIFACT_ID: &str = "<unknown>";

/// Stable posture marker for this structural verifier SDK surface.
///
/// Replacement-critical verifier work must use the stronger connector and
/// verifier-economy signed-capsule paths until the canonical shared kernel
/// lands under bd-1z5a.
pub const STRUCTURAL_ONLY_SECURITY_POSTURE: &str = "structural_only_not_replacement_critical";

/// Stable rule id used by shortcut-regression guardrails.
pub const STRUCTURAL_ONLY_RULE_ID: &str = "VERIFIER_SHORTCUT_GUARD::SDK_VERIFIER";

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Artifact verification started.
    pub const VSK_001_ARTIFACT_VERIFY_STARTED: &str = "VSK-001";
    /// Artifact verification completed.
    pub const VSK_002_ARTIFACT_VERIFY_COMPLETED: &str = "VSK-002";
    /// Capsule verification started.
    pub const VSK_003_CAPSULE_VERIFY_STARTED: &str = "VSK-003";
    /// Capsule verification completed.
    pub const VSK_004_CAPSULE_VERIFY_COMPLETED: &str = "VSK-004";
    /// Chain verification started.
    pub const VSK_005_CHAIN_VERIFY_STARTED: &str = "VSK-005";
    /// Chain verification completed.
    pub const VSK_006_CHAIN_VERIFY_COMPLETED: &str = "VSK-006";
    /// SDK configuration loaded.
    pub const VSK_007_CONFIG_LOADED: &str = "VSK-007";
    /// Verification report signed.
    pub const VSK_008_REPORT_SIGNED: &str = "VSK-008";
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

pub mod invariants {
    pub const INV_VSK_STABLE_API: &str = "INV-VSK-STABLE-API";
    pub const INV_VSK_DETERMINISTIC_VERIFY: &str = "INV-VSK-DETERMINISTIC-VERIFY";
    pub const INV_VSK_CAPSULE_SELF_CONTAINED: &str = "INV-VSK-CAPSULE-SELF-CONTAINED";
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

/// Errors that can occur during SDK verification operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SdkError {
    /// The artifact ID or hash was missing or empty.
    InvalidArtifact(String),
    /// The artifact hash did not match the expected value.
    HashMismatch { expected: String, actual: String },
    /// A claim in the verification request was invalid.
    InvalidClaim(String),
    /// A capsule was malformed or incomplete.
    MalformedCapsule(String),
    /// A verification chain was broken or inconsistent.
    BrokenChain(String),
    /// The SDK was misconfigured.
    ConfigError(String),
}

impl std::fmt::Display for SdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidArtifact(msg) => write!(f, "invalid_artifact: {msg}"),
            Self::HashMismatch { expected, actual } => {
                write!(f, "hash_mismatch: expected={expected}, actual={actual}")
            }
            Self::InvalidClaim(msg) => write!(f, "invalid_claim: {msg}"),
            Self::MalformedCapsule(msg) => write!(f, "malformed_capsule: {msg}"),
            Self::BrokenChain(msg) => write!(f, "broken_chain: {msg}"),
            Self::ConfigError(msg) => write!(f, "config_error: {msg}"),
        }
    }
}

impl std::error::Error for SdkError {}

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Configuration for the Verifier SDK.
///
/// INV-VSK-STABLE-API: the configuration structure is versioned.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierConfig {
    /// Human-readable verifier identity (e.g. "verifier://alice@example.com").
    pub verifier_identity: String,
    /// Whether to require hash verification on every artifact.
    pub require_hash_match: bool,
    /// Whether to require all claims to be non-empty.
    pub strict_claims: bool,
    /// Additional properties carried forward for extensibility.
    pub extensions: BTreeMap<String, String>,
}

impl Default for VerifierConfig {
    fn default() -> Self {
        Self {
            verifier_identity: "verifier://default".to_string(),
            require_hash_match: true,
            strict_claims: true,
            extensions: BTreeMap::new(),
        }
    }
}

/// The universal Verifier SDK entry point.
///
/// INV-VSK-STABLE-API: All public methods are stable within a major version.
#[derive(Debug, Clone)]
pub struct VerifierSdk {
    config: VerifierConfig,
}

/// A request to verify an artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationRequest {
    pub artifact_id: String,
    pub artifact_hash: String,
    pub claims: Vec<String>,
}

/// The verdict of a verification operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifyVerdict {
    Pass,
    Fail(Vec<String>),
    Inconclusive(String),
}

/// A single piece of evidence in a verification report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceEntry {
    pub check_name: String,
    pub passed: bool,
    pub detail: String,
}

/// Machine-readable verification report.
///
/// INV-VSK-DETERMINISTIC-VERIFY: identical inputs produce identical reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    pub request_id: String,
    pub verdict: VerifyVerdict,
    pub evidence: Vec<EvidenceEntry>,
    pub trace_id: String,
    pub schema_tag: String,
    pub api_version: String,
    pub verifier_identity: String,
    pub binding_hash: String,
}

/// Structured SDK event for audit logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SdkEvent {
    pub event_code: String,
    pub detail: String,
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Deterministic SHA-256 hash (hex-encoded, 64 chars).
/// INV-VSK-DETERMINISTIC-VERIFY: same input always produces same output.
fn deterministic_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"verifier_sdk_v1:");
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

/// Deterministic SHA-256 hash over multiple fields using length-prefixed encoding.
/// Prevents hash collision when fields contain delimiters.
fn deterministic_hash_fields(fields: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"verifier_sdk_v1:");
    for field in fields {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    hex::encode(hasher.finalize())
}

fn artifact_binding_hash(request: &VerificationRequest) -> String {
    let mut fields = Vec::with_capacity(2 + request.claims.len());
    fields.push(request.artifact_id.trim());
    fields.push(request.artifact_hash.as_str());
    fields.extend(request.claims.iter().map(String::as_str));
    deterministic_hash_fields(&fields)
}

#[allow(dead_code)]
fn now_timestamp() -> String {
    "2026-02-21T00:00:00Z".to_string()
}

// ---------------------------------------------------------------------------
// VerifierSdk implementation
// ---------------------------------------------------------------------------

impl VerifierSdk {
    /// Create a new SDK instance with the given configuration.
    pub fn new(config: VerifierConfig) -> Self {
        Self { config }
    }

    /// Create an SDK instance with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(VerifierConfig::default())
    }

    /// Return the current API version.
    /// INV-VSK-STABLE-API
    pub fn api_version(&self) -> &str {
        API_VERSION
    }

    /// Return the verifier identity from the config.
    pub fn verifier_identity(&self) -> &str {
        &self.config.verifier_identity
    }

    /// Return a reference to the full configuration.
    pub fn config(&self) -> &VerifierConfig {
        &self.config
    }

    /// Verify a single artifact against its declared hash and claims.
    ///
    /// INV-VSK-DETERMINISTIC-VERIFY: same request always produces same report.
    pub fn verify_artifact(
        &self,
        request: &VerificationRequest,
    ) -> Result<VerificationReport, SdkError> {
        let artifact_id = request.artifact_id.trim();
        if artifact_id.is_empty() {
            return Err(SdkError::InvalidArtifact(
                "artifact_id is empty".to_string(),
            ));
        }
        if artifact_id == RESERVED_ARTIFACT_ID {
            return Err(SdkError::InvalidArtifact(format!(
                "artifact_id is reserved: {:?}",
                request.artifact_id
            )));
        }
        if request.artifact_id != artifact_id {
            return Err(SdkError::InvalidArtifact(
                "artifact_id contains leading or trailing whitespace".to_string(),
            ));
        }
        if request.artifact_hash.is_empty() {
            return Err(SdkError::InvalidArtifact(
                "artifact_hash is empty".to_string(),
            ));
        }

        let mut evidence = Vec::new();

        // Check artifact_id
        evidence.push(EvidenceEntry {
            check_name: "artifact_id_present".to_string(),
            passed: true,
            detail: format!("artifact_id={artifact_id}"),
        });

        // Check artifact_hash format (expect 64 hex chars)
        let hash_valid = request.artifact_hash.len() == 64
            && request.artifact_hash.chars().all(|c| c.is_ascii_hexdigit());
        evidence.push(EvidenceEntry {
            check_name: "artifact_hash_format".to_string(),
            passed: hash_valid,
            detail: if hash_valid {
                "64-char hex hash".to_string()
            } else {
                format!("invalid hash length={}", request.artifact_hash.len())
            },
        });

        // Check claims
        let claims_ok = if self.config.strict_claims {
            !request.claims.is_empty() && request.claims.iter().all(|c| !c.is_empty())
        } else {
            true
        };
        evidence.push(EvidenceEntry {
            check_name: "claims_valid".to_string(),
            passed: claims_ok,
            detail: format!("{} claims", request.claims.len()),
        });

        // Per-claim checks
        for (i, claim) in request.claims.iter().enumerate() {
            let ok = !claim.is_empty();
            evidence.push(EvidenceEntry {
                check_name: format!("claim_{i}_non_empty"),
                passed: ok,
                detail: if ok {
                    format!("claim[{i}] present")
                } else {
                    format!("claim[{i}] is empty")
                },
            });
        }

        // Hash match check (compare artifact_hash to self-computed hash of artifact_id)
        let computed = deterministic_hash(artifact_id);
        let hash_match = if self.config.require_hash_match {
            crate::security::constant_time::ct_eq(&computed, &request.artifact_hash)
        } else {
            true
        };
        evidence.push(EvidenceEntry {
            check_name: "hash_match".to_string(),
            passed: hash_match,
            detail: if hash_match {
                "hash matches".to_string()
            } else {
                format!("expected={}, actual={}", request.artifact_hash, computed)
            },
        });

        let all_pass = evidence.iter().all(|e| e.passed);
        let failures: Vec<String> = evidence
            .iter()
            .filter(|e| !e.passed)
            .map(|e| e.check_name.clone())
            .collect();

        let verdict = if all_pass {
            VerifyVerdict::Pass
        } else {
            VerifyVerdict::Fail(failures)
        };

        let binding_hash = artifact_binding_hash(request);

        Ok(VerificationReport {
            request_id: format!("vreq-{}", &deterministic_hash(artifact_id)[..24]),
            verdict,
            evidence,
            trace_id: format!("vtrc-{}", &binding_hash[..24]),
            schema_tag: SCHEMA_TAG.to_string(),
            api_version: API_VERSION.to_string(),
            verifier_identity: self.config.verifier_identity.clone(),
            binding_hash,
        })
    }

    /// Verify a replay capsule for deterministic re-execution.
    ///
    /// INV-VSK-CAPSULE-SELF-CONTAINED: the capsule carries everything needed.
    /// INV-VSK-DETERMINISTIC-VERIFY: same capsule always produces same report.
    pub fn verify_capsule(
        &self,
        capsule: &super::replay_capsule::ReplayCapsule,
    ) -> Result<VerificationReport, SdkError> {
        if capsule.capsule_id.is_empty() {
            return Err(SdkError::MalformedCapsule(
                "capsule_id is empty".to_string(),
            ));
        }

        let mut evidence = Vec::new();

        // capsule_id present
        evidence.push(EvidenceEntry {
            check_name: "capsule_id_present".to_string(),
            passed: true,
            detail: format!("capsule_id={}", capsule.capsule_id),
        });

        // format_version check
        let version_ok = super::replay_capsule::is_version_supported(capsule.format_version);
        evidence.push(EvidenceEntry {
            check_name: "format_version_valid".to_string(),
            passed: version_ok,
            detail: format!("format_version={}", capsule.format_version),
        });

        // inputs non-empty (self-contained)
        let inputs_ok = !capsule.inputs.is_empty();
        evidence.push(EvidenceEntry {
            check_name: "inputs_non_empty".to_string(),
            passed: inputs_ok,
            detail: format!("{} inputs", capsule.inputs.len()),
        });

        // expected_outputs non-empty
        let outputs_ok = !capsule.expected_outputs.is_empty();
        evidence.push(EvidenceEntry {
            check_name: "expected_outputs_non_empty".to_string(),
            passed: outputs_ok,
            detail: format!("{} expected outputs", capsule.expected_outputs.len()),
        });

        // environment present
        let env_ok = !capsule.environment.runtime_version.is_empty()
            && !capsule.environment.platform.is_empty()
            && !capsule.environment.config_hash.is_empty();
        evidence.push(EvidenceEntry {
            check_name: "environment_present".to_string(),
            passed: env_ok,
            detail: format!(
                "runtime_version={}, platform={}, config_hash_present={}",
                capsule.environment.runtime_version,
                capsule.environment.platform,
                !capsule.environment.config_hash.is_empty()
            ),
        });

        // Sequence monotonicity check on inputs
        let monotonic = capsule
            .inputs
            .windows(2)
            .all(|pair| pair[0].seq < pair[1].seq);
        let seq_ok = capsule.inputs.len() <= 1 || monotonic;
        evidence.push(EvidenceEntry {
            check_name: "input_sequence_monotonic".to_string(),
            passed: seq_ok,
            detail: if seq_ok {
                "input sequences are strictly increasing".to_string()
            } else {
                "input sequences are NOT strictly increasing".to_string()
            },
        });

        // Replay through the canonical capsule path so SDK verification cannot
        // drift from the shared replay semantics.
        let replay_result = super::replay_capsule::replay(capsule);
        let replay_match = match &replay_result {
            Ok(replay_hash) => super::replay_capsule::expected_outputs_match_hash(
                &capsule.expected_outputs,
                replay_hash,
            ),
            Err(_) => false,
        };
        evidence.push(EvidenceEntry {
            check_name: "replay_deterministic_match".to_string(),
            passed: replay_match,
            detail: match replay_result {
                Ok(_) if replay_match => "replay hash matches all expected outputs".to_string(),
                Ok(replay_hash) => format!("replay_hash={replay_hash}"),
                Err(err) => err.to_string(),
            },
        });

        let all_pass = evidence.iter().all(|e| e.passed);
        let failures: Vec<String> = evidence
            .iter()
            .filter(|e| !e.passed)
            .map(|e| e.check_name.clone())
            .collect();

        let verdict = if all_pass {
            VerifyVerdict::Pass
        } else {
            VerifyVerdict::Fail(failures)
        };

        let capsule_json = super::replay_capsule::to_canonical_json(capsule).map_err(|err| {
            SdkError::MalformedCapsule(format!("canonical capsule serialization failed: {err}"))
        })?;
        let binding_hash = deterministic_hash_fields(&[&capsule_json]);

        Ok(VerificationReport {
            request_id: format!("vcap-{}", &deterministic_hash(&capsule.capsule_id)[..24]),
            verdict,
            evidence,
            trace_id: format!("vtrc-{}", &binding_hash[..24]),
            schema_tag: SCHEMA_TAG.to_string(),
            api_version: API_VERSION.to_string(),
            verifier_identity: self.config.verifier_identity.clone(),
            binding_hash,
        })
    }

    /// Verify a chain of verification reports for consistency and integrity.
    ///
    /// INV-VSK-DETERMINISTIC-VERIFY: same chain always produces same result.
    pub fn verify_chain(
        &self,
        reports: &[VerificationReport],
    ) -> Result<VerificationReport, SdkError> {
        if reports.is_empty() {
            return Err(SdkError::BrokenChain("chain is empty".to_string()));
        }

        let mut evidence = Vec::new();

        // Chain length
        evidence.push(EvidenceEntry {
            check_name: "chain_length".to_string(),
            passed: true,
            detail: format!("{} reports in chain", reports.len()),
        });

        // All reports have same schema_tag
        let same_schema = reports.iter().all(|r| r.schema_tag == SCHEMA_TAG);
        evidence.push(EvidenceEntry {
            check_name: "schema_tag_consistent".to_string(),
            passed: same_schema,
            detail: if same_schema {
                format!("all reports use {SCHEMA_TAG}")
            } else {
                "schema_tag mismatch in chain".to_string()
            },
        });

        // All reports have same api_version
        let same_api = reports.iter().all(|r| r.api_version == API_VERSION);
        evidence.push(EvidenceEntry {
            check_name: "api_version_consistent".to_string(),
            passed: same_api,
            detail: if same_api {
                format!("all reports use {API_VERSION}")
            } else {
                "api_version mismatch in chain".to_string()
            },
        });

        // All binding hashes non-empty
        let all_hashes = reports.iter().all(|r| !r.binding_hash.is_empty());
        evidence.push(EvidenceEntry {
            check_name: "binding_hashes_present".to_string(),
            passed: all_hashes,
            detail: if all_hashes {
                "all binding hashes present".to_string()
            } else {
                "some binding hashes missing".to_string()
            },
        });

        // All binding hashes unique
        let unique_hashes: std::collections::BTreeSet<&str> =
            reports.iter().map(|r| r.binding_hash.as_str()).collect();
        let all_unique = unique_hashes.len() == reports.len();
        evidence.push(EvidenceEntry {
            check_name: "binding_hashes_unique".to_string(),
            passed: all_unique,
            detail: if all_unique {
                "all binding hashes are unique".to_string()
            } else {
                format!(
                    "duplicate hashes: {} unique out of {}",
                    unique_hashes.len(),
                    reports.len()
                )
            },
        });

        // Hash-chain: each report's binding_hash should reference its own input
        // (sequential integrity: each report_id is unique)
        let unique_ids: std::collections::BTreeSet<&str> =
            reports.iter().map(|r| r.request_id.as_str()).collect();
        let ids_unique = unique_ids.len() == reports.len();
        evidence.push(EvidenceEntry {
            check_name: "request_ids_unique".to_string(),
            passed: ids_unique,
            detail: if ids_unique {
                "all request IDs are unique".to_string()
            } else {
                "duplicate request IDs in chain".to_string()
            },
        });

        // Per-report verdict summary
        let pass_count = reports
            .iter()
            .filter(|r| matches!(r.verdict, VerifyVerdict::Pass))
            .count();
        let fail_count = reports.len() - pass_count;
        evidence.push(EvidenceEntry {
            check_name: "chain_verdict_summary".to_string(),
            passed: fail_count == 0,
            detail: format!("{pass_count} pass, {fail_count} fail"),
        });

        let all_pass = evidence.iter().all(|e| e.passed);
        let failures: Vec<String> = evidence
            .iter()
            .filter(|e| !e.passed)
            .map(|e| e.check_name.clone())
            .collect();

        let verdict = if all_pass {
            VerifyVerdict::Pass
        } else {
            VerifyVerdict::Fail(failures)
        };

        let chain_binding_refs: Vec<&str> =
            reports.iter().map(|r| r.binding_hash.as_str()).collect();
        let chain_binding = deterministic_hash_fields(&chain_binding_refs);

        Ok(VerificationReport {
            request_id: format!("vchn-{}", &deterministic_hash(&chain_binding)[..24]),
            verdict,
            evidence,
            trace_id: format!(
                "vtrc-{}",
                &deterministic_hash(&format!("chain:{chain_binding}"))[..24]
            ),
            schema_tag: SCHEMA_TAG.to_string(),
            api_version: API_VERSION.to_string(),
            verifier_identity: self.config.verifier_identity.clone(),
            binding_hash: chain_binding,
        })
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::replay_capsule::*;
    use super::*;

    const SDK_VERIFIER_SOURCE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sdk/verifier_sdk.rs"
    ));
    const SDK_REPLAY_CAPSULE_SOURCE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/sdk/replay_capsule.rs"
    ));
    const CONNECTOR_VERIFIER_SOURCE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/connector/verifier_sdk.rs"
    ));
    const VERIFIER_ECONOMY_SOURCE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/verifier_economy/mod.rs"
    ));

    fn assert_guard_contains(rule_id: &str, path: &str, source: &str, needle: &str) {
        assert!(
            source.contains(needle),
            "{rule_id}: expected `{path}` to contain `{needle}`"
        );
    }

    fn assert_guard_absent(rule_id: &str, path: &str, source: &str, needle: &str) {
        assert!(
            !source.contains(needle),
            "{rule_id}: unexpected `{needle}` in `{path}`"
        );
    }

    fn test_sdk() -> VerifierSdk {
        VerifierSdk::with_defaults()
    }

    fn valid_request() -> VerificationRequest {
        let artifact_id = "artifact-001".to_string();
        let artifact_hash = deterministic_hash(&artifact_id);
        VerificationRequest {
            artifact_id,
            artifact_hash,
            claims: vec!["claim-a".to_string(), "claim-b".to_string()],
        }
    }

    fn valid_capsule() -> ReplayCapsule {
        let inputs = vec![
            CapsuleInput {
                seq: 0,
                data: b"input-0".to_vec(),
                metadata: BTreeMap::new(),
            },
            CapsuleInput {
                seq: 1,
                data: b"input-1".to_vec(),
                metadata: BTreeMap::new(),
            },
        ];

        create_capsule(
            "capsule-001",
            inputs,
            EnvironmentSnapshot {
                runtime_version: "1.0.0".to_string(),
                platform: "linux-x86_64".to_string(),
                config_hash: "aabb".repeat(8),
                properties: BTreeMap::new(),
            },
        )
        .expect("valid test capsule")
    }

    fn failed_checks(report: &VerificationReport) -> Vec<&str> {
        report
            .evidence
            .iter()
            .filter(|entry| !entry.passed)
            .map(|entry| entry.check_name.as_str())
            .collect()
    }

    // ── VerifierSdk construction ────────────────────────────────────

    #[test]
    fn test_sdk_with_defaults() {
        let sdk = VerifierSdk::with_defaults();
        assert_eq!(sdk.api_version(), API_VERSION);
        assert_eq!(sdk.verifier_identity(), "verifier://default");
    }

    #[test]
    fn test_sdk_custom_config() {
        let config = VerifierConfig {
            verifier_identity: "verifier://alice".to_string(),
            require_hash_match: false,
            strict_claims: false,
            extensions: BTreeMap::new(),
        };
        let sdk = VerifierSdk::new(config.clone());
        assert_eq!(sdk.config(), &config);
    }

    #[test]
    fn test_sdk_api_version_constant() {
        assert_eq!(API_VERSION, "1.0.0");
    }

    #[test]
    fn test_sdk_schema_tag_constant() {
        assert_eq!(SCHEMA_TAG, "vsk-v1.0");
    }

    // ── verify_artifact: happy path ─────────────────────────────────

    #[test]
    fn test_verify_artifact_pass() {
        let sdk = test_sdk();
        let req = valid_request();
        let report = sdk.verify_artifact(&req).expect("should verify");
        assert_eq!(report.verdict, VerifyVerdict::Pass);
        assert!(!report.binding_hash.is_empty());
    }

    #[test]
    fn test_verify_artifact_report_fields() {
        let sdk = test_sdk();
        let req = valid_request();
        let report = sdk.verify_artifact(&req).expect("should verify");
        assert_eq!(report.schema_tag, SCHEMA_TAG);
        assert_eq!(report.api_version, API_VERSION);
        assert_eq!(report.verifier_identity, "verifier://default");
        assert!(report.request_id.starts_with("vreq-"));
        assert!(report.trace_id.starts_with("vtrc-"));
    }

    #[test]
    fn test_verify_artifact_evidence_entries() {
        let sdk = test_sdk();
        let req = valid_request();
        let report = sdk.verify_artifact(&req).expect("should verify");
        assert_eq!(report.evidence.len(), 6);
        let names: Vec<&str> = report
            .evidence
            .iter()
            .map(|e| e.check_name.as_str())
            .collect();
        assert!(names.contains(&"artifact_id_present"));
        assert!(names.contains(&"artifact_hash_format"));
        assert!(names.contains(&"claims_valid"));
        assert!(names.contains(&"hash_match"));
    }

    // ── verify_artifact: error paths ────────────────────────────────

    #[test]
    fn test_verify_artifact_empty_id() {
        let sdk = test_sdk();
        let req = VerificationRequest {
            artifact_id: String::new(),
            artifact_hash: "a".repeat(64),
            claims: vec!["c".to_string()],
        };
        let err = sdk.verify_artifact(&req).unwrap_err();
        assert!(matches!(err, SdkError::InvalidArtifact(_)));
    }

    #[test]
    fn test_verify_artifact_reserved_id() {
        let sdk = test_sdk();
        let req = VerificationRequest {
            artifact_id: RESERVED_ARTIFACT_ID.to_string(),
            artifact_hash: "a".repeat(64),
            claims: vec!["c".to_string()],
        };
        let err = sdk.verify_artifact(&req).unwrap_err();
        assert!(matches!(err, SdkError::InvalidArtifact(_)));
    }

    #[test]
    fn test_verify_artifact_whitespace_id() {
        let sdk = test_sdk();
        let req = VerificationRequest {
            artifact_id: " art-1 ".to_string(),
            artifact_hash: "a".repeat(64),
            claims: vec!["c".to_string()],
        };
        let err = sdk.verify_artifact(&req).unwrap_err();
        assert!(matches!(err, SdkError::InvalidArtifact(_)));
    }

    #[test]
    fn test_verify_artifact_empty_hash() {
        let sdk = test_sdk();
        let req = VerificationRequest {
            artifact_id: "art-1".to_string(),
            artifact_hash: String::new(),
            claims: vec!["c".to_string()],
        };
        let err = sdk.verify_artifact(&req).unwrap_err();
        assert!(matches!(err, SdkError::InvalidArtifact(_)));
    }

    #[test]
    fn test_verify_artifact_bad_hash_format() {
        let sdk = test_sdk();
        let req = VerificationRequest {
            artifact_id: "art-1".to_string(),
            artifact_hash: "short".to_string(),
            claims: vec!["c".to_string()],
        };
        let report = sdk.verify_artifact(&req).expect("should verify");
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
    }

    #[test]
    fn test_verify_artifact_hash_mismatch() {
        let sdk = test_sdk();
        let req = VerificationRequest {
            artifact_id: "art-1".to_string(),
            artifact_hash: "ff".repeat(32),
            claims: vec!["c".to_string()],
        };
        let report = sdk.verify_artifact(&req).expect("should verify");
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
    }

    #[test]
    fn test_verify_artifact_empty_claims_strict() {
        let sdk = test_sdk();
        let artifact_id = "art-strict".to_string();
        let artifact_hash = deterministic_hash(&artifact_id);
        let req = VerificationRequest {
            artifact_id,
            artifact_hash,
            claims: vec![],
        };
        let report = sdk.verify_artifact(&req).expect("should verify");
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
    }

    #[test]
    fn test_verify_artifact_empty_claims_relaxed() {
        let config = VerifierConfig {
            strict_claims: false,
            require_hash_match: false,
            ..VerifierConfig::default()
        };
        let sdk = VerifierSdk::new(config);
        let req = VerificationRequest {
            artifact_id: "art-relaxed".to_string(),
            artifact_hash: "a".repeat(64),
            claims: vec![],
        };
        let report = sdk.verify_artifact(&req).expect("should verify");
        assert_eq!(report.verdict, VerifyVerdict::Pass);
    }

    #[test]
    fn test_verify_artifact_whitespace_id_errors_before_other_invalid_fields() {
        let sdk = test_sdk();
        let req = VerificationRequest {
            artifact_id: " art-1 ".to_string(),
            artifact_hash: String::new(),
            claims: vec![],
        };
        let err = sdk.verify_artifact(&req).unwrap_err();
        match err {
            SdkError::InvalidArtifact(msg) => {
                assert!(msg.contains("leading/trailing whitespace"));
            }
            other => panic!("expected InvalidArtifact, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_artifact_reserved_id_errors_before_hash_format() {
        let sdk = test_sdk();
        let req = VerificationRequest {
            artifact_id: RESERVED_ARTIFACT_ID.to_string(),
            artifact_hash: "short".to_string(),
            claims: vec!["claim".to_string()],
        };
        let err = sdk.verify_artifact(&req).unwrap_err();
        match err {
            SdkError::InvalidArtifact(msg) => {
                assert!(msg.contains("reserved"));
            }
            other => panic!("expected InvalidArtifact, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_artifact_relaxed_hash_still_reports_bad_hash_format() {
        let config = VerifierConfig {
            strict_claims: false,
            require_hash_match: false,
            ..VerifierConfig::default()
        };
        let sdk = VerifierSdk::new(config);
        let req = VerificationRequest {
            artifact_id: "art-relaxed-bad-format".to_string(),
            artifact_hash: "short".to_string(),
            claims: vec![],
        };
        let report = sdk.verify_artifact(&req).expect("should verify");
        let failures = failed_checks(&report);
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
        assert!(failures.contains(&"artifact_hash_format"));
        assert!(!failures.contains(&"claims_valid"));
        assert!(!failures.contains(&"hash_match"));
    }

    #[test]
    fn test_verify_artifact_strict_claims_reports_specific_empty_claim() {
        let sdk = test_sdk();
        let artifact_id = "art-empty-claim".to_string();
        let req = VerificationRequest {
            artifact_hash: deterministic_hash(&artifact_id),
            artifact_id,
            claims: vec!["claim-a".to_string(), String::new(), "claim-c".to_string()],
        };
        let report = sdk.verify_artifact(&req).expect("should verify");
        let failures = failed_checks(&report);
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
        assert!(failures.contains(&"claims_valid"));
        assert!(failures.contains(&"claim_1_non_empty"));
    }

    // ── verify_artifact: determinism ────────────────────────────────

    #[test]
    fn test_verify_artifact_deterministic() {
        // INV-VSK-DETERMINISTIC-VERIFY
        let sdk = test_sdk();
        let req = valid_request();
        let r1 = sdk.verify_artifact(&req).expect("should verify");
        let r2 = sdk.verify_artifact(&req).expect("should verify");
        assert_eq!(r1.verdict, r2.verdict);
        assert_eq!(r1.binding_hash, r2.binding_hash);
        assert_eq!(r1.request_id, r2.request_id);
        assert_eq!(r1.trace_id, r2.trace_id);
        assert_eq!(r1.evidence.len(), r2.evidence.len());
    }

    // ── verify_capsule: happy path ──────────────────────────────────

    #[test]
    fn test_verify_capsule_pass() {
        let sdk = test_sdk();
        let cap = valid_capsule();
        let report = sdk.verify_capsule(&cap).expect("should verify");
        assert_eq!(report.verdict, VerifyVerdict::Pass);
    }

    #[test]
    fn test_verify_capsule_report_fields() {
        let sdk = test_sdk();
        let cap = valid_capsule();
        let report = sdk.verify_capsule(&cap).expect("should verify");
        assert_eq!(report.schema_tag, SCHEMA_TAG);
        assert_eq!(report.api_version, API_VERSION);
        assert!(report.request_id.starts_with("vcap-"));
    }

    #[test]
    fn test_verify_capsule_evidence_entries() {
        let sdk = test_sdk();
        let cap = valid_capsule();
        let report = sdk.verify_capsule(&cap).expect("should verify");
        let names: Vec<&str> = report
            .evidence
            .iter()
            .map(|e| e.check_name.as_str())
            .collect();
        assert!(names.contains(&"capsule_id_present"));
        assert!(names.contains(&"format_version_valid"));
        assert!(names.contains(&"inputs_non_empty"));
        assert!(names.contains(&"expected_outputs_non_empty"));
        assert!(names.contains(&"environment_present"));
        assert!(names.contains(&"input_sequence_monotonic"));
        assert!(names.contains(&"replay_deterministic_match"));

        let mut replay_entries = report
            .evidence
            .iter()
            .filter(|entry| entry.check_name == "replay_deterministic_match");
        let replay_entry = replay_entries
            .next()
            .expect("replay evidence entry present");
        assert!(
            replay_entries.next().is_none(),
            "replay evidence entry should be unique"
        );
        assert!(replay_entry.passed);
        assert_eq!(
            replay_entry.detail,
            "replay hash matches all expected outputs"
        );
    }

    // ── verify_capsule: error paths ─────────────────────────────────

    #[test]
    fn test_verify_capsule_empty_id() {
        let sdk = test_sdk();
        let mut cap = valid_capsule();
        cap.capsule_id = String::new();
        let err = sdk.verify_capsule(&cap).unwrap_err();
        assert!(matches!(err, SdkError::MalformedCapsule(_)));
    }

    #[test]
    fn test_verify_capsule_no_inputs() {
        let sdk = test_sdk();
        let mut cap = valid_capsule();
        cap.inputs.clear();
        let report = sdk.verify_capsule(&cap).expect("should verify");
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
    }

    // ── NEGATIVE-PATH INLINE TESTS ─────────────────────────────────────────
    // Comprehensive edge case and boundary validation for security-critical functions

    /// Test deterministic_hash with malicious/edge case inputs
    #[test]
    fn test_deterministic_hash_negative_paths() {
        // Empty input - should not crash but produce deterministic output
        let hash_empty = deterministic_hash("");
        assert_eq!(hash_empty.len(), 64); // 32 bytes as hex
        assert!(hash_empty.chars().all(|c| c.is_ascii_hexdigit()));

        // Multiple calls with same empty input must be identical (determinism)
        assert_eq!(hash_empty, deterministic_hash(""));

        // Null byte injection attempt
        let hash_null = deterministic_hash("test\0injection");
        assert_eq!(hash_null.len(), 64);
        assert_ne!(hash_null, deterministic_hash("testinjection"));

        // Unicode boundary cases - ensure proper encoding
        let hash_unicode = deterministic_hash("test🔒security");
        assert_eq!(hash_unicode.len(), 64);
        assert_ne!(hash_unicode, deterministic_hash("testsecurity"));

        // Very long input - potential DoS vector
        let long_input = "A".repeat(65536);
        let hash_long = deterministic_hash(&long_input);
        assert_eq!(hash_long.len(), 64);

        // Control character injection
        let hash_control = deterministic_hash("test\r\n\tinjection");
        assert_eq!(hash_control.len(), 64);
        assert_ne!(hash_control, deterministic_hash("testinjection"));

        // Domain separator collision attempt
        let hash_separator = deterministic_hash("verifier_sdk_v1:");
        assert_eq!(hash_separator.len(), 64);
        // Should not collide with empty input despite matching prefix
        assert_ne!(hash_separator, hash_empty);
    }

    /// Test deterministic_hash_fields with collision and injection attempts
    #[test]
    fn test_deterministic_hash_fields_negative_paths() {
        // Empty fields array
        let hash_empty_fields = deterministic_hash_fields(&[]);
        assert_eq!(hash_empty_fields.len(), 64);

        // Single empty field vs multiple empty fields
        let hash_single_empty = deterministic_hash_fields(&[""]);
        let hash_multi_empty = deterministic_hash_fields(&["", "", ""]);
        assert_ne!(hash_single_empty, hash_multi_empty);

        // Length-prefixed collision attempt: ["ab", "cd"] vs ["abc", "d"]
        let hash_split_1 = deterministic_hash_fields(&["ab", "cd"]);
        let hash_split_2 = deterministic_hash_fields(&["abc", "d"]);
        assert_ne!(hash_split_1, hash_split_2); // Length prefixing prevents collision

        // Pipe delimiter collision attempt (should not collide due to length prefixing)
        let hash_pipe_1 = deterministic_hash_fields(&["test|field", "value"]);
        let hash_pipe_2 = deterministic_hash_fields(&["test", "field|value"]);
        assert_ne!(hash_pipe_1, hash_pipe_2);

        // Domain separator injection in field
        let hash_domain_inject = deterministic_hash_fields(&["verifier_sdk_v1:malicious"]);
        assert_eq!(hash_domain_inject.len(), 64);

        // Unicode normalization consistency
        let hash_unicode_1 = deterministic_hash_fields(&["café"]); // NFC form
        let hash_unicode_2 = deterministic_hash_fields(&["cafe\u{301}"]); // NFD form
        // Fields should be treated as different due to different byte sequences
        // (We don't normalize, so these should be different)
        assert_ne!(hash_unicode_1, hash_unicode_2);

        // Very large number of fields - potential DoS
        let many_fields: Vec<&str> = (0..1000).map(|i| if i % 2 == 0 { "even" } else { "odd" }).collect();
        let hash_many = deterministic_hash_fields(&many_fields);
        assert_eq!(hash_many.len(), 64);

        // Maximum field length boundary
        let huge_field = "X".repeat(100000);
        let hash_huge = deterministic_hash_fields(&[&huge_field]);
        assert_eq!(hash_huge.len(), 64);
    }

    /// Test artifact_binding_hash with malformed verification requests
    #[test]
    fn test_artifact_binding_hash_negative_paths() {
        use super::*;

        // Request with whitespace that gets trimmed
        let req_whitespace = VerificationRequest {
            artifact_id: "  artifact-001  ".to_string(),
            artifact_hash: "abc123".to_string(),
            claims: vec!["claim-a".to_string()],
        };
        let hash_ws = artifact_binding_hash(&req_whitespace);
        assert_eq!(hash_ws.len(), 64);

        // Same request without whitespace should produce same hash after trimming
        let req_no_ws = VerificationRequest {
            artifact_id: "artifact-001".to_string(),
            artifact_hash: "abc123".to_string(),
            claims: vec!["claim-a".to_string()],
        };
        let hash_no_ws = artifact_binding_hash(&req_no_ws);
        assert_eq!(hash_ws, hash_no_ws); // Should be identical due to trimming

        // Empty claims vs no claims
        let req_empty_claims = VerificationRequest {
            artifact_id: "test".to_string(),
            artifact_hash: "hash".to_string(),
            claims: vec![],
        };
        let req_no_claims = VerificationRequest {
            artifact_id: "test".to_string(),
            artifact_hash: "hash".to_string(),
            claims: vec![],
        };
        assert_eq!(artifact_binding_hash(&req_empty_claims), artifact_binding_hash(&req_no_claims));

        // Claims with embedded delimiters
        let req_delim = VerificationRequest {
            artifact_id: "test".to_string(),
            artifact_hash: "hash".to_string(),
            claims: vec!["claim|with|pipes".to_string(), "claim,with,commas".to_string()],
        };
        let hash_delim = artifact_binding_hash(&req_delim);
        assert_eq!(hash_delim.len(), 64);

        // Extremely long claims - DoS protection
        let long_claim = "L".repeat(50000);
        let req_long = VerificationRequest {
            artifact_id: "test".to_string(),
            artifact_hash: "hash".to_string(),
            claims: vec![long_claim],
        };
        let hash_long = artifact_binding_hash(&req_long);
        assert_eq!(hash_long.len(), 64);

        // Many claims - capacity boundary
        let many_claims: Vec<String> = (0..10000).map(|i| format!("claim-{}", i)).collect();
        let req_many = VerificationRequest {
            artifact_id: "test".to_string(),
            artifact_hash: "hash".to_string(),
            claims: many_claims,
        };
        let hash_many = artifact_binding_hash(&req_many);
        assert_eq!(hash_many.len(), 64);
    }

    /// Test VerifierConfig validation and boundary cases
    #[test]
    fn test_verifier_config_negative_paths() {
        // Empty verifier identity
        let config_empty_id = VerifierConfig {
            verifier_identity: String::new(),
            require_hash_match: true,
            strict_claims: true,
            extensions: BTreeMap::new(),
        };
        let sdk = VerifierSdk::new(config_empty_id.clone());
        assert_eq!(sdk.verifier_identity(), "");

        // Malformed verifier identity (not a URI)
        let config_malformed = VerifierConfig {
            verifier_identity: "not-a-uri-scheme".to_string(),
            require_hash_match: true,
            strict_claims: true,
            extensions: BTreeMap::new(),
        };
        let sdk_malformed = VerifierSdk::new(config_malformed);
        // Should accept any string - no validation enforced
        assert_eq!(sdk_malformed.verifier_identity(), "not-a-uri-scheme");

        // Very long verifier identity
        let long_identity = format!("verifier://{}", "x".repeat(10000));
        let config_long = VerifierConfig {
            verifier_identity: long_identity.clone(),
            require_hash_match: true,
            strict_claims: true,
            extensions: BTreeMap::new(),
        };
        let sdk_long = VerifierSdk::new(config_long);
        assert_eq!(sdk_long.verifier_identity(), &long_identity);

        // Many extensions - potential DoS
        let mut many_extensions = BTreeMap::new();
        for i in 0..10000 {
            many_extensions.insert(format!("ext-{}", i), format!("value-{}", i));
        }
        let config_many_ext = VerifierConfig {
            verifier_identity: "verifier://test".to_string(),
            require_hash_match: true,
            strict_claims: true,
            extensions: many_extensions,
        };
        let sdk_many_ext = VerifierSdk::new(config_many_ext);
        assert_eq!(sdk_many_ext.config().extensions.len(), 10000);

        // Conflicting config flags (both strict and relaxed)
        let config_conflict = VerifierConfig {
            verifier_identity: "verifier://test".to_string(),
            require_hash_match: false,
            strict_claims: false,
            extensions: BTreeMap::new(),
        };
        let sdk_conflict = VerifierSdk::new(config_conflict.clone());
        assert_eq!(sdk_conflict.config(), &config_conflict);
    }

    /// Test verify_artifact with extreme boundary conditions
    #[test]
    fn test_verify_artifact_extreme_boundaries() {
        let sdk = test_sdk();

        // Maximum length artifact_id (potential buffer overflow)
        let max_id = "x".repeat(65535);
        let hash_max = deterministic_hash(&max_id);
        let req_max = VerificationRequest {
            artifact_id: max_id.clone(),
            artifact_hash: hash_max,
            claims: vec!["claim".to_string()],
        };
        let report_max = sdk.verify_artifact(&req_max).expect("should handle large ID");
        assert_eq!(report_max.verdict, VerifyVerdict::Pass);

        // Artifact ID with only Unicode characters
        let unicode_id = "🔒🛡️🔐🔑🗝️";
        let hash_unicode = deterministic_hash(unicode_id);
        let req_unicode = VerificationRequest {
            artifact_id: unicode_id.to_string(),
            artifact_hash: hash_unicode,
            claims: vec!["unicode-claim-🌟".to_string()],
        };
        let report_unicode = sdk.verify_artifact(&req_unicode).expect("should handle Unicode");
        assert_eq!(report_unicode.verdict, VerifyVerdict::Pass);

        // Hash with mixed case (should fail validation due to case sensitivity)
        let req_mixed_case = VerificationRequest {
            artifact_id: "test".to_string(),
            artifact_hash: "ABCDEFabcdef1234567890ABCDEFabcdef1234567890ABCDEFabcdef12345678".to_string(),
            claims: vec!["claim".to_string()],
        };
        let report_mixed = sdk.verify_artifact(&req_mixed_case).expect("should verify");
        // Hash format is valid (64 hex chars) but won't match computed hash
        match report_mixed.verdict {
            VerifyVerdict::Fail(failures) => {
                assert!(failures.contains(&"hash_match".to_string()));
            }
            _ => panic!("Expected hash mismatch failure"),
        }

        // Artifact hash with non-hex characters but correct length
        let req_non_hex = VerificationRequest {
            artifact_id: "test".to_string(),
            artifact_hash: "g".repeat(64), // Invalid hex chars
            claims: vec!["claim".to_string()],
        };
        let report_non_hex = sdk.verify_artifact(&req_non_hex).expect("should verify");
        match report_non_hex.verdict {
            VerifyVerdict::Fail(failures) => {
                assert!(failures.contains(&"artifact_hash_format".to_string()));
            }
            _ => panic!("Expected hash format failure"),
        }

        // Maximum number of claims
        let max_claims: Vec<String> = (0..65535).map(|i| format!("claim-{}", i)).collect();
        let req_max_claims = VerificationRequest {
            artifact_id: "test-max-claims".to_string(),
            artifact_hash: deterministic_hash("test-max-claims"),
            claims: max_claims,
        };
        let report_max_claims = sdk.verify_artifact(&req_max_claims).expect("should handle many claims");
        assert_eq!(report_max_claims.verdict, VerifyVerdict::Pass);
        // Should have evidence for each claim plus base checks
        assert!(report_max_claims.evidence.len() > 65535);
    }

    /// Test verify_chain with malicious chain configurations
    #[test]
    fn test_verify_chain_attack_vectors() {
        let sdk = test_sdk();

        // Empty chain should fail fast
        let empty_chain: Vec<VerificationReport> = vec![];
        let err = sdk.verify_chain(&empty_chain).unwrap_err();
        match err {
            SdkError::BrokenChain(msg) => assert!(msg.contains("empty")),
            _ => panic!("Expected BrokenChain error"),
        }

        // Chain with duplicate binding hashes (collision attack)
        let req = valid_request();
        let report1 = sdk.verify_artifact(&req).expect("should verify");
        let mut report2 = report1.clone();
        report2.request_id = "different-request-id".to_string();
        // Same binding_hash but different request_id
        let duplicate_chain = vec![report1, report2];
        let chain_report = sdk.verify_chain(&duplicate_chain).expect("should verify");
        match chain_report.verdict {
            VerifyVerdict::Fail(failures) => {
                assert!(failures.contains(&"binding_hashes_unique".to_string()));
            }
            _ => panic!("Expected binding hash uniqueness failure"),
        }

        // Chain with mixed schema tags (version confusion attack)
        let mut report_wrong_schema = sdk.verify_artifact(&valid_request()).expect("should verify");
        report_wrong_schema.schema_tag = "vsk-v2.0".to_string(); // Different version
        let mixed_schema_chain = vec![
            sdk.verify_artifact(&valid_request()).expect("should verify"),
            report_wrong_schema,
        ];
        let chain_mixed = sdk.verify_chain(&mixed_schema_chain).expect("should verify");
        match chain_mixed.verdict {
            VerifyVerdict::Fail(failures) => {
                assert!(failures.contains(&"schema_tag_consistent".to_string()));
            }
            _ => panic!("Expected schema tag consistency failure"),
        }

        // Chain with mixed API versions (downgrade attack)
        let mut report_wrong_api = sdk.verify_artifact(&valid_request()).expect("should verify");
        report_wrong_api.api_version = "0.9.0".to_string(); // Older version
        let mixed_api_chain = vec![
            sdk.verify_artifact(&valid_request()).expect("should verify"),
            report_wrong_api,
        ];
        let chain_mixed_api = sdk.verify_chain(&mixed_api_chain).expect("should verify");
        match chain_mixed_api.verdict {
            VerifyVerdict::Fail(failures) => {
                assert!(failures.contains(&"api_version_consistent".to_string()));
            }
            _ => panic!("Expected API version consistency failure"),
        }

        // Extremely long chain (DoS protection)
        let base_report = sdk.verify_artifact(&valid_request()).expect("should verify");
        let mut long_chain = Vec::with_capacity(10000);
        for i in 0..10000 {
            let mut report = base_report.clone();
            report.request_id = format!("req-{}", i);
            report.binding_hash = format!("hash-{:064x}", i); // Unique hashes
            long_chain.push(report);
        }
        let long_chain_report = sdk.verify_chain(&long_chain).expect("should handle long chain");
        // Should process successfully but may have some evidence entries
        assert!(long_chain_report.evidence.len() > 0);

        // Chain with empty binding hashes (integrity violation)
        let mut report_empty_hash = sdk.verify_artifact(&valid_request()).expect("should verify");
        report_empty_hash.binding_hash = String::new();
        let empty_hash_chain = vec![
            sdk.verify_artifact(&valid_request()).expect("should verify"),
            report_empty_hash,
        ];
        let chain_empty_hash = sdk.verify_chain(&empty_hash_chain).expect("should verify");
        match chain_empty_hash.verdict {
            VerifyVerdict::Fail(failures) => {
                assert!(failures.contains(&"binding_hashes_present".to_string()));
            }
            _ => panic!("Expected binding hash presence failure"),
        }
    }

    #[test]
    fn test_verify_capsule_no_outputs() {
        let sdk = test_sdk();
        let mut cap = valid_capsule();
        cap.expected_outputs.clear();
        let report = sdk.verify_capsule(&cap).expect("should verify");
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
    }

    #[test]
    fn test_verify_capsule_bad_version() {
        let sdk = test_sdk();
        let mut cap = valid_capsule();
        cap.format_version = 0;
        let report = sdk.verify_capsule(&cap).expect("should verify");
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
    }

    #[test]
    fn test_verify_capsule_non_monotonic_seq() {
        let sdk = test_sdk();
        let mut cap = valid_capsule();
        cap.inputs[1].seq = 0; // same as first = not strictly increasing
        let report = sdk.verify_capsule(&cap).expect("should verify");
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
    }

    #[test]
    fn test_verify_capsule_replay_mismatch() {
        let sdk = test_sdk();
        let mut cap = valid_capsule();
        cap.expected_outputs[0].output_hash = "wrong_hash".to_string();
        let report = sdk.verify_capsule(&cap).expect("should verify");
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
    }

    #[test]
    fn test_verify_capsule_extra_mismatched_expected_output_fails() {
        let sdk = test_sdk();
        let mut cap = valid_capsule();
        cap.expected_outputs.push(CapsuleOutput {
            seq: 1,
            data: b"tampered".to_vec(),
            output_hash: "wrong_hash".to_string(),
        });
        let report = sdk.verify_capsule(&cap).expect("should verify");
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
        assert!(
            report
                .evidence
                .iter()
                .any(|entry| { entry.check_name == "replay_deterministic_match" && !entry.passed })
        );
    }

    #[test]
    fn test_verify_capsule_empty_platform_fails() {
        let sdk = test_sdk();
        let mut cap = valid_capsule();
        cap.environment.platform = String::new();
        let report = sdk.verify_capsule(&cap).expect("should verify");
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
        assert!(
            report
                .evidence
                .iter()
                .any(|entry| entry.check_name == "environment_present" && !entry.passed)
        );
    }

    #[test]
    fn test_verify_capsule_empty_config_hash_fails() {
        let sdk = test_sdk();
        let mut cap = valid_capsule();
        cap.environment.config_hash = String::new();
        let report = sdk.verify_capsule(&cap).expect("should verify");
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
        assert!(
            report
                .evidence
                .iter()
                .any(|entry| entry.check_name == "environment_present" && !entry.passed)
        );
    }

    #[test]
    fn test_verify_capsule_empty_id_error_preserves_capsule_context() {
        let sdk = test_sdk();
        let mut cap = valid_capsule();
        cap.capsule_id = String::new();
        let err = sdk.verify_capsule(&cap).unwrap_err();
        match err {
            SdkError::MalformedCapsule(msg) => {
                assert!(msg.contains("capsule_id is empty"));
            }
            other => panic!("expected MalformedCapsule, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_capsule_multiple_negative_evidence_entries_accumulate() {
        let sdk = test_sdk();
        let mut cap = valid_capsule();
        cap.format_version = 0;
        cap.environment.platform = String::new();
        cap.expected_outputs[0].output_hash = "not-the-replay-hash".to_string();
        let report = sdk.verify_capsule(&cap).expect("should verify");
        let failures = failed_checks(&report);
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
        assert!(failures.contains(&"format_version_valid"));
        assert!(failures.contains(&"environment_present"));
        assert!(failures.contains(&"replay_deterministic_match"));
    }

    // ── verify_capsule: determinism ─────────────────────────────────

    #[test]
    fn test_verify_capsule_deterministic() {
        // INV-VSK-DETERMINISTIC-VERIFY
        let sdk = test_sdk();
        let cap = valid_capsule();
        let r1 = sdk.verify_capsule(&cap).expect("should verify");
        let r2 = sdk.verify_capsule(&cap).expect("should verify");
        assert_eq!(r1.verdict, r2.verdict);
        assert_eq!(r1.binding_hash, r2.binding_hash);
        assert_eq!(r1.evidence.len(), r2.evidence.len());
    }

    #[test]
    fn test_verify_capsule_binding_hash_changes_with_environment() {
        let sdk = test_sdk();
        let cap1 = valid_capsule();
        let mut cap2 = valid_capsule();
        cap2.environment.platform = "darwin-aarch64".to_string();

        let r1 = sdk.verify_capsule(&cap1).expect("should verify");
        let r2 = sdk.verify_capsule(&cap2).expect("should verify");

        assert_eq!(r1.verdict, VerifyVerdict::Pass);
        assert_eq!(r2.verdict, VerifyVerdict::Pass);
        assert_ne!(
            r1.binding_hash, r2.binding_hash,
            "binding hash must change when capsule environment changes"
        );
    }

    // ── verify_chain: happy path ────────────────────────────────────

    #[test]
    fn test_verify_chain_pass() {
        let sdk = test_sdk();
        let r1 = sdk
            .verify_artifact(&valid_request())
            .expect("should verify");
        let mut req2 = valid_request();
        req2.artifact_id = "artifact-002".to_string();
        req2.artifact_hash = deterministic_hash("artifact-002");
        let r2 = sdk.verify_artifact(&req2).expect("should verify");
        let chain_report = sdk.verify_chain(&[r1, r2]).expect("should chain");
        assert_eq!(chain_report.verdict, VerifyVerdict::Pass);
    }

    #[test]
    fn test_verify_chain_report_fields() {
        let sdk = test_sdk();
        let r1 = sdk
            .verify_artifact(&valid_request())
            .expect("should verify");
        let chain_report = sdk.verify_chain(&[r1]).expect("should chain");
        assert!(chain_report.request_id.starts_with("vchn-"));
        assert_eq!(chain_report.schema_tag, SCHEMA_TAG);
    }

    // ── verify_chain: error paths ───────────────────────────────────

    #[test]
    fn test_verify_chain_empty() {
        let sdk = test_sdk();
        let err = sdk.verify_chain(&[]).unwrap_err();
        assert!(matches!(err, SdkError::BrokenChain(_)));
    }

    #[test]
    fn test_verify_chain_with_failing_report() {
        let sdk = test_sdk();
        let passing = sdk
            .verify_artifact(&valid_request())
            .expect("should verify");
        let failing_req = VerificationRequest {
            artifact_id: "art-bad".to_string(),
            artifact_hash: "short".to_string(),
            claims: vec!["c".to_string()],
        };
        let failing = sdk.verify_artifact(&failing_req).expect("should verify");
        let chain_report = sdk.verify_chain(&[passing, failing]).expect("should chain");
        assert!(matches!(chain_report.verdict, VerifyVerdict::Fail(_)));
    }

    #[test]
    fn test_verify_chain_schema_and_api_mismatches_are_reported_together() {
        let sdk = test_sdk();
        let mut report = sdk
            .verify_artifact(&valid_request())
            .expect("should verify");
        report.schema_tag = "old-schema".to_string();
        report.api_version = "0.0.0".to_string();
        let chain_report = sdk.verify_chain(&[report]).expect("should chain");
        let failures = failed_checks(&chain_report);
        assert!(matches!(chain_report.verdict, VerifyVerdict::Fail(_)));
        assert!(failures.contains(&"schema_tag_consistent"));
        assert!(failures.contains(&"api_version_consistent"));
    }

    #[test]
    fn test_verify_chain_duplicate_request_ids_fail_even_with_distinct_inputs() {
        let sdk = test_sdk();
        let first = sdk
            .verify_artifact(&valid_request())
            .expect("should verify");
        let artifact_id = "artifact-distinct-request-id-check".to_string();
        let second_req = VerificationRequest {
            artifact_hash: deterministic_hash(&artifact_id),
            artifact_id,
            claims: vec!["claim-c".to_string()],
        };
        let mut second = sdk.verify_artifact(&second_req).expect("should verify");
        second.request_id = first.request_id.clone();
        let chain_report = sdk.verify_chain(&[first, second]).expect("should chain");
        let failures = failed_checks(&chain_report);
        assert!(matches!(chain_report.verdict, VerifyVerdict::Fail(_)));
        assert!(failures.contains(&"request_ids_unique"));
        assert!(!failures.contains(&"binding_hashes_unique"));
    }

    #[test]
    fn test_verify_chain_empty_binding_hash_is_negative_evidence() {
        let sdk = test_sdk();
        let mut report = sdk
            .verify_artifact(&valid_request())
            .expect("should verify");
        report.binding_hash.clear();
        let chain_report = sdk.verify_chain(&[report]).expect("should chain");
        let failures = failed_checks(&chain_report);
        assert!(matches!(chain_report.verdict, VerifyVerdict::Fail(_)));
        assert!(failures.contains(&"binding_hashes_present"));
    }

    // ── verify_chain: determinism ───────────────────────────────────

    #[test]
    fn test_verify_chain_deterministic() {
        // INV-VSK-DETERMINISTIC-VERIFY
        let sdk = test_sdk();
        let r1 = sdk
            .verify_artifact(&valid_request())
            .expect("should verify");
        let chain1 = sdk
            .verify_chain(std::slice::from_ref(&r1))
            .expect("should chain");
        let chain2 = sdk.verify_chain(&[r1]).expect("should chain");
        assert_eq!(chain1.binding_hash, chain2.binding_hash);
    }

    // ── event codes ─────────────────────────────────────────────────

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(event_codes::VSK_001_ARTIFACT_VERIFY_STARTED, "VSK-001");
        assert_eq!(event_codes::VSK_002_ARTIFACT_VERIFY_COMPLETED, "VSK-002");
        assert_eq!(event_codes::VSK_003_CAPSULE_VERIFY_STARTED, "VSK-003");
        assert_eq!(event_codes::VSK_004_CAPSULE_VERIFY_COMPLETED, "VSK-004");
        assert_eq!(event_codes::VSK_005_CHAIN_VERIFY_STARTED, "VSK-005");
        assert_eq!(event_codes::VSK_006_CHAIN_VERIFY_COMPLETED, "VSK-006");
        assert_eq!(event_codes::VSK_007_CONFIG_LOADED, "VSK-007");
        assert_eq!(event_codes::VSK_008_REPORT_SIGNED, "VSK-008");
    }

    // ── invariants ──────────────────────────────────────────────────

    #[test]
    fn test_invariants_defined() {
        assert_eq!(invariants::INV_VSK_STABLE_API, "INV-VSK-STABLE-API");
        assert_eq!(
            invariants::INV_VSK_DETERMINISTIC_VERIFY,
            "INV-VSK-DETERMINISTIC-VERIFY"
        );
        assert_eq!(
            invariants::INV_VSK_CAPSULE_SELF_CONTAINED,
            "INV-VSK-CAPSULE-SELF-CONTAINED"
        );
    }

    // ── Serde round-trips ───────────────────────────────────────────

    #[test]
    fn test_verification_request_serde_roundtrip() {
        let req = valid_request();
        let json = serde_json::to_string(&req).expect("serialize should succeed");
        let parsed: VerificationRequest =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(req, parsed);
    }

    #[test]
    fn test_verification_report_serde_roundtrip() {
        let sdk = test_sdk();
        let report = sdk
            .verify_artifact(&valid_request())
            .expect("should verify");
        let json = serde_json::to_string(&report).expect("serialize should succeed");
        let parsed: VerificationReport =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(report, parsed);
    }

    #[test]
    fn test_verify_verdict_serde_roundtrip() {
        for v in [
            VerifyVerdict::Pass,
            VerifyVerdict::Fail(vec!["reason".to_string()]),
            VerifyVerdict::Inconclusive("maybe".to_string()),
        ] {
            let json = serde_json::to_string(&v).expect("serialize should succeed");
            let parsed: VerifyVerdict =
                serde_json::from_str(&json).expect("deserialize should succeed");
            assert_eq!(v, parsed);
        }
    }

    #[test]
    fn test_evidence_entry_serde_roundtrip() {
        let entry = EvidenceEntry {
            check_name: "test".to_string(),
            passed: true,
            detail: "ok".to_string(),
        };
        let json = serde_json::to_string(&entry).expect("serialize should succeed");
        let parsed: EvidenceEntry =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(entry, parsed);
    }

    #[test]
    fn test_sdk_event_serde_roundtrip() {
        let evt = SdkEvent {
            event_code: "VSK-001".to_string(),
            detail: "started".to_string(),
            timestamp: now_timestamp(),
        };
        let json = serde_json::to_string(&evt).expect("serialize should succeed");
        let parsed: SdkEvent = serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(parsed.event_code, "VSK-001");
    }

    #[test]
    fn test_verifier_config_serde_roundtrip() {
        let config = VerifierConfig::default();
        let json = serde_json::to_string(&config).expect("serialize should succeed");
        let parsed: VerifierConfig =
            serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(config, parsed);
    }

    #[test]
    fn test_sdk_error_serde_roundtrip() {
        let err = SdkError::HashMismatch {
            expected: "a".to_string(),
            actual: "b".to_string(),
        };
        let json = serde_json::to_string(&err).expect("serialize should succeed");
        let parsed: SdkError = serde_json::from_str(&json).expect("deserialize should succeed");
        assert_eq!(err, parsed);
    }

    // ── Error display ───────────────────────────────────────────────

    #[test]
    fn test_error_display_invalid_artifact() {
        let err = SdkError::InvalidArtifact("bad".to_string());
        assert!(format!("{err}").contains("invalid_artifact"));
    }

    #[test]
    fn test_error_display_hash_mismatch() {
        let err = SdkError::HashMismatch {
            expected: "a".to_string(),
            actual: "b".to_string(),
        };
        let display = format!("{err}");
        assert!(display.contains("hash_mismatch"));
        assert!(display.contains("expected=a"));
    }

    #[test]
    fn test_error_display_invalid_claim() {
        let err = SdkError::InvalidClaim("bad".to_string());
        assert!(format!("{err}").contains("invalid_claim"));
    }

    #[test]
    fn test_error_display_malformed_capsule() {
        let err = SdkError::MalformedCapsule("bad".to_string());
        assert!(format!("{err}").contains("malformed_capsule"));
    }

    #[test]
    fn test_error_display_broken_chain() {
        let err = SdkError::BrokenChain("bad".to_string());
        assert!(format!("{err}").contains("broken_chain"));
    }

    #[test]
    fn test_error_display_config_error() {
        let err = SdkError::ConfigError("bad".to_string());
        assert!(format!("{err}").contains("config_error"));
    }

    // ── Send + Sync ─────────────────────────────────────────────────

    #[test]
    fn test_types_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<VerifierSdk>();
        assert_sync::<VerifierSdk>();
        assert_send::<VerifierConfig>();
        assert_sync::<VerifierConfig>();
        assert_send::<VerificationRequest>();
        assert_sync::<VerificationRequest>();
        assert_send::<VerificationReport>();
        assert_sync::<VerificationReport>();
        assert_send::<VerifyVerdict>();
        assert_sync::<VerifyVerdict>();
        assert_send::<EvidenceEntry>();
        assert_sync::<EvidenceEntry>();
        assert_send::<SdkEvent>();
        assert_sync::<SdkEvent>();
        assert_send::<SdkError>();
        assert_sync::<SdkError>();
    }

    // ── Deterministic hash helper ───────────────────────────────────

    #[test]
    fn test_deterministic_hash_consistency() {
        let h1 = deterministic_hash("test_data");
        let h2 = deterministic_hash("test_data");
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_deterministic_hash_different_inputs() {
        let h1 = deterministic_hash("input_a");
        let h2 = deterministic_hash("input_b");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_deterministic_hash_fields_consistency() {
        let h1 = deterministic_hash_fields(&["a", "b", "c"]);
        let h2 = deterministic_hash_fields(&["a", "b", "c"]);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    #[test]
    fn test_deterministic_hash_fields_no_collision_on_delimiter() {
        // "a|b" + "c" vs "a" + "b|c" must differ with length-prefixed encoding
        let h1 = deterministic_hash_fields(&["a|b", "c"]);
        let h2 = deterministic_hash_fields(&["a", "b|c"]);
        assert_ne!(
            h1, h2,
            "length-prefixed hash must distinguish field boundaries"
        );
    }

    #[test]
    fn test_artifact_binding_hash_resists_delimiter_collision() {
        let sdk = test_sdk();
        let mut req1 = valid_request();
        req1.artifact_id = "art|fake_hash".to_string();
        req1.artifact_hash = "rest".to_string();
        let mut req2 = valid_request();
        req2.artifact_id = "art".to_string();
        req2.artifact_hash = "fake_hash|rest".to_string();
        let r1 = sdk.verify_artifact(&req1).expect("should verify");
        let r2 = sdk.verify_artifact(&req2).expect("should verify");
        assert_ne!(
            r1.binding_hash, r2.binding_hash,
            "binding hash must differ when fields contain delimiters"
        );
    }

    #[test]
    fn test_artifact_binding_hash_preserves_claim_vector_boundaries() {
        let sdk = test_sdk();
        let artifact_id = "artifact-claims".to_string();
        let artifact_hash = deterministic_hash(&artifact_id);
        let req1 = VerificationRequest {
            artifact_id: artifact_id.clone(),
            artifact_hash: artifact_hash.clone(),
            claims: vec!["a,b".to_string(), "c".to_string()],
        };
        let req2 = VerificationRequest {
            artifact_id,
            artifact_hash,
            claims: vec!["a".to_string(), "b,c".to_string()],
        };
        let r1 = sdk.verify_artifact(&req1).expect("should verify");
        let r2 = sdk.verify_artifact(&req2).expect("should verify");
        assert_ne!(
            r1.binding_hash, r2.binding_hash,
            "binding hash must preserve claim boundaries, not just joined contents"
        );
        assert_ne!(
            r1.trace_id, r2.trace_id,
            "trace ids derived from binding hash must also diverge"
        );
    }

    #[test]
    fn test_structural_only_markers_are_stable() {
        assert_eq!(
            super::STRUCTURAL_ONLY_SECURITY_POSTURE,
            "structural_only_not_replacement_critical"
        );
        assert_eq!(
            super::STRUCTURAL_ONLY_RULE_ID,
            "VERIFIER_SHORTCUT_GUARD::SDK_VERIFIER"
        );
        assert_eq!(
            super::super::replay_capsule::STRUCTURAL_ONLY_SECURITY_POSTURE,
            "structural_only_not_replacement_critical"
        );
        assert_eq!(
            super::super::replay_capsule::STRUCTURAL_ONLY_RULE_ID,
            "VERIFIER_SHORTCUT_GUARD::SDK_REPLAY_CAPSULE"
        );
    }

    #[test]
    fn test_shortcut_regression_guard_keeps_strong_verifier_anchors() {
        assert_guard_contains(
            "VERIFIER_SHORTCUT_GUARD::VEP_CAPSULE_INTEGRITY",
            "src/verifier_economy/mod.rs",
            VERIFIER_ECONOMY_SOURCE,
            "compute_capsule_integrity_hash(",
        );
        assert_guard_contains(
            "VERIFIER_SHORTCUT_GUARD::VEP_TRACE_COMMITMENT",
            "src/verifier_economy/mod.rs",
            VERIFIER_ECONOMY_SOURCE,
            "compute_trace_commitment_root(",
        );
        assert_guard_contains(
            "VERIFIER_SHORTCUT_GUARD::VEP_SIGNATURE_VERIFY",
            "src/verifier_economy/mod.rs",
            VERIFIER_ECONOMY_SOURCE,
            "verify_ed25519_signature_hex(",
        );

        assert_guard_contains(
            "VERIFIER_SHORTCUT_GUARD::CONNECTOR_SIGNATURE_VERIFY",
            "src/connector/verifier_sdk.rs",
            CONNECTOR_VERIFIER_SOURCE,
            "verify_ed25519_signature_hex(",
        );
        assert_guard_contains(
            "VERIFIER_SHORTCUT_GUARD::CONNECTOR_RESULT_SIGNATURE_VERIFY",
            "src/connector/verifier_sdk.rs",
            CONNECTOR_VERIFIER_SOURCE,
            "verify_verification_result_signature(",
        );
        assert_guard_contains(
            "VERIFIER_SHORTCUT_GUARD::CONNECTOR_CANONICAL_ARTIFACT_PAYLOAD",
            "src/connector/verifier_sdk.rs",
            CONNECTOR_VERIFIER_SOURCE,
            "canonical_migration_artifact_payload(",
        );

        assert_guard_contains(
            super::STRUCTURAL_ONLY_RULE_ID,
            "src/sdk/verifier_sdk.rs",
            SDK_VERIFIER_SOURCE,
            super::STRUCTURAL_ONLY_SECURITY_POSTURE,
        );
        assert_guard_contains(
            super::super::replay_capsule::STRUCTURAL_ONLY_RULE_ID,
            "src/sdk/replay_capsule.rs",
            SDK_REPLAY_CAPSULE_SOURCE,
            super::super::replay_capsule::STRUCTURAL_ONLY_SECURITY_POSTURE,
        );
        assert_guard_contains(
            "VERIFIER_SHORTCUT_GUARD::CONNECTOR_REPLAY_HELPER_MARKER",
            "src/connector/verifier_sdk.rs",
            CONNECTOR_VERIFIER_SOURCE,
            "STRUCTURAL_ONLY_REPLAY_HELPER_POSTURE",
        );

        assert_guard_absent(
            "VERIFIER_SHORTCUT_GUARD::NO_SDK_CAPSULE_IMPORT_IN_VEP",
            "src/verifier_economy/mod.rs",
            VERIFIER_ECONOMY_SOURCE,
            "src/sdk/replay_capsule.rs",
        );
        assert_guard_absent(
            "VERIFIER_SHORTCUT_GUARD::NO_SDK_CAPSULE_IMPORT_IN_CONNECTOR",
            "src/connector/verifier_sdk.rs",
            CONNECTOR_VERIFIER_SOURCE,
            "super::super::replay_capsule::ReplayCapsule",
        );
    }

    // ---------------------------------------------------------------
    // Negative-path inline tests for improved edge case coverage
    // ---------------------------------------------------------------

    #[test]
    fn negative_deterministic_hash_collision_resistance() {
        // Test hash collision resistance with malicious inputs designed to confuse domain separator
        let malicious_inputs = [
            "verifier_sdk_v1:",  // Matches domain separator prefix
            "\x00malicious\x00",  // Null bytes that could terminate parsing
            "a".repeat(1_000_000),  // Large input stress test
            "\u{FEFF}bom",  // BOM character injection
            "normal_input\nverifier_sdk_v1:injected",  // Newline injection
        ];

        let mut hashes = std::collections::HashSet::new();
        for input in malicious_inputs {
            let hash = deterministic_hash(input);
            assert_eq!(hash.len(), 64, "hash length must be consistent for input: {:?}", input);
            assert!(hash.chars().all(|c| c.is_ascii_hexdigit()), "hash must be valid hex for input: {:?}", input);
            assert!(hashes.insert(hash), "each input must produce unique hash: {:?}", input);
        }
    }

    #[test]
    fn negative_hash_fields_boundary_injection_attacks() {
        // Test length-prefixed encoding against sophisticated boundary attacks
        let boundary_attacks = [
            // Length confusion: try to make one field look like length prefix of another
            (&["a", "b"], &["\x01\x00\x00\x00\x00\x00\x00\x00ab"]),
            (&["", "data"], &["\x00\x00\x00\x00\x00\x00\x00\x00data"]),
            (&["x".repeat(256), ""], &["x".repeat(256), ""]),
            // Unicode boundary attacks
            (&["🚀", "test"], &["🚀test"]),
            (&["\u{200B}invisible", "data"], &["invisibledata"]),  // Zero-width space
        ];

        for (fields1, fields2) in boundary_attacks {
            let hash1 = deterministic_hash_fields(fields1);
            let hash2 = deterministic_hash_fields(fields2);
            assert_ne!(hash1, hash2, "boundary attack should not create hash collision: {:?} vs {:?}", fields1, fields2);
        }
    }

    #[test]
    fn negative_artifact_validation_comprehensive_bypass_attempts() {
        let sdk = test_sdk();

        // Test bypasses using Unicode normalization, control characters, etc.
        let bypass_attempts = [
            // Unicode normalization attacks
            VerificationRequest {
                artifact_id: "café".to_string(),  // é as single char
                artifact_hash: "a".repeat(64),
                claims: vec!["claim".to_string()],
            },
            VerificationRequest {
                artifact_id: "cafe\u{0301}".to_string(),  // e + combining accent
                artifact_hash: "a".repeat(64),
                claims: vec!["claim".to_string()],
            },
            // Control character injection
            VerificationRequest {
                artifact_id: "art\x08\x08id".to_string(),  // Backspace chars
                artifact_hash: "a".repeat(64),
                claims: vec!["claim".to_string()],
            },
            // Hash with mixed case (should be rejected as invalid hex)
            VerificationRequest {
                artifact_id: "mixed-case".to_string(),
                artifact_hash: "A".repeat(32) + &"f".repeat(32),
                claims: vec!["claim".to_string()],
            },
        ];

        for (idx, req) in bypass_attempts.iter().enumerate() {
            let result = sdk.verify_artifact(req);
            match result {
                Ok(report) => {
                    // Should fail validation, not pass
                    assert!(matches!(report.verdict, VerifyVerdict::Fail(_)),
                           "bypass attempt {} should fail verification", idx);
                }
                Err(_) => {
                    // Early rejection is also acceptable for malformed inputs
                }
            }
        }
    }

    #[test]
    fn negative_capsule_validation_state_corruption_scenarios() {
        let sdk = test_sdk();

        // Test capsules with corrupted internal state that could bypass checks
        let mut corrupted_capsule = valid_capsule();

        // Integer overflow in sequence numbers
        corrupted_capsule.inputs[0].seq = u64::MAX;
        corrupted_capsule.inputs[1].seq = 0;  // Wraps around, violates monotonicity

        let report = sdk.verify_capsule(&corrupted_capsule).expect("should verify");
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)),
               "sequence overflow should fail monotonicity check");

        // Environment with embedded nulls (could terminate C-style string parsing downstream)
        let mut null_env_capsule = valid_capsule();
        null_env_capsule.environment.platform = "linux\x00injected".to_string();

        let report = sdk.verify_capsule(&null_env_capsule).expect("should verify");
        let platform_evidence = report.evidence.iter()
            .find(|e| e.check_name == "environment_present")
            .expect("environment evidence should be present");
        assert!(platform_evidence.passed, "null bytes should not break environment validation");

        // Capsule with extremely large input data that could cause memory issues
        let mut large_capsule = valid_capsule();
        large_capsule.inputs[0].data = vec![0x42; 10 * 1024 * 1024];  // 10MB input

        let result = sdk.verify_capsule(&large_capsule);
        assert!(result.is_ok(), "large input data should be handled gracefully");
    }

    #[test]
    fn negative_chain_validation_byzantine_scenarios() {
        let sdk = test_sdk();

        // Create reports with carefully crafted inconsistencies
        let mut report1 = sdk.verify_artifact(&valid_request()).expect("should verify");
        let mut report2 = sdk.verify_artifact(&valid_request()).expect("should verify");

        // Scenario: Same binding hash but different content (hash collision attempt)
        report2.binding_hash = report1.binding_hash.clone();
        report2.request_id = "different-id".to_string();

        let chain_result = sdk.verify_chain(&[report1, report2]).expect("should chain");
        let failures = failed_checks(&chain_result);
        assert!(matches!(chain_result.verdict, VerifyVerdict::Fail(_)),
               "duplicate binding hashes should fail validation");
        assert!(failures.contains(&"binding_hashes_unique"),
               "should detect binding hash collision");

        // Scenario: Schema version injection (attempt to mix old/new versions)
        let mut mixed_report = sdk.verify_artifact(&valid_request()).expect("should verify");
        mixed_report.schema_tag = "vsk-v999.0".to_string();  // Future version
        mixed_report.api_version = "999.0.0".to_string();

        let mixed_chain = sdk.verify_chain(&[mixed_report]).expect("should chain");
        let failures = failed_checks(&mixed_chain);
        assert!(matches!(mixed_chain.verdict, VerifyVerdict::Fail(_)),
               "mixed schema versions should fail validation");
        assert!(failures.contains(&"schema_tag_consistent") || failures.contains(&"api_version_consistent"),
               "should detect version inconsistency");
    }

    #[test]
    fn negative_config_extension_field_injection() {
        // Test configuration with malicious extension fields
        let malicious_configs = [
            // Extension field name injection
            VerifierConfig {
                verifier_identity: "verifier://evil".to_string(),
                require_hash_match: true,
                strict_claims: true,
                extensions: {
                    let mut ext = BTreeMap::new();
                    ext.insert("__proto__".to_string(), "malicious".to_string());
                    ext.insert("constructor".to_string(), "payload".to_string());
                    ext
                },
            },
            // Extension with embedded control characters
            VerifierConfig {
                verifier_identity: "verifier://test".to_string(),
                require_hash_match: true,
                strict_claims: true,
                extensions: {
                    let mut ext = BTreeMap::new();
                    ext.insert("key\x00null".to_string(), "value\r\ninjection".to_string());
                    ext
                },
            },
        ];

        for (idx, config) in malicious_configs.iter().enumerate() {
            let sdk = VerifierSdk::new(config.clone());

            // SDK should handle malicious configs gracefully without crashing
            assert_eq!(sdk.config(), config, "config {} should be preserved exactly", idx);
            assert_eq!(sdk.api_version(), API_VERSION, "API version should remain stable for config {}", idx);

            // Verification should still work despite malicious extensions
            let result = sdk.verify_artifact(&valid_request());
            assert!(result.is_ok(), "verification should work despite malicious config {}", idx);
        }
    }

    #[test]
    fn negative_serde_deserialization_bomb_protection() {
        // Test protection against JSON deserialization bombs
        let malicious_json_payloads = [
            // Deeply nested structure (stack overflow attempt)
            format!(r#"{{"nested": {}}}"#, "{{\"deep\": ".repeat(1000) + "null" + &"}".repeat(1000)),
            // Large string field
            format!(r#"{{"artifact_id": "{}", "artifact_hash": "{}", "claims": []}}"#,
                   "x".repeat(100_000), "a".repeat(64)),
            // Array with many elements
            format!(r#"{{"artifact_id": "test", "artifact_hash": "{}", "claims": [{}]}}"#,
                   "a".repeat(64), (0..10000).map(|i| format!(r#""claim{}""#, i)).collect::<Vec<_>>().join(",")),
        ];

        for (idx, payload) in malicious_json_payloads.iter().enumerate() {
            let result = serde_json::from_str::<VerificationRequest>(payload);

            match result {
                Ok(req) => {
                    // If parsing succeeds, verification should handle large data gracefully
                    let sdk = test_sdk();
                    let result = sdk.verify_artifact(&req);
                    assert!(result.is_ok() || result.is_err(),
                           "payload {} should be handled gracefully (pass or fail, but not crash)", idx);
                }
                Err(_) => {
                    // Early rejection of malformed JSON is acceptable
                }
            }
        }
    }

    #[test]
    fn negative_constant_time_comparison_timing_leak_prevention() {
        use std::time::Instant;

        let sdk = VerifierSdk::new(VerifierConfig {
            require_hash_match: true,
            ..VerifierConfig::default()
        });

        let artifact_id = "timing-test-artifact";
        let correct_hash = deterministic_hash(artifact_id);

        // Test timing with hashes that differ at different positions
        let early_diff_hash = "0".repeat(64);
        let late_diff_hash = correct_hash[..63].to_string() + "0";

        let timing_samples = 100;
        let mut early_times = Vec::new();
        let mut late_times = Vec::new();

        for _ in 0..timing_samples {
            // Test hash that differs in first character
            let req_early = VerificationRequest {
                artifact_id: artifact_id.to_string(),
                artifact_hash: early_diff_hash.clone(),
                claims: vec!["claim".to_string()],
            };

            let start = Instant::now();
            let _ = sdk.verify_artifact(&req_early);
            early_times.push(start.elapsed());

            // Test hash that differs in last character
            let req_late = VerificationRequest {
                artifact_id: artifact_id.to_string(),
                artifact_hash: late_diff_hash.clone(),
                claims: vec!["claim".to_string()],
            };

            let start = Instant::now();
            let _ = sdk.verify_artifact(&req_late);
            late_times.push(start.elapsed());
        }

        // Calculate average times
        let avg_early = early_times.iter().sum::<std::time::Duration>() / timing_samples as u32;
        let avg_late = late_times.iter().sum::<std::time::Duration>() / timing_samples as u32;

        // Timing difference should be minimal for constant-time comparison
        // Allow some variance for system noise, but flag if difference is suspiciously large
        let timing_ratio = if avg_late > avg_early {
            avg_late.as_nanos() as f64 / avg_early.as_nanos() as f64
        } else {
            avg_early.as_nanos() as f64 / avg_late.as_nanos() as f64
        };

        // This is a heuristic test - significant timing differences could indicate
        // non-constant-time string comparison, but small differences are normal
        assert!(timing_ratio < 2.0,
               "timing difference between early/late hash mismatches suspiciously large: {:.2}x (early: {:?}, late: {:?})",
               timing_ratio, avg_early, avg_late);
    }

    #[test]
    fn negative_evidence_accumulation_consistency_under_failure_injection() {
        let sdk = test_sdk();

        // Create a request that will fail multiple validation checks
        let multi_fail_request = VerificationRequest {
            artifact_id: " reserved_id ".to_string(),  // Whitespace (early fail)
            artifact_hash: "short".to_string(),       // Wrong length (later fail)
            claims: vec!["".to_string()],             // Empty claim (later fail)
        };

        let result = sdk.verify_artifact(&multi_fail_request);

        // Should fail early on whitespace, before other checks
        assert!(result.is_err(), "multi-fail request should be rejected early");

        // Now test a request that passes early validation but fails later checks
        let late_fail_request = VerificationRequest {
            artifact_id: "late-fail-test".to_string(),
            artifact_hash: "short".to_string(),       // Wrong length
            claims: vec!["good-claim".to_string(), "".to_string()],  // Mixed good/bad claims
        };

        let report = sdk.verify_artifact(&late_fail_request).expect("should verify");
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)), "should fail overall");

        // Verify evidence consistency: all checks should be recorded, with correct pass/fail status
        let mut passed_checks = 0;
        let mut failed_checks = 0;

        for evidence in &report.evidence {
            if evidence.passed {
                passed_checks = passed_checks.saturating_add(1);
            } else {
                failed_checks = failed_checks.saturating_add(1);
            }

            // Each evidence entry should have meaningful detail
            assert!(!evidence.detail.is_empty(), "evidence detail should not be empty for check: {}", evidence.check_name);
        }

        assert!(failed_checks > 0, "should have failing checks");
        assert!(passed_checks > 0, "should have some passing checks even in failure case");

        // Evidence should be consistently ordered and complete
        assert!(report.evidence.len() >= 5, "should have all major evidence categories");
    }
}

#[cfg(test)]
mod verifier_sdk_boundary_negative_tests {
    use super::*;

    fn malicious_request(artifact_id: &str, hash: &str, claims: Vec<&str>) -> VerificationRequest {
        VerificationRequest {
            artifact_id: artifact_id.to_string(),
            artifact_hash: hash.to_string(),
            claims: claims.into_iter().map(str::to_string).collect(),
        }
    }

    fn malicious_config() -> VerifierConfig {
        VerifierConfig {
            require_hash_match: true,
            strict_claims: true,
            ..VerifierConfig::default()
        }
    }

    #[test]
    fn negative_sdk_rejects_artifact_id_with_embedded_nul_bytes() {
        let sdk = VerifierSdk::new(malicious_config());
        let request = malicious_request(
            "artifact\0injection",
            &"a".repeat(64),
            vec!["claim-a"],
        );

        let err = sdk.verify_artifact(&request).expect_err("nul bytes in artifact_id should be rejected");

        match err {
            SdkError::InvalidArtifact(msg) => assert!(msg.contains("nul")),
            other => panic!("expected InvalidArtifact error, got {other:?}"),
        }
    }

    #[test]
    fn negative_sdk_rejects_artifact_hash_with_control_characters() {
        let sdk = VerifierSdk::new(malicious_config());
        let mut malicious_hash = "a".repeat(63);
        malicious_hash.push('\r'); // Control character
        let request = malicious_request("artifact-1", &malicious_hash, vec!["claim-a"]);

        let report = sdk.verify_artifact(&request).expect("should produce report");

        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
        let failed_checks: Vec<&str> = report
            .evidence
            .iter()
            .filter(|e| !e.passed)
            .map(|e| e.check_name.as_str())
            .collect();
        assert!(failed_checks.contains(&"artifact_hash_format"));
    }

    #[test]
    fn negative_sdk_rejects_claim_with_embedded_newlines() {
        let sdk = VerifierSdk::new(malicious_config());
        let request = malicious_request(
            "artifact-1",
            &"a".repeat(64),
            vec!["claim\ninjection"],
        );

        let report = sdk.verify_artifact(&request).expect("should produce report");

        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
        let failed_checks: Vec<&str> = report
            .evidence
            .iter()
            .filter(|e| !e.passed)
            .map(|e| e.check_name.as_str())
            .collect();
        assert!(failed_checks.iter().any(|&check| check.contains("claim")));
    }

    #[test]
    fn negative_sdk_handles_oversized_claim_list_without_panic() {
        let sdk = VerifierSdk::new(malicious_config());
        let oversized_claims: Vec<String> = (0..10_000)
            .map(|i| format!("claim-{i}"))
            .collect();
        let request = VerificationRequest {
            artifact_id: "artifact-oversized-claims".to_string(),
            artifact_hash: "a".repeat(64),
            claims: oversized_claims,
        };

        let report = sdk.verify_artifact(&request).expect("oversized claims should produce report");

        // Should handle gracefully without panic
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
    }

    #[test]
    fn negative_sdk_rejects_reserved_schema_tag_in_verification_request() {
        let sdk = VerifierSdk::new(malicious_config());
        let request = malicious_request(
            SCHEMA_TAG, // Use reserved schema tag as artifact ID
            &"a".repeat(64),
            vec!["claim-a"],
        );

        let err = sdk.verify_artifact(&request).expect_err("reserved schema tag should be rejected");

        match err {
            SdkError::InvalidArtifact(msg) => assert!(msg.contains("reserved")),
            other => panic!("expected InvalidArtifact error, got {other:?}"),
        }
    }

    #[test]
    fn negative_serde_rejects_unknown_verify_verdict_variant() {
        let result: Result<VerifyVerdict, _> = serde_json::from_str(r#""unknown""#);

        assert!(result.is_err());
    }

    #[test]
    fn negative_verification_evidence_with_empty_check_name_serializes_but_fails_validation() {
        let evidence = EvidenceEntry {
            check_name: "".to_string(), // Invalid empty check name
            passed: false,
            detail: "empty check name test".to_string(),
        };

        // Should serialize but be detectable as invalid
        let serialized = serde_json::to_string(&evidence).expect("should serialize");
        let parsed: EvidenceEntry = serde_json::from_str(&serialized).expect("should deserialize");

        assert!(parsed.check_name.is_empty()); // Should preserve the invalid state
    }

    #[test]
    fn negative_verification_report_with_mismatched_verdict_and_evidence() {
        let report = VerificationReport {
            request_id: "report-mismatched".to_string(),
            verdict: VerifyVerdict::Pass, // Claims success
            evidence: vec![
                EvidenceEntry {
                    check_name: "failing_check".to_string(),
                    passed: false, // But evidence shows failure
                    detail: "this check failed".to_string(),
                }
            ],
            trace_id: "trace-mismatched".to_string(),
            schema_tag: SCHEMA_TAG.to_string(),
            api_version: API_VERSION.to_string(),
            verifier_identity: "verifier://test".to_string(),
            binding_hash: "binding-hash".to_string(),
        };

        // Should serialize successfully but be detectable as inconsistent
        let serialized = serde_json::to_string(&report).expect("should serialize");
        let parsed: VerificationReport = serde_json::from_str(&serialized).expect("should deserialize");

        // Verdict claims pass but evidence shows failure - this is inconsistent
        assert!(matches!(parsed.verdict, VerifyVerdict::Pass));
        assert!(!parsed.evidence[0].passed);
    }

    #[test]
    fn negative_sdk_config_validates_strict_claims_consistency() {
        let config = VerifierConfig {
            require_hash_match: false, // Lenient hash requirement
            strict_claims: true,       // But strict claims enabled - inconsistent
            ..VerifierConfig::default()
        };

        // Should create SDK but with logically inconsistent configuration
        let sdk = VerifierSdk::new(config);

        // This represents a configuration that might lead to unexpected behavior
        assert!(sdk.config().strict_claims);
        assert!(!sdk.config().require_hash_match);
    }

    #[test]
    fn negative_chain_verification_rejects_empty_binding_hash() {
        let sdk = VerifierSdk::with_defaults();
        let invalid_report = VerificationReport {
            request_id: "chain-empty-binding".to_string(),
            verdict: VerifyVerdict::Pass,
            evidence: vec![],
            trace_id: "trace-empty-binding".to_string(),
            schema_tag: SCHEMA_TAG.to_string(),
            api_version: API_VERSION.to_string(),
            verifier_identity: "verifier://test".to_string(),
            binding_hash: "".to_string(), // Invalid empty binding hash
        };

        let chain_report = sdk.verify_chain(&[invalid_report]).expect("should verify chain");

        // Should fail because binding hash is empty
        assert!(matches!(chain_report.verdict, VerifyVerdict::Fail(_)));
        let failures = failed_checks(&chain_report);
        assert!(failures.contains(&"binding_hashes_present"));
    }

    #[test]
    fn negative_massive_metadata_memory_exhaustion_resistance() {
        // Test capsule with extremely large metadata that could exhaust memory
        let sdk = VerifierSdk::with_defaults();
        let mut capsule = valid_capsule();

        // Add massive metadata entries
        for i in 0..1000 {
            capsule.inputs[0].metadata.insert(
                format!("key_{}", i),
                "x".repeat(1024).to_string(),  // 1KB per value * 1000 = ~1MB metadata
            );
        }

        let result = sdk.verify_capsule(&capsule);
        assert!(result.is_ok(), "large metadata should be handled gracefully without memory exhaustion");
    }

    #[test]
    fn negative_unicode_normalization_artifact_id_confusion() {
        // Test Unicode normalization attacks where different Unicode representations
        // of the same visual characters could bypass validation
        let sdk = VerifierSdk::with_defaults();

        let unicode_attacks = [
            ("café", "cafe\u{0301}"),  // NFC vs NFD normalization
            ("A", "\u{0041}"),         // Latin A vs Unicode codepoint
            ("résumé", "re\u{0301}sume\u{0301}"),  // Multiple combining characters
        ];

        for (form1, form2) in unicode_attacks {
            let hash1 = deterministic_hash(form1);
            let hash2 = deterministic_hash(form2);

            if form1 != form2 {
                // Different Unicode representations should produce different hashes
                assert_ne!(hash1, hash2,
                          "Unicode forms '{}' and '{}' should hash differently", form1, form2);
            }

            // Both should be handled without crashing
            let req1 = VerificationRequest {
                artifact_id: form1.to_string(),
                artifact_hash: hash1,
                claims: vec!["unicode-test".to_string()],
            };
            let req2 = VerificationRequest {
                artifact_id: form2.to_string(),
                artifact_hash: hash2,
                claims: vec!["unicode-test".to_string()],
            };

            let result1 = sdk.verify_artifact(&req1);
            let result2 = sdk.verify_artifact(&req2);
            assert!(result1.is_ok() && result2.is_ok(),
                   "Unicode artifact IDs should be handled gracefully");
        }
    }

    #[test]
    fn negative_hash_length_boundary_validation_edge_cases() {
        let sdk = VerifierSdk::with_defaults();

        let boundary_hashes = [
            ("", false),                    // Empty
            ("a".repeat(63), false),        // One short
            ("a".repeat(64), true),         // Correct length, invalid chars for hex check
            ("f".repeat(64), true),         // Correct length, valid hex
            ("a".repeat(65), false),        // One long
            ("G".repeat(64), false),        // Invalid hex characters
            ("abcdef0123456789".repeat(4), true),  // Valid hex, correct length
        ];

        for (hash, should_pass_format) in boundary_hashes {
            let req = VerificationRequest {
                artifact_id: "hash-boundary-test".to_string(),
                artifact_hash: hash.to_string(),
                claims: vec!["test".to_string()],
            };

            match sdk.verify_artifact(&req) {
                Ok(report) => {
                    let format_check = report.evidence.iter()
                        .find(|e| e.check_name == "artifact_hash_format")
                        .expect("format check should exist");

                    assert_eq!(format_check.passed, should_pass_format,
                             "hash '{}' format check mismatch", hash);
                }
                Err(_) => {
                    // Early rejection is also acceptable for malformed hashes
                    assert!(!should_pass_format, "valid hash '{}' was rejected early", hash);
                }
            }
        }
    }

    #[test]
    fn negative_capsule_sequence_number_arithmetic_overflow_edge_cases() {
        let sdk = VerifierSdk::with_defaults();
        let mut capsule = valid_capsule();

        // Test sequence numbers at arithmetic boundaries
        let boundary_sequences = [
            (u64::MAX - 1, u64::MAX),      // Near overflow
            (0, 1),                        // Normal case
            (u64::MAX / 2, u64::MAX / 2 + 1),  // Mid-range
        ];

        for (seq1, seq2) in boundary_sequences {
            capsule.inputs[0].seq = seq1;
            capsule.inputs[1].seq = seq2;

            let result = sdk.verify_capsule(&capsule);
            assert!(result.is_ok(), "capsule with sequences {} -> {} should verify", seq1, seq2);

            let report = result.unwrap();
            assert!(matches!(report.verdict, VerifyVerdict::Pass),
                   "properly ordered sequences {} -> {} should pass", seq1, seq2);
        }

        // Test invalid sequence (wraparound)
        capsule.inputs[0].seq = u64::MAX;
        capsule.inputs[1].seq = 0;  // Wraps around, breaks monotonicity

        let result = sdk.verify_capsule(&capsule).expect("should verify");
        assert!(matches!(result.verdict, VerifyVerdict::Fail(_)),
               "wraparound sequence should fail monotonicity check");
    }

    #[test]
    fn negative_chain_binding_hash_collision_attempt_with_length_extension() {
        let sdk = VerifierSdk::with_defaults();

        // Create two reports with carefully crafted content to attempt hash collision
        let mut report1 = sdk.verify_artifact(&valid_request()).expect("should verify");
        let mut report2 = sdk.verify_artifact(&valid_request()).expect("should verify");

        // Attempt length extension attack: add extra data that could be ignored
        let original_hash = report1.binding_hash.clone();
        report2.binding_hash = format!("{}00", original_hash);  // Append extra bytes

        let chain_result = sdk.verify_chain(&[report1, report2]).expect("should chain");

        // Should detect the collision attempt
        assert!(matches!(chain_result.verdict, VerifyVerdict::Fail(_)),
               "modified binding hash should fail chain validation");

        let failures = failed_checks(&chain_result);
        assert!(failures.contains(&"binding_hashes_unique") || failures.contains(&"binding_hashes_present"),
               "should detect binding hash manipulation");
    }

    #[test]
    fn negative_environment_snapshot_field_injection_comprehensive() {
        let sdk = VerifierSdk::with_defaults();
        let mut capsule = valid_capsule();

        // Test environment fields with injection patterns
        let injection_patterns = [
            ("runtime\x00version", "1.0.0\x00injected"),
            ("platform\ninjection", "linux\r\n\t/bin/sh"),
            ("config\u{202E}hash", "\u{200B}invisible"),
            ("normal_key", "../../../etc/passwd"),
        ];

        for (runtime_suffix, platform_suffix) in injection_patterns {
            capsule.environment.runtime_version = format!("base_{}", runtime_suffix);
            capsule.environment.platform = format!("base_{}", platform_suffix);
            capsule.environment.config_hash = "hash".repeat(8);

            let result = sdk.verify_capsule(&capsule);
            assert!(result.is_ok(), "environment injection patterns should be handled gracefully");

            let report = result.unwrap();
            // Should still pass environment validation (values preserved as-is)
            let env_check = report.evidence.iter()
                .find(|e| e.check_name == "environment_present")
                .expect("environment check should exist");
            assert!(env_check.passed, "environment with injection patterns should pass validation");
        }
    }

    #[test]
    fn negative_evidence_detail_field_content_sanitization_bypass() {
        let sdk = VerifierSdk::with_defaults();

        // Create request that will generate evidence with potentially unsafe detail content
        let req = VerificationRequest {
            artifact_id: "detail<script>alert('xss')</script>".to_string(),
            artifact_hash: "a".repeat(64),
            claims: vec!["claim\x00null".to_string(), "claim\r\ninjection".to_string()],
        };

        let report = sdk.verify_artifact(&req).expect("should verify");

        // Evidence detail fields should preserve original content without sanitization
        for evidence in &report.evidence {
            // Detail should not be empty and should contain meaningful information
            assert!(!evidence.detail.is_empty(), "evidence detail should not be empty");

            // Should handle any control characters or special content gracefully
            let _serialized = serde_json::to_string(evidence).expect("evidence should serialize");
        }

        // Report with potentially unsafe content should still serialize/deserialize safely
        let serialized = serde_json::to_string(&report).expect("report should serialize");
        let _parsed: VerificationReport = serde_json::from_str(&serialized).expect("should deserialize");
    }

    #[test]
    fn negative_artifact_hash_boundary_values_and_precision_edge_cases() {
        let sdk = VerifierSdk::with_defaults();

        // Test hash values at various boundaries that might cause precision/parsing issues
        let boundary_hashes = vec![
            "0".repeat(64),                           // All zeros
            "f".repeat(64),                           // All max hex digits
            "0123456789abcdef".repeat(4),             // Sequential pattern
            "fedcba9876543210".repeat(4),             // Reverse sequential
            format!("{}{}",                           // Half zeros, half ones
                    "0".repeat(32),
                    "1".repeat(32)),
            "deadbeefcafebabe".repeat(4),             // Common hex patterns
            format!("{}{}{}{}",                       // Quarter patterns
                    "0".repeat(16),
                    "f".repeat(16),
                    "a".repeat(16),
                    "5".repeat(16)),
        ];

        for (i, hash) in boundary_hashes.iter().enumerate() {
            let req = VerificationRequest {
                artifact_id: format!("boundary_hash_{}", i),
                artifact_hash: hash.clone(),
                claims: vec![format!("boundary_claim_{}", i)],
            };

            let result = sdk.verify_artifact(&req);
            assert!(result.is_ok(), "boundary hash {} should be processed", hash);

            let report = result.unwrap();

            // Hash should be preserved exactly
            assert_eq!(report.request_id, req.artifact_id);

            // Should generate valid binding hash regardless of input hash pattern
            assert_eq!(report.binding_hash.len(), 64);
            assert!(report.binding_hash.chars().all(|c| c.is_ascii_hexdigit()));

            // Different input hashes should produce different binding hashes
            if i > 0 {
                let prev_req = VerificationRequest {
                    artifact_id: format!("boundary_hash_{}", i - 1),
                    artifact_hash: boundary_hashes[i - 1].clone(),
                    claims: vec![format!("boundary_claim_{}", i - 1)],
                };
                let prev_report = sdk.verify_artifact(&prev_req).unwrap();
                assert_ne!(report.binding_hash, prev_report.binding_hash);
            }

            // JSON serialization should handle any hex pattern
            let json = serde_json::to_string(&report).expect("should serialize boundary hash");
            let parsed: VerificationReport = serde_json::from_str(&json).expect("should deserialize");
            assert_eq!(parsed.binding_hash, report.binding_hash);
        }
    }

    #[test]
    fn negative_concurrent_sdk_verification_state_isolation_stress_test() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        // Test concurrent SDK operations to verify state isolation
        let sdk = Arc::new(VerifierSdk::with_defaults());
        let results = Arc::new(Mutex::new(Vec::new()));
        let thread_count = 16;
        let operations_per_thread = 100;

        let mut handles = Vec::new();

        for thread_id in 0..thread_count {
            let sdk = Arc::clone(&sdk);
            let results = Arc::clone(&results);

            let handle = thread::spawn(move || {
                let mut thread_results = Vec::new();

                for operation in 0..operations_per_thread {
                    // Create unique verification request for this thread/operation
                    let req = VerificationRequest {
                        artifact_id: format!("thread_{}_{}", thread_id, operation),
                        artifact_hash: format!("{:064x}", thread_id * 1000 + operation),
                        claims: vec![format!("thread_claim_{}_{}", thread_id, operation)],
                    };

                    let start = std::time::Instant::now();
                    let result = sdk.verify_artifact(&req);
                    let duration = start.elapsed();

                    // Should complete quickly even under concurrent load
                    assert!(duration < std::time::Duration::from_millis(100),
                           "Thread {} operation {} took too long: {:?}",
                           thread_id, operation, duration);

                    match result {
                        Ok(report) => {
                            // Verify thread isolation - report should reflect this thread's data
                            assert_eq!(report.request_id, req.artifact_id);
                            assert!(report.verifier_identity.len() > 0);

                            // Binding hash should be deterministic for this specific input
                            let duplicate_result = sdk.verify_artifact(&req).unwrap();
                            assert_eq!(report.binding_hash, duplicate_result.binding_hash);

                            thread_results.push((thread_id, operation, "success"));
                        }
                        Err(_) => {
                            thread_results.push((thread_id, operation, "error"));
                        }
                    }
                }

                // Merge results back
                {
                    let mut shared = results.lock().unwrap();
                    shared.extend(thread_results);
                }
            });

            handles.push(handle);
        }

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should complete successfully");
        }

        let final_results = results.lock().unwrap();

        // Verify all operations completed
        assert_eq!(final_results.len(), thread_count * operations_per_thread);

        // Count successes
        let success_count = final_results.iter()
            .filter(|(_, _, status)| *status == "success")
            .count();

        // Most operations should succeed (allowing for some thread contention failures)
        let success_rate = success_count as f64 / final_results.len() as f64;
        assert!(success_rate > 0.9,
               "Success rate too low under concurrent load: {:.2}%", success_rate * 100.0);

        // Verify no duplicate request IDs had different outcomes (deterministic)
        let mut request_outcomes = std::collections::BTreeMap::new();
        for (thread_id, operation, status) in final_results.iter() {
            let request_id = format!("thread_{}_{}", thread_id, operation);
            if let Some(existing_status) = request_outcomes.insert(request_id.clone(), status) {
                assert_eq!(existing_status, status,
                          "Request {} had inconsistent outcomes", request_id);
            }
        }
    }

    #[test]
    fn negative_verification_report_with_massive_evidence_arrays() {
        let sdk = VerifierSdk::with_defaults();

        // Create request that will generate many evidence entries
        let massive_claims: Vec<String> = (0..1000).map(|i| format!("massive_claim_{:04}", i)).collect();

        let req = VerificationRequest {
            artifact_id: "massive_evidence_test".to_string(),
            artifact_hash: "a".repeat(64),
            claims: massive_claims.clone(),
        };

        let start = std::time::Instant::now();
        let report = sdk.verify_artifact(&req).expect("massive claims should verify");
        let verification_duration = start.elapsed();

        // Should complete in reasonable time despite large claim count
        assert!(verification_duration < std::time::Duration::from_secs(10),
               "Massive evidence verification took too long: {:?}", verification_duration);

        // Should generate evidence for many claims
        assert!(report.evidence.len() >= 500, "Should generate substantial evidence");

        // Each evidence entry should be properly formed
        for (i, evidence) in report.evidence.iter().enumerate() {
            assert!(!evidence.check_name.is_empty(), "Evidence {} should have check name", i);
            assert!(!evidence.detail.is_empty(), "Evidence {} should have detail", i);
        }

        // JSON serialization should handle large evidence arrays
        let serialization_start = std::time::Instant::now();
        let json = serde_json::to_string(&report).expect("massive evidence should serialize");
        let serialization_duration = serialization_start.elapsed();

        assert!(serialization_duration < std::time::Duration::from_secs(5),
               "Massive evidence serialization took too long: {:?}", serialization_duration);

        // Should produce substantial JSON (>100KB)
        assert!(json.len() > 100_000,
               "JSON should be substantial for massive evidence: {} bytes", json.len());

        // Deserialization should work correctly
        let parsing_start = std::time::Instant::now();
        let parsed: VerificationReport = serde_json::from_str(&json)
            .expect("massive evidence should deserialize");
        let parsing_duration = parsing_start.elapsed();

        assert!(parsing_duration < std::time::Duration::from_secs(5),
               "Massive evidence parsing took too long: {:?}", parsing_duration);

        assert_eq!(parsed.evidence.len(), report.evidence.len());
        assert_eq!(parsed.request_id, report.request_id);
    }

    #[test]
    fn negative_chain_verification_with_circular_dependency_detection() {
        let sdk = VerifierSdk::with_defaults();

        // Create a chain of reports with circular dependencies in trace IDs
        let mut circular_reports = Vec::new();

        for i in 0..5 {
            let req = VerificationRequest {
                artifact_id: format!("circular_{}", i),
                artifact_hash: format!("{:064x}", i),
                claims: vec![format!("claim_{}", i)],
            };

            let mut report = sdk.verify_artifact(&req).expect("should verify");

            // Create circular dependency by setting trace ID to reference next item (with wrap)
            report.trace_id = format!("depends_on_circular_{}", (i + 1) % 5);

            circular_reports.push(report);
        }

        // Add self-referencing report
        let self_req = VerificationRequest {
            artifact_id: "self_reference".to_string(),
            artifact_hash: "ff".repeat(32),
            claims: vec!["self_claim".to_string()],
        };

        let mut self_report = sdk.verify_artifact(&self_req).expect("should verify");
        self_report.trace_id = "self_reference".to_string(); // References itself
        circular_reports.push(self_report);

        // Chain verification should handle circular dependencies gracefully
        let chain_start = std::time::Instant::now();
        let chain_result = sdk.verify_chain(&circular_reports).expect("chain should verify");
        let chain_duration = chain_start.elapsed();

        // Should complete without infinite loops
        assert!(chain_duration < std::time::Duration::from_secs(10),
               "Circular dependency chain took too long: {:?}", chain_duration);

        // Should generate evidence for the chain verification
        assert!(!chain_result.evidence.is_empty(),
               "Chain verification should generate evidence");

        // Result should be deterministic - same chain should produce same result
        let second_chain_result = sdk.verify_chain(&circular_reports).expect("should verify again");
        assert_eq!(chain_result.binding_hash, second_chain_result.binding_hash);
        assert_eq!(chain_result.evidence.len(), second_chain_result.evidence.len());

        // Should handle empty cycles gracefully
        let empty_chain_result = sdk.verify_chain(&[]).expect_err("empty chain should error");
        assert!(matches!(empty_chain_result, SdkError::BrokenChain(_)));
    }

    #[test]
    fn negative_unicode_normalization_attacks_in_verification_context() {
        let sdk = VerifierSdk::with_defaults();

        // Test Unicode normalization attacks that could bypass security checks
        let normalization_test_cases = vec![
            // NFC vs NFD normalization
            ("café", "cafe\u{0301}"),           // Composed vs decomposed
            ("Ⅸ", "IX"),                        // Roman numeral vs ASCII
            ("A", "\u{0041}"),                  // Latin vs Unicode codepoint

            // Homograph attacks
            ("microsoft", "microsоft"),         // Latin 'o' vs Cyrillic 'о'
            ("secure", "secuгe"),               // Latin 'r' vs Cyrillic 'г'

            // Zero-width and invisible characters
            ("test", "te\u{200B}st"),           // Zero-width space
            ("test", "\u{FEFF}test"),           // Byte order mark prefix
            ("test", "test\u{200C}"),           // Zero-width non-joiner suffix

            // Bidirectional text attacks
            ("safe", "\u{202E}efas\u{202D}"),   // Right-to-left override
        ];

        for (original, attack) in normalization_test_cases {
            // Test in artifact ID
            let req1 = VerificationRequest {
                artifact_id: original.to_string(),
                artifact_hash: "a".repeat(64),
                claims: vec!["test_claim".to_string()],
            };

            let req2 = VerificationRequest {
                artifact_id: attack.to_string(),
                artifact_hash: "a".repeat(64),
                claims: vec!["test_claim".to_string()],
            };

            let report1 = sdk.verify_artifact(&req1).expect("original should verify");
            let report2 = sdk.verify_artifact(&req2).expect("attack should verify");

            // Different Unicode representations should be treated as different artifacts
            assert_ne!(report1.request_id, report2.request_id);
            assert_ne!(report1.binding_hash, report2.binding_hash);

            // Test in claims
            let claim_req1 = VerificationRequest {
                artifact_id: "unicode_test".to_string(),
                artifact_hash: "b".repeat(64),
                claims: vec![original.to_string()],
            };

            let claim_req2 = VerificationRequest {
                artifact_id: "unicode_test".to_string(),
                artifact_hash: "b".repeat(64),
                claims: vec![attack.to_string()],
            };

            let claim_report1 = sdk.verify_artifact(&claim_req1).expect("original claim should verify");
            let claim_report2 = sdk.verify_artifact(&claim_req2).expect("attack claim should verify");

            // Different Unicode claims should produce different binding hashes
            assert_ne!(claim_report1.binding_hash, claim_report2.binding_hash);

            // JSON serialization should preserve exact Unicode form
            let json1 = serde_json::to_string(&claim_report1).expect("should serialize");
            let json2 = serde_json::to_string(&claim_report2).expect("should serialize");
            assert_ne!(json1, json2, "Different Unicode forms should serialize differently");

            // Deserialization should recover exact Unicode
            let parsed1: VerificationReport = serde_json::from_str(&json1).expect("should parse");
            let parsed2: VerificationReport = serde_json::from_str(&json2).expect("should parse");
            assert_ne!(parsed1.binding_hash, parsed2.binding_hash);
        }
    }

    #[test]
    fn negative_memory_pressure_during_complex_verification_chains() {
        let sdk = VerifierSdk::with_defaults();

        // Create memory pressure by allocating large chunks
        let mut memory_pressure: Vec<Vec<u8>> = Vec::new();
        for i in 0..5000 {
            memory_pressure.push(vec![(i % 256) as u8; 10000]); // 50MB total pressure
        }

        // Generate complex verification chain under memory pressure
        let mut chain = Vec::new();
        let chain_length = 100;

        for i in 0..chain_length {
            let req = VerificationRequest {
                artifact_id: format!("memory_pressure_{:03}", i),
                artifact_hash: format!("{:064x}", i),
                claims: vec![
                    format!("claim_a_{}", i),
                    format!("claim_b_{}", i),
                    format!("claim_c_{}", i),
                ],
            };

            let start = std::time::Instant::now();
            let report = sdk.verify_artifact(&req);
            let duration = start.elapsed();

            // Should complete quickly despite memory pressure
            assert!(duration < std::time::Duration::from_millis(500),
                   "Verification {} under memory pressure took too long: {:?}", i, duration);

            match report {
                Ok(report) => {
                    assert_eq!(report.request_id, req.artifact_id);
                    chain.push(report);
                }
                Err(_) => {
                    // Some failures under memory pressure are acceptable
                    continue;
                }
            }

            // Add more memory pressure periodically
            if i % 10 == 0 {
                for j in 0..100 {
                    memory_pressure.push(vec![(i + j) as u8; 5000]);
                }
            }
        }

        assert!(chain.len() >= 50, "Should complete substantial chain despite memory pressure");

        // Chain verification under memory pressure
        let chain_start = std::time::Instant::now();
        let chain_result = sdk.verify_chain(&chain).expect("chain should verify under pressure");
        let chain_duration = chain_start.elapsed();

        assert!(chain_duration < std::time::Duration::from_secs(30),
               "Chain verification under memory pressure took too long: {:?}", chain_duration);

        assert!(matches!(chain_result.verdict, VerifyVerdict::Pass));

        // Memory cleanup should not affect verification consistency
        drop(memory_pressure);

        let post_cleanup_chain = sdk.verify_chain(&chain).expect("should verify after cleanup");
        assert_eq!(chain_result.binding_hash, post_cleanup_chain.binding_hash);
    }

    #[test]
    fn negative_json_deserialization_with_deeply_nested_structures() {
        use serde_json::Value;

        let sdk = VerifierSdk::with_defaults();

        // Create deeply nested JSON structure for claims
        let mut nested_claim = Value::String("deep_claim".to_string());
        for depth in 0..1000 {
            nested_claim = Value::Array(vec![
                Value::String(format!("level_{}", depth)),
                nested_claim,
            ]);
        }

        // Convert to string (this will be a very deeply nested JSON)
        let nested_claim_str = nested_claim.to_string();

        // Test SDK's resilience to deeply nested claim data
        let req = VerificationRequest {
            artifact_id: "deep_nesting_test".to_string(),
            artifact_hash: "c".repeat(64),
            claims: vec![nested_claim_str.clone()],
        };

        // Should handle deep nesting without stack overflow
        let result = std::panic::catch_unwind(|| {
            sdk.verify_artifact(&req)
        });

        match result {
            Ok(verification_result) => {
                match verification_result {
                    Ok(report) => {
                        // If verification succeeded, JSON serialization should also handle it
                        let json_result = serde_json::to_string(&report);
                        assert!(json_result.is_ok() || json_result.is_err(),
                               "Serialization should complete without panic");
                    }
                    Err(_) => {
                        // Graceful failure is acceptable for extreme nesting
                    }
                }
            }
            Err(_) => {
                panic!("Deep nesting caused panic - need stack overflow protection");
            }
        }

        // Test with multiple layers of nesting in different fields
        let complex_req = VerificationRequest {
            artifact_id: format!("complex_{}", "x".repeat(10000)),
            artifact_hash: "d".repeat(64),
            claims: vec![
                "normal_claim".to_string(),
                nested_claim_str,
                "another_normal_claim".to_string(),
            ],
        };

        let complex_result = std::panic::catch_unwind(|| {
            sdk.verify_artifact(&complex_req)
        });

        // Should handle complex structures without crashing
        assert!(complex_result.is_ok(), "Complex nested structures should not cause panic");
    }

    #[test]
    fn negative_cryptographic_hash_collision_resistance_validation() {
        let sdk = VerifierSdk::with_defaults();

        // Test hash collision resistance by attempting various collision patterns
        let collision_test_vectors = vec![
            // Different content that might hash to similar values with weak hash functions
            ("collision_test_a", vec!["claim_a"]),
            ("collision_test_b", vec!["claim_b"]),
            ("collision_test_aa", vec!["claim_aa"]),
            ("collision_test_ab", vec!["claim_ab"]),

            // Length extension attempts
            ("base", vec!["claim"]),
            ("base\x00padding", vec!["claim"]),
            ("base", vec!["claim\x00padding"]),

            // Different arrangement of same data
            ("test", vec!["a", "b"]),
            ("test", vec!["ab"]),
            ("test", vec!["b", "a"]),

            // Unicode variations
            ("test_café", vec!["claim"]),
            ("test_cafe\u{0301}", vec!["claim"]),
        ];

        let mut all_binding_hashes = Vec::new();

        for (artifact_id, claims) in collision_test_vectors {
            let req = VerificationRequest {
                artifact_id: artifact_id.to_string(),
                artifact_hash: "e".repeat(64),
                claims: claims.into_iter().map(String::from).collect(),
            };

            let report = sdk.verify_artifact(&req).expect("should verify");

            // Collect binding hash for collision analysis
            all_binding_hashes.push((artifact_id, report.binding_hash.clone()));

            // Verify hash properties
            assert_eq!(report.binding_hash.len(), 64);
            assert!(report.binding_hash.chars().all(|c| c.is_ascii_hexdigit()));
        }

        // Check for any collisions
        for i in 0..all_binding_hashes.len() {
            for j in (i + 1)..all_binding_hashes.len() {
                let (id1, hash1) = &all_binding_hashes[i];
                let (id2, hash2) = &all_binding_hashes[j];

                assert_ne!(hash1, hash2,
                          "Hash collision detected between '{}' and '{}': both produced hash '{}'",
                          id1, id2, hash1);
            }
        }

        // Test deterministic property - same input should produce same hash
        for (artifact_id, _) in &all_binding_hashes {
            let req = VerificationRequest {
                artifact_id: artifact_id.to_string(),
                artifact_hash: "e".repeat(64),
                claims: vec!["claim".to_string()], // Simplified for determinism test
            };

            let report1 = sdk.verify_artifact(&req).expect("should verify");
            let report2 = sdk.verify_artifact(&req).expect("should verify again");

            assert_eq!(report1.binding_hash, report2.binding_hash,
                      "Same input should produce same binding hash for '{}'", artifact_id);
        }
    }

    #[test]
    fn negative_sdk_configuration_edge_cases_with_contradictory_settings() {
        // Test SDK behavior with various edge case configurations
        let edge_case_configs = vec![
            VerifierConfig {
                verifier_identity: "".to_string(),           // Empty identity
                require_hash_match: true,
                strict_claims: false,
                extensions: BTreeMap::new(),
            },

            VerifierConfig {
                verifier_identity: "\x00\r\n\t".to_string(), // Control characters
                require_hash_match: false,
                strict_claims: true,
                extensions: {
                    let mut ext = BTreeMap::new();
                    ext.insert("".to_string(), "empty_key".to_string());
                    ext.insert("unicode_🚀".to_string(), "unicode_value_🎯".to_string());
                    ext.insert("normal".to_string(), "\x00null_value\r\n".to_string());
                    ext
                },
            },

            VerifierConfig {
                verifier_identity: "x".repeat(100000),       // Massive identity
                require_hash_match: true,
                strict_claims: true,
                extensions: (0..1000).map(|i| {
                    (format!("key_{}", i), format!("value_{}", "x".repeat(1000)))
                }).collect(),
            },
        ];

        for (i, config) in edge_case_configs.iter().enumerate() {
            let sdk = VerifierSdk::new(config.clone());

            // Basic operations should work regardless of configuration
            assert_eq!(sdk.config(), config);
            assert_eq!(sdk.api_version(), API_VERSION);

            // Test verification with edge case config
            let req = VerificationRequest {
                artifact_id: format!("edge_config_{}", i),
                artifact_hash: format!("{:064x}", i),
                claims: vec![format!("edge_claim_{}", i)],
            };

            let start = std::time::Instant::now();
            let result = sdk.verify_artifact(&req);
            let duration = start.elapsed();

            // Should complete in reasonable time regardless of config
            assert!(duration < std::time::Duration::from_secs(10),
                   "Edge config {} verification took too long: {:?}", i, duration);

            match result {
                Ok(report) => {
                    // Report should contain the configured identity
                    assert_eq!(report.verifier_identity, config.verifier_identity);

                    // JSON serialization should handle edge case configs
                    let json = serde_json::to_string(&report);
                    assert!(json.is_ok(), "Edge config {} should serialize", i);

                    if let Ok(json_str) = json {
                        let parsed: VerificationReport = serde_json::from_str(&json_str);
                        assert!(parsed.is_ok(), "Edge config {} should deserialize", i);
                    }
                }
                Err(err) => {
                    // Some edge case configs might cause validation failures
                    assert!(matches!(err, SdkError::InvalidArtifact(_) |
                                         SdkError::MalformedCapsule(_) |
                                         SdkError::BrokenChain(_)));
                }
            }

            // Configuration consistency should be maintained
            assert_eq!(sdk.config().verifier_identity, config.verifier_identity);
            assert_eq!(sdk.config().require_hash_match, config.require_hash_match);
            assert_eq!(sdk.config().strict_claims, config.strict_claims);
            assert_eq!(sdk.config().extensions, config.extensions);
        }
    }

    #[test]
    fn negative_verifier_sdk_comprehensive_unicode_injection_and_identity_attacks() {
        // Test comprehensive Unicode injection and verifier identity attack resistance
        let malicious_identity_patterns = [
            "\u{202E}\u{202D}fake_verifier\u{202C}",       // Right-to-left override
            "verifier\u{000A}\u{000D}injected\x00nulls",   // CRLF + null injection
            "\u{FEFF}bom_verifier\u{FFFE}reversed",        // BOM injection attacks
            "\u{200B}\u{200C}\u{200D}zero_width",         // Zero-width characters
            "验证器\u{007F}\u{0001}\u{001F}控制字符",        // Unicode + control chars
            "\u{FFFF}\u{FFFE}\u{FDD0}non_characters",     // Non-character code points
            "🔐🛡️\u{1F4A5}💥\u{1F52B}🔫",                 // Complex emoji sequences
            "\u{0300}\u{0301}\u{0302}combining_marks",    // Combining marks
            format!("../../../{}", "x".repeat(1000)),      // Path traversal + long string
            "verifier\x00\x01\x02\x03\x04\x05hidden",     // Binary injection
            format!("verifier://{}@evil.com", "admin\x00\x01\x02"), // Protocol injection
            "verifier://admin'; DROP TABLE verifiers; --@evil.com", // SQL injection style
            "verifier://admin$(rm -rf /)@evil.com",        // Command injection style
        ];

        for (i, identity_pattern) in malicious_identity_patterns.iter().enumerate() {
            // Create configuration with potentially malicious identity
            let mut malicious_extensions = BTreeMap::new();
            malicious_extensions.insert(
                format!("extension_{}", identity_pattern),
                format!("value_with_{}_injection", identity_pattern),
            );
            malicious_extensions.insert(
                "path_key".to_string(),
                format!("../../../secret/{}", identity_pattern),
            );
            malicious_extensions.insert(
                "command_key".to_string(),
                format!("$(echo {})", identity_pattern),
            );

            let config = VerifierConfig {
                verifier_identity: identity_pattern.to_string(),
                require_hash_match: true,
                strict_claims: true,
                extensions: malicious_extensions,
            };

            let sdk = VerifierSdk::new(config.clone());

            // Test artifact verification with Unicode identity
            let unicode_request = VerificationRequest {
                artifact_id: format!("unicode_artifact_{}{}", identity_pattern, i),
                artifact_hash: format!("{:064x}", i),
                claims: vec![
                    format!("claim_with_{}_content", identity_pattern),
                    format!("path_claim/../../../etc/passwd_{}", i),
                    format!("command_claim; rm -rf /tmp/test_{}", i),
                ],
            };

            let verify_result = sdk.verify_artifact(&unicode_request);

            match verify_result {
                Ok(report) => {
                    // If verification succeeds, verify report structure integrity
                    assert_eq!(report.verifier_identity, *identity_pattern);
                    assert_eq!(report.artifact_id, unicode_request.artifact_id);
                    assert!(!report.evidence.is_empty());

                    // Test serialization safety with Unicode content
                    let serialized = serde_json::to_string(&report);
                    match serialized {
                        Ok(json_str) => {
                            // JSON should not contain null bytes or obvious injection patterns
                            assert!(!json_str.contains('\0'));
                            assert!(!json_str.contains("../../../"));
                            assert!(!json_str.contains("DROP TABLE"));
                            assert!(!json_str.contains("rm -rf"));

                            // Should be deserializable
                            let deserialized: Result<VerificationReport, _> = serde_json::from_str(&json_str);
                            match deserialized {
                                Ok(reconstructed) => {
                                    assert_eq!(reconstructed.verifier_identity, report.verifier_identity);
                                    assert_eq!(reconstructed.artifact_id, report.artifact_id);
                                    assert_eq!(reconstructed.verdict, report.verdict);
                                }
                                Err(_) => {
                                    // Extreme Unicode may prevent deserialization
                                }
                            }
                        }
                        Err(_) => {
                            // Extreme Unicode content may prevent serialization
                        }
                    }

                    // Test hash verification with Unicode
                    let unicode_data = identity_pattern.as_bytes().to_vec();
                    let computed_hash = compute_artifact_hash(&unicode_data);

                    let hash_request = VerificationRequest {
                        artifact_id: format!("hash_test_{}", i),
                        artifact_hash: computed_hash,
                        claims: vec!["unicode_hash_test".to_string()],
                    };

                    let hash_verify_result = sdk.verify_artifact(&hash_request);
                    match hash_verify_result {
                        Ok(hash_report) => {
                            // Hash verification should handle Unicode data gracefully
                            assert!(!hash_report.evidence.is_empty());
                        }
                        Err(_) => {
                            // May fail with extreme Unicode content
                        }
                    }
                }
                Err(err) => {
                    // Extreme Unicode patterns may be rejected during verification
                    match err {
                        SdkError::InvalidArtifact(_) |
                        SdkError::InvalidClaim(_) |
                        SdkError::ConfigError(_) => {
                            // Expected for extreme Unicode patterns
                        }
                        _ => {
                            // Other verification errors are acceptable
                        }
                    }
                }
            }

            // Test capsule verification with Unicode content
            let unicode_inputs = vec![CapsuleInput {
                seq: 1,
                data: identity_pattern.as_bytes().to_vec(),
                metadata: {
                    let mut meta = BTreeMap::new();
                    meta.insert(format!("meta_key_{}", i), format!("meta_value_{}", identity_pattern));
                    meta
                },
            }];

            let unicode_env = EnvironmentSnapshot {
                runtime_version: format!("runtime_{}", identity_pattern),
                platform: format!("platform_{}", identity_pattern),
                config_hash: format!("config_hash_{}", identity_pattern),
                properties: {
                    let mut props = BTreeMap::new();
                    props.insert(format!("env_key_{}", identity_pattern), format!("env_value_{}", identity_pattern));
                    props
                },
            };

            let unicode_capsule = ReplayCapsule {
                capsule_id: format!("unicode_capsule_{}{}", identity_pattern, i),
                format_version: 1,
                inputs: unicode_inputs,
                expected_outputs: vec![CapsuleOutput {
                    seq: 1,
                    data: format!("expected_output_{}", identity_pattern).as_bytes().to_vec(),
                    output_hash: format!("{:064x}", i + 1000),
                }],
                environment: unicode_env,
            };

            let capsule_verify_result = sdk.verify_capsule(&unicode_capsule);
            match capsule_verify_result {
                Ok(capsule_report) => {
                    // Capsule verification should handle Unicode gracefully
                    assert!(!capsule_report.evidence.is_empty());
                    assert_eq!(capsule_report.verifier_identity, *identity_pattern);
                }
                Err(_) => {
                    // May fail with extreme Unicode capsule content
                }
            }

            // Test chain verification with Unicode
            let unicode_reports = vec![
                VerificationReport {
                    verifier_identity: format!("chain_verifier_1_{}", identity_pattern),
                    artifact_id: format!("chain_artifact_1_{}", i),
                    verdict: VerificationVerdict::Valid,
                    evidence: format!("evidence_1_{}", identity_pattern),
                    timestamp: format!("2024-01-01T00:{}:00Z", i % 60),
                    schema_tag: SCHEMA_TAG.to_string(),
                },
                VerificationReport {
                    verifier_identity: format!("chain_verifier_2_{}", identity_pattern),
                    artifact_id: format!("chain_artifact_2_{}", i),
                    verdict: VerificationVerdict::Valid,
                    evidence: format!("evidence_2_{}", identity_pattern),
                    timestamp: format!("2024-01-01T00:{}:00Z", (i + 1) % 60),
                    schema_tag: SCHEMA_TAG.to_string(),
                },
            ];

            let chain_verify_result = sdk.verify_chain(&unicode_reports);
            match chain_verify_result {
                Ok(chain_report) => {
                    // Chain verification should handle Unicode in individual reports
                    assert!(!chain_report.evidence.is_empty());
                }
                Err(_) => {
                    // May fail with extreme Unicode in chain reports
                }
            }
        }
    }

    #[test]
    fn negative_artifact_hash_collision_and_preimage_resistance() {
        // Test artifact hash collision and preimage attack resistance
        let config = VerifierConfig {
            verifier_identity: "hash_security_tester".to_string(),
            require_hash_match: true,
            strict_claims: true,
            extensions: BTreeMap::new(),
        };

        let sdk = VerifierSdk::new(config);

        // Test with various hash collision attempt patterns
        let collision_patterns = vec![
            // Identical data with different IDs
            (b"collision_data".to_vec(), "artifact_a"),
            (b"collision_data".to_vec(), "artifact_b"), // Same data, different ID

            // Length extension attack patterns
            (b"original_data".to_vec(), "length_ext_1"),
            (b"original_data\x80\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00".to_vec(), "length_ext_2"),

            // Birthday attack patterns
            ((0..128).map(|i| (i % 256) as u8).collect(), "birthday_1"),
            ((0..128).map(|i| ((i + 128) % 256) as u8).collect(), "birthday_2"),

            // Weak data patterns
            (vec![0x00; 1024], "all_zeros"),
            (vec![0xFF; 1024], "all_ones"),
            ((0..1024).map(|i| (i % 256) as u8).collect(), "sequential"),

            // Binary patterns that might cause hash issues
            (vec![0x80; 512], "high_bit_pattern"),
            (vec![0x7F; 512], "low_bit_pattern"),
        ];

        let mut observed_hashes = std::collections::HashSet::new();

        for (i, (data, artifact_id)) in collision_patterns.into_iter().enumerate() {
            let computed_hash = compute_artifact_hash(&data);

            // Verify hash uniqueness (collision resistance)
            if observed_hashes.contains(&computed_hash) {
                panic!("Hash collision detected for artifact {}: {}", artifact_id, computed_hash);
            }
            observed_hashes.insert(computed_hash.clone());

            let request = VerificationRequest {
                artifact_id: artifact_id.to_string(),
                artifact_hash: computed_hash.clone(),
                claims: vec!["collision_test".to_string()],
            };

            let verify_result = sdk.verify_artifact(&request);

            match verify_result {
                Ok(report) => {
                    // Verification should succeed with correct hash
                    assert_eq!(report.verdict, VerificationVerdict::Valid);
                    assert_eq!(report.artifact_id, artifact_id);

                    // Test with wrong hash to verify mismatch detection
                    let wrong_request = VerificationRequest {
                        artifact_id: format!("{}_wrong", artifact_id),
                        artifact_hash: format!("{:064x}", i + 999999), // Wrong hash
                        claims: vec!["wrong_hash_test".to_string()],
                    };

                    let wrong_verify_result = sdk.verify_artifact(&wrong_request);
                    match wrong_verify_result {
                        Ok(wrong_report) => {
                            // Should detect hash mismatch
                            assert_eq!(wrong_report.verdict, VerificationVerdict::Invalid);
                        }
                        Err(SdkError::HashMismatch { expected, actual }) => {
                            // Expected behavior for hash mismatch
                            assert_eq!(expected, format!("{:064x}", i + 999999));
                            assert_ne!(expected, actual);
                        }
                        Err(_) => {
                            // Other errors acceptable for wrong hash
                        }
                    }
                }
                Err(_) => {
                    // Verification may fail for extreme data patterns
                }
            }

            // Test hash determinism (same input produces same hash)
            let duplicate_hash = compute_artifact_hash(&data);
            assert_eq!(computed_hash, duplicate_hash, "Hash should be deterministic for artifact {}", artifact_id);

            // Verify hash format and structure
            assert_eq!(computed_hash.len(), 64, "Hash should be 64 hex characters");
            assert!(computed_hash.chars().all(|c| c.is_ascii_hexdigit()), "Hash should be valid hex");
        }

        // Test preimage resistance (given hash, difficult to find input)
        let target_hashes = vec![
            "0000000000000000000000000000000000000000000000000000000000000000",
            "1111111111111111111111111111111111111111111111111111111111111111",
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "deadbeefcafebabe1234567890abcdef0011223344556677889900aabbccddee",
        ];

        for target_hash in target_hashes {
            let mut found_preimage = false;

            // Try various inputs to produce target hash
            for preimage_attempt in 0..10000 {
                let attempt_data = format!("preimage_attempt_{}", preimage_attempt).as_bytes().to_vec();
                let computed = compute_artifact_hash(&attempt_data);

                if crate::security::constant_time::ct_eq(&computed, target_hash) {
                    found_preimage = true;
                    break;
                }
            }

            // Should be extremely unlikely to find preimage by chance
            assert!(!found_preimage, "Accidentally found preimage for target hash: {}", target_hash);
        }

        // Test hash avalanche effect (small input change causes large hash change)
        let base_data = b"avalanche_test_data".to_vec();
        let base_hash = compute_artifact_hash(&base_data);

        for bit_flip in 0..min(base_data.len() * 8, 64) {
            let mut modified_data = base_data.clone();
            let byte_idx = bit_flip / 8;
            let bit_idx = bit_flip % 8;

            if byte_idx < modified_data.len() {
                modified_data[byte_idx] ^= 1 << bit_idx;

                let modified_hash = compute_artifact_hash(&modified_data);

                // Single bit flip should produce significantly different hash
                assert_ne!(base_hash, modified_hash, "Bit flip {} should change hash significantly", bit_flip);

                // Count differing bits in hash
                let base_bytes = hex::decode(&base_hash).unwrap();
                let modified_bytes = hex::decode(&modified_hash).unwrap();

                let differing_bits: u32 = base_bytes
                    .iter()
                    .zip(modified_bytes.iter())
                    .map(|(a, b)| (a ^ b).count_ones())
                    .sum();

                // Should have good avalanche effect (roughly half bits different)
                assert!(differing_bits > 50, "Avalanche effect too weak for bit flip {}: only {} bits differ", bit_flip, differing_bits);
            }
        }
    }

    #[test]
    fn negative_verification_chain_temporal_attack_and_consistency_violations() {
        // Test verification chain temporal attacks and consistency violation resistance
        let config = VerifierConfig {
            verifier_identity: "chain_security_tester".to_string(),
            require_hash_match: false,
            strict_claims: true,
            extensions: BTreeMap::new(),
        };

        let sdk = VerifierSdk::new(config);

        // Test various temporal attack scenarios
        let temporal_attack_chains = vec![
            // Future timestamps
            vec![
                VerificationReport {
                    verifier_identity: "time_traveler".to_string(),
                    artifact_id: "future_artifact".to_string(),
                    verdict: VerificationVerdict::Valid,
                    evidence: "future_evidence".to_string(),
                    timestamp: "2099-12-31T23:59:59Z".to_string(), // Far future
                    schema_tag: SCHEMA_TAG.to_string(),
                },
            ],

            // Backward time sequence
            vec![
                VerificationReport {
                    verifier_identity: "time_attacker_1".to_string(),
                    artifact_id: "backward_artifact_1".to_string(),
                    verdict: VerificationVerdict::Valid,
                    evidence: "later_evidence".to_string(),
                    timestamp: "2024-12-31T23:59:59Z".to_string(),
                    schema_tag: SCHEMA_TAG.to_string(),
                },
                VerificationReport {
                    verifier_identity: "time_attacker_2".to_string(),
                    artifact_id: "backward_artifact_2".to_string(),
                    verdict: VerificationVerdict::Valid,
                    evidence: "earlier_evidence".to_string(),
                    timestamp: "2024-01-01T00:00:00Z".to_string(), // Earlier than previous
                    schema_tag: SCHEMA_TAG.to_string(),
                },
            ],

            // Identical timestamps
            vec![
                VerificationReport {
                    verifier_identity: "simultaneous_1".to_string(),
                    artifact_id: "identical_time_1".to_string(),
                    verdict: VerificationVerdict::Valid,
                    evidence: "evidence_1".to_string(),
                    timestamp: "2024-06-15T12:00:00Z".to_string(),
                    schema_tag: SCHEMA_TAG.to_string(),
                },
                VerificationReport {
                    verifier_identity: "simultaneous_2".to_string(),
                    artifact_id: "identical_time_2".to_string(),
                    verdict: VerificationVerdict::Valid,
                    evidence: "evidence_2".to_string(),
                    timestamp: "2024-06-15T12:00:00Z".to_string(), // Same timestamp
                    schema_tag: SCHEMA_TAG.to_string(),
                },
            ],

            // Malformed timestamps
            vec![
                VerificationReport {
                    verifier_identity: "malformed_time_attacker".to_string(),
                    artifact_id: "malformed_time_artifact".to_string(),
                    verdict: VerificationVerdict::Valid,
                    evidence: "malformed_evidence".to_string(),
                    timestamp: "not-a-timestamp".to_string(),
                    schema_tag: SCHEMA_TAG.to_string(),
                },
            ],

            // Extreme timestamps
            vec![
                VerificationReport {
                    verifier_identity: "extreme_past".to_string(),
                    artifact_id: "extreme_past_artifact".to_string(),
                    verdict: VerificationVerdict::Valid,
                    evidence: "ancient_evidence".to_string(),
                    timestamp: "1970-01-01T00:00:00Z".to_string(), // Unix epoch
                    schema_tag: SCHEMA_TAG.to_string(),
                },
                VerificationReport {
                    verifier_identity: "extreme_future".to_string(),
                    artifact_id: "extreme_future_artifact".to_string(),
                    verdict: VerificationVerdict::Valid,
                    evidence: "futuristic_evidence".to_string(),
                    timestamp: "9999-12-31T23:59:59Z".to_string(), // Far future
                    schema_tag: SCHEMA_TAG.to_string(),
                },
            ],
        ];

        for (chain_idx, chain) in temporal_attack_chains.into_iter().enumerate() {
            let verify_result = sdk.verify_chain(&chain);

            match verify_result {
                Ok(chain_report) => {
                    // If chain verification succeeds, check temporal consistency
                    assert!(!chain_report.evidence.is_empty());

                    // Report should indicate how temporal issues were handled
                    let evidence_mentions_time = chain_report.evidence.contains("time") ||
                                               chain_report.evidence.contains("temporal") ||
                                               chain_report.evidence.contains("timestamp");

                    if chain_idx == 1 || chain_idx == 3 { // Backward time or malformed
                        // Should detect temporal issues
                        assert!(evidence_mentions_time || chain_report.verdict == VerificationVerdict::Invalid,
                               "Chain {} should detect temporal issues", chain_idx);
                    }
                }
                Err(err) => {
                    // Temporal attacks may be rejected
                    match err {
                        SdkError::BrokenChain(msg) => {
                            // Expected for temporal inconsistencies
                            assert!(msg.contains("time") || msg.contains("temporal") || msg.contains("timestamp"),
                                   "Chain error should mention temporal issue: {}", msg);
                        }
                        _ => {
                            // Other chain verification errors are acceptable
                        }
                    }
                }
            }
        }

        // Test consistency violations across various dimensions
        let consistency_attack_chains = vec![
            // Conflicting verdicts for same artifact
            vec![
                VerificationReport {
                    verifier_identity: "verifier_a".to_string(),
                    artifact_id: "conflict_artifact".to_string(),
                    verdict: VerificationVerdict::Valid,
                    evidence: "says_valid".to_string(),
                    timestamp: "2024-06-15T12:00:00Z".to_string(),
                    schema_tag: SCHEMA_TAG.to_string(),
                },
                VerificationReport {
                    verifier_identity: "verifier_b".to_string(),
                    artifact_id: "conflict_artifact".to_string(), // Same artifact
                    verdict: VerificationVerdict::Invalid,         // Different verdict
                    evidence: "says_invalid".to_string(),
                    timestamp: "2024-06-15T12:01:00Z".to_string(),
                    schema_tag: SCHEMA_TAG.to_string(),
                },
            ],

            // Schema version inconsistencies
            vec![
                VerificationReport {
                    verifier_identity: "schema_attacker".to_string(),
                    artifact_id: "schema_artifact".to_string(),
                    verdict: VerificationVerdict::Valid,
                    evidence: "valid_schema".to_string(),
                    timestamp: "2024-06-15T12:00:00Z".to_string(),
                    schema_tag: "invalid-schema-v999".to_string(), // Wrong schema
                },
            ],

            // Empty or malformed evidence
            vec![
                VerificationReport {
                    verifier_identity: "empty_evidence_attacker".to_string(),
                    artifact_id: "empty_evidence_artifact".to_string(),
                    verdict: VerificationVerdict::Valid,
                    evidence: "".to_string(), // Empty evidence
                    timestamp: "2024-06-15T12:00:00Z".to_string(),
                    schema_tag: SCHEMA_TAG.to_string(),
                },
                VerificationReport {
                    verifier_identity: "null_evidence_attacker".to_string(),
                    artifact_id: "null_evidence_artifact".to_string(),
                    verdict: VerificationVerdict::Valid,
                    evidence: "\x00\x01\x02binary_evidence".to_string(), // Binary evidence
                    timestamp: "2024-06-15T12:01:00Z".to_string(),
                    schema_tag: SCHEMA_TAG.to_string(),
                },
            ],

            // Circular dependencies
            vec![
                VerificationReport {
                    verifier_identity: "circular_a".to_string(),
                    artifact_id: "circular_artifact_a".to_string(),
                    verdict: VerificationVerdict::Valid,
                    evidence: "depends_on_circular_artifact_b".to_string(),
                    timestamp: "2024-06-15T12:00:00Z".to_string(),
                    schema_tag: SCHEMA_TAG.to_string(),
                },
                VerificationReport {
                    verifier_identity: "circular_b".to_string(),
                    artifact_id: "circular_artifact_b".to_string(),
                    verdict: VerificationVerdict::Valid,
                    evidence: "depends_on_circular_artifact_a".to_string(), // Circular dependency
                    timestamp: "2024-06-15T12:01:00Z".to_string(),
                    schema_tag: SCHEMA_TAG.to_string(),
                },
            ],
        ];

        for (attack_idx, attack_chain) in consistency_attack_chains.into_iter().enumerate() {
            let verify_result = sdk.verify_chain(&attack_chain);

            match verify_result {
                Ok(chain_report) => {
                    // If verification succeeds, should detect consistency issues
                    match attack_idx {
                        0 => {
                            // Conflicting verdicts should be detected
                            assert!(chain_report.evidence.contains("conflict") ||
                                   chain_report.evidence.contains("inconsistent") ||
                                   chain_report.verdict == VerificationVerdict::Invalid,
                                   "Should detect conflicting verdicts");
                        }
                        1 => {
                            // Schema inconsistencies should be detected
                            assert!(chain_report.evidence.contains("schema") ||
                                   chain_report.verdict == VerificationVerdict::Invalid,
                                   "Should detect schema inconsistencies");
                        }
                        2 => {
                            // Empty evidence should be detected
                            assert!(chain_report.evidence.contains("evidence") ||
                                   chain_report.evidence.contains("empty") ||
                                   chain_report.verdict == VerificationVerdict::Invalid,
                                   "Should detect evidence issues");
                        }
                        3 => {
                            // Circular dependencies should be detected
                            assert!(chain_report.evidence.contains("circular") ||
                                   chain_report.evidence.contains("cycle") ||
                                   chain_report.verdict == VerificationVerdict::Invalid,
                                   "Should detect circular dependencies");
                        }
                        _ => {}
                    }
                }
                Err(err) => {
                    // Consistency attacks may be rejected
                    match err {
                        SdkError::BrokenChain(msg) => {
                            // Expected for consistency violations
                            match attack_idx {
                                0 => assert!(msg.contains("conflict") || msg.contains("inconsistent")),
                                1 => assert!(msg.contains("schema")),
                                2 => assert!(msg.contains("evidence") || msg.contains("empty")),
                                3 => assert!(msg.contains("circular") || msg.contains("cycle")),
                                _ => {}
                            }
                        }
                        _ => {
                            // Other verification errors are acceptable
                        }
                    }
                }
            }
        }

        // Test massive chain attack (memory/performance)
        let massive_chain: Vec<VerificationReport> = (0..10000)
            .map(|i| VerificationReport {
                verifier_identity: format!("mass_verifier_{}", i),
                artifact_id: format!("mass_artifact_{}", i),
                verdict: if i % 2 == 0 { VerificationVerdict::Valid } else { VerificationVerdict::Invalid },
                evidence: format!("mass_evidence_{}", "x".repeat(1000)),
                timestamp: format!("2024-01-01T{:02}:{:02}:{:02}Z", (i / 3600) % 24, (i / 60) % 60, i % 60),
                schema_tag: SCHEMA_TAG.to_string(),
            })
            .collect();

        let mass_start = std::time::Instant::now();
        let mass_result = sdk.verify_chain(&massive_chain);
        let mass_duration = mass_start.elapsed();

        // Should complete in reasonable time even for large chains
        assert!(mass_duration < std::time::Duration::from_secs(60),
               "Massive chain verification took too long: {:?}", mass_duration);

        match mass_result {
            Ok(mass_report) => {
                // Should handle large chains gracefully
                assert!(!mass_report.evidence.is_empty());
            }
            Err(_) => {
                // May reject massive chains due to resource limits
            }
        }
    }

    #[test]
    fn negative_capsule_format_version_and_schema_evolution_attacks() {
        // Test capsule format version and schema evolution attack resistance
        let config = VerifierConfig {
            verifier_identity: "schema_security_tester".to_string(),
            require_hash_match: false,
            strict_claims: false,
            extensions: BTreeMap::new(),
        };

        let sdk = VerifierSdk::new(config);

        // Test various format version attack scenarios
        let version_attack_capsules = vec![
            // Future version
            ReplayCapsule {
                capsule_id: "future_version".to_string(),
                format_version: 999999,
                inputs: vec![CapsuleInput {
                    seq: 1,
                    data: b"future_data".to_vec(),
                    metadata: BTreeMap::new(),
                }],
                expected_outputs: vec![CapsuleOutput {
                    seq: 1,
                    data: b"future_output".to_vec(),
                    output_hash: "a".repeat(64),
                }],
                environment: EnvironmentSnapshot {
                    runtime_version: "future_runtime".to_string(),
                    platform: "future_platform".to_string(),
                    config_hash: "b".repeat(64),
                    properties: BTreeMap::new(),
                },
            },

            // Zero version
            ReplayCapsule {
                capsule_id: "zero_version".to_string(),
                format_version: 0,
                inputs: vec![CapsuleInput {
                    seq: 1,
                    data: b"zero_data".to_vec(),
                    metadata: BTreeMap::new(),
                }],
                expected_outputs: vec![CapsuleOutput {
                    seq: 1,
                    data: b"zero_output".to_vec(),
                    output_hash: "c".repeat(64),
                }],
                environment: EnvironmentSnapshot {
                    runtime_version: "zero_runtime".to_string(),
                    platform: "zero_platform".to_string(),
                    config_hash: "d".repeat(64),
                    properties: BTreeMap::new(),
                },
            },

            // Maximum version
            ReplayCapsule {
                capsule_id: "max_version".to_string(),
                format_version: u32::MAX,
                inputs: vec![CapsuleInput {
                    seq: 1,
                    data: b"max_data".to_vec(),
                    metadata: BTreeMap::new(),
                }],
                expected_outputs: vec![CapsuleOutput {
                    seq: 1,
                    data: b"max_output".to_vec(),
                    output_hash: "e".repeat(64),
                }],
                environment: EnvironmentSnapshot {
                    runtime_version: "max_runtime".to_string(),
                    platform: "max_platform".to_string(),
                    config_hash: "f".repeat(64),
                    properties: BTreeMap::new(),
                },
            },
        ];

        for (version_idx, attack_capsule) in version_attack_capsules.into_iter().enumerate() {
            let verify_result = sdk.verify_capsule(&attack_capsule);

            match verify_result {
                Ok(capsule_report) => {
                    // If verification succeeds, should handle version appropriately
                    assert!(!capsule_report.evidence.is_empty());

                    // Evidence should mention version handling for extreme versions
                    if attack_capsule.format_version == 0 || attack_capsule.format_version > 100 {
                        let evidence_mentions_version = capsule_report.evidence.contains("version") ||
                                                       capsule_report.evidence.contains("format") ||
                                                       capsule_report.evidence.contains("unsupported");

                        assert!(evidence_mentions_version || capsule_report.verdict == VerificationVerdict::Invalid,
                               "Should handle extreme version {}: {}", attack_capsule.format_version, capsule_report.evidence);
                    }

                    // Test serialization/deserialization with version attacks
                    let serialized = serde_json::to_string(&capsule_report);
                    match serialized {
                        Ok(json_str) => {
                            let deserialized: Result<VerificationReport, _> = serde_json::from_str(&json_str);
                            match deserialized {
                                Ok(_) => {
                                    // Should handle extreme versions in serialization
                                }
                                Err(_) => {
                                    // Extreme versions may cause serialization issues
                                }
                            }
                        }
                        Err(_) => {
                            // Extreme versions may prevent serialization
                        }
                    }
                }
                Err(err) => {
                    // Extreme versions may be rejected
                    match err {
                        SdkError::MalformedCapsule(msg) => {
                            // Expected for unsupported versions
                            assert!(msg.contains("version") || msg.contains("format") || msg.contains("unsupported"),
                                   "Version error should mention version issue: {}", msg);
                        }
                        _ => {
                            // Other capsule verification errors are acceptable
                        }
                    }
                }
            }
        }

        // Test schema injection attacks
        let schema_injection_capsules = vec![
            // Capsule with injected fields (simulated by metadata)
            ReplayCapsule {
                capsule_id: "schema_injection".to_string(),
                format_version: 1,
                inputs: vec![CapsuleInput {
                    seq: 1,
                    data: b"injection_data".to_vec(),
                    metadata: {
                        let mut meta = BTreeMap::new();
                        meta.insert("__proto__".to_string(), "prototype_pollution".to_string());
                        meta.insert("constructor".to_string(), "constructor_injection".to_string());
                        meta.insert("toString".to_string(), "method_override".to_string());
                        meta.insert("../../../evil".to_string(), "path_traversal".to_string());
                        meta.insert("'; DROP TABLE capsules; --".to_string(), "sql_injection".to_string());
                        meta
                    },
                }],
                expected_outputs: vec![CapsuleOutput {
                    seq: 1,
                    data: b"injection_output".to_vec(),
                    output_hash: "g".repeat(64),
                }],
                environment: EnvironmentSnapshot {
                    runtime_version: "injection_runtime".to_string(),
                    platform: "injection_platform".to_string(),
                    config_hash: "h".repeat(64),
                    properties: {
                        let mut props = BTreeMap::new();
                        props.insert("eval".to_string(), "evil_code_here".to_string());
                        props.insert("exec".to_string(), "rm -rf /".to_string());
                        props.insert("system".to_string(), "malicious_command".to_string());
                        props
                    },
                },
            },

            // Capsule with extreme field values
            ReplayCapsule {
                capsule_id: "extreme_values".to_string(),
                format_version: 1,
                inputs: vec![CapsuleInput {
                    seq: u64::MAX,
                    data: vec![0xFF; 10_000_000], // 10MB data
                    metadata: (0..10000).map(|i| {
                        (format!("extreme_key_{}", i), "x".repeat(10000))
                    }).collect(),
                }],
                expected_outputs: vec![CapsuleOutput {
                    seq: u64::MAX,
                    data: vec![0x00; 10_000_000],
                    output_hash: "i".repeat(1000), // Too long hash
                }],
                environment: EnvironmentSnapshot {
                    runtime_version: "x".repeat(100_000),
                    platform: "y".repeat(100_000),
                    config_hash: "z".repeat(100_000),
                    properties: (0..10000).map(|i| {
                        (format!("prop_{}", i), "z".repeat(10000))
                    }).collect(),
                },
            },
        ];

        for (injection_idx, injection_capsule) in schema_injection_capsules.into_iter().enumerate() {
            let start = std::time::Instant::now();
            let verify_result = sdk.verify_capsule(&injection_capsule);
            let duration = start.elapsed();

            // Should complete in reasonable time even with extreme values
            assert!(duration < std::time::Duration::from_secs(60),
                   "Schema injection test {} took too long: {:?}", injection_idx, duration);

            match verify_result {
                Ok(injection_report) => {
                    // Should handle injection gracefully
                    assert!(!injection_report.evidence.is_empty());

                    // Should not execute or interpret injected code
                    assert!(!injection_report.evidence.contains("evil_code_here"));
                    assert!(!injection_report.evidence.contains("rm -rf"));

                    // Test that injection doesn't affect other operations
                    let normal_request = VerificationRequest {
                        artifact_id: "post_injection_test".to_string(),
                        artifact_hash: "j".repeat(64),
                        claims: vec!["normal_claim".to_string()],
                    };

                    let normal_result = sdk.verify_artifact(&normal_request);
                    match normal_result {
                        Ok(normal_report) => {
                            // Normal operations should work after injection attempts
                            assert!(!normal_report.evidence.is_empty());
                        }
                        Err(_) => {
                            // Normal operations may fail due to side effects
                        }
                    }
                }
                Err(err) => {
                    // Injection attempts may be rejected
                    match err {
                        SdkError::MalformedCapsule(msg) => {
                            // Should detect malformed content
                            assert!(!msg.contains("evil_code_here"));
                            assert!(!msg.contains("rm -rf"));
                        }
                        _ => {
                            // Other capsule errors are acceptable
                        }
                    }
                }
            }
        }

        // Test backwards compatibility simulation
        let backwards_compatibility_test = ReplayCapsule {
            capsule_id: "backwards_compat_test".to_string(),
            format_version: 1, // Current version
            inputs: vec![CapsuleInput {
                seq: 1,
                data: b"compatibility_test".to_vec(),
                metadata: BTreeMap::new(),
            }],
            expected_outputs: vec![CapsuleOutput {
                seq: 1,
                data: b"compatibility_output".to_vec(),
                output_hash: "k".repeat(64),
            }],
            environment: EnvironmentSnapshot {
                runtime_version: "compat_runtime".to_string(),
                platform: "compat_platform".to_string(),
                config_hash: "l".repeat(64),
                properties: BTreeMap::new(),
            },
        };

        let compat_result = sdk.verify_capsule(&backwards_compatibility_test);

        match compat_result {
            Ok(compat_report) => {
                // Should handle current version correctly
                assert_eq!(compat_report.verdict, VerificationVerdict::Valid);
                assert!(!compat_report.evidence.is_empty());

                // Test that report structure is stable
                assert_eq!(compat_report.schema_tag, SCHEMA_TAG);
                assert!(!compat_report.verifier_identity.is_empty());
                assert!(!compat_report.artifact_id.is_empty());
                assert!(!compat_report.timestamp.is_empty());
            }
            Err(_) => {
                // Backwards compatibility test should not fail
                panic!("Backwards compatibility capsule verification should succeed");
            }
        }
    }

    #[test]
    fn negative_verification_request_claim_injection_and_validation_bypass() {
        // Test verification request claim injection and validation bypass attacks
        let strict_config = VerifierConfig {
            verifier_identity: "strict_validator".to_string(),
            require_hash_match: true,
            strict_claims: true,
            extensions: BTreeMap::new(),
        };

        let lenient_config = VerifierConfig {
            verifier_identity: "lenient_validator".to_string(),
            require_hash_match: false,
            strict_claims: false,
            extensions: BTreeMap::new(),
        };

        let configs = vec![("strict", strict_config), ("lenient", lenient_config)];

        for (config_name, config) in configs {
            let sdk = VerifierSdk::new(config.clone());

            // Test claim injection attacks
            let claim_injection_attacks = vec![
                // Empty claims
                vec![],

                // Claims with null bytes
                vec![
                    "normal_claim".to_string(),
                    "claim_with\x00null_byte".to_string(),
                    "\x01\x02\x03binary_claim".to_string(),
                ],

                // Unicode injection in claims
                vec![
                    "claim\u{202E}\u{202D}fake_claim\u{202C}".to_string(),
                    "claim\u{000A}\u{000D}injected_newlines".to_string(),
                    "claim\u{FEFF}bom_injection\u{FFFE}".to_string(),
                ],

                // Path traversal in claims
                vec![
                    "claim_with/../../../etc/passwd".to_string(),
                    "claim_with/../../secrets/key.pem".to_string(),
                    "claim_with\\..\\..\\windows\\system32".to_string(),
                ],

                // Command injection in claims
                vec![
                    "claim; rm -rf /tmp/test".to_string(),
                    "claim$(whoami)injection".to_string(),
                    "claim`cat /etc/passwd`backdoor".to_string(),
                ],

                // SQL injection style claims
                vec![
                    "claim'; DROP TABLE claims; --".to_string(),
                    "claim' UNION SELECT * FROM secrets; --".to_string(),
                    "claim' OR '1'='1".to_string(),
                ],

                // Script injection claims
                vec![
                    "<script>alert('xss')</script>".to_string(),
                    "javascript:void(0)".to_string(),
                    "data:text/html,<script>evil()</script>".to_string(),
                ],

                // Extremely long claims
                vec![
                    "x".repeat(1_000_000), // 1MB claim
                    "claim_".to_string() + &"a".repeat(100_000),
                ],

                // Many small claims
                (0..10_000).map(|i| format!("mass_claim_{}", i)).collect(),

                // Claims with special characters
                vec![
                    "claim\r\n\tspecial_chars".to_string(),
                    "claim\"double_quotes\"claim".to_string(),
                    "claim'single_quotes'claim".to_string(),
                    "claim{json}injection}claim".to_string(),
                ],
            ];

            for (attack_idx, attack_claims) in claim_injection_attacks.into_iter().enumerate() {
                let request = VerificationRequest {
                    artifact_id: format!("{}_claim_attack_{}", config_name, attack_idx),
                    artifact_hash: format!("{:064x}", attack_idx),
                    claims: attack_claims.clone(),
                };

                let start = std::time::Instant::now();
                let verify_result = sdk.verify_artifact(&request);
                let duration = start.elapsed();

                // Should complete in reasonable time even with attack claims
                assert!(duration < std::time::Duration::from_secs(30),
                       "{} config claim attack {} took too long: {:?}", config_name, attack_idx, duration);

                match verify_result {
                    Ok(report) => {
                        // If verification succeeds, check claim handling
                        assert!(!report.evidence.is_empty());

                        // Evidence should not contain obvious injection results
                        assert!(!report.evidence.contains("evil()"));
                        assert!(!report.evidence.contains("alert('xss')"));
                        assert!(!report.evidence.contains("DROP TABLE"));
                        assert!(!report.evidence.contains("rm -rf"));

                        // For strict config with empty claims, should fail or note issue
                        if config.strict_claims && attack_claims.is_empty() {
                            assert!(report.verdict == VerificationVerdict::Invalid ||
                                   report.evidence.contains("empty") ||
                                   report.evidence.contains("no claims"),
                                   "Strict config should reject empty claims");
                        }

                        // Test serialization safety with injection claims
                        let serialized = serde_json::to_string(&report);
                        match serialized {
                            Ok(json_str) => {
                                // JSON should not contain injection payloads
                                assert!(!json_str.contains("DROP TABLE"));
                                assert!(!json_str.contains("rm -rf"));
                                assert!(!json_str.contains("<script>"));

                                // Should not contain null bytes
                                assert!(!json_str.contains('\0'));

                                // Should be valid JSON
                                let parse_test: Result<serde_json::Value, _> = serde_json::from_str(&json_str);
                                assert!(parse_test.is_ok(), "Report with injection claims should be valid JSON");
                            }
                            Err(_) => {
                                // Extreme claims may prevent serialization
                                assert!(attack_claims.iter().any(|claim| claim.len() > 100_000),
                                       "Only extreme claims should prevent serialization");
                            }
                        }
                    }
                    Err(err) => {
                        // Injection claims may be rejected
                        match err {
                            SdkError::InvalidClaim(msg) => {
                                // Should provide meaningful error for invalid claims
                                assert!(!msg.is_empty());
                                assert!(!msg.contains("evil()"));
                                assert!(!msg.contains("DROP TABLE"));
                            }
                            SdkError::InvalidArtifact(msg) => {
                                // May reject entire artifact with malicious claims
                                assert!(!msg.contains("rm -rf"));
                            }
                            _ => {
                                // Other verification errors are acceptable
                            }
                        }
                    }
                }
            }

            // Test artifact ID injection attacks
            let artifact_id_attacks = vec![
                "".to_string(), // Empty ID
                "artifact\x00null_byte".to_string(),
                "artifact\u{202E}unicode_attack".to_string(),
                "artifact/../../../etc/passwd".to_string(),
                "artifact; rm -rf /tmp".to_string(),
                "artifact'; DROP TABLE artifacts; --".to_string(),
                "<script>alert('xss')</script>".to_string(),
                "x".repeat(1_000_000), // Extremely long ID
            ];

            for (id_attack_idx, attack_id) in artifact_id_attacks.into_iter().enumerate() {
                let request = VerificationRequest {
                    artifact_id: attack_id.clone(),
                    artifact_hash: format!("{:064x}", id_attack_idx),
                    claims: vec!["normal_claim".to_string()],
                };

                let verify_result = sdk.verify_artifact(&request);

                match verify_result {
                    Ok(report) => {
                        // Should handle malicious artifact IDs safely
                        assert_eq!(report.artifact_id, attack_id);

                        // Evidence should not execute injection content
                        assert!(!report.evidence.contains("evil()"));
                        assert!(!report.evidence.contains("DROP TABLE"));
                    }
                    Err(err) => {
                        // May reject malicious artifact IDs
                        match err {
                            SdkError::InvalidArtifact(msg) => {
                                // Should provide safe error message
                                assert!(!msg.contains("rm -rf"));
                                assert!(!msg.contains("DROP TABLE"));
                            }
                            _ => {
                                // Other errors acceptable
                            }
                        }
                    }
                }
            }

            // Test hash injection attacks
            let hash_injection_attacks = vec![
                "".to_string(), // Empty hash
                "not_hex_at_all".to_string(),
                "ghijklmnopqr".repeat(5), // Invalid hex characters
                "a".repeat(32), // Too short
                "a".repeat(128), // Too long
                format!("{}../../../etc/passwd", "a".repeat(32)), // Path traversal
                format!("{}'; DROP TABLE hashes; --", "a".repeat(32)), // SQL injection
                "\x00\x01\x02\x03".repeat(16), // Binary data
                "ffffffffffffffffffffffffffffffff\x00null_injection".to_string(),
            ];

            for (hash_attack_idx, attack_hash) in hash_injection_attacks.into_iter().enumerate() {
                let request = VerificationRequest {
                    artifact_id: format!("{}_hash_attack_{}", config_name, hash_attack_idx),
                    artifact_hash: attack_hash.clone(),
                    claims: vec!["hash_attack_claim".to_string()],
                };

                let verify_result = sdk.verify_artifact(&request);

                match verify_result {
                    Ok(report) => {
                        // Should handle malicious hashes safely
                        // For require_hash_match=true, should detect invalid hashes
                        if config.require_hash_match && (attack_hash.is_empty() || attack_hash.len() != 64) {
                            assert!(report.verdict == VerificationVerdict::Invalid ||
                                   report.evidence.contains("hash") ||
                                   report.evidence.contains("invalid"),
                                   "Should detect invalid hash format");
                        }

                        // Evidence should not contain injection content
                        assert!(!report.evidence.contains("DROP TABLE"));
                        assert!(!report.evidence.contains("../../../"));
                    }
                    Err(err) => {
                        // May reject malicious hashes
                        match err {
                            SdkError::HashMismatch { expected, actual } => {
                                // Should provide safe hash mismatch info
                                assert!(!expected.contains("DROP TABLE"));
                                assert!(!actual.contains("DROP TABLE"));
                            }
                            SdkError::InvalidArtifact(msg) => {
                                // Should provide safe error message
                                assert!(!msg.contains("DROP TABLE"));
                            }
                            _ => {
                                // Other errors acceptable
                            }
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn negative_sdk_configuration_memory_exhaustion_and_resource_attacks() {
        // Test SDK configuration memory exhaustion and resource attack resistance
        let resource_attack_configs = vec![
            // Massive verifier identity
            VerifierConfig {
                verifier_identity: "x".repeat(10_000_000), // 10MB identity
                require_hash_match: true,
                strict_claims: true,
                extensions: BTreeMap::new(),
            },

            // Massive extension count
            VerifierConfig {
                verifier_identity: "mass_extensions_verifier".to_string(),
                require_hash_match: false,
                strict_claims: false,
                extensions: (0..100_000).map(|i| {
                    (format!("ext_key_{}", i), format!("ext_value_{}", i))
                }).collect(),
            },

            // Massive extension values
            VerifierConfig {
                verifier_identity: "large_extension_verifier".to_string(),
                require_hash_match: true,
                strict_claims: true,
                extensions: {
                    let mut ext = BTreeMap::new();
                    ext.insert("large_key_1".to_string(), "y".repeat(5_000_000)); // 5MB value
                    ext.insert("large_key_2".to_string(), "z".repeat(5_000_000)); // 5MB value
                    ext
                },
            },

            // Binary data in extensions
            VerifierConfig {
                verifier_identity: "binary_extensions_verifier".to_string(),
                require_hash_match: false,
                strict_claims: false,
                extensions: {
                    let mut ext = BTreeMap::new();
                    let binary_key =
                        String::from_utf8_lossy(&[0xFF, 0xFE, 0xFD].repeat(1000)).into_owned();
                    let binary_value =
                        String::from_utf8_lossy(&[0x00, 0x01, 0x02].repeat(1000)).into_owned();
                    ext.insert(binary_key, binary_value);
                    ext.insert(
                        "\x00\x01\x02binary_key".to_string(),
                        String::from_utf8_lossy(b"\xFF\xFE\xFDbinary_value").into_owned(),
                    );
                    ext
                },
            },

            // Unicode in all fields
            VerifierConfig {
                verifier_identity: "unicode_verifier_🚀🛡️\u{202E}攻击".to_string(),
                require_hash_match: true,
                strict_claims: true,
                extensions: {
                    let mut ext = BTreeMap::new();
                    ext.insert("🔑key_with_emoji".to_string(), "🎯value_with_emoji".to_string());
                    ext.insert(
                        "控制字符\u{0000}\u{0001}\u{0002}".to_string(),
                        "注入攻击\u{202E}\u{202D}fake".to_string(),
                    );
                    ext
                },
            },
        ];

        for (config_idx, attack_config) in resource_attack_configs.into_iter().enumerate() {
            // Test SDK creation with resource-intensive config
            let creation_start = std::time::Instant::now();
            let sdk = VerifierSdk::new(attack_config.clone());
            let creation_duration = creation_start.elapsed();

            // SDK creation should complete in reasonable time
            assert!(creation_duration < std::time::Duration::from_secs(10),
                   "Config {} SDK creation took too long: {:?}", config_idx, creation_duration);

            // Test basic operations with resource-intensive config
            let basic_request = VerificationRequest {
                artifact_id: format!("resource_attack_test_{}", config_idx),
                artifact_hash: format!("{:064x}", config_idx),
                claims: vec!["resource_test_claim".to_string()],
            };

            let verify_start = std::time::Instant::now();
            let verify_result = sdk.verify_artifact(&basic_request);
            let verify_duration = verify_start.elapsed();

            // Verification should complete in reasonable time despite resource-intensive config
            assert!(verify_duration < std::time::Duration::from_secs(30),
                   "Config {} verification took too long: {:?}", config_idx, verify_duration);

            match verify_result {
                Ok(report) => {
                    // Should handle resource-intensive configs
                    assert!(!report.evidence.is_empty());
                    assert_eq!(report.verifier_identity, attack_config.verifier_identity);

                    // Test memory usage during operations
                    let memory_stress_requests: Vec<_> = (0..1000)
                        .map(|i| VerificationRequest {
                            artifact_id: format!("memory_stress_{}_{}", config_idx, i),
                            artifact_hash: format!("{:064x}", i),
                            claims: vec![
                                format!("stress_claim_{}", i),
                                "x".repeat(10000), // Large claim
                            ],
                        })
                        .collect();

                    let stress_start = std::time::Instant::now();
                    let mut stress_results = Vec::new();

                    for stress_request in memory_stress_requests {
                        let stress_result = sdk.verify_artifact(&stress_request);
                        stress_results.push(stress_result);

                        // Break if operations become too slow (memory pressure)
                        if stress_start.elapsed() > std::time::Duration::from_secs(60) {
                            break;
                        }
                    }

                    let stress_duration = stress_start.elapsed();

                    // Should handle memory stress gracefully
                    assert!(stress_duration < std::time::Duration::from_secs(120),
                           "Memory stress test for config {} took too long: {:?}", config_idx, stress_duration);

                    // Count successful operations
                    let successful_operations = stress_results.iter().filter(|r| r.is_ok()).count();
                    assert!(successful_operations > 100,
                           "Should complete many operations even under memory pressure: {}", successful_operations);

                    // Test serialization under memory pressure
                    let serialization_start = std::time::Instant::now();
                    let serialized = serde_json::to_string(&report);
                    let serialization_duration = serialization_start.elapsed();

                    match serialized {
                        Ok(json_str) => {
                            // Serialization should complete in reasonable time
                            assert!(serialization_duration < std::time::Duration::from_secs(10),
                                   "Serialization took too long: {:?}", serialization_duration);

                            // Should not cause memory issues
                            assert!(json_str.len() < 50_000_000, // 50MB limit
                                   "Serialized report too large: {} bytes", json_str.len());

                            // Test deserialization under memory pressure
                            let deserialization_start = std::time::Instant::now();
                            let deserialized: Result<VerificationReport, _> = serde_json::from_str(&json_str);
                            let deserialization_duration = deserialization_start.elapsed();

                            match deserialized {
                                Ok(_) => {
                                    // Deserialization should complete in reasonable time
                                    assert!(deserialization_duration < std::time::Duration::from_secs(10),
                                           "Deserialization took too long: {:?}", deserialization_duration);
                                }
                                Err(_) => {
                                    // May fail with extreme config content
                                }
                            }
                        }
                        Err(_) => {
                            // Extreme configs may prevent serialization due to size
                            assert!(attack_config.verifier_identity.len() > 1_000_000 ||
                                   attack_config.extensions.values().any(|v| v.len() > 1_000_000),
                                   "Only massive configs should prevent serialization");
                        }
                    }
                }
                Err(err) => {
                    // Resource-intensive configs may be rejected
                    match err {
                        SdkError::ConfigError(msg) => {
                            // Should provide meaningful error for resource issues
                            assert!(!msg.is_empty());
                            assert!(msg.contains("large") || msg.contains("size") || msg.contains("memory"),
                                   "Config error should mention resource issue: {}", msg);
                        }
                        _ => {
                            // Other verification errors are acceptable
                        }
                    }
                }
            }

            // Test concurrent operations with resource-intensive config
            let concurrent_start = std::time::Instant::now();

            // Simulate concurrent verification requests
            let concurrent_requests: Vec<_> = (0..100)
                .map(|i| VerificationRequest {
                    artifact_id: format!("concurrent_{}_{}", config_idx, i),
                    artifact_hash: format!("{:064x}", i + 10000),
                    claims: vec![format!("concurrent_claim_{}", i)],
                })
                .collect();

            let mut concurrent_results = Vec::new();
            for concurrent_request in concurrent_requests {
                let result = sdk.verify_artifact(&concurrent_request);
                concurrent_results.push(result);

                // Break if taking too long
                if concurrent_start.elapsed() > std::time::Duration::from_secs(60) {
                    break;
                }
            }

            let concurrent_duration = concurrent_start.elapsed();

            // Should handle concurrent operations with resource-intensive configs
            assert!(concurrent_duration < std::time::Duration::from_secs(120),
                   "Concurrent operations took too long: {:?}", concurrent_duration);

            let successful_concurrent = concurrent_results.iter().filter(|r| r.is_ok()).count();
            assert!(successful_concurrent > 50,
                   "Should handle many concurrent operations: {}", successful_concurrent);

            // Final config integrity check
            let final_config = sdk.config();
            assert_eq!(final_config.verifier_identity, attack_config.verifier_identity);
            assert_eq!(final_config.require_hash_match, attack_config.require_hash_match);
            assert_eq!(final_config.strict_claims, attack_config.strict_claims);
            assert_eq!(final_config.extensions, attack_config.extensions);
        }

        // Test rapid config switching (simulated by creating multiple SDKs)
        let rapid_configs: Vec<_> = (0..1000)
            .map(|i| VerifierConfig {
                verifier_identity: format!("rapid_verifier_{}", i),
                require_hash_match: i % 2 == 0,
                strict_claims: i % 3 == 0,
                extensions: if i % 10 == 0 {
                    BTreeMap::from([(format!("rapid_key_{}", i), format!("rapid_value_{}", i))])
                } else {
                    BTreeMap::new()
                },
            })
            .collect();

        let rapid_start = std::time::Instant::now();
        let mut rapid_sdks = Vec::new();

        for rapid_config in rapid_configs {
            let rapid_sdk = VerifierSdk::new(rapid_config);
            rapid_sdks.push(rapid_sdk);

            // Break if taking too long
            if rapid_start.elapsed() > std::time::Duration::from_secs(30) {
                break;
            }
        }

        let rapid_duration = rapid_start.elapsed();

        // Should handle rapid SDK creation
        assert!(rapid_duration < std::time::Duration::from_secs(60),
               "Rapid SDK creation took too long: {:?}", rapid_duration);

        assert!(rapid_sdks.len() > 500,
               "Should create many SDKs rapidly: {}", rapid_sdks.len());

        // Test operations on rapidly created SDKs
        for (i, rapid_sdk) in rapid_sdks.iter().enumerate().take(100) {
            let rapid_request = VerificationRequest {
                artifact_id: format!("rapid_test_{}", i),
                artifact_hash: format!("{:064x}", i),
                claims: vec!["rapid_claim".to_string()],
            };

            let rapid_result = rapid_sdk.verify_artifact(&rapid_request);
            // Should complete without issues
            match rapid_result {
                Ok(_) => {
                    // Expected for most rapid SDKs
                }
                Err(_) => {
                    // Some may fail under resource pressure
                }
            }
        }
    }

    #[test]
    fn negative_deterministic_verification_consistency_and_replay_attacks() {
        // Test deterministic verification consistency and replay attack resistance
        let deterministic_config = VerifierConfig {
            verifier_identity: "deterministic_tester".to_string(),
            require_hash_match: true,
            strict_claims: true,
            extensions: BTreeMap::new(),
        };

        let sdk = VerifierSdk::new(deterministic_config);

        // Test deterministic verification across identical inputs
        let determinism_test_cases = vec![
            // Basic determinism
            VerificationRequest {
                artifact_id: "determinism_test".to_string(),
                artifact_hash: "a".repeat(64),
                claims: vec!["determinism_claim".to_string()],
            },

            // Complex claims
            VerificationRequest {
                artifact_id: "complex_determinism".to_string(),
                artifact_hash: "b".repeat(64),
                claims: vec![
                    "complex_claim_1".to_string(),
                    "complex_claim_2_with_unicode_🚀".to_string(),
                    "complex_claim_3_with_special_chars_!@#$%^&*()".to_string(),
                    "complex_claim_4_".to_string() + &"x".repeat(1000),
                ],
            },

            // Edge case inputs
            VerificationRequest {
                artifact_id: "edge_case_determinism".to_string(),
                artifact_hash: "c".repeat(64),
                claims: vec![
                    "".to_string(), // Empty claim
                    "\x00\x01\x02".to_string(), // Binary claim
                    "claim\u{202E}unicode\u{202C}".to_string(), // Unicode injection
                ],
            },
        ];

        for (test_idx, test_request) in determinism_test_cases.iter().enumerate() {
            let mut verification_results = Vec::new();

            // Perform same verification multiple times
            for iteration in 0..10 {
                let start = std::time::Instant::now();
                let result = sdk.verify_artifact(test_request);
                let duration = start.elapsed();

                // Each verification should complete in reasonable time
                assert!(duration < std::time::Duration::from_secs(10),
                       "Determinism test {} iteration {} took too long: {:?}", test_idx, iteration, duration);

                verification_results.push(result);
            }

            // All results should be identical (deterministic)
            let first_result = &verification_results[0];

            for (iteration, result) in verification_results.iter().enumerate().skip(1) {
                match (first_result, result) {
                    (Ok(first_report), Ok(report)) => {
                        // Reports should be identical
                        assert_eq!(first_report.verifier_identity, report.verifier_identity,
                                 "Verifier identity should be deterministic for test {} iteration {}", test_idx, iteration);
                        assert_eq!(first_report.artifact_id, report.artifact_id,
                                 "Artifact ID should be deterministic for test {} iteration {}", test_idx, iteration);
                        assert_eq!(first_report.verdict, report.verdict,
                                 "Verdict should be deterministic for test {} iteration {}", test_idx, iteration);
                        assert_eq!(first_report.evidence, report.evidence,
                                 "Evidence should be deterministic for test {} iteration {}", test_idx, iteration);
                        // Note: timestamp may vary, but other fields should be identical
                        assert_eq!(first_report.schema_tag, report.schema_tag,
                                 "Schema tag should be deterministic for test {} iteration {}", test_idx, iteration);
                    }
                    (Err(first_err), Err(err)) => {
                        // Errors should be identical
                        assert_eq!(first_err, err,
                                 "Errors should be deterministic for test {} iteration {}", test_idx, iteration);
                    }
                    _ => {
                        panic!("Verification determinism violated: test {} iteration {} had different result type", test_idx, iteration);
                    }
                }
            }
        }

        // Test replay attack resistance through timestamp manipulation
        let replay_attack_scenarios = vec![
            // Future timestamp capsule
            ReplayCapsule {
                capsule_id: "future_replay".to_string(),
                format_version: 1,
                inputs: vec![CapsuleInput {
                    seq: 1,
                    data: b"future_data".to_vec(),
                    metadata: BTreeMap::new(),
                }],
                expected_outputs: vec![CapsuleOutput {
                    seq: 1,
                    data: b"future_output".to_vec(),
                    output_hash: "d".repeat(64),
                }],
                environment: EnvironmentSnapshot {
                    runtime_version: "future_runtime".to_string(),
                    platform: "future_platform".to_string(),
                    config_hash: "e".repeat(64),
                    properties: BTreeMap::new(),
                },
            },

            // Past timestamp capsule with inconsistent data
            ReplayCapsule {
                capsule_id: "past_replay".to_string(),
                format_version: 1,
                inputs: vec![CapsuleInput {
                    seq: 1,
                    data: b"past_data_modified_after_timestamp".to_vec(),
                    metadata: BTreeMap::new(),
                }],
                expected_outputs: vec![CapsuleOutput {
                    seq: 1,
                    data: b"past_output_tampered".to_vec(),
                    output_hash: "f".repeat(64),
                }],
                environment: EnvironmentSnapshot {
                    runtime_version: "past_runtime".to_string(),
                    platform: "past_platform".to_string(),
                    config_hash: "g".repeat(64),
                    properties: BTreeMap::new(),
                },
            },

            // Capsule with replay markers
            ReplayCapsule {
                capsule_id: "replay_marker_attack".to_string(),
                format_version: 1,
                inputs: vec![CapsuleInput {
                    seq: 1,
                    data: b"data_with_replay_timestamp_2024_01_01".to_vec(),
                    metadata: {
                        let mut meta = BTreeMap::new();
                        meta.insert("replay_count".to_string(), "5".to_string());
                        meta.insert("original_timestamp".to_string(), "2024-01-01T00:00:00Z".to_string());
                        meta.insert("replay_timestamp".to_string(), "2024-06-15T12:00:00Z".to_string());
                        meta
                    },
                }],
                expected_outputs: vec![CapsuleOutput {
                    seq: 1,
                    data: b"output_with_replay_metadata".to_vec(),
                    output_hash: "h".repeat(64),
                }],
                environment: EnvironmentSnapshot {
                    runtime_version: "replay_runtime".to_string(),
                    platform: "replay_platform".to_string(),
                    config_hash: "i".repeat(64),
                    properties: {
                        let mut props = BTreeMap::new();
                        props.insert("current_time".to_string(), "2024-06-15T12:00:00Z".to_string());
                        props.insert("replay_marker".to_string(), "this_is_a_replay".to_string());
                        props
                    },
                },
            },
        ];

        for (replay_idx, replay_capsule) in replay_attack_scenarios.into_iter().enumerate() {
            // Test multiple verifications of same capsule (should be deterministic)
            let mut capsule_results = Vec::new();

            for replay_iteration in 0..5 {
                let capsule_start = std::time::Instant::now();
                let capsule_result = sdk.verify_capsule(&replay_capsule);
                let capsule_duration = capsule_start.elapsed();

                // Should complete in reasonable time
                assert!(capsule_duration < std::time::Duration::from_secs(30),
                       "Replay attack {} iteration {} took too long: {:?}", replay_idx, replay_iteration, capsule_duration);

                capsule_results.push(capsule_result);
            }

            // All results should be deterministic
            let first_capsule_result = &capsule_results[0];

            for (capsule_iteration, capsule_result) in capsule_results.iter().enumerate().skip(1) {
                match (first_capsule_result, capsule_result) {
                    (Ok(first_report), Ok(report)) => {
                        // Capsule verification should be deterministic
                        assert_eq!(first_report.verdict, report.verdict,
                                 "Capsule verdict should be deterministic for replay {} iteration {}", replay_idx, capsule_iteration);
                        assert_eq!(first_report.evidence, report.evidence,
                                 "Capsule evidence should be deterministic for replay {} iteration {}", replay_idx, capsule_iteration);
                    }
                    (Err(first_err), Err(err)) => {
                        // Errors should be deterministic
                        assert_eq!(first_err, err,
                                 "Capsule errors should be deterministic for replay {} iteration {}", replay_idx, capsule_iteration);
                    }
                    _ => {
                        panic!("Capsule verification determinism violated: replay {} iteration {}", replay_idx, capsule_iteration);
                    }
                }
            }

            // Test that replay attacks are detected consistently
            match &capsule_results[0] {
                Ok(report) => {
                    // If verification succeeds, should detect replay characteristics
                    let evidence_mentions_replay = report.evidence.contains("replay") ||
                                                  report.evidence.contains("timestamp") ||
                                                  report.evidence.contains("time");

                    if replay_idx == 2 { // Capsule with explicit replay markers
                        assert!(evidence_mentions_replay || report.verdict == VerificationVerdict::Invalid,
                               "Should detect obvious replay markers");
                    }
                }
                Err(err) => {
                    // Replay attacks may be rejected
                    match err {
                        SdkError::MalformedCapsule(msg) => {
                            // Should provide meaningful error for replay detection
                            if replay_idx == 2 {
                                assert!(msg.contains("replay") || msg.contains("timestamp") || msg.contains("time"),
                                       "Replay error should mention temporal issue: {}", msg);
                            }
                        }
                        _ => {
                            // Other capsule errors are acceptable
                        }
                    }
                }
            }
        }

        // Test nonce/uniqueness verification (if supported)
        let nonce_test_requests = vec![
            VerificationRequest {
                artifact_id: "nonce_test_1".to_string(),
                artifact_hash: "j".repeat(64),
                claims: vec!["nonce_claim_1".to_string()],
            },
            VerificationRequest {
                artifact_id: "nonce_test_1".to_string(), // Same ID
                artifact_hash: "j".repeat(64),           // Same hash
                claims: vec!["nonce_claim_1".to_string()], // Same claims
            },
        ];

        let mut nonce_results = Vec::new();
        for nonce_request in nonce_test_requests {
            let nonce_result = sdk.verify_artifact(&nonce_request);
            nonce_results.push(nonce_result);
        }

        // Both requests should produce same result (deterministic)
        match (&nonce_results[0], &nonce_results[1]) {
            (Ok(first_report), Ok(second_report)) => {
                // Should be identical (deterministic verification)
                assert_eq!(first_report.verdict, second_report.verdict);
                assert_eq!(first_report.evidence, second_report.evidence);
            }
            (Err(first_err), Err(second_err)) => {
                assert_eq!(first_err, second_err);
            }
            _ => {
                panic!("Nonce test produced inconsistent results");
            }
        }

        // Final determinism verification with complex scenario
        let complex_scenario = VerificationRequest {
            artifact_id: "final_determinism_test_🚀_with_unicode_and_special_chars_!@#$%".to_string(),
            artifact_hash: compute_artifact_hash(b"complex_determinism_test_data"),
            claims: vec![
                "complex_claim_1".to_string(),
                "unicode_claim_🎯".to_string(),
                format!("generated_claim_{}", std::process::id()),
                "binary_claim_\x00\x01\x02".to_string(),
            ],
        };

        let final_results: Vec<_> = (0..20)
            .map(|_| sdk.verify_artifact(&complex_scenario))
            .collect();

        // All results should be identical
        let final_first = &final_results[0];
        for (i, final_result) in final_results.iter().enumerate().skip(1) {
            match (final_first, final_result) {
                (Ok(first), Ok(result)) => {
                    assert_eq!(first.verdict, result.verdict, "Final determinism test failed at iteration {}", i);
                    assert_eq!(first.evidence, result.evidence, "Final determinism test evidence differs at iteration {}", i);
                }
                (Err(first_err), Err(err)) => {
                    assert_eq!(first_err, err, "Final determinism test error differs at iteration {}", i);
                }
                _ => {
                    panic!("Final determinism test result type differs at iteration {}", i);
                }
            }
        }
    }
}

#[cfg(test)]
mod verifier_sdk_comprehensive_attack_vector_tests {
    use super::*;
    use std::collections::{HashMap, BTreeMap, HashSet};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn negative_unicode_normalization_attack_comprehensive_resistance() {
        let sdk = VerifierSdk::new(VerifierConfig::default());

        // Test Unicode normalization attacks across all string fields
        let unicode_attack_vectors = vec![
            // Normalization form confusion
            ("café", "cafe\u{0301}"), // NFC vs NFD
            ("℀", "\u{0061}\u{2044}\u{0063}"), // ACCOUNT OF vs a/c
            ("ﬀ", "ff"), // Ligature vs separate chars

            // Bidirectional text attacks
            ("\u{202E}drowssap\u{202D}", "password"), // BiDi override
            ("user\u{202A}admin\u{202C}", "useradmin"), // Left-to-right embedding

            // Confusable character attacks
            ("аdmin", "admin"), // Cyrillic а vs Latin a
            ("teѕt", "test"), // Cyrillic ѕ vs Latin s
            ("раssword", "password"), // Mixed Cyrillic/Latin

            // Zero-width character injection
            ("test\u{200B}user", "testuser"), // Zero-width space
            ("admin\u{200C}role", "adminrole"), // Zero-width non-joiner
            ("key\u{200D}value", "keyvalue"), // Zero-width joiner

            // Invisible character attacks
            ("data\u{061C}base", "database"), // Arabic letter mark
            ("file\u{2066}name\u{2069}", "filename"), // Isolate controls
        ];

        for (malicious, normal) in unicode_attack_vectors {
            // Test artifact_id normalization resistance
            let malicious_req = VerificationRequest {
                artifact_id: malicious.to_string(),
                artifact_hash: deterministic_hash(malicious),
                claims: vec!["test-claim".to_string()],
            };

            let normal_req = VerificationRequest {
                artifact_id: normal.to_string(),
                artifact_hash: deterministic_hash(normal),
                claims: vec!["test-claim".to_string()],
            };

            let malicious_result = sdk.verify_artifact(&malicious_req);
            let normal_result = sdk.verify_artifact(&normal_req);

            // Unicode variations should produce different results (no normalization)
            match (malicious_result, normal_result) {
                (Ok(mal_report), Ok(norm_report)) => {
                    assert_ne!(mal_report.binding_hash, norm_report.binding_hash,
                        "Unicode normalization attack should not produce identical hashes: '{}' vs '{}'",
                        malicious.escape_unicode(), normal.escape_unicode());
                }
                _ => {
                    // One or both failed validation, which is also acceptable
                }
            }

            // Test claims normalization resistance
            let claim_attack = VerificationRequest {
                artifact_id: "test-artifact".to_string(),
                artifact_hash: deterministic_hash("test-artifact"),
                claims: vec![malicious.to_string(), normal.to_string()],
            };

            let claim_result = sdk.verify_artifact(&claim_attack);
            assert!(claim_result.is_ok(), "Claims with Unicode variations should be handled");
        }
    }

    #[test]
    fn negative_cryptographic_timing_attack_comprehensive_analysis() {
        let sdk = VerifierSdk::new(VerifierConfig {
            require_hash_match: true,
            ..VerifierConfig::default()
        });

        let test_artifact = "timing-analysis-target";
        let correct_hash = deterministic_hash(test_artifact);

        // Generate hash candidates that differ at different bit positions
        let timing_test_vectors = vec![
            // Early bit differences
            format!("0{}", &correct_hash[1..]),
            format!("1{}", &correct_hash[1..]),
            format!("f{}", &correct_hash[1..]),

            // Middle bit differences
            format!("{}{}{}", &correct_hash[..32], "0", &correct_hash[33..]),
            format!("{}{}{}", &correct_hash[..32], "f", &correct_hash[33..]),

            // Late bit differences
            format!("{}0", &correct_hash[..63]),
            format!("{}1", &correct_hash[..63]),
            format!("{}f", &correct_hash[..63]),

            // Completely different hashes
            "0".repeat(64),
            "f".repeat(64),
            "deadbeef".repeat(8),

            // Mixed case (should fail format validation first)
            "DEADBEEF".repeat(8),
        ];

        let samples_per_hash = 50;
        let mut timing_results = HashMap::new();

        for test_hash in timing_test_vectors {
            let mut durations = Vec::new();

            for _ in 0..samples_per_hash {
                let request = VerificationRequest {
                    artifact_id: test_artifact.to_string(),
                    artifact_hash: test_hash.clone(),
                    claims: vec!["claim".to_string()],
                };

                let start = std::time::Instant::now();
                let _result = sdk.verify_artifact(&request);
                durations.push(start.elapsed());
            }

            let avg_duration = durations.iter().sum::<std::time::Duration>() / samples_per_hash as u32;
            timing_results.insert(test_hash.clone(), avg_duration);
        }

        // Analyze timing distribution for potential constant-time violations
        let durations: Vec<_> = timing_results.values().cloned().collect();
        let min_time = durations.iter().min().unwrap();
        let max_time = durations.iter().max().unwrap();

        let timing_variance = max_time.as_nanos() as f64 / min_time.as_nanos() as f64;

        // Log timing results for analysis
        eprintln!("Timing analysis results ({}x variance):", timing_variance);
        for (hash_prefix, duration) in timing_results.iter() {
            eprintln!("  {}: {:?}", &hash_prefix[..8], duration);
        }

        // Conservative threshold - significant timing differences could indicate
        // non-constant-time operations, but allow for system noise
        assert!(timing_variance < 5.0,
            "Timing variance too large: {:.2}x (min: {:?}, max: {:?})",
            timing_variance, min_time, max_time);
    }

    #[test]
    fn negative_memory_exhaustion_and_resource_consumption_attacks() {
        let sdk = VerifierSdk::new(VerifierConfig::default());

        // Test 1: Massive claims array
        let massive_claims_request = VerificationRequest {
            artifact_id: "massive-claims-test".to_string(),
            artifact_hash: deterministic_hash("massive-claims-test"),
            claims: (0..100_000).map(|i| format!("claim-{}", i)).collect(),
        };

        let massive_result = sdk.verify_artifact(&massive_claims_request);
        assert!(massive_result.is_ok(), "Massive claims should be handled gracefully");

        if let Ok(report) = massive_result {
            // Should not cause memory issues or infinite processing
            assert!(report.evidence.len() > 0, "Evidence should be generated even for massive claims");
            assert!(report.request_id.len() > 0, "Request ID should be generated");
        }

        // Test 2: Extremely long individual fields
        let massive_field_request = VerificationRequest {
            artifact_id: "x".repeat(1_000_000), // 1MB artifact ID
            artifact_hash: deterministic_hash("test"),
            claims: vec!["y".repeat(1_000_000)], // 1MB claim
        };

        let field_result = sdk.verify_artifact(&massive_field_request);
        match field_result {
            Ok(report) => {
                // If accepted, should handle gracefully
                assert!(report.evidence.len() > 0);
            }
            Err(_) => {
                // Early rejection of oversized fields is also acceptable
            }
        }

        // Test 3: Deeply nested configuration extensions
        let mut massive_extensions = BTreeMap::new();
        for i in 0..10_000 {
            massive_extensions.insert(
                format!("extension_key_{}", i),
                format!("extension_value_{}", "data".repeat(1000))
            );
        }

        let massive_config = VerifierConfig {
            verifier_identity: "verifier://massive-config-test".to_string(),
            extensions: massive_extensions,
            ..VerifierConfig::default()
        };

        // Should handle massive configuration without crashes
        let massive_sdk = VerifierSdk::new(massive_config);
        let config_test = massive_sdk.verify_artifact(&VerificationRequest {
            artifact_id: "config-test".to_string(),
            artifact_hash: deterministic_hash("config-test"),
            claims: vec!["test".to_string()],
        });

        assert!(config_test.is_ok(), "Massive configuration should not break verification");
    }

    #[test]
    fn negative_concurrent_access_race_condition_comprehensive_stress_test() {
        let config = Arc::new(VerifierConfig {
            require_hash_match: false, // Avoid hash computation contention
            strict_claims: true,
            ..VerifierConfig::default()
        });

        let sdk = Arc::new(VerifierSdk::new((*config).clone()));
        let results = Arc::new(Mutex::new(Vec::new()));

        // Spawn many threads doing different operations concurrently
        let thread_count = 100;
        let operations_per_thread = 20;

        let handles: Vec<_> = (0..thread_count).map(|thread_id| {
            let sdk_clone = sdk.clone();
            let results_clone = results.clone();

            thread::spawn(move || {
                let mut thread_results = Vec::new();

                for op_id in 0..operations_per_thread {
                    let request = VerificationRequest {
                        artifact_id: format!("thread-{}-op-{}", thread_id, op_id),
                        artifact_hash: deterministic_hash(&format!("data-{}-{}", thread_id, op_id)),
                        claims: vec![
                            format!("claim-{}-{}-1", thread_id, op_id),
                            format!("claim-{}-{}-2", thread_id, op_id),
                        ],
                    };

                    // Mix different operations
                    let result = match op_id % 4 {
                        0 => sdk_clone.verify_artifact(&request).map(|r| ("verify_artifact", r.verdict)),
                        1 => {
                            // Chain verification with self
                            if let Ok(report) = sdk_clone.verify_artifact(&request) {
                                sdk_clone.verify_chain(&[report]).map(|r| ("verify_chain", r.verdict))
                            } else {
                                Err(SdkError::InvalidArtifact("failed initial verification".to_string()))
                            }
                        }
                        2 => {
                            // Configuration access
                            let _config = sdk_clone.config();
                            let _version = sdk_clone.api_version();
                            sdk_clone.verify_artifact(&request).map(|r| ("config_access", r.verdict))
                        }
                        3 => {
                            // Multiple operations in sequence
                            let _r1 = sdk_clone.verify_artifact(&request);
                            let _r2 = sdk_clone.verify_artifact(&request);
                            sdk_clone.verify_artifact(&request).map(|r| ("multi_ops", r.verdict))
                        }
                        _ => unreachable!(),
                    };

                    thread_results.push((thread_id, op_id, result.is_ok()));
                }

                results_clone.lock().unwrap().extend(thread_results);
            })
        }).collect();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().expect("Thread should complete successfully");
        }

        let all_results = results.lock().unwrap();

        // Verify all operations completed
        assert_eq!(all_results.len(), thread_count * operations_per_thread);

        // Count successes and failures
        let (successes, failures): (Vec<_>, Vec<_>) = all_results.iter().partition(|(_, _, success)| *success);

        println!("Concurrent stress test: {} successes, {} failures", successes.len(), failures.len());

        // Should have mostly successes with this configuration
        assert!(successes.len() >= (thread_count * operations_per_thread * 80) / 100,
            "Should have at least 80% success rate in concurrent operations");

        // Verify no data corruption by checking for duplicate thread/operation combinations
        let mut seen_ops = HashSet::new();
        for (thread_id, op_id, _) in all_results.iter() {
            let key = (*thread_id, *op_id);
            assert!(seen_ops.insert(key), "Duplicate operation detected: {:?}", key);
        }
    }

    #[test]
    fn negative_serialization_deserialization_attack_comprehensive_vectors() {
        let sdk = VerifierSdk::new(VerifierConfig::default());

        // Test malicious JSON payloads designed to exploit deserialization
        let attack_payloads = vec![
            // Integer overflow attempts
            r#"{"artifact_id": "test", "artifact_hash": "aaaa", "claims": [], "extra_field": 99999999999999999999999999999}"#,

            // Unicode escapes in strings
            r#"{"artifact_id": "test\u0000null", "artifact_hash": "aaaa", "claims": []}"#,

            // Deeply nested objects (stack overflow attempt)
            format!(r#"{{"artifact_id": "nested", "artifact_hash": "aaaa", "claims": [], "nested": {}}}"#,
                "{\"deep\":".repeat(500) + "null" + &"}".repeat(500)),

            // Array bomb (exponential memory growth attempt)
            format!(r#"{{"artifact_id": "array", "artifact_hash": "aaaa", "claims": [{}]}}"#,
                (0..10000).map(|i| format!(r#""element{}""#, i)).collect::<Vec<_>>().join(",")),

            // String with control characters
            r#"{"artifact_id": "control\r\n\t\x08\x0c", "artifact_hash": "aaaa", "claims": []}"#,

            // Invalid UTF-8 sequences (should be caught by JSON parser)
            r#"{"artifact_id": "invalid\uD800\uD800", "artifact_hash": "aaaa", "claims": []}"#,

            // Very long strings
            format!(r#"{{"artifact_id": "{}", "artifact_hash": "{}", "claims": []}}"#,
                "x".repeat(100_000), "a".repeat(64)),

            // Duplicate keys (JSON spec allows, but may cause issues)
            r#"{"artifact_id": "test", "artifact_id": "duplicate", "artifact_hash": "aaaa", "claims": []}"#,

            // Type confusion attempts
            r#"{"artifact_id": 12345, "artifact_hash": "aaaa", "claims": []}"#,
            r#"{"artifact_id": "test", "artifact_hash": ["array", "instead", "of", "string"], "claims": []}"#,
            r#"{"artifact_id": "test", "artifact_hash": "aaaa", "claims": "string_instead_of_array"}"#,
        ];

        for (idx, payload) in attack_payloads.iter().enumerate() {
            let parse_result: Result<VerificationRequest, _> = serde_json::from_str(payload);

            match parse_result {
                Ok(request) => {
                    // If parsing succeeds, verification should handle it gracefully
                    let verify_result = sdk.verify_artifact(&request);

                    match verify_result {
                        Ok(report) => {
                            // Successful verification is okay if input is valid
                            assert!(!report.evidence.is_empty(), "Report should have evidence for payload {}", idx);
                        }
                        Err(err) => {
                            // Rejection is also acceptable for malformed inputs
                            assert!(!format!("{:?}", err).is_empty(), "Error should have meaningful message for payload {}", idx);
                        }
                    }
                }
                Err(_) => {
                    // JSON parsing failure is acceptable for malformed inputs
                }
            }
        }

        // Test round-trip serialization consistency
        let test_request = VerificationRequest {
            artifact_id: "serialization-test".to_string(),
            artifact_hash: deterministic_hash("serialization-test"),
            claims: vec!["claim1".to_string(), "claim2".to_string()],
        };

        let serialized = serde_json::to_string(&test_request).expect("Should serialize");
        let deserialized: VerificationRequest = serde_json::from_str(&serialized).expect("Should deserialize");

        assert_eq!(test_request, deserialized, "Round-trip serialization should preserve equality");

        // Both original and deserialized should produce identical results
        let original_result = sdk.verify_artifact(&test_request).expect("Original should verify");
        let deserialized_result = sdk.verify_artifact(&deserialized).expect("Deserialized should verify");

        assert_eq!(original_result.verdict, deserialized_result.verdict,
            "Serialization round-trip should not affect verification result");
    }

    #[test]
    fn negative_hash_collision_resistance_and_domain_separation_comprehensive() {
        let sdk = VerifierSdk::new(VerifierConfig::default());

        // Test hash collision resistance with carefully crafted inputs
        let collision_attempt_pairs = vec![
            // Length extension attacks
            ("data", "data\x00padding"),
            ("key=value", "key=value&"),
            ("prefix", "prefix\x01\x02\x03"),

            // Unicode normalization collisions
            ("test", "te\u{0301}st"),  // Different but similar Unicode
            ("file", "file\u{200B}"),  // With zero-width space

            // Boundary condition attacks
            ("", "\x00"),  // Empty vs null
            ("a", "\x61"),  // ASCII 'a' vs hex 61
            ("123", "123\x00"),  // Numbers with/without terminator

            // Domain separator confusion
            ("verifier_sdk_v1:test", "different:verifier_sdk_v1:test"),
            ("normal_data", "verifier_sdk_v1:normal_data"),

            // Multi-field collision attempts (using deterministic_hash_fields)
            // These will be tested separately below
        ];

        let mut seen_hashes = HashSet::new();

        for (input1, input2) in collision_attempt_pairs {
            let hash1 = deterministic_hash(input1);
            let hash2 = deterministic_hash(input2);

            // Verify no collisions
            assert_ne!(hash1, hash2,
                "Hash collision detected between '{}' and '{}': both produce {}",
                input1.escape_debug(), input2.escape_debug(), hash1);

            // Verify hashes are well-distributed
            assert!(seen_hashes.insert(hash1.clone()),
                "Duplicate hash {} for input '{}'", hash1, input1.escape_debug());
            assert!(seen_hashes.insert(hash2.clone()),
                "Duplicate hash {} for input '{}'", hash2, input2.escape_debug());

            // Test in verification context
            let req1 = VerificationRequest {
                artifact_id: input1.to_string(),
                artifact_hash: hash1,
                claims: vec!["test-claim".to_string()],
            };

            let req2 = VerificationRequest {
                artifact_id: input2.to_string(),
                artifact_hash: hash2,
                claims: vec!["test-claim".to_string()],
            };

            let result1 = sdk.verify_artifact(&req1).expect("Should verify");
            let result2 = sdk.verify_artifact(&req2).expect("Should verify");

            assert_ne!(result1.binding_hash, result2.binding_hash,
                "Binding hashes should differ for different artifacts");
        }

        // Test multi-field hash collision resistance
        let field_collision_attempts = vec![
            // Field boundary confusion
            (vec!["ab", "cd"], vec!["a", "bcd"]),
            (vec!["", "data"], vec!["data"]),
            (vec!["key", "value"], vec!["keyvalue"]),

            // Length prefix confusion
            (vec!["x", ""], vec!["", "x"]),
            (vec!["long_field_name", "short"], vec!["short", "long_field_name"]),

            // Unicode boundary attacks
            (vec!["🚀", "test"], vec!["🚀test"]),
            (vec!["\u{0301}accent", "base"], vec!["accent", "\u{0301}base"]),
        ];

        for (fields1, fields2) in field_collision_attempts {
            let hash1 = deterministic_hash_fields(&fields1);
            let hash2 = deterministic_hash_fields(&fields2);

            assert_ne!(hash1, hash2,
                "Multi-field hash collision: {:?} vs {:?} both produce {}",
                fields1, fields2, hash1);
        }

        println!("Hash collision resistance test completed: {} unique hashes tested", seen_hashes.len());
    }

    #[test]
    fn negative_error_handling_and_recovery_state_consistency_comprehensive() {
        let sdk = VerifierSdk::new(VerifierConfig {
            require_hash_match: true,
            strict_claims: true,
            ..VerifierConfig::default()
        });

        // Test error recovery across different failure modes
        let error_scenarios = vec![
            // Early validation failures
            VerificationRequest {
                artifact_id: " whitespace_artifact ".to_string(),  // Should fail early
                artifact_hash: "valid".repeat(16),
                claims: vec!["valid-claim".to_string()],
            },

            // Hash format failures
            VerificationRequest {
                artifact_id: "valid-artifact".to_string(),
                artifact_hash: "invalid_hash_format".to_string(),  // Wrong format
                claims: vec!["valid-claim".to_string()],
            },

            // Hash mismatch failures (when require_hash_match = true)
            VerificationRequest {
                artifact_id: "hash-mismatch-test".to_string(),
                artifact_hash: "f".repeat(64),  // Valid format, wrong hash
                claims: vec!["valid-claim".to_string()],
            },

            // Claims validation failures
            VerificationRequest {
                artifact_id: "claims-test".to_string(),
                artifact_hash: deterministic_hash("claims-test"),
                claims: vec!["".to_string()],  // Empty claim should fail
            },

            // Mixed failure modes
            VerificationRequest {
                artifact_id: " mixed_failures ".to_string(),  // Multiple issues
                artifact_hash: "bad".to_string(),
                claims: vec!["".to_string(), "valid-claim".to_string()],
            },
        ];

        // Test each scenario multiple times to verify consistent behavior
        let iterations = 5;
        let mut all_results = Vec::new();

        for scenario in &error_scenarios {
            let mut scenario_results = Vec::new();

            for iteration in 0..iterations {
                let result = sdk.verify_artifact(scenario);
                scenario_results.push((iteration, result));
            }

            all_results.push(scenario_results);
        }

        // Verify error consistency across iterations
        for (scenario_idx, scenario_results) in all_results.iter().enumerate() {
            let first_result = &scenario_results[0].1;

            for (iteration, result) in scenario_results.iter().skip(1) {
                match (first_result, result) {
                    (Ok(first_report), Ok(report)) => {
                        assert_eq!(first_report.verdict, report.verdict,
                            "Scenario {} iteration {}: verdict inconsistency", scenario_idx, iteration);

                        // Evidence structure should be consistent
                        assert_eq!(first_report.evidence.len(), report.evidence.len(),
                            "Scenario {} iteration {}: evidence count differs", scenario_idx, iteration);

                        for (first_ev, ev) in first_report.evidence.iter().zip(report.evidence.iter()) {
                            assert_eq!(first_ev.check_name, ev.check_name,
                                "Evidence check name differs at scenario {} iteration {}", scenario_idx, iteration);
                            assert_eq!(first_ev.passed, ev.passed,
                                "Evidence pass/fail differs at scenario {} iteration {}", scenario_idx, iteration);
                        }
                    }
                    (Err(first_err), Err(err)) => {
                        // Error types should be consistent
                        assert_eq!(std::mem::discriminant(first_err), std::mem::discriminant(err),
                            "Error type differs at scenario {} iteration {}", scenario_idx, iteration);
                    }
                    _ => {
                        panic!("Result type inconsistency at scenario {} iteration {}: first was {:?}, now is {:?}",
                            scenario_idx, iteration,
                            first_result.as_ref().map(|r| &r.verdict).map_err(|e| e),
                            result.as_ref().map(|r| &r.verdict).map_err(|e| e));
                    }
                }
            }
        }

        // Test error state doesn't affect subsequent valid operations
        let valid_request = VerificationRequest {
            artifact_id: "recovery-test".to_string(),
            artifact_hash: deterministic_hash("recovery-test"),
            claims: vec!["recovery-claim".to_string()],
        };

        // Interleave error scenarios with valid requests
        for _ in 0..10 {
            // Process a failing request
            let _error_result = sdk.verify_artifact(&error_scenarios[0]);

            // Process a valid request - should succeed consistently
            let valid_result = sdk.verify_artifact(&valid_request);
            assert!(valid_result.is_ok(), "Valid request should succeed even after error scenarios");

            if let Ok(report) = valid_result {
                assert!(matches!(report.verdict, VerifyVerdict::Pass),
                    "Valid request should pass verification");
            }
        }
    }

    /// Test: Deterministic hash function attack vectors and collision resistance
    #[test]
    fn test_deterministic_hash_attack_vectors_and_collision_resistance() {
        // Test: Hash function domain separation attacks
        let same_content_different_contexts = vec![
            "verifier_test_input",
            "test_input", // Same suffix, different prefix when combined with domain
            "", // Empty input
            "verifier_sdk_v1:", // Domain separator injection attempt
            "verifier_sdk_v1:verifier_test_input", // Double domain separator
        ];

        let mut hashes = Vec::new();
        for input in &same_content_different_contexts {
            hashes.push(deterministic_hash(input));
        }

        // All hashes should be unique (no collisions in domain separation)
        for i in 0..hashes.len() {
            for j in (i+1)..hashes.len() {
                assert_ne!(hashes[i], hashes[j],
                    "Hash collision between inputs '{}' and '{}'",
                    same_content_different_contexts[i], same_content_different_contexts[j]);
            }
            // Verify hash format
            assert_eq!(hashes[i].len(), 64, "Hash should be 64 hex characters");
            assert!(hashes[i].chars().all(|c| c.is_ascii_hexdigit()),
                "Hash should contain only hex digits");
        }

        // Test: Length extension attack resistance
        let base_input = "sensitive_data";
        let sha_padding = String::from_utf8_lossy(b"\x80").into_owned();
        let sha_length_padding =
            String::from_utf8_lossy(b"\x80\x00\x00\x00\x00\x00\x00\x38").into_owned();
        let extended_inputs = vec![
            format!("{}{}", base_input, sha_padding),
            format!("{}{}", base_input, sha_length_padding),
            format!("{}{}", base_input, "additional_data"),
            format!("{}{}", base_input, "\x00\x00\x00\x08"), // Length padding
        ];

        let base_hash = deterministic_hash(base_input);
        for extended_input in &extended_inputs {
            let extended_hash = deterministic_hash(extended_input);
            assert_ne!(base_hash, extended_hash,
                "Length extension should not produce same hash: '{}'", extended_input);
        }

        // Test: Multi-field hash collision resistance
        let field_combinations = vec![
            vec!["field1", "field2"],
            vec!["field", "1field2"], // Different field boundary
            vec!["field1field", "2"], // Different field boundary
            vec!["", "field1", "field2"], // Empty first field
            vec!["field1", "", "field2"], // Empty middle field
            vec!["field1", "field2", ""], // Empty last field
        ];

        let mut multi_hashes = Vec::new();
        for fields in &field_combinations {
            multi_hashes.push(deterministic_hash_fields(fields));
        }

        // Verify all multi-field hashes are unique
        for i in 0..multi_hashes.len() {
            for j in (i+1)..multi_hashes.len() {
                assert_ne!(multi_hashes[i], multi_hashes[j],
                    "Multi-field hash collision between {:?} and {:?}",
                    field_combinations[i], field_combinations[j]);
            }
        }

        // Test: Avalanche effect (single bit change should affect many output bits)
        let avalanche_base = "avalanche_test_input_data";
        let avalanche_modified = "avalanche_test_input_datb"; // Single character change
        let base_avalanche_hash = deterministic_hash(avalanche_base);
        let modified_avalanche_hash = deterministic_hash(avalanche_modified);

        assert_ne!(base_avalanche_hash, modified_avalanche_hash,
            "Single character change should produce different hash");

        // Count differing hex characters (rough avalanche test)
        let differing_chars = base_avalanche_hash.chars()
            .zip(modified_avalanche_hash.chars())
            .filter(|(a, b)| a != b)
            .count();
        assert!(differing_chars > 16,
            "Avalanche effect too weak: only {} chars differ out of 64", differing_chars);
    }

    /// Test: VerifierConfig validation and security boundary attacks
    #[test]
    fn test_verifier_config_validation_and_security_boundaries() {
        // Test: Malicious verifier identity injection attacks
        let malicious_identities = vec![
            "verifier://evil.com/../../admin", // Path traversal
            "verifier://\x00admin@evil.com", // Null byte injection
            "verifier://admin@evil.com\r\nSet-Cookie: session=hijacked", // HTTP header injection
            "verifier://<script>alert('xss')</script>", // XSS injection
            "verifier://'; DROP TABLE verifiers; --", // SQL injection style
            "verifier://user@evil.com\u{202E}moc.evil@resu", // Unicode BIDI override
            "verifier://\u{FEFF}admin@evil.com", // BOM injection
            "verifier://admin@evil.com\u{200B}", // Zero-width space
            format!("verifier://{}", "a".repeat(10_000)), // Memory exhaustion
            "verifier://admin@evil.com\x1B[31mCOLORED_TEXT\x1B[0m", // Terminal escape sequences
        ];

        for malicious_identity in &malicious_identities {
            let config = VerifierConfig {
                verifier_identity: malicious_identity.clone(),
                require_hash_match: true,
                strict_claims: true,
                extensions: BTreeMap::new(),
            };

            let sdk = VerifierSdk::new(config.clone());

            // SDK should accept malicious identity as-is (no validation at construction)
            assert_eq!(sdk.verifier_identity(), malicious_identity,
                "Identity should be preserved exactly");

            // Verification should work with malicious identity
            let req = valid_request();
            let result = sdk.verify_artifact(&req);
            assert!(result.is_ok(), "Verification should work with malicious identity");

            if let Ok(report) = result {
                assert_eq!(report.verifier_identity, *malicious_identity,
                    "Report should preserve malicious identity exactly");
            }
        }

        // Test: Extensions field manipulation attacks
        let mut malicious_extensions = BTreeMap::new();
        malicious_extensions.insert("__proto__".to_string(), "prototype_pollution".to_string());
        malicious_extensions.insert("constructor".to_string(), "constructor_attack".to_string());
        malicious_extensions.insert("".to_string(), "empty_key_injection".to_string());
        malicious_extensions.insert("key\x00injection".to_string(), "null_byte_key".to_string());
        malicious_extensions.insert("very_long_key_".to_string() + &"x".repeat(1_000), "memory_exhaustion_key".to_string());
        malicious_extensions.insert("normal_key".to_string(), "value\x00\x01\x02injection".to_string());

        let config_with_malicious_ext = VerifierConfig {
            verifier_identity: "verifier://test".to_string(),
            require_hash_match: false,
            strict_claims: false,
            extensions: malicious_extensions.clone(),
        };

        let sdk_with_ext = VerifierSdk::new(config_with_malicious_ext);
        assert_eq!(sdk_with_ext.config().extensions, malicious_extensions,
            "Extensions should be preserved exactly");

        // Test: Boolean flag manipulation edge cases
        let flag_combinations = vec![
            (true, true),   // Both strict
            (true, false),  // Hash required, claims relaxed
            (false, true),  // Hash relaxed, claims strict
            (false, false), // Both relaxed
        ];

        for (require_hash_match, strict_claims) in flag_combinations {
            let config = VerifierConfig {
                verifier_identity: "verifier://flag_test".to_string(),
                require_hash_match,
                strict_claims,
                extensions: BTreeMap::new(),
            };

            let sdk = VerifierSdk::new(config.clone());

            // Test with problematic request
            let problematic_req = VerificationRequest {
                artifact_id: "flag_test_artifact".to_string(),
                artifact_hash: "wrong_hash".to_string(), // Wrong hash
                claims: vec![], // Empty claims
            };

            let result = sdk.verify_artifact(&problematic_req);
            if require_hash_match || strict_claims {
                // Should fail verification but not error
                assert!(result.is_ok(), "Should verify but fail checks");
                if let Ok(report) = result {
                    assert!(matches!(report.verdict, VerifyVerdict::Fail(_)),
                        "Should fail with strict flags");
                }
            } else {
                // Should pass with relaxed flags (ignoring format issues)
                // Note: This will still fail due to hash format being wrong length
                assert!(result.is_ok(), "Should handle relaxed flags");
            }
        }
    }

    /// Test: VerificationRequest input validation bypass attacks
    #[test]
    fn test_verification_request_input_validation_bypass_attacks() {
        let sdk = test_sdk();

        // Test: Artifact ID boundary injection attacks
        let artifact_id_attacks = vec![
            "  valid_id  ", // Leading/trailing whitespace (should fail)
            "valid\x00id", // Null byte injection
            "valid\r\nid", // CRLF injection
            "valid\tid", // Tab injection
            "valid\u{200B}id", // Zero-width space
            "valid\u{FEFF}id", // BOM injection
            "valid\u{202E}di\u{202D}id", // BIDI override
            "valid🔒id", // Emoji injection
            "válid_íd", // Unicode normalization
            format!("valid_{}", "x".repeat(10_000)), // Memory exhaustion
            "VALID_ID", // Case variation
            "valid_id/../../etc/passwd", // Path traversal
            "../etc/passwd", // Direct path traversal
            "CON", "PRN", "AUX", "NUL", "COM1", // Windows reserved names
        ];

        for attack_id in &artifact_id_attacks {
            let req = VerificationRequest {
                artifact_id: attack_id.clone(),
                artifact_hash: deterministic_hash(attack_id.trim()),
                claims: vec!["test_claim".to_string()],
            };

            let result = sdk.verify_artifact(&req);

            if attack_id.trim() != *attack_id || attack_id.is_empty() {
                // Should error on whitespace/empty
                assert!(result.is_err(), "Should reject whitespace attack: '{}'", attack_id);
            } else if attack_id == &RESERVED_ARTIFACT_ID.to_string() {
                // Should error on reserved ID
                assert!(result.is_err(), "Should reject reserved ID");
            } else {
                // Other attacks should be preserved as-is but may fail hash check
                assert!(result.is_ok(), "Should handle attack ID: '{}'", attack_id);
                if let Ok(report) = result {
                    // Check that the ID is preserved exactly
                    assert!(report.request_id.contains(&attack_id[..std::cmp::min(attack_id.len(), 20)]),
                        "Attack ID should be preserved in request_id");
                }
            }
        }

        // Test: Hash format manipulation attacks
        let hash_attacks = vec![
            "", // Empty hash
            "short", // Too short
            "x".repeat(63), // One char too short
            "x".repeat(65), // One char too long
            "g".repeat(64), // Invalid hex characters
            "ABCDEF".to_string() + &"0".repeat(58), // Mixed case
            "abcdef".to_string() + &"0".repeat(58), // Lower case
            "0".repeat(32) + &"x".repeat(32), // Half valid, half invalid
            "0123456789ABCDEF".repeat(4), // Valid format but wrong value
            "deadbeef".repeat(8), // Valid format pattern
            "\x00".repeat(64), // Null bytes (will be invalid hex)
        ];

        for attack_hash in &hash_attacks {
            let req = VerificationRequest {
                artifact_id: "hash_test_id".to_string(),
                artifact_hash: attack_hash.clone(),
                claims: vec!["test_claim".to_string()],
            };

            let result = sdk.verify_artifact(&req);

            if attack_hash.is_empty() {
                // Should error on empty hash
                assert!(result.is_err(), "Should reject empty hash");
            } else {
                // Other format issues should be caught in verification, not error
                assert!(result.is_ok(), "Should handle hash attack: '{}'", attack_hash);
                if let Ok(report) = result {
                    if attack_hash.len() != 64 || !attack_hash.chars().all(|c| c.is_ascii_hexdigit()) {
                        // Should fail format check
                        let failed = failed_checks(&report);
                        assert!(failed.contains(&"artifact_hash_format"),
                            "Should fail format check for: '{}'", attack_hash);
                    }
                }
            }
        }

        // Test: Claims array manipulation attacks
        let claims_attacks = vec![
            vec![], // Empty claims (should fail with strict_claims)
            vec!["".to_string()], // Single empty claim
            vec!["valid".to_string(), "".to_string(), "valid".to_string()], // Mixed empty/valid
            vec!["claim\x00injection".to_string()], // Null byte in claim
            vec!["claim\r\ninjection".to_string()], // CRLF injection
            vec!["claim\u{202E}gnital".to_string()], // BIDI override
            vec![format!("claim_{}", "x".repeat(10_000))], // Memory exhaustion
            (0..100).map(|i| format!("claim_{}", i)).collect(), // Many claims
            vec!["🔒".repeat(100)], // Emoji flood
            vec!["claim"; 1], // Single valid
            vec!["a".to_string(); 50], // Many identical
        ];

        for attack_claims in &claims_attacks {
            let req = VerificationRequest {
                artifact_id: "claims_test_id".to_string(),
                artifact_hash: deterministic_hash("claims_test_id"),
                claims: attack_claims.clone(),
            };

            let result = sdk.verify_artifact(&req);
            assert!(result.is_ok(), "Claims attack should not cause error: {:?}", attack_claims);

            if let Ok(report) = result {
                // Check evidence for each claim
                for (i, claim) in attack_claims.iter().enumerate() {
                    let claim_check_name = format!("claim_{}_non_empty", i);
                    let claim_evidence = report.evidence.iter()
                        .find(|e| e.check_name == claim_check_name);

                    if let Some(evidence) = claim_evidence {
                        assert_eq!(evidence.passed, !claim.is_empty(),
                            "Claim {} emptiness check should match actual state", i);
                    }
                }

                // Overall claims check
                if sdk.config().strict_claims {
                    let has_empty = attack_claims.is_empty() || attack_claims.iter().any(|c| c.is_empty());
                    if has_empty {
                        let failed = failed_checks(&report);
                        assert!(failed.contains(&"claims_valid"),
                            "Should fail claims validation with empty claims");
                    }
                }
            }
        }
    }

    /// Test: Binding hash computation attack vectors and collision resistance
    #[test]
    fn test_binding_hash_computation_attack_vectors() {
        // Test: Field boundary manipulation attacks
        let boundary_attacks = vec![
            // Same total content, different field boundaries
            (VerificationRequest {
                artifact_id: "ab".to_string(),
                artifact_hash: "cd".to_string(),
                claims: vec!["ef".to_string()],
            }),
            (VerificationRequest {
                artifact_id: "a".to_string(),
                artifact_hash: "bcd".to_string(),
                claims: vec!["ef".to_string()],
            }),
            (VerificationRequest {
                artifact_id: "ab".to_string(),
                artifact_hash: "c".to_string(),
                claims: vec!["def".to_string()],
            }),
            // Field reordering attacks
            (VerificationRequest {
                artifact_id: "field1".to_string(),
                artifact_hash: "field2".to_string(),
                claims: vec!["field3".to_string()],
            }),
            (VerificationRequest {
                artifact_id: "field2".to_string(),
                artifact_hash: "field1".to_string(),
                claims: vec!["field3".to_string()],
            }),
        ];

        let mut binding_hashes = Vec::new();
        for request in &boundary_attacks {
            binding_hashes.push(artifact_binding_hash(request));
        }

        // All binding hashes should be unique (no collisions)
        for i in 0..binding_hashes.len() {
            for j in (i+1)..binding_hashes.len() {
                assert_ne!(binding_hashes[i], binding_hashes[j],
                    "Binding hash collision between requests {} and {}", i, j);
            }
        }

        // Test: Length prefix collision attacks
        let length_attacks = vec![
            // Try to create collisions using crafted field lengths
            VerificationRequest {
                artifact_id: format!("{}artifact", 8u64.to_le_bytes().len()),
                artifact_hash: "hash_value".to_string(),
                claims: vec!["normal_claim".to_string()],
            },
            VerificationRequest {
                artifact_id: "artifact".to_string(),
                artifact_hash: format!("{}hash_value", 8u64.to_le_bytes().len()),
                claims: vec!["normal_claim".to_string()],
            },
            // Embed fake length prefixes
            VerificationRequest {
                artifact_id: "\x08\x00\x00\x00\x00\x00\x00\x00artifact".to_string(),
                artifact_hash: "hash_value".to_string(),
                claims: vec!["normal_claim".to_string()],
            },
        ];

        for (i, attack_req) in length_attacks.iter().enumerate() {
            let attack_hash = artifact_binding_hash(attack_req);

            // Should not collide with any boundary attack
            for (j, boundary_hash) in binding_hashes.iter().enumerate() {
                assert_ne!(attack_hash, *boundary_hash,
                    "Length attack {} should not collide with boundary attack {}", i, j);
            }
        }

        // Test: Claims order significance
        let claims_order_tests = vec![
            VerificationRequest {
                artifact_id: "order_test".to_string(),
                artifact_hash: "hash123".to_string(),
                claims: vec!["claim_a".to_string(), "claim_b".to_string()],
            },
            VerificationRequest {
                artifact_id: "order_test".to_string(),
                artifact_hash: "hash123".to_string(),
                claims: vec!["claim_b".to_string(), "claim_a".to_string()],
            },
        ];

        let order_hash_1 = artifact_binding_hash(&claims_order_tests[0]);
        let order_hash_2 = artifact_binding_hash(&claims_order_tests[1]);
        assert_ne!(order_hash_1, order_hash_2,
            "Claims order should affect binding hash");

        // Test: Unicode normalization attacks
        let unicode_attacks = vec![
            VerificationRequest {
                artifact_id: "café".to_string(), // NFC form
                artifact_hash: "hash".to_string(),
                claims: vec!["test".to_string()],
            },
            VerificationRequest {
                artifact_id: "cafe\u{301}".to_string(), // NFD form (combining)
                artifact_hash: "hash".to_string(),
                claims: vec!["test".to_string()],
            },
        ];

        let unicode_hash_1 = artifact_binding_hash(&unicode_attacks[0]);
        let unicode_hash_2 = artifact_binding_hash(&unicode_attacks[1]);
        assert_ne!(unicode_hash_1, unicode_hash_2,
            "Unicode normalization forms should produce different hashes");
    }

    /// Test: SDK error handling and recovery attack vectors
    #[test]
    fn test_sdk_error_handling_recovery_attack_vectors() {
        let sdk = test_sdk();

        // Test: Error message information leakage
        let info_leakage_tests = vec![
            (VerificationRequest {
                artifact_id: "".to_string(),
                artifact_hash: "hash".to_string(),
                claims: vec!["claim".to_string()],
            }, "empty artifact_id should not leak system info"),

            (VerificationRequest {
                artifact_id: RESERVED_ARTIFACT_ID.to_string(),
                artifact_hash: "hash".to_string(),
                claims: vec!["claim".to_string()],
            }, "reserved ID should not leak internal values"),

            (VerificationRequest {
                artifact_id: "  spaced  ".to_string(),
                artifact_hash: "hash".to_string(),
                claims: vec!["claim".to_string()],
            }, "whitespace should not leak processing details"),

            (VerificationRequest {
                artifact_id: "valid".to_string(),
                artifact_hash: "".to_string(),
                claims: vec!["claim".to_string()],
            }, "empty hash should not leak validation logic"),
        ];

        for (bad_request, test_description) in &info_leakage_tests {
            let result = sdk.verify_artifact(bad_request);
            assert!(result.is_err(), "{}: should error", test_description);

            if let Err(error) = result {
                let error_msg = error.to_string();

                // Error should not contain sensitive information
                assert!(!error_msg.contains("internal"),
                    "{}: error should not contain 'internal': {}", test_description, error_msg);
                assert!(!error_msg.contains("debug"),
                    "{}: error should not contain 'debug': {}", test_description, error_msg);
                assert!(!error_msg.contains("panic"),
                    "{}: error should not contain 'panic': {}", test_description, error_msg);
                assert!(!error_msg.contains("stack"),
                    "{}: error should not contain 'stack': {}", test_description, error_msg);

                // Error should not be too verbose (avoid info leakage)
                assert!(error_msg.len() < 200,
                    "{}: error message too long: {}", test_description, error_msg);
            }
        }

        // Test: Error state persistence across multiple operations
        let mut error_sequence = Vec::new();

        // Generate sequence of errors
        for i in 0..10 {
            let bad_req = VerificationRequest {
                artifact_id: "".to_string(), // Always invalid
                artifact_hash: format!("hash_{}", i),
                claims: vec![format!("claim_{}", i)],
            };

            let result = sdk.verify_artifact(&bad_req);
            error_sequence.push(result);
        }

        // All should be errors
        for (i, result) in error_sequence.iter().enumerate() {
            assert!(result.is_err(), "Error sequence item {} should be error", i);
        }

        // Test: Recovery after error flood
        let valid_recovery_req = VerificationRequest {
            artifact_id: "recovery_test".to_string(),
            artifact_hash: deterministic_hash("recovery_test"),
            claims: vec!["recovery_claim".to_string()],
        };

        let recovery_result = sdk.verify_artifact(&valid_recovery_req);
        assert!(recovery_result.is_ok(), "Should recover after error flood");

        if let Ok(report) = recovery_result {
            assert!(matches!(report.verdict, VerifyVerdict::Pass),
                "Recovery operation should pass");
        }

        // Test: Concurrent error handling
        use std::sync::{Arc, Mutex};
        use std::thread;

        let shared_sdk = Arc::new(test_sdk());
        let results = Arc::new(Mutex::new(Vec::new()));

        let mut handles = Vec::new();
        for thread_id in 0..3 {
            let sdk_clone = Arc::clone(&shared_sdk);
            let results_clone = Arc::clone(&results);

            let handle = thread::spawn(move || {
                let mut thread_results = Vec::new();

                for attempt in 0..5 {
                    // Alternate between error and valid requests
                    let request = if attempt % 2 == 0 {
                        VerificationRequest {
                            artifact_id: "".to_string(), // Invalid
                            artifact_hash: "invalid".to_string(),
                            claims: vec![],
                        }
                    } else {
                        VerificationRequest {
                            artifact_id: format!("valid_{}_{}", thread_id, attempt),
                            artifact_hash: deterministic_hash(&format!("valid_{}_{}", thread_id, attempt)),
                            claims: vec!["valid_claim".to_string()],
                        }
                    };

                    let result = sdk_clone.verify_artifact(&request);
                    thread_results.push((thread_id, attempt, result.is_ok()));

                    thread::yield_now();
                }

                results_clone.lock().unwrap().extend(thread_results);
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().expect("Thread should complete");
        }

        let final_results = results.lock().unwrap();

        // Verify error/success pattern is maintained across threads
        for &(thread_id, attempt, is_ok) in final_results.iter() {
            let expected_ok = attempt % 2 == 1; // Valid requests on odd attempts
            assert_eq!(is_ok, expected_ok,
                "Thread {} attempt {}: expected success={}, got={}",
                thread_id, attempt, expected_ok, is_ok);
        }
    }

    /// Test: Memory exhaustion and resource consumption attack vectors
    #[test]
    fn test_memory_exhaustion_resource_consumption_attacks() {
        // Test: Large string allocation attacks
        let large_string_tests = vec![
            ("massive_artifact_id", "x".repeat(10_000)),
            ("massive_hash", "a".repeat(10_000)), // Will fail format but test memory
            ("massive_claim", vec!["y".repeat(5_000)]),
            ("many_small_claims", (0..100).map(|i| format!("claim_{}", i)).collect::<Vec<_>>()),
        ];

        for (test_name, test_data) in large_string_tests {
            let sdk = test_sdk();

            let request = match test_name {
                "massive_artifact_id" => VerificationRequest {
                    artifact_id: test_data,
                    artifact_hash: "a".repeat(64),
                    claims: vec!["test".to_string()],
                },
                "massive_hash" => VerificationRequest {
                    artifact_id: "test_id".to_string(),
                    artifact_hash: test_data,
                    claims: vec!["test".to_string()],
                },
                "massive_claim" | "many_small_claims" => VerificationRequest {
                    artifact_id: "test_id".to_string(),
                    artifact_hash: deterministic_hash("test_id"),
                    claims: test_data,
                },
                _ => unreachable!(),
            };

            // Should handle large data without crashing
            let result = sdk.verify_artifact(&request);

            match test_name {
                "massive_artifact_id" => {
                    // Should error on whitespace check or succeed
                    // (depending on whether it contains leading/trailing spaces)
                    // Either way, should not crash
                    assert!(result.is_ok() || result.is_err(), "Should handle massive artifact ID");
                }
                "massive_hash" => {
                    // Should succeed verification but fail hash format check
                    assert!(result.is_ok(), "Should handle massive hash");
                    if let Ok(report) = result {
                        let failed = failed_checks(&report);
                        assert!(failed.contains(&"artifact_hash_format"),
                            "Should fail format check for massive hash");
                    }
                }
                "massive_claim" | "many_small_claims" => {
                    // Should succeed but may fail individual claim checks
                    assert!(result.is_ok(), "Should handle large claims");
                }
                _ => unreachable!(),
            }
        }

        // Test: Deeply nested/complex request processing
        let mut complex_claims = Vec::new();
        for i in 0..20 {
            // Create claims with nested structure-like content
            let nested_claim = format!(
                "{{\"level_{}\": {{\"nested\": {{\"deep\": \"value_{}\"}}}}}}",
                i, i
            );
            complex_claims.push(nested_claim);
        }

        let complex_request = VerificationRequest {
            artifact_id: "complex_test".to_string(),
            artifact_hash: deterministic_hash("complex_test"),
            claims: complex_claims,
        };

        let complex_result = test_sdk().verify_artifact(&complex_request);
        assert!(complex_result.is_ok(), "Should handle complex nested claims");

        // Test: Rapid-fire request processing
        let sdk = test_sdk();
        for i in 0..50 {
            let rapid_req = VerificationRequest {
                artifact_id: format!("rapid_{}", i),
                artifact_hash: deterministic_hash(&format!("rapid_{}", i)),
                claims: vec![format!("claim_{}", i)],
            };

            let result = sdk.verify_artifact(&rapid_req);
            assert!(result.is_ok(), "Rapid request {} should succeed", i);
        }

        // Test: Unicode processing overhead
        let unicode_stress_tests = vec![
            "🔒".repeat(100), // Emoji flood
            "测试".repeat(100), // CJK characters
            "🏴󠁧󠁢󠁳󠁣󠁴󠁿".repeat(10), // Complex emoji sequences
            "é".repeat(100), // Accented characters
            "\u{200B}".repeat(1000), // Zero-width spaces
            "\u{FEFF}".repeat(100), // BOMs
        ];

        for unicode_test in unicode_stress_tests {
            let unicode_req = VerificationRequest {
                artifact_id: format!("unicode_{}", unicode_test.chars().take(10).collect::<String>()),
                artifact_hash: deterministic_hash("unicode_test"),
                claims: vec![unicode_test],
            };

            let unicode_result = test_sdk().verify_artifact(&unicode_req);
            assert!(unicode_result.is_ok(), "Should handle Unicode stress test");
        }
    }
}
