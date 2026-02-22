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
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Current API version of the Verifier SDK.
pub const API_VERSION: &str = "1.0.0";

/// Schema tag embedded in every verification report.
pub const SCHEMA_TAG: &str = "vsk-v1.0";

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

/// Deterministic XOR-based hash (hex-encoded, 64 chars).
/// INV-VSK-DETERMINISTIC-VERIFY: same input always produces same output.
fn deterministic_hash(data: &str) -> String {
    let mut hash = [0u8; 32];
    for (i, b) in data.bytes().enumerate() {
        hash[i % 32] ^= b;
    }
    hex::encode(hash)
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
        if request.artifact_id.is_empty() {
            return Err(SdkError::InvalidArtifact(
                "artifact_id is empty".to_string(),
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
            detail: format!("artifact_id={}", request.artifact_id),
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
        let computed = deterministic_hash(&request.artifact_id);
        let hash_match = if self.config.require_hash_match {
            computed == request.artifact_hash
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

        let binding_input = format!(
            "{}|{}|{}",
            request.artifact_id,
            request.artifact_hash,
            request.claims.join(",")
        );
        let binding_hash = deterministic_hash(&binding_input);

        Ok(VerificationReport {
            request_id: format!(
                "vreq-{}",
                &deterministic_hash(&request.artifact_id)[..24]
            ),
            verdict,
            evidence,
            trace_id: format!(
                "vtrc-{}",
                &deterministic_hash(&binding_input)[..24]
            ),
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
        let version_ok = capsule.format_version >= 1;
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
        let env_ok = !capsule.environment.runtime_version.is_empty();
        evidence.push(EvidenceEntry {
            check_name: "environment_present".to_string(),
            passed: env_ok,
            detail: format!("runtime_version={}", capsule.environment.runtime_version),
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

        // Replay: compute deterministic hash of all inputs, compare to first expected output hash
        let input_data: String = capsule
            .inputs
            .iter()
            .map(|inp| format!("{}:{}", inp.seq, hex::encode(&inp.data)))
            .collect::<Vec<_>>()
            .join("|");
        let replay_hash = deterministic_hash(&input_data);

        let replay_match = if let Some(first_output) = capsule.expected_outputs.first() {
            first_output.output_hash == replay_hash
        } else {
            false
        };
        evidence.push(EvidenceEntry {
            check_name: "replay_deterministic_match".to_string(),
            passed: replay_match,
            detail: if replay_match {
                "replay hash matches expected output".to_string()
            } else {
                format!("replay_hash={replay_hash}")
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

        let binding_input = format!(
            "capsule:{}|v{}|inputs:{}",
            capsule.capsule_id,
            capsule.format_version,
            capsule.inputs.len()
        );
        let binding_hash = deterministic_hash(&binding_input);

        Ok(VerificationReport {
            request_id: format!(
                "vcap-{}",
                &deterministic_hash(&capsule.capsule_id)[..24]
            ),
            verdict,
            evidence,
            trace_id: format!(
                "vtrc-{}",
                &deterministic_hash(&binding_input)[..24]
            ),
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

        let chain_binding_parts: Vec<String> =
            reports.iter().map(|r| r.binding_hash.clone()).collect();
        let chain_binding = deterministic_hash(&chain_binding_parts.join("|"));

        Ok(VerificationReport {
            request_id: format!(
                "vchn-{}",
                &deterministic_hash(&chain_binding)[..24]
            ),
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

        let input_data: String = inputs
            .iter()
            .map(|inp| format!("{}:{}", inp.seq, hex::encode(&inp.data)))
            .collect::<Vec<_>>()
            .join("|");
        let expected_hash = deterministic_hash(&input_data);

        ReplayCapsule {
            capsule_id: "capsule-001".to_string(),
            format_version: 1,
            inputs,
            expected_outputs: vec![CapsuleOutput {
                seq: 0,
                data: b"output-0".to_vec(),
                output_hash: expected_hash,
            }],
            environment: EnvironmentSnapshot {
                runtime_version: "1.0.0".to_string(),
                platform: "linux-x86_64".to_string(),
                config_hash: "aabb".repeat(8),
                properties: BTreeMap::new(),
            },
        }
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
        let report = sdk.verify_artifact(&req).unwrap();
        assert_eq!(report.verdict, VerifyVerdict::Pass);
        assert!(!report.binding_hash.is_empty());
    }

    #[test]
    fn test_verify_artifact_report_fields() {
        let sdk = test_sdk();
        let req = valid_request();
        let report = sdk.verify_artifact(&req).unwrap();
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
        let report = sdk.verify_artifact(&req).unwrap();
        assert!(report.evidence.len() >= 4);
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
        let report = sdk.verify_artifact(&req).unwrap();
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
        let report = sdk.verify_artifact(&req).unwrap();
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
        let report = sdk.verify_artifact(&req).unwrap();
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
        let report = sdk.verify_artifact(&req).unwrap();
        assert_eq!(report.verdict, VerifyVerdict::Pass);
    }

    // ── verify_artifact: determinism ────────────────────────────────

    #[test]
    fn test_verify_artifact_deterministic() {
        // INV-VSK-DETERMINISTIC-VERIFY
        let sdk = test_sdk();
        let req = valid_request();
        let r1 = sdk.verify_artifact(&req).unwrap();
        let r2 = sdk.verify_artifact(&req).unwrap();
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
        let report = sdk.verify_capsule(&cap).unwrap();
        assert_eq!(report.verdict, VerifyVerdict::Pass);
    }

    #[test]
    fn test_verify_capsule_report_fields() {
        let sdk = test_sdk();
        let cap = valid_capsule();
        let report = sdk.verify_capsule(&cap).unwrap();
        assert_eq!(report.schema_tag, SCHEMA_TAG);
        assert_eq!(report.api_version, API_VERSION);
        assert!(report.request_id.starts_with("vcap-"));
    }

    #[test]
    fn test_verify_capsule_evidence_entries() {
        let sdk = test_sdk();
        let cap = valid_capsule();
        let report = sdk.verify_capsule(&cap).unwrap();
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
        let report = sdk.verify_capsule(&cap).unwrap();
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
    }

    #[test]
    fn test_verify_capsule_no_outputs() {
        let sdk = test_sdk();
        let mut cap = valid_capsule();
        cap.expected_outputs.clear();
        let report = sdk.verify_capsule(&cap).unwrap();
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
    }

    #[test]
    fn test_verify_capsule_bad_version() {
        let sdk = test_sdk();
        let mut cap = valid_capsule();
        cap.format_version = 0;
        let report = sdk.verify_capsule(&cap).unwrap();
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
    }

    #[test]
    fn test_verify_capsule_non_monotonic_seq() {
        let sdk = test_sdk();
        let mut cap = valid_capsule();
        cap.inputs[1].seq = 0; // same as first = not strictly increasing
        let report = sdk.verify_capsule(&cap).unwrap();
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
    }

    #[test]
    fn test_verify_capsule_replay_mismatch() {
        let sdk = test_sdk();
        let mut cap = valid_capsule();
        cap.expected_outputs[0].output_hash = "wrong_hash".to_string();
        let report = sdk.verify_capsule(&cap).unwrap();
        assert!(matches!(report.verdict, VerifyVerdict::Fail(_)));
    }

    // ── verify_capsule: determinism ─────────────────────────────────

    #[test]
    fn test_verify_capsule_deterministic() {
        // INV-VSK-DETERMINISTIC-VERIFY
        let sdk = test_sdk();
        let cap = valid_capsule();
        let r1 = sdk.verify_capsule(&cap).unwrap();
        let r2 = sdk.verify_capsule(&cap).unwrap();
        assert_eq!(r1.verdict, r2.verdict);
        assert_eq!(r1.binding_hash, r2.binding_hash);
        assert_eq!(r1.evidence.len(), r2.evidence.len());
    }

    // ── verify_chain: happy path ────────────────────────────────────

    #[test]
    fn test_verify_chain_pass() {
        let sdk = test_sdk();
        let r1 = sdk.verify_artifact(&valid_request()).unwrap();
        let mut req2 = valid_request();
        req2.artifact_id = "artifact-002".to_string();
        req2.artifact_hash = deterministic_hash("artifact-002");
        let r2 = sdk.verify_artifact(&req2).unwrap();
        let chain_report = sdk.verify_chain(&[r1, r2]).unwrap();
        assert_eq!(chain_report.verdict, VerifyVerdict::Pass);
    }

    #[test]
    fn test_verify_chain_report_fields() {
        let sdk = test_sdk();
        let r1 = sdk.verify_artifact(&valid_request()).unwrap();
        let chain_report = sdk.verify_chain(&[r1]).unwrap();
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
        let passing = sdk.verify_artifact(&valid_request()).unwrap();
        let failing_req = VerificationRequest {
            artifact_id: "art-bad".to_string(),
            artifact_hash: "short".to_string(),
            claims: vec!["c".to_string()],
        };
        let failing = sdk.verify_artifact(&failing_req).unwrap();
        let chain_report = sdk.verify_chain(&[passing, failing]).unwrap();
        assert!(matches!(chain_report.verdict, VerifyVerdict::Fail(_)));
    }

    // ── verify_chain: determinism ───────────────────────────────────

    #[test]
    fn test_verify_chain_deterministic() {
        // INV-VSK-DETERMINISTIC-VERIFY
        let sdk = test_sdk();
        let r1 = sdk.verify_artifact(&valid_request()).unwrap();
        let chain1 = sdk.verify_chain(std::slice::from_ref(&r1)).unwrap();
        let chain2 = sdk.verify_chain(&[r1]).unwrap();
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
        let json = serde_json::to_string(&req).unwrap();
        let parsed: VerificationRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(req, parsed);
    }

    #[test]
    fn test_verification_report_serde_roundtrip() {
        let sdk = test_sdk();
        let report = sdk.verify_artifact(&valid_request()).unwrap();
        let json = serde_json::to_string(&report).unwrap();
        let parsed: VerificationReport = serde_json::from_str(&json).unwrap();
        assert_eq!(report, parsed);
    }

    #[test]
    fn test_verify_verdict_serde_roundtrip() {
        for v in [
            VerifyVerdict::Pass,
            VerifyVerdict::Fail(vec!["reason".to_string()]),
            VerifyVerdict::Inconclusive("maybe".to_string()),
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let parsed: VerifyVerdict = serde_json::from_str(&json).unwrap();
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
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: EvidenceEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, parsed);
    }

    #[test]
    fn test_sdk_event_serde_roundtrip() {
        let evt = SdkEvent {
            event_code: "VSK-001".to_string(),
            detail: "started".to_string(),
            timestamp: now_timestamp(),
        };
        let json = serde_json::to_string(&evt).unwrap();
        let parsed: SdkEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_code, "VSK-001");
    }

    #[test]
    fn test_verifier_config_serde_roundtrip() {
        let config = VerifierConfig::default();
        let json = serde_json::to_string(&config).unwrap();
        let parsed: VerifierConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(config, parsed);
    }

    #[test]
    fn test_sdk_error_serde_roundtrip() {
        let err = SdkError::HashMismatch {
            expected: "a".to_string(),
            actual: "b".to_string(),
        };
        let json = serde_json::to_string(&err).unwrap();
        let parsed: SdkError = serde_json::from_str(&json).unwrap();
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
}
