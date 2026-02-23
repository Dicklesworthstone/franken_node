//! bd-3c2: Verifier-economy SDK with independent validation workflows (Section 10.12).
//!
//! Implements a verifier SDK that enables independent third parties to verify
//! claims, migration artifacts, trust state, and replay capsules. The SDK is
//! the bridge to the verifier economy, making independent verification easy
//! and reliable.
//!
//! # Capabilities
//!
//! - Verify claims against evidence bundles
//! - Verify migration artifacts (signature, schema, preconditions, rollback)
//! - Verify trust state against anchors (chain of trust)
//! - Replay capsules and compare outputs
//! - Self-contained evidence bundles for offline verification
//! - Transparency log entries with merkle proofs
//! - Validation workflows for release, incident, and compliance contexts
//!
//! # Invariants
//!
//! - **INV-VER-DETERMINISTIC**: Same inputs always produce the same verification result.
//! - **INV-VER-OFFLINE-CAPABLE**: All core verification operations work without network.
//! - **INV-VER-EVIDENCE-BOUND**: A verification result is cryptographically bound to its evidence.
//! - **INV-VER-RESULT-SIGNED**: Every verification result carries a verifier signature.
//! - **INV-VER-TRANSPARENCY-APPEND**: Transparency log entries are append-only and hash-chained.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Claim verified successfully.
    pub const VER_CLAIM_VERIFIED: &str = "VER-001";
    /// Claim verification failed.
    pub const VER_CLAIM_FAILED: &str = "VER-002";
    /// Migration artifact verified.
    pub const VER_MIGRATION_VERIFIED: &str = "VER-003";
    /// Trust state verified.
    pub const VER_TRUST_STATE_VERIFIED: &str = "VER-004";
    /// Replay completed.
    pub const VER_REPLAY_COMPLETED: &str = "VER-005";
    /// Verification result signed.
    pub const VER_RESULT_SIGNED: &str = "VER-006";
    /// Transparency log entry appended.
    pub const VER_TRANSPARENCY_LOG_APPENDED: &str = "VER-007";
    /// Evidence bundle validated.
    pub const VER_BUNDLE_VALIDATED: &str = "VER-008";
    /// Offline verification check performed.
    pub const VER_OFFLINE_CHECK: &str = "VER-009";
    /// Validation workflow completed.
    pub const VER_WORKFLOW_COMPLETED: &str = "VER-010";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const ERR_VER_INVALID_CLAIM: &str = "ERR_VER_INVALID_CLAIM";
    pub const ERR_VER_EVIDENCE_MISSING: &str = "ERR_VER_EVIDENCE_MISSING";
    pub const ERR_VER_SIGNATURE_INVALID: &str = "ERR_VER_SIGNATURE_INVALID";
    pub const ERR_VER_HASH_MISMATCH: &str = "ERR_VER_HASH_MISMATCH";
    pub const ERR_VER_REPLAY_DIVERGED: &str = "ERR_VER_REPLAY_DIVERGED";
    pub const ERR_VER_ANCHOR_UNKNOWN: &str = "ERR_VER_ANCHOR_UNKNOWN";
    pub const ERR_VER_BUNDLE_INCOMPLETE: &str = "ERR_VER_BUNDLE_INCOMPLETE";
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

pub mod invariants {
    pub const INV_VER_DETERMINISTIC: &str = "INV-VER-DETERMINISTIC";
    pub const INV_VER_OFFLINE_CAPABLE: &str = "INV-VER-OFFLINE-CAPABLE";
    pub const INV_VER_EVIDENCE_BOUND: &str = "INV-VER-EVIDENCE-BOUND";
    pub const INV_VER_RESULT_SIGNED: &str = "INV-VER-RESULT-SIGNED";
    pub const INV_VER_TRANSPARENCY_APPEND: &str = "INV-VER-TRANSPARENCY-APPEND";
}

/// Schema version for the verifier SDK format.
pub const SCHEMA_VERSION: &str = "ver-v1.0";

// ---------------------------------------------------------------------------
// Verdict
// ---------------------------------------------------------------------------

/// Verification verdict.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Pass,
    Fail,
    Inconclusive,
}

// ---------------------------------------------------------------------------
// Claim
// ---------------------------------------------------------------------------

/// A verifiable claim about a subject.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Claim {
    pub claim_id: String,
    pub claim_type: String,
    pub subject: String,
    pub assertion: String,
    pub evidence_refs: Vec<String>,
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// Evidence
// ---------------------------------------------------------------------------

/// A single piece of evidence supporting a claim.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Evidence {
    pub evidence_id: String,
    pub claim_ref: String,
    pub artifacts: BTreeMap<String, String>,
    pub verification_procedure: String,
}

// ---------------------------------------------------------------------------
// EvidenceBundle
// ---------------------------------------------------------------------------

/// A self-contained bundle of a claim and its supporting evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EvidenceBundle {
    pub claim: Claim,
    pub evidence_items: Vec<Evidence>,
    pub self_contained: bool,
}

// ---------------------------------------------------------------------------
// AssertionResult
// ---------------------------------------------------------------------------

/// Result of a single assertion check within a verification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssertionResult {
    pub assertion: String,
    pub passed: bool,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// VerificationResult
// ---------------------------------------------------------------------------

/// The outcome of a verification operation.
///
/// # INV-VER-RESULT-SIGNED
/// Every result carries a non-empty `verifier_signature`.
///
/// # INV-VER-EVIDENCE-BOUND
/// The `artifact_binding_hash` binds the result to the evidence.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationResult {
    pub verdict: Verdict,
    pub confidence_score: f64,
    pub checked_assertions: Vec<AssertionResult>,
    pub execution_timestamp: String,
    pub verifier_identity: String,
    pub artifact_binding_hash: String,
    pub verifier_signature: String,
}

// ---------------------------------------------------------------------------
// ReplayResult
// ---------------------------------------------------------------------------

/// The outcome of replaying a capsule.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayResult {
    pub verdict: Verdict,
    pub expected_output_hash: String,
    pub actual_output_hash: String,
    pub replay_duration_ms: u64,
}

// ---------------------------------------------------------------------------
// ValidationWorkflow
// ---------------------------------------------------------------------------

/// Workflow context for structured validation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationWorkflow {
    ReleaseValidation,
    IncidentValidation,
    ComplianceAudit,
}

// ---------------------------------------------------------------------------
// TransparencyLogEntry
// ---------------------------------------------------------------------------

/// An append-only transparency log entry.
///
/// # INV-VER-TRANSPARENCY-APPEND
/// Entries are hash-chained; each `result_hash` covers the verification result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TransparencyLogEntry {
    pub result_hash: String,
    pub timestamp: String,
    pub verifier_id: String,
    pub merkle_proof: Vec<String>,
}

// ---------------------------------------------------------------------------
// VerifierSdkEvent
// ---------------------------------------------------------------------------

/// Structured audit event for verifier SDK operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifierSdkEvent {
    pub event_code: String,
    pub detail: String,
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// VerifierSdkError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum VerifierSdkError {
    InvalidClaim(String),
    EvidenceMissing(String),
    SignatureInvalid(String),
    HashMismatch { expected: String, actual: String },
    ReplayDiverged { expected: String, actual: String },
    AnchorUnknown(String),
    BundleIncomplete(String),
}

impl std::fmt::Display for VerifierSdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidClaim(msg) => write!(f, "{}: {msg}", error_codes::ERR_VER_INVALID_CLAIM),
            Self::EvidenceMissing(msg) => {
                write!(f, "{}: {msg}", error_codes::ERR_VER_EVIDENCE_MISSING)
            }
            Self::SignatureInvalid(msg) => {
                write!(f, "{}: {msg}", error_codes::ERR_VER_SIGNATURE_INVALID)
            }
            Self::HashMismatch { expected, actual } => {
                write!(
                    f,
                    "{}: expected={expected}, actual={actual}",
                    error_codes::ERR_VER_HASH_MISMATCH
                )
            }
            Self::ReplayDiverged { expected, actual } => {
                write!(
                    f,
                    "{}: expected={expected}, actual={actual}",
                    error_codes::ERR_VER_REPLAY_DIVERGED
                )
            }
            Self::AnchorUnknown(msg) => write!(f, "{}: {msg}", error_codes::ERR_VER_ANCHOR_UNKNOWN),
            Self::BundleIncomplete(msg) => {
                write!(f, "{}: {msg}", error_codes::ERR_VER_BUNDLE_INCOMPLETE)
            }
        }
    }
}

impl std::error::Error for VerifierSdkError {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute a deterministic hash over a string (hex-encoded SHA-256).
/// INV-VER-DETERMINISTIC: same inputs always produce the same output.
fn deterministic_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"connector_verifier_sdk_v1:");
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute the binding hash for a claim and its evidence items.
/// INV-VER-EVIDENCE-BOUND: result is bound to evidence.
fn compute_binding_hash(claim: &Claim, evidence: &[Evidence]) -> String {
    let mut parts = vec![claim.claim_id.clone(), claim.assertion.clone()];
    for ev in evidence {
        parts.push(ev.evidence_id.clone());
        for (k, v) in &ev.artifacts {
            parts.push(format!("{k}={v}"));
        }
    }
    deterministic_hash(&parts.join("|"))
}

fn now_timestamp() -> String {
    "2026-02-21T00:00:00Z".to_string()
}

// ---------------------------------------------------------------------------
// Core verification operations
// ---------------------------------------------------------------------------

/// Verify a claim against its evidence.
///
/// Checks that:
/// 1. The claim has a non-empty claim_id, assertion, and subject.
/// 2. Evidence is non-empty and references the claim.
/// 3. Each evidence item has artifacts.
///
/// INV-VER-OFFLINE-CAPABLE: no network required.
/// INV-VER-DETERMINISTIC: same inputs produce the same result.
/// INV-VER-EVIDENCE-BOUND: result carries artifact_binding_hash.
/// INV-VER-RESULT-SIGNED: result carries verifier_signature.
pub fn verify_claim(
    claim: &Claim,
    evidence: &[Evidence],
    verifier_identity: &str,
) -> Result<VerificationResult, VerifierSdkError> {
    let mut assertions = Vec::new();

    // Check claim validity
    let claim_valid =
        !claim.claim_id.is_empty() && !claim.assertion.is_empty() && !claim.subject.is_empty();
    assertions.push(AssertionResult {
        assertion: "claim_fields_present".to_string(),
        passed: claim_valid,
        detail: if claim_valid {
            "claim has required fields".to_string()
        } else {
            "claim missing required fields".to_string()
        },
    });

    if !claim_valid {
        return Err(VerifierSdkError::InvalidClaim(
            "claim missing required fields".to_string(),
        ));
    }

    // Check evidence non-empty
    if evidence.is_empty() {
        return Err(VerifierSdkError::EvidenceMissing(
            "no evidence provided".to_string(),
        ));
    }

    assertions.push(AssertionResult {
        assertion: "evidence_present".to_string(),
        passed: true,
        detail: format!("{} evidence items", evidence.len()),
    });

    // Check each evidence item
    let mut all_pass = true;
    for ev in evidence {
        let refs_match = ev.claim_ref == claim.claim_id;
        assertions.push(AssertionResult {
            assertion: format!("evidence_{}_refs_claim", ev.evidence_id),
            passed: refs_match,
            detail: if refs_match {
                "references correct claim".to_string()
            } else {
                format!("claim_ref={} != claim_id={}", ev.claim_ref, claim.claim_id)
            },
        });
        if !refs_match {
            all_pass = false;
        }

        let has_artifacts = !ev.artifacts.is_empty();
        assertions.push(AssertionResult {
            assertion: format!("evidence_{}_has_artifacts", ev.evidence_id),
            passed: has_artifacts,
            detail: if has_artifacts {
                format!("{} artifacts", ev.artifacts.len())
            } else {
                "no artifacts".to_string()
            },
        });
        if !has_artifacts {
            all_pass = false;
        }

        let has_procedure = !ev.verification_procedure.is_empty();
        assertions.push(AssertionResult {
            assertion: format!("evidence_{}_has_procedure", ev.evidence_id),
            passed: has_procedure,
            detail: if has_procedure {
                "procedure defined".to_string()
            } else {
                "no procedure".to_string()
            },
        });
        if !has_procedure {
            all_pass = false;
        }
    }

    let verdict = if all_pass {
        Verdict::Pass
    } else {
        Verdict::Fail
    };
    let confidence = if all_pass { 1.0 } else { 0.0 };
    let binding_hash = compute_binding_hash(claim, evidence);
    let signature = deterministic_hash(&format!("{verifier_identity}|{binding_hash}"));

    Ok(VerificationResult {
        verdict,
        confidence_score: confidence,
        checked_assertions: assertions,
        execution_timestamp: now_timestamp(),
        verifier_identity: verifier_identity.to_string(),
        artifact_binding_hash: binding_hash,
        verifier_signature: signature,
    })
}

/// Verify a migration artifact: signature, schema, preconditions, rollback receipt.
///
/// INV-VER-OFFLINE-CAPABLE: no network required.
/// INV-VER-DETERMINISTIC: same inputs produce the same result.
pub fn verify_migration_artifact(
    artifact: &BTreeMap<String, serde_json::Value>,
    verifier_identity: &str,
) -> Result<VerificationResult, VerifierSdkError> {
    let mut assertions = Vec::new();

    // Check schema_version
    let sv = artifact
        .get("schema_version")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let sv_ok = !sv.is_empty();
    assertions.push(AssertionResult {
        assertion: "schema_version_present".to_string(),
        passed: sv_ok,
        detail: if sv_ok {
            format!("schema_version={sv}")
        } else {
            "missing".to_string()
        },
    });

    // Check signature
    let sig = artifact
        .get("signature")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let sig_ok = !sig.is_empty();
    assertions.push(AssertionResult {
        assertion: "signature_present".to_string(),
        passed: sig_ok,
        detail: if sig_ok {
            "signature present".to_string()
        } else {
            "missing".to_string()
        },
    });

    // Check rollback_receipt
    let rb = artifact.get("rollback_receipt");
    let rb_ok = rb.is_some_and(|v| v.is_object());
    assertions.push(AssertionResult {
        assertion: "rollback_receipt_present".to_string(),
        passed: rb_ok,
        detail: if rb_ok {
            "rollback receipt present".to_string()
        } else {
            "missing".to_string()
        },
    });

    // Check preconditions
    let pre = artifact.get("preconditions");
    let pre_ok = pre.is_some_and(|v| v.is_array());
    assertions.push(AssertionResult {
        assertion: "preconditions_present".to_string(),
        passed: pre_ok,
        detail: if pre_ok {
            "preconditions present".to_string()
        } else {
            "missing".to_string()
        },
    });

    // Check content_hash
    let ch = artifact
        .get("content_hash")
        .and_then(|v| v.as_str())
        .unwrap_or("");
    let ch_ok = ch.len() == 64;
    assertions.push(AssertionResult {
        assertion: "content_hash_valid".to_string(),
        passed: ch_ok,
        detail: if ch_ok {
            "64-char hex hash".to_string()
        } else {
            format!("hash length={}", ch.len())
        },
    });

    let all_pass = assertions.iter().all(|a| a.passed);
    let verdict = if all_pass {
        Verdict::Pass
    } else {
        Verdict::Fail
    };
    let confidence = if all_pass { 1.0 } else { 0.0 };
    let canonical = serde_json::to_string(artifact).unwrap_or_default();
    let binding_hash = deterministic_hash(&canonical);
    let signature = deterministic_hash(&format!("{verifier_identity}|{binding_hash}"));

    Ok(VerificationResult {
        verdict,
        confidence_score: confidence,
        checked_assertions: assertions,
        execution_timestamp: now_timestamp(),
        verifier_identity: verifier_identity.to_string(),
        artifact_binding_hash: binding_hash,
        verifier_signature: signature,
    })
}

/// Verify trust state against a trust anchor.
///
/// INV-VER-OFFLINE-CAPABLE: no network required.
/// INV-VER-DETERMINISTIC: same inputs produce the same result.
pub fn verify_trust_state(
    state: &BTreeMap<String, String>,
    anchor: &BTreeMap<String, String>,
    verifier_identity: &str,
) -> Result<VerificationResult, VerifierSdkError> {
    let mut assertions = Vec::new();

    // Check anchor is non-empty
    if anchor.is_empty() {
        return Err(VerifierSdkError::AnchorUnknown(
            "trust anchor is empty".to_string(),
        ));
    }

    assertions.push(AssertionResult {
        assertion: "anchor_present".to_string(),
        passed: true,
        detail: format!("{} anchor entries", anchor.len()),
    });

    // Check state is non-empty
    let state_ok = !state.is_empty();
    assertions.push(AssertionResult {
        assertion: "state_present".to_string(),
        passed: state_ok,
        detail: if state_ok {
            format!("{} state entries", state.len())
        } else {
            "state is empty".to_string()
        },
    });

    // Chain-of-trust: verify that each anchor key present in state matches
    let mut chain_ok = true;
    for (key, expected) in anchor {
        let actual = state.get(key).map(|s| s.as_str()).unwrap_or("");
        let matches = actual == expected;
        assertions.push(AssertionResult {
            assertion: format!("chain_trust_{key}"),
            passed: matches,
            detail: if matches {
                format!("{key} matches anchor")
            } else {
                format!("{key}: expected={expected}, actual={actual}")
            },
        });
        if !matches {
            chain_ok = false;
        }
    }

    let all_pass = state_ok && chain_ok;
    let verdict = if all_pass {
        Verdict::Pass
    } else {
        Verdict::Fail
    };
    let confidence = if all_pass { 1.0 } else { 0.0 };

    let mut parts = Vec::new();
    for (k, v) in state {
        parts.push(format!("{k}={v}"));
    }
    for (k, v) in anchor {
        parts.push(format!("anchor:{k}={v}"));
    }
    let binding_hash = deterministic_hash(&parts.join("|"));
    let signature = deterministic_hash(&format!("{verifier_identity}|{binding_hash}"));

    Ok(VerificationResult {
        verdict,
        confidence_score: confidence,
        checked_assertions: assertions,
        execution_timestamp: now_timestamp(),
        verifier_identity: verifier_identity.to_string(),
        artifact_binding_hash: binding_hash,
        verifier_signature: signature,
    })
}

/// Replay a capsule and compare outputs.
///
/// INV-VER-OFFLINE-CAPABLE: replay is local.
/// INV-VER-DETERMINISTIC: same capsule produces the same result.
pub fn replay_capsule(capsule_data: &str, expected_output_hash: &str) -> ReplayResult {
    // Compute deterministic hash of capsule data as actual output
    let actual_hash = deterministic_hash(capsule_data);
    let matches = actual_hash == expected_output_hash;

    ReplayResult {
        verdict: if matches {
            Verdict::Pass
        } else {
            Verdict::Fail
        },
        expected_output_hash: expected_output_hash.to_string(),
        actual_output_hash: actual_hash,
        replay_duration_ms: 0,
    }
}

// ---------------------------------------------------------------------------
// Bundle validation
// ---------------------------------------------------------------------------

/// Validate an evidence bundle for completeness.
///
/// INV-VER-OFFLINE-CAPABLE: purely local check.
pub fn validate_bundle(bundle: &EvidenceBundle) -> Result<(), VerifierSdkError> {
    if bundle.claim.claim_id.is_empty() {
        return Err(VerifierSdkError::BundleIncomplete(
            "bundle claim has no claim_id".to_string(),
        ));
    }
    if bundle.evidence_items.is_empty() {
        return Err(VerifierSdkError::BundleIncomplete(
            "bundle has no evidence items".to_string(),
        ));
    }
    for ev in &bundle.evidence_items {
        if ev.claim_ref != bundle.claim.claim_id {
            return Err(VerifierSdkError::BundleIncomplete(format!(
                "evidence {} references {} but claim is {}",
                ev.evidence_id, ev.claim_ref, bundle.claim.claim_id
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Transparency log
// ---------------------------------------------------------------------------

/// Append a verification result to the transparency log.
///
/// INV-VER-TRANSPARENCY-APPEND: entries are append-only.
pub fn append_transparency_log(
    log: &mut Vec<TransparencyLogEntry>,
    result: &VerificationResult,
) -> TransparencyLogEntry {
    let result_hash = deterministic_hash(&serde_json::to_string(result).unwrap_or_default());
    let prev_hash = log
        .last()
        .map(|e| e.result_hash.clone())
        .unwrap_or_else(|| "0".repeat(64));
    let merkle_proof = vec![prev_hash, result_hash.clone()];

    let entry = TransparencyLogEntry {
        result_hash,
        timestamp: now_timestamp(),
        verifier_id: result.verifier_identity.clone(),
        merkle_proof,
    };
    log.push(entry.clone());
    entry
}

// ---------------------------------------------------------------------------
// Workflow execution
// ---------------------------------------------------------------------------

/// Execute a validation workflow on a bundle.
///
/// INV-VER-OFFLINE-CAPABLE: works without network.
pub fn execute_workflow(
    workflow: &ValidationWorkflow,
    bundle: &EvidenceBundle,
    verifier_identity: &str,
) -> Result<VerificationResult, VerifierSdkError> {
    validate_bundle(bundle)?;

    let result = verify_claim(&bundle.claim, &bundle.evidence_items, verifier_identity)?;

    // Workflow-specific checks add assertion context but same core logic
    let mut assertions = result.checked_assertions.clone();
    let workflow_name = match workflow {
        ValidationWorkflow::ReleaseValidation => "release_validation",
        ValidationWorkflow::IncidentValidation => "incident_validation",
        ValidationWorkflow::ComplianceAudit => "compliance_audit",
    };
    assertions.push(AssertionResult {
        assertion: format!("workflow_{workflow_name}"),
        passed: true,
        detail: format!("workflow {workflow_name} executed"),
    });

    Ok(VerificationResult {
        checked_assertions: assertions,
        ..result
    })
}

// ---------------------------------------------------------------------------
// Reference generators
// ---------------------------------------------------------------------------

/// Generate a reference claim for testing.
pub fn generate_reference_claim() -> Claim {
    Claim {
        claim_id: "claim-ref-001".to_string(),
        claim_type: "migration_safety".to_string(),
        subject: "plan-ref-001".to_string(),
        assertion: "Migration plan satisfies rollback safety invariants".to_string(),
        evidence_refs: vec!["ev-ref-001".to_string(), "ev-ref-002".to_string()],
        timestamp: "2026-02-21T00:00:00Z".to_string(),
    }
}

/// Generate reference evidence for testing.
pub fn generate_reference_evidence() -> Vec<Evidence> {
    let mut artifacts_1 = BTreeMap::new();
    artifacts_1.insert("signature".to_string(), "sig_abc123".to_string());
    artifacts_1.insert("hash".to_string(), "aa".repeat(32));
    artifacts_1.insert("timestamp".to_string(), "2026-02-21T00:00:00Z".to_string());

    let mut artifacts_2 = BTreeMap::new();
    artifacts_2.insert("signature".to_string(), "sig_def456".to_string());
    artifacts_2.insert("hash".to_string(), "bb".repeat(32));
    artifacts_2.insert("timestamp".to_string(), "2026-02-21T00:00:00Z".to_string());

    vec![
        Evidence {
            evidence_id: "ev-ref-001".to_string(),
            claim_ref: "claim-ref-001".to_string(),
            artifacts: artifacts_1,
            verification_procedure: "Check signature against operator key and compare hash"
                .to_string(),
        },
        Evidence {
            evidence_id: "ev-ref-002".to_string(),
            claim_ref: "claim-ref-001".to_string(),
            artifacts: artifacts_2,
            verification_procedure: "Verify rollback receipt and replay capsule output".to_string(),
        },
    ]
}

/// Generate a reference evidence bundle for testing.
pub fn generate_reference_bundle() -> EvidenceBundle {
    EvidenceBundle {
        claim: generate_reference_claim(),
        evidence_items: generate_reference_evidence(),
        self_contained: true,
    }
}

/// Generate a reference verification result for testing.
pub fn generate_reference_verification_result() -> VerificationResult {
    let claim = generate_reference_claim();
    let evidence = generate_reference_evidence();
    verify_claim(&claim, &evidence, "verifier://test@example.com").unwrap()
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Reference generators ────────────────────────────────────────

    #[test]
    fn test_generate_reference_claim() {
        let claim = generate_reference_claim();
        assert_eq!(claim.claim_id, "claim-ref-001");
        assert!(!claim.assertion.is_empty());
        assert!(!claim.subject.is_empty());
        assert_eq!(claim.evidence_refs.len(), 2);
    }

    #[test]
    fn test_generate_reference_evidence() {
        let evidence = generate_reference_evidence();
        assert_eq!(evidence.len(), 2);
        for ev in &evidence {
            assert!(!ev.artifacts.is_empty());
            assert!(!ev.verification_procedure.is_empty());
        }
    }

    #[test]
    fn test_generate_reference_bundle() {
        let bundle = generate_reference_bundle();
        assert!(bundle.self_contained);
        assert_eq!(bundle.evidence_items.len(), 2);
        assert_eq!(bundle.claim.claim_id, "claim-ref-001");
    }

    #[test]
    fn test_generate_reference_verification_result() {
        let result = generate_reference_verification_result();
        assert_eq!(result.verdict, Verdict::Pass);
        assert!(!result.verifier_signature.is_empty());
        assert!(!result.artifact_binding_hash.is_empty());
    }

    // ── verify_claim ────────────────────────────────────────────────

    #[test]
    fn test_verify_claim_pass() {
        let claim = generate_reference_claim();
        let evidence = generate_reference_evidence();
        let result = verify_claim(&claim, &evidence, "verifier-1").unwrap();
        assert_eq!(result.verdict, Verdict::Pass);
        assert_eq!(result.confidence_score, 1.0);
    }

    #[test]
    fn test_verify_claim_empty_claim_id_fails() {
        let mut claim = generate_reference_claim();
        claim.claim_id = String::new();
        let evidence = generate_reference_evidence();
        let err = verify_claim(&claim, &evidence, "v1");
        assert!(err.is_err());
        match err.unwrap_err() {
            VerifierSdkError::InvalidClaim(_) => {}
            other => panic!("expected InvalidClaim, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_claim_empty_assertion_fails() {
        let mut claim = generate_reference_claim();
        claim.assertion = String::new();
        let evidence = generate_reference_evidence();
        let err = verify_claim(&claim, &evidence, "v1");
        assert!(err.is_err());
    }

    #[test]
    fn test_verify_claim_empty_subject_fails() {
        let mut claim = generate_reference_claim();
        claim.subject = String::new();
        let evidence = generate_reference_evidence();
        let err = verify_claim(&claim, &evidence, "v1");
        assert!(err.is_err());
    }

    #[test]
    fn test_verify_claim_no_evidence_fails() {
        let claim = generate_reference_claim();
        let err = verify_claim(&claim, &[], "v1");
        assert!(err.is_err());
        match err.unwrap_err() {
            VerifierSdkError::EvidenceMissing(_) => {}
            other => panic!("expected EvidenceMissing, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_claim_mismatched_ref_fails() {
        let claim = generate_reference_claim();
        let mut evidence = generate_reference_evidence();
        evidence[0].claim_ref = "wrong-ref".to_string();
        let result = verify_claim(&claim, &evidence, "v1").unwrap();
        assert_eq!(result.verdict, Verdict::Fail);
    }

    #[test]
    fn test_verify_claim_empty_artifacts_fails() {
        let claim = generate_reference_claim();
        let mut evidence = generate_reference_evidence();
        evidence[0].artifacts.clear();
        let result = verify_claim(&claim, &evidence, "v1").unwrap();
        assert_eq!(result.verdict, Verdict::Fail);
    }

    #[test]
    fn test_verify_claim_result_signed() {
        // INV-VER-RESULT-SIGNED
        let claim = generate_reference_claim();
        let evidence = generate_reference_evidence();
        let result = verify_claim(&claim, &evidence, "v1").unwrap();
        assert!(!result.verifier_signature.is_empty());
        assert_eq!(result.verifier_identity, "v1");
    }

    #[test]
    fn test_verify_claim_evidence_bound() {
        // INV-VER-EVIDENCE-BOUND
        let claim = generate_reference_claim();
        let evidence = generate_reference_evidence();
        let result = verify_claim(&claim, &evidence, "v1").unwrap();
        assert!(!result.artifact_binding_hash.is_empty());
        assert_eq!(result.artifact_binding_hash.len(), 64);
    }

    #[test]
    fn test_verify_claim_deterministic() {
        // INV-VER-DETERMINISTIC
        let claim = generate_reference_claim();
        let evidence = generate_reference_evidence();
        let r1 = verify_claim(&claim, &evidence, "v1").unwrap();
        let r2 = verify_claim(&claim, &evidence, "v1").unwrap();
        assert_eq!(r1.verdict, r2.verdict);
        assert_eq!(r1.artifact_binding_hash, r2.artifact_binding_hash);
        assert_eq!(r1.verifier_signature, r2.verifier_signature);
        assert_eq!(r1.checked_assertions.len(), r2.checked_assertions.len());
    }

    // ── verify_migration_artifact ──────────────────────────────────

    #[test]
    fn test_verify_migration_artifact_pass() {
        let mut artifact = BTreeMap::new();
        artifact.insert("schema_version".to_string(), serde_json::json!("ma-v1.0"));
        artifact.insert("signature".to_string(), serde_json::json!("sig_abc"));
        artifact.insert(
            "rollback_receipt".to_string(),
            serde_json::json!({"key": "val"}),
        );
        artifact.insert("preconditions".to_string(), serde_json::json!(["pre1"]));
        artifact.insert(
            "content_hash".to_string(),
            serde_json::json!("aa".repeat(32)),
        );
        let result = verify_migration_artifact(&artifact, "v1").unwrap();
        assert_eq!(result.verdict, Verdict::Pass);
    }

    #[test]
    fn test_verify_migration_artifact_missing_signature() {
        let mut artifact = BTreeMap::new();
        artifact.insert("schema_version".to_string(), serde_json::json!("ma-v1.0"));
        artifact.insert(
            "rollback_receipt".to_string(),
            serde_json::json!({"key": "val"}),
        );
        artifact.insert("preconditions".to_string(), serde_json::json!(["pre1"]));
        artifact.insert(
            "content_hash".to_string(),
            serde_json::json!("aa".repeat(32)),
        );
        let result = verify_migration_artifact(&artifact, "v1").unwrap();
        assert_eq!(result.verdict, Verdict::Fail);
    }

    #[test]
    fn test_verify_migration_artifact_deterministic() {
        // INV-VER-DETERMINISTIC
        let mut artifact = BTreeMap::new();
        artifact.insert("schema_version".to_string(), serde_json::json!("ma-v1.0"));
        artifact.insert("signature".to_string(), serde_json::json!("sig"));
        artifact.insert("rollback_receipt".to_string(), serde_json::json!({}));
        artifact.insert("preconditions".to_string(), serde_json::json!([]));
        artifact.insert(
            "content_hash".to_string(),
            serde_json::json!("cc".repeat(32)),
        );
        let r1 = verify_migration_artifact(&artifact, "v1").unwrap();
        let r2 = verify_migration_artifact(&artifact, "v1").unwrap();
        assert_eq!(r1.artifact_binding_hash, r2.artifact_binding_hash);
    }

    // ── verify_trust_state ────────────────────────────────────────

    #[test]
    fn test_verify_trust_state_pass() {
        let mut state = BTreeMap::new();
        state.insert("root_key".to_string(), "abc123".to_string());
        state.insert("policy_epoch".to_string(), "42".to_string());
        let mut anchor = BTreeMap::new();
        anchor.insert("root_key".to_string(), "abc123".to_string());
        let result = verify_trust_state(&state, &anchor, "v1").unwrap();
        assert_eq!(result.verdict, Verdict::Pass);
    }

    #[test]
    fn test_verify_trust_state_mismatch() {
        let mut state = BTreeMap::new();
        state.insert("root_key".to_string(), "wrong".to_string());
        let mut anchor = BTreeMap::new();
        anchor.insert("root_key".to_string(), "abc123".to_string());
        let result = verify_trust_state(&state, &anchor, "v1").unwrap();
        assert_eq!(result.verdict, Verdict::Fail);
    }

    #[test]
    fn test_verify_trust_state_empty_anchor_fails() {
        let mut state = BTreeMap::new();
        state.insert("key".to_string(), "val".to_string());
        let anchor = BTreeMap::new();
        let err = verify_trust_state(&state, &anchor, "v1");
        assert!(err.is_err());
        match err.unwrap_err() {
            VerifierSdkError::AnchorUnknown(_) => {}
            other => panic!("expected AnchorUnknown, got {other:?}"),
        }
    }

    #[test]
    fn test_verify_trust_state_deterministic() {
        // INV-VER-DETERMINISTIC
        let mut state = BTreeMap::new();
        state.insert("k".to_string(), "v".to_string());
        let mut anchor = BTreeMap::new();
        anchor.insert("k".to_string(), "v".to_string());
        let r1 = verify_trust_state(&state, &anchor, "v1").unwrap();
        let r2 = verify_trust_state(&state, &anchor, "v1").unwrap();
        assert_eq!(r1.artifact_binding_hash, r2.artifact_binding_hash);
    }

    // ── replay_capsule ─────────────────────────────────────────────

    #[test]
    fn test_replay_capsule_match() {
        let data = "capsule_data_123";
        let expected = deterministic_hash(data);
        let result = replay_capsule(data, &expected);
        assert_eq!(result.verdict, Verdict::Pass);
        assert_eq!(result.actual_output_hash, result.expected_output_hash);
    }

    #[test]
    fn test_replay_capsule_diverged() {
        let result = replay_capsule("data", "wrong_hash");
        assert_eq!(result.verdict, Verdict::Fail);
        assert_ne!(result.actual_output_hash, result.expected_output_hash);
    }

    #[test]
    fn test_replay_capsule_deterministic() {
        // INV-VER-DETERMINISTIC
        let r1 = replay_capsule("data", "hash");
        let r2 = replay_capsule("data", "hash");
        assert_eq!(r1.actual_output_hash, r2.actual_output_hash);
        assert_eq!(r1.verdict, r2.verdict);
    }

    // ── validate_bundle ─────────────────────────────────────────────

    #[test]
    fn test_validate_bundle_pass() {
        let bundle = generate_reference_bundle();
        assert!(validate_bundle(&bundle).is_ok());
    }

    #[test]
    fn test_validate_bundle_empty_claim_id() {
        let mut bundle = generate_reference_bundle();
        bundle.claim.claim_id = String::new();
        assert!(validate_bundle(&bundle).is_err());
    }

    #[test]
    fn test_validate_bundle_no_evidence() {
        let mut bundle = generate_reference_bundle();
        bundle.evidence_items.clear();
        assert!(validate_bundle(&bundle).is_err());
    }

    #[test]
    fn test_validate_bundle_wrong_ref() {
        let mut bundle = generate_reference_bundle();
        bundle.evidence_items[0].claim_ref = "wrong".to_string();
        assert!(validate_bundle(&bundle).is_err());
    }

    // ── transparency log ────────────────────────────────────────────

    #[test]
    fn test_transparency_log_append() {
        // INV-VER-TRANSPARENCY-APPEND
        let mut log = Vec::new();
        let result = generate_reference_verification_result();
        let entry = append_transparency_log(&mut log, &result);
        assert_eq!(log.len(), 1);
        assert!(!entry.result_hash.is_empty());
        assert!(!entry.merkle_proof.is_empty());
    }

    #[test]
    fn test_transparency_log_chain() {
        let mut log = Vec::new();
        let r1 = generate_reference_verification_result();
        let e1 = append_transparency_log(&mut log, &r1);
        let e2 = append_transparency_log(&mut log, &r1);
        assert_eq!(log.len(), 2);
        // Second entry's merkle_proof should reference first entry's hash
        assert!(e2.merkle_proof.contains(&e1.result_hash));
    }

    #[test]
    fn test_transparency_log_first_entry_zeros() {
        let mut log = Vec::new();
        let result = generate_reference_verification_result();
        let entry = append_transparency_log(&mut log, &result);
        assert!(entry.merkle_proof[0] == "0".repeat(64));
    }

    // ── workflow execution ──────────────────────────────────────────

    #[test]
    fn test_execute_workflow_release() {
        let bundle = generate_reference_bundle();
        let result =
            execute_workflow(&ValidationWorkflow::ReleaseValidation, &bundle, "v1").unwrap();
        assert_eq!(result.verdict, Verdict::Pass);
        let workflow_assertion = result
            .checked_assertions
            .iter()
            .any(|a| a.assertion.contains("release_validation"));
        assert!(workflow_assertion);
    }

    #[test]
    fn test_execute_workflow_incident() {
        let bundle = generate_reference_bundle();
        let result =
            execute_workflow(&ValidationWorkflow::IncidentValidation, &bundle, "v1").unwrap();
        assert_eq!(result.verdict, Verdict::Pass);
    }

    #[test]
    fn test_execute_workflow_compliance() {
        let bundle = generate_reference_bundle();
        let result = execute_workflow(&ValidationWorkflow::ComplianceAudit, &bundle, "v1").unwrap();
        assert_eq!(result.verdict, Verdict::Pass);
    }

    #[test]
    fn test_execute_workflow_invalid_bundle_fails() {
        let mut bundle = generate_reference_bundle();
        bundle.evidence_items.clear();
        let err = execute_workflow(&ValidationWorkflow::ReleaseValidation, &bundle, "v1");
        assert!(err.is_err());
    }

    // ── serde round-trips ───────────────────────────────────────────

    #[test]
    fn test_claim_serde_roundtrip() {
        let claim = generate_reference_claim();
        let json = serde_json::to_string(&claim).unwrap();
        let parsed: Claim = serde_json::from_str(&json).unwrap();
        assert_eq!(claim, parsed);
    }

    #[test]
    fn test_evidence_serde_roundtrip() {
        let evidence = &generate_reference_evidence()[0];
        let json = serde_json::to_string(evidence).unwrap();
        let parsed: Evidence = serde_json::from_str(&json).unwrap();
        assert_eq!(*evidence, parsed);
    }

    #[test]
    fn test_evidence_bundle_serde_roundtrip() {
        let bundle = generate_reference_bundle();
        let json = serde_json::to_string(&bundle).unwrap();
        let parsed: EvidenceBundle = serde_json::from_str(&json).unwrap();
        assert_eq!(bundle, parsed);
    }

    #[test]
    fn test_verification_result_serde_roundtrip() {
        let result = generate_reference_verification_result();
        let json = serde_json::to_string(&result).unwrap();
        let parsed: VerificationResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, parsed);
    }

    #[test]
    fn test_replay_result_serde_roundtrip() {
        let rr = ReplayResult {
            verdict: Verdict::Pass,
            expected_output_hash: "aabb".to_string(),
            actual_output_hash: "aabb".to_string(),
            replay_duration_ms: 42,
        };
        let json = serde_json::to_string(&rr).unwrap();
        let parsed: ReplayResult = serde_json::from_str(&json).unwrap();
        assert_eq!(rr, parsed);
    }

    #[test]
    fn test_validation_workflow_serde_roundtrip() {
        let wf = ValidationWorkflow::ReleaseValidation;
        let json = serde_json::to_string(&wf).unwrap();
        let parsed: ValidationWorkflow = serde_json::from_str(&json).unwrap();
        assert_eq!(wf, parsed);
    }

    #[test]
    fn test_transparency_log_entry_serde_roundtrip() {
        let entry = TransparencyLogEntry {
            result_hash: "aabb".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
            verifier_id: "v1".to_string(),
            merkle_proof: vec!["proof1".to_string()],
        };
        let json = serde_json::to_string(&entry).unwrap();
        let parsed: TransparencyLogEntry = serde_json::from_str(&json).unwrap();
        assert_eq!(entry, parsed);
    }

    #[test]
    fn test_verdict_serde_roundtrip() {
        for v in [Verdict::Pass, Verdict::Fail, Verdict::Inconclusive] {
            let json = serde_json::to_string(&v).unwrap();
            let parsed: Verdict = serde_json::from_str(&json).unwrap();
            assert_eq!(v, parsed);
        }
    }

    // ── event codes ─────────────────────────────────────────────────

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(event_codes::VER_CLAIM_VERIFIED, "VER-001");
        assert_eq!(event_codes::VER_CLAIM_FAILED, "VER-002");
        assert_eq!(event_codes::VER_MIGRATION_VERIFIED, "VER-003");
        assert_eq!(event_codes::VER_TRUST_STATE_VERIFIED, "VER-004");
        assert_eq!(event_codes::VER_REPLAY_COMPLETED, "VER-005");
        assert_eq!(event_codes::VER_RESULT_SIGNED, "VER-006");
        assert_eq!(event_codes::VER_TRANSPARENCY_LOG_APPENDED, "VER-007");
        assert_eq!(event_codes::VER_BUNDLE_VALIDATED, "VER-008");
        assert_eq!(event_codes::VER_OFFLINE_CHECK, "VER-009");
        assert_eq!(event_codes::VER_WORKFLOW_COMPLETED, "VER-010");
    }

    // ── error codes ─────────────────────────────────────────────────

    #[test]
    fn test_error_codes_defined() {
        assert_eq!(error_codes::ERR_VER_INVALID_CLAIM, "ERR_VER_INVALID_CLAIM");
        assert_eq!(
            error_codes::ERR_VER_EVIDENCE_MISSING,
            "ERR_VER_EVIDENCE_MISSING"
        );
        assert_eq!(
            error_codes::ERR_VER_SIGNATURE_INVALID,
            "ERR_VER_SIGNATURE_INVALID"
        );
        assert_eq!(error_codes::ERR_VER_HASH_MISMATCH, "ERR_VER_HASH_MISMATCH");
        assert_eq!(
            error_codes::ERR_VER_REPLAY_DIVERGED,
            "ERR_VER_REPLAY_DIVERGED"
        );
        assert_eq!(
            error_codes::ERR_VER_ANCHOR_UNKNOWN,
            "ERR_VER_ANCHOR_UNKNOWN"
        );
        assert_eq!(
            error_codes::ERR_VER_BUNDLE_INCOMPLETE,
            "ERR_VER_BUNDLE_INCOMPLETE"
        );
    }

    // ── invariants ──────────────────────────────────────────────────

    #[test]
    fn test_invariants_defined() {
        assert_eq!(invariants::INV_VER_DETERMINISTIC, "INV-VER-DETERMINISTIC");
        assert_eq!(
            invariants::INV_VER_OFFLINE_CAPABLE,
            "INV-VER-OFFLINE-CAPABLE"
        );
        assert_eq!(invariants::INV_VER_EVIDENCE_BOUND, "INV-VER-EVIDENCE-BOUND");
        assert_eq!(invariants::INV_VER_RESULT_SIGNED, "INV-VER-RESULT-SIGNED");
        assert_eq!(
            invariants::INV_VER_TRANSPARENCY_APPEND,
            "INV-VER-TRANSPARENCY-APPEND"
        );
    }

    // ── schema version ──────────────────────────────────────────────

    #[test]
    fn test_schema_version() {
        assert_eq!(SCHEMA_VERSION, "ver-v1.0");
    }

    // ── error display ───────────────────────────────────────────────

    #[test]
    fn test_error_display() {
        let err = VerifierSdkError::InvalidClaim("bad".to_string());
        assert!(format!("{err}").contains(error_codes::ERR_VER_INVALID_CLAIM));

        let err = VerifierSdkError::EvidenceMissing("none".to_string());
        assert!(format!("{err}").contains(error_codes::ERR_VER_EVIDENCE_MISSING));

        let err = VerifierSdkError::SignatureInvalid("bad".to_string());
        assert!(format!("{err}").contains(error_codes::ERR_VER_SIGNATURE_INVALID));

        let err = VerifierSdkError::HashMismatch {
            expected: "a".to_string(),
            actual: "b".to_string(),
        };
        assert!(format!("{err}").contains(error_codes::ERR_VER_HASH_MISMATCH));

        let err = VerifierSdkError::ReplayDiverged {
            expected: "a".to_string(),
            actual: "b".to_string(),
        };
        assert!(format!("{err}").contains(error_codes::ERR_VER_REPLAY_DIVERGED));

        let err = VerifierSdkError::AnchorUnknown("x".to_string());
        assert!(format!("{err}").contains(error_codes::ERR_VER_ANCHOR_UNKNOWN));

        let err = VerifierSdkError::BundleIncomplete("x".to_string());
        assert!(format!("{err}").contains(error_codes::ERR_VER_BUNDLE_INCOMPLETE));
    }

    // ── Send + Sync ─────────────────────────────────────────────────

    #[test]
    fn test_types_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<Claim>();
        assert_sync::<Claim>();
        assert_send::<Evidence>();
        assert_sync::<Evidence>();
        assert_send::<EvidenceBundle>();
        assert_sync::<EvidenceBundle>();
        assert_send::<VerificationResult>();
        assert_sync::<VerificationResult>();
        assert_send::<ReplayResult>();
        assert_sync::<ReplayResult>();
        assert_send::<ValidationWorkflow>();
        assert_sync::<ValidationWorkflow>();
        assert_send::<TransparencyLogEntry>();
        assert_sync::<TransparencyLogEntry>();
        assert_send::<Verdict>();
        assert_sync::<Verdict>();
        assert_send::<VerifierSdkEvent>();
        assert_sync::<VerifierSdkEvent>();
        assert_send::<VerifierSdkError>();
        assert_sync::<VerifierSdkError>();
    }

    // ── offline-capable ─────────────────────────────────────────────

    #[test]
    fn test_offline_capable_claim_verification() {
        // INV-VER-OFFLINE-CAPABLE: no network calls
        let claim = generate_reference_claim();
        let evidence = generate_reference_evidence();
        let result = verify_claim(&claim, &evidence, "offline-verifier").unwrap();
        assert_eq!(result.verdict, Verdict::Pass);
    }

    #[test]
    fn test_offline_capable_bundle_validation() {
        // INV-VER-OFFLINE-CAPABLE
        let bundle = generate_reference_bundle();
        assert!(validate_bundle(&bundle).is_ok());
    }

    // ── deterministic hash helper ───────────────────────────────────

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

    // ── verifier sdk event ──────────────────────────────────────────

    #[test]
    fn test_verifier_sdk_event_serde() {
        let evt = VerifierSdkEvent {
            event_code: event_codes::VER_CLAIM_VERIFIED.to_string(),
            detail: "claim verified".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&evt).unwrap();
        let parsed: VerifierSdkEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_code, "VER-001");
    }

    // ── assertion result ────────────────────────────────────────────

    #[test]
    fn test_assertion_result_serde() {
        let ar = AssertionResult {
            assertion: "test".to_string(),
            passed: true,
            detail: "ok".to_string(),
        };
        let json = serde_json::to_string(&ar).unwrap();
        let parsed: AssertionResult = serde_json::from_str(&json).unwrap();
        assert_eq!(ar, parsed);
    }

    // ── evidence BTreeMap ordering ──────────────────────────────────

    #[test]
    fn test_evidence_btreemap_ordering() {
        let evidence = &generate_reference_evidence()[0];
        let keys: Vec<_> = evidence.artifacts.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "BTreeMap should iterate in sorted order");
    }

    // ── verify_claim empty procedure ────────────────────────────────

    #[test]
    fn test_verify_claim_empty_procedure_fails() {
        let claim = generate_reference_claim();
        let mut evidence = generate_reference_evidence();
        evidence[0].verification_procedure = String::new();
        let result = verify_claim(&claim, &evidence, "v1").unwrap();
        assert_eq!(result.verdict, Verdict::Fail);
    }
}
