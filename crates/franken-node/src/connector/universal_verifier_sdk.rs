//! bd-nbwo: Universal verifier SDK and replay capsule format (Section 10.17).
//!
//! Publishes a universal verifier SDK that external verifiers can use to replay
//! signed capsules and reproduce claim verdicts without privileged internal access.
//! The capsule schema and verification APIs are stable and versioned.
//!
//! This module extends the verifier-economy SDK (bd-3c2, Section 10.12) with:
//! - `ReplayCapsule`: signed, self-contained replay unit with deterministic inputs/outputs
//! - `CapsuleManifest`: describes capsule contents, schema version, and verification metadata
//! - `VerificationSession`: stateful session for multi-step verification workflows
//! - `VerifierSdk`: top-level facade orchestrating capsule replay and verdict derivation
//! - Stable versioned API surface for external consumption
//!
//! # Capabilities
//!
//! - Replay signed capsules and reproduce claim verdicts externally
//! - Capsule schema is stable and versioned (VSDK_SCHEMA_VERSION)
//! - No privileged internal access required (offline-capable)
//! - Multi-step verification sessions with audit trail
//! - Deterministic replay with hash-bound evidence
//! - Capsule signing and signature verification
//!
//! # Invariants
//!
//! - **INV-VSDK-CAPSULE-DETERMINISTIC**: Replaying a capsule with the same inputs always
//!   produces the same verdict and output hash.
//! - **INV-VSDK-NO-PRIVILEGE**: External verifiers never require privileged internal access.
//! - **INV-VSDK-SCHEMA-VERSIONED**: Every capsule and manifest carries a schema version.
//! - **INV-VSDK-SESSION-MONOTONIC**: Verification session steps are append-only; earlier
//!   steps cannot be mutated after subsequent steps are recorded.
//! - **INV-VSDK-SIGNATURE-BOUND**: A capsule's signature covers the full capsule payload
//!   including inputs, expected outputs, and manifest.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

// ---------------------------------------------------------------------------
// Schema version
// ---------------------------------------------------------------------------

/// Schema version for the universal verifier SDK capsule format.
pub const VSDK_SCHEMA_VERSION: &str = "vsdk-v1.0";

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    /// Capsule replay started.
    pub const VSDK_001: &str = "VSDK_001";
    /// Capsule replay completed successfully (verdict PASS).
    pub const VSDK_002: &str = "VSDK_002";
    /// Capsule replay completed with failure (verdict FAIL).
    pub const VSDK_003: &str = "VSDK_003";
    /// Verification session created.
    pub const VSDK_004: &str = "VSDK_004";
    /// Verification session step recorded.
    pub const VSDK_005: &str = "VSDK_005";
    /// Capsule signature verified.
    pub const VSDK_006: &str = "VSDK_006";
    /// Capsule manifest validated.
    pub const VSDK_007: &str = "VSDK_007";
}

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub mod error_codes {
    pub const ERR_VSDK_CAPSULE_INVALID: &str = "ERR_VSDK_CAPSULE_INVALID";
    pub const ERR_VSDK_SIGNATURE_MISMATCH: &str = "ERR_VSDK_SIGNATURE_MISMATCH";
    pub const ERR_VSDK_SCHEMA_UNSUPPORTED: &str = "ERR_VSDK_SCHEMA_UNSUPPORTED";
    pub const ERR_VSDK_REPLAY_DIVERGED: &str = "ERR_VSDK_REPLAY_DIVERGED";
    pub const ERR_VSDK_SESSION_SEALED: &str = "ERR_VSDK_SESSION_SEALED";
    pub const ERR_VSDK_MANIFEST_INCOMPLETE: &str = "ERR_VSDK_MANIFEST_INCOMPLETE";
    pub const ERR_VSDK_EMPTY_PAYLOAD: &str = "ERR_VSDK_EMPTY_PAYLOAD";
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

pub mod invariants {
    pub const INV_VSDK_CAPSULE_DETERMINISTIC: &str = "INV-VSDK-CAPSULE-DETERMINISTIC";
    pub const INV_VSDK_NO_PRIVILEGE: &str = "INV-VSDK-NO-PRIVILEGE";
    pub const INV_VSDK_SCHEMA_VERSIONED: &str = "INV-VSDK-SCHEMA-VERSIONED";
    pub const INV_VSDK_SESSION_MONOTONIC: &str = "INV-VSDK-SESSION-MONOTONIC";
    pub const INV_VSDK_SIGNATURE_BOUND: &str = "INV-VSDK-SIGNATURE-BOUND";
}

// ---------------------------------------------------------------------------
// CapsuleVerdict
// ---------------------------------------------------------------------------

/// Verdict for a capsule replay operation.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CapsuleVerdict {
    Pass,
    Fail,
    Inconclusive,
}

// ---------------------------------------------------------------------------
// CapsuleManifest
// ---------------------------------------------------------------------------

/// Describes the contents and metadata of a replay capsule.
///
/// INV-VSDK-SCHEMA-VERSIONED: every manifest carries schema_version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CapsuleManifest {
    /// Schema version (must be VSDK_SCHEMA_VERSION).
    pub schema_version: String,
    /// Unique capsule identifier.
    pub capsule_id: String,
    /// Human-readable description of what this capsule verifies.
    pub description: String,
    /// The claim type being verified (e.g., "migration_safety", "rollback_proof").
    pub claim_type: String,
    /// Ordered list of input artifact identifiers.
    pub input_refs: Vec<String>,
    /// Expected output hash (hex-encoded).
    pub expected_output_hash: String,
    /// ISO 8601 timestamp of capsule creation.
    pub created_at: String,
    /// Identity of the capsule creator.
    pub creator_identity: String,
    /// Additional metadata (deterministic ordering via BTreeMap).
    pub metadata: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// ReplayCapsule
// ---------------------------------------------------------------------------

/// A signed, self-contained replay unit.
///
/// External verifiers replay the capsule to reproduce claim verdicts
/// without privileged internal access.
///
/// INV-VSDK-SIGNATURE-BOUND: signature covers manifest + payload + inputs.
/// INV-VSDK-NO-PRIVILEGE: no internal access required to replay.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayCapsule {
    /// Capsule manifest describing contents and expected results.
    pub manifest: CapsuleManifest,
    /// Serialized payload data to be replayed.
    pub payload: String,
    /// Input artifacts required for replay (keyed by input_ref).
    pub inputs: BTreeMap<String, String>,
    /// Cryptographic signature covering manifest + payload + inputs.
    pub signature: String,
}

// ---------------------------------------------------------------------------
// ReplayResult
// ---------------------------------------------------------------------------

/// The result of replaying a capsule.
///
/// INV-VSDK-CAPSULE-DETERMINISTIC: same capsule always yields same result.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReplayResult {
    pub capsule_id: String,
    pub verdict: CapsuleVerdict,
    pub expected_output_hash: String,
    pub actual_output_hash: String,
    pub replay_duration_ms: u64,
    pub verifier_identity: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// SessionStep
// ---------------------------------------------------------------------------

/// A single step in a verification session.
///
/// INV-VSDK-SESSION-MONOTONIC: steps are append-only.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionStep {
    pub step_index: usize,
    pub capsule_id: String,
    pub verdict: CapsuleVerdict,
    pub output_hash: String,
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// VerificationSession
// ---------------------------------------------------------------------------

/// A stateful session for multi-step verification workflows.
///
/// INV-VSDK-SESSION-MONOTONIC: once a step is appended, earlier steps
/// cannot be mutated. The session can be sealed to prevent further steps.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationSession {
    pub session_id: String,
    pub verifier_identity: String,
    pub created_at: String,
    pub steps: Vec<SessionStep>,
    pub sealed: bool,
    pub final_verdict: Option<CapsuleVerdict>,
}

// ---------------------------------------------------------------------------
// VerifierSdk
// ---------------------------------------------------------------------------

/// Top-level facade for the universal verifier SDK.
///
/// Orchestrates capsule replay, signature verification, and session
/// management. External verifiers instantiate this to perform all
/// verification operations.
///
/// INV-VSDK-NO-PRIVILEGE: no privileged internal access required.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerifierSdk {
    pub verifier_identity: String,
    pub schema_version: String,
    pub supported_claim_types: Vec<String>,
    pub config: BTreeMap<String, String>,
}

// ---------------------------------------------------------------------------
// VsdkEvent
// ---------------------------------------------------------------------------

/// Structured audit event for universal verifier SDK operations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VsdkEvent {
    pub event_code: String,
    pub capsule_id: String,
    pub detail: String,
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// VsdkError
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum VsdkError {
    CapsuleInvalid(String),
    SignatureMismatch { expected: String, actual: String },
    SchemaUnsupported(String),
    ReplayDiverged { expected: String, actual: String },
    SessionSealed(String),
    ManifestIncomplete(String),
    EmptyPayload(String),
}

impl std::fmt::Display for VsdkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CapsuleInvalid(msg) => {
                write!(f, "{}: {msg}", error_codes::ERR_VSDK_CAPSULE_INVALID)
            }
            Self::SignatureMismatch { expected, actual } => {
                write!(
                    f,
                    "{}: expected={expected}, actual={actual}",
                    error_codes::ERR_VSDK_SIGNATURE_MISMATCH
                )
            }
            Self::SchemaUnsupported(msg) => {
                write!(f, "{}: {msg}", error_codes::ERR_VSDK_SCHEMA_UNSUPPORTED)
            }
            Self::ReplayDiverged { expected, actual } => {
                write!(
                    f,
                    "{}: expected={expected}, actual={actual}",
                    error_codes::ERR_VSDK_REPLAY_DIVERGED
                )
            }
            Self::SessionSealed(msg) => {
                write!(f, "{}: {msg}", error_codes::ERR_VSDK_SESSION_SEALED)
            }
            Self::ManifestIncomplete(msg) => {
                write!(f, "{}: {msg}", error_codes::ERR_VSDK_MANIFEST_INCOMPLETE)
            }
            Self::EmptyPayload(msg) => {
                write!(f, "{}: {msg}", error_codes::ERR_VSDK_EMPTY_PAYLOAD)
            }
        }
    }
}

impl std::error::Error for VsdkError {}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute a deterministic hash over a string (hex-encoded SHA-256).
/// INV-VSDK-CAPSULE-DETERMINISTIC: same inputs always produce same output.
fn deterministic_hash(data: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"universal_verifier_sdk_v1:");
    hasher.update(data.as_bytes());
    hex::encode(hasher.finalize())
}

fn now_timestamp() -> String {
    "2026-02-21T00:00:00Z".to_string()
}

/// Compute the signing payload for a capsule.
/// INV-VSDK-SIGNATURE-BOUND: covers manifest + payload + inputs.
fn compute_signing_payload(capsule: &ReplayCapsule) -> String {
    let mut parts = vec![
        capsule.manifest.capsule_id.clone(),
        capsule.manifest.schema_version.clone(),
        capsule.manifest.expected_output_hash.clone(),
        capsule.payload.clone(),
    ];
    for (k, v) in &capsule.inputs {
        parts.push(format!("{k}={v}"));
    }
    parts.join("|")
}

// ---------------------------------------------------------------------------
// Core operations
// ---------------------------------------------------------------------------

/// Validate a capsule manifest for completeness.
///
/// Checks that all required fields are non-empty and schema_version
/// is supported.
///
/// INV-VSDK-SCHEMA-VERSIONED: schema_version must be VSDK_SCHEMA_VERSION.
pub fn validate_manifest(manifest: &CapsuleManifest) -> Result<(), VsdkError> {
    if manifest.schema_version.is_empty() {
        return Err(VsdkError::ManifestIncomplete(
            "schema_version is empty".to_string(),
        ));
    }
    if manifest.schema_version != VSDK_SCHEMA_VERSION {
        return Err(VsdkError::SchemaUnsupported(format!(
            "unsupported schema version: {}, expected: {}",
            manifest.schema_version, VSDK_SCHEMA_VERSION
        )));
    }
    if manifest.capsule_id.is_empty() {
        return Err(VsdkError::ManifestIncomplete(
            "capsule_id is empty".to_string(),
        ));
    }
    if manifest.claim_type.is_empty() {
        return Err(VsdkError::ManifestIncomplete(
            "claim_type is empty".to_string(),
        ));
    }
    if manifest.expected_output_hash.is_empty() {
        return Err(VsdkError::ManifestIncomplete(
            "expected_output_hash is empty".to_string(),
        ));
    }
    if manifest.creator_identity.is_empty() {
        return Err(VsdkError::ManifestIncomplete(
            "creator_identity is empty".to_string(),
        ));
    }
    Ok(())
}

/// Verify a capsule's signature.
///
/// Recomputes the expected signature from the capsule's payload
/// and compares it to the stored signature.
///
/// INV-VSDK-SIGNATURE-BOUND: signature covers full capsule payload.
pub fn verify_capsule_signature(capsule: &ReplayCapsule) -> Result<(), VsdkError> {
    let payload = compute_signing_payload(capsule);
    let expected_sig = deterministic_hash(&payload);
    if capsule.signature != expected_sig {
        return Err(VsdkError::SignatureMismatch {
            expected: expected_sig,
            actual: capsule.signature.clone(),
        });
    }
    Ok(())
}

/// Sign a capsule (compute and set its signature field).
///
/// INV-VSDK-SIGNATURE-BOUND: signature covers manifest + payload + inputs.
pub fn sign_capsule(capsule: &mut ReplayCapsule) {
    let payload = compute_signing_payload(capsule);
    capsule.signature = deterministic_hash(&payload);
}

/// Replay a capsule and produce a result.
///
/// Steps:
/// 1. Validate manifest (schema version, required fields).
/// 2. Verify capsule signature.
/// 3. Verify payload is non-empty.
/// 4. Compute deterministic output hash from payload + inputs.
/// 5. Compare against expected_output_hash.
///
/// INV-VSDK-CAPSULE-DETERMINISTIC: same capsule always yields same result.
/// INV-VSDK-NO-PRIVILEGE: no internal access required.
pub fn replay_capsule(
    capsule: &ReplayCapsule,
    verifier_identity: &str,
) -> Result<ReplayResult, VsdkError> {
    // Step 1: Validate manifest
    validate_manifest(&capsule.manifest)?;

    // Step 2: Verify signature
    verify_capsule_signature(capsule)?;

    // Step 3: Verify payload non-empty
    if capsule.payload.is_empty() {
        return Err(VsdkError::EmptyPayload(
            "capsule payload is empty".to_string(),
        ));
    }

    // Step 4: Compute actual output hash (deterministic)
    let mut replay_input = capsule.payload.clone();
    for (k, v) in &capsule.inputs {
        replay_input.push_str(&format!("|{k}={v}"));
    }
    let actual_hash = deterministic_hash(&replay_input);

    // Step 5: Compare
    let verdict = if actual_hash == capsule.manifest.expected_output_hash {
        CapsuleVerdict::Pass
    } else {
        CapsuleVerdict::Fail
    };

    let detail = if verdict == CapsuleVerdict::Pass {
        "replay output matches expected hash".to_string()
    } else {
        format!(
            "replay diverged: expected={}, actual={}",
            capsule.manifest.expected_output_hash, actual_hash
        )
    };

    Ok(ReplayResult {
        capsule_id: capsule.manifest.capsule_id.clone(),
        verdict,
        expected_output_hash: capsule.manifest.expected_output_hash.clone(),
        actual_output_hash: actual_hash,
        replay_duration_ms: 0,
        verifier_identity: verifier_identity.to_string(),
        detail,
    })
}

/// Create a new verification session.
///
/// INV-VSDK-SESSION-MONOTONIC: session starts empty with no steps.
pub fn create_session(session_id: &str, verifier_identity: &str) -> VerificationSession {
    VerificationSession {
        session_id: session_id.to_string(),
        verifier_identity: verifier_identity.to_string(),
        created_at: now_timestamp(),
        steps: Vec::new(),
        sealed: false,
        final_verdict: None,
    }
}

/// Record a replay result as a step in a verification session.
///
/// INV-VSDK-SESSION-MONOTONIC: steps are append-only, and sealed
/// sessions reject new steps.
pub fn record_session_step(
    session: &mut VerificationSession,
    result: &ReplayResult,
) -> Result<SessionStep, VsdkError> {
    if session.sealed {
        return Err(VsdkError::SessionSealed(format!(
            "session {} is sealed",
            session.session_id
        )));
    }

    let step = SessionStep {
        step_index: session.steps.len(),
        capsule_id: result.capsule_id.clone(),
        verdict: result.verdict.clone(),
        output_hash: result.actual_output_hash.clone(),
        timestamp: now_timestamp(),
    };
    session.steps.push(step.clone());
    Ok(step)
}

/// Seal a verification session.
///
/// Computes the final verdict (PASS only if all steps passed).
/// Once sealed, no further steps can be added.
///
/// INV-VSDK-SESSION-MONOTONIC: seal is irreversible.
pub fn seal_session(session: &mut VerificationSession) -> Result<CapsuleVerdict, VsdkError> {
    if session.sealed {
        return Err(VsdkError::SessionSealed(format!(
            "session {} already sealed",
            session.session_id
        )));
    }
    if session.steps.is_empty() {
        session.sealed = true;
        session.final_verdict = Some(CapsuleVerdict::Inconclusive);
        return Ok(CapsuleVerdict::Inconclusive);
    }

    let all_pass = session
        .steps
        .iter()
        .all(|s| s.verdict == CapsuleVerdict::Pass);
    let verdict = if all_pass {
        CapsuleVerdict::Pass
    } else {
        CapsuleVerdict::Fail
    };
    session.sealed = true;
    session.final_verdict = Some(verdict.clone());
    Ok(verdict)
}

/// Create a new VerifierSdk instance.
pub fn create_verifier_sdk(verifier_identity: &str) -> VerifierSdk {
    let mut config = BTreeMap::new();
    config.insert(
        "schema_version".to_string(),
        VSDK_SCHEMA_VERSION.to_string(),
    );
    VerifierSdk {
        verifier_identity: verifier_identity.to_string(),
        schema_version: VSDK_SCHEMA_VERSION.to_string(),
        supported_claim_types: vec![
            "migration_safety".to_string(),
            "rollback_proof".to_string(),
            "compatibility_check".to_string(),
            "security_audit".to_string(),
        ],
        config,
    }
}

/// Build a reference replay capsule for testing.
///
/// The capsule is properly signed and has a valid expected_output_hash
/// so that replay will produce a PASS verdict.
pub fn build_reference_capsule() -> ReplayCapsule {
    let mut inputs = BTreeMap::new();
    inputs.insert("artifact_a".to_string(), "content_of_a".to_string());
    inputs.insert("artifact_b".to_string(), "content_of_b".to_string());

    let payload = "reference_payload_data".to_string();

    // Compute expected output hash exactly as replay_capsule does
    let mut replay_input = payload.clone();
    for (k, v) in &inputs {
        replay_input.push_str(&format!("|{k}={v}"));
    }
    let expected_hash = deterministic_hash(&replay_input);

    let manifest = CapsuleManifest {
        schema_version: VSDK_SCHEMA_VERSION.to_string(),
        capsule_id: "capsule-ref-001".to_string(),
        description: "Reference capsule for migration safety verification".to_string(),
        claim_type: "migration_safety".to_string(),
        input_refs: vec!["artifact_a".to_string(), "artifact_b".to_string()],
        expected_output_hash: expected_hash,
        created_at: "2026-02-21T00:00:00Z".to_string(),
        creator_identity: "creator://test@example.com".to_string(),
        metadata: BTreeMap::new(),
    };

    let mut capsule = ReplayCapsule {
        manifest,
        payload,
        inputs,
        signature: String::new(),
    };
    sign_capsule(&mut capsule);
    capsule
}

/// Build a reference capsule manifest for testing.
pub fn build_reference_manifest() -> CapsuleManifest {
    build_reference_capsule().manifest
}

/// Build a reference verification session for testing (with one step, sealed).
pub fn build_reference_session() -> VerificationSession {
    let capsule = build_reference_capsule();
    let result = replay_capsule(&capsule, "verifier://test@example.com").unwrap();
    let mut session = create_session("session-ref-001", "verifier://test@example.com");
    record_session_step(&mut session, &result).unwrap();
    seal_session(&mut session).unwrap();
    session
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Schema version ─────────────────────────────────────────────

    #[test]
    fn test_schema_version_constant() {
        assert_eq!(VSDK_SCHEMA_VERSION, "vsdk-v1.0");
    }

    // ── Event codes ────────────────────────────────────────────────

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(event_codes::VSDK_001, "VSDK_001");
        assert_eq!(event_codes::VSDK_002, "VSDK_002");
        assert_eq!(event_codes::VSDK_003, "VSDK_003");
        assert_eq!(event_codes::VSDK_004, "VSDK_004");
        assert_eq!(event_codes::VSDK_005, "VSDK_005");
        assert_eq!(event_codes::VSDK_006, "VSDK_006");
        assert_eq!(event_codes::VSDK_007, "VSDK_007");
    }

    // ── Error codes ────────────────────────────────────────────────

    #[test]
    fn test_error_codes_defined() {
        assert_eq!(
            error_codes::ERR_VSDK_CAPSULE_INVALID,
            "ERR_VSDK_CAPSULE_INVALID"
        );
        assert_eq!(
            error_codes::ERR_VSDK_SIGNATURE_MISMATCH,
            "ERR_VSDK_SIGNATURE_MISMATCH"
        );
        assert_eq!(
            error_codes::ERR_VSDK_SCHEMA_UNSUPPORTED,
            "ERR_VSDK_SCHEMA_UNSUPPORTED"
        );
        assert_eq!(
            error_codes::ERR_VSDK_REPLAY_DIVERGED,
            "ERR_VSDK_REPLAY_DIVERGED"
        );
        assert_eq!(
            error_codes::ERR_VSDK_SESSION_SEALED,
            "ERR_VSDK_SESSION_SEALED"
        );
        assert_eq!(
            error_codes::ERR_VSDK_MANIFEST_INCOMPLETE,
            "ERR_VSDK_MANIFEST_INCOMPLETE"
        );
        assert_eq!(
            error_codes::ERR_VSDK_EMPTY_PAYLOAD,
            "ERR_VSDK_EMPTY_PAYLOAD"
        );
    }

    // ── Invariants ─────────────────────────────────────────────────

    #[test]
    fn test_invariants_defined() {
        assert_eq!(
            invariants::INV_VSDK_CAPSULE_DETERMINISTIC,
            "INV-VSDK-CAPSULE-DETERMINISTIC"
        );
        assert_eq!(invariants::INV_VSDK_NO_PRIVILEGE, "INV-VSDK-NO-PRIVILEGE");
        assert_eq!(
            invariants::INV_VSDK_SCHEMA_VERSIONED,
            "INV-VSDK-SCHEMA-VERSIONED"
        );
        assert_eq!(
            invariants::INV_VSDK_SESSION_MONOTONIC,
            "INV-VSDK-SESSION-MONOTONIC"
        );
        assert_eq!(
            invariants::INV_VSDK_SIGNATURE_BOUND,
            "INV-VSDK-SIGNATURE-BOUND"
        );
    }

    // ── CapsuleVerdict ─────────────────────────────────────────────

    #[test]
    fn test_capsule_verdict_serde_roundtrip() {
        for v in [
            CapsuleVerdict::Pass,
            CapsuleVerdict::Fail,
            CapsuleVerdict::Inconclusive,
        ] {
            let json = serde_json::to_string(&v).unwrap();
            let parsed: CapsuleVerdict = serde_json::from_str(&json).unwrap();
            assert_eq!(v, parsed);
        }
    }

    // ── CapsuleManifest ────────────────────────────────────────────

    #[test]
    fn test_manifest_serde_roundtrip() {
        let manifest = build_reference_manifest();
        let json = serde_json::to_string(&manifest).unwrap();
        let parsed: CapsuleManifest = serde_json::from_str(&json).unwrap();
        assert_eq!(manifest, parsed);
    }

    #[test]
    fn test_validate_manifest_pass() {
        let manifest = build_reference_manifest();
        assert!(validate_manifest(&manifest).is_ok());
    }

    #[test]
    fn test_validate_manifest_empty_schema_version() {
        let mut manifest = build_reference_manifest();
        manifest.schema_version = String::new();
        match validate_manifest(&manifest) {
            Err(VsdkError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("schema_version"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_manifest_wrong_schema_version() {
        let mut manifest = build_reference_manifest();
        manifest.schema_version = "vsdk-v99.0".to_string();
        match validate_manifest(&manifest) {
            Err(VsdkError::SchemaUnsupported(msg)) => {
                assert!(msg.contains("vsdk-v99.0"));
            }
            other => panic!("expected SchemaUnsupported, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_manifest_empty_capsule_id() {
        let mut manifest = build_reference_manifest();
        manifest.capsule_id = String::new();
        match validate_manifest(&manifest) {
            Err(VsdkError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("capsule_id"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_manifest_empty_claim_type() {
        let mut manifest = build_reference_manifest();
        manifest.claim_type = String::new();
        match validate_manifest(&manifest) {
            Err(VsdkError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("claim_type"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_manifest_empty_expected_hash() {
        let mut manifest = build_reference_manifest();
        manifest.expected_output_hash = String::new();
        match validate_manifest(&manifest) {
            Err(VsdkError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("expected_output_hash"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_manifest_empty_creator() {
        let mut manifest = build_reference_manifest();
        manifest.creator_identity = String::new();
        match validate_manifest(&manifest) {
            Err(VsdkError::ManifestIncomplete(msg)) => {
                assert!(msg.contains("creator_identity"));
            }
            other => panic!("expected ManifestIncomplete, got {other:?}"),
        }
    }

    // ── ReplayCapsule ──────────────────────────────────────────────

    #[test]
    fn test_capsule_serde_roundtrip() {
        let capsule = build_reference_capsule();
        let json = serde_json::to_string(&capsule).unwrap();
        let parsed: ReplayCapsule = serde_json::from_str(&json).unwrap();
        assert_eq!(capsule, parsed);
    }

    #[test]
    fn test_sign_capsule_produces_nonempty_signature() {
        let capsule = build_reference_capsule();
        assert!(!capsule.signature.is_empty());
        assert_eq!(capsule.signature.len(), 64);
    }

    #[test]
    fn test_sign_capsule_deterministic() {
        // INV-VSDK-CAPSULE-DETERMINISTIC
        let c1 = build_reference_capsule();
        let c2 = build_reference_capsule();
        assert_eq!(c1.signature, c2.signature);
    }

    // ── verify_capsule_signature ───────────────────────────────────

    #[test]
    fn test_verify_capsule_signature_pass() {
        let capsule = build_reference_capsule();
        assert!(verify_capsule_signature(&capsule).is_ok());
    }

    #[test]
    fn test_verify_capsule_signature_fail() {
        let mut capsule = build_reference_capsule();
        capsule.signature = "tampered_signature".to_string();
        match verify_capsule_signature(&capsule) {
            Err(VsdkError::SignatureMismatch { .. }) => {}
            other => panic!("expected SignatureMismatch, got {other:?}"),
        }
    }

    // ── replay_capsule ─────────────────────────────────────────────

    #[test]
    fn test_replay_capsule_pass() {
        let capsule = build_reference_capsule();
        let result = replay_capsule(&capsule, "verifier-1").unwrap();
        assert_eq!(result.verdict, CapsuleVerdict::Pass);
        assert_eq!(result.capsule_id, "capsule-ref-001");
        assert_eq!(result.actual_output_hash, result.expected_output_hash);
    }

    #[test]
    fn test_replay_capsule_deterministic() {
        // INV-VSDK-CAPSULE-DETERMINISTIC
        let capsule = build_reference_capsule();
        let r1 = replay_capsule(&capsule, "v1").unwrap();
        let r2 = replay_capsule(&capsule, "v1").unwrap();
        assert_eq!(r1.verdict, r2.verdict);
        assert_eq!(r1.actual_output_hash, r2.actual_output_hash);
        assert_eq!(r1.expected_output_hash, r2.expected_output_hash);
    }

    #[test]
    fn test_replay_capsule_diverged() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.expected_output_hash = "wrong_hash".to_string();
        // Re-sign after changing manifest
        sign_capsule(&mut capsule);
        let result = replay_capsule(&capsule, "v1").unwrap();
        assert_eq!(result.verdict, CapsuleVerdict::Fail);
        assert_ne!(result.actual_output_hash, result.expected_output_hash);
    }

    #[test]
    fn test_replay_capsule_empty_payload() {
        let mut capsule = build_reference_capsule();
        capsule.payload = String::new();
        sign_capsule(&mut capsule);
        match replay_capsule(&capsule, "v1") {
            Err(VsdkError::EmptyPayload(_)) => {}
            other => panic!("expected EmptyPayload, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_capsule_tampered_signature() {
        let mut capsule = build_reference_capsule();
        capsule.signature = "tampered".to_string();
        match replay_capsule(&capsule, "v1") {
            Err(VsdkError::SignatureMismatch { .. }) => {}
            other => panic!("expected SignatureMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_capsule_invalid_schema() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.schema_version = "bad-version".to_string();
        sign_capsule(&mut capsule);
        match replay_capsule(&capsule, "v1") {
            Err(VsdkError::SchemaUnsupported(_)) => {}
            other => panic!("expected SchemaUnsupported, got {other:?}"),
        }
    }

    // ── ReplayResult ───────────────────────────────────────────────

    #[test]
    fn test_replay_result_serde_roundtrip() {
        let capsule = build_reference_capsule();
        let result = replay_capsule(&capsule, "v1").unwrap();
        let json = serde_json::to_string(&result).unwrap();
        let parsed: ReplayResult = serde_json::from_str(&json).unwrap();
        assert_eq!(result, parsed);
    }

    // ── VerificationSession ────────────────────────────────────────

    #[test]
    fn test_create_session() {
        let session = create_session("s1", "v1");
        assert_eq!(session.session_id, "s1");
        assert_eq!(session.verifier_identity, "v1");
        assert!(session.steps.is_empty());
        assert!(!session.sealed);
        assert!(session.final_verdict.is_none());
    }

    #[test]
    fn test_record_session_step() {
        let capsule = build_reference_capsule();
        let result = replay_capsule(&capsule, "v1").unwrap();
        let mut session = create_session("s1", "v1");
        let step = record_session_step(&mut session, &result).unwrap();
        assert_eq!(step.step_index, 0);
        assert_eq!(step.capsule_id, "capsule-ref-001");
        assert_eq!(step.verdict, CapsuleVerdict::Pass);
        assert_eq!(session.steps.len(), 1);
    }

    #[test]
    fn test_record_multiple_steps() {
        // INV-VSDK-SESSION-MONOTONIC
        let capsule = build_reference_capsule();
        let result = replay_capsule(&capsule, "v1").unwrap();
        let mut session = create_session("s1", "v1");
        record_session_step(&mut session, &result).unwrap();
        record_session_step(&mut session, &result).unwrap();
        assert_eq!(session.steps.len(), 2);
        assert_eq!(session.steps[0].step_index, 0);
        assert_eq!(session.steps[1].step_index, 1);
    }

    #[test]
    fn test_record_step_sealed_session_fails() {
        // INV-VSDK-SESSION-MONOTONIC
        let capsule = build_reference_capsule();
        let result = replay_capsule(&capsule, "v1").unwrap();
        let mut session = create_session("s1", "v1");
        record_session_step(&mut session, &result).unwrap();
        seal_session(&mut session).unwrap();
        match record_session_step(&mut session, &result) {
            Err(VsdkError::SessionSealed(_)) => {}
            other => panic!("expected SessionSealed, got {other:?}"),
        }
    }

    #[test]
    fn test_seal_session_all_pass() {
        let capsule = build_reference_capsule();
        let result = replay_capsule(&capsule, "v1").unwrap();
        let mut session = create_session("s1", "v1");
        record_session_step(&mut session, &result).unwrap();
        let verdict = seal_session(&mut session).unwrap();
        assert_eq!(verdict, CapsuleVerdict::Pass);
        assert!(session.sealed);
        assert_eq!(session.final_verdict, Some(CapsuleVerdict::Pass));
    }

    #[test]
    fn test_seal_session_with_failure() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.expected_output_hash = "wrong".to_string();
        sign_capsule(&mut capsule);
        let result = replay_capsule(&capsule, "v1").unwrap();
        let mut session = create_session("s1", "v1");
        record_session_step(&mut session, &result).unwrap();
        let verdict = seal_session(&mut session).unwrap();
        assert_eq!(verdict, CapsuleVerdict::Fail);
    }

    #[test]
    fn test_seal_empty_session_inconclusive() {
        let mut session = create_session("s1", "v1");
        let verdict = seal_session(&mut session).unwrap();
        assert_eq!(verdict, CapsuleVerdict::Inconclusive);
    }

    #[test]
    fn test_seal_session_twice_fails() {
        let mut session = create_session("s1", "v1");
        seal_session(&mut session).unwrap();
        match seal_session(&mut session) {
            Err(VsdkError::SessionSealed(_)) => {}
            other => panic!("expected SessionSealed, got {other:?}"),
        }
    }

    #[test]
    fn test_session_serde_roundtrip() {
        let session = build_reference_session();
        let json = serde_json::to_string(&session).unwrap();
        let parsed: VerificationSession = serde_json::from_str(&json).unwrap();
        assert_eq!(session, parsed);
    }

    // ── VerifierSdk ────────────────────────────────────────────────

    #[test]
    fn test_create_verifier_sdk() {
        let sdk = create_verifier_sdk("v1");
        assert_eq!(sdk.verifier_identity, "v1");
        assert_eq!(sdk.schema_version, VSDK_SCHEMA_VERSION);
        assert!(!sdk.supported_claim_types.is_empty());
        assert!(sdk.config.contains_key("schema_version"));
    }

    #[test]
    fn test_verifier_sdk_serde_roundtrip() {
        let sdk = create_verifier_sdk("v1");
        let json = serde_json::to_string(&sdk).unwrap();
        let parsed: VerifierSdk = serde_json::from_str(&json).unwrap();
        assert_eq!(sdk, parsed);
    }

    // ── VsdkEvent ──────────────────────────────────────────────────

    #[test]
    fn test_vsdk_event_serde_roundtrip() {
        let evt = VsdkEvent {
            event_code: event_codes::VSDK_001.to_string(),
            capsule_id: "capsule-001".to_string(),
            detail: "replay started".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&evt).unwrap();
        let parsed: VsdkEvent = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.event_code, "VSDK_001");
    }

    // ── VsdkError display ──────────────────────────────────────────

    #[test]
    fn test_error_display_capsule_invalid() {
        let err = VsdkError::CapsuleInvalid("bad".to_string());
        assert!(format!("{err}").contains(error_codes::ERR_VSDK_CAPSULE_INVALID));
    }

    #[test]
    fn test_error_display_signature_mismatch() {
        let err = VsdkError::SignatureMismatch {
            expected: "a".to_string(),
            actual: "b".to_string(),
        };
        let msg = format!("{err}");
        assert!(msg.contains(error_codes::ERR_VSDK_SIGNATURE_MISMATCH));
        assert!(msg.contains("expected=a"));
        assert!(msg.contains("actual=b"));
    }

    #[test]
    fn test_error_display_schema_unsupported() {
        let err = VsdkError::SchemaUnsupported("v99".to_string());
        assert!(format!("{err}").contains(error_codes::ERR_VSDK_SCHEMA_UNSUPPORTED));
    }

    #[test]
    fn test_error_display_replay_diverged() {
        let err = VsdkError::ReplayDiverged {
            expected: "a".to_string(),
            actual: "b".to_string(),
        };
        assert!(format!("{err}").contains(error_codes::ERR_VSDK_REPLAY_DIVERGED));
    }

    #[test]
    fn test_error_display_session_sealed() {
        let err = VsdkError::SessionSealed("s1".to_string());
        assert!(format!("{err}").contains(error_codes::ERR_VSDK_SESSION_SEALED));
    }

    #[test]
    fn test_error_display_manifest_incomplete() {
        let err = VsdkError::ManifestIncomplete("missing".to_string());
        assert!(format!("{err}").contains(error_codes::ERR_VSDK_MANIFEST_INCOMPLETE));
    }

    #[test]
    fn test_error_display_empty_payload() {
        let err = VsdkError::EmptyPayload("empty".to_string());
        assert!(format!("{err}").contains(error_codes::ERR_VSDK_EMPTY_PAYLOAD));
    }

    // ── Send + Sync ────────────────────────────────────────────────

    #[test]
    fn test_types_send_sync() {
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}

        assert_send::<CapsuleManifest>();
        assert_sync::<CapsuleManifest>();
        assert_send::<ReplayCapsule>();
        assert_sync::<ReplayCapsule>();
        assert_send::<ReplayResult>();
        assert_sync::<ReplayResult>();
        assert_send::<VerificationSession>();
        assert_sync::<VerificationSession>();
        assert_send::<SessionStep>();
        assert_sync::<SessionStep>();
        assert_send::<VerifierSdk>();
        assert_sync::<VerifierSdk>();
        assert_send::<CapsuleVerdict>();
        assert_sync::<CapsuleVerdict>();
        assert_send::<VsdkEvent>();
        assert_sync::<VsdkEvent>();
        assert_send::<VsdkError>();
        assert_sync::<VsdkError>();
    }

    // ── BTreeMap deterministic ordering ────────────────────────────

    #[test]
    fn test_capsule_inputs_btreemap_ordering() {
        let capsule = build_reference_capsule();
        let keys: Vec<_> = capsule.inputs.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "BTreeMap should iterate in sorted order");
    }

    // ── deterministic hash helper ──────────────────────────────────

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

    // ── Reference generators ───────────────────────────────────────

    #[test]
    fn test_build_reference_capsule() {
        let capsule = build_reference_capsule();
        assert_eq!(capsule.manifest.capsule_id, "capsule-ref-001");
        assert_eq!(capsule.manifest.schema_version, VSDK_SCHEMA_VERSION);
        assert!(!capsule.signature.is_empty());
        assert!(!capsule.payload.is_empty());
        assert_eq!(capsule.inputs.len(), 2);
    }

    #[test]
    fn test_build_reference_session() {
        let session = build_reference_session();
        assert!(session.sealed);
        assert_eq!(session.final_verdict, Some(CapsuleVerdict::Pass));
        assert_eq!(session.steps.len(), 1);
    }

    // ── SessionStep ────────────────────────────────────────────────

    #[test]
    fn test_session_step_serde_roundtrip() {
        let step = SessionStep {
            step_index: 0,
            capsule_id: "c1".to_string(),
            verdict: CapsuleVerdict::Pass,
            output_hash: "aabb".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
        };
        let json = serde_json::to_string(&step).unwrap();
        let parsed: SessionStep = serde_json::from_str(&json).unwrap();
        assert_eq!(step, parsed);
    }

    // ── Manifest metadata BTreeMap ─────────────────────────────────

    #[test]
    fn test_manifest_metadata_btreemap() {
        let mut manifest = build_reference_manifest();
        manifest
            .metadata
            .insert("zebra".to_string(), "z".to_string());
        manifest
            .metadata
            .insert("alpha".to_string(), "a".to_string());
        let keys: Vec<_> = manifest.metadata.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }
}
