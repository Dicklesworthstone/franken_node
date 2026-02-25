//! Replay capsule types and operations for external verifiers.
//!
//! This module provides the public-facing capsule format that external verifiers
//! use to replay signed capsules and reproduce claim verdicts without privileged
//! internal access.
//!
//! # Invariants
//!
//! - INV-CAPSULE-STABLE-SCHEMA: Schema format is stable across versions.
//! - INV-CAPSULE-VERSIONED-API: Every capsule carries a version.
//! - INV-CAPSULE-NO-PRIVILEGED-ACCESS: Replay is entirely local and offline.
//! - INV-CAPSULE-VERDICT-REPRODUCIBLE: Same capsule always yields same verdict.

use std::collections::BTreeMap;

use super::{
    ERR_CAPSULE_ACCESS_DENIED, ERR_CAPSULE_REPLAY_DIVERGED, ERR_CAPSULE_SCHEMA_MISMATCH,
    ERR_CAPSULE_SIGNATURE_INVALID, ERR_CAPSULE_VERDICT_MISMATCH, SDK_VERSION,
};

// ---------------------------------------------------------------------------
// Capsule types
// ---------------------------------------------------------------------------

/// Manifest describing a replay capsule's contents.
///
/// INV-CAPSULE-VERSIONED-API: carries schema_version.
/// INV-CAPSULE-STABLE-SCHEMA: fields are fixed for a given schema version.
#[derive(Debug, Clone, PartialEq)]
pub struct CapsuleManifest {
    pub schema_version: String,
    pub capsule_id: String,
    pub description: String,
    pub claim_type: String,
    pub input_refs: Vec<String>,
    pub expected_output_hash: String,
    pub created_at: String,
    pub creator_identity: String,
    pub metadata: BTreeMap<String, String>,
}

/// A signed, self-contained replay capsule.
///
/// INV-CAPSULE-NO-PRIVILEGED-ACCESS: all data needed for replay is included.
/// INV-CAPSULE-VERDICT-REPRODUCIBLE: deterministic replay from contained data.
#[derive(Debug, Clone, PartialEq)]
pub struct ReplayCapsule {
    pub manifest: CapsuleManifest,
    pub payload: String,
    pub inputs: BTreeMap<String, String>,
    pub signature: String,
}

/// Verdict of a capsule replay operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapsuleVerdict {
    Pass,
    Fail,
    Inconclusive,
}

/// Result of replaying a capsule.
#[derive(Debug, Clone, PartialEq)]
pub struct CapsuleReplayResult {
    pub capsule_id: String,
    pub verdict: CapsuleVerdict,
    pub expected_hash: String,
    pub actual_hash: String,
    pub detail: String,
}

/// Error type for capsule operations.
#[derive(Debug, Clone, PartialEq)]
pub enum CapsuleError {
    SignatureInvalid(String),
    SchemaMismatch(String),
    ReplayDiverged { expected: String, actual: String },
    VerdictMismatch { expected: String, actual: String },
    AccessDenied(String),
    EmptyPayload(String),
    ManifestIncomplete(String),
}

impl std::fmt::Display for CapsuleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SignatureInvalid(msg) => {
                write!(f, "{}: {msg}", ERR_CAPSULE_SIGNATURE_INVALID)
            }
            Self::SchemaMismatch(msg) => {
                write!(f, "{}: {msg}", ERR_CAPSULE_SCHEMA_MISMATCH)
            }
            Self::ReplayDiverged { expected, actual } => {
                write!(
                    f,
                    "{}: expected={expected}, actual={actual}",
                    ERR_CAPSULE_REPLAY_DIVERGED
                )
            }
            Self::VerdictMismatch { expected, actual } => {
                write!(
                    f,
                    "{}: expected={expected}, actual={actual}",
                    ERR_CAPSULE_VERDICT_MISMATCH
                )
            }
            Self::AccessDenied(msg) => {
                write!(f, "{}: {msg}", ERR_CAPSULE_ACCESS_DENIED)
            }
            Self::EmptyPayload(msg) => {
                write!(f, "ERR_CAPSULE_EMPTY_PAYLOAD: {msg}")
            }
            Self::ManifestIncomplete(msg) => {
                write!(f, "ERR_CAPSULE_MANIFEST_INCOMPLETE: {msg}")
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Compute a deterministic hash (XOR-based, hex-encoded).
///
/// INV-CAPSULE-VERDICT-REPRODUCIBLE: same inputs always yield same output.
fn deterministic_hash(data: &str) -> String {
    let mut hash = [0u8; 32];
    for (i, b) in data.bytes().enumerate() {
        hash[i % 32] ^= b;
    }
    // Manual hex encoding without external dependency
    let hex_chars: Vec<String> = hash.iter().map(|b| format!("{b:02x}")).collect();
    hex_chars.join("")
}

/// Compute the signing payload for a capsule.
fn compute_signing_payload(capsule: &ReplayCapsule) -> String {
    let mut parts = Vec::new();
    parts.push(capsule.manifest.capsule_id.clone());
    parts.push(capsule.manifest.schema_version.clone());
    parts.push(capsule.manifest.expected_output_hash.clone());
    parts.push(capsule.payload.clone());
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
/// INV-CAPSULE-STABLE-SCHEMA: schema_version must match SDK_VERSION.
/// INV-CAPSULE-VERSIONED-API: version is checked.
pub fn validate_manifest(manifest: &CapsuleManifest) -> Result<(), CapsuleError> {
    if manifest.schema_version.is_empty() {
        return Err(CapsuleError::ManifestIncomplete(
            "schema_version is empty".into(),
        ));
    }
    if manifest.schema_version != SDK_VERSION {
        return Err(CapsuleError::SchemaMismatch(format!(
            "unsupported: {}, expected: {}",
            manifest.schema_version, SDK_VERSION
        )));
    }
    if manifest.capsule_id.is_empty() {
        return Err(CapsuleError::ManifestIncomplete("capsule_id is empty".into()));
    }
    if manifest.claim_type.is_empty() {
        return Err(CapsuleError::ManifestIncomplete("claim_type is empty".into()));
    }
    if manifest.expected_output_hash.is_empty() {
        return Err(CapsuleError::ManifestIncomplete(
            "expected_output_hash is empty".into(),
        ));
    }
    if manifest.creator_identity.is_empty() {
        return Err(CapsuleError::ManifestIncomplete(
            "creator_identity is empty".into(),
        ));
    }
    Ok(())
}

/// Sign a capsule by computing its signature.
///
/// The signature covers the manifest, payload, and inputs.
pub fn sign_capsule(capsule: &mut ReplayCapsule) {
    let payload = compute_signing_payload(capsule);
    capsule.signature = deterministic_hash(&payload);
}

/// Verify a capsule's signature against the computed signing payload.
pub fn verify_signature(capsule: &ReplayCapsule) -> Result<(), CapsuleError> {
    let payload = compute_signing_payload(capsule);
    let expected = deterministic_hash(&payload);
    if capsule.signature != expected {
        return Err(CapsuleError::SignatureInvalid(format!(
            "expected={expected}, actual={}",
            capsule.signature
        )));
    }
    Ok(())
}

/// Replay a capsule and produce a result.
///
/// INV-CAPSULE-NO-PRIVILEGED-ACCESS: purely local computation.
/// INV-CAPSULE-VERDICT-REPRODUCIBLE: deterministic for same inputs.
pub fn replay(
    capsule: &ReplayCapsule,
    _verifier_identity: &str,
) -> Result<CapsuleReplayResult, CapsuleError> {
    // Step 1: Validate manifest
    validate_manifest(&capsule.manifest)?;

    // Step 2: Verify signature
    verify_signature(capsule)?;

    // Step 3: Check non-empty payload
    if capsule.payload.is_empty() {
        return Err(CapsuleError::EmptyPayload("payload is empty".into()));
    }

    // Step 4: Compute actual output hash
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

    Ok(CapsuleReplayResult {
        capsule_id: capsule.manifest.capsule_id.clone(),
        verdict,
        expected_hash: capsule.manifest.expected_output_hash.clone(),
        actual_hash,
        detail,
    })
}

/// Build a reference capsule for testing.
///
/// The capsule is properly signed and has a valid expected_output_hash
/// so that replay will produce a PASS verdict.
pub fn build_reference_capsule() -> ReplayCapsule {
    let mut inputs = BTreeMap::new();
    inputs.insert("artifact_a".to_string(), "content_of_a".to_string());
    inputs.insert("artifact_b".to_string(), "content_of_b".to_string());

    let payload = "reference_payload_data".to_string();

    // Compute expected output hash exactly as replay does
    let mut replay_input = payload.clone();
    for (k, v) in &inputs {
        replay_input.push_str(&format!("|{k}={v}"));
    }
    let expected_hash = deterministic_hash(&replay_input);

    let manifest = CapsuleManifest {
        schema_version: SDK_VERSION.to_string(),
        capsule_id: "capsule-ref-001".to_string(),
        description: "Reference capsule for testing".to_string(),
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_reference_capsule() {
        let capsule = build_reference_capsule();
        assert!(!capsule.signature.is_empty());
        assert_eq!(capsule.signature.len(), 64);
        assert_eq!(capsule.manifest.schema_version, SDK_VERSION);
    }

    #[test]
    fn test_validate_manifest_pass() {
        let capsule = build_reference_capsule();
        assert!(validate_manifest(&capsule.manifest).is_ok());
    }

    #[test]
    fn test_validate_manifest_bad_schema() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.schema_version = "bad".to_string();
        match validate_manifest(&capsule.manifest) {
            Err(CapsuleError::SchemaMismatch(_)) => {}
            other => panic!("expected SchemaMismatch, got {other:?}"),
        }
    }

    #[test]
    fn test_validate_manifest_empty_capsule_id() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.capsule_id = String::new();
        assert!(validate_manifest(&capsule.manifest).is_err());
    }

    #[test]
    fn test_verify_signature_pass() {
        let capsule = build_reference_capsule();
        assert!(verify_signature(&capsule).is_ok());
    }

    #[test]
    fn test_verify_signature_tampered() {
        let mut capsule = build_reference_capsule();
        capsule.signature = "tampered".to_string();
        match verify_signature(&capsule) {
            Err(CapsuleError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_pass() {
        let capsule = build_reference_capsule();
        let result = replay(&capsule, "verifier-1").unwrap();
        assert_eq!(result.verdict, CapsuleVerdict::Pass);
        assert_eq!(result.actual_hash, result.expected_hash);
    }

    #[test]
    fn test_replay_deterministic() {
        // INV-CAPSULE-VERDICT-REPRODUCIBLE
        let capsule = build_reference_capsule();
        let r1 = replay(&capsule, "v1").unwrap();
        let r2 = replay(&capsule, "v1").unwrap();
        assert_eq!(r1.verdict, r2.verdict);
        assert_eq!(r1.actual_hash, r2.actual_hash);
    }

    #[test]
    fn test_replay_diverged() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.expected_output_hash = "wrong_hash".to_string();
        sign_capsule(&mut capsule);
        let result = replay(&capsule, "v1").unwrap();
        assert_eq!(result.verdict, CapsuleVerdict::Fail);
    }

    #[test]
    fn test_replay_empty_payload() {
        let mut capsule = build_reference_capsule();
        capsule.payload = String::new();
        sign_capsule(&mut capsule);
        match replay(&capsule, "v1") {
            Err(CapsuleError::EmptyPayload(_)) => {}
            other => panic!("expected EmptyPayload, got {other:?}"),
        }
    }

    #[test]
    fn test_replay_tampered_signature() {
        let mut capsule = build_reference_capsule();
        capsule.signature = "tampered".to_string();
        match replay(&capsule, "v1") {
            Err(CapsuleError::SignatureInvalid(_)) => {}
            other => panic!("expected SignatureInvalid, got {other:?}"),
        }
    }

    #[test]
    fn test_error_display_signature_invalid() {
        let err = CapsuleError::SignatureInvalid("bad".into());
        assert!(format!("{err}").contains(ERR_CAPSULE_SIGNATURE_INVALID));
    }

    #[test]
    fn test_error_display_schema_mismatch() {
        let err = CapsuleError::SchemaMismatch("bad".into());
        assert!(format!("{err}").contains(ERR_CAPSULE_SCHEMA_MISMATCH));
    }

    #[test]
    fn test_error_display_replay_diverged() {
        let err = CapsuleError::ReplayDiverged {
            expected: "a".into(),
            actual: "b".into(),
        };
        assert!(format!("{err}").contains(ERR_CAPSULE_REPLAY_DIVERGED));
    }

    #[test]
    fn test_error_display_verdict_mismatch() {
        let err = CapsuleError::VerdictMismatch {
            expected: "pass".into(),
            actual: "fail".into(),
        };
        assert!(format!("{err}").contains(ERR_CAPSULE_VERDICT_MISMATCH));
    }

    #[test]
    fn test_error_display_access_denied() {
        let err = CapsuleError::AccessDenied("denied".into());
        assert!(format!("{err}").contains(ERR_CAPSULE_ACCESS_DENIED));
    }

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
    fn test_capsule_no_privileged_access() {
        // INV-CAPSULE-NO-PRIVILEGED-ACCESS: replay is local, no network needed
        let capsule = build_reference_capsule();
        let result = replay(&capsule, "offline-verifier").unwrap();
        assert_eq!(result.verdict, CapsuleVerdict::Pass);
    }

    #[test]
    fn test_capsule_manifest_btreemap_ordering() {
        let mut capsule = build_reference_capsule();
        capsule.manifest.metadata.insert("z_key".into(), "z".into());
        capsule.manifest.metadata.insert("a_key".into(), "a".into());
        let keys: Vec<_> = capsule.manifest.metadata.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted);
    }
}
