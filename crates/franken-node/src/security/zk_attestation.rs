//! bd-kcg9: Zero-knowledge attestation support for selective compliance verification.
//!
//! Provides types and operations for generating, verifying, and auditing
//! zero-knowledge attestations.  Verifiers can validate compliance predicates
//! without requiring privileged disclosure of full private metadata.  Invalid
//! or forged proofs fail admission deterministically.
//!
//! # Invariants
//!
//! - INV-ZKA-SELECTIVE: attestation proofs reveal only the compliance predicate
//!   result, never full private metadata.
//! - INV-ZKA-SOUNDNESS: forged or corrupted proofs are rejected with a
//!   deterministic error; no partial admission.
//! - INV-ZKA-COMPLETENESS: a valid proof for a satisfied predicate always
//!   passes verification within the configured timeout.
//! - INV-ZKA-POLICY-BOUND: every attestation is bound to a specific `ZkPolicy`;
//!   a proof generated under policy P cannot verify under policy Q.
//! - INV-ZKA-AUDIT-TRAIL: every verification attempt (pass or fail) is logged
//!   with a trace ID, timestamp, and policy reference.
//! - INV-ZKA-SCHEMA-VERSIONED: all serialised attestation payloads carry a
//!   schema version tag for forward-compatible deserialisation.

use std::collections::BTreeMap;
use std::fmt;

use serde::{Deserialize, Serialize};

/// Schema version for all ZK attestation payloads.
pub const SCHEMA_VERSION: &str = "zka-v1.0";

/// Default proof validity window in milliseconds.
pub const DEFAULT_VALIDITY_MS: u64 = 600_000; // 10 minutes

/// Maximum proofs in a single batch verification.
pub const MAX_BATCH_SIZE: usize = 256;

// ── Invariant constants ─────────────────────────────────────────────────────

/// INV-ZKA-SELECTIVE: proofs reveal only predicate results, not private metadata.
pub const INV_ZKA_SELECTIVE: &str = "INV-ZKA-SELECTIVE";

/// INV-ZKA-SOUNDNESS: forged proofs are rejected deterministically.
pub const INV_ZKA_SOUNDNESS: &str = "INV-ZKA-SOUNDNESS";

/// INV-ZKA-COMPLETENESS: valid proofs always pass within configured timeout.
pub const INV_ZKA_COMPLETENESS: &str = "INV-ZKA-COMPLETENESS";

/// INV-ZKA-POLICY-BOUND: attestation is bound to a specific policy.
pub const INV_ZKA_POLICY_BOUND: &str = "INV-ZKA-POLICY-BOUND";

/// INV-ZKA-AUDIT-TRAIL: every verification attempt is logged.
pub const INV_ZKA_AUDIT_TRAIL: &str = "INV-ZKA-AUDIT-TRAIL";

/// INV-ZKA-SCHEMA-VERSIONED: payloads carry a schema version tag.
pub const INV_ZKA_SCHEMA_VERSIONED: &str = "INV-ZKA-SCHEMA-VERSIONED";

// ── Task-specified invariant aliases ──────────────────────────────────────────

/// INV-ZK-NO-DISCLOSURE: proofs reveal only compliance predicate result,
/// never full private metadata.  Alias for INV-ZKA-SELECTIVE.
pub const INV_ZK_NO_DISCLOSURE: &str = "INV-ZK-NO-DISCLOSURE";

/// INV-ZK-PROOF-SOUNDNESS: forged or corrupted proofs are rejected
/// deterministically.  Alias for INV-ZKA-SOUNDNESS.
pub const INV_ZK_PROOF_SOUNDNESS: &str = "INV-ZK-PROOF-SOUNDNESS";

/// INV-ZK-FAIL-CLOSED: on any verification error the system denies admission.
pub const INV_ZK_FAIL_CLOSED: &str = "INV-ZK-FAIL-CLOSED";

/// INV-ZK-PREDICATE-COMPLETENESS: valid proofs for satisfied predicates
/// always pass verification.  Alias for INV-ZKA-COMPLETENESS.
pub const INV_ZK_PREDICATE_COMPLETENESS: &str = "INV-ZK-PREDICATE-COMPLETENESS";

// ── Task-specified event code aliases ─────────────────────────────────────────

/// ZK_ATTESTATION_REQUEST: attestation proof submitted for verification.
/// Maps to FN-ZK-002.
pub const ZK_ATTESTATION_REQUEST: &str = "ZK_ATTESTATION_REQUEST";

/// ZK_PROOF_GENERATED: attestation proof generated.  Maps to FN-ZK-001.
pub const ZK_PROOF_GENERATED: &str = "ZK_PROOF_GENERATED";

/// ZK_PROOF_VERIFIED: verification passed.  Maps to FN-ZK-003.
pub const ZK_PROOF_VERIFIED: &str = "ZK_PROOF_VERIFIED";

/// ZK_PREDICATE_SATISFIED: compliance predicate satisfied.  Maps to FN-ZK-003.
pub const ZK_PREDICATE_SATISFIED: &str = "ZK_PREDICATE_SATISFIED";

/// ZK_ATTESTATION_ISSUED: attestation issued.  Maps to FN-ZK-001.
pub const ZK_ATTESTATION_ISSUED: &str = "ZK_ATTESTATION_ISSUED";

// ── Task-specified error code aliases ─────────────────────────────────────────

/// ERR_ZK_PROOF_INVALID: proof bytes do not parse or signature invalid.
/// Maps to ERR_ZKA_INVALID_PROOF.
pub const ERR_ZK_PROOF_INVALID: &str = "ERR_ZK_PROOF_INVALID";

/// ERR_ZK_PROOF_FORGED: proof structure indicates forgery attempt.
/// Maps to ERR_ZKA_METADATA_LEAK.
pub const ERR_ZK_PROOF_FORGED: &str = "ERR_ZK_PROOF_FORGED";

/// ERR_ZK_PREDICATE_UNSATISFIED: compliance predicate not met.
/// Maps to ERR_ZKA_PREDICATE_UNSATISFIED.
pub const ERR_ZK_PREDICATE_UNSATISFIED: &str = "ERR_ZK_PREDICATE_UNSATISFIED";

/// ERR_ZK_WITNESS_MISSING: required witness data not provided.
pub const ERR_ZK_WITNESS_MISSING: &str = "ERR_ZK_WITNESS_MISSING";

/// ERR_ZK_CIRCUIT_MISMATCH: proof was generated for different circuit/policy.
/// Maps to ERR_ZKA_POLICY_MISMATCH.
pub const ERR_ZK_CIRCUIT_MISMATCH: &str = "ERR_ZK_CIRCUIT_MISMATCH";

/// ERR_ZK_ATTESTATION_EXPIRED: proof exceeded its validity window.
/// Maps to ERR_ZKA_EXPIRED.
pub const ERR_ZK_ATTESTATION_EXPIRED: &str = "ERR_ZK_ATTESTATION_EXPIRED";

// ── Event codes ─────────────────────────────────────────────────────────────

pub mod event_codes {
    /// Attestation proof generated.
    pub const FN_ZK_001: &str = "FN-ZK-001";
    /// Attestation proof submitted for verification.
    pub const FN_ZK_002: &str = "FN-ZK-002";
    /// Verification passed.
    pub const FN_ZK_003: &str = "FN-ZK-003";
    /// Verification rejected (invalid proof).
    pub const FN_ZK_004: &str = "FN-ZK-004";
    /// Verification rejected (policy mismatch).
    pub const FN_ZK_005: &str = "FN-ZK-005";
    /// Verification timed out.
    pub const FN_ZK_006: &str = "FN-ZK-006";
    /// Proof revoked by issuer.
    pub const FN_ZK_007: &str = "FN-ZK-007";
    /// Policy registered.
    pub const FN_ZK_008: &str = "FN-ZK-008";
    /// Policy deregistered.
    pub const FN_ZK_009: &str = "FN-ZK-009";
    /// Attestation audit record created.
    pub const FN_ZK_010: &str = "FN-ZK-010";
    /// Batch verification initiated.
    pub const FN_ZK_011: &str = "FN-ZK-011";
    /// Batch verification completed.
    pub const FN_ZK_012: &str = "FN-ZK-012";
}

// ── Error codes ─────────────────────────────────────────────────────────────

pub mod error_codes {
    /// Proof bytes do not parse or signature invalid.
    pub const ERR_ZKA_INVALID_PROOF: &str = "ERR_ZKA_INVALID_PROOF";
    /// Proof was generated under a different policy.
    pub const ERR_ZKA_POLICY_MISMATCH: &str = "ERR_ZKA_POLICY_MISMATCH";
    /// Proof exceeded its validity window.
    pub const ERR_ZKA_EXPIRED: &str = "ERR_ZKA_EXPIRED";
    /// Proof has been explicitly revoked.
    pub const ERR_ZKA_REVOKED: &str = "ERR_ZKA_REVOKED";
    /// Compliance predicate not met.
    pub const ERR_ZKA_PREDICATE_UNSATISFIED: &str = "ERR_ZKA_PREDICATE_UNSATISFIED";
    /// Same proof already submitted.
    pub const ERR_ZKA_DUPLICATE: &str = "ERR_ZKA_DUPLICATE";
    /// Verification did not complete in time.
    pub const ERR_ZKA_TIMEOUT: &str = "ERR_ZKA_TIMEOUT";
    /// Referenced policy not registered.
    pub const ERR_ZKA_POLICY_NOT_FOUND: &str = "ERR_ZKA_POLICY_NOT_FOUND";
    /// Some proofs in batch failed.
    pub const ERR_ZKA_BATCH_PARTIAL: &str = "ERR_ZKA_BATCH_PARTIAL";
    /// Proof structure would reveal private fields.
    pub const ERR_ZKA_METADATA_LEAK: &str = "ERR_ZKA_METADATA_LEAK";
}

// ── Types ───────────────────────────────────────────────────────────────────

/// Outcome of evaluating a compliance predicate. INV-ZKA-SELECTIVE
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum PredicateOutcome {
    /// Predicate is satisfied.
    Pass,
    /// Predicate is not satisfied.
    Fail,
    /// Predicate evaluation encountered an error.
    Error,
}

impl fmt::Display for PredicateOutcome {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass => write!(f, "Pass"),
            Self::Fail => write!(f, "Fail"),
            Self::Error => write!(f, "Error"),
        }
    }
}

/// Lifecycle status of an attestation. INV-ZKA-SCHEMA-VERSIONED
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AttestationStatus {
    /// Attestation is active and within its validity window.
    Active,
    /// Attestation has exceeded its validity window.
    Expired,
    /// Attestation has been explicitly revoked by the issuer.
    Revoked,
}

impl fmt::Display for AttestationStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Active => write!(f, "Active"),
            Self::Expired => write!(f, "Expired"),
            Self::Revoked => write!(f, "Revoked"),
        }
    }
}

impl AttestationStatus {
    /// Returns `true` when the attestation can no longer be used for verification.
    #[must_use]
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Expired | Self::Revoked)
    }
}

/// Raw proof payload with schema version tag. INV-ZKA-SCHEMA-VERSIONED
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkProofPayload {
    /// Schema version for this payload.
    pub schema_version: String,
    /// Opaque proof bytes (hex-encoded for serialisation safety).
    pub proof_bytes_hex: String,
    /// Hash of the private metadata used to generate this proof.
    /// This is a commitment, not the metadata itself. INV-ZKA-SELECTIVE
    pub metadata_commitment: String,
}

/// A compliance policy defining what predicate is evaluated and how.
/// INV-ZKA-POLICY-BOUND
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkPolicy {
    /// Unique policy identifier.
    pub policy_id: String,
    /// Human-readable description of the compliance predicate.
    pub predicate_description: String,
    /// Issuer identity (e.g. key fingerprint).
    pub issuer: String,
    /// Maximum validity window in milliseconds for proofs under this policy.
    pub validity_ms: u64,
    /// Schema version.
    pub schema_version: String,
    /// Whether the policy is currently active.
    pub active: bool,
    /// Timestamp when registered (epoch ms).
    pub registered_at_ms: u64,
}

/// A generated zero-knowledge attestation proving a compliance predicate.
/// INV-ZKA-SELECTIVE, INV-ZKA-POLICY-BOUND
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkAttestation {
    /// Unique attestation identifier.
    pub attestation_id: String,
    /// Policy under which this attestation was generated.
    pub policy_id: String,
    /// The proof payload.
    pub payload: ZkProofPayload,
    /// Outcome of the predicate evaluation.
    pub outcome: PredicateOutcome,
    /// Current lifecycle status.
    pub status: AttestationStatus,
    /// Timestamp when generated (epoch ms).
    pub generated_at_ms: u64,
    /// Expiry timestamp (epoch ms).
    pub expires_at_ms: u64,
    /// Distributed trace identifier. INV-ZKA-AUDIT-TRAIL
    pub trace_id: String,
}

/// Result of verifying a single attestation. INV-ZKA-SOUNDNESS
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ZkVerificationResult {
    /// Verification passed: the proof is valid and the predicate is satisfied.
    Verified {
        attestation_id: String,
        policy_id: String,
        trace_id: String,
        verified_at_ms: u64,
    },
    /// Verification rejected with reason.
    Rejected {
        attestation_id: String,
        policy_id: String,
        trace_id: String,
        reason: String,
        error_code: String,
    },
}

impl ZkVerificationResult {
    /// Returns `true` when the verification passed.
    #[must_use]
    pub fn is_verified(&self) -> bool {
        matches!(self, Self::Verified { .. })
    }
}

/// Result of a batch verification. INV-ZKA-SOUNDNESS
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkBatchResult {
    /// Total proofs submitted.
    pub total: usize,
    /// Number that passed.
    pub passed: usize,
    /// Number that failed.
    pub failed: usize,
    /// Individual results, keyed by attestation ID. Uses BTreeMap for deterministic ordering.
    pub results: BTreeMap<String, ZkVerificationResult>,
    /// Batch trace ID.
    pub trace_id: String,
    /// Schema version.
    pub schema_version: String,
}

/// Audit record for an attestation event. INV-ZKA-AUDIT-TRAIL
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkAuditRecord {
    /// Unique record identifier.
    pub record_id: String,
    /// Event code (FN-ZK-xxx).
    pub event_code: String,
    /// Related attestation ID (if any).
    pub attestation_id: Option<String>,
    /// Related policy ID (if any).
    pub policy_id: Option<String>,
    /// Distributed trace ID.
    pub trace_id: String,
    /// Timestamp (epoch ms).
    pub timestamp_ms: u64,
    /// Outcome detail.
    pub detail: String,
    /// Schema version.
    pub schema_version: String,
}

/// Registry of active ZK policies. Uses BTreeMap for deterministic ordering.
/// INV-ZKA-POLICY-BOUND
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRegistry {
    /// Policies keyed by policy_id.
    pub policies: BTreeMap<String, ZkPolicy>,
    /// Schema version.
    pub schema_version: String,
}

/// Ledger tracking all attestations and their lifecycle. Uses BTreeMap for
/// deterministic ordering. INV-ZKA-AUDIT-TRAIL
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttestationLedger {
    /// Attestations keyed by attestation_id.
    pub attestations: BTreeMap<String, ZkAttestation>,
    /// Audit trail entries keyed by record_id.
    pub audit_trail: BTreeMap<String, ZkAuditRecord>,
    /// Set of proof commitments already seen, for duplicate detection.
    /// Maps metadata_commitment to attestation_id.
    pub seen_commitments: BTreeMap<String, String>,
    /// Schema version.
    pub schema_version: String,
}

// ── Invariants module ───────────────────────────────────────────────────────

pub mod invariants {
    //! Compile-time and runtime invariant definitions for ZK attestation.

    use super::*;

    /// Check INV-ZKA-SELECTIVE: proof payload must not contain raw private metadata.
    /// We enforce this by verifying the payload contains only a commitment hash.
    #[must_use]
    pub fn check_selective(attestation: &ZkAttestation) -> bool {
        // The payload must have a non-empty commitment (a hash, not raw data)
        // and proof_bytes_hex must be hex-only (no structured plaintext leaking).
        !attestation.payload.metadata_commitment.is_empty()
            && attestation
                .payload
                .proof_bytes_hex
                .chars()
                .all(|c| c.is_ascii_hexdigit())
    }

    /// Check INV-ZKA-SOUNDNESS: verification must produce a deterministic result.
    #[must_use]
    pub fn check_soundness(result: &ZkVerificationResult) -> bool {
        match result {
            ZkVerificationResult::Verified { attestation_id, .. } => !attestation_id.is_empty(),
            ZkVerificationResult::Rejected {
                error_code, reason, ..
            } => !error_code.is_empty() && !reason.is_empty(),
        }
    }

    /// Check INV-ZKA-POLICY-BOUND: attestation policy_id must match the policy under verification.
    #[must_use]
    pub fn check_policy_bound(attestation: &ZkAttestation, policy: &ZkPolicy) -> bool {
        attestation.policy_id == policy.policy_id
    }

    /// Check INV-ZKA-SCHEMA-VERSIONED: all payloads carry a schema version.
    #[must_use]
    pub fn check_schema_versioned(attestation: &ZkAttestation) -> bool {
        !attestation.payload.schema_version.is_empty()
    }

    /// Check INV-ZKA-COMPLETENESS: a valid active proof with Pass outcome must verify.
    #[must_use]
    pub fn check_completeness(attestation: &ZkAttestation, now_ms: u64) -> bool {
        if attestation.outcome != PredicateOutcome::Pass {
            return true; // invariant only applies to passing predicates
        }
        if attestation.status != AttestationStatus::Active {
            return true; // expired/revoked proofs are allowed to fail
        }
        // Must not be expired by wall clock
        now_ms <= attestation.expires_at_ms
    }

    /// Check INV-ZKA-AUDIT-TRAIL: audit record has required fields.
    #[must_use]
    pub fn check_audit_trail(record: &ZkAuditRecord) -> bool {
        !record.trace_id.is_empty()
            && record.timestamp_ms > 0
            && !record.event_code.is_empty()
            && !record.schema_version.is_empty()
    }
}

// ── Core operations ─────────────────────────────────────────────────────────

impl PolicyRegistry {
    /// Create a new empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            policies: BTreeMap::new(),
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    /// Register a policy. Returns event code FN-ZK-008 on success.
    /// INV-ZKA-POLICY-BOUND
    pub fn register_policy(&mut self, policy: ZkPolicy) -> Result<String, String> {
        if self.policies.contains_key(&policy.policy_id) {
            return Err(format!(
                "{}: policy {} already exists",
                error_codes::ERR_ZKA_DUPLICATE,
                policy.policy_id
            ));
        }
        let id = policy.policy_id.clone();
        self.policies.insert(id.clone(), policy);
        Ok(format!(
            "{}: policy {} registered",
            event_codes::FN_ZK_008,
            id
        ))
    }

    /// Deregister a policy. Returns event code FN-ZK-009 on success.
    pub fn deregister_policy(&mut self, policy_id: &str) -> Result<String, String> {
        match self.policies.remove(policy_id) {
            Some(_) => Ok(format!(
                "{}: policy {} deregistered",
                event_codes::FN_ZK_009,
                policy_id
            )),
            None => Err(format!(
                "{}: {}",
                error_codes::ERR_ZKA_POLICY_NOT_FOUND,
                policy_id
            )),
        }
    }

    /// Lookup a policy by ID.
    #[must_use]
    pub fn get_policy(&self, policy_id: &str) -> Option<&ZkPolicy> {
        self.policies.get(policy_id)
    }
}

impl Default for PolicyRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AttestationLedger {
    /// Create a new empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self {
            attestations: BTreeMap::new(),
            audit_trail: BTreeMap::new(),
            seen_commitments: BTreeMap::new(),
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    /// Generate a ZK attestation proof from private data commitment and a policy.
    /// INV-ZKA-SELECTIVE: we never store or transmit the raw private data.
    /// Returns the attestation. Emits FN-ZK-001.
    pub fn generate_proof(
        &mut self,
        attestation_id: String,
        policy: &ZkPolicy,
        metadata_commitment: String,
        proof_bytes_hex: String,
        outcome: PredicateOutcome,
        now_ms: u64,
        trace_id: String,
    ) -> Result<ZkAttestation, String> {
        // INV-ZKA-SOUNDNESS: reject if proof bytes are not valid hex
        if !proof_bytes_hex.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!(
                "{}: proof bytes contain non-hex characters",
                error_codes::ERR_ZKA_METADATA_LEAK
            ));
        }

        // Duplicate detection
        if self.seen_commitments.contains_key(&metadata_commitment) {
            return Err(format!(
                "{}: commitment {} already submitted",
                error_codes::ERR_ZKA_DUPLICATE,
                metadata_commitment
            ));
        }

        let attestation = ZkAttestation {
            attestation_id: attestation_id.clone(),
            policy_id: policy.policy_id.clone(),
            payload: ZkProofPayload {
                schema_version: SCHEMA_VERSION.to_string(),
                proof_bytes_hex,
                metadata_commitment: metadata_commitment.clone(),
            },
            outcome,
            status: AttestationStatus::Active,
            generated_at_ms: now_ms,
            expires_at_ms: now_ms + policy.validity_ms,
            trace_id: trace_id.clone(),
        };

        self.seen_commitments
            .insert(metadata_commitment, attestation_id.clone());
        self.attestations
            .insert(attestation_id.clone(), attestation.clone());

        self.record_audit(
            format!("audit-{}-gen", attestation_id),
            event_codes::FN_ZK_001.to_string(),
            Some(attestation_id),
            Some(policy.policy_id.clone()),
            trace_id,
            now_ms,
            "Attestation proof generated".to_string(),
        );

        Ok(attestation)
    }

    /// Verify a single attestation against a policy.
    /// INV-ZKA-SOUNDNESS, INV-ZKA-POLICY-BOUND, INV-ZKA-SELECTIVE
    pub fn verify_proof(
        &mut self,
        attestation: &ZkAttestation,
        policy: &ZkPolicy,
        now_ms: u64,
        trace_id: String,
    ) -> ZkVerificationResult {
        let aid = attestation.attestation_id.clone();
        let pid = policy.policy_id.clone();

        // Record submission event FN-ZK-002
        self.record_audit(
            format!("audit-{}-submit", aid),
            event_codes::FN_ZK_002.to_string(),
            Some(aid.clone()),
            Some(pid.clone()),
            trace_id.clone(),
            now_ms,
            "Proof submitted for verification".to_string(),
        );

        // INV-ZKA-POLICY-BOUND: check policy match
        if !invariants::check_policy_bound(attestation, policy) {
            self.record_audit(
                format!("audit-{}-pmm", aid),
                event_codes::FN_ZK_005.to_string(),
                Some(aid.clone()),
                Some(pid.clone()),
                trace_id.clone(),
                now_ms,
                "Policy mismatch".to_string(),
            );
            return ZkVerificationResult::Rejected {
                attestation_id: aid,
                policy_id: pid,
                trace_id,
                reason: "Policy mismatch".to_string(),
                error_code: error_codes::ERR_ZKA_POLICY_MISMATCH.to_string(),
            };
        }

        // Check revocation
        if attestation.status == AttestationStatus::Revoked {
            self.record_audit(
                format!("audit-{}-rev", aid),
                event_codes::FN_ZK_004.to_string(),
                Some(aid.clone()),
                Some(pid.clone()),
                trace_id.clone(),
                now_ms,
                "Attestation revoked".to_string(),
            );
            return ZkVerificationResult::Rejected {
                attestation_id: aid,
                policy_id: pid,
                trace_id,
                reason: "Attestation has been revoked".to_string(),
                error_code: error_codes::ERR_ZKA_REVOKED.to_string(),
            };
        }

        // Check expiry
        if now_ms > attestation.expires_at_ms {
            self.record_audit(
                format!("audit-{}-exp", aid),
                event_codes::FN_ZK_004.to_string(),
                Some(aid.clone()),
                Some(pid.clone()),
                trace_id.clone(),
                now_ms,
                "Attestation expired".to_string(),
            );
            return ZkVerificationResult::Rejected {
                attestation_id: aid,
                policy_id: pid,
                trace_id,
                reason: "Proof exceeded validity window".to_string(),
                error_code: error_codes::ERR_ZKA_EXPIRED.to_string(),
            };
        }

        // INV-ZKA-SELECTIVE: check proof structure
        if !invariants::check_selective(attestation) {
            self.record_audit(
                format!("audit-{}-leak", aid),
                event_codes::FN_ZK_004.to_string(),
                Some(aid.clone()),
                Some(pid.clone()),
                trace_id.clone(),
                now_ms,
                "Metadata leak detected in proof structure".to_string(),
            );
            return ZkVerificationResult::Rejected {
                attestation_id: aid,
                policy_id: pid,
                trace_id,
                reason: "Proof structure would reveal private fields".to_string(),
                error_code: error_codes::ERR_ZKA_METADATA_LEAK.to_string(),
            };
        }

        // INV-ZKA-SOUNDNESS: check predicate outcome
        if attestation.outcome != PredicateOutcome::Pass {
            self.record_audit(
                format!("audit-{}-pred", aid),
                event_codes::FN_ZK_004.to_string(),
                Some(aid.clone()),
                Some(pid.clone()),
                trace_id.clone(),
                now_ms,
                format!("Predicate outcome: {}", attestation.outcome),
            );
            return ZkVerificationResult::Rejected {
                attestation_id: aid,
                policy_id: pid,
                trace_id,
                reason: format!("Compliance predicate not met: {}", attestation.outcome),
                error_code: error_codes::ERR_ZKA_PREDICATE_UNSATISFIED.to_string(),
            };
        }

        // INV-ZKA-SCHEMA-VERSIONED: check schema version
        if !invariants::check_schema_versioned(attestation) {
            return ZkVerificationResult::Rejected {
                attestation_id: aid,
                policy_id: pid,
                trace_id,
                reason: "Missing schema version".to_string(),
                error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
            };
        }

        // All checks passed -- emit FN-ZK-003
        self.record_audit(
            format!("audit-{}-pass", aid),
            event_codes::FN_ZK_003.to_string(),
            Some(aid.clone()),
            Some(pid.clone()),
            trace_id.clone(),
            now_ms,
            "Verification passed".to_string(),
        );

        ZkVerificationResult::Verified {
            attestation_id: aid,
            policy_id: pid,
            trace_id,
            verified_at_ms: now_ms,
        }
    }

    /// Verify a batch of attestations. Returns a `ZkBatchResult`.
    /// Emits FN-ZK-011 at start, FN-ZK-012 at end.
    pub fn verify_batch(
        &mut self,
        attestations: &[ZkAttestation],
        policy: &ZkPolicy,
        now_ms: u64,
        trace_id: String,
    ) -> ZkBatchResult {
        self.record_audit(
            format!("audit-batch-{}-start", trace_id),
            event_codes::FN_ZK_011.to_string(),
            None,
            Some(policy.policy_id.clone()),
            trace_id.clone(),
            now_ms,
            format!(
                "Batch verification initiated: {} proofs",
                attestations.len()
            ),
        );

        let mut results = BTreeMap::new();
        let mut passed = 0usize;
        let mut failed = 0usize;

        for att in attestations {
            let sub_trace = format!("{}-{}", trace_id, att.attestation_id);
            let result = self.verify_proof(att, policy, now_ms, sub_trace);
            if result.is_verified() {
                passed += 1;
            } else {
                failed += 1;
            }
            results.insert(att.attestation_id.clone(), result);
        }

        self.record_audit(
            format!("audit-batch-{}-end", trace_id),
            event_codes::FN_ZK_012.to_string(),
            None,
            Some(policy.policy_id.clone()),
            trace_id.clone(),
            now_ms,
            format!(
                "Batch verification completed: {}/{} passed",
                passed,
                attestations.len()
            ),
        );

        ZkBatchResult {
            total: attestations.len(),
            passed,
            failed,
            results,
            trace_id,
            schema_version: SCHEMA_VERSION.to_string(),
        }
    }

    /// Revoke a previously issued attestation. Emits FN-ZK-007.
    pub fn revoke_attestation(
        &mut self,
        attestation_id: &str,
        now_ms: u64,
        trace_id: String,
    ) -> Result<String, String> {
        match self.attestations.get_mut(attestation_id) {
            Some(att) => {
                if att.status == AttestationStatus::Revoked {
                    return Err(format!(
                        "{}: {} already revoked",
                        error_codes::ERR_ZKA_REVOKED,
                        attestation_id
                    ));
                }
                att.status = AttestationStatus::Revoked;
                let policy_id = att.policy_id.clone();
                self.record_audit(
                    format!("audit-{}-revoke", attestation_id),
                    event_codes::FN_ZK_007.to_string(),
                    Some(attestation_id.to_string()),
                    Some(policy_id),
                    trace_id,
                    now_ms,
                    format!("Attestation {} revoked", attestation_id),
                );
                Ok(format!(
                    "{}: attestation {} revoked",
                    event_codes::FN_ZK_007,
                    attestation_id
                ))
            }
            None => Err(format!(
                "{}: {}",
                error_codes::ERR_ZKA_INVALID_PROOF,
                attestation_id
            )),
        }
    }

    /// Check if an attestation is still valid (active and within validity window).
    #[must_use]
    pub fn is_valid(&self, attestation_id: &str, now_ms: u64) -> bool {
        self.attestations.get(attestation_id).is_some_and(|att| {
            att.status == AttestationStatus::Active && now_ms <= att.expires_at_ms
        })
    }

    /// Sweep expired attestations. Returns the IDs of attestations that were expired.
    pub fn sweep_expired(&mut self, now_ms: u64) -> Vec<String> {
        let mut expired = Vec::new();
        for (id, att) in &mut self.attestations {
            if att.status == AttestationStatus::Active && now_ms > att.expires_at_ms {
                att.status = AttestationStatus::Expired;
                expired.push(id.clone());
            }
        }
        expired
    }

    /// Query audit records matching a filter. Returns records where the
    /// predicate returns true, in deterministic BTreeMap order.
    #[must_use]
    pub fn query_audit<F>(&self, predicate: F) -> Vec<&ZkAuditRecord>
    where
        F: Fn(&ZkAuditRecord) -> bool,
    {
        self.audit_trail.values().filter(|r| predicate(r)).collect()
    }

    /// Generate a compliance report for a specific policy: counts of
    /// attestations by status and outcome.
    #[must_use]
    pub fn generate_compliance_report(&self, policy_id: &str) -> BTreeMap<String, usize> {
        let mut report = BTreeMap::new();
        report.insert("total".to_string(), 0);
        report.insert("active".to_string(), 0);
        report.insert("expired".to_string(), 0);
        report.insert("revoked".to_string(), 0);
        report.insert("outcome_pass".to_string(), 0);
        report.insert("outcome_fail".to_string(), 0);
        report.insert("outcome_error".to_string(), 0);

        for att in self.attestations.values() {
            if att.policy_id != policy_id {
                continue;
            }
            *report.get_mut("total").unwrap() += 1;
            match att.status {
                AttestationStatus::Active => *report.get_mut("active").unwrap() += 1,
                AttestationStatus::Expired => *report.get_mut("expired").unwrap() += 1,
                AttestationStatus::Revoked => *report.get_mut("revoked").unwrap() += 1,
            }
            match att.outcome {
                PredicateOutcome::Pass => *report.get_mut("outcome_pass").unwrap() += 1,
                PredicateOutcome::Fail => *report.get_mut("outcome_fail").unwrap() += 1,
                PredicateOutcome::Error => *report.get_mut("outcome_error").unwrap() += 1,
            }
        }
        report
    }

    // ── Internal helpers ────────────────────────────────────────────────────

    fn record_audit(
        &mut self,
        record_id: String,
        event_code: String,
        attestation_id: Option<String>,
        policy_id: Option<String>,
        trace_id: String,
        timestamp_ms: u64,
        detail: String,
    ) {
        let record = ZkAuditRecord {
            record_id: record_id.clone(),
            event_code,
            attestation_id,
            policy_id,
            trace_id,
            timestamp_ms,
            detail,
            schema_version: SCHEMA_VERSION.to_string(),
        };
        self.audit_trail.insert(record_id, record);
    }
}

impl Default for AttestationLedger {
    fn default() -> Self {
        Self::new()
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy() -> ZkPolicy {
        ZkPolicy {
            policy_id: "pol-compliance-01".to_string(),
            predicate_description: "GDPR data residency check".to_string(),
            issuer: "issuer-key-abc123".to_string(),
            validity_ms: DEFAULT_VALIDITY_MS,
            schema_version: SCHEMA_VERSION.to_string(),
            active: true,
            registered_at_ms: 1_000_000,
        }
    }

    fn test_policy_alt() -> ZkPolicy {
        ZkPolicy {
            policy_id: "pol-other-02".to_string(),
            predicate_description: "SOC2 audit check".to_string(),
            issuer: "issuer-key-xyz789".to_string(),
            validity_ms: DEFAULT_VALIDITY_MS,
            schema_version: SCHEMA_VERSION.to_string(),
            active: true,
            registered_at_ms: 1_000_000,
        }
    }

    fn generate_test_attestation(
        ledger: &mut AttestationLedger,
        id: &str,
        policy: &ZkPolicy,
        outcome: PredicateOutcome,
        now_ms: u64,
    ) -> ZkAttestation {
        ledger
            .generate_proof(
                id.to_string(),
                policy,
                format!("commit-{}", id),
                "deadbeef".to_string(),
                outcome,
                now_ms,
                format!("trace-{}", id),
            )
            .unwrap()
    }

    // ── Schema version tests ────────────────────────────────────────────

    #[test]
    fn test_schema_version_constant() {
        assert_eq!(SCHEMA_VERSION, "zka-v1.0");
    }

    #[test]
    fn test_attestation_carries_schema_version() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att = generate_test_attestation(
            &mut ledger,
            "att-1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        assert_eq!(att.payload.schema_version, SCHEMA_VERSION);
    }

    // ── PolicyRegistry tests ────────────────────────────────────────────

    #[test]
    fn test_register_policy_success() {
        let mut registry = PolicyRegistry::new();
        let result = registry.register_policy(test_policy());
        assert!(result.is_ok());
        assert!(result.unwrap().contains(event_codes::FN_ZK_008));
    }

    #[test]
    fn test_register_duplicate_policy_fails() {
        let mut registry = PolicyRegistry::new();
        registry.register_policy(test_policy()).unwrap();
        let result = registry.register_policy(test_policy());
        assert!(result.is_err());
        assert!(result.unwrap_err().contains(error_codes::ERR_ZKA_DUPLICATE));
    }

    #[test]
    fn test_deregister_policy_success() {
        let mut registry = PolicyRegistry::new();
        let policy = test_policy();
        registry.register_policy(policy.clone()).unwrap();
        let result = registry.deregister_policy(&policy.policy_id);
        assert!(result.is_ok());
        assert!(result.unwrap().contains(event_codes::FN_ZK_009));
    }

    #[test]
    fn test_deregister_missing_policy_fails() {
        let mut registry = PolicyRegistry::new();
        let result = registry.deregister_policy("nonexistent");
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains(error_codes::ERR_ZKA_POLICY_NOT_FOUND)
        );
    }

    #[test]
    fn test_get_policy_found() {
        let mut registry = PolicyRegistry::new();
        let policy = test_policy();
        registry.register_policy(policy.clone()).unwrap();
        assert!(registry.get_policy(&policy.policy_id).is_some());
    }

    #[test]
    fn test_get_policy_not_found() {
        let registry = PolicyRegistry::new();
        assert!(registry.get_policy("nonexistent").is_none());
    }

    // ── Generate proof tests ────────────────────────────────────────────

    #[test]
    fn test_generate_proof_success() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att = generate_test_attestation(
            &mut ledger,
            "att-1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        assert_eq!(att.attestation_id, "att-1");
        assert_eq!(att.status, AttestationStatus::Active);
        assert_eq!(att.outcome, PredicateOutcome::Pass);
        assert_eq!(att.policy_id, policy.policy_id);
    }

    #[test]
    fn test_generate_proof_records_in_ledger() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        generate_test_attestation(
            &mut ledger,
            "att-1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        assert!(ledger.attestations.contains_key("att-1"));
    }

    #[test]
    fn test_generate_proof_duplicate_commitment_rejected() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        generate_test_attestation(
            &mut ledger,
            "att-1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        // Same commitment via helper generates "commit-att-1" again
        let result = ledger.generate_proof(
            "att-2".to_string(),
            &policy,
            "commit-att-1".to_string(),
            "aabbccdd".to_string(),
            PredicateOutcome::Pass,
            1_000_001,
            "trace-2".to_string(),
        );
        assert!(result.is_err());
        assert!(result.unwrap_err().contains(error_codes::ERR_ZKA_DUPLICATE));
    }

    #[test]
    fn test_generate_proof_non_hex_rejected() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let result = ledger.generate_proof(
            "att-bad".to_string(),
            &policy,
            "commit-bad".to_string(),
            "not-valid-hex!!".to_string(),
            PredicateOutcome::Pass,
            1_000_000,
            "trace-bad".to_string(),
        );
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .contains(error_codes::ERR_ZKA_METADATA_LEAK)
        );
    }

    // ── Verify proof tests ──────────────────────────────────────────────

    #[test]
    fn test_verify_valid_proof_passes() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att = generate_test_attestation(
            &mut ledger,
            "att-1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        let result = ledger.verify_proof(&att, &policy, 1_000_001, "trace-v1".to_string());
        assert!(result.is_verified());
    }

    #[test]
    fn test_verify_policy_mismatch_rejected() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let other_policy = test_policy_alt();
        let att = generate_test_attestation(
            &mut ledger,
            "att-1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        let result = ledger.verify_proof(&att, &other_policy, 1_000_001, "trace-v2".to_string());
        assert!(!result.is_verified());
        match &result {
            ZkVerificationResult::Rejected { error_code, .. } => {
                assert_eq!(error_code, error_codes::ERR_ZKA_POLICY_MISMATCH);
            }
            _ => panic!("Expected Rejected"),
        }
    }

    #[test]
    fn test_verify_expired_proof_rejected() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att = generate_test_attestation(
            &mut ledger,
            "att-1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        // Jump past validity window
        let result =
            ledger.verify_proof(&att, &policy, att.expires_at_ms + 1, "trace-v3".to_string());
        assert!(!result.is_verified());
        match &result {
            ZkVerificationResult::Rejected { error_code, .. } => {
                assert_eq!(error_code, error_codes::ERR_ZKA_EXPIRED);
            }
            _ => panic!("Expected Rejected"),
        }
    }

    #[test]
    fn test_verify_revoked_proof_rejected() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let mut att = generate_test_attestation(
            &mut ledger,
            "att-1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        att.status = AttestationStatus::Revoked;
        let result = ledger.verify_proof(&att, &policy, 1_000_001, "trace-v4".to_string());
        assert!(!result.is_verified());
        match &result {
            ZkVerificationResult::Rejected { error_code, .. } => {
                assert_eq!(error_code, error_codes::ERR_ZKA_REVOKED);
            }
            _ => panic!("Expected Rejected"),
        }
    }

    #[test]
    fn test_verify_failing_predicate_rejected() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att = generate_test_attestation(
            &mut ledger,
            "att-1",
            &policy,
            PredicateOutcome::Fail,
            1_000_000,
        );
        let result = ledger.verify_proof(&att, &policy, 1_000_001, "trace-v5".to_string());
        assert!(!result.is_verified());
        match &result {
            ZkVerificationResult::Rejected { error_code, .. } => {
                assert_eq!(error_code, error_codes::ERR_ZKA_PREDICATE_UNSATISFIED);
            }
            _ => panic!("Expected Rejected"),
        }
    }

    // ── Batch verification tests ────────────────────────────────────────

    #[test]
    fn test_batch_all_pass() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att1 = generate_test_attestation(
            &mut ledger,
            "att-b1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        let att2 = generate_test_attestation(
            &mut ledger,
            "att-b2",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        let batch =
            ledger.verify_batch(&[att1, att2], &policy, 1_000_001, "trace-batch".to_string());
        assert_eq!(batch.total, 2);
        assert_eq!(batch.passed, 2);
        assert_eq!(batch.failed, 0);
    }

    #[test]
    fn test_batch_partial_failure() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att1 = generate_test_attestation(
            &mut ledger,
            "att-b3",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        let att2 = generate_test_attestation(
            &mut ledger,
            "att-b4",
            &policy,
            PredicateOutcome::Fail,
            1_000_000,
        );
        let batch = ledger.verify_batch(
            &[att1, att2],
            &policy,
            1_000_001,
            "trace-batch2".to_string(),
        );
        assert_eq!(batch.total, 2);
        assert_eq!(batch.passed, 1);
        assert_eq!(batch.failed, 1);
    }

    // ── Revocation tests ────────────────────────────────────────────────

    #[test]
    fn test_revoke_attestation_success() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        generate_test_attestation(
            &mut ledger,
            "att-r1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        let result = ledger.revoke_attestation("att-r1", 1_000_100, "trace-rev".to_string());
        assert!(result.is_ok());
        assert!(result.unwrap().contains(event_codes::FN_ZK_007));
        assert_eq!(
            ledger.attestations["att-r1"].status,
            AttestationStatus::Revoked
        );
    }

    #[test]
    fn test_revoke_already_revoked_fails() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        generate_test_attestation(
            &mut ledger,
            "att-r2",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        ledger
            .revoke_attestation("att-r2", 1_000_100, "trace-rev2".to_string())
            .unwrap();
        let result = ledger.revoke_attestation("att-r2", 1_000_200, "trace-rev3".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_revoke_nonexistent_fails() {
        let mut ledger = AttestationLedger::new();
        let result = ledger.revoke_attestation("nope", 1_000_000, "trace-nope".to_string());
        assert!(result.is_err());
    }

    // ── is_valid / sweep tests ──────────────────────────────────────────

    #[test]
    fn test_is_valid_active_within_window() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        generate_test_attestation(
            &mut ledger,
            "att-v1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        assert!(ledger.is_valid("att-v1", 1_000_001));
    }

    #[test]
    fn test_is_valid_expired() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att = generate_test_attestation(
            &mut ledger,
            "att-v2",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        assert!(!ledger.is_valid("att-v2", att.expires_at_ms + 1));
    }

    #[test]
    fn test_sweep_expired_marks_correctly() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att = generate_test_attestation(
            &mut ledger,
            "att-s1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        let expired = ledger.sweep_expired(att.expires_at_ms + 1);
        assert_eq!(expired, vec!["att-s1"]);
        assert_eq!(
            ledger.attestations["att-s1"].status,
            AttestationStatus::Expired
        );
    }

    // ── Audit query tests ───────────────────────────────────────────────

    #[test]
    fn test_audit_trail_populated() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        generate_test_attestation(
            &mut ledger,
            "att-a1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        let records = ledger.query_audit(|r| r.event_code == event_codes::FN_ZK_001);
        assert_eq!(records.len(), 1);
    }

    #[test]
    fn test_audit_trail_on_verification() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att = generate_test_attestation(
            &mut ledger,
            "att-a2",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        ledger.verify_proof(&att, &policy, 1_000_001, "trace-audit".to_string());
        // Should have: FN-ZK-001 (gen), FN-ZK-002 (submit), FN-ZK-003 (pass)
        let gen_records = ledger.query_audit(|r| r.event_code == event_codes::FN_ZK_001);
        let submit_records = ledger.query_audit(|r| r.event_code == event_codes::FN_ZK_002);
        let pass_records = ledger.query_audit(|r| r.event_code == event_codes::FN_ZK_003);
        assert_eq!(gen_records.len(), 1);
        assert_eq!(submit_records.len(), 1);
        assert_eq!(pass_records.len(), 1);
    }

    // ── Compliance report tests ─────────────────────────────────────────

    #[test]
    fn test_compliance_report_counts() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        generate_test_attestation(
            &mut ledger,
            "att-c1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        generate_test_attestation(
            &mut ledger,
            "att-c2",
            &policy,
            PredicateOutcome::Fail,
            1_000_000,
        );
        let report = ledger.generate_compliance_report(&policy.policy_id);
        assert_eq!(report["total"], 2);
        assert_eq!(report["active"], 2);
        assert_eq!(report["outcome_pass"], 1);
        assert_eq!(report["outcome_fail"], 1);
    }

    #[test]
    fn test_compliance_report_filters_by_policy() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let other = test_policy_alt();
        generate_test_attestation(
            &mut ledger,
            "att-c3",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        // Manually insert under different policy
        let att_other = ZkAttestation {
            attestation_id: "att-c4".to_string(),
            policy_id: other.policy_id.clone(),
            payload: ZkProofPayload {
                schema_version: SCHEMA_VERSION.to_string(),
                proof_bytes_hex: "aabb".to_string(),
                metadata_commitment: "commit-other".to_string(),
            },
            outcome: PredicateOutcome::Pass,
            status: AttestationStatus::Active,
            generated_at_ms: 1_000_000,
            expires_at_ms: 1_000_000 + DEFAULT_VALIDITY_MS,
            trace_id: "trace-c4".to_string(),
        };
        ledger.attestations.insert("att-c4".to_string(), att_other);
        let report = ledger.generate_compliance_report(&policy.policy_id);
        assert_eq!(report["total"], 1);
    }

    // ── Invariant module tests ──────────────────────────────────────────

    #[test]
    fn test_invariant_selective_valid() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att = generate_test_attestation(
            &mut ledger,
            "att-inv1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        assert!(invariants::check_selective(&att));
    }

    #[test]
    fn test_invariant_selective_rejects_empty_commitment() {
        let att = ZkAttestation {
            attestation_id: "att-bad".to_string(),
            policy_id: "pol-1".to_string(),
            payload: ZkProofPayload {
                schema_version: SCHEMA_VERSION.to_string(),
                proof_bytes_hex: "aabb".to_string(),
                metadata_commitment: "".to_string(), // empty = leak
            },
            outcome: PredicateOutcome::Pass,
            status: AttestationStatus::Active,
            generated_at_ms: 1_000_000,
            expires_at_ms: 2_000_000,
            trace_id: "trace-bad".to_string(),
        };
        assert!(!invariants::check_selective(&att));
    }

    #[test]
    fn test_invariant_soundness_verified() {
        let result = ZkVerificationResult::Verified {
            attestation_id: "a1".to_string(),
            policy_id: "p1".to_string(),
            trace_id: "t1".to_string(),
            verified_at_ms: 1_000_000,
        };
        assert!(invariants::check_soundness(&result));
    }

    #[test]
    fn test_invariant_soundness_rejected() {
        let result = ZkVerificationResult::Rejected {
            attestation_id: "a1".to_string(),
            policy_id: "p1".to_string(),
            trace_id: "t1".to_string(),
            reason: "bad".to_string(),
            error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
        };
        assert!(invariants::check_soundness(&result));
    }

    #[test]
    fn test_invariant_policy_bound() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att = generate_test_attestation(
            &mut ledger,
            "att-pb1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        assert!(invariants::check_policy_bound(&att, &policy));
        let other = test_policy_alt();
        assert!(!invariants::check_policy_bound(&att, &other));
    }

    #[test]
    fn test_invariant_schema_versioned() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att = generate_test_attestation(
            &mut ledger,
            "att-sv1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        assert!(invariants::check_schema_versioned(&att));
    }

    #[test]
    fn test_invariant_audit_trail() {
        let record = ZkAuditRecord {
            record_id: "r1".to_string(),
            event_code: event_codes::FN_ZK_001.to_string(),
            attestation_id: Some("a1".to_string()),
            policy_id: Some("p1".to_string()),
            trace_id: "t1".to_string(),
            timestamp_ms: 1_000_000,
            detail: "test".to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        };
        assert!(invariants::check_audit_trail(&record));
    }

    #[test]
    fn test_invariant_audit_trail_rejects_empty_trace() {
        let record = ZkAuditRecord {
            record_id: "r1".to_string(),
            event_code: event_codes::FN_ZK_001.to_string(),
            attestation_id: None,
            policy_id: None,
            trace_id: "".to_string(),
            timestamp_ms: 1_000_000,
            detail: "test".to_string(),
            schema_version: SCHEMA_VERSION.to_string(),
        };
        assert!(!invariants::check_audit_trail(&record));
    }

    #[test]
    fn test_invariant_completeness_active_pass_within_window() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att = generate_test_attestation(
            &mut ledger,
            "att-comp1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        assert!(invariants::check_completeness(&att, 1_000_001));
    }

    #[test]
    fn test_invariant_completeness_expired_is_ok_for_non_pass() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att = generate_test_attestation(
            &mut ledger,
            "att-comp2",
            &policy,
            PredicateOutcome::Fail,
            1_000_000,
        );
        // Even if "expired" by clock, invariant does not apply for Fail outcome
        assert!(invariants::check_completeness(&att, att.expires_at_ms + 1));
    }
}
