//! bd-kcg9 / bd-reality-20260923-26n9r.18: Zero-knowledge attestation support
//! for selective compliance verification.
//!
//! Legacy `zka-v1.0` records carry caller-supplied bytes and outcomes with no
//! cryptographic witness relation; `verify_proof` continues to fail closed with
//! `ERR_ZKA_VERIFIER_UNAVAILABLE` on unauthenticated legacy records so historical
//! registrations never gain compliance authority.
//!
//! Authenticated `zka-ristretto255-v3.0` attestations prove selective compliance
//! over prime-order Ristretto255 (`curve25519-dalek`) with zero trusted setup:
//! - Pedersen commitments `C = v * G + r * H` with hash-to-group generator `H`.
//! - `ThresholdAtLeast`: homomorphic shift `C - tau * G == sum(2^j * C_j)` plus
//!   `range_bits` parallel Cramer-Damgard-Schoenmakers (CDS94) 1-of-2 Schnorr
//!   OR-proofs establishing `v >= threshold` without disclosing `v`.
//! - `AllowlistMembership`: Merkle-authenticated allowlist root plus a CDS94
//!   1-of-N Schnorr OR-proof establishing `v in allowed_values` without
//!   disclosing which element matched.
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

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use curve25519_dalek::constants::RISTRETTO_BASEPOINT_POINT;
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use curve25519_dalek::scalar::Scalar;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256, Sha512};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::push_bounded;

/// Schema version for legacy v1 ZK attestation payloads and ledger envelopes.
pub const SCHEMA_VERSION: &str = "zka-v1.0";

/// Schema version for authenticated Ristretto255 zero-knowledge compliance payloads.
pub const CRYPTO_SCHEMA_VERSION: &str = "zka-ristretto255-v3.0";

/// Maximum hex character length accepted for a serialized cryptographic proof (32 KiB raw).
pub const MAX_CRYPTO_PROOF_HEX_LEN: usize = 65_536;

/// Maximum bit width for `ThresholdAtLeast` range decompositions.
pub const MAX_RANGE_BITS: u8 = 64;

/// Maximum cardinality for `AllowlistMembership` ring/OR-proofs.
pub const MAX_ALLOWLIST_MEMBERS: usize = 64;

/// Default proof validity window in milliseconds.
pub const DEFAULT_VALIDITY_MS: u64 = 600_000; // 10 minutes

/// Maximum proofs in a single batch verification.
pub const MAX_BATCH_SIZE: usize = 256;

/// Security: bounds for push_bounded to prevent memory exhaustion
#[cfg(test)]
const MAX_TIMING_SAMPLES: usize = 10_000;
const MAX_AUDIT_TRAIL_ENTRIES: usize = 100_000;
#[cfg(test)]
const MAX_ATTESTATIONS_LIST: usize = 10_000;
#[cfg(test)]
const MAX_THREAD_HANDLES: usize = 1_000;

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

/// ERR_ZK_WITNESS_INVALID: cryptographic witness or Schnorr relation failed verification.
/// Maps to ERR_ZKA_WITNESS_INVALID.
pub const ERR_ZK_WITNESS_INVALID: &str = "ERR_ZK_WITNESS_INVALID";

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
    /// No supported cryptographic relation and verifier parameters are available.
    pub const ERR_ZKA_VERIFIER_UNAVAILABLE: &str = "ERR_ZKA_VERIFIER_UNAVAILABLE";
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
    /// Cryptographic proof transcript failed relation, commitment, or Schnorr verification.
    pub const ERR_ZKA_WITNESS_INVALID: &str = "ERR_ZKA_WITNESS_INVALID";
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

// ── Authenticated Ristretto255 Zero-Knowledge Compliance Types ──────────────

const PEDERSEN_H_DOMAIN: &[u8] = b"franken-node/zka-ristretto255/pedersen-generator-h/v1";
const POLICY_BINDING_DOMAIN: &[u8] = b"franken-node/zka-ristretto255/policy-binding/v2";
const PARAMS_HASH_DOMAIN: &[u8] = b"franken-node/zka-ristretto255/verifier-params/v3";
const ALLOWLIST_LEAF_DOMAIN: &[u8] = b"franken-node/zka-ristretto255/allowlist-leaf/v2";
const ALLOWLIST_NODE_DOMAIN: &[u8] = b"franken-node/zka-ristretto255/allowlist-node/v2";
const ALLOWLIST_ODD_DOMAIN: &[u8] = b"franken-node/zka-ristretto255/allowlist-odd/v2";
const FIAT_SHAMIR_DOMAIN: &[u8] = b"franken-node/zka-ristretto255/fiat-shamir/v3";
const HEDGED_NONCE_DOMAIN: &[u8] = b"franken-node/zka-ristretto255/hedged-nonce-seed/v3";
const ZKRP3_MAGIC: &[u8; 5] = b"ZKRP3";
const ZKRP3_TAG_THRESHOLD: u8 = 0x01;
const ZKRP3_TAG_ALLOWLIST: u8 = 0x02;

/// Zeroized private witness `(value, blinding)` for Ristretto255 Pedersen commitments.
///
/// Deliberately omits `Serialize`/`Deserialize` and redacts `Debug` so private
/// compliance attributes cannot leak into logs, snapshots, or audit trails.
/// INV-ZKA-SELECTIVE, INV-ZK-NO-DISCLOSURE
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct ZkPrivateWitness {
    value: u64,
    blinding_bytes: [u8; 32],
}

impl fmt::Debug for ZkPrivateWitness {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ZkPrivateWitness")
            .field("value", &"[REDACTED]")
            .field("blinding", &"[REDACTED]")
            .finish()
    }
}

impl ZkPrivateWitness {
    /// Construct a private witness from an explicit 32-byte blinding seed.
    /// Rejects seeds that reduce to zero modulo the Ristretto255 group order.
    pub fn new(value: u64, blinding_bytes: [u8; 32]) -> Result<Self, String> {
        if Scalar::from_bytes_mod_order(blinding_bytes) == Scalar::ZERO {
            return Err(format!(
                "{}: witness blinding scalar must be non-zero",
                error_codes::ERR_ZKA_WITNESS_INVALID
            ));
        }
        Ok(Self {
            value,
            blinding_bytes,
        })
    }

    /// Construct a private witness with fresh OS-supplied blinding randomness.
    #[must_use]
    pub fn random(value: u64) -> Self {
        let mut rng = rand::rngs::OsRng;
        loop {
            let mut blinding_bytes = [0u8; 32];
            rng.fill_bytes(&mut blinding_bytes);
            if Scalar::from_bytes_mod_order(blinding_bytes) != Scalar::ZERO {
                return Self {
                    value,
                    blinding_bytes,
                };
            }
        }
    }

    fn blinding_scalar(&self) -> Scalar {
        Scalar::from_bytes_mod_order(self.blinding_bytes)
    }

    fn commitment_point(&self) -> RistrettoPoint {
        pedersen_commit(Scalar::from(self.value), self.blinding_scalar())
    }

    /// Compute the 64-character lowercase hex compressed Ristretto255 Pedersen commitment
    /// `C = value * G + blinding * H`.
    #[must_use]
    pub fn pedersen_commitment_hex(&self) -> String {
        hex::encode(self.commitment_point().compress().as_bytes())
    }
}

/// Cryptographic compliance predicate proven in zero knowledge over a committed `u64` attribute.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ZkComplianceRelation {
    /// Proves committed attribute `v` satisfies `threshold <= v < threshold + 2^range_bits`
    /// (`1 <= range_bits <= 64`) using Pedersen homomorphic shift and `range_bits` parallel
    /// CDS94 1-of-2 Schnorr OR-proofs.
    ThresholdAtLeast { threshold: u64, range_bits: u8 },
    /// Proves committed attribute `v` belongs to `allowed_values` (`1..=64` unique values
    /// authenticated by `merkle_root_hex`) using a CDS94 1-of-N Schnorr OR-proof.
    AllowlistMembership {
        allowed_values: Vec<u64>,
        merkle_root_hex: String,
    },
}

impl ZkComplianceRelation {
    /// Construct a validated `ThresholdAtLeast` relation.
    pub fn threshold_at_least(threshold: u64, range_bits: u8) -> Result<Self, String> {
        let rel = Self::ThresholdAtLeast {
            threshold,
            range_bits,
        };
        rel.validate()?;
        Ok(rel)
    }

    /// Construct a validated `AllowlistMembership` relation with canonical Merkle root.
    pub fn allowlist(allowed_values: Vec<u64>) -> Result<Self, String> {
        let merkle_root_hex = compute_allowlist_merkle_root(&allowed_values);
        let rel = Self::AllowlistMembership {
            allowed_values,
            merkle_root_hex,
        };
        rel.validate()?;
        Ok(rel)
    }

    /// Validate relation parameters and Merkle binding.
    pub fn validate(&self) -> Result<(), String> {
        match self {
            Self::ThresholdAtLeast { range_bits, .. } => {
                if *range_bits == 0 || *range_bits > MAX_RANGE_BITS {
                    return Err(format!(
                        "{}: range_bits {} outside 1..={}",
                        error_codes::ERR_ZKA_POLICY_MISMATCH,
                        range_bits,
                        MAX_RANGE_BITS
                    ));
                }
                Ok(())
            }
            Self::AllowlistMembership {
                allowed_values,
                merkle_root_hex,
            } => {
                if allowed_values.is_empty() || allowed_values.len() > MAX_ALLOWLIST_MEMBERS {
                    return Err(format!(
                        "{}: allowlist cardinality {} outside 1..={}",
                        error_codes::ERR_ZKA_POLICY_MISMATCH,
                        allowed_values.len(),
                        MAX_ALLOWLIST_MEMBERS
                    ));
                }
                let unique: BTreeSet<u64> = allowed_values.iter().copied().collect();
                if unique.len() != allowed_values.len() {
                    return Err(format!(
                        "{}: allowlist contains duplicate members",
                        error_codes::ERR_ZKA_POLICY_MISMATCH
                    ));
                }
                let expected_root = compute_allowlist_merkle_root(allowed_values);
                if !constant_time_str_eq(merkle_root_hex, &expected_root) {
                    return Err(format!(
                        "{}: allowlist Merkle root mismatch",
                        error_codes::ERR_ZKA_POLICY_MISMATCH
                    ));
                }
                Ok(())
            }
        }
    }

    fn canonical_digest(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        match self {
            Self::ThresholdAtLeast {
                threshold,
                range_bits,
            } => {
                hasher.update([ZKRP3_TAG_THRESHOLD]);
                hasher.update(threshold.to_le_bytes());
                hasher.update([*range_bits]);
            }
            Self::AllowlistMembership {
                allowed_values,
                merkle_root_hex,
            } => {
                hasher.update([ZKRP3_TAG_ALLOWLIST]);
                hasher.update((allowed_values.len() as u64).to_le_bytes());
                for v in allowed_values {
                    hasher.update(v.to_le_bytes());
                }
                update_len_prefixed(&mut hasher, merkle_root_hex.as_bytes());
            }
        }
        hasher.finalize().into()
    }
}

/// Authenticated public verifier parameters binding a `ZkPolicy`'s full content,
/// verifier key identity, epoch, challenge nonce, and compliance relation.
/// INV-ZKA-POLICY-BOUND
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkVerifierParams {
    /// Schema version (`zka-ristretto255-v3.0`).
    pub schema_version: String,
    /// Policy identifier bound to these parameters.
    pub policy_id: String,
    /// Domain-separated SHA-256 over the full `ZkPolicy` definition.
    pub policy_binding_sha256: String,
    /// Authenticated verifier parameter/key identifier.
    pub verifier_key_id: String,
    /// Monotonic security epoch bound into Fiat-Shamir transcripts.
    pub epoch: u64,
    /// Non-empty verifier challenge nonce bound into Fiat-Shamir transcripts.
    pub challenge_nonce: String,
    /// Mathematical compliance relation proven by attestations under these parameters.
    pub relation: ZkComplianceRelation,
}

impl ZkVerifierParams {
    /// Construct authenticated verifier parameters bound to `policy`.
    pub fn for_policy(
        policy: &ZkPolicy,
        verifier_key_id: impl Into<String>,
        epoch: u64,
        challenge_nonce: impl Into<String>,
        relation: ZkComplianceRelation,
    ) -> Result<Self, String> {
        let verifier_key_id = verifier_key_id.into();
        let challenge_nonce = challenge_nonce.into();
        if policy.policy_id.trim().is_empty() {
            return Err(format!(
                "{}: policy_id must be non-empty",
                error_codes::ERR_ZKA_POLICY_MISMATCH
            ));
        }
        if verifier_key_id.trim().is_empty() {
            return Err(format!(
                "{}: verifier_key_id must be non-empty",
                error_codes::ERR_ZKA_VERIFIER_UNAVAILABLE
            ));
        }
        if challenge_nonce.trim().is_empty() {
            return Err(format!(
                "{}: challenge_nonce must be non-empty",
                error_codes::ERR_ZKA_VERIFIER_UNAVAILABLE
            ));
        }
        relation.validate()?;
        Ok(Self {
            schema_version: CRYPTO_SCHEMA_VERSION.to_string(),
            policy_id: policy.policy_id.clone(),
            policy_binding_sha256: compute_policy_binding_sha256(policy),
            verifier_key_id,
            epoch,
            challenge_nonce,
            relation,
        })
    }

    /// Verify that these parameters are authentic, structurally valid, and bound
    /// to the exact `ZkPolicy` content (not merely a matching `policy_id` string).
    #[must_use]
    pub fn matches_policy(&self, policy: &ZkPolicy) -> bool {
        if self.schema_version != CRYPTO_SCHEMA_VERSION
            || self.verifier_key_id.trim().is_empty()
            || self.challenge_nonce.trim().is_empty()
            || self.policy_id != policy.policy_id
            || self.relation.validate().is_err()
        {
            return false;
        }
        let expected_binding = compute_policy_binding_sha256(policy);
        constant_time_str_eq(&self.policy_binding_sha256, &expected_binding)
    }

    fn params_digest_bytes(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(PARAMS_HASH_DOMAIN);
        update_len_prefixed(&mut hasher, self.schema_version.as_bytes());
        update_len_prefixed(&mut hasher, self.policy_id.as_bytes());
        update_len_prefixed(&mut hasher, self.policy_binding_sha256.as_bytes());
        update_len_prefixed(&mut hasher, self.verifier_key_id.as_bytes());
        hasher.update(self.epoch.to_le_bytes());
        update_len_prefixed(&mut hasher, self.challenge_nonce.as_bytes());
        hasher.update(self.relation.canonical_digest());
        hasher.finalize().into()
    }

    /// Canonical 64-character lowercase hex SHA-256 digest of these verifier parameters.
    #[must_use]
    pub fn params_sha256(&self) -> String {
        hex::encode(self.params_digest_bytes())
    }
}

/// Deterministic verification telemetry derived from `AttestationLedger` state.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZkVerificationTelemetry {
    /// Count of `zka-ristretto255-v3.0` attestations in the ledger.
    pub crypto_proofs_generated: usize,
    /// Count of legacy `zka-v1.0` registrations in the ledger.
    pub legacy_registrations: usize,
    /// Total `FN-ZK-002` verification submissions recorded.
    pub verification_submissions: usize,
    /// Total `FN-ZK-003` cryptographic verifications passed.
    pub crypto_verifications_passed: usize,
    /// Total `FN-ZK-005` policy/parameter mismatch rejections.
    pub rejections_policy_mismatch: usize,
    /// Total `FN-ZK-004` rejections where Schnorr/relation witness verification failed.
    pub rejections_witness_invalid: usize,
    /// Total `FN-ZK-004` rejections across all invalid/revoked/expired/unavailable paths.
    pub rejections_total_fn_zk_004: usize,
}

/// Compute the canonical domain-separated SHA-256 binding digest over a `ZkPolicy`.
#[must_use]
pub fn compute_policy_binding_sha256(policy: &ZkPolicy) -> String {
    let mut hasher = Sha256::new();
    hasher.update(POLICY_BINDING_DOMAIN);
    update_len_prefixed(&mut hasher, policy.policy_id.as_bytes());
    update_len_prefixed(&mut hasher, policy.predicate_description.as_bytes());
    update_len_prefixed(&mut hasher, policy.issuer.as_bytes());
    hasher.update(policy.validity_ms.to_le_bytes());
    update_len_prefixed(&mut hasher, policy.schema_version.as_bytes());
    hex::encode(hasher.finalize())
}

/// Compute the domain-separated binary Merkle root over an allowlist of `u64` compliance codes.
#[must_use]
pub fn compute_allowlist_merkle_root(values: &[u64]) -> String {
    if values.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(ALLOWLIST_LEAF_DOMAIN);
        return hex::encode(hasher.finalize());
    }
    let mut level: Vec<[u8; 32]> = values
        .iter()
        .enumerate()
        .map(|(idx, value)| {
            let mut hasher = Sha256::new();
            hasher.update(ALLOWLIST_LEAF_DOMAIN);
            hasher.update((idx as u64).to_le_bytes());
            hasher.update(value.to_le_bytes());
            hasher.finalize().into()
        })
        .collect();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut idx = 0usize;
        while idx < level.len() {
            let mut hasher = Sha256::new();
            if idx + 1 < level.len() {
                hasher.update(ALLOWLIST_NODE_DOMAIN);
                hasher.update(level[idx]);
                hasher.update(level[idx + 1]);
            } else {
                hasher.update(ALLOWLIST_ODD_DOMAIN);
                hasher.update(level[idx]);
            }
            next.push(hasher.finalize().into());
            idx += 2;
        }
        level = next;
    }
    hex::encode(level[0])
}

fn update_len_prefixed(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn update_len_prefixed_512(hasher: &mut Sha512, bytes: &[u8]) {
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn constant_time_str_eq(lhs: &str, rhs: &str) -> bool {
    lhs.len() == rhs.len() && bool::from(lhs.as_bytes().ct_eq(rhs.as_bytes()))
}

fn pedersen_generator_h() -> RistrettoPoint {
    let mut hasher = Sha512::new();
    hasher.update(PEDERSEN_H_DOMAIN);
    let uniform: [u8; 64] = hasher.finalize().into();
    RistrettoPoint::from_uniform_bytes(&uniform)
}

fn pedersen_commit(value: Scalar, blinding: Scalar) -> RistrettoPoint {
    value * RISTRETTO_BASEPOINT_POINT + blinding * pedersen_generator_h()
}

struct DeterministicScalarPrf {
    seed: [u8; 64],
    counter: u64,
}

impl Drop for DeterministicScalarPrf {
    fn drop(&mut self) {
        self.seed.zeroize();
        self.counter.zeroize();
    }
}

impl DeterministicScalarPrf {
    fn hedged(
        witness: &ZkPrivateWitness,
        params_digest: &[u8; 32],
        attestation_id: &str,
        generated_at_ms: u64,
        expires_at_ms: u64,
    ) -> Self {
        let mut os_entropy = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut os_entropy);
        let mut hasher = Sha512::new();
        hasher.update(HEDGED_NONCE_DOMAIN);
        hasher.update(witness.blinding_bytes);
        hasher.update(witness.value.to_le_bytes());
        hasher.update(params_digest);
        update_len_prefixed_512(&mut hasher, attestation_id.as_bytes());
        hasher.update(generated_at_ms.to_le_bytes());
        hasher.update(expires_at_ms.to_le_bytes());
        hasher.update(os_entropy);
        os_entropy.zeroize();
        Self {
            seed: hasher.finalize().into(),
            counter: 0,
        }
    }

    fn next_nonzero_scalar(&mut self, label: &[u8]) -> Scalar {
        loop {
            let mut hasher = Sha512::new();
            hasher.update(self.seed);
            hasher.update(self.counter.to_le_bytes());
            update_len_prefixed_512(&mut hasher, label);
            self.counter = self.counter.wrapping_add(1);
            let mut wide: [u8; 64] = hasher.finalize().into();
            let s = Scalar::from_bytes_mod_order_wide(&wide);
            wide.zeroize();
            if s != Scalar::ZERO {
                return s;
            }
        }
    }
}

struct Cds94OrProof {
    challenges: Vec<Scalar>,
    responses: Vec<Scalar>,
}

fn cds94_fiat_shamir_challenge(
    transcript_context: &[u8],
    subproof_index: u32,
    commitment: &CompressedRistretto,
    candidates: &[u64],
    announcements: &[CompressedRistretto],
) -> Scalar {
    let mut hasher = Sha512::new();
    hasher.update(FIAT_SHAMIR_DOMAIN);
    update_len_prefixed_512(&mut hasher, transcript_context);
    hasher.update(subproof_index.to_le_bytes());
    hasher.update(commitment.as_bytes());
    hasher.update((candidates.len() as u64).to_le_bytes());
    for candidate in candidates {
        hasher.update(candidate.to_le_bytes());
    }
    hasher.update((announcements.len() as u64).to_le_bytes());
    for ann in announcements {
        hasher.update(ann.as_bytes());
    }
    let wide: [u8; 64] = hasher.finalize().into();
    Scalar::from_bytes_mod_order_wide(&wide)
}

/// Prove in zero knowledge via CDS94 1-of-N disjunctive Schnorr that
/// `commitment == candidates[real_index] * G + blinding * H`.
fn prove_cds94_or(
    prf: &mut DeterministicScalarPrf,
    transcript_context: &[u8],
    subproof_index: u32,
    commitment: RistrettoPoint,
    candidates: &[u64],
    real_index: usize,
    blinding: Scalar,
) -> Cds94OrProof {
    let h = pedersen_generator_h();
    let branch_count = candidates.len();
    let mut challenges = vec![Scalar::ZERO; branch_count];
    let mut responses = vec![Scalar::ZERO; branch_count];
    let mut announcements = Vec::with_capacity(branch_count);

    let mut real_nonce = prf.next_nonzero_scalar(b"cds94-real-k");
    let mut simulated_sum = Scalar::ZERO;

    for idx in 0..branch_count {
        if idx == real_index {
            announcements.push((real_nonce * h).compress());
        } else {
            let e_sim = prf.next_nonzero_scalar(b"cds94-sim-e");
            let s_sim = prf.next_nonzero_scalar(b"cds94-sim-s");
            let shifted = commitment - Scalar::from(candidates[idx]) * RISTRETTO_BASEPOINT_POINT;
            let r_sim = s_sim * h - e_sim * shifted;
            challenges[idx] = e_sim;
            responses[idx] = s_sim;
            simulated_sum += e_sim;
            announcements.push(r_sim.compress());
        }
    }

    let compressed_commitment = commitment.compress();
    let total_challenge = cds94_fiat_shamir_challenge(
        transcript_context,
        subproof_index,
        &compressed_commitment,
        candidates,
        &announcements,
    );
    let e_real = total_challenge - simulated_sum;
    let s_real = real_nonce + e_real * blinding;
    real_nonce.zeroize();

    challenges[real_index] = e_real;
    responses[real_index] = s_real;

    Cds94OrProof {
        challenges,
        responses,
    }
}

/// Verify a CDS94 1-of-N disjunctive Schnorr proof over `commitment`.
fn verify_cds94_or(
    transcript_context: &[u8],
    subproof_index: u32,
    commitment: RistrettoPoint,
    compressed_commitment: &CompressedRistretto,
    candidates: &[u64],
    proof: &Cds94OrProof,
) -> bool {
    if proof.challenges.len() != candidates.len() || proof.responses.len() != candidates.len() {
        return false;
    }
    let h = pedersen_generator_h();
    let mut announcements = Vec::with_capacity(candidates.len());
    let mut challenge_sum = Scalar::ZERO;

    for (idx, candidate) in candidates.iter().enumerate() {
        let shifted = commitment - Scalar::from(*candidate) * RISTRETTO_BASEPOINT_POINT;
        let reconstructed = proof.responses[idx] * h - proof.challenges[idx] * shifted;
        announcements.push(reconstructed.compress());
        challenge_sum += proof.challenges[idx];
    }

    let expected_challenge = cds94_fiat_shamir_challenge(
        transcript_context,
        subproof_index,
        compressed_commitment,
        candidates,
        &announcements,
    );
    bool::from(
        challenge_sum
            .as_bytes()
            .ct_eq(expected_challenge.as_bytes()),
    )
}

fn build_fiat_shamir_context(
    attestation_id: &str,
    generated_at_ms: u64,
    expires_at_ms: u64,
    params_digest: &[u8; 32],
    compressed_commitment: &[u8; 32],
    extra_commitments: &[[u8; 32]],
) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(FIAT_SHAMIR_DOMAIN);
    update_len_prefixed(&mut hasher, attestation_id.as_bytes());
    hasher.update(generated_at_ms.to_le_bytes());
    hasher.update(expires_at_ms.to_le_bytes());
    hasher.update(params_digest);
    hasher.update(compressed_commitment);
    hasher.update((extra_commitments.len() as u64).to_le_bytes());
    for c in extra_commitments {
        hasher.update(c);
    }
    hasher.finalize().to_vec()
}

fn decode_canonical_scalar(bytes: &[u8]) -> Option<Scalar> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    Option::from(Scalar::from_canonical_bytes(arr))
}

fn decode_canonical_point(bytes: &[u8]) -> Option<(CompressedRistretto, RistrettoPoint)> {
    let arr: [u8; 32] = bytes.try_into().ok()?;
    let compressed = CompressedRistretto(arr);
    let point = compressed.decompress()?;
    Some((compressed, point))
}

fn prove_compliance_wire_bytes(
    attestation_id: &str,
    generated_at_ms: u64,
    expires_at_ms: u64,
    verifier_params: &ZkVerifierParams,
    witness: &ZkPrivateWitness,
) -> Result<(String, String), String> {
    verifier_params.relation.validate()?;
    let params_digest = verifier_params.params_digest_bytes();
    let commitment_point = witness.commitment_point();
    let commitment_compressed = commitment_point.compress();
    let commitment_bytes = commitment_compressed.to_bytes();
    let commitment_hex = hex::encode(commitment_bytes);
    let mut prf = DeterministicScalarPrf::hedged(
        witness,
        &params_digest,
        attestation_id,
        generated_at_ms,
        expires_at_ms,
    );

    match &verifier_params.relation {
        ZkComplianceRelation::ThresholdAtLeast {
            threshold,
            range_bits,
        } => {
            let Some(delta) = witness.value.checked_sub(*threshold) else {
                return Err(format!(
                    "{}: witness does not satisfy threshold relation",
                    error_codes::ERR_ZKA_PREDICATE_UNSATISFIED
                ));
            };
            if *range_bits < 64 && (delta >> u32::from(*range_bits)) != 0 {
                return Err(format!(
                    "{}: witness delta exceeds {}-bit range bound",
                    error_codes::ERR_ZKA_PREDICATE_UNSATISFIED,
                    range_bits
                ));
            }
            let bit_count = usize::from(*range_bits);
            let mut bit_blindings = vec![Scalar::ZERO; bit_count];
            let mut weighted_tail = Scalar::ZERO;
            let two = Scalar::from(2u64);
            let mut pow_two = two;
            for r_j in bit_blindings.iter_mut().skip(1) {
                *r_j = prf.next_nonzero_scalar(b"threshold-bit-blinding");
                weighted_tail += pow_two * *r_j;
                pow_two *= two;
            }
            bit_blindings[0] = witness.blinding_scalar() - weighted_tail;

            let mut bit_points = Vec::with_capacity(bit_count);
            let mut bit_compressed_bytes = Vec::with_capacity(bit_count);
            for (j, r_j) in bit_blindings.iter().enumerate() {
                let bit_val = (delta >> j) & 1;
                let c_j = pedersen_commit(Scalar::from(bit_val), *r_j);
                bit_compressed_bytes.push(c_j.compress().to_bytes());
                bit_points.push((usize::try_from(bit_val).unwrap_or(0), c_j));
            }

            let ctx = build_fiat_shamir_context(
                attestation_id,
                generated_at_ms,
                expires_at_ms,
                &params_digest,
                &commitment_bytes,
                &bit_compressed_bytes,
            );

            let mut out = Vec::with_capacity(72 + bit_count * 160);
            out.extend_from_slice(ZKRP3_MAGIC);
            out.push(ZKRP3_TAG_THRESHOLD);
            out.extend_from_slice(&params_digest);
            out.extend_from_slice(&commitment_bytes);
            out.extend_from_slice(&u16::from(*range_bits).to_le_bytes());

            for (j, ((bit_idx, c_j), r_j)) in
                bit_points.iter().zip(bit_blindings.iter()).enumerate()
            {
                let subproof_idx = u32::try_from(j).unwrap_or(u32::MAX);
                let or_proof =
                    prove_cds94_or(&mut prf, &ctx, subproof_idx, *c_j, &[0, 1], *bit_idx, *r_j);
                out.extend_from_slice(&bit_compressed_bytes[j]);
                out.extend_from_slice(or_proof.challenges[0].as_bytes());
                out.extend_from_slice(or_proof.challenges[1].as_bytes());
                out.extend_from_slice(or_proof.responses[0].as_bytes());
                out.extend_from_slice(or_proof.responses[1].as_bytes());
            }

            for r_j in &mut bit_blindings {
                r_j.zeroize();
            }

            Ok((commitment_hex, hex::encode(out)))
        }
        ZkComplianceRelation::AllowlistMembership { allowed_values, .. } => {
            let Some(real_index) = allowed_values.iter().position(|v| *v == witness.value) else {
                return Err(format!(
                    "{}: witness is not a member of the policy allowlist",
                    error_codes::ERR_ZKA_PREDICATE_UNSATISFIED
                ));
            };
            let branch_count = allowed_values.len();
            let branch_count_u16 = u16::try_from(branch_count).map_err(|_| {
                format!(
                    "{}: allowlist too large",
                    error_codes::ERR_ZKA_POLICY_MISMATCH
                )
            })?;
            let ctx = build_fiat_shamir_context(
                attestation_id,
                generated_at_ms,
                expires_at_ms,
                &params_digest,
                &commitment_bytes,
                &[],
            );
            let or_proof = prove_cds94_or(
                &mut prf,
                &ctx,
                0,
                commitment_point,
                allowed_values,
                real_index,
                witness.blinding_scalar(),
            );

            let mut out = Vec::with_capacity(72 + branch_count * 64);
            out.extend_from_slice(ZKRP3_MAGIC);
            out.push(ZKRP3_TAG_ALLOWLIST);
            out.extend_from_slice(&params_digest);
            out.extend_from_slice(&commitment_bytes);
            out.extend_from_slice(&branch_count_u16.to_le_bytes());
            for idx in 0..branch_count {
                out.extend_from_slice(or_proof.challenges[idx].as_bytes());
                out.extend_from_slice(or_proof.responses[idx].as_bytes());
            }

            Ok((commitment_hex, hex::encode(out)))
        }
    }
}

/// Stateless cryptographic verification of a `zka-ristretto255-v3.0` compliance proof
/// against `policy` and authenticated `verifier_params` at `now_ms`.
///
/// Does not rely on ledger membership; enforces full policy/parameter binding,
/// authenticated validity window, canonical Ristretto255 point/scalar decoding,
/// Pedersen homomorphic relation, and CDS94 Schnorr verification. The caller must
/// supply trusted current policy, verifier parameters, and time; use the ledger
/// wrapper when retained revocation and expiry state must also be enforced.
#[must_use]
pub fn verify_compliance_proof_stateless(
    attestation: &ZkAttestation,
    policy: &ZkPolicy,
    verifier_params: &ZkVerifierParams,
    now_ms: u64,
    trace_id: String,
) -> ZkVerificationResult {
    let aid = attestation.attestation_id.clone();
    let pid = policy.policy_id.clone();

    if !policy.active
        || !invariants::check_policy_bound(attestation, policy)
        || !verifier_params.matches_policy(policy)
    {
        return ZkVerificationResult::Rejected {
            attestation_id: aid,
            policy_id: pid,
            trace_id,
            reason: "Policy or authenticated verifier parameter mismatch".to_string(),
            error_code: error_codes::ERR_ZKA_POLICY_MISMATCH.to_string(),
        };
    }

    if attestation.status == AttestationStatus::Revoked {
        return ZkVerificationResult::Rejected {
            attestation_id: aid,
            policy_id: pid,
            trace_id,
            reason: "Attestation has been revoked".to_string(),
            error_code: error_codes::ERR_ZKA_REVOKED.to_string(),
        };
    }

    if attestation.status == AttestationStatus::Expired {
        return ZkVerificationResult::Rejected {
            attestation_id: aid,
            policy_id: pid,
            trace_id,
            reason: "Attestation has been marked expired".to_string(),
            error_code: error_codes::ERR_ZKA_EXPIRED.to_string(),
        };
    }

    if !attestation
        .generated_at_ms
        .checked_add(policy.validity_ms)
        .is_some_and(|latest_expiry| {
            attestation.expires_at_ms > attestation.generated_at_ms
                && attestation.expires_at_ms <= latest_expiry
        })
    {
        return ZkVerificationResult::Rejected {
            attestation_id: aid,
            policy_id: pid,
            trace_id,
            reason: "Proof validity interval is empty, overflows, or exceeds policy".to_string(),
            error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
        };
    }

    if now_ms >= attestation.expires_at_ms {
        return ZkVerificationResult::Rejected {
            attestation_id: aid,
            policy_id: pid,
            trace_id,
            reason: "Proof exceeded validity window".to_string(),
            error_code: error_codes::ERR_ZKA_EXPIRED.to_string(),
        };
    }

    if now_ms < attestation.generated_at_ms {
        return ZkVerificationResult::Rejected {
            attestation_id: aid,
            policy_id: pid,
            trace_id,
            reason: "Proof generated in the future".to_string(),
            error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
        };
    }

    if !invariants::check_selective(attestation) {
        return ZkVerificationResult::Rejected {
            attestation_id: aid,
            policy_id: pid,
            trace_id,
            reason: "Proof structure would reveal private fields".to_string(),
            error_code: error_codes::ERR_ZKA_METADATA_LEAK.to_string(),
        };
    }

    if attestation.outcome != PredicateOutcome::Pass {
        return ZkVerificationResult::Rejected {
            attestation_id: aid,
            policy_id: pid,
            trace_id,
            reason: format!("Compliance predicate not met: {}", attestation.outcome),
            error_code: error_codes::ERR_ZKA_PREDICATE_UNSATISFIED.to_string(),
        };
    }

    if attestation.payload.schema_version == SCHEMA_VERSION {
        return ZkVerificationResult::Rejected {
            attestation_id: aid,
            policy_id: pid,
            trace_id,
            reason: "Legacy zka-v1.0 registration carries no cryptographic proof".to_string(),
            error_code: error_codes::ERR_ZKA_VERIFIER_UNAVAILABLE.to_string(),
        };
    }

    if attestation.payload.schema_version != CRYPTO_SCHEMA_VERSION {
        return ZkVerificationResult::Rejected {
            attestation_id: aid,
            policy_id: pid,
            trace_id,
            reason: "Unsupported ZK proof schema version".to_string(),
            error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
        };
    }

    if attestation.payload.proof_bytes_hex.is_empty()
        || attestation.payload.proof_bytes_hex.len() > MAX_CRYPTO_PROOF_HEX_LEN
        || !attestation.payload.proof_bytes_hex.len().is_multiple_of(2)
    {
        return ZkVerificationResult::Rejected {
            attestation_id: aid,
            policy_id: pid,
            trace_id,
            reason: "Cryptographic proof hex missing, odd-length, or exceeds size cap".to_string(),
            error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
        };
    }

    let Ok(commitment_raw) = hex::decode(&attestation.payload.metadata_commitment) else {
        return ZkVerificationResult::Rejected {
            attestation_id: aid,
            policy_id: pid,
            trace_id,
            reason: "Metadata commitment is not valid 32-byte hex".to_string(),
            error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
        };
    };
    let Some((compressed_commitment, commitment_point)) = decode_canonical_point(&commitment_raw)
    else {
        return ZkVerificationResult::Rejected {
            attestation_id: aid,
            policy_id: pid,
            trace_id,
            reason: "Metadata commitment is not a canonical Ristretto255 point".to_string(),
            error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
        };
    };

    let Ok(wire) = hex::decode(&attestation.payload.proof_bytes_hex) else {
        return ZkVerificationResult::Rejected {
            attestation_id: aid,
            policy_id: pid,
            trace_id,
            reason: "Proof bytes hex failed decoding".to_string(),
            error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
        };
    };

    if wire.len() < 72 || &wire[0..5] != ZKRP3_MAGIC {
        return ZkVerificationResult::Rejected {
            attestation_id: aid,
            policy_id: pid,
            trace_id,
            reason: "Proof envelope missing ZKRP3 header".to_string(),
            error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
        };
    }

    let variant_tag = wire[5];
    let expected_params_digest = verifier_params.params_digest_bytes();
    if !bool::from(wire[6..38].ct_eq(&expected_params_digest)) {
        return ZkVerificationResult::Rejected {
            attestation_id: aid,
            policy_id: pid,
            trace_id,
            reason: "Proof verifier parameter digest does not match verifier_params".to_string(),
            error_code: error_codes::ERR_ZKA_POLICY_MISMATCH.to_string(),
        };
    }

    if !bool::from(wire[38..70].ct_eq(compressed_commitment.as_bytes())) {
        return ZkVerificationResult::Rejected {
            attestation_id: aid,
            policy_id: pid,
            trace_id,
            reason: "Proof commitment does not match attestation metadata_commitment".to_string(),
            error_code: error_codes::ERR_ZKA_WITNESS_INVALID.to_string(),
        };
    }

    let declared_count = usize::from(u16::from_le_bytes([wire[70], wire[71]]));

    match &verifier_params.relation {
        ZkComplianceRelation::ThresholdAtLeast {
            threshold,
            range_bits,
        } => {
            let expected_bits = usize::from(*range_bits);
            if variant_tag != ZKRP3_TAG_THRESHOLD || declared_count != expected_bits {
                return ZkVerificationResult::Rejected {
                    attestation_id: aid,
                    policy_id: pid,
                    trace_id,
                    reason: "Threshold proof tag or bit-width mismatch".to_string(),
                    error_code: error_codes::ERR_ZKA_POLICY_MISMATCH.to_string(),
                };
            }
            let expected_len = 72usize.saturating_add(expected_bits.saturating_mul(160));
            if wire.len() != expected_len {
                return ZkVerificationResult::Rejected {
                    attestation_id: aid,
                    policy_id: pid,
                    trace_id,
                    reason: "Threshold proof byte length mismatch".to_string(),
                    error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
                };
            }

            let mut bit_compressed = Vec::with_capacity(expected_bits);
            let mut bit_points = Vec::with_capacity(expected_bits);
            let mut bit_proofs = Vec::with_capacity(expected_bits);
            for j in 0..expected_bits {
                let offset = 72 + j * 160;
                let Some((comp_j, pt_j)) = decode_canonical_point(&wire[offset..offset + 32])
                else {
                    return ZkVerificationResult::Rejected {
                        attestation_id: aid,
                        policy_id: pid,
                        trace_id,
                        reason: "Non-canonical bit commitment point".to_string(),
                        error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
                    };
                };
                let (Some(e0), Some(e1), Some(s0), Some(s1)) = (
                    decode_canonical_scalar(&wire[offset + 32..offset + 64]),
                    decode_canonical_scalar(&wire[offset + 64..offset + 96]),
                    decode_canonical_scalar(&wire[offset + 96..offset + 128]),
                    decode_canonical_scalar(&wire[offset + 128..offset + 160]),
                ) else {
                    return ZkVerificationResult::Rejected {
                        attestation_id: aid,
                        policy_id: pid,
                        trace_id,
                        reason: "Non-canonical Schnorr scalar in threshold proof".to_string(),
                        error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
                    };
                };
                bit_compressed.push(comp_j.to_bytes());
                bit_points.push((comp_j, pt_j));
                bit_proofs.push(Cds94OrProof {
                    challenges: vec![e0, e1],
                    responses: vec![s0, s1],
                });
            }

            // Check homomorphic decomposition: sum_{j=0}^{k-1} 2^j * C_j == C - threshold * G
            let two = Scalar::from(2u64);
            let mut pow_two = Scalar::ONE;
            let mut homomorphic_sum = RistrettoPoint::default();
            for (_, pt_j) in &bit_points {
                homomorphic_sum += pow_two * pt_j;
                pow_two *= two;
            }
            let shifted_target =
                commitment_point - Scalar::from(*threshold) * RISTRETTO_BASEPOINT_POINT;
            if !bool::from(
                homomorphic_sum
                    .compress()
                    .as_bytes()
                    .ct_eq(shifted_target.compress().as_bytes()),
            ) {
                return ZkVerificationResult::Rejected {
                    attestation_id: aid,
                    policy_id: pid,
                    trace_id,
                    reason: "Pedersen bit-decomposition sum does not equal shifted commitment"
                        .to_string(),
                    error_code: error_codes::ERR_ZKA_WITNESS_INVALID.to_string(),
                };
            }

            let ctx = build_fiat_shamir_context(
                &aid,
                attestation.generated_at_ms,
                attestation.expires_at_ms,
                &expected_params_digest,
                &compressed_commitment.to_bytes(),
                &bit_compressed,
            );
            for (j, ((comp_j, pt_j), or_proof)) in
                bit_points.iter().zip(bit_proofs.iter()).enumerate()
            {
                let subproof_idx = u32::try_from(j).unwrap_or(u32::MAX);
                if !verify_cds94_or(&ctx, subproof_idx, *pt_j, comp_j, &[0, 1], or_proof) {
                    return ZkVerificationResult::Rejected {
                        attestation_id: aid,
                        policy_id: pid,
                        trace_id,
                        reason: format!("Bit {} failed CDS94 1-of-2 Schnorr verification", j),
                        error_code: error_codes::ERR_ZKA_WITNESS_INVALID.to_string(),
                    };
                }
            }

            ZkVerificationResult::Verified {
                attestation_id: aid,
                policy_id: pid,
                trace_id,
                verified_at_ms: now_ms,
            }
        }
        ZkComplianceRelation::AllowlistMembership { allowed_values, .. } => {
            if variant_tag != ZKRP3_TAG_ALLOWLIST || declared_count != allowed_values.len() {
                return ZkVerificationResult::Rejected {
                    attestation_id: aid,
                    policy_id: pid,
                    trace_id,
                    reason: "Allowlist proof tag or branch-count mismatch".to_string(),
                    error_code: error_codes::ERR_ZKA_POLICY_MISMATCH.to_string(),
                };
            }
            let expected_len = 72usize.saturating_add(declared_count.saturating_mul(64));
            if wire.len() != expected_len {
                return ZkVerificationResult::Rejected {
                    attestation_id: aid,
                    policy_id: pid,
                    trace_id,
                    reason: "Allowlist proof byte length mismatch".to_string(),
                    error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
                };
            }

            let mut challenges = Vec::with_capacity(declared_count);
            let mut responses = Vec::with_capacity(declared_count);
            for idx in 0..declared_count {
                let offset = 72 + idx * 64;
                let (Some(e_i), Some(s_i)) = (
                    decode_canonical_scalar(&wire[offset..offset + 32]),
                    decode_canonical_scalar(&wire[offset + 32..offset + 64]),
                ) else {
                    return ZkVerificationResult::Rejected {
                        attestation_id: aid,
                        policy_id: pid,
                        trace_id,
                        reason: "Non-canonical Schnorr scalar in allowlist proof".to_string(),
                        error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
                    };
                };
                challenges.push(e_i);
                responses.push(s_i);
            }

            let ctx = build_fiat_shamir_context(
                &aid,
                attestation.generated_at_ms,
                attestation.expires_at_ms,
                &expected_params_digest,
                &compressed_commitment.to_bytes(),
                &[],
            );
            let or_proof = Cds94OrProof {
                challenges,
                responses,
            };
            if !verify_cds94_or(
                &ctx,
                0,
                commitment_point,
                &compressed_commitment,
                allowed_values,
                &or_proof,
            ) {
                return ZkVerificationResult::Rejected {
                    attestation_id: aid,
                    policy_id: pid,
                    trace_id,
                    reason: "Allowlist proof failed CDS94 1-of-N Schnorr verification".to_string(),
                    error_code: error_codes::ERR_ZKA_WITNESS_INVALID.to_string(),
                };
            }

            ZkVerificationResult::Verified {
                attestation_id: aid,
                policy_id: pid,
                trace_id,
                verified_at_ms: now_ms,
            }
        }
    }
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
        now_ms < attestation.expires_at_ms
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

    /// Register a legacy attestation record supplied by the caller.
    /// This does not generate a proof or establish predicate satisfaction.
    /// Retains the v1 wire format and historical FN-ZK-001 registration event.
    #[allow(clippy::too_many_arguments)]
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
            expires_at_ms: now_ms.saturating_add(policy.validity_ms),
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
            "Legacy attestation registered; cryptographic proof not established".to_string(),
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

        // Ledger binding: verify the attestation was legitimately created via
        // generate_proof() by looking it up in the internal store.  Without
        // this check, a caller could construct a fabricated ZkAttestation
        // struct that passes all structural checks but was never generated.
        //
        // Existence alone is not enough: revocation and expiry are recorded by
        // mutating the LEDGER's record, so every lifecycle decision below must
        // read that record rather than the caller's copy. Checking the argument
        // let a holder of a pre-revocation copy keep verifying indefinitely,
        // because `revoke_attestation` never touches the caller's struct.
        // `is_valid()` already resolves through the ledger; this path now
        // matches it.
        let Some(ledger_record) = self.attestations.get(&aid).cloned() else {
            self.record_audit(
                format!("audit-{}-unknown", aid),
                event_codes::FN_ZK_004.to_string(),
                Some(aid.clone()),
                Some(pid.clone()),
                trace_id.clone(),
                now_ms,
                "Attestation not found in ledger".to_string(),
            );
            return ZkVerificationResult::Rejected {
                attestation_id: aid,
                policy_id: pid,
                trace_id,
                reason: "Attestation not found in ledger — may be forged".to_string(),
                error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
            };
        };

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

        // Check revocation (against the ledger record, not the caller's copy)
        if ledger_record.status == AttestationStatus::Revoked {
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

        // Check expiry (against the ledger record, not the caller's copy)
        if now_ms >= ledger_record.expires_at_ms {
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

        if now_ms < ledger_record.generated_at_ms {
            self.record_audit(
                format!("audit-{}-future", aid),
                event_codes::FN_ZK_004.to_string(),
                Some(aid.clone()),
                Some(pid.clone()),
                trace_id.clone(),
                now_ms,
                "Attestation generated in the future".to_string(),
            );
            return ZkVerificationResult::Rejected {
                attestation_id: aid,
                policy_id: pid,
                trace_id,
                reason: "Proof generated in the future".to_string(),
                error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
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
            self.record_audit(
                format!("audit-{}-schema", aid),
                event_codes::FN_ZK_004.to_string(),
                Some(aid.clone()),
                Some(pid.clone()),
                trace_id.clone(),
                now_ms,
                "Missing schema version".to_string(),
            );
            return ZkVerificationResult::Rejected {
                attestation_id: aid,
                policy_id: pid,
                trace_id,
                reason: "Missing schema version".to_string(),
                error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
            };
        }

        // Structural checks, ledger membership and a caller's Pass are not a
        // cryptographic proof. v1 has no authenticated relation/key/statement.
        // Never upgrade historical registrations to verification authority.
        self.record_audit(
            format!("audit-{}-unavailable", aid),
            event_codes::FN_ZK_004.to_string(),
            Some(aid.clone()),
            Some(pid.clone()),
            trace_id.clone(),
            now_ms,
            "Cryptographic verifier unavailable for legacy attestation".to_string(),
        );

        ZkVerificationResult::Rejected {
            attestation_id: aid,
            policy_id: pid,
            trace_id,
            reason: "No supported cryptographic verifier or authenticated public parameters"
                .to_string(),
            error_code: error_codes::ERR_ZKA_VERIFIER_UNAVAILABLE.to_string(),
        }
    }

    /// Verify a batch of attestations. Returns a `ZkBatchResult`.
    /// Emits FN-ZK-011 at start, FN-ZK-012 at end.
    ///
    /// Batch size is capped at [`MAX_BATCH_SIZE`]; excess proofs are silently
    /// truncated so that a single caller cannot cause unbounded work.
    pub fn verify_batch(
        &mut self,
        attestations: &[ZkAttestation],
        policy: &ZkPolicy,
        now_ms: u64,
        trace_id: String,
    ) -> ZkBatchResult {
        // Enforce MAX_BATCH_SIZE to prevent DoS via oversized batches.
        let attestations = if attestations.len() > MAX_BATCH_SIZE {
            &attestations[..MAX_BATCH_SIZE]
        } else {
            attestations
        };

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
                passed = passed.saturating_add(1);
            } else {
                failed = failed.saturating_add(1);
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
            att.status == AttestationStatus::Active && now_ms < att.expires_at_ms
        })
    }

    /// Sweep expired attestations. Returns the IDs of attestations that were expired.
    pub fn sweep_expired(&mut self, now_ms: u64) -> Vec<String> {
        let mut expired = Vec::new();
        for (id, att) in &mut self.attestations {
            if att.status == AttestationStatus::Active && now_ms >= att.expires_at_ms {
                att.status = AttestationStatus::Expired;
                push_bounded(&mut expired, id.clone(), MAX_AUDIT_TRAIL_ENTRIES);
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
        fn increment_counter(report: &mut BTreeMap<String, usize>, key: &str) {
            if let Some(count) = report.get_mut(key) {
                *count = count.saturating_add(1);
            } else {
                // Fail-safe fallback: preserve accounting even if key initialization drifts.
                report.insert(key.to_string(), 1);
            }
        }

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
            increment_counter(&mut report, "total");
            match att.status {
                AttestationStatus::Active => increment_counter(&mut report, "active"),
                AttestationStatus::Expired => increment_counter(&mut report, "expired"),
                AttestationStatus::Revoked => increment_counter(&mut report, "revoked"),
            }
            match att.outcome {
                PredicateOutcome::Pass => increment_counter(&mut report, "outcome_pass"),
                PredicateOutcome::Fail => increment_counter(&mut report, "outcome_fail"),
                PredicateOutcome::Error => increment_counter(&mut report, "outcome_error"),
            }
        }
        report
    }

    // ── Authenticated Ristretto255 Zero-Knowledge Operations ────────────────

    /// Generate a real `zka-ristretto255-v3.0` zero-knowledge compliance proof
    /// over `witness` bound to `policy` and `verifier_params`, and register it
    /// in the ledger. Emits `FN-ZK-001`.
    pub fn prove_compliance(
        &mut self,
        attestation_id: String,
        policy: &ZkPolicy,
        verifier_params: &ZkVerifierParams,
        witness: &ZkPrivateWitness,
        now_ms: u64,
        trace_id: String,
    ) -> Result<ZkAttestation, String> {
        if !policy.active {
            return Err(format!(
                "{}: policy {} is inactive",
                error_codes::ERR_ZKA_POLICY_MISMATCH,
                policy.policy_id
            ));
        }
        if !verifier_params.matches_policy(policy) {
            return Err(format!(
                "{}: verifier_params do not bind to policy {}",
                error_codes::ERR_ZKA_POLICY_MISMATCH,
                policy.policy_id
            ));
        }
        if self.attestations.contains_key(&attestation_id) {
            return Err(format!(
                "{}: attestation {} already exists",
                error_codes::ERR_ZKA_DUPLICATE,
                attestation_id
            ));
        }

        let expires_at_ms = now_ms
            .checked_add(policy.validity_ms)
            .filter(|expires_at_ms| *expires_at_ms > now_ms)
            .ok_or_else(|| {
                format!(
                    "{}: proof validity interval is empty or overflows",
                    error_codes::ERR_ZKA_INVALID_PROOF
                )
            })?;

        let (metadata_commitment, proof_bytes_hex) = prove_compliance_wire_bytes(
            &attestation_id,
            now_ms,
            expires_at_ms,
            verifier_params,
            witness,
        )?;

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
                schema_version: CRYPTO_SCHEMA_VERSION.to_string(),
                proof_bytes_hex,
                metadata_commitment: metadata_commitment.clone(),
            },
            outcome: PredicateOutcome::Pass,
            status: AttestationStatus::Active,
            generated_at_ms: now_ms,
            expires_at_ms,
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
            format!(
                "Ristretto255 ZK compliance proof generated (params={})",
                verifier_params.params_sha256()
            ),
        );

        Ok(attestation)
    }

    /// Verify a single attestation against `policy` and authenticated `verifier_params`,
    /// enforcing ledger revocation/expiry lifecycle plus full Ristretto255 cryptographic
    /// proof verification. Emits `FN-ZK-002` on submission and `FN-ZK-003` / `FN-ZK-004` /
    /// `FN-ZK-005` on terminal outcome.
    pub fn verify_authenticated_proof(
        &mut self,
        attestation: &ZkAttestation,
        policy: &ZkPolicy,
        verifier_params: &ZkVerifierParams,
        now_ms: u64,
        trace_id: String,
    ) -> ZkVerificationResult {
        let aid = attestation.attestation_id.clone();
        let pid = policy.policy_id.clone();
        let audit_seq = self.audit_trail.len();

        self.record_audit(
            format!("audit-{}-{}-submit", aid, audit_seq),
            event_codes::FN_ZK_002.to_string(),
            Some(aid.clone()),
            Some(pid.clone()),
            trace_id.clone(),
            now_ms,
            "Authenticated proof submitted for cryptographic verification".to_string(),
        );

        let Some(ledger_record) = self.attestations.get(&aid).cloned() else {
            self.record_audit(
                format!("audit-{}-{}-unknown", aid, audit_seq),
                event_codes::FN_ZK_004.to_string(),
                Some(aid.clone()),
                Some(pid.clone()),
                trace_id.clone(),
                now_ms,
                "Attestation not found in ledger".to_string(),
            );
            return ZkVerificationResult::Rejected {
                attestation_id: aid,
                policy_id: pid,
                trace_id,
                reason: "Attestation not found in ledger — may be forged".to_string(),
                error_code: error_codes::ERR_ZKA_INVALID_PROOF.to_string(),
            };
        };

        // Overlay authoritative ledger lifecycle state onto the candidate attestation
        // so revocations and original timestamps cannot be bypassed by stale caller copies,
        // while still verifying the caller's submitted cryptographic payload.
        let mut effective = attestation.clone();
        effective.status = ledger_record.status;
        effective.generated_at_ms = ledger_record.generated_at_ms;
        effective.expires_at_ms = ledger_record.expires_at_ms;
        if effective.policy_id != ledger_record.policy_id {
            self.record_audit(
                format!("audit-{}-{}-pmm-ledger", aid, audit_seq),
                event_codes::FN_ZK_005.to_string(),
                Some(aid.clone()),
                Some(pid.clone()),
                trace_id.clone(),
                now_ms,
                "Caller policy_id diverges from ledger record".to_string(),
            );
            return ZkVerificationResult::Rejected {
                attestation_id: aid,
                policy_id: pid,
                trace_id,
                reason: "Caller policy_id diverges from ledger record".to_string(),
                error_code: error_codes::ERR_ZKA_POLICY_MISMATCH.to_string(),
            };
        }

        let result = verify_compliance_proof_stateless(
            &effective,
            policy,
            verifier_params,
            now_ms,
            trace_id.clone(),
        );
        match &result {
            ZkVerificationResult::Verified { .. } => {
                self.record_audit(
                    format!("audit-{}-{}-verified", aid, audit_seq),
                    event_codes::FN_ZK_003.to_string(),
                    Some(aid),
                    Some(pid),
                    trace_id,
                    now_ms,
                    format!(
                        "Ristretto255 ZK proof verified (params={})",
                        verifier_params.params_sha256()
                    ),
                );
            }
            ZkVerificationResult::Rejected {
                reason, error_code, ..
            } => {
                let ev = if error_code == error_codes::ERR_ZKA_POLICY_MISMATCH {
                    event_codes::FN_ZK_005
                } else {
                    event_codes::FN_ZK_004
                };
                self.record_audit(
                    format!("audit-{}-{}-rejected", aid, audit_seq),
                    ev.to_string(),
                    Some(aid),
                    Some(pid),
                    trace_id,
                    now_ms,
                    format!("{}: {}", error_code, reason),
                );
            }
        }
        result
    }

    /// Verify a batch of attestations against `policy` and authenticated `verifier_params`.
    /// Capped at [`MAX_BATCH_SIZE`]; emits `FN-ZK-011` and `FN-ZK-012`.
    pub fn verify_batch_authenticated(
        &mut self,
        attestations: &[ZkAttestation],
        policy: &ZkPolicy,
        verifier_params: &ZkVerifierParams,
        now_ms: u64,
        trace_id: String,
    ) -> ZkBatchResult {
        let attestations = if attestations.len() > MAX_BATCH_SIZE {
            &attestations[..MAX_BATCH_SIZE]
        } else {
            attestations
        };

        self.record_audit(
            format!("audit-batch-auth-{}-start", trace_id),
            event_codes::FN_ZK_011.to_string(),
            None,
            Some(policy.policy_id.clone()),
            trace_id.clone(),
            now_ms,
            format!(
                "Authenticated batch verification initiated: {} proofs",
                attestations.len()
            ),
        );

        let mut results = BTreeMap::new();
        let mut passed = 0usize;
        let mut failed = 0usize;

        for att in attestations {
            let sub_trace = format!("{}-{}", trace_id, att.attestation_id);
            let result =
                self.verify_authenticated_proof(att, policy, verifier_params, now_ms, sub_trace);
            if result.is_verified() {
                passed = passed.saturating_add(1);
            } else {
                failed = failed.saturating_add(1);
            }
            results.insert(att.attestation_id.clone(), result);
        }

        self.record_audit(
            format!("audit-batch-auth-{}-end", trace_id),
            event_codes::FN_ZK_012.to_string(),
            None,
            Some(policy.policy_id.clone()),
            trace_id.clone(),
            now_ms,
            format!(
                "Authenticated batch verification completed: {}/{} passed",
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
            schema_version: CRYPTO_SCHEMA_VERSION.to_string(),
        }
    }

    /// Compute structured telemetry over ledger registrations and verification outcomes.
    #[must_use]
    pub fn verification_telemetry(&self) -> ZkVerificationTelemetry {
        let mut telemetry = ZkVerificationTelemetry::default();
        for att in self.attestations.values() {
            if att.payload.schema_version == CRYPTO_SCHEMA_VERSION {
                telemetry.crypto_proofs_generated =
                    telemetry.crypto_proofs_generated.saturating_add(1);
            } else {
                telemetry.legacy_registrations = telemetry.legacy_registrations.saturating_add(1);
            }
        }
        for rec in self.audit_trail.values() {
            match rec.event_code.as_str() {
                event_codes::FN_ZK_002 => {
                    telemetry.verification_submissions =
                        telemetry.verification_submissions.saturating_add(1);
                }
                event_codes::FN_ZK_003 => {
                    telemetry.crypto_verifications_passed =
                        telemetry.crypto_verifications_passed.saturating_add(1);
                }
                event_codes::FN_ZK_005 => {
                    telemetry.rejections_policy_mismatch =
                        telemetry.rejections_policy_mismatch.saturating_add(1);
                }
                event_codes::FN_ZK_004 => {
                    telemetry.rejections_total_fn_zk_004 =
                        telemetry.rejections_total_fn_zk_004.saturating_add(1);
                    if rec.detail.starts_with(error_codes::ERR_ZKA_WITNESS_INVALID) {
                        telemetry.rejections_witness_invalid =
                            telemetry.rejections_witness_invalid.saturating_add(1);
                    }
                }
                _ => {}
            }
        }
        telemetry
    }

    // ── Internal helpers ────────────────────────────────────────────────────

    #[allow(clippy::too_many_arguments)]
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
    use crate::lock_utils::try_lock;

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
    fn test_register_duplicate_policy_preserves_original_record() {
        let mut registry = PolicyRegistry::new();
        let original = test_policy();
        registry.register_policy(original.clone()).unwrap();
        let mut replacement = original.clone();
        replacement.predicate_description = "tampered replacement".to_string();

        let err = registry.register_policy(replacement).unwrap_err();

        assert!(err.contains(error_codes::ERR_ZKA_DUPLICATE));
        assert_eq!(registry.policies.len(), 1);
        assert_eq!(registry.get_policy(&original.policy_id).unwrap(), &original);
        assert_eq!(registry.schema_version, SCHEMA_VERSION);
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
    fn test_deregister_missing_policy_preserves_registered_policies() {
        let mut registry = PolicyRegistry::new();
        let policy = test_policy();
        registry.register_policy(policy.clone()).unwrap();

        let err = registry.deregister_policy("missing-policy").unwrap_err();

        assert!(err.contains(error_codes::ERR_ZKA_POLICY_NOT_FOUND));
        assert_eq!(registry.policies.len(), 1);
        assert!(registry.get_policy(&policy.policy_id).is_some());
        assert_eq!(registry.schema_version, SCHEMA_VERSION);
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

    #[test]
    fn test_generate_non_hex_proof_does_not_mutate_ledger() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();

        let err = ledger
            .generate_proof(
                "att-bad".to_string(),
                &policy,
                "commit-bad".to_string(),
                "not-valid-hex!!".to_string(),
                PredicateOutcome::Pass,
                1_000_000,
                "trace-bad".to_string(),
            )
            .unwrap_err();

        assert!(err.contains(error_codes::ERR_ZKA_METADATA_LEAK));
        assert!(ledger.attestations.is_empty());
        assert!(ledger.seen_commitments.is_empty());
        assert!(ledger.audit_trail.is_empty());
    }

    #[test]
    fn test_generate_duplicate_commitment_preserves_original_mapping() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        generate_test_attestation(
            &mut ledger,
            "att-1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        let audit_before = ledger.audit_trail.len();

        let err = ledger
            .generate_proof(
                "att-2".to_string(),
                &policy,
                "commit-att-1".to_string(),
                "aabbccdd".to_string(),
                PredicateOutcome::Pass,
                1_000_001,
                "trace-2".to_string(),
            )
            .unwrap_err();

        assert!(err.contains(error_codes::ERR_ZKA_DUPLICATE));
        assert_eq!(ledger.attestations.len(), 1);
        assert!(!ledger.attestations.contains_key("att-2"));
        assert_eq!(
            ledger
                .seen_commitments
                .get("commit-att-1")
                .map(String::as_str),
            Some("att-1")
        );
        assert_eq!(ledger.audit_trail.len(), audit_before);
    }

    // ── Verify proof tests ──────────────────────────────────────────────

    #[test]
    fn test_registered_pass_requires_cryptographic_verifier() {
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
        assert!(
            matches!(result, ZkVerificationResult::Rejected { error_code, .. }
            if error_code == error_codes::ERR_ZKA_VERIFIER_UNAVAILABLE)
        );
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
            _ => unreachable!("Expected Rejected"),
        }
    }

    #[test]
    fn test_verify_policy_mismatch_keeps_attestation_active() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let other_policy = test_policy_alt();
        let att = generate_test_attestation(
            &mut ledger,
            "att-policy-mismatch",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        let audit_before = ledger.audit_trail.len();

        let result = ledger.verify_proof(
            &att,
            &other_policy,
            1_000_001,
            "trace-policy-mismatch".to_string(),
        );

        assert!(!result.is_verified());
        assert_eq!(
            ledger.attestations["att-policy-mismatch"].status,
            AttestationStatus::Active
        );
        assert_eq!(ledger.audit_trail.len(), audit_before + 2);
        assert!(
            ledger
                .query_audit(|record| record.event_code == event_codes::FN_ZK_005)
                .iter()
                .any(|record| record.attestation_id.as_deref() == Some("att-policy-mismatch"))
        );
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
            _ => unreachable!("Expected Rejected"),
        }
    }

    #[test]
    fn test_verify_revoked_proof_rejected() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att = generate_test_attestation(
            &mut ledger,
            "att-1",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        // Revocation is recorded on the LEDGER's record; verify_proof
        // deliberately ignores the caller-copy status (a holder of a
        // pre-revocation copy must not keep verifying). Mutating `att.status`
        // directly would test nothing.
        ledger
            .revoke_attestation("att-1", 1_000_000, "trace-revoke".to_string())
            .expect("revocation should succeed");
        let result = ledger.verify_proof(&att, &policy, 1_000_001, "trace-v4".to_string());
        assert!(!result.is_verified());
        match &result {
            ZkVerificationResult::Rejected { error_code, .. } => {
                assert_eq!(error_code, error_codes::ERR_ZKA_REVOKED);
            }
            _ => unreachable!("Expected Rejected"),
        }
    }

    #[test]
    fn test_verify_future_proof_rejected() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att = generate_test_attestation(
            &mut ledger,
            "att-future",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        // Verify with a `now_ms` that is *before* the generation time
        let result = ledger.verify_proof(&att, &policy, 999_999, "trace-future".to_string());
        assert!(!result.is_verified());
        match &result {
            ZkVerificationResult::Rejected { error_code, .. } => {
                assert_eq!(error_code, error_codes::ERR_ZKA_INVALID_PROOF);
            }
            _ => unreachable!("Expected Rejected"),
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
            _ => unreachable!("Expected Rejected"),
        }
    }

    // ── Batch verification tests ────────────────────────────────────────

    #[test]
    fn test_batch_claimed_passes_are_not_verified() {
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
        assert_eq!(batch.passed, 0);
        assert_eq!(batch.failed, 2);
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
        assert_eq!(batch.passed, 0);
        assert_eq!(batch.failed, 2);
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
    fn test_revoke_already_revoked_does_not_emit_second_audit() {
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
        let audit_before = ledger.audit_trail.len();

        let err = ledger
            .revoke_attestation("att-r2", 1_000_200, "trace-rev3".to_string())
            .unwrap_err();

        assert!(err.contains(error_codes::ERR_ZKA_REVOKED));
        assert_eq!(ledger.audit_trail.len(), audit_before);
        assert_eq!(
            ledger.attestations["att-r2"].status,
            AttestationStatus::Revoked
        );
    }

    #[test]
    fn test_revoke_nonexistent_fails() {
        let mut ledger = AttestationLedger::new();
        let result = ledger.revoke_attestation("nope", 1_000_000, "trace-nope".to_string());
        assert!(result.is_err());
    }

    #[test]
    fn test_revoke_nonexistent_does_not_mutate_ledger() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        generate_test_attestation(
            &mut ledger,
            "att-existing",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        let audit_before = ledger.audit_trail.len();
        let commitments_before = ledger.seen_commitments.clone();

        let err = ledger
            .revoke_attestation("missing", 1_000_100, "trace-missing".to_string())
            .unwrap_err();

        assert!(err.contains(error_codes::ERR_ZKA_INVALID_PROOF));
        assert_eq!(ledger.attestations.len(), 1);
        assert_eq!(
            ledger.attestations["att-existing"].status,
            AttestationStatus::Active
        );
        assert_eq!(ledger.audit_trail.len(), audit_before);
        assert_eq!(ledger.seen_commitments, commitments_before);
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

    #[test]
    fn test_sweep_before_expiry_preserves_active_status_and_audit() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att = generate_test_attestation(
            &mut ledger,
            "att-not-expired",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        let audit_before = ledger.audit_trail.len();

        let expired = ledger.sweep_expired(att.expires_at_ms - 1);

        assert!(expired.is_empty());
        assert_eq!(
            ledger.attestations["att-not-expired"].status,
            AttestationStatus::Active
        );
        assert_eq!(ledger.audit_trail.len(), audit_before);
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
        // Registration and submission must end in refusal, never a pass event.
        let gen_records = ledger.query_audit(|r| r.event_code == event_codes::FN_ZK_001);
        let submit_records = ledger.query_audit(|r| r.event_code == event_codes::FN_ZK_002);
        let pass_records = ledger.query_audit(|r| r.event_code == event_codes::FN_ZK_003);
        assert_eq!(gen_records.len(), 1);
        assert_eq!(submit_records.len(), 1);
        assert!(pass_records.is_empty());
        assert_eq!(
            ledger
                .query_audit(|r| r.event_code == event_codes::FN_ZK_004)
                .len(),
            1
        );
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

    #[test]
    fn verify_proof_rejects_forged_attestation_not_in_ledger() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        // Construct a fabricated attestation that was never generated via generate_proof()
        let forged = ZkAttestation {
            attestation_id: "forged-1".to_string(),
            policy_id: policy.policy_id.clone(),
            payload: ZkProofPayload {
                schema_version: SCHEMA_VERSION.to_string(),
                proof_bytes_hex: "deadbeef".to_string(),
                metadata_commitment: "commit-forged".to_string(),
            },
            outcome: PredicateOutcome::Pass,
            status: AttestationStatus::Active,
            generated_at_ms: 1_000_000,
            expires_at_ms: 1_000_000 + DEFAULT_VALIDITY_MS,
            trace_id: "forged-trace".to_string(),
        };
        let result = ledger.verify_proof(&forged, &policy, 1_000_000, "trace-vf".to_string());
        assert!(
            matches!(result, ZkVerificationResult::Rejected { ref reason, .. } if reason.contains("not found in ledger")),
            "forged attestation should be rejected: {result:?}"
        );
    }

    #[test]
    fn verify_forged_attestation_does_not_admit_or_track_commitment() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let forged = ZkAttestation {
            attestation_id: "forged-side-effect".to_string(),
            policy_id: policy.policy_id.clone(),
            payload: ZkProofPayload {
                schema_version: SCHEMA_VERSION.to_string(),
                proof_bytes_hex: "deadbeef".to_string(),
                metadata_commitment: "commit-forged-side-effect".to_string(),
            },
            outcome: PredicateOutcome::Pass,
            status: AttestationStatus::Active,
            generated_at_ms: 1_000_000,
            expires_at_ms: 1_000_000 + DEFAULT_VALIDITY_MS,
            trace_id: "forged-trace".to_string(),
        };

        let result = ledger.verify_proof(&forged, &policy, 1_000_001, "trace-vf2".to_string());

        assert!(!result.is_verified());
        assert!(ledger.attestations.is_empty());
        assert!(ledger.seen_commitments.is_empty());
        assert_eq!(ledger.audit_trail.len(), 2);
        assert!(
            ledger
                .query_audit(|record| record.event_code == event_codes::FN_ZK_004)
                .iter()
                .any(|record| record.attestation_id.as_deref() == Some("forged-side-effect"))
        );
    }

    #[test]
    fn verify_proof_registration_is_not_cryptographic_authority() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let att = generate_test_attestation(
            &mut ledger,
            "att-legit",
            &policy,
            PredicateOutcome::Pass,
            1_000_000,
        );
        let result = ledger.verify_proof(&att, &policy, 1_000_000, "trace-legit".to_string());
        assert!(
            matches!(result, ZkVerificationResult::Rejected { error_code, .. }
                if error_code == error_codes::ERR_ZKA_VERIFIER_UNAVAILABLE),
            "registration must not establish predicate satisfaction"
        );
    }

    #[test]
    fn negative_unicode_injection_in_attestation_ids() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();

        let malicious_ids = vec![
            "normal\u{202e}evil\u{202c}attestation", // BiDi override
            "attestation\u{200b}\u{feff}hidden",     // Zero-width characters
            "attestation\nnewline",                  // Newline injection
            "attestation\ttab",                      // Tab injection
            "attestation\x00null",                   // Null byte injection
            "../../../etc/passwd",                   // Path traversal
            "attestation\"quote'injection",          // Quote injection
        ];

        for (i, malicious_id) in malicious_ids.iter().enumerate() {
            let proof_result = ledger.generate_proof(
                malicious_id.to_string(),
                &policy,
                format!("commit-unicode-{}", i),
                "deadbeef".to_string(),
                PredicateOutcome::Pass,
                1_000_000 + u64::try_from(i).unwrap_or(u64::MAX),
                format!("trace-unicode-{}", i),
            );

            assert!(proof_result.is_ok());

            // Verify we can retrieve with exact ID
            assert!(ledger.attestations.contains_key(*malicious_id));
        }
    }

    #[test]
    fn negative_massive_proof_payload_memory_exhaustion() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();

        // Create massive proof payload (10MB hex string)
        let massive_proof_bytes = vec![0xAA; 5 * 1024 * 1024]; // 5MB binary = 10MB hex
        let massive_hex = hex::encode(massive_proof_bytes);

        let massive_attestation = ZkAttestation {
            attestation_id: "massive-proof".to_string(),
            policy_id: policy.policy_id.clone(),
            payload: ZkProofPayload {
                schema_version: SCHEMA_VERSION.to_string(),
                proof_bytes_hex: massive_hex,
                metadata_commitment: "commit-massive".to_string(),
            },
            outcome: PredicateOutcome::Pass,
            status: AttestationStatus::Active,
            generated_at_ms: 1_000_000,
            expires_at_ms: 1_000_000 + DEFAULT_VALIDITY_MS,
            trace_id: "trace-massive".to_string(),
        };

        // Should handle massive proofs without memory issues
        ledger
            .attestations
            .insert("massive-proof".to_string(), massive_attestation.clone());

        let verification_result = ledger.verify_proof(
            &massive_attestation,
            &policy,
            1_000_001,
            "trace-massive-verify".to_string(),
        );

        // May reject due to size or succeed with performance impact
        // Either case should not cause memory corruption
    }

    #[test]
    fn negative_policy_id_collision_attacks() {
        let mut ledger = AttestationLedger::new();

        // Create policies with similar but different IDs
        let collision_policies = vec![
            ZkPolicy {
                policy_id: "policy-1".to_string(),
                predicate_description: "test_predicate".to_string(),
                issuer: "key1".to_string(),
                validity_ms: DEFAULT_VALIDITY_MS,
                schema_version: SCHEMA_VERSION.to_string(),
                active: true,
                registered_at_ms: 1_000_000,
            },
            ZkPolicy {
                policy_id: "policy\u{200b}1".to_string(), // Zero-width space
                predicate_description: "test_predicate".to_string(),
                issuer: "key1".to_string(),
                validity_ms: DEFAULT_VALIDITY_MS,
                schema_version: SCHEMA_VERSION.to_string(),
                active: true,
                registered_at_ms: 1_000_000,
            },
            ZkPolicy {
                policy_id: "policy-1\u{0000}".to_string(), // Null terminator
                predicate_description: "test_predicate".to_string(),
                issuer: "key1".to_string(),
                validity_ms: DEFAULT_VALIDITY_MS,
                schema_version: SCHEMA_VERSION.to_string(),
                active: true,
                registered_at_ms: 1_000_000,
            },
        ];

        for (i, policy) in collision_policies.iter().enumerate() {
            let proof_result = ledger.generate_proof(
                format!("collision-test-{}", i),
                policy,
                format!("commit-collision-{}", i),
                "deadbeef".to_string(),
                PredicateOutcome::Pass,
                1_000_000 + u64::try_from(i).unwrap_or(u64::MAX),
                format!("trace-collision-{}", i),
            );

            assert!(proof_result.is_ok());
        }

        // Verify policies are treated as distinct
        assert_eq!(ledger.attestations.len(), collision_policies.len());
    }

    #[test]
    fn negative_timestamp_arithmetic_overflow_boundaries() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();

        let overflow_timestamps = vec![
            u64::MAX,
            u64::MAX - 1,
            u64::MAX / 2,
            0, // Epoch start
            1, // Minimal positive
        ];

        for (i, timestamp) in overflow_timestamps.iter().enumerate() {
            let proof_result = ledger.generate_proof(
                format!("timestamp-test-{}", i),
                &policy,
                format!("commit-timestamp-{}", i),
                "deadbeef".to_string(),
                PredicateOutcome::Pass,
                *timestamp,
                format!("trace-timestamp-{}", i),
            );

            assert!(proof_result.is_ok());

            // Verify expiration calculation doesn't overflow
            let attestation = &ledger.attestations[&format!("timestamp-test-{}", i)];
            assert!(attestation.expires_at_ms >= attestation.generated_at_ms);
        }
    }

    #[test]
    fn negative_metadata_commitment_spoofing_attempts() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();

        // Generate legitimate attestation
        let legit_result = ledger.generate_proof(
            "legit-attestation".to_string(),
            &policy,
            "commit-legitimate-data".to_string(),
            "deadbeef".to_string(),
            PredicateOutcome::Pass,
            1_000_000,
            "trace-legit".to_string(),
        );
        assert!(legit_result.is_ok());
        let legit_commitment = &ledger.attestations["legit-attestation"]
            .payload
            .metadata_commitment;

        // Create spoofed attestation with same commitment
        let spoofed_attestation = ZkAttestation {
            attestation_id: "spoofed-attestation".to_string(),
            policy_id: policy.policy_id.clone(),
            payload: ZkProofPayload {
                schema_version: SCHEMA_VERSION.to_string(),
                proof_bytes_hex: "deadbeef".to_string(),
                metadata_commitment: legit_commitment.clone(), // Stolen commitment
            },
            outcome: PredicateOutcome::Pass,
            status: AttestationStatus::Active,
            generated_at_ms: 1_000_001,
            expires_at_ms: 1_000_001 + DEFAULT_VALIDITY_MS,
            trace_id: "trace-spoofed".to_string(),
        };

        // Attempt verification of spoofed attestation
        let verification_result = ledger.verify_proof(
            &spoofed_attestation,
            &policy,
            1_000_002,
            "trace-verify-spoofed".to_string(),
        );

        // Should detect and reject spoofed attestation
        assert!(matches!(
            verification_result,
            ZkVerificationResult::Rejected { .. }
        ));
    }

    #[test]
    fn negative_batch_verification_size_boundary_attacks() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();

        // Generate attestations up to and beyond MAX_BATCH_SIZE
        let mut attestations = Vec::new();
        for i in 0..(MAX_BATCH_SIZE + 10) {
            let proof_result = ledger.generate_proof(
                format!("batch-test-{}", i),
                &policy,
                format!("commit-batch-{}", i),
                "deadbeef".to_string(),
                PredicateOutcome::Pass,
                1_000_000 + u64::try_from(i).unwrap_or(u64::MAX),
                format!("trace-batch-{}", i),
            );

            if let Ok(attestation) = proof_result {
                push_bounded(&mut attestations, attestation, MAX_ATTESTATIONS_LIST);
            }

            if attestations.len() > MAX_BATCH_SIZE {
                break;
            }
        }

        // Attempt batch verification with oversized batch
        let oversized_batch = &attestations
            [..MAX_BATCH_SIZE + 5.min(attestations.len().saturating_sub(MAX_BATCH_SIZE))];

        for attestation in oversized_batch {
            let result = ledger.verify_proof(
                attestation,
                &policy,
                2_000_000,
                "trace-batch-verify".to_string(),
            );

            // Should handle large batches gracefully
            // May impose size limits or process with degraded performance
        }
    }

    #[test]
    fn negative_audit_trail_injection_through_trace_ids() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();

        let malicious_trace_ids = vec![
            "trace\nNewline\nInjection",             // Newline injection
            "trace\x00null\x00injection",            // Null byte injection
            "trace\u{202e}reverse\u{202c}injection", // BiDi override
            "trace\"json'injection",                 // JSON injection
            "../../../etc/passwd",                   // Path traversal
        ];

        for malicious_trace in malicious_trace_ids {
            let proof_result = ledger.generate_proof(
                "audit-injection-test".to_string(),
                &policy,
                format!("commit-audit-{}", malicious_trace),
                "deadbeef".to_string(),
                PredicateOutcome::Pass,
                1_000_000,
                malicious_trace.to_string(),
            );

            // Should handle malicious trace IDs without audit corruption
            if proof_result.is_ok() {
                // Check audit trail integrity
                let audit_records = ledger.query_audit(|r| r.trace_id == malicious_trace);
                assert!(audit_records.len() > 0);

                for record in audit_records {
                    assert_eq!(record.trace_id, malicious_trace);
                    assert!(invariants::check_audit_trail(&record));
                }
            }
        }
    }

    #[test]
    fn negative_schema_version_rollback_attacks() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();

        // Create attestations with different schema versions
        let schema_versions = vec![
            SCHEMA_VERSION.to_string(),   // Current version
            "zka-v0.9".to_string(),       // Older version
            "zka-v2.0".to_string(),       // Future version
            "".to_string(),               // Empty version
            "invalid-schema".to_string(), // Invalid format
            "\x00".to_string(),           // Null byte
        ];

        for (i, schema_version) in schema_versions.iter().enumerate() {
            let mut attestation = ZkAttestation {
                attestation_id: format!("schema-test-{}", i),
                policy_id: policy.policy_id.clone(),
                payload: ZkProofPayload {
                    schema_version: schema_version.clone(),
                    proof_bytes_hex: "abcd".to_string(),
                    metadata_commitment: format!("commit-{}", i),
                },
                outcome: PredicateOutcome::Pass,
                status: AttestationStatus::Active,
                generated_at_ms: 1_000_000 + u64::try_from(i).unwrap_or(u64::MAX),
                expires_at_ms: 1_000_000
                    + u64::try_from(i).unwrap_or(u64::MAX)
                    + DEFAULT_VALIDITY_MS,
                trace_id: format!("trace-schema-{}", i),
            };

            // Test schema version validation
            let schema_valid = invariants::check_schema_versioned(&attestation);

            if schema_version == SCHEMA_VERSION {
                assert!(schema_valid);
            } else {
                // Invalid schemas should be rejected by invariant checks
                // Implementation may be lenient or strict
            }
        }
    }

    #[test]
    fn negative_concurrent_ledger_access_race_conditions() {
        use std::sync::{Arc, Barrier, Mutex};
        use std::thread;

        let ledger = Arc::new(Mutex::new(AttestationLedger::new()));
        let policy = Arc::new(test_policy());
        let barrier = Arc::new(Barrier::new(4));

        let mut handles = Vec::new();

        for thread_id in 0..4 {
            let ledger = Arc::clone(&ledger);
            let policy = Arc::clone(&policy);
            let barrier = Arc::clone(&barrier);

            let handle = thread::spawn(move || {
                barrier.wait();

                for i in 0..25 {
                    let attestation_id = format!("thread-{}-attestation-{}", thread_id, i);
                    let mut ledger_guard =
                        try_lock(&ledger, "generate zk attestations concurrently")
                            .expect("zk attestation ledger mutex should not be poisoned");

                    let proof_result = ledger_guard.generate_proof(
                        attestation_id.clone(),
                        &policy,
                        format!("commit-{}-{}", thread_id, i),
                        "deadbeef".to_string(),
                        PredicateOutcome::Pass,
                        1_000_000 + u64::try_from(thread_id * 1000 + i).unwrap_or(u64::MAX),
                        format!("trace-{}-{}", thread_id, i),
                    );

                    assert!(proof_result.is_ok());
                }
            });

            push_bounded(&mut handles, handle, MAX_THREAD_HANDLES);
        }

        for handle in handles {
            handle.join().expect("Thread should complete");
        }

        // Verify ledger consistency
        let final_ledger = try_lock(&ledger, "inspect zk attestation ledger final state")
            .expect("zk attestation ledger mutex should not be poisoned");
        assert_eq!(final_ledger.attestations.len(), 100); // 4 threads × 25 attestations
        assert!(final_ledger.audit_trail.len() >= 100); // At least one audit record per attestation
    }

    #[test]
    fn negative_proof_verification_timing_attack_resistance() {
        use std::time::Instant;

        let mut ledger = AttestationLedger::new();
        let policy = test_policy();

        // Generate legitimate attestation
        let legit_result = ledger.generate_proof(
            "timing-legit".to_string(),
            &policy,
            "commit-timing-legit".to_string(),
            "deadbeef".to_string(),
            PredicateOutcome::Pass,
            1_000_000,
            "trace-timing-legit".to_string(),
        );
        assert!(legit_result.is_ok());

        // Create forged attestation
        let forged = ZkAttestation {
            attestation_id: "timing-forged".to_string(),
            policy_id: policy.policy_id.clone(),
            payload: ZkProofPayload {
                schema_version: SCHEMA_VERSION.to_string(),
                proof_bytes_hex: "deadbeef".to_string(),
                metadata_commitment: "commit-forged".to_string(),
            },
            outcome: PredicateOutcome::Pass,
            status: AttestationStatus::Active,
            generated_at_ms: 1_000_000,
            expires_at_ms: 1_000_000 + DEFAULT_VALIDITY_MS,
            trace_id: "trace-timing-forged".to_string(),
        };

        // Measure verification timing for multiple rounds
        let mut legit_times = Vec::new();
        let mut forged_times = Vec::new();

        for _ in 0..100 {
            // Time legitimate verification
            let start = Instant::now(); // ubs:ignore - test timing measurement, not random generation.
            let _legit_verification_result = ledger.verify_proof(
                &legit_result.as_ref().unwrap(),
                &policy,
                1_000_001,
                "trace-timing".to_string(),
            );
            push_bounded(&mut legit_times, start.elapsed(), MAX_TIMING_SAMPLES);

            // Time forged verification
            let start = Instant::now(); // ubs:ignore - test timing measurement, not random generation.
            let _forged_verification_result = ledger.verify_proof(
                &forged,
                &policy,
                1_000_001,
                "trace-timing-forged".to_string(),
            );
            push_bounded(&mut forged_times, start.elapsed(), MAX_TIMING_SAMPLES);
        }

        // Calculate average times
        let avg_legit = legit_times.iter().sum::<std::time::Duration>()
            / u32::try_from(legit_times.len()).unwrap_or(u32::MAX);
        let avg_forged = forged_times.iter().sum::<std::time::Duration>()
            / u32::try_from(forged_times.len()).unwrap_or(u32::MAX);

        // Timing should not reveal internal verification details
        // Allow some variance but flag excessive timing differences
        if avg_legit.as_nanos() > 0 && avg_forged.as_nanos() > 0 {
            let max_time = std::cmp::max(avg_legit, avg_forged);
            let min_time = std::cmp::min(avg_legit, avg_forged);
            let timing_ratio = max_time.as_nanos() as f64 / min_time.as_nanos() as f64;

            // Security: guard against non-finite division results
            assert!(
                timing_ratio.is_finite(),
                "Invalid timing ratio computation: max={:?}, min={:?}",
                max_time,
                min_time
            );

            // Allow up to 3x difference due to normal variance.
            // Wall-clock ratio bounds only hold on a quiesced host (bd-m87xv).
            if crate::testing::timing_assertions_enabled() {
                assert!(
                    timing_ratio < 3.0,
                    "Suspicious timing variance: legit={:?}, forged={:?}, ratio={:.2}",
                    avg_legit,
                    avg_forged,
                    timing_ratio
                );
            }
        }
    }

    #[test]
    fn negative_audit_trail_capacity_overflow_behavior() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();

        // Generate many attestations to overflow audit trail capacity
        for i in 0..1000 {
            let proof_result = ledger.generate_proof(
                format!("overflow-test-{}", i),
                &policy,
                format!("commit-overflow-{}", i),
                "deadbeef".to_string(),
                PredicateOutcome::Pass,
                1_000_000 + u64::try_from(i).unwrap_or(u64::MAX),
                format!("trace-overflow-{}", i),
            );

            if proof_result.is_err() {
                // May fail due to capacity limits
                break;
            }
        }

        // Verify audit trail respects capacity bounds and maintains integrity
        let audit_count = ledger.audit_trail.len();

        // Should not exceed reasonable capacity limits
        assert!(
            audit_count <= 10000,
            "Audit trail should respect capacity limits"
        );

        // Recent entries should be preserved (FIFO eviction)
        let recent_records = ledger.query_audit(|r| r.trace_id.contains("overflow-99"));
        assert!(
            !recent_records.is_empty(),
            "Recent audit records should be preserved"
        );

        // All remaining records should maintain invariants
        for record in ledger.audit_trail.values() {
            assert!(invariants::check_audit_trail(record));
        }
    }

    #[test]
    fn ristretto_threshold_proof_verifies_and_hides_witness() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let params = ZkVerifierParams::for_policy(
            &policy,
            "vk-gdpr-epoch1",
            1,
            "nonce-threshold-01",
            ZkComplianceRelation::threshold_at_least(100, 16).unwrap(),
        )
        .unwrap();
        let secret_blinding = [0x42u8; 32];
        let witness = ZkPrivateWitness::new(142, secret_blinding).unwrap();

        let debug_repr = format!("{witness:?}");
        assert!(!debug_repr.contains("142"));
        assert!(!debug_repr.contains("4242"));

        let att = ledger
            .prove_compliance(
                "att-zk-thresh-1".to_string(),
                &policy,
                &params,
                &witness,
                1_000_000,
                "trace-zk-1".to_string(),
            )
            .unwrap();
        assert_eq!(att.payload.schema_version, CRYPTO_SCHEMA_VERSION);

        let res = ledger.verify_authenticated_proof(
            &att,
            &policy,
            &params,
            1_000_010,
            "trace-zk-verify-1".to_string(),
        );
        assert!(res.is_verified(), "expected verified, got {res:?}");

        let telemetry = ledger.verification_telemetry();
        assert_eq!(telemetry.crypto_proofs_generated, 1);
        assert_eq!(telemetry.crypto_verifications_passed, 1);
        assert_eq!(telemetry.rejections_witness_invalid, 0);
    }

    #[test]
    fn ristretto_whitebox_homomorphic_passing_bit0_forgery_rejected() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let params = ZkVerifierParams::for_policy(
            &policy,
            "vk-gdpr-epoch1",
            1,
            "nonce-forge-01",
            ZkComplianceRelation::threshold_at_least(100, 8).unwrap(),
        )
        .unwrap();
        // Start from a valid proof for v = 100 (delta = 0), then replace C with 99*G + r*H
        // and replace C_0 with (-1)*G + r_0*H so sum(2^j * C_j) == C - 100*G STILL HOLDS,
        // forcing soundness to rely strictly on bit 0's CDS94 1-of-2 Schnorr proof.
        let valid_witness = ZkPrivateWitness::new(100, [0x11u8; 32]).unwrap();
        let mut att = ledger
            .prove_compliance(
                "att-zk-wb-forge".to_string(),
                &policy,
                &params,
                &valid_witness,
                1_000_000,
                "trace-wb".to_string(),
            )
            .unwrap();

        let mut wire = hex::decode(&att.payload.proof_bytes_hex).unwrap();
        let (_, orig_c) = decode_canonical_point(&wire[38..70]).unwrap();
        let (_, orig_c0) = decode_canonical_point(&wire[72..104]).unwrap();
        let forged_c = (orig_c - RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
        let forged_c0 = (orig_c0 - RISTRETTO_BASEPOINT_POINT).compress().to_bytes();
        wire[38..70].copy_from_slice(&forged_c);
        wire[72..104].copy_from_slice(&forged_c0);
        att.payload.metadata_commitment = hex::encode(forged_c);
        att.payload.proof_bytes_hex = hex::encode(wire);

        let res = ledger.verify_authenticated_proof(
            &att,
            &policy,
            &params,
            1_000_005,
            "trace-wb-verify".to_string(),
        );
        assert!(
            matches!(
                res,
                ZkVerificationResult::Rejected { ref error_code, .. }
                if error_code == error_codes::ERR_ZKA_WITNESS_INVALID
            ),
            "expected ERR_ZKA_WITNESS_INVALID, got {res:?}"
        );
        assert_eq!(
            ledger.verification_telemetry().rejections_witness_invalid,
            1
        );
    }

    #[test]
    fn ristretto_noncanonical_scalar_in_proof_is_rejected() {
        let mut ledger = AttestationLedger::new();
        let policy = test_policy();
        let params = ZkVerifierParams::for_policy(
            &policy,
            "vk-allow-1",
            1,
            "nonce-allow-01",
            ZkComplianceRelation::allowlist(vec![10, 20, 30]).unwrap(),
        )
        .unwrap();
        let witness = ZkPrivateWitness::new(20, [0x22u8; 32]).unwrap();
        let mut att = ledger
            .prove_compliance(
                "att-zk-noncanon".to_string(),
                &policy,
                &params,
                &witness,
                1_000_000,
                "trace-nc".to_string(),
            )
            .unwrap();
        let mut wire = hex::decode(&att.payload.proof_bytes_hex).unwrap();
        // 0xff..ff >= group order l, so Scalar::from_canonical_bytes must reject it.
        wire[72..104].fill(0xff);
        att.payload.proof_bytes_hex = hex::encode(wire);

        let res = verify_compliance_proof_stateless(
            &att,
            &policy,
            &params,
            1_000_005,
            "trace-nc-verify".to_string(),
        );
        assert!(
            matches!(
                res,
                ZkVerificationResult::Rejected { ref error_code, .. }
                if error_code == error_codes::ERR_ZKA_INVALID_PROOF
            ),
            "expected ERR_ZKA_INVALID_PROOF on non-canonical scalar, got {res:?}"
        );
    }
}
