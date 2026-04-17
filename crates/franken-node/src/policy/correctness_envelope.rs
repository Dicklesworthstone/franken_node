//! bd-sddz: Immutable correctness envelope for policy controllers.
//!
//! Defines the boundary between "tunable policy" and "immutable correctness"
//! via a formal enumeration of invariants that no policy controller is
//! permitted to modify.
//!
//! Log codes:
//! - `EVD-ENVELOPE-001`: envelope check passed
//! - `EVD-ENVELOPE-002`: envelope violation detected
//! - `EVD-ENVELOPE-003`: envelope loaded at startup

use serde::{Deserialize, Serialize};
use std::fmt;

// ── Invariant identity ──────────────────────────────────────────────

/// Stable identifier for a correctness invariant.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct InvariantId(pub String);

impl InvariantId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InvariantId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── Section ownership ───────────────────────────────────────────────

/// Section that owns an invariant (maps to 10.N tracks).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SectionId(pub String);

impl SectionId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SectionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── Enforcement mode ────────────────────────────────────────────────

/// How an invariant is enforced.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcementMode {
    /// Enforced at compile time (type system / const assertions).
    Compile,
    /// Enforced at runtime via checks and gates.
    Runtime,
    /// Enforced via conformance test suite.
    Conformance,
}

impl EnforcementMode {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Compile => "compile",
            Self::Runtime => "runtime",
            Self::Conformance => "conformance",
        }
    }

    pub fn from_label(s: &str) -> Option<Self> {
        match s {
            "compile" => Some(Self::Compile),
            "runtime" => Some(Self::Runtime),
            "conformance" => Some(Self::Conformance),
            _ => None,
        }
    }
}

// ── Invariant definition ────────────────────────────────────────────

/// A single immutable correctness invariant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Invariant {
    pub id: InvariantId,
    pub name: String,
    pub description: String,
    pub owner_track: SectionId,
    pub enforcement: EnforcementMode,
}

// ── Envelope violation ──────────────────────────────────────────────

/// Error returned when a policy proposal violates the correctness envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvelopeViolation {
    pub invariant_id: InvariantId,
    pub invariant_name: String,
    pub proposal_field: String,
    pub reason: String,
}

impl fmt::Display for EnvelopeViolation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "EVD-ENVELOPE-002: correctness envelope violation: invariant {} ({}) cannot be modified by policy proposal field '{}': {}",
            self.invariant_id, self.invariant_name, self.proposal_field, self.reason
        )
    }
}

impl std::error::Error for EnvelopeViolation {}

// ── Policy proposal ─────────────────────────────────────────────────

/// A proposed policy change from a controller.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyProposal {
    pub proposal_id: String,
    pub controller_id: String,
    pub epoch_id: u64,
    pub changes: Vec<PolicyChange>,
}

/// A single field-level change within a proposal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PolicyChange {
    pub field: String,
    pub old_value: serde_json::Value,
    pub new_value: serde_json::Value,
}

// ── The correctness envelope ────────────────────────────────────────

/// The correctness envelope: a boundary between tunable policy and
/// immutable correctness invariants.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorrectnessEnvelope {
    pub invariants: Vec<Invariant>,
    /// Fields that map to immutable invariants (field prefix -> invariant ID).
    immutable_fields: Vec<(String, InvariantId)>,
}

impl CorrectnessEnvelope {
    /// Build the canonical envelope with the initial invariant set.
    pub fn canonical() -> Self {
        let invariants = canonical_invariants();
        let immutable_fields = canonical_immutable_fields();
        Self {
            invariants,
            immutable_fields,
        }
    }

    /// Return the number of invariants in the envelope.
    pub fn len(&self) -> usize {
        self.invariants.len()
    }

    /// Return whether the envelope is empty.
    pub fn is_empty(&self) -> bool {
        self.invariants.is_empty()
    }

    /// Look up an invariant by ID.
    pub fn get(&self, id: &InvariantId) -> Option<&Invariant> {
        self.invariants.iter().find(|inv| inv.id == *id)
    }

    /// Check whether a proposed policy change falls within the envelope
    /// (i.e. does NOT touch any immutable invariant).
    ///
    /// Returns `Ok(())` if all changes are to tunable parameters.
    /// Returns `Err(EnvelopeViolation)` if any change targets an immutable field.
    pub fn is_within_envelope(&self, proposal: &PolicyProposal) -> Result<(), EnvelopeViolation> {
        for change in &proposal.changes {
            if let Some(violation) = self.check_field(&change.field) {
                eprintln!(
                    "EVD-ENVELOPE-002: envelope violation detected: invariant={}, field={}, epoch={}",
                    violation.invariant_id, change.field, proposal.epoch_id
                );
                return Err(violation);
            }
        }
        eprintln!(
            "EVD-ENVELOPE-001: envelope check passed: proposal={}, epoch={}",
            proposal.proposal_id, proposal.epoch_id
        );
        Ok(())
    }

    /// Check a single field against the immutable field map.
    fn check_field(&self, field: &str) -> Option<EnvelopeViolation> {
        for (prefix, inv_id) in &self.immutable_fields {
            if field == prefix.as_str() || field.starts_with(&format!("{prefix}.")) {
                let Some(inv) = self.get(inv_id) else {
                    return Some(EnvelopeViolation {
                        invariant_id: inv_id.clone(),
                        invariant_name: "missing invariant definition".to_string(),
                        proposal_field: field.to_string(),
                        reason: format!(
                            "field '{}' is governed by immutable invariant '{}' but the invariant definition is missing",
                            field,
                            inv_id.as_str()
                        ),
                    });
                };
                return Some(EnvelopeViolation {
                    invariant_id: inv_id.clone(),
                    invariant_name: inv.name.clone(),
                    proposal_field: field.to_string(),
                    reason: format!(
                        "field '{}' is governed by immutable invariant '{}' (enforcement: {})",
                        field,
                        inv.name,
                        inv.enforcement.label()
                    ),
                });
            }
        }
        None
    }

    /// Log that the envelope was loaded at startup.
    pub fn log_loaded(&self, epoch_id: u64) {
        eprintln!(
            "EVD-ENVELOPE-003: correctness envelope loaded: {} invariants, epoch={}",
            self.invariants.len(),
            epoch_id
        );
    }

    /// Export the envelope as a JSON manifest suitable for artifact storage.
    pub fn to_manifest_json(&self) -> serde_json::Value {
        serde_json::json!({
            "schema_version": "1.0",
            "envelope_version": "1.0",
            "invariant_count": self.invariants.len(),
            "invariants": self.invariants.iter().map(|inv| {
                serde_json::json!({
                    "id": inv.id.as_str(),
                    "name": &inv.name,
                    "description": &inv.description,
                    "owner_track": inv.owner_track.as_str(),
                    "enforcement": inv.enforcement.label(),
                })
            }).collect::<Vec<_>>(),
            "immutable_field_count": self.immutable_fields.len(),
            "immutable_fields": self.immutable_fields.iter().map(|(field, inv_id)| {
                serde_json::json!({
                    "field_prefix": field,
                    "invariant_id": inv_id.as_str(),
                })
            }).collect::<Vec<_>>(),
        })
    }
}

// ── Canonical invariant set ─────────────────────────────────────────

/// The initial set of immutable correctness invariants.
/// Covers Section 8.5 hard runtime invariants.
fn canonical_invariants() -> Vec<Invariant> {
    vec![
        Invariant {
            id: InvariantId::new("INV-001-MONOTONIC-HARDENING"),
            name: "Monotonic hardening direction".to_string(),
            description: "Security hardening level can only increase within an epoch; \
                reversal requires a governance artifact with quorum approval."
                .to_string(),
            owner_track: SectionId::new("10.14"),
            enforcement: EnforcementMode::Runtime,
        },
        Invariant {
            id: InvariantId::new("INV-002-EVIDENCE-EMISSION"),
            name: "Evidence emission mandatory".to_string(),
            description: "Every policy-driven control action must emit an EvidenceEntry \
                (per bd-nupr schema). Suppression is not a tunable parameter."
                .to_string(),
            owner_track: SectionId::new("10.14"),
            enforcement: EnforcementMode::Runtime,
        },
        Invariant {
            id: InvariantId::new("INV-003-DETERMINISTIC-SEED"),
            name: "Deterministic seed derivation algorithm".to_string(),
            description: "The content-derived seed algorithm (SHA-256 over canonical \
                representation) is fixed per version. Controllers cannot substitute \
                alternative hash functions or seed sources."
                .to_string(),
            owner_track: SectionId::new("10.14"),
            enforcement: EnforcementMode::Compile,
        },
        Invariant {
            id: InvariantId::new("INV-004-INTEGRITY-PROOF-VERIFICATION"),
            name: "Integrity proof verification cannot be bypassed".to_string(),
            description: "Marker stream hash-chain verification and integrity proof \
                checks run unconditionally. No controller flag can disable them."
                .to_string(),
            owner_track: SectionId::new("10.14"),
            enforcement: EnforcementMode::Runtime,
        },
        Invariant {
            id: InvariantId::new("INV-005-RING-BUFFER-FIFO"),
            name: "Ring buffer overflow policy is FIFO".to_string(),
            description: "When the evidence ledger ring buffer is full, the oldest \
                entry is evicted. The eviction order is not policy-tunable."
                .to_string(),
            owner_track: SectionId::new("10.14"),
            enforcement: EnforcementMode::Compile,
        },
        Invariant {
            id: InvariantId::new("INV-006-EPOCH-MONOTONIC"),
            name: "Epoch boundaries are monotonically increasing".to_string(),
            description: "Control epoch IDs must strictly increase. A controller \
                cannot set an epoch ID less than or equal to the current epoch."
                .to_string(),
            owner_track: SectionId::new("10.14"),
            enforcement: EnforcementMode::Runtime,
        },
        Invariant {
            id: InvariantId::new("INV-007-WITNESS-HASH-SHA256"),
            name: "Witness reference integrity hashes are SHA-256".to_string(),
            description: "All witness_ref digest fields use SHA-256. The hash \
                algorithm is not overridable by policy controllers."
                .to_string(),
            owner_track: SectionId::new("10.14"),
            enforcement: EnforcementMode::Compile,
        },
        Invariant {
            id: InvariantId::new("INV-008-GUARDRAIL-PRECEDENCE"),
            name: "Guardrail precedence over Bayesian recommendations".to_string(),
            description: "When a guardrail monitor fires, its decision overrides \
                any Bayesian posterior recommendation. Controllers cannot invert \
                this precedence."
                .to_string(),
            owner_track: SectionId::new("10.14"),
            enforcement: EnforcementMode::Runtime,
        },
        Invariant {
            id: InvariantId::new("INV-009-OBJECT-CLASS-APPEND-ONLY"),
            name: "Object class profiles are versioned and append-only".to_string(),
            description: "Object class profile definitions are append-only. \
                Existing profile versions cannot be mutated or deleted by policy \
                controllers; only new versions can be added."
                .to_string(),
            owner_track: SectionId::new("10.14"),
            enforcement: EnforcementMode::Runtime,
        },
        Invariant {
            id: InvariantId::new("INV-010-REMOTE-CAP-REQUIRED"),
            name: "Remote capability tokens required for network operations".to_string(),
            description: "All network-bound trust and control operations must \
                present a valid RemoteCap token. Controllers cannot grant implicit \
                network access."
                .to_string(),
            owner_track: SectionId::new("10.14"),
            enforcement: EnforcementMode::Runtime,
        },
        Invariant {
            id: InvariantId::new("INV-011-MARKER-CHAIN-APPEND-ONLY"),
            name: "Marker stream is append-only".to_string(),
            description: "The marker stream is strictly append-only with hash-chain \
                linking. No controller can rewrite, delete, or reorder existing \
                markers."
                .to_string(),
            owner_track: SectionId::new("10.14"),
            enforcement: EnforcementMode::Runtime,
        },
        Invariant {
            id: InvariantId::new("INV-012-RECEIPT-CHAIN-IMMUTABLE"),
            name: "Decision receipt chain is immutable".to_string(),
            description: "Signed decision receipts form a hash-chain that cannot \
                be truncated, modified, or forked by controllers."
                .to_string(),
            owner_track: SectionId::new("10.5"),
            enforcement: EnforcementMode::Runtime,
        },
    ]
}

/// Maps policy field prefixes to the invariant they are governed by.
fn canonical_immutable_fields() -> Vec<(String, InvariantId)> {
    vec![
        (
            "hardening.direction".to_string(),
            InvariantId::new("INV-001-MONOTONIC-HARDENING"),
        ),
        (
            "hardening.level_decrease".to_string(),
            InvariantId::new("INV-001-MONOTONIC-HARDENING"),
        ),
        (
            "evidence.emission_enabled".to_string(),
            InvariantId::new("INV-002-EVIDENCE-EMISSION"),
        ),
        (
            "evidence.suppress".to_string(),
            InvariantId::new("INV-002-EVIDENCE-EMISSION"),
        ),
        (
            "seed.algorithm".to_string(),
            InvariantId::new("INV-003-DETERMINISTIC-SEED"),
        ),
        (
            "seed.hash_function".to_string(),
            InvariantId::new("INV-003-DETERMINISTIC-SEED"),
        ),
        (
            "integrity.proof_verification_enabled".to_string(),
            InvariantId::new("INV-004-INTEGRITY-PROOF-VERIFICATION"),
        ),
        (
            "integrity.bypass_hash_check".to_string(),
            InvariantId::new("INV-004-INTEGRITY-PROOF-VERIFICATION"),
        ),
        (
            "ring_buffer.overflow_policy".to_string(),
            InvariantId::new("INV-005-RING-BUFFER-FIFO"),
        ),
        (
            "ring_buffer.eviction_order".to_string(),
            InvariantId::new("INV-005-RING-BUFFER-FIFO"),
        ),
        (
            "epoch.set_id".to_string(),
            InvariantId::new("INV-006-EPOCH-MONOTONIC"),
        ),
        (
            "epoch.decrement".to_string(),
            InvariantId::new("INV-006-EPOCH-MONOTONIC"),
        ),
        (
            "witness.hash_algorithm".to_string(),
            InvariantId::new("INV-007-WITNESS-HASH-SHA256"),
        ),
        (
            "guardrail.precedence".to_string(),
            InvariantId::new("INV-008-GUARDRAIL-PRECEDENCE"),
        ),
        (
            "guardrail.override_bayesian".to_string(),
            InvariantId::new("INV-008-GUARDRAIL-PRECEDENCE"),
        ),
        (
            "object_class.mutate_existing".to_string(),
            InvariantId::new("INV-009-OBJECT-CLASS-APPEND-ONLY"),
        ),
        (
            "object_class.delete_version".to_string(),
            InvariantId::new("INV-009-OBJECT-CLASS-APPEND-ONLY"),
        ),
        (
            "network.implicit_access".to_string(),
            InvariantId::new("INV-010-REMOTE-CAP-REQUIRED"),
        ),
        (
            "network.bypass_remote_cap".to_string(),
            InvariantId::new("INV-010-REMOTE-CAP-REQUIRED"),
        ),
        (
            "marker_stream.rewrite".to_string(),
            InvariantId::new("INV-011-MARKER-CHAIN-APPEND-ONLY"),
        ),
        (
            "marker_stream.delete".to_string(),
            InvariantId::new("INV-011-MARKER-CHAIN-APPEND-ONLY"),
        ),
        (
            "marker_stream.reorder".to_string(),
            InvariantId::new("INV-011-MARKER-CHAIN-APPEND-ONLY"),
        ),
        (
            "receipt_chain.truncate".to_string(),
            InvariantId::new("INV-012-RECEIPT-CHAIN-IMMUTABLE"),
        ),
        (
            "receipt_chain.modify".to_string(),
            InvariantId::new("INV-012-RECEIPT-CHAIN-IMMUTABLE"),
        ),
        (
            "receipt_chain.fork".to_string(),
            InvariantId::new("INV-012-RECEIPT-CHAIN-IMMUTABLE"),
        ),
    ]
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_proposal(field: &str) -> PolicyProposal {
        PolicyProposal {
            proposal_id: "test-proposal-001".to_string(),
            controller_id: "controller-alpha".to_string(),
            epoch_id: 42,
            changes: vec![PolicyChange {
                field: field.to_string(),
                old_value: serde_json::json!(true),
                new_value: serde_json::json!(false),
            }],
        }
    }

    fn tunable_proposal(field: &str) -> PolicyProposal {
        PolicyProposal {
            proposal_id: "test-tunable-001".to_string(),
            controller_id: "controller-beta".to_string(),
            epoch_id: 43,
            changes: vec![PolicyChange {
                field: field.to_string(),
                old_value: serde_json::json!(100),
                new_value: serde_json::json!(200),
            }],
        }
    }

    #[test]
    fn canonical_envelope_has_at_least_10_invariants() {
        let env = CorrectnessEnvelope::canonical();
        assert!(
            env.len() >= 10,
            "canonical envelope must have >= 10 invariants, got {}",
            env.len()
        );
    }

    #[test]
    fn canonical_envelope_has_12_invariants() {
        let env = CorrectnessEnvelope::canonical();
        assert_eq!(env.len(), 12);
    }

    #[test]
    fn all_invariants_have_non_empty_fields() {
        let env = CorrectnessEnvelope::canonical();
        for inv in &env.invariants {
            assert!(
                !inv.id.as_str().is_empty(),
                "invariant ID must not be empty"
            );
            assert!(!inv.name.is_empty(), "invariant name must not be empty");
            assert!(
                !inv.description.is_empty(),
                "invariant description must not be empty"
            );
            assert!(
                !inv.owner_track.as_str().is_empty(),
                "owner_track must not be empty"
            );
        }
    }

    #[test]
    fn all_invariant_ids_are_unique() {
        let env = CorrectnessEnvelope::canonical();
        let mut seen = std::collections::BTreeSet::new();
        for inv in &env.invariants {
            assert!(
                seen.insert(inv.id.clone()),
                "duplicate invariant ID: {}",
                inv.id
            );
        }
    }

    #[test]
    fn no_invariant_has_enforcement_none() {
        let env = CorrectnessEnvelope::canonical();
        for inv in &env.invariants {
            // EnforcementMode has no None variant, so this is structurally guaranteed.
            // Verify the label is one of the known values.
            assert!(
                matches!(
                    inv.enforcement,
                    EnforcementMode::Compile
                        | EnforcementMode::Runtime
                        | EnforcementMode::Conformance
                ),
                "invariant {} has unexpected enforcement mode",
                inv.id
            );
        }
    }

    // ── Rejection tests: each immutable invariant has at least one field ──

    #[test]
    fn rejects_hardening_direction_change() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("hardening.direction");
        let err = env.is_within_envelope(&proposal).unwrap_err();
        assert_eq!(err.invariant_id.as_str(), "INV-001-MONOTONIC-HARDENING");
    }

    #[test]
    fn rejects_evidence_suppression() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("evidence.suppress");
        let err = env.is_within_envelope(&proposal).unwrap_err();
        assert_eq!(err.invariant_id.as_str(), "INV-002-EVIDENCE-EMISSION");
    }

    #[test]
    fn rejects_seed_algorithm_change() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("seed.algorithm");
        let err = env.is_within_envelope(&proposal).unwrap_err();
        assert_eq!(err.invariant_id.as_str(), "INV-003-DETERMINISTIC-SEED");
    }

    #[test]
    fn rejects_integrity_bypass() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("integrity.bypass_hash_check");
        let err = env.is_within_envelope(&proposal).unwrap_err();
        assert_eq!(
            err.invariant_id.as_str(),
            "INV-004-INTEGRITY-PROOF-VERIFICATION"
        );
    }

    #[test]
    fn rejects_ring_buffer_overflow_change() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("ring_buffer.overflow_policy");
        let err = env.is_within_envelope(&proposal).unwrap_err();
        assert_eq!(err.invariant_id.as_str(), "INV-005-RING-BUFFER-FIFO");
    }

    #[test]
    fn rejects_epoch_decrement() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("epoch.decrement");
        let err = env.is_within_envelope(&proposal).unwrap_err();
        assert_eq!(err.invariant_id.as_str(), "INV-006-EPOCH-MONOTONIC");
    }

    #[test]
    fn rejects_witness_hash_algorithm_change() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("witness.hash_algorithm");
        let err = env.is_within_envelope(&proposal).unwrap_err();
        assert_eq!(err.invariant_id.as_str(), "INV-007-WITNESS-HASH-SHA256");
    }

    #[test]
    fn rejects_guardrail_precedence_override() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("guardrail.precedence");
        let err = env.is_within_envelope(&proposal).unwrap_err();
        assert_eq!(err.invariant_id.as_str(), "INV-008-GUARDRAIL-PRECEDENCE");
    }

    #[test]
    fn rejects_object_class_mutation() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("object_class.mutate_existing");
        let err = env.is_within_envelope(&proposal).unwrap_err();
        assert_eq!(
            err.invariant_id.as_str(),
            "INV-009-OBJECT-CLASS-APPEND-ONLY"
        );
    }

    #[test]
    fn rejects_network_implicit_access() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("network.bypass_remote_cap");
        let err = env.is_within_envelope(&proposal).unwrap_err();
        assert_eq!(err.invariant_id.as_str(), "INV-010-REMOTE-CAP-REQUIRED");
    }

    #[test]
    fn rejects_marker_stream_rewrite() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("marker_stream.rewrite");
        let err = env.is_within_envelope(&proposal).unwrap_err();
        assert_eq!(
            err.invariant_id.as_str(),
            "INV-011-MARKER-CHAIN-APPEND-ONLY"
        );
    }

    #[test]
    fn rejects_receipt_chain_truncation() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("receipt_chain.truncate");
        let err = env.is_within_envelope(&proposal).unwrap_err();
        assert_eq!(err.invariant_id.as_str(), "INV-012-RECEIPT-CHAIN-IMMUTABLE");
    }

    #[test]
    fn rejects_hardening_level_decrease_alias() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("hardening.level_decrease");

        let err = env.is_within_envelope(&proposal).unwrap_err();

        assert_eq!(err.invariant_id.as_str(), "INV-001-MONOTONIC-HARDENING");
        assert_eq!(err.proposal_field, "hardening.level_decrease");
    }

    #[test]
    fn rejects_evidence_emission_toggle_alias() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("evidence.emission_enabled");

        let err = env.is_within_envelope(&proposal).unwrap_err();

        assert_eq!(err.invariant_id.as_str(), "INV-002-EVIDENCE-EMISSION");
        assert_eq!(err.proposal_field, "evidence.emission_enabled");
    }

    #[test]
    fn rejects_integrity_verification_disable_alias() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("integrity.proof_verification_enabled");

        let err = env.is_within_envelope(&proposal).unwrap_err();

        assert_eq!(
            err.invariant_id.as_str(),
            "INV-004-INTEGRITY-PROOF-VERIFICATION"
        );
        assert_eq!(err.proposal_field, "integrity.proof_verification_enabled");
    }

    #[test]
    fn rejects_ring_buffer_eviction_order_alias() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("ring_buffer.eviction_order");

        let err = env.is_within_envelope(&proposal).unwrap_err();

        assert_eq!(err.invariant_id.as_str(), "INV-005-RING-BUFFER-FIFO");
        assert_eq!(err.proposal_field, "ring_buffer.eviction_order");
    }

    #[test]
    fn rejects_object_class_delete_version_alias() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("object_class.delete_version");

        let err = env.is_within_envelope(&proposal).unwrap_err();

        assert_eq!(
            err.invariant_id.as_str(),
            "INV-009-OBJECT-CLASS-APPEND-ONLY"
        );
        assert_eq!(err.proposal_field, "object_class.delete_version");
    }

    #[test]
    fn rejects_network_implicit_access_alias() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("network.implicit_access");

        let err = env.is_within_envelope(&proposal).unwrap_err();

        assert_eq!(err.invariant_id.as_str(), "INV-010-REMOTE-CAP-REQUIRED");
        assert_eq!(err.proposal_field, "network.implicit_access");
    }

    #[test]
    fn rejects_marker_stream_reorder_alias() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("marker_stream.reorder");

        let err = env.is_within_envelope(&proposal).unwrap_err();

        assert_eq!(
            err.invariant_id.as_str(),
            "INV-011-MARKER-CHAIN-APPEND-ONLY"
        );
        assert_eq!(err.proposal_field, "marker_stream.reorder");
    }

    #[test]
    fn rejects_receipt_chain_modify_alias() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("receipt_chain.modify");

        let err = env.is_within_envelope(&proposal).unwrap_err();

        assert_eq!(err.invariant_id.as_str(), "INV-012-RECEIPT-CHAIN-IMMUTABLE");
        assert_eq!(err.proposal_field, "receipt_chain.modify");
    }

    // ── Acceptance tests: tunable parameters pass ──

    #[test]
    fn allows_tunable_budget_change() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = tunable_proposal("admission.budget_limit");
        assert!(env.is_within_envelope(&proposal).is_ok());
    }

    #[test]
    fn allows_tunable_threshold_change() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = tunable_proposal("scoring.risk_threshold");
        assert!(env.is_within_envelope(&proposal).is_ok());
    }

    #[test]
    fn allows_tunable_scheduling_parameter() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = tunable_proposal("scheduling.max_concurrent_activations");
        assert!(env.is_within_envelope(&proposal).is_ok());
    }

    #[test]
    fn allows_tunable_telemetry_interval() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = tunable_proposal("telemetry.flush_interval_ms");
        assert!(env.is_within_envelope(&proposal).is_ok());
    }

    // ── Sub-field matching ──

    #[test]
    fn rejects_sub_field_of_immutable_prefix() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("hardening.direction.level");
        let err = env.is_within_envelope(&proposal).unwrap_err();
        assert_eq!(err.invariant_id.as_str(), "INV-001-MONOTONIC-HARDENING");
    }

    #[test]
    fn rejects_nested_network_capability_bypass_field() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("network.bypass_remote_cap.scope");

        let err = env.is_within_envelope(&proposal).unwrap_err();

        assert_eq!(err.invariant_id.as_str(), "INV-010-REMOTE-CAP-REQUIRED");
        assert_eq!(err.proposal_field, "network.bypass_remote_cap.scope");
    }

    #[test]
    fn rejects_marker_stream_delete_subfield() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("marker_stream.delete.confirmation");

        let err = env.is_within_envelope(&proposal).unwrap_err();

        assert_eq!(
            err.invariant_id.as_str(),
            "INV-011-MARKER-CHAIN-APPEND-ONLY"
        );
        assert!(err.reason.contains("append-only"));
    }

    #[test]
    fn rejects_receipt_chain_fork_variant() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("receipt_chain.fork");

        let err = env.is_within_envelope(&proposal).unwrap_err();

        assert_eq!(err.invariant_id.as_str(), "INV-012-RECEIPT-CHAIN-IMMUTABLE");
        assert_eq!(err.proposal_field, "receipt_chain.fork");
    }

    #[test]
    fn rejects_seed_hash_function_subfield() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("seed.hash_function.override");

        let err = env.is_within_envelope(&proposal).unwrap_err();

        assert_eq!(err.invariant_id.as_str(), "INV-003-DETERMINISTIC-SEED");
        assert!(
            err.reason
                .contains("Deterministic seed derivation algorithm")
        );
    }

    #[test]
    fn rejects_malformed_envelope_mapping_without_invariant_definition() {
        let env = CorrectnessEnvelope {
            invariants: Vec::new(),
            immutable_fields: vec![(
                "secret.root_access".to_string(),
                InvariantId::new("INV-MISSING"),
            )],
        };
        let proposal = make_proposal("secret.root_access");

        let err = env.is_within_envelope(&proposal).unwrap_err();

        assert_eq!(err.invariant_id.as_str(), "INV-MISSING");
        assert_eq!(err.invariant_name, "missing invariant definition");
        assert!(err.reason.contains("definition is missing"));
    }

    #[test]
    fn rejects_malformed_envelope_mapping_for_nested_field() {
        let env = CorrectnessEnvelope {
            invariants: Vec::new(),
            immutable_fields: vec![(
                "secret.root_access".to_string(),
                InvariantId::new("INV-MISSING"),
            )],
        };
        let proposal = make_proposal("secret.root_access.override");

        let err = env.is_within_envelope(&proposal).unwrap_err();

        assert_eq!(err.invariant_id.as_str(), "INV-MISSING");
        assert_eq!(err.proposal_field, "secret.root_access.override");
    }

    #[test]
    fn rejects_multi_change_when_missing_invariant_mapping_is_second() {
        let env = CorrectnessEnvelope {
            invariants: Vec::new(),
            immutable_fields: vec![(
                "secret.root_access".to_string(),
                InvariantId::new("INV-MISSING"),
            )],
        };
        let proposal = PolicyProposal {
            proposal_id: "malformed-env-001".to_string(),
            controller_id: "controller-delta".to_string(),
            epoch_id: 45,
            changes: vec![
                PolicyChange {
                    field: "telemetry.flush_interval_ms".to_string(),
                    old_value: serde_json::json!(1000),
                    new_value: serde_json::json!(500),
                },
                PolicyChange {
                    field: "secret.root_access".to_string(),
                    old_value: serde_json::json!(false),
                    new_value: serde_json::json!(true),
                },
            ],
        };

        let err = env.is_within_envelope(&proposal).unwrap_err();

        assert_eq!(err.invariant_id.as_str(), "INV-MISSING");
        assert_eq!(err.proposal_field, "secret.root_access");
    }

    // ── Violation error contains invariant ID ──

    #[test]
    fn violation_contains_invariant_id_and_field() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = make_proposal("evidence.suppress");
        let err = env.is_within_envelope(&proposal).unwrap_err();
        assert_eq!(err.invariant_id.as_str(), "INV-002-EVIDENCE-EMISSION");
        assert_eq!(err.proposal_field, "evidence.suppress");
        assert!(!err.reason.is_empty());
    }

    // ── Multi-change proposals ──

    #[test]
    fn rejects_mixed_proposal_on_first_violation() {
        let env = CorrectnessEnvelope::canonical();
        let proposal = PolicyProposal {
            proposal_id: "mixed-001".to_string(),
            controller_id: "controller-gamma".to_string(),
            epoch_id: 44,
            changes: vec![
                PolicyChange {
                    field: "telemetry.flush_interval_ms".to_string(),
                    old_value: serde_json::json!(1000),
                    new_value: serde_json::json!(2000),
                },
                PolicyChange {
                    field: "evidence.suppress".to_string(),
                    old_value: serde_json::json!(false),
                    new_value: serde_json::json!(true),
                },
            ],
        };
        let err = env.is_within_envelope(&proposal).unwrap_err();
        assert_eq!(err.invariant_id.as_str(), "INV-002-EVIDENCE-EMISSION");
    }

    // ── Adversarial tests ──

    #[test]
    fn cannot_modify_envelope_via_controller_api_field() {
        let env = CorrectnessEnvelope::canonical();
        // Attempting to modify the envelope struct itself via a policy field
        // that happens to start with "envelope" should be allowed since
        // "envelope" is not a protected prefix — the envelope is protected
        // structurally, not via a policy field.
        let proposal = make_proposal("envelope.invariants");
        // This should pass because "envelope" is not in the immutable field map.
        // The actual envelope is protected by being a compile-time constant.
        assert!(env.is_within_envelope(&proposal).is_ok());
    }

    // ── Manifest export ──

    #[test]
    fn manifest_json_contains_all_invariants() {
        let env = CorrectnessEnvelope::canonical();
        let manifest = env.to_manifest_json();
        let count = manifest["invariant_count"].as_u64().unwrap();
        assert_eq!(count, 12);
        let invariants = manifest["invariants"].as_array().unwrap();
        assert_eq!(invariants.len(), 12);
        for inv in invariants {
            assert!(inv["id"].as_str().is_some());
            assert!(inv["name"].as_str().is_some());
            assert!(inv["enforcement"].as_str().is_some());
        }
    }

    #[test]
    fn manifest_json_contains_immutable_fields() {
        let env = CorrectnessEnvelope::canonical();
        let manifest = env.to_manifest_json();
        let fields = manifest["immutable_fields"].as_array().unwrap();
        assert_eq!(fields.len(), 25, "expected exactly 25 immutable fields");
    }

    // ── Serialization round-trip ──

    #[test]
    fn envelope_serialization_round_trip() {
        let env = CorrectnessEnvelope::canonical();
        let json = serde_json::to_string(&env).unwrap();
        let deserialized: CorrectnessEnvelope = serde_json::from_str(&json).unwrap();
        assert_eq!(env.len(), deserialized.len());
        for (a, b) in env.invariants.iter().zip(deserialized.invariants.iter()) {
            assert_eq!(a.id, b.id);
            assert_eq!(a.name, b.name);
            assert_eq!(a.enforcement, b.enforcement);
        }
    }

    // ── Lookup ──

    #[test]
    fn get_returns_invariant_by_id() {
        let env = CorrectnessEnvelope::canonical();
        let inv = env
            .get(&InvariantId::new("INV-001-MONOTONIC-HARDENING"))
            .unwrap();
        assert_eq!(inv.name, "Monotonic hardening direction");
    }

    #[test]
    fn get_returns_none_for_unknown_id() {
        let env = CorrectnessEnvelope::canonical();
        assert!(env.get(&InvariantId::new("INV-999-NONEXISTENT")).is_none());
    }

    // ── Display ──

    #[test]
    fn violation_display_includes_all_fields() {
        let violation = EnvelopeViolation {
            invariant_id: InvariantId::new("INV-001-MONOTONIC-HARDENING"),
            invariant_name: "Monotonic hardening direction".to_string(),
            proposal_field: "hardening.direction".to_string(),
            reason: "test reason".to_string(),
        };
        let display = format!("{violation}");
        assert!(display.contains("EVD-ENVELOPE-002"));
        assert!(display.contains("INV-001-MONOTONIC-HARDENING"));
        assert!(display.contains("hardening.direction"));
    }

    // ── EnforcementMode label round-trip ──

    #[test]
    fn enforcement_mode_label_round_trip() {
        for mode in [
            EnforcementMode::Compile,
            EnforcementMode::Runtime,
            EnforcementMode::Conformance,
        ] {
            let label = mode.label();
            let parsed = EnforcementMode::from_label(label).unwrap();
            assert_eq!(mode, parsed);
        }
    }

    #[test]
    fn enforcement_mode_from_label_returns_none_for_unknown() {
        assert!(EnforcementMode::from_label("unknown").is_none());
    }
}

#[cfg(test)]
mod correctness_envelope_comprehensive_negative_tests {
    use super::*;

    #[test]
    fn negative_invariant_id_with_unicode_injection_attacks() {
        // Test InvariantId with malicious Unicode patterns
        let malicious_ids = vec![
            "INV\u{202E}spoofed\u{202D}-001",              // BiDi override
            "INV\u{0000}null\r\n\t\x1b[31mred\x1b[0m",    // Null bytes + ANSI
            "INV\u{FEFF}\u{200B}\u{200C}\u{200D}hidden",  // BOM + zero-width
            "INV\u{10FFFF}\u{E000}\u{FDD0}extreme",       // Private use + non-chars
            "INV\"quotes'apostrophe\\backslash",           // Quote injection
            "INV<script>alert('xss')</script>",           // XSS pattern
            "INV\u{D800}\u{DFFF}surrogate",               // Surrogate pairs
            "../../../etc/passwd\x00malicious",           // Path traversal
        ];

        for malicious_id in malicious_ids {
            let id = InvariantId::new(malicious_id);

            // Verify malicious content preserved exactly
            assert_eq!(id.as_str(), malicious_id);
            assert_eq!(format!("{}", id), malicious_id);

            // Test serialization preserves malicious content
            let json = serde_json::to_string(&id).unwrap();
            let deserialized: InvariantId = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.0, malicious_id);
        }
    }

    #[test]
    fn negative_policy_proposal_with_massive_malicious_content() {
        // Create policy proposal with extreme and malicious content
        let massive_changes = (0..10000).map(|i| {
            PolicyChange {
                field: format!("malicious.field.{}.{}", i, "x".repeat(1000)),
                old_value: serde_json::json!({
                    "massive_key": "y".repeat(10000),
                    "unicode_key\u{202E}spoofed": "z".repeat(5000),
                    "control_chars": "\x00\x01\x02\x03\x04\x05",
                    "nested": {
                        "deep": {
                            "structure": "a".repeat(50000)
                        }
                    }
                }),
                new_value: serde_json::json!({
                    "xss_attack": "<script>alert('proposal')</script>",
                    "sql_injection": "'; DROP TABLE invariants; --",
                    "unicode_normalization": "café vs cafe\u{0301}",
                    "bidi_override": "\u{202A}ltr\u{202B}rtl\u{202C}pop",
                    "massive_array": (0..1000).map(|j| format!("item_{}", j)).collect::<Vec<_>>()
                }),
            }
        }).collect();

        let malicious_proposal = PolicyProposal {
            proposal_id: "proposal\u{FEFF}\u{200B}hidden".repeat(1000),
            controller_id: "controller\r\nHTTP/1.1 200 OK\r\n\r\n".repeat(100),
            epoch_id: u64::MAX,
            changes: massive_changes,
        };

        // Test serialization with massive malicious content
        let json = serde_json::to_string(&malicious_proposal).unwrap();
        assert!(json.len() > 10_000_000); // Should be massive

        let deserialized: PolicyProposal = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.changes.len(), 10000);
        assert_eq!(deserialized.epoch_id, u64::MAX);

        // Test envelope checking with massive proposal
        let env = CorrectnessEnvelope::canonical();
        let result = env.is_within_envelope(&malicious_proposal);

        // Should handle massive proposals without panic
        assert!(result.is_ok()); // Should pass since fields don't match immutable prefixes
    }

    #[test]
    fn negative_envelope_violation_display_injection_resistance() {
        // Test violation display with malicious content in all fields
        let malicious_violations = vec![
            EnvelopeViolation {
                invariant_id: InvariantId::new("INV\u{202E}spoofed\u{202D}"),
                invariant_name: "Malicious\r\n\t\x1b[31mRED\x1b[0m Name".to_string(),
                proposal_field: "field\x00null\u{FEFF}bom".to_string(),
                reason: "Reason with<script>alert('violation')</script>injection".to_string(),
            },
            EnvelopeViolation {
                invariant_id: InvariantId::new("INV\"quotes'apostrophe\\backslash"),
                invariant_name: "Name\u{10FFFF}\u{E000}\u{FDD0}unicode".to_string(),
                proposal_field: "field\u{D800}\u{DFFF}surrogate".to_string(),
                reason: "HTTP/1.1 200 OK\r\n\r\n<html>injection".to_string(),
            },
            EnvelopeViolation {
                invariant_id: InvariantId::new("INV\u{202A}bidi\u{202B}isolate\u{202C}"),
                invariant_name: "Name' OR '1'='1' --".to_string(),
                proposal_field: "field\u{FDD0}nonchar\u{FFFE}".to_string(),
                reason: "Reason\u{200B}\u{200C}\u{200D}zerowidth".to_string(),
            },
        ];

        for violation in malicious_violations {
            // Test display formatting safety
            let display_string = format!("{}", violation);

            // Verify error code is preserved
            assert!(display_string.contains("EVD-ENVELOPE-002"));

            // Verify malicious content is included but display remains structured
            assert!(display_string.contains(&violation.invariant_id.0));
            assert!(display_string.contains(&violation.invariant_name));
            assert!(display_string.contains(&violation.proposal_field));
            assert!(display_string.contains(&violation.reason));

            // Test serialization safety
            let json = serde_json::to_string(&violation).unwrap();
            let deserialized: EnvelopeViolation = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, violation);
        }
    }

    #[test]
    fn negative_invariant_with_extreme_field_lengths_and_injection() {
        // Test invariants with extreme field sizes and injection patterns
        let extreme_invariants = vec![
            Invariant {
                id: InvariantId::new("INV\u{202E}spoofed\u{202D}".repeat(1000)),
                name: "Extreme name: ".to_string() + &"x".repeat(100000), // 100KB name
                description: "Extreme description: ".to_string() + &"y".repeat(1000000), // 1MB description
                owner_track: SectionId::new("10\u{FEFF}.14\u{200B}"),
                enforcement: EnforcementMode::Runtime,
            },
            Invariant {
                id: InvariantId::new("INV<script>alert('invariant')</script>"),
                name: "XSS\"quotes'apostrophe\\backslash".to_string(),
                description: "HTTP/1.1 200 OK\r\n\r\n<html>injection".to_string(),
                owner_track: SectionId::new("10.14\r\nInjected"),
                enforcement: EnforcementMode::Compile,
            },
            Invariant {
                id: InvariantId::new("INV\u{D800}\u{DFFF}\u{10FFFF}"),
                name: "Unicode\u{FDD0}nonchar\u{FFFE}name".to_string(),
                description: "Description\u{0000}null\x01\x02\x03".to_string(),
                owner_track: SectionId::new("10.14' OR '1'='1' --"),
                enforcement: EnforcementMode::Conformance,
            },
        ];

        for invariant in extreme_invariants {
            // Test serialization with extreme content
            let json = serde_json::to_string(&invariant).unwrap();
            let deserialized: Invariant = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, invariant);

            // Verify field lengths preserved for extreme content
            if invariant.name.len() > 100000 {
                assert_eq!(deserialized.name.len(), invariant.name.len());
            }
            if invariant.description.len() > 1000000 {
                assert_eq!(deserialized.description.len(), invariant.description.len());
            }
        }
    }

    #[test]
    fn negative_field_prefix_bypass_attempts_and_validation_attacks() {
        let env = CorrectnessEnvelope::canonical();

        // Test various field prefix bypass attempts
        let bypass_attempts = vec![
            // Case sensitivity attacks
            "Hardening.direction",
            "HARDENING.DIRECTION",
            "hardening.Direction",

            // Unicode normalization attacks
            "hardening.direction", // Normal
            "hardening.direction\u{0301}", // With combining char
            "hardening.direction\u{FEFF}", // With BOM
            "hardening.direction\u{200B}", // With zero-width space

            // Prefix confusion attacks
            "hardening.direction_bypass",
            "hardening.directional",
            "hardening.direction2",
            "hardening.direction\x00null",

            // Path traversal in field names
            "../hardening.direction",
            "./hardening.direction",
            "config/../hardening.direction",

            // Injection attacks in field names
            "hardening.direction'; DROP TABLE config; --",
            "hardening.direction<script>alert('field')</script>",
            "hardening.direction\r\nHTTP/1.1 200 OK\r\n\r\n",
        ];

        for malicious_field in bypass_attempts {
            let proposal = PolicyProposal {
                proposal_id: "bypass-test".to_string(),
                controller_id: "attacker".to_string(),
                epoch_id: 1,
                changes: vec![PolicyChange {
                    field: malicious_field.to_string(),
                    old_value: serde_json::json!(true),
                    new_value: serde_json::json!(false),
                }],
            };

            let result = env.is_within_envelope(&proposal);

            // Most should pass (bypass attempts), only exact matches should fail
            if malicious_field == "hardening.direction" {
                assert!(result.is_err());
            } else {
                assert!(result.is_ok(), "Failed for field: {}", malicious_field);
            }
        }
    }

    #[test]
    fn negative_correctness_envelope_with_malformed_immutable_fields() {
        // Test envelope with malformed immutable field mappings
        let malformed_invariants = vec![
            Invariant {
                id: InvariantId::new("INV-VALID"),
                name: "Valid Invariant".to_string(),
                description: "A valid invariant for testing".to_string(),
                owner_track: SectionId::new("10.14"),
                enforcement: EnforcementMode::Runtime,
            }
        ];

        let malformed_fields = vec![
            // Mapping to non-existent invariant
            ("malicious.field\u{202E}spoofed".to_string(), InvariantId::new("INV-NONEXISTENT")),
            // Unicode attacks in field prefixes
            ("field\x00null\u{FEFF}bom".to_string(), InvariantId::new("INV-VALID")),
            // Extremely long field prefixes
            ("field.".repeat(10000), InvariantId::new("INV-VALID")),
            // XSS in field prefixes
            ("field<script>alert('field')</script>".to_string(), InvariantId::new("INV-VALID")),
            // Empty field prefix
            ("".to_string(), InvariantId::new("INV-VALID")),
        ];

        let malformed_env = CorrectnessEnvelope {
            invariants: malformed_invariants,
            immutable_fields: malformed_fields,
        };

        // Test various proposals against malformed envelope
        let test_proposals = vec![
            "malicious.field\u{202E}spoofed",
            "field\x00null\u{FEFF}bom",
            &"field.".repeat(10000),
            "field<script>alert('field')</script>",
            "",
            "malicious.field\u{202E}spoofed.subfield",
        ];

        for field in test_proposals {
            let proposal = PolicyProposal {
                proposal_id: "malformed-test".to_string(),
                controller_id: "tester".to_string(),
                epoch_id: 1,
                changes: vec![PolicyChange {
                    field: field.to_string(),
                    old_value: serde_json::json!(null),
                    new_value: serde_json::json!(true),
                }],
            };

            let result = malformed_env.is_within_envelope(&proposal);

            // Should handle malformed mappings gracefully
            if field.starts_with("malicious.field\u{202E}spoofed") ||
               field.starts_with("field\x00null") ||
               field.starts_with(&"field.".repeat(10000)) ||
               field.starts_with("field<script>") {
                // Should detect violations even with malformed invariant
                assert!(result.is_err());
                let err = result.unwrap_err();
                assert!(err.invariant_name.contains("missing") || err.invariant_name == "Valid Invariant");
            }
        }
    }

    #[test]
    fn negative_enforcement_mode_serialization_tampering() {
        // Test EnforcementMode with invalid serialization attempts
        let invalid_enforcement_modes = [
            "\"Compile\"", // Wrong case
            "\"RUNTIME\"", // All caps
            "\"execution\"", // Different word
            "\"\"", // Empty string
            "null",
            "42",
            "true",
            "{}",
            "[]",
        ];

        for invalid_json in invalid_enforcement_modes {
            let result: Result<EnforcementMode, _> = serde_json::from_str(invalid_json);
            assert!(result.is_err(), "Should reject invalid EnforcementMode: {}", invalid_json);
        }

        // Test from_label with malicious inputs
        let malicious_labels = [
            "compile\x00null",
            "runtime\u{FEFF}bom",
            "conformance\u{202E}spoofed",
            "compile<script>",
            "runtime'; DROP TABLE modes; --",
            " compile", // Leading whitespace
            "compile ", // Trailing whitespace
            "Compile", // Wrong case
            "\u{200B}runtime", // Zero-width prefix
        ];

        for label in malicious_labels {
            assert_eq!(EnforcementMode::from_label(label), None);
        }

        // Test valid round-trips still work
        for mode in [EnforcementMode::Compile, EnforcementMode::Runtime, EnforcementMode::Conformance] {
            let label = mode.label();
            let parsed = EnforcementMode::from_label(label).unwrap();
            assert_eq!(mode, parsed);

            let json = serde_json::to_string(&mode).unwrap();
            let deserialized: EnforcementMode = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, mode);
        }
    }

    #[test]
    fn negative_manifest_json_generation_with_malicious_invariants() {
        // Create envelope with malicious invariants to test manifest generation
        let malicious_invariants = vec![
            Invariant {
                id: InvariantId::new("INV\u{202E}spoofed\u{202D}"),
                name: "XSS<script>alert('manifest')</script>Name".to_string(),
                description: "Description\r\nHTTP/1.1 200 OK\r\n\r\n<html>".to_string(),
                owner_track: SectionId::new("10.14\x00null"),
                enforcement: EnforcementMode::Runtime,
            },
            Invariant {
                id: InvariantId::new("INV\u{10FFFF}\u{E000}"),
                name: "Name\"quotes'apostrophe\\backslash".to_string(),
                description: "Description' OR '1'='1' --".to_string(),
                owner_track: SectionId::new("10.14\u{FEFF}\u{200B}"),
                enforcement: EnforcementMode::Compile,
            },
            Invariant {
                id: InvariantId::new("INV\u{D800}\u{DFFF}"),
                name: "Name\u{FDD0}nonchar\u{FFFE}".to_string(),
                description: "Description\u{202A}bidi\u{202B}isolate\u{202C}".to_string(),
                owner_track: SectionId::new("../../../etc/passwd"),
                enforcement: EnforcementMode::Conformance,
            },
        ];

        let malicious_fields = vec![
            ("field\x00null".to_string(), InvariantId::new("INV\u{202E}spoofed\u{202D}")),
            ("field<script>".to_string(), InvariantId::new("INV\u{10FFFF}\u{E000}")),
            ("field\u{D800}\u{DFFF}".to_string(), InvariantId::new("INV\u{D800}\u{DFFF}")),
        ];

        let malicious_env = CorrectnessEnvelope {
            invariants: malicious_invariants,
            immutable_fields: malicious_fields,
        };

        // Test manifest generation with malicious content
        let manifest = malicious_env.to_manifest_json();

        // Verify structure is preserved
        assert_eq!(manifest["schema_version"].as_str(), Some("1.0"));
        assert_eq!(manifest["envelope_version"].as_str(), Some("1.0"));
        assert_eq!(manifest["invariant_count"].as_u64(), Some(3));
        assert_eq!(manifest["immutable_field_count"].as_u64(), Some(3));

        // Verify malicious content preserved in manifest
        let invariants = manifest["invariants"].as_array().unwrap();
        assert_eq!(invariants.len(), 3);

        for inv in invariants {
            let id = inv["id"].as_str().unwrap();
            let name = inv["name"].as_str().unwrap();

            // Should contain malicious content
            assert!(id.contains("INV") || name.contains("Name"));
        }

        // Test manifest serialization doesn't break JSON structure
        let manifest_json = serde_json::to_string(&manifest).unwrap();
        let reparsed: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();
        assert_eq!(reparsed["invariant_count"].as_u64(), Some(3));
    }

    #[test]
    fn negative_policy_change_with_extreme_json_values() {
        // Test PolicyChange with extreme JSON values
        let extreme_changes = vec![
            PolicyChange {
                field: "extreme.nested".to_string(),
                old_value: serde_json::json!({
                    "level1": {
                        "level2": {
                            "level3": {
                                "level4": {
                                    "level5": "x".repeat(100000)
                                }
                            }
                        }
                    }
                }),
                new_value: serde_json::json!(null),
            },
            PolicyChange {
                field: "extreme.array".to_string(),
                old_value: serde_json::json!((0..50000).collect::<Vec<i32>>()),
                new_value: serde_json::json!((0..50000).map(|i| format!("item_{}", "x".repeat(100))).collect::<Vec<_>>()),
            },
            PolicyChange {
                field: "extreme.unicode".to_string(),
                old_value: serde_json::json!({
                    "\u{202E}spoofed\u{202D}": "value\x00null",
                    "unicode\u{FEFF}\u{200B}": "value\u{10FFFF}\u{E000}",
                    "<script>alert('json')</script>": "value\r\nHTTP/1.1 200 OK\r\n\r\n"
                }),
                new_value: serde_json::json!("value\u{D800}\u{DFFF}\u{FDD0}\u{FFFE}"),
            },
        ];

        for change in extreme_changes {
            // Test serialization with extreme values
            let json = serde_json::to_string(&change).unwrap();
            let deserialized: PolicyChange = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized, change);
        }

        // Test proposal with extreme changes
        let extreme_proposal = PolicyProposal {
            proposal_id: "extreme-json-test".to_string(),
            controller_id: "extreme-controller".to_string(),
            epoch_id: u64::MAX,
            changes: extreme_changes,
        };

        let env = CorrectnessEnvelope::canonical();
        let result = env.is_within_envelope(&extreme_proposal);

        // Should handle extreme JSON without panic
        assert!(result.is_ok());
    }

    #[test]
    fn negative_section_id_and_invariant_id_edge_cases() {
        // Test edge cases with SectionId and InvariantId
        let edge_case_sections = vec![
            "",
            "\x00",
            "\u{FEFF}",
            "\u{200B}\u{200C}\u{200D}",
            "x".repeat(1000000), // 1MB section ID
            "10.14\r\n<script>alert('section')</script>",
            "10.14' OR '1'='1' --",
        ];

        for section_str in edge_case_sections {
            let section = SectionId::new(section_str.clone());
            assert_eq!(section.as_str(), section_str);
            assert_eq!(format!("{}", section), section_str);

            // Test serialization
            let json = serde_json::to_string(&section).unwrap();
            let deserialized: SectionId = serde_json::from_str(&json).unwrap();
            assert_eq!(deserialized.0, section_str);
        }

        // Test empty envelope
        let empty_env = CorrectnessEnvelope {
            invariants: Vec::new(),
            immutable_fields: Vec::new(),
        };

        assert_eq!(empty_env.len(), 0);
        assert!(empty_env.is_empty());
        assert!(empty_env.get(&InvariantId::new("any")).is_none());

        // Any proposal should pass on empty envelope
        let proposal = PolicyProposal {
            proposal_id: "empty-env-test".to_string(),
            controller_id: "tester".to_string(),
            epoch_id: 1,
            changes: vec![PolicyChange {
                field: "any.field".to_string(),
                old_value: serde_json::json!(true),
                new_value: serde_json::json!(false),
            }],
        };
        assert!(empty_env.is_within_envelope(&proposal).is_ok());
    }

    #[test]
    fn negative_envelope_stress_testing_with_massive_invariants() {
        // Create envelope with massive number of invariants and field mappings
        let mut massive_invariants = Vec::new();
        let mut massive_fields = Vec::new();

        for i in 0..10000 {
            massive_invariants.push(Invariant {
                id: InvariantId::new(format!("INV-{:05}-{}", i, "x".repeat(100))),
                name: format!("Invariant {} with massive content: {}", i, "y".repeat(1000)),
                description: format!("Description {} with extreme length: {}", i, "z".repeat(10000)),
                owner_track: SectionId::new(format!("10.{}", i)),
                enforcement: match i % 3 {
                    0 => EnforcementMode::Compile,
                    1 => EnforcementMode::Runtime,
                    _ => EnforcementMode::Conformance,
                },
            });

            massive_fields.push((
                format!("field_{}.{}", i, "a".repeat(500)),
                InvariantId::new(format!("INV-{:05}-{}", i, "x".repeat(100))),
            ));
        }

        let massive_env = CorrectnessEnvelope {
            invariants: massive_invariants,
            immutable_fields: massive_fields,
        };

        // Test envelope operations with massive data
        assert_eq!(massive_env.len(), 10000);
        assert!(!massive_env.is_empty());

        // Test lookup performance
        let lookup_id = InvariantId::new("INV-05000-".to_string() + &"x".repeat(100));
        let found = massive_env.get(&lookup_id);
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, lookup_id);

        // Test proposal checking with massive envelope
        let proposal = PolicyProposal {
            proposal_id: "massive-env-test".to_string(),
            controller_id: "stress-tester".to_string(),
            epoch_id: 1,
            changes: vec![PolicyChange {
                field: "field_5000.".to_string() + &"a".repeat(500),
                old_value: serde_json::json!(false),
                new_value: serde_json::json!(true),
            }],
        };

        let result = massive_env.is_within_envelope(&proposal);
        assert!(result.is_err()); // Should find the immutable field

        // Test manifest generation with massive data
        let manifest = massive_env.to_manifest_json();
        assert_eq!(manifest["invariant_count"].as_u64(), Some(10000));
        assert_eq!(manifest["immutable_field_count"].as_u64(), Some(10000));
    }
}

#[cfg(test)]
mod correctness_envelope_additional_negative_path_tests {
    use super::*;
    use std::collections::{HashMap, BTreeMap};
    use std::sync::{Arc, Mutex};
    use std::thread;

    #[test]
    fn negative_concurrent_envelope_access_simulation_and_race_conditions() {
        // Simulate concurrent access patterns that could expose race conditions
        let env = Arc::new(CorrectnessEnvelope::canonical());
        let results = Arc::new(Mutex::new(Vec::new()));

        // Spawn multiple threads performing different envelope operations
        let handles: Vec<_> = (0..50).map(|i| {
            let env_clone = env.clone();
            let results_clone = results.clone();

            thread::spawn(move || {
                let proposal = PolicyProposal {
                    proposal_id: format!("concurrent-{}", i),
                    controller_id: format!("thread-{}", i),
                    epoch_id: (i as u64).saturating_mul(1000000), // Large epoch IDs
                    changes: vec![
                        PolicyChange {
                            field: format!("concurrent.field.{}.{}", i, "x".repeat(i * 10)),
                            old_value: serde_json::json!(i),
                            new_value: serde_json::json!(i * 2),
                        },
                        PolicyChange {
                            field: if i % 3 == 0 { "hardening.direction" } else { "tunable.param" }.to_string(),
                            old_value: serde_json::json!(false),
                            new_value: serde_json::json!(true),
                        },
                    ],
                };

                // Test multiple operations concurrently
                let check_result = env_clone.is_within_envelope(&proposal);
                let lookup_result = env_clone.get(&InvariantId::new("INV-001-MONOTONIC-HARDENING"));
                let len_result = env_clone.len();
                let manifest_result = env_clone.to_manifest_json();

                results_clone.lock().unwrap().push((
                    i,
                    check_result.is_ok(),
                    lookup_result.is_some(),
                    len_result,
                    manifest_result["invariant_count"].as_u64().unwrap(),
                ));
            })
        }).collect();

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        let results = results.lock().unwrap();
        assert_eq!(results.len(), 50);

        // Verify consistency across all concurrent operations
        let expected_len = 12;
        let expected_count = 12;
        let mut violation_count = 0;

        for (i, check_ok, lookup_ok, len, count) in results.iter() {
            // All lookups should succeed consistently
            assert!(*lookup_ok, "Lookup failed for thread {}", i);
            assert_eq!(*len, expected_len, "Inconsistent length for thread {}", i);
            assert_eq!(*count, expected_count, "Inconsistent count for thread {}", i);

            // Only threads that modify hardening.direction should fail
            if i % 3 == 0 {
                assert!(!check_ok, "Thread {} should have failed envelope check", i);
                violation_count += 1;
            } else {
                assert!(*check_ok, "Thread {} should have passed envelope check", i);
            }
        }

        assert_eq!(violation_count, 17); // 50/3 rounded up = 17 threads modifying hardening.direction
    }

    #[test]
    fn negative_memory_exhaustion_attack_via_deeply_nested_structures() {
        // Test envelope resistance to memory exhaustion via extreme nesting
        let mut deeply_nested = serde_json::json!("base");

        // Create deeply nested JSON structure (limited to prevent actual OOM)
        for i in 0..1000 {
            deeply_nested = serde_json::json!({
                format!("level_{}", i): deeply_nested,
                format!("attack_{}", i): "x".repeat(100), // Additional memory pressure
                format!("unicode_{}\u{202E}", i): "y".repeat(100),
                format!("injection_{}<script>", i): "z".repeat(100),
            });
        }

        let memory_attack_changes = vec![
            PolicyChange {
                field: "memory.exhaustion.deeply.nested.field".to_string(),
                old_value: deeply_nested.clone(),
                new_value: serde_json::json!({
                    "replacement": deeply_nested,
                    "massive_array": (0..10000).map(|j| {
                        serde_json::json!({
                            "item": j,
                            "content": "a".repeat(1000),
                            "unicode": format!("\u{202E}spoofed_{}\u{202D}", j),
                        })
                    }).collect::<Vec<_>>()
                }),
            }
        ];

        let memory_attack_proposal = PolicyProposal {
            proposal_id: "memory-exhaustion-attack".repeat(100),
            controller_id: "memory-attacker".repeat(50),
            epoch_id: u64::MAX,
            changes: memory_attack_changes,
        };

        let env = CorrectnessEnvelope::canonical();

        // Should handle memory attack gracefully without panic or excessive memory use
        let result = env.is_within_envelope(&memory_attack_proposal);
        assert!(result.is_ok()); // Should pass as field doesn't match immutable prefixes

        // Test serialization still works with deeply nested structures
        let json = serde_json::to_string(&memory_attack_proposal).unwrap();
        assert!(json.len() > 1_000_000); // Should be very large but bounded

        // Test deserialization round-trip
        let deserialized: PolicyProposal = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.proposal_id, memory_attack_proposal.proposal_id);
        assert_eq!(deserialized.epoch_id, u64::MAX);
        assert_eq!(deserialized.changes.len(), 1);
    }

    #[test]
    fn negative_cryptographic_hash_collision_and_avalanche_testing() {
        // Test envelope resistance to hash collision and avalanche attacks
        let env = CorrectnessEnvelope::canonical();

        // Generate similar field names that could cause hash collisions
        let collision_candidates = vec![
            ("hardening.direction", true),  // Should violate
            ("hardening.directions", false), // Should pass (different)
            ("hardening.directio", false),   // Should pass (truncated)
            ("hardening.direction\x00", false), // Should pass (null terminated)
            ("hardening.direction\u{FEFF}", false), // Should pass (BOM)
            ("hardening.direction\u{200B}", false), // Should pass (zero-width)
        ];

        // Test each collision candidate
        let mut violation_results = HashMap::new();

        for (field, should_violate) in collision_candidates {
            let proposal = PolicyProposal {
                proposal_id: format!("collision-test-{}", field.len()),
                controller_id: "collision-tester".to_string(),
                epoch_id: 1,
                changes: vec![PolicyChange {
                    field: field.to_string(),
                    old_value: serde_json::json!(true),
                    new_value: serde_json::json!(false),
                }],
            };

            let result = env.is_within_envelope(&proposal);
            violation_results.insert(field, result.is_err());

            if should_violate {
                assert!(result.is_err(), "Field '{}' should violate envelope", field);
            } else {
                assert!(result.is_ok(), "Field '{}' should pass envelope", field);
            }
        }

        // Test avalanche effect: small changes in field names should have predictable results
        assert_eq!(violation_results["hardening.direction"], true);
        assert_eq!(violation_results["hardening.directions"], false);
        assert_eq!(violation_results["hardening.directio"], false);

        // Test hash-based lookup consistency with similar invariant IDs
        let avalanche_ids = vec![
            "INV-001-MONOTONIC-HARDENING",
            "INV-001-MONOTONIC-HARDENING\x00",
            "INV-001-MONOTONIC-HARDENIN",
            "INV-001-MONOTONIC-HARDENINGA",
        ];

        for id_str in avalanche_ids {
            let id = InvariantId::new(id_str);
            let lookup = env.get(&id);

            if id_str == "INV-001-MONOTONIC-HARDENING" {
                assert!(lookup.is_some(), "Original ID should be found");
            } else {
                assert!(lookup.is_none(), "Modified ID '{}' should not be found", id_str);
            }
        }
    }

    #[test]
    fn negative_time_based_attacks_and_epoch_boundary_manipulation() {
        let env = CorrectnessEnvelope::canonical();

        // Test epoch boundary attacks with extreme values
        let epoch_attacks = vec![
            (0, "zero epoch"),
            (1, "minimum epoch"),
            (u64::MAX, "maximum epoch"),
            (u64::MAX - 1, "near-maximum epoch"),
            (9223372036854775808, "signed overflow epoch"), // i64::MAX + 1
        ];

        for (epoch, description) in epoch_attacks {
            let proposal = PolicyProposal {
                proposal_id: format!("epoch-attack-{}", epoch),
                controller_id: format!("time-attacker-{}", description.replace(" ", "-")),
                epoch_id: epoch,
                changes: vec![
                    PolicyChange {
                        field: "epoch.timing.attack".to_string(),
                        old_value: serde_json::json!(epoch),
                        new_value: serde_json::json!(epoch.saturating_add(1)),
                    },
                    PolicyChange {
                        field: "epoch.decrement".to_string(), // Should violate
                        old_value: serde_json::json!(epoch),
                        new_value: serde_json::json!(epoch.saturating_sub(1)),
                    },
                ],
            };

            let result = env.is_within_envelope(&proposal);
            assert!(result.is_err(), "Epoch attack {} should be rejected", description);

            let err = result.unwrap_err();
            assert_eq!(err.invariant_id.as_str(), "INV-006-EPOCH-MONOTONIC");
            assert_eq!(err.proposal_field, "epoch.decrement");
        }

        // Test timing-based field manipulation attempts
        let timing_fields = vec![
            ("timestamp.now", false),
            ("timestamp.past", false),
            ("timestamp.future", false),
            ("epoch.set_id", true), // Should violate
            ("epoch.increment", false),
            ("epoch.overflow", false),
        ];

        for (field, should_violate) in timing_fields {
            let proposal = PolicyProposal {
                proposal_id: format!("timing-{}", field.replace(".", "-")),
                controller_id: "timing-manipulator".to_string(),
                epoch_id: 42,
                changes: vec![PolicyChange {
                    field: field.to_string(),
                    old_value: serde_json::json!(1000000),
                    new_value: serde_json::json!(2000000),
                }],
            };

            let result = env.is_within_envelope(&proposal);
            if should_violate {
                assert!(result.is_err(), "Timing field '{}' should violate", field);
            } else {
                assert!(result.is_ok(), "Timing field '{}' should pass", field);
            }
        }
    }

    #[test]
    fn negative_serialization_round_trip_corruption_detection() {
        let env = CorrectnessEnvelope::canonical();

        // Test corrupted serialization scenarios
        let original_proposal = PolicyProposal {
            proposal_id: "corruption-test".to_string(),
            controller_id: "corruption-detector".to_string(),
            epoch_id: 123456,
            changes: vec![
                PolicyChange {
                    field: "test.field".to_string(),
                    old_value: serde_json::json!({
                        "nested": {"value": 42},
                        "array": [1, 2, 3, 4, 5]
                    }),
                    new_value: serde_json::json!("replacement"),
                },
            ],
        };

        // Test normal round-trip first
        let json = serde_json::to_string(&original_proposal).unwrap();
        let deserialized: PolicyProposal = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized, original_proposal);

        // Test envelope checking consistency across serialization
        let result1 = env.is_within_envelope(&original_proposal);
        let result2 = env.is_within_envelope(&deserialized);
        assert_eq!(result1.is_ok(), result2.is_ok());

        // Test with corrupted JSON-like inputs (should fail gracefully)
        let corrupted_jsons = vec![
            r#"{"proposal_id": "test", "controller_id": "test", "epoch_id": 999999999999999999999999999999999999999999999999999999999999999999999999}"#, // Overflow
            r#"{"proposal_id": "test\u{0000}null", "controller_id": "test", "epoch_id": 1, "changes": []}"#, // Null bytes
            r#"{"proposal_id": "test", "controller_id": "test", "epoch_id": -1, "changes": []}"#, // Negative epoch
            r#"{"proposal_id": "test", "controller_id": "test", "epoch_id": 1.5, "changes": []}"#, // Float epoch
            r#"{"proposal_id": "test", "controller_id": "test", "epoch_id": "string", "changes": []}"#, // String epoch
        ];

        for corrupted in corrupted_jsons {
            let parse_result: Result<PolicyProposal, _> = serde_json::from_str(corrupted);
            // Should either fail to parse or handle gracefully if parsed
            match parse_result {
                Ok(parsed_proposal) => {
                    // If it parses, envelope check should not panic
                    let _envelope_result = env.is_within_envelope(&parsed_proposal);
                }
                Err(_) => {
                    // Parsing failure is acceptable for corrupted input
                }
            }
        }

        // Test manifest corruption detection
        let manifest = env.to_manifest_json();
        let manifest_json = serde_json::to_string(&manifest).unwrap();
        let reparsed_manifest: serde_json::Value = serde_json::from_str(&manifest_json).unwrap();

        // Verify critical fields preserved
        assert_eq!(manifest["schema_version"], reparsed_manifest["schema_version"]);
        assert_eq!(manifest["invariant_count"], reparsed_manifest["invariant_count"]);
        assert_eq!(manifest["immutable_field_count"], reparsed_manifest["immutable_field_count"]);
    }

    #[test]
    fn negative_field_validation_bypass_via_encoding_tricks() {
        let env = CorrectnessEnvelope::canonical();

        // Test various encoding tricks to bypass field validation
        let encoding_tricks = vec![
            // URL encoding attempts
            ("hardening%2Edirection", false),
            ("hardening%2edirection", false),
            ("hardening.direction%00", false),

            // HTML entity encoding attempts
            ("hardening&period;direction", false),
            ("hardening&#46;direction", false),
            ("hardening&#x2E;direction", false),

            // Base64 encoding attempts
            ("aGFyZGVuaW5nLmRpcmVjdGlvbg==", false), // "hardening.direction" in base64

            // Hex encoding attempts
            ("\\x68\\x61\\x72\\x64\\x65\\x6E\\x69\\x6E\\x67\\x2E\\x64\\x69\\x72\\x65\\x63\\x74\\x69\\x6F\\x6E", false),

            // Unicode escape attempts
            ("\\u0068\\u0061\\u0072\\u0064\\u0065\\u006E\\u0069\\u006E\\u0067\\u002E\\u0064\\u0069\\u0072\\u0065\\u0063\\u0074\\u0069\\u006F\\u006E", false),

            // Case variations (should pass since we do exact matching)
            ("Hardening.Direction", false),
            ("HARDENING.DIRECTION", false),
            ("hardening.DIRECTION", false),

            // Homograph attacks using lookalike Unicode
            ("hardеning.direction", false), // Cyrillic 'е' instead of 'e'
            ("hardening.direсtion", false), // Cyrillic 'с' instead of 'c'
            ("hаrdening.direction", false), // Cyrillic 'а' instead of 'a'

            // Actual field (should violate)
            ("hardening.direction", true),
        ];

        for (field, should_violate) in encoding_tricks {
            let proposal = PolicyProposal {
                proposal_id: format!("encoding-bypass-{}", field.len()),
                controller_id: "encoding-attacker".to_string(),
                epoch_id: 1,
                changes: vec![PolicyChange {
                    field: field.to_string(),
                    old_value: serde_json::json!(true),
                    new_value: serde_json::json!(false),
                }],
            };

            let result = env.is_within_envelope(&proposal);
            if should_violate {
                assert!(result.is_err(), "Encoded field '{}' should violate envelope", field);
                let err = result.unwrap_err();
                assert_eq!(err.invariant_id.as_str(), "INV-001-MONOTONIC-HARDENING");
            } else {
                assert!(result.is_ok(), "Encoded field '{}' should not bypass validation", field);
            }
        }

        // Test normalization consistency
        let normalized_test_fields = vec![
            "hardening.direction",
            "hardening.direction\u{0301}", // With combining character
            "hardening.direction\u{FEFF}", // With BOM
            "hardening.direction\u{200B}", // With zero-width space
        ];

        for field in normalized_test_fields {
            let proposal = PolicyProposal {
                proposal_id: format!("normalization-{}", field.len()),
                controller_id: "normalization-tester".to_string(),
                epoch_id: 1,
                changes: vec![PolicyChange {
                    field: field.to_string(),
                    old_value: serde_json::json!(true),
                    new_value: serde_json::json!(false),
                }],
            };

            let result = env.is_within_envelope(&proposal);

            if field == "hardening.direction" {
                assert!(result.is_err(), "Base field should violate");
            } else {
                // Unicode variations should NOT match (no normalization)
                assert!(result.is_ok(), "Unicode variation '{}' should not match", field.escape_unicode());
            }
        }
    }

    #[test]
    fn negative_cross_field_dependency_violation_patterns() {
        let env = CorrectnessEnvelope::canonical();

        // Test proposals with multiple changes that could interact unexpectedly
        let cross_dependency_proposals = vec![
            // Multiple immutable field violations in one proposal
            PolicyProposal {
                proposal_id: "multi-violation".to_string(),
                controller_id: "multi-attacker".to_string(),
                epoch_id: 1,
                changes: vec![
                    PolicyChange {
                        field: "hardening.direction".to_string(), // Violation 1
                        old_value: serde_json::json!(true),
                        new_value: serde_json::json!(false),
                    },
                    PolicyChange {
                        field: "evidence.suppress".to_string(), // Violation 2
                        old_value: serde_json::json!(false),
                        new_value: serde_json::json!(true),
                    },
                    PolicyChange {
                        field: "epoch.decrement".to_string(), // Violation 3
                        old_value: serde_json::json!(100),
                        new_value: serde_json::json!(99),
                    },
                ],
            },

            // Mixed violations with tunable fields
            PolicyProposal {
                proposal_id: "mixed-violations".to_string(),
                controller_id: "mixed-attacker".to_string(),
                epoch_id: 2,
                changes: vec![
                    PolicyChange {
                        field: "tunable.parameter1".to_string(), // OK
                        old_value: serde_json::json!(10),
                        new_value: serde_json::json!(20),
                    },
                    PolicyChange {
                        field: "seed.algorithm".to_string(), // Violation
                        old_value: serde_json::json!("sha256"),
                        new_value: serde_json::json!("md5"),
                    },
                    PolicyChange {
                        field: "tunable.parameter2".to_string(), // OK
                        old_value: serde_json::json!("value1"),
                        new_value: serde_json::json!("value2"),
                    },
                ],
            },
        ];

        for proposal in cross_dependency_proposals {
            let result = env.is_within_envelope(&proposal);
            assert!(result.is_err(), "Cross-dependency proposal should be rejected");

            // Should fail on FIRST violation encountered, not later ones
            let err = result.unwrap_err();

            // Verify it's one of the expected invariant violations
            assert!(
                err.invariant_id.as_str() == "INV-001-MONOTONIC-HARDENING" ||
                err.invariant_id.as_str() == "INV-002-EVIDENCE-EMISSION" ||
                err.invariant_id.as_str() == "INV-006-EPOCH-MONOTONIC" ||
                err.invariant_id.as_str() == "INV-003-DETERMINISTIC-SEED",
                "Unexpected invariant violation: {}", err.invariant_id
            );
        }

        // Test dependency chain simulation
        let mut dependent_changes = Vec::new();
        for i in 0..100 {
            dependent_changes.push(PolicyChange {
                field: format!("chain.level_{}.param", i),
                old_value: serde_json::json!(i),
                new_value: serde_json::json!(i + 1),
            });
        }

        // Add violation at the end
        dependent_changes.push(PolicyChange {
            field: "integrity.bypass_hash_check".to_string(),
            old_value: serde_json::json!(false),
            new_value: serde_json::json!(true),
        });

        let chain_proposal = PolicyProposal {
            proposal_id: "dependency-chain".to_string(),
            controller_id: "chain-attacker".to_string(),
            epoch_id: 3,
            changes: dependent_changes,
        };

        let result = env.is_within_envelope(&chain_proposal);
        assert!(result.is_err(), "Chain proposal with violation should be rejected");

        let err = result.unwrap_err();
        assert_eq!(err.invariant_id.as_str(), "INV-004-INTEGRITY-PROOF-VERIFICATION");
        assert_eq!(err.proposal_field, "integrity.bypass_hash_check");
    }

    #[test]
    fn negative_error_propagation_chain_and_recovery_testing() {
        // Test error propagation and recovery scenarios

        // Test with malformed envelope (missing invariant definitions)
        let malformed_env = CorrectnessEnvelope {
            invariants: Vec::new(), // Empty invariants
            immutable_fields: vec![
                ("test.field1".to_string(), InvariantId::new("INV-MISSING-1")),
                ("test.field2".to_string(), InvariantId::new("INV-MISSING-2")),
                ("test.field3".to_string(), InvariantId::new("INV-MISSING-3")),
            ],
        };

        // Test error propagation through multiple missing invariants
        let error_chain_proposals = vec![
            ("test.field1", "INV-MISSING-1"),
            ("test.field2", "INV-MISSING-2"),
            ("test.field3", "INV-MISSING-3"),
            ("test.field1.subfield", "INV-MISSING-1"), // Nested field
        ];

        for (field, expected_inv_id) in error_chain_proposals {
            let proposal = PolicyProposal {
                proposal_id: format!("error-chain-{}", field.replace(".", "-")),
                controller_id: "error-tester".to_string(),
                epoch_id: 1,
                changes: vec![PolicyChange {
                    field: field.to_string(),
                    old_value: serde_json::json!(null),
                    new_value: serde_json::json!(true),
                }],
            };

            let result = malformed_env.is_within_envelope(&proposal);
            assert!(result.is_err(), "Malformed envelope should produce error for field '{}'", field);

            let err = result.unwrap_err();
            assert_eq!(err.invariant_id.as_str(), expected_inv_id);
            assert_eq!(err.invariant_name, "missing invariant definition");
            assert!(err.reason.contains("definition is missing"));
        }

        // Test error recovery with partially valid envelope
        let partial_env = CorrectnessEnvelope {
            invariants: vec![
                Invariant {
                    id: InvariantId::new("INV-VALID-ONLY"),
                    name: "Valid Invariant".to_string(),
                    description: "A single valid invariant".to_string(),
                    owner_track: SectionId::new("10.14"),
                    enforcement: EnforcementMode::Runtime,
                }
            ],
            immutable_fields: vec![
                ("valid.field".to_string(), InvariantId::new("INV-VALID-ONLY")),
                ("invalid.field".to_string(), InvariantId::new("INV-MISSING")),
            ],
        };

        let recovery_tests = vec![
            ("valid.field", true, "Should reject valid field with valid invariant"),
            ("invalid.field", true, "Should reject invalid field with missing invariant"),
            ("unrelated.field", false, "Should allow unrelated field"),
        ];

        for (field, should_error, description) in recovery_tests {
            let proposal = PolicyProposal {
                proposal_id: format!("recovery-{}", field.replace(".", "-")),
                controller_id: "recovery-tester".to_string(),
                epoch_id: 1,
                changes: vec![PolicyChange {
                    field: field.to_string(),
                    old_value: serde_json::json!(false),
                    new_value: serde_json::json!(true),
                }],
            };

            let result = partial_env.is_within_envelope(&proposal);
            if should_error {
                assert!(result.is_err(), "{}", description);
            } else {
                assert!(result.is_ok(), "{}", description);
            }
        }

        // Test error state preservation across multiple checks
        let multi_check_proposal = PolicyProposal {
            proposal_id: "multi-check".to_string(),
            controller_id: "multi-checker".to_string(),
            epoch_id: 1,
            changes: vec![PolicyChange {
                field: "hardening.direction".to_string(),
                old_value: serde_json::json!(true),
                new_value: serde_json::json!(false),
            }],
        };

        let canonical_env = CorrectnessEnvelope::canonical();

        // Multiple checks should produce identical errors
        let error1 = canonical_env.is_within_envelope(&multi_check_proposal).unwrap_err();
        let error2 = canonical_env.is_within_envelope(&multi_check_proposal).unwrap_err();
        let error3 = canonical_env.is_within_envelope(&multi_check_proposal).unwrap_err();

        assert_eq!(error1.invariant_id, error2.invariant_id);
        assert_eq!(error2.invariant_id, error3.invariant_id);
        assert_eq!(error1.proposal_field, error2.proposal_field);
        assert_eq!(error2.proposal_field, error3.proposal_field);
        assert_eq!(error1.reason, error2.reason);
        assert_eq!(error2.reason, error3.reason);
    }
}
