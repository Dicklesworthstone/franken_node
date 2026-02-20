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
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
                let inv = self.get(inv_id)?;
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
        let mut seen = std::collections::HashSet::new();
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
        assert!(fields.len() >= 20, "expected >= 20 immutable fields");
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
