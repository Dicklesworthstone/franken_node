//! bd-b9b6: Durability contract violation diagnostic bundles.
//!
//! When hardening is fully exhausted and verifiability cannot be restored,
//! emit a comprehensive diagnostic bundle capturing the full causal chain.
//! This is the last-resort safety mechanism: fail-safe with full diagnostic context.
//!
//! # Invariants
//!
//! - INV-VIOLATION-DETERMINISTIC: identical context produces identical bundle
//! - INV-VIOLATION-CAUSAL: bundle includes complete causal event chain
//! - INV-VIOLATION-HALT: gating operations blocked after emission

use sha2::{Digest, Sha256};
use std::fmt;

use serde_json::json;

const MAX_ACTIVE_HALTS: usize = 4096;
const MAX_BUNDLES: usize = 4096;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

/// Stable event codes for structured logging.
pub mod event_codes {
    pub const VIOLATION_BUNDLE_GENERATED: &str = "EVD-VIOLATION-001";
    pub const VIOLATION_GATING_HALTED: &str = "EVD-VIOLATION-002";
    pub const VIOLATION_HALT_CLEARED: &str = "EVD-VIOLATION-003";
    pub const VIOLATION_OP_REJECTED: &str = "EVD-VIOLATION-004";
}

// ── BundleId ───────────────────────────────────────────────────────

/// Deterministically-derived bundle identifier.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BundleId(pub String);

impl BundleId {
    pub fn new(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for BundleId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

// ── CausalEvent ────────────────────────────────────────────────────

/// An event in the causal chain leading to a durability violation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CausalEvent {
    /// What happened.
    pub event_type: CausalEventType,
    /// When it happened (monotonic ms).
    pub timestamp_ms: u64,
    /// Human-readable description.
    pub description: String,
    /// Reference to related evidence entry, if any.
    pub evidence_ref: Option<String>,
}

/// Classification of causal events.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CausalEventType {
    /// A guardrail rejection occurred.
    GuardrailRejection,
    /// Hardening was escalated.
    HardeningEscalation,
    /// A repair attempt failed.
    RepairFailed,
    /// An integrity check failed.
    IntegrityCheckFailed,
    /// An artifact became unverifiable.
    ArtifactUnverifiable,
}

impl CausalEventType {
    pub fn label(&self) -> &'static str {
        match self {
            Self::GuardrailRejection => "guardrail_rejection",
            Self::HardeningEscalation => "hardening_escalation",
            Self::RepairFailed => "repair_failed",
            Self::IntegrityCheckFailed => "integrity_check_failed",
            Self::ArtifactUnverifiable => "artifact_unverifiable",
        }
    }

    pub fn all() -> &'static [CausalEventType] {
        &[
            Self::GuardrailRejection,
            Self::HardeningEscalation,
            Self::RepairFailed,
            Self::IntegrityCheckFailed,
            Self::ArtifactUnverifiable,
        ]
    }
}

impl fmt::Display for CausalEventType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ── FailedArtifact ─────────────────────────────────────────────────

/// An artifact that could not be verified.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct FailedArtifact {
    /// Path or identifier of the artifact.
    pub artifact_path: String,
    /// Expected integrity hash (hex).
    pub expected_hash: String,
    /// Actual computed hash (hex), or empty if unavailable.
    pub actual_hash: String,
    /// Why verification failed.
    pub failure_reason: String,
}

// ── ProofContext ───────────────────────────────────────────────────

/// State of proof verification at violation time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProofContext {
    /// Proofs that were attempted and failed.
    pub failed_proofs: Vec<String>,
    /// Proofs that are missing entirely.
    pub missing_proofs: Vec<String>,
    /// Proofs that passed (for context).
    pub passed_proofs: Vec<String>,
}

impl ProofContext {
    pub fn new() -> Self {
        Self {
            failed_proofs: Vec::new(),
            missing_proofs: Vec::new(),
            passed_proofs: Vec::new(),
        }
    }

    /// Total number of proofs examined.
    pub fn total(&self) -> usize {
        self.failed_proofs
            .len()
            .saturating_add(self.missing_proofs.len())
            .saturating_add(self.passed_proofs.len())
    }

    /// Whether all proofs are in a failure/missing state.
    pub fn all_failed(&self) -> bool {
        self.passed_proofs.is_empty() && self.total() > 0
    }
}

impl Default for ProofContext {
    fn default() -> Self {
        Self::new()
    }
}

// ── HaltPolicy ─────────────────────────────────────────────────────

/// Policy for halting operations after a violation.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum HaltPolicy {
    /// Halt all durable-claiming operations globally.
    HaltAll,
    /// Halt operations only for the specified scope.
    HaltScope(String),
    /// Emit warning but don't halt operations.
    WarnOnly,
}

impl HaltPolicy {
    pub fn label(&self) -> &str {
        match self {
            Self::HaltAll => "halt_all",
            Self::HaltScope(_) => "halt_scope",
            Self::WarnOnly => "warn_only",
        }
    }
}

impl fmt::Display for HaltPolicy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HaltAll => write!(f, "halt_all"),
            Self::HaltScope(scope) => write!(f, "halt_scope({scope})"),
            Self::WarnOnly => write!(f, "warn_only"),
        }
    }
}

// ── ViolationBundle ────────────────────────────────────────────────

/// Comprehensive diagnostic bundle for a durability contract violation.
#[derive(Debug, Clone, PartialEq)]
pub struct ViolationBundle {
    /// Deterministically-derived identifier.
    pub bundle_id: BundleId,
    /// Ordered causal event chain.
    pub causal_event_sequence: Vec<CausalEvent>,
    /// Artifacts that could not be verified.
    pub failed_artifacts: Vec<FailedArtifact>,
    /// Proof verification state at violation time.
    pub proof_context: ProofContext,
    /// Hardening level at time of violation.
    pub hardening_level: String,
    /// Monotonic timestamp.
    pub timestamp_ms: u64,
    /// Epoch at time of violation.
    pub epoch_id: u64,
}

impl ViolationBundle {
    /// Number of causal events.
    pub fn event_count(&self) -> usize {
        self.causal_event_sequence.len()
    }

    /// Number of failed artifacts.
    pub fn artifact_count(&self) -> usize {
        self.failed_artifacts.len()
    }

    /// Serialize as JSON for export.
    pub fn to_json(&self) -> String {
        let causal_events: Vec<serde_json::Value> = self
            .causal_event_sequence
            .iter()
            .map(|e| {
                json!({
                    "type": e.event_type.label(),
                    "timestamp_ms": e.timestamp_ms,
                    "description": &e.description,
                    "evidence_ref": &e.evidence_ref,
                })
            })
            .collect();

        let failed_artifacts: Vec<serde_json::Value> = self
            .failed_artifacts
            .iter()
            .map(|a| {
                json!({
                    "path": &a.artifact_path,
                    "expected_hash": &a.expected_hash,
                    "actual_hash": &a.actual_hash,
                    "reason": &a.failure_reason,
                })
            })
            .collect();

        json!({
            "bundle_id": self.bundle_id.as_str(),
            "event_count": self.event_count(),
            "artifact_count": self.artifact_count(),
            "hardening_level": self.hardening_level,
            "epoch_id": self.epoch_id,
            "timestamp_ms": self.timestamp_ms,
            "causal_events": causal_events,
            "failed_artifacts": failed_artifacts,
            "proof_context": {
                "failed_proofs": &self.proof_context.failed_proofs,
                "missing_proofs": &self.proof_context.missing_proofs,
                "passed_proofs": &self.proof_context.passed_proofs,
            }
        })
        .to_string()
    }
}

// ── ViolationContext ───────────────────────────────────────────────

/// Input context for generating a violation bundle.
#[derive(Debug, Clone)]
pub struct ViolationContext {
    /// Causal events leading to the violation.
    pub events: Vec<CausalEvent>,
    /// Failed artifacts.
    pub artifacts: Vec<FailedArtifact>,
    /// Proof context.
    pub proofs: ProofContext,
    /// Current hardening level label.
    pub hardening_level: String,
    /// Current epoch.
    pub epoch_id: u64,
    /// Timestamp of violation detection.
    pub timestamp_ms: u64,
}

// ── DurabilityViolationDetector ────────────────────────────────────

/// Detects durability violations and manages operational halts.
///
/// INV-VIOLATION-DETERMINISTIC: same context -> same bundle.
/// INV-VIOLATION-CAUSAL: complete causal chain in every bundle.
/// INV-VIOLATION-HALT: gating halted after emission.
#[derive(Debug)]
pub struct DurabilityViolationDetector {
    /// Halt policy.
    halt_policy: HaltPolicy,
    /// Active halt bundle IDs.
    active_halts: Vec<BundleId>,
    /// Generated bundles.
    bundles: Vec<ViolationBundle>,
}

impl DurabilityViolationDetector {
    /// Create with the given halt policy.
    pub fn new(policy: HaltPolicy) -> Self {
        Self {
            halt_policy: policy,
            active_halts: Vec::new(),
            bundles: Vec::new(),
        }
    }

    /// Create with default HaltAll policy.
    pub fn with_defaults() -> Self {
        Self::new(HaltPolicy::HaltAll)
    }

    /// Get the halt policy.
    pub fn halt_policy(&self) -> &HaltPolicy {
        &self.halt_policy
    }

    /// Get all generated bundles.
    pub fn bundles(&self) -> &[ViolationBundle] {
        &self.bundles
    }

    /// Number of bundles generated.
    pub fn bundle_count(&self) -> usize {
        self.bundles.len()
    }

    /// Whether operations are currently halted.
    pub fn is_halted(&self) -> bool {
        !self.active_halts.is_empty()
    }

    /// Whether a specific scope is halted.
    pub fn is_scope_halted(&self, _scope: &str) -> bool {
        match &self.halt_policy {
            HaltPolicy::HaltAll => self.is_halted(),
            HaltPolicy::HaltScope(s) => self.is_halted() && _scope == s,
            HaltPolicy::WarnOnly => false,
        }
    }

    /// Get active halt bundle IDs.
    pub fn active_halts(&self) -> &[BundleId] {
        &self.active_halts
    }

    /// Generate a violation bundle from the given context.
    ///
    /// Deterministic: identical context produces identical bundle.
    pub fn generate_bundle(&mut self, context: &ViolationContext) -> &ViolationBundle {
        let bundle = generate_bundle(context);
        let bundle_id = bundle.bundle_id.clone();

        // Apply halt policy
        match &self.halt_policy {
            HaltPolicy::HaltAll | HaltPolicy::HaltScope(_) => {
                push_bounded(&mut self.active_halts, bundle_id, MAX_ACTIVE_HALTS);
            }
            HaltPolicy::WarnOnly => {}
        }

        push_bounded(&mut self.bundles, bundle, MAX_BUNDLES);
        let idx = self.bundles.len().saturating_sub(1);
        &self.bundles[idx]
    }

    /// Check if a durable operation is allowed.
    ///
    /// Returns Ok(()) if allowed, Err with the blocking bundle_id if halted.
    pub fn check_durable_op(&self, scope: &str) -> Result<(), DurabilityHaltedError> {
        if self.active_halts.is_empty() {
            return Ok(());
        }

        let last_halt = || {
            self.active_halts
                .last()
                .cloned()
                .unwrap_or_else(|| BundleId::new("unknown".to_string()))
        };
        match &self.halt_policy {
            HaltPolicy::HaltAll => Err(DurabilityHaltedError {
                bundle_id: last_halt(),
                scope: scope.to_string(),
            }),
            HaltPolicy::HaltScope(halt_scope) if halt_scope == scope => {
                Err(DurabilityHaltedError {
                    bundle_id: last_halt(),
                    scope: scope.to_string(),
                })
            }
            _ => Ok(()),
        }
    }

    /// Clear halt state (after remediation).
    pub fn clear_halt(&mut self) {
        self.active_halts.clear();
    }
}

/// Error returned when a durable operation is blocked by a violation halt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DurabilityHaltedError {
    pub bundle_id: BundleId,
    pub scope: String,
}

impl fmt::Display for DurabilityHaltedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: bundle_id={}, scope={}",
            event_codes::VIOLATION_OP_REJECTED,
            self.bundle_id,
            self.scope
        )
    }
}

impl std::error::Error for DurabilityHaltedError {}

// ── Bundle generation (deterministic) ──────────────────────────────

fn hash_len(len: usize) -> [u8; 8] {
    u64::try_from(len).unwrap_or(u64::MAX).to_le_bytes()
}

fn update_hash_u64(hasher: &mut Sha256, domain: &'static [u8], value: u64) {
    hasher.update(domain);
    hasher.update(value.to_le_bytes());
}

fn update_hash_bytes(hasher: &mut Sha256, domain: &'static [u8], value: &[u8]) {
    hasher.update(domain);
    hasher.update(hash_len(value.len()));
    hasher.update(value);
}

fn update_hash_string_list(hasher: &mut Sha256, domain: &'static [u8], values: &[String]) {
    hasher.update(domain);
    hasher.update(hash_len(values.len()));
    for value in values {
        update_hash_bytes(
            hasher,
            b"durability_violation_bundle_v1:string_list_item",
            value.as_bytes(),
        );
    }
}

/// Generate a violation bundle deterministically from context.
pub fn generate_bundle(context: &ViolationContext) -> ViolationBundle {
    // Derive bundle_id deterministically from content.
    // Length-prefix variable-length strings and domain-separate fields to
    // prevent delimiter, section, and optional-field collisions.
    let mut hasher = Sha256::new();
    hasher.update(b"franken_node:observability:durability_violation_bundle:v1");
    update_hash_u64(
        &mut hasher,
        b"durability_violation_bundle_v1:epoch_id",
        context.epoch_id,
    );
    update_hash_u64(
        &mut hasher,
        b"durability_violation_bundle_v1:timestamp_ms",
        context.timestamp_ms,
    );
    update_hash_bytes(
        &mut hasher,
        b"durability_violation_bundle_v1:hardening_level",
        context.hardening_level.as_bytes(),
    );
    hasher.update(b"durability_violation_bundle_v1:events");
    hasher.update(hash_len(context.events.len()));
    for event in &context.events {
        let label = event.event_type.label();
        hasher.update(b"durability_violation_bundle_v1:event");
        update_hash_bytes(
            &mut hasher,
            b"durability_violation_bundle_v1:event_type",
            label.as_bytes(),
        );
        update_hash_u64(
            &mut hasher,
            b"durability_violation_bundle_v1:event_timestamp_ms",
            event.timestamp_ms,
        );
        update_hash_bytes(
            &mut hasher,
            b"durability_violation_bundle_v1:event_description",
            event.description.as_bytes(),
        );
        match &event.evidence_ref {
            Some(eref) => update_hash_bytes(
                &mut hasher,
                b"durability_violation_bundle_v1:event_evidence_ref_some",
                eref.as_bytes(),
            ),
            None => hasher.update(b"durability_violation_bundle_v1:event_evidence_ref_none"),
        }
    }
    hasher.update(b"durability_violation_bundle_v1:artifacts");
    hasher.update(hash_len(context.artifacts.len()));
    for artifact in &context.artifacts {
        hasher.update(b"durability_violation_bundle_v1:artifact");
        update_hash_bytes(
            &mut hasher,
            b"durability_violation_bundle_v1:artifact_path",
            artifact.artifact_path.as_bytes(),
        );
        update_hash_bytes(
            &mut hasher,
            b"durability_violation_bundle_v1:artifact_expected_hash",
            artifact.expected_hash.as_bytes(),
        );
        update_hash_bytes(
            &mut hasher,
            b"durability_violation_bundle_v1:artifact_actual_hash",
            artifact.actual_hash.as_bytes(),
        );
        update_hash_bytes(
            &mut hasher,
            b"durability_violation_bundle_v1:artifact_failure_reason",
            artifact.failure_reason.as_bytes(),
        );
    }
    update_hash_string_list(
        &mut hasher,
        b"durability_violation_bundle_v1:proofs_failed",
        &context.proofs.failed_proofs,
    );
    update_hash_string_list(
        &mut hasher,
        b"durability_violation_bundle_v1:proofs_missing",
        &context.proofs.missing_proofs,
    );
    update_hash_string_list(
        &mut hasher,
        b"durability_violation_bundle_v1:proofs_passed",
        &context.proofs.passed_proofs,
    );
    let digest = hasher.finalize();
    let hash = u64::from_le_bytes(digest[..8].try_into().unwrap_or([0u8; 8]));
    let bundle_id = BundleId::new(format!("VB-{hash:016x}"));

    ViolationBundle {
        bundle_id,
        causal_event_sequence: context.events.clone(),
        failed_artifacts: context.artifacts.clone(),
        proof_context: context.proofs.clone(),
        hardening_level: context.hardening_level.clone(),
        timestamp_ms: context.timestamp_ms,
        epoch_id: context.epoch_id,
    }
}

// ── Tests ──────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_context() -> ViolationContext {
        ViolationContext {
            events: vec![
                CausalEvent {
                    event_type: CausalEventType::GuardrailRejection,
                    timestamp_ms: 1000,
                    description: "memory budget exceeded".into(),
                    evidence_ref: Some("EVD-001".into()),
                },
                CausalEvent {
                    event_type: CausalEventType::HardeningEscalation,
                    timestamp_ms: 1001,
                    description: "escalated to critical".into(),
                    evidence_ref: Some("EVD-002".into()),
                },
                CausalEvent {
                    event_type: CausalEventType::RepairFailed,
                    timestamp_ms: 1500,
                    description: "repair attempt failed: no backup".into(),
                    evidence_ref: None,
                },
            ],
            artifacts: vec![FailedArtifact {
                artifact_path: "objects/abc123".into(),
                expected_hash: "deadbeef".into(),
                actual_hash: "00000000".into(),
                failure_reason: "hash mismatch after repair".into(),
            }],
            proofs: ProofContext {
                failed_proofs: vec!["proof-abc".into()],
                missing_proofs: vec!["proof-def".into()],
                passed_proofs: vec!["proof-ghi".into()],
            },
            hardening_level: "critical".into(),
            epoch_id: 42,
            timestamp_ms: 2000,
        }
    }

    fn bundle_id_for(context: &ViolationContext) -> BundleId {
        generate_bundle(context).bundle_id
    }

    // ── BundleId tests ──

    #[test]
    fn bundle_id_display() {
        let id = BundleId::new("VB-001");
        assert_eq!(id.to_string(), "VB-001");
        assert_eq!(id.as_str(), "VB-001");
    }

    // ── CausalEventType tests ──

    #[test]
    fn causal_event_type_labels() {
        assert_eq!(
            CausalEventType::GuardrailRejection.label(),
            "guardrail_rejection"
        );
        assert_eq!(
            CausalEventType::HardeningEscalation.label(),
            "hardening_escalation"
        );
        assert_eq!(CausalEventType::RepairFailed.label(), "repair_failed");
        assert_eq!(
            CausalEventType::IntegrityCheckFailed.label(),
            "integrity_check_failed"
        );
        assert_eq!(
            CausalEventType::ArtifactUnverifiable.label(),
            "artifact_unverifiable"
        );
    }

    #[test]
    fn causal_event_type_all() {
        assert_eq!(CausalEventType::all().len(), 5);
    }

    #[test]
    fn causal_event_type_display() {
        assert_eq!(CausalEventType::RepairFailed.to_string(), "repair_failed");
    }

    // ── ProofContext tests ──

    #[test]
    fn proof_context_empty() {
        let ctx = ProofContext::new();
        assert_eq!(ctx.total(), 0);
        assert!(!ctx.all_failed()); // empty is not "all failed"
    }

    #[test]
    fn proof_context_all_failed() {
        let ctx = ProofContext {
            failed_proofs: vec!["p1".into()],
            missing_proofs: vec!["p2".into()],
            passed_proofs: vec![],
        };
        assert!(ctx.all_failed());
        assert_eq!(ctx.total(), 2);
    }

    #[test]
    fn proof_context_not_all_failed() {
        let ctx = ProofContext {
            failed_proofs: vec!["p1".into()],
            missing_proofs: vec![],
            passed_proofs: vec!["p2".into()],
        };
        assert!(!ctx.all_failed());
    }

    // ── HaltPolicy tests ──

    #[test]
    fn halt_policy_labels() {
        assert_eq!(HaltPolicy::HaltAll.label(), "halt_all");
        assert_eq!(HaltPolicy::HaltScope("test".into()).label(), "halt_scope");
        assert_eq!(HaltPolicy::WarnOnly.label(), "warn_only");
    }

    #[test]
    fn halt_policy_display() {
        assert_eq!(HaltPolicy::HaltAll.to_string(), "halt_all");
        assert_eq!(
            HaltPolicy::HaltScope("db".into()).to_string(),
            "halt_scope(db)"
        );
        assert_eq!(HaltPolicy::WarnOnly.to_string(), "warn_only");
    }

    // ── Bundle generation ──

    #[test]
    fn generate_bundle_from_context() {
        let ctx = make_context();
        let bundle = generate_bundle(&ctx);

        assert!(!bundle.bundle_id.as_str().is_empty());
        assert!(bundle.bundle_id.as_str().starts_with("VB-"));
        assert_eq!(bundle.event_count(), 3);
        assert_eq!(bundle.artifact_count(), 1);
        assert_eq!(bundle.hardening_level, "critical");
        assert_eq!(bundle.epoch_id, 42);
        assert_eq!(bundle.timestamp_ms, 2000);
    }

    #[test]
    fn bundle_determinism() {
        let ctx = make_context();
        let bundle1 = generate_bundle(&ctx);
        let bundle2 = generate_bundle(&ctx);

        assert_eq!(bundle1.bundle_id, bundle2.bundle_id);
        assert_eq!(bundle1.event_count(), bundle2.event_count());
        assert_eq!(bundle1.artifact_count(), bundle2.artifact_count());
    }

    #[test]
    fn bundle_determinism_100_runs() {
        let ctx = make_context();
        let reference = generate_bundle(&ctx);

        for i in 0..100 {
            let bundle = generate_bundle(&ctx);
            assert_eq!(
                bundle.bundle_id, reference.bundle_id,
                "bundle_id mismatch on run {i}"
            );
        }
    }

    #[test]
    fn different_context_different_bundle_id() {
        let ctx1 = make_context();
        let mut ctx2 = make_context();
        ctx2.epoch_id = 99;

        let b1 = generate_bundle(&ctx1);
        let b2 = generate_bundle(&ctx2);
        assert_ne!(b1.bundle_id, b2.bundle_id);
    }

    #[test]
    fn artifact_actual_hash_change_changes_bundle_id() {
        let ctx1 = make_context();
        let mut ctx2 = make_context();
        ctx2.artifacts[0].actual_hash = "feedface".into();

        let b1 = generate_bundle(&ctx1);
        let b2 = generate_bundle(&ctx2);
        assert_ne!(b1.bundle_id, b2.bundle_id);
    }

    #[test]
    fn event_evidence_ref_change_changes_bundle_id() {
        let ctx1 = make_context();
        let mut ctx2 = make_context();
        ctx2.events[0].evidence_ref = Some("EVD-ALT".into());

        let b1 = generate_bundle(&ctx1);
        let b2 = generate_bundle(&ctx2);
        assert_ne!(b1.bundle_id, b2.bundle_id);
    }

    #[test]
    fn artifact_failure_reason_change_changes_bundle_id() {
        let ctx1 = make_context();
        let mut ctx2 = make_context();
        ctx2.artifacts[0].failure_reason = "signature was missing".into();

        let b1 = generate_bundle(&ctx1);
        let b2 = generate_bundle(&ctx2);
        assert_ne!(b1.bundle_id, b2.bundle_id);
    }

    #[test]
    fn artifact_expected_hash_change_changes_bundle_id() {
        let ctx1 = make_context();
        let mut ctx2 = make_context();
        ctx2.artifacts[0].expected_hash = "cafebabe".into();

        let b1 = generate_bundle(&ctx1);
        let b2 = generate_bundle(&ctx2);
        assert_ne!(b1.bundle_id, b2.bundle_id);
    }

    #[test]
    fn causal_events_ordering_preserved() {
        let ctx = make_context();
        let bundle = generate_bundle(&ctx);

        assert_eq!(
            bundle.causal_event_sequence[0].event_type,
            CausalEventType::GuardrailRejection
        );
        assert_eq!(
            bundle.causal_event_sequence[1].event_type,
            CausalEventType::HardeningEscalation
        );
        assert_eq!(
            bundle.causal_event_sequence[2].event_type,
            CausalEventType::RepairFailed
        );
    }

    #[test]
    fn empty_context_produces_valid_bundle() {
        let ctx = ViolationContext {
            events: vec![],
            artifacts: vec![],
            proofs: ProofContext::new(),
            hardening_level: "critical".into(),
            epoch_id: 1,
            timestamp_ms: 0,
        };
        let bundle = generate_bundle(&ctx);
        assert_eq!(bundle.event_count(), 0);
        assert_eq!(bundle.artifact_count(), 0);
        assert!(!bundle.bundle_id.as_str().is_empty());
    }

    // ── Bundle JSON export ──

    #[test]
    fn bundle_to_json() {
        let ctx = make_context();
        let bundle = generate_bundle(&ctx);
        let json = bundle.to_json();

        assert!(json.contains(&bundle.bundle_id.as_str().to_string()));
        assert!(json.contains("guardrail_rejection"));
        assert!(json.contains("objects/abc123"));
        // Verify it's valid JSON
        let _: serde_json::Value = serde_json::from_str(&json).expect("should succeed");
    }

    #[test]
    fn bundle_to_json_escapes_and_includes_proof_context() {
        let mut ctx = make_context();
        ctx.events[0].description = "quote \"danger\" newline\nok".into();
        ctx.events[0].evidence_ref = Some("EVD-\"A\"".into());
        ctx.artifacts[0].failure_reason = "bad path C:\\tmp\\bundle".into();
        ctx.proofs.missing_proofs.push("proof-\"zzz\"".into());

        let bundle = generate_bundle(&ctx);
        let json = bundle.to_json();
        let parsed: serde_json::Value = serde_json::from_str(&json).expect("should succeed");

        assert_eq!(
            parsed["causal_events"][0]["description"].as_str(),
            Some("quote \"danger\" newline\nok")
        );
        assert_eq!(
            parsed["causal_events"][0]["evidence_ref"].as_str(),
            Some("EVD-\"A\"")
        );
        assert_eq!(
            parsed["failed_artifacts"][0]["reason"].as_str(),
            Some("bad path C:\\tmp\\bundle")
        );
        assert_eq!(
            parsed["proof_context"]["missing_proofs"][1].as_str(),
            Some("proof-\"zzz\"")
        );
    }

    // ── DurabilityViolationDetector tests ──

    #[test]
    fn detector_defaults() {
        let detector = DurabilityViolationDetector::with_defaults();
        assert_eq!(*detector.halt_policy(), HaltPolicy::HaltAll);
        assert!(!detector.is_halted());
        assert_eq!(detector.bundle_count(), 0);
    }

    #[test]
    fn detector_generates_bundle_and_halts() {
        let mut detector = DurabilityViolationDetector::with_defaults();
        let ctx = make_context();

        let bid = detector.generate_bundle(&ctx).bundle_id.clone();
        assert!(detector.is_halted());
        assert_eq!(detector.bundle_count(), 1);
        assert!(!bid.as_str().is_empty());
    }

    #[test]
    fn detector_halt_all_blocks_all_scopes() {
        let mut detector = DurabilityViolationDetector::new(HaltPolicy::HaltAll);
        let ctx = make_context();
        detector.generate_bundle(&ctx);

        assert!(detector.check_durable_op("scope-a").is_err());
        assert!(detector.check_durable_op("scope-b").is_err());
    }

    #[test]
    fn detector_halt_scope_blocks_only_matching() {
        let mut detector =
            DurabilityViolationDetector::new(HaltPolicy::HaltScope("scope-a".into()));
        let ctx = make_context();
        detector.generate_bundle(&ctx);

        assert!(detector.check_durable_op("scope-a").is_err());
        assert!(detector.check_durable_op("scope-b").is_ok());
    }

    #[test]
    fn detector_halt_scope_empty_string_does_not_block_other_scopes() {
        let mut detector = DurabilityViolationDetector::new(HaltPolicy::HaltScope(String::new()));
        let ctx = make_context();
        detector.generate_bundle(&ctx);

        assert!(detector.check_durable_op("").is_err());
        assert!(detector.check_durable_op("db").is_ok());
    }

    #[test]
    fn detector_warn_only_never_blocks() {
        let mut detector = DurabilityViolationDetector::new(HaltPolicy::WarnOnly);
        let ctx = make_context();
        detector.generate_bundle(&ctx);

        assert!(!detector.is_halted());
        assert!(detector.check_durable_op("any-scope").is_ok());
    }

    #[test]
    fn detector_clear_halt() {
        let mut detector = DurabilityViolationDetector::with_defaults();
        let ctx = make_context();
        detector.generate_bundle(&ctx);

        assert!(detector.is_halted());
        detector.clear_halt();
        assert!(!detector.is_halted());
        assert!(detector.check_durable_op("any").is_ok());
    }

    #[test]
    fn detector_op_before_violation_allowed() {
        let detector = DurabilityViolationDetector::with_defaults();
        assert!(detector.check_durable_op("scope-a").is_ok());
    }

    #[test]
    fn halted_error_contains_bundle_id() {
        let mut detector = DurabilityViolationDetector::with_defaults();
        let ctx = make_context();
        let bid = detector.generate_bundle(&ctx).bundle_id.clone();

        let err = detector.check_durable_op("test").unwrap_err();
        assert_eq!(err.bundle_id, bid);
        assert!(err.to_string().contains("EVD-VIOLATION-004"));
    }

    #[test]
    fn halt_all_empty_context_still_rejects_durable_ops() {
        let mut detector = DurabilityViolationDetector::new(HaltPolicy::HaltAll);
        let ctx = ViolationContext {
            events: vec![],
            artifacts: vec![],
            proofs: ProofContext::new(),
            hardening_level: "exhausted".into(),
            epoch_id: 7,
            timestamp_ms: 0,
        };
        let bundle_id = detector.generate_bundle(&ctx).bundle_id.clone();

        let err = detector.check_durable_op("ledger").unwrap_err();

        assert_eq!(err.bundle_id, bundle_id);
        assert_eq!(err.scope, "ledger");
        assert!(detector.is_scope_halted("unrelated"));
    }

    #[test]
    fn scoped_halt_rejects_exact_scope_and_reports_requested_scope() {
        let mut detector = DurabilityViolationDetector::new(HaltPolicy::HaltScope("ledger".into()));
        let ctx = make_context();
        detector.generate_bundle(&ctx);

        let err = detector.check_durable_op("ledger").unwrap_err();

        assert_eq!(err.scope, "ledger");
        assert!(detector.check_durable_op("ledger/child").is_ok());
        assert!(detector.check_durable_op("storage").is_ok());
    }

    #[test]
    fn multiple_halts_rejection_uses_latest_bundle_id() {
        let mut detector = DurabilityViolationDetector::with_defaults();
        let first = make_context();
        let mut second = make_context();
        second.epoch_id = first.epoch_id.saturating_add(1);
        second.timestamp_ms = first.timestamp_ms.saturating_add(1);

        let first_id = detector.generate_bundle(&first).bundle_id.clone();
        let second_id = detector.generate_bundle(&second).bundle_id.clone();
        let err = detector.check_durable_op("any").unwrap_err();

        assert_ne!(first_id, second_id);
        assert_eq!(err.bundle_id, second_id);
        assert_eq!(detector.active_halts().len(), 2);
    }

    #[test]
    fn clearing_scoped_halt_removes_rejection_without_erasing_bundles() {
        let mut detector =
            DurabilityViolationDetector::new(HaltPolicy::HaltScope("tenant-a".into()));
        let ctx = make_context();
        detector.generate_bundle(&ctx);

        assert!(detector.check_durable_op("tenant-a").is_err());
        detector.clear_halt();

        assert!(detector.check_durable_op("tenant-a").is_ok());
        assert_eq!(detector.bundle_count(), 1);
        assert!(detector.active_halts().is_empty());
    }

    #[test]
    fn proof_context_with_only_passed_proofs_is_not_all_failed() {
        let ctx = ProofContext {
            failed_proofs: vec![],
            missing_proofs: vec![],
            passed_proofs: vec!["integrity-proof".into()],
        };

        assert_eq!(ctx.total(), 1);
        assert!(!ctx.all_failed());
    }

    #[test]
    fn proof_context_with_only_missing_proofs_is_all_failed() {
        let ctx = ProofContext {
            failed_proofs: vec![],
            missing_proofs: vec!["retrievability-proof".into()],
            passed_proofs: vec![],
        };

        assert_eq!(ctx.total(), 1);
        assert!(ctx.all_failed());
    }

    #[test]
    fn json_keeps_empty_actual_hash_for_unavailable_artifact() {
        let mut ctx = make_context();
        ctx.artifacts[0].actual_hash = String::new();
        ctx.artifacts[0].failure_reason = "artifact unavailable during replay".into();

        let bundle = generate_bundle(&ctx);
        let parsed: serde_json::Value =
            serde_json::from_str(&bundle.to_json()).expect("bundle JSON should parse");

        assert_eq!(
            parsed["failed_artifacts"][0]["actual_hash"].as_str(),
            Some("")
        );
        assert_eq!(
            parsed["failed_artifacts"][0]["reason"].as_str(),
            Some("artifact unavailable during replay")
        );
    }

    // ── Failed artifact verification ──

    #[test]
    fn failed_artifact_hash_mismatch() {
        let ctx = make_context();
        let bundle = generate_bundle(&ctx);
        let artifact = &bundle.failed_artifacts[0];

        assert_eq!(artifact.expected_hash, "deadbeef");
        assert_eq!(artifact.actual_hash, "00000000");
        assert!(!artifact.failure_reason.is_empty());
    }

    // ── Multiple bundles ──

    #[test]
    fn multiple_bundles_accumulate() {
        let mut detector = DurabilityViolationDetector::with_defaults();
        let ctx1 = make_context();
        let mut ctx2 = make_context();
        ctx2.epoch_id = 100;

        detector.generate_bundle(&ctx1);
        detector.generate_bundle(&ctx2);

        assert_eq!(detector.bundle_count(), 2);
        assert_eq!(detector.active_halts().len(), 2);
    }

    // ── Proof context in bundle ──

    #[test]
    fn bundle_includes_proof_context() {
        let ctx = make_context();
        let bundle = generate_bundle(&ctx);

        assert_eq!(bundle.proof_context.failed_proofs.len(), 1);
        assert_eq!(bundle.proof_context.missing_proofs.len(), 1);
        assert_eq!(bundle.proof_context.passed_proofs.len(), 1);
        assert_eq!(bundle.proof_context.total(), 3);
    }

    // ── Scope halt ──

    #[test]
    fn is_scope_halted_with_halt_all() {
        let mut detector = DurabilityViolationDetector::new(HaltPolicy::HaltAll);
        let ctx = make_context();
        detector.generate_bundle(&ctx);

        assert!(detector.is_scope_halted("any-scope"));
    }

    #[test]
    fn is_scope_halted_with_matching_scope() {
        let mut detector = DurabilityViolationDetector::new(HaltPolicy::HaltScope("db".into()));
        let ctx = make_context();
        detector.generate_bundle(&ctx);

        assert!(detector.is_scope_halted("db"));
        assert!(!detector.is_scope_halted("other"));
    }

    #[test]
    fn is_scope_halted_with_warn_only() {
        let mut detector = DurabilityViolationDetector::new(HaltPolicy::WarnOnly);
        let ctx = make_context();
        detector.generate_bundle(&ctx);

        assert!(!detector.is_scope_halted("any"));
    }

    // ── Delimiter-collision resistance ──

    #[test]
    fn delimiter_collision_hardening_level_vs_event_label() {
        // Old scheme: "critical|guardrail_rejection" == "critical|guardrail" + "|" + "rejection"
        // With length-prefixing, these must produce different bundle IDs.
        let mut ctx1 = make_context();
        ctx1.hardening_level = "critical".into();

        let mut ctx2 = make_context();
        ctx2.hardening_level = "critical|guardrail_rejection".into();
        // Remove first event so event label doesn't contribute
        ctx2.events.clear();

        let b1 = generate_bundle(&ctx1);
        let b2 = generate_bundle(&ctx2);
        assert_ne!(b1.bundle_id, b2.bundle_id);
    }

    #[test]
    fn delimiter_collision_description_vs_evidence_ref() {
        // description="desc|" + evidence_ref="ref" vs description="desc" + "|ref"
        let mut ctx1 = make_context();
        ctx1.events = vec![CausalEvent {
            event_type: CausalEventType::RepairFailed,
            timestamp_ms: 100,
            description: "desc|".into(),
            evidence_ref: Some("ref".into()),
        }];

        let mut ctx2 = make_context();
        ctx2.events = vec![CausalEvent {
            event_type: CausalEventType::RepairFailed,
            timestamp_ms: 100,
            description: "desc".into(),
            evidence_ref: Some("|ref".into()),
        }];

        let b1 = generate_bundle(&ctx1);
        let b2 = generate_bundle(&ctx2);
        assert_ne!(b1.bundle_id, b2.bundle_id);
    }

    #[test]
    fn delimiter_collision_artifact_path_vs_expected_hash() {
        // artifact_path="path|" + expected_hash="hash" vs artifact_path="path" + "|hash"
        let mut ctx1 = make_context();
        ctx1.artifacts = vec![FailedArtifact {
            artifact_path: "path|".into(),
            expected_hash: "hash".into(),
            actual_hash: "ah".into(),
            failure_reason: "reason".into(),
        }];

        let mut ctx2 = make_context();
        ctx2.artifacts = vec![FailedArtifact {
            artifact_path: "path".into(),
            expected_hash: "|hash".into(),
            actual_hash: "ah".into(),
            failure_reason: "reason".into(),
        }];

        let b1 = generate_bundle(&ctx1);
        let b2 = generate_bundle(&ctx2);
        assert_ne!(b1.bundle_id, b2.bundle_id);
    }

    // ── Metamorphic hardening regressions ──

    #[test]
    fn mr_failed_proof_content_rebinds_bundle_id() {
        let ctx1 = make_context();
        let mut ctx2 = make_context();
        ctx2.proofs.failed_proofs[0] = "proof-mutated".into();

        assert_ne!(bundle_id_for(&ctx1), bundle_id_for(&ctx2));
    }

    #[test]
    fn mr_missing_proof_content_rebinds_bundle_id() {
        let ctx1 = make_context();
        let mut ctx2 = make_context();
        ctx2.proofs.missing_proofs[0] = "missing-proof-mutated".into();

        assert_ne!(bundle_id_for(&ctx1), bundle_id_for(&ctx2));
    }

    #[test]
    fn mr_passed_proof_content_rebinds_bundle_id() {
        let ctx1 = make_context();
        let mut ctx2 = make_context();
        ctx2.proofs.passed_proofs[0] = "passed-proof-mutated".into();

        assert_ne!(bundle_id_for(&ctx1), bundle_id_for(&ctx2));
    }

    #[test]
    fn mr_proof_reclassification_rebinds_bundle_id() {
        let mut ctx1 = make_context();
        ctx1.proofs = ProofContext {
            failed_proofs: vec!["proof-x".into()],
            missing_proofs: vec![],
            passed_proofs: vec![],
        };
        let mut ctx2 = make_context();
        ctx2.proofs = ProofContext {
            failed_proofs: vec![],
            missing_proofs: vec![],
            passed_proofs: vec!["proof-x".into()],
        };

        assert_ne!(bundle_id_for(&ctx1), bundle_id_for(&ctx2));
    }

    #[test]
    fn mr_proof_list_delimiter_collision_is_domain_separated() {
        let mut ctx1 = make_context();
        ctx1.proofs = ProofContext {
            failed_proofs: vec!["alpha|".into()],
            missing_proofs: vec!["beta".into()],
            passed_proofs: vec![],
        };
        let mut ctx2 = make_context();
        ctx2.proofs = ProofContext {
            failed_proofs: vec!["alpha".into()],
            missing_proofs: vec!["|beta".into()],
            passed_proofs: vec![],
        };

        assert_ne!(bundle_id_for(&ctx1), bundle_id_for(&ctx2));
    }

    #[test]
    fn mr_causal_event_order_rebinds_bundle_id_without_losing_events() {
        let ctx1 = make_context();
        let mut ctx2 = make_context();
        ctx2.events.swap(0, 1);

        let bundle1 = generate_bundle(&ctx1);
        let bundle2 = generate_bundle(&ctx2);

        assert_ne!(bundle1.bundle_id, bundle2.bundle_id);
        assert_eq!(bundle1.event_count(), bundle2.event_count());
        assert_eq!(ctx1.events.len(), ctx2.events.len());
    }

    #[test]
    fn mr_absent_and_empty_evidence_ref_are_domain_separated() {
        let mut ctx1 = make_context();
        ctx1.events = vec![CausalEvent {
            event_type: CausalEventType::IntegrityCheckFailed,
            timestamp_ms: 1700,
            description: "integrity checker had no evidence ref".into(),
            evidence_ref: None,
        }];
        let mut ctx2 = make_context();
        ctx2.events = vec![CausalEvent {
            event_type: CausalEventType::IntegrityCheckFailed,
            timestamp_ms: 1700,
            description: "integrity checker had no evidence ref".into(),
            evidence_ref: Some(String::new()),
        }];

        let bundle1 = generate_bundle(&ctx1);
        let bundle2 = generate_bundle(&ctx2);
        let json1: serde_json::Value =
            serde_json::from_str(&bundle1.to_json()).expect("bundle JSON should parse");
        let json2: serde_json::Value =
            serde_json::from_str(&bundle2.to_json()).expect("bundle JSON should parse");

        assert_ne!(bundle1.bundle_id, bundle2.bundle_id);
        assert_eq!(bundle1.event_count(), bundle2.event_count());
        assert!(json1["causal_events"][0]["evidence_ref"].is_null());
        assert_eq!(json2["causal_events"][0]["evidence_ref"].as_str(), Some(""));
    }

    #[test]
    fn mr_failed_artifact_order_rebinds_bundle_id_without_losing_artifacts() {
        let mut ctx1 = make_context();
        ctx1.artifacts.push(FailedArtifact {
            artifact_path: "objects/def456".into(),
            expected_hash: "abcd".into(),
            actual_hash: "1234".into(),
            failure_reason: "missing detached signature".into(),
        });
        let mut ctx2 = ctx1.clone();
        ctx2.artifacts.swap(0, 1);

        let bundle1 = generate_bundle(&ctx1);
        let bundle2 = generate_bundle(&ctx2);

        assert_ne!(bundle1.bundle_id, bundle2.bundle_id);
        assert_eq!(bundle1.artifact_count(), bundle2.artifact_count());
    }

    #[test]
    fn mr_extra_causal_event_increments_json_count_and_rebinds_id() {
        let ctx1 = make_context();
        let mut ctx2 = make_context();
        ctx2.events.push(CausalEvent {
            event_type: CausalEventType::ArtifactUnverifiable,
            timestamp_ms: 1600,
            description: "artifact could not be reconstructed".into(),
            evidence_ref: Some("EVD-003".into()),
        });

        let bundle1 = generate_bundle(&ctx1);
        let bundle2 = generate_bundle(&ctx2);
        let parsed: serde_json::Value =
            serde_json::from_str(&bundle2.to_json()).expect("bundle JSON should parse");

        assert_ne!(bundle1.bundle_id, bundle2.bundle_id);
        assert_eq!(bundle2.event_count(), bundle1.event_count() + 1);
        assert_eq!(
            parsed["event_count"].as_u64(),
            Some(u64::try_from(bundle2.event_count()).unwrap_or(u64::MAX))
        );
    }

    #[test]
    fn mr_extra_failed_artifact_increments_json_count_and_rebinds_id() {
        let ctx1 = make_context();
        let mut ctx2 = make_context();
        ctx2.artifacts.push(FailedArtifact {
            artifact_path: "objects/ghi789".into(),
            expected_hash: "eeee".into(),
            actual_hash: "".into(),
            failure_reason: "artifact missing from replay bundle".into(),
        });

        let bundle1 = generate_bundle(&ctx1);
        let bundle2 = generate_bundle(&ctx2);
        let parsed: serde_json::Value =
            serde_json::from_str(&bundle2.to_json()).expect("bundle JSON should parse");

        assert_ne!(bundle1.bundle_id, bundle2.bundle_id);
        assert_eq!(bundle2.artifact_count(), bundle1.artifact_count() + 1);
        assert_eq!(
            parsed["artifact_count"].as_u64(),
            Some(u64::try_from(bundle2.artifact_count()).unwrap_or(u64::MAX))
        );
    }

    #[test]
    fn mr_halt_policy_does_not_rewrite_bundle_identity() {
        let ctx = make_context();
        let expected = bundle_id_for(&ctx);
        let mut halt_all = DurabilityViolationDetector::new(HaltPolicy::HaltAll);
        let mut halt_scope = DurabilityViolationDetector::new(HaltPolicy::HaltScope("db".into()));
        let mut warn_only = DurabilityViolationDetector::new(HaltPolicy::WarnOnly);

        assert_eq!(halt_all.generate_bundle(&ctx).bundle_id, expected);
        assert_eq!(halt_scope.generate_bundle(&ctx).bundle_id, expected);
        assert_eq!(warn_only.generate_bundle(&ctx).bundle_id, expected);
    }

    #[test]
    fn mr_warn_only_records_bundle_without_active_halt() {
        let mut detector = DurabilityViolationDetector::new(HaltPolicy::WarnOnly);
        let ctx = make_context();

        detector.generate_bundle(&ctx);

        assert_eq!(detector.bundle_count(), 1);
        assert!(detector.active_halts().is_empty());
        assert!(!detector.is_halted());
        assert!(detector.check_durable_op("db").is_ok());
    }

    #[test]
    fn mr_clear_halt_is_idempotent_and_preserves_bundles() {
        let mut detector = DurabilityViolationDetector::with_defaults();
        let ctx = make_context();
        detector.generate_bundle(&ctx);

        detector.clear_halt();
        detector.clear_halt();

        assert_eq!(detector.bundle_count(), 1);
        assert!(detector.active_halts().is_empty());
        assert!(detector.check_durable_op("db").is_ok());
    }

    #[test]
    fn push_bounded_zero_capacity_clears_without_panic() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_retains_latest_window_after_over_capacity() {
        let mut items = Vec::new();

        for item in 0..6 {
            push_bounded(&mut items, item, 3);
        }

        assert_eq!(items, vec![3, 4, 5]);
    }
}
