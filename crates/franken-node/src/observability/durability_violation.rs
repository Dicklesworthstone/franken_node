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

use std::collections::hash_map::DefaultHasher;
use std::fmt;
use std::hash::{Hash, Hasher};

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
        self.failed_proofs.len() + self.missing_proofs.len() + self.passed_proofs.len()
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
        let events_json: Vec<String> = self.causal_event_sequence.iter().map(|e| {
            format!(
                r#"{{"type":"{}","timestamp_ms":{},"description":"{}","evidence_ref":{}}}"#,
                e.event_type.label(),
                e.timestamp_ms,
                e.description,
                match &e.evidence_ref {
                    Some(r) => format!("\"{}\"", r),
                    None => "null".to_string(),
                }
            )
        }).collect();

        let artifacts_json: Vec<String> = self.failed_artifacts.iter().map(|a| {
            format!(
                r#"{{"path":"{}","expected_hash":"{}","actual_hash":"{}","reason":"{}"}}"#,
                a.artifact_path, a.expected_hash, a.actual_hash, a.failure_reason
            )
        }).collect();

        format!(
            r#"{{"bundle_id":"{}","event_count":{},"artifact_count":{},"hardening_level":"{}","epoch_id":{},"timestamp_ms":{},"causal_events":[{}],"failed_artifacts":[{}]}}"#,
            self.bundle_id,
            self.event_count(),
            self.artifact_count(),
            self.hardening_level,
            self.epoch_id,
            self.timestamp_ms,
            events_json.join(","),
            artifacts_json.join(","),
        )
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
                self.active_halts.push(bundle_id);
            }
            HaltPolicy::WarnOnly => {}
        }

        self.bundles.push(bundle);
        self.bundles.last().unwrap()
    }

    /// Check if a durable operation is allowed.
    ///
    /// Returns Ok(()) if allowed, Err with the blocking bundle_id if halted.
    pub fn check_durable_op(&self, scope: &str) -> Result<(), DurabilityHaltedError> {
        if self.active_halts.is_empty() {
            return Ok(());
        }

        match &self.halt_policy {
            HaltPolicy::HaltAll => Err(DurabilityHaltedError {
                bundle_id: self.active_halts.last().unwrap().clone(),
                scope: scope.to_string(),
            }),
            HaltPolicy::HaltScope(halt_scope) if halt_scope == scope => {
                Err(DurabilityHaltedError {
                    bundle_id: self.active_halts.last().unwrap().clone(),
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
            f, "{}: bundle_id={}, scope={}",
            event_codes::VIOLATION_OP_REJECTED, self.bundle_id, self.scope
        )
    }
}

impl std::error::Error for DurabilityHaltedError {}

// ── Bundle generation (deterministic) ──────────────────────────────

/// Generate a violation bundle deterministically from context.
pub fn generate_bundle(context: &ViolationContext) -> ViolationBundle {
    // Derive bundle_id deterministically from content
    let mut hasher = DefaultHasher::new();
    context.epoch_id.hash(&mut hasher);
    context.timestamp_ms.hash(&mut hasher);
    context.hardening_level.hash(&mut hasher);
    for event in &context.events {
        event.event_type.label().hash(&mut hasher);
        event.timestamp_ms.hash(&mut hasher);
        event.description.hash(&mut hasher);
    }
    for artifact in &context.artifacts {
        artifact.artifact_path.hash(&mut hasher);
        artifact.expected_hash.hash(&mut hasher);
    }
    let hash = hasher.finish();
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
            artifacts: vec![
                FailedArtifact {
                    artifact_path: "objects/abc123".into(),
                    expected_hash: "deadbeef".into(),
                    actual_hash: "00000000".into(),
                    failure_reason: "hash mismatch after repair".into(),
                },
            ],
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
        assert_eq!(CausalEventType::GuardrailRejection.label(), "guardrail_rejection");
        assert_eq!(CausalEventType::HardeningEscalation.label(), "hardening_escalation");
        assert_eq!(CausalEventType::RepairFailed.label(), "repair_failed");
        assert_eq!(CausalEventType::IntegrityCheckFailed.label(), "integrity_check_failed");
        assert_eq!(CausalEventType::ArtifactUnverifiable.label(), "artifact_unverifiable");
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
        assert_eq!(HaltPolicy::HaltScope("db".into()).to_string(), "halt_scope(db)");
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
        let _: serde_json::Value = serde_json::from_str(&json).unwrap();
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
        let mut detector = DurabilityViolationDetector::new(
            HaltPolicy::HaltScope("scope-a".into())
        );
        let ctx = make_context();
        detector.generate_bundle(&ctx);

        assert!(detector.check_durable_op("scope-a").is_err());
        assert!(detector.check_durable_op("scope-b").is_ok());
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
        let mut detector = DurabilityViolationDetector::new(
            HaltPolicy::HaltScope("db".into())
        );
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
}
