//! bd-8qlj: Integrate VEF verification state into high-risk control transitions
//! and action authorization.
//!
//! This module implements a `ControlTransitionGate` that requires valid VEF
//! verification evidence before authorizing high-risk control transitions such
//! as capability grants, trust-level changes, artifact promotions, and policy
//! overrides.  Unauthorized transitions without valid VEF evidence are blocked
//! with a structured denial containing a stable reason code.
//!
//! # Invariants
//!
//! - INV-CTL-EVIDENCE-REQUIRED: every high-risk transition must reference at
//!   least one valid VEF evidence entry; transitions with no evidence are
//!   denied unconditionally.
//! - INV-CTL-DENY-LOGGED: every denial produces a structured event with a
//!   stable event code and human-readable reason.
//! - INV-CTL-NO-BYPASS: there is no code path that skips evidence validation
//!   for high-risk transition types.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ── Schema version ──────────────────────────────────────────────────────────

/// Schema version for the VEF control-integration evidence format.
pub const CONTROL_INTEGRATION_SCHEMA_VERSION: &str = "vef-control-integration-v1";

// ── Invariant constants ─────────────────────────────────────────────────────

/// Every high-risk transition must reference valid VEF evidence.
pub const INV_CTL_EVIDENCE_REQUIRED: &str = "INV-CTL-EVIDENCE-REQUIRED";

/// Every denial is logged as a structured event.
pub const INV_CTL_DENY_LOGGED: &str = "INV-CTL-DENY-LOGGED";

/// No code path bypasses evidence validation for high-risk transitions.
pub const INV_CTL_NO_BYPASS: &str = "INV-CTL-NO-BYPASS";

// ── Event codes ─────────────────────────────────────────────────────────────

pub mod event_codes {
    /// Transition request received and evidence validation started.
    pub const CTL_001_REQUEST_RECEIVED: &str = "CTL-001";
    /// Transition authorized with valid VEF evidence.
    pub const CTL_002_AUTHORIZED: &str = "CTL-002";
    /// Transition denied: missing evidence.
    pub const CTL_003_DENIED_MISSING_EVIDENCE: &str = "CTL-003";
    /// Transition denied: expired evidence.
    pub const CTL_004_DENIED_EXPIRED_EVIDENCE: &str = "CTL-004";
    /// Transition denied: evidence scope mismatch.
    pub const CTL_005_DENIED_SCOPE_MISMATCH: &str = "CTL-005";
    /// Transition placed in pending-verification state.
    pub const CTL_006_PENDING_VERIFICATION: &str = "CTL-006";
    /// Transition denied: invalid evidence hash.
    pub const CTL_007_DENIED_INVALID_HASH: &str = "CTL-007";
    /// Transition denied: insufficient trust level.
    pub const CTL_008_DENIED_INSUFFICIENT_TRUST: &str = "CTL-008";
}

// ── Error codes ─────────────────────────────────────────────────────────────

pub mod error_codes {
    pub const ERR_CTL_MISSING_EVIDENCE: &str = "ERR-CTL-MISSING-EVIDENCE";
    pub const ERR_CTL_EXPIRED_EVIDENCE: &str = "ERR-CTL-EXPIRED-EVIDENCE";
    pub const ERR_CTL_SCOPE_MISMATCH: &str = "ERR-CTL-SCOPE-MISMATCH";
    pub const ERR_CTL_INVALID_HASH: &str = "ERR-CTL-INVALID-HASH";
    pub const ERR_CTL_INSUFFICIENT_TRUST: &str = "ERR-CTL-INSUFFICIENT-TRUST";
    pub const ERR_CTL_INTERNAL: &str = "ERR-CTL-INTERNAL";
}

// ── Core types ──────────────────────────────────────────────────────────────

/// Classification of high-risk control transitions that require VEF evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TransitionType {
    /// Granting a capability to an actor or connector.
    CapabilityGrant,
    /// Changing the trust level of an entity.
    TrustLevelChange,
    /// Promoting an artifact through a trust gate.
    ArtifactPromotion,
    /// Overriding an existing policy constraint.
    PolicyOverride,
}

impl TransitionType {
    /// All defined transition types in canonical order.
    pub const ALL: &'static [TransitionType] = &[
        TransitionType::CapabilityGrant,
        TransitionType::TrustLevelChange,
        TransitionType::ArtifactPromotion,
        TransitionType::PolicyOverride,
    ];

    pub fn as_str(&self) -> &'static str {
        match self {
            TransitionType::CapabilityGrant => "capability_grant",
            TransitionType::TrustLevelChange => "trust_level_change",
            TransitionType::ArtifactPromotion => "artifact_promotion",
            TransitionType::PolicyOverride => "policy_override",
        }
    }

    /// Whether this transition type always requires VEF evidence (all do).
    pub fn requires_evidence(&self) -> bool {
        // INV-CTL-NO-BYPASS: every high-risk transition requires evidence.
        true
    }
}

impl fmt::Display for TransitionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Verification state of a VEF evidence entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerificationState {
    /// Evidence has been verified and is currently valid.
    Verified,
    /// Evidence has not yet been verified.
    Unverified,
    /// Evidence has expired and is no longer valid.
    Expired,
    /// Evidence was found to be invalid (hash mismatch, tamper, etc.).
    Invalid,
}

impl VerificationState {
    pub fn is_valid(&self) -> bool {
        matches!(self, VerificationState::Verified)
    }
}

impl fmt::Display for VerificationState {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            VerificationState::Verified => "verified",
            VerificationState::Unverified => "unverified",
            VerificationState::Expired => "expired",
            VerificationState::Invalid => "invalid",
        };
        f.write_str(s)
    }
}

/// A single piece of VEF evidence referenced by a transition request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VefEvidenceRef {
    /// Unique identifier for this evidence entry.
    pub evidence_id: String,
    /// SHA-256 hash of the evidence payload.
    pub evidence_hash: String,
    /// The transition type(s) this evidence covers.
    pub scope: Vec<TransitionType>,
    /// Verification state of this evidence.
    pub state: VerificationState,
    /// Timestamp (millis since epoch) when the evidence was created.
    pub created_at_millis: u64,
    /// Timestamp (millis since epoch) when the evidence expires.
    pub expires_at_millis: u64,
    /// Optional trace ID for correlation.
    pub trace_id: String,
}

impl VefEvidenceRef {
    /// Check whether the evidence is expired relative to the given timestamp.
    pub fn is_expired_at(&self, now_millis: u64) -> bool {
        now_millis >= self.expires_at_millis
    }

    /// Check whether the evidence scope covers the requested transition type.
    pub fn covers_transition(&self, tt: TransitionType) -> bool {
        self.scope.contains(&tt)
    }
}

/// A request to perform a high-risk control transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionRequest {
    /// Unique request identifier.
    pub request_id: String,
    /// Type of transition being requested.
    pub transition_type: TransitionType,
    /// Actor or entity requesting the transition.
    pub actor_identity: String,
    /// Target entity or artifact of the transition.
    pub target_identity: String,
    /// References to VEF evidence supporting this transition.
    pub evidence_refs: Vec<VefEvidenceRef>,
    /// Additional context metadata (deterministic ordered map).
    pub context: BTreeMap<String, String>,
    /// Trace ID for distributed tracing.
    pub trace_id: String,
    /// Timestamp (millis since epoch) of the request.
    pub requested_at_millis: u64,
}

/// The authorization decision for a transition request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum AuthorizationDecision {
    /// Transition is authorized with valid evidence.
    Authorized {
        evidence_ids: Vec<String>,
        detail: String,
    },
    /// Transition is denied with a structured reason.
    Denied {
        reason: DenialReason,
        detail: String,
    },
    /// Transition is pending additional verification.
    PendingVerification {
        pending_evidence_ids: Vec<String>,
        detail: String,
    },
}

impl AuthorizationDecision {
    pub fn is_authorized(&self) -> bool {
        matches!(self, AuthorizationDecision::Authorized { .. })
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, AuthorizationDecision::Denied { .. })
    }

    pub fn is_pending(&self) -> bool {
        matches!(self, AuthorizationDecision::PendingVerification { .. })
    }
}

/// Structured denial reason with stable error code.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenialReason {
    /// Stable error code (from error_codes module).
    pub error_code: String,
    /// Stable event code emitted on denial.
    pub event_code: String,
    /// Human-readable explanation.
    pub message: String,
    /// Transition type that was denied.
    pub transition_type: TransitionType,
}

impl fmt::Display for DenialReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.error_code, self.transition_type, self.message)
    }
}

/// Structured event emitted during gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateEvent {
    pub event_code: String,
    pub request_id: String,
    pub transition_type: TransitionType,
    pub trace_id: String,
    pub detail: String,
    pub timestamp_millis: u64,
}

/// Policy configuration for the control-transition gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GatePolicy {
    /// Maximum age (milliseconds) of evidence before it is considered stale.
    pub max_evidence_age_millis: u64,
    /// Minimum number of evidence references required per transition.
    pub min_evidence_count: usize,
    /// Minimum trust level for the requesting actor (0-100).
    pub min_trust_level: u32,
    /// Per-transition-type overrides for minimum evidence count.
    pub transition_overrides: BTreeMap<TransitionType, TransitionOverride>,
}

/// Per-transition-type policy override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionOverride {
    pub min_evidence_count: Option<usize>,
    pub max_evidence_age_millis: Option<u64>,
    pub min_trust_level: Option<u32>,
}

impl Default for GatePolicy {
    fn default() -> Self {
        Self {
            max_evidence_age_millis: 3_600_000, // 1 hour
            min_evidence_count: 1,
            min_trust_level: 0,
            transition_overrides: BTreeMap::new(),
        }
    }
}

impl GatePolicy {
    /// Effective minimum evidence count for a transition type.
    fn effective_min_evidence(&self, tt: TransitionType) -> usize {
        self.transition_overrides
            .get(&tt)
            .and_then(|o| o.min_evidence_count)
            .unwrap_or(self.min_evidence_count)
    }

    /// Effective maximum evidence age for a transition type.
    fn effective_max_age(&self, tt: TransitionType) -> u64 {
        self.transition_overrides
            .get(&tt)
            .and_then(|o| o.max_evidence_age_millis)
            .unwrap_or(self.max_evidence_age_millis)
    }

    /// Effective minimum trust level for a transition type.
    fn effective_min_trust(&self, tt: TransitionType) -> u32 {
        self.transition_overrides
            .get(&tt)
            .and_then(|o| o.min_trust_level)
            .unwrap_or(self.min_trust_level)
    }
}

/// Metrics tracked by the gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateMetrics {
    pub total_requests: u64,
    pub authorized_count: u64,
    pub denied_count: u64,
    pub pending_count: u64,
    pub denied_missing_evidence: u64,
    pub denied_expired_evidence: u64,
    pub denied_scope_mismatch: u64,
    pub denied_invalid_hash: u64,
    pub denied_insufficient_trust: u64,
    pub per_transition_type: BTreeMap<TransitionType, TransitionMetrics>,
}

/// Per-transition-type metrics.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransitionMetrics {
    pub total: u64,
    pub authorized: u64,
    pub denied: u64,
    pub pending: u64,
}

impl Default for GateMetrics {
    fn default() -> Self {
        let mut per_transition_type = BTreeMap::new();
        for tt in TransitionType::ALL {
            per_transition_type.insert(*tt, TransitionMetrics::default());
        }
        Self {
            total_requests: 0,
            authorized_count: 0,
            denied_count: 0,
            pending_count: 0,
            denied_missing_evidence: 0,
            denied_expired_evidence: 0,
            denied_scope_mismatch: 0,
            denied_invalid_hash: 0,
            denied_insufficient_trust: 0,
            per_transition_type,
        }
    }
}

/// Actor trust context presented alongside the transition request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActorTrustContext {
    pub actor_identity: String,
    pub trust_level: u32,
    pub capabilities: Vec<String>,
}

/// The ControlTransitionGate evaluates transition requests against VEF evidence
/// and gate policy, producing structured authorization decisions.
///
/// # Invariant enforcement
///
/// - INV-CTL-EVIDENCE-REQUIRED: `evaluate` always checks that at least one
///   valid, in-scope, unexpired evidence entry exists. If none, a Denied
///   decision is returned.
/// - INV-CTL-DENY-LOGGED: every denial pushes a `GateEvent` with the
///   corresponding CTL event code.
/// - INV-CTL-NO-BYPASS: there is no early-return path that skips evidence
///   validation for any `TransitionType`. The `requires_evidence()` call
///   is exhaustive over all variants.
#[derive(Debug, Clone)]
pub struct ControlTransitionGate {
    policy: GatePolicy,
    events: Vec<GateEvent>,
    metrics: GateMetrics,
    now_millis: u64,
}

impl ControlTransitionGate {
    /// Create a new gate with the given policy and current timestamp.
    pub fn new(policy: GatePolicy, now_millis: u64) -> Self {
        Self {
            policy,
            events: Vec::new(),
            metrics: GateMetrics::default(),
            now_millis,
        }
    }

    /// Advance the gate's notion of "now".
    pub fn set_now_millis(&mut self, now_millis: u64) {
        self.now_millis = now_millis;
    }

    /// Evaluate a transition request and return an authorization decision.
    ///
    /// INV-CTL-NO-BYPASS: this method is the sole entry point for
    /// authorization decisions. It unconditionally validates evidence
    /// for all transition types.
    pub fn evaluate(
        &mut self,
        request: &TransitionRequest,
        trust_ctx: &ActorTrustContext,
    ) -> AuthorizationDecision {
        let tt = request.transition_type;

        // INV-CTL-NO-BYPASS: every transition type requires evidence.
        assert!(
            tt.requires_evidence(),
            "INV-CTL-NO-BYPASS violated: transition type {:?} claims no evidence required",
            tt
        );

        // Emit request-received event.
        self.emit_event(
            event_codes::CTL_001_REQUEST_RECEIVED,
            &request.request_id,
            tt,
            &request.trace_id,
            format!("Transition request received for {}", tt),
        );

        self.metrics.total_requests += 1;
        if let Some(tm) = self.metrics.per_transition_type.get_mut(&tt) {
            tm.total += 1;
        }

        // Step 1: Check trust level (INV-CTL-EVIDENCE-REQUIRED precondition).
        let min_trust = self.policy.effective_min_trust(tt);
        if trust_ctx.trust_level < min_trust {
            return self.deny(
                &request.request_id,
                tt,
                &request.trace_id,
                error_codes::ERR_CTL_INSUFFICIENT_TRUST,
                event_codes::CTL_008_DENIED_INSUFFICIENT_TRUST,
                format!(
                    "Actor trust level {} below minimum {} for {}",
                    trust_ctx.trust_level, min_trust, tt
                ),
            );
        }

        // Step 2: INV-CTL-EVIDENCE-REQUIRED — check evidence is present.
        let min_evidence = self.policy.effective_min_evidence(tt);
        if request.evidence_refs.is_empty() {
            return self.deny(
                &request.request_id,
                tt,
                &request.trace_id,
                error_codes::ERR_CTL_MISSING_EVIDENCE,
                event_codes::CTL_003_DENIED_MISSING_EVIDENCE,
                format!(
                    "No VEF evidence provided for {}; at least {} required",
                    tt, min_evidence
                ),
            );
        }

        // Step 3: Validate each evidence reference.
        let max_age = self.policy.effective_max_age(tt);
        let mut valid_evidence_ids: Vec<String> = Vec::new();
        let mut pending_evidence_ids: Vec<String> = Vec::new();

        for ev in &request.evidence_refs {
            // Check scope coverage.
            if !ev.covers_transition(tt) {
                self.emit_event(
                    event_codes::CTL_005_DENIED_SCOPE_MISMATCH,
                    &request.request_id,
                    tt,
                    &request.trace_id,
                    format!(
                        "Evidence {} does not cover transition type {}",
                        ev.evidence_id, tt
                    ),
                );
                continue;
            }

            // Check expiration.
            if ev.is_expired_at(self.now_millis) {
                self.emit_event(
                    event_codes::CTL_004_DENIED_EXPIRED_EVIDENCE,
                    &request.request_id,
                    tt,
                    &request.trace_id,
                    format!(
                        "Evidence {} expired at {} (now {})",
                        ev.evidence_id, ev.expires_at_millis, self.now_millis
                    ),
                );
                continue;
            }

            // Check evidence age against policy.
            let age = self.now_millis.saturating_sub(ev.created_at_millis);
            if age >= max_age {
                self.emit_event(
                    event_codes::CTL_004_DENIED_EXPIRED_EVIDENCE,
                    &request.request_id,
                    tt,
                    &request.trace_id,
                    format!(
                        "Evidence {} age {}ms exceeds max {}ms for {}",
                        ev.evidence_id, age, max_age, tt
                    ),
                );
                continue;
            }

            // Check hash is non-empty as basic integrity regardless of state.
            if ev.evidence_hash.is_empty() {
                self.emit_event(
                    event_codes::CTL_007_DENIED_INVALID_HASH,
                    &request.request_id,
                    tt,
                    &request.trace_id,
                    format!("Evidence {} has empty hash", ev.evidence_id),
                );
                continue;
            }

            // Check verification state.
            match ev.state {
                VerificationState::Verified => {
                    valid_evidence_ids.push(ev.evidence_id.clone());
                }
                VerificationState::Unverified => {
                    pending_evidence_ids.push(ev.evidence_id.clone());
                }
                VerificationState::Expired => {
                    self.emit_event(
                        event_codes::CTL_004_DENIED_EXPIRED_EVIDENCE,
                        &request.request_id,
                        tt,
                        &request.trace_id,
                        format!(
                            "Evidence {} has expired verification state",
                            ev.evidence_id
                        ),
                    );
                }
                VerificationState::Invalid => {
                    self.emit_event(
                        event_codes::CTL_007_DENIED_INVALID_HASH,
                        &request.request_id,
                        tt,
                        &request.trace_id,
                        format!(
                            "Evidence {} has invalid verification state",
                            ev.evidence_id
                        ),
                    );
                }
            }
        }

        // Step 4: Decision based on collected valid evidence.
        if valid_evidence_ids.len() >= min_evidence {
            self.authorize(
                &request.request_id,
                tt,
                &request.trace_id,
                valid_evidence_ids,
            )
        } else if !pending_evidence_ids.is_empty() {
            self.pend(
                &request.request_id,
                tt,
                &request.trace_id,
                pending_evidence_ids,
            )
        } else {
            // INV-CTL-EVIDENCE-REQUIRED: no valid evidence found.
            let has_scope_mismatch = request
                .evidence_refs
                .iter()
                .any(|e| !e.covers_transition(tt));
            let has_expired = request
                .evidence_refs
                .iter()
                .any(|e| e.is_expired_at(self.now_millis));
            let has_invalid = request
                .evidence_refs
                .iter()
                .any(|e| e.state == VerificationState::Invalid);

            if has_invalid {
                self.deny(
                    &request.request_id,
                    tt,
                    &request.trace_id,
                    error_codes::ERR_CTL_INVALID_HASH,
                    event_codes::CTL_007_DENIED_INVALID_HASH,
                    format!(
                        "All evidence for {} is invalid (hash/verification failure)",
                        tt
                    ),
                )
            } else if has_expired {
                self.deny(
                    &request.request_id,
                    tt,
                    &request.trace_id,
                    error_codes::ERR_CTL_EXPIRED_EVIDENCE,
                    event_codes::CTL_004_DENIED_EXPIRED_EVIDENCE,
                    format!("All evidence for {} has expired", tt),
                )
            } else if has_scope_mismatch {
                self.deny(
                    &request.request_id,
                    tt,
                    &request.trace_id,
                    error_codes::ERR_CTL_SCOPE_MISMATCH,
                    event_codes::CTL_005_DENIED_SCOPE_MISMATCH,
                    format!(
                        "No evidence covers transition type {}",
                        tt
                    ),
                )
            } else {
                self.deny(
                    &request.request_id,
                    tt,
                    &request.trace_id,
                    error_codes::ERR_CTL_MISSING_EVIDENCE,
                    event_codes::CTL_003_DENIED_MISSING_EVIDENCE,
                    format!(
                        "Insufficient valid evidence for {} (have {}, need {})",
                        tt,
                        valid_evidence_ids.len(),
                        min_evidence
                    ),
                )
            }
        }
    }

    /// Batch-evaluate multiple requests. Returns decisions in order.
    pub fn evaluate_batch(
        &mut self,
        requests: &[(TransitionRequest, ActorTrustContext)],
    ) -> Vec<AuthorizationDecision> {
        requests
            .iter()
            .map(|(req, ctx)| self.evaluate(req, ctx))
            .collect()
    }

    /// Return all emitted gate events.
    pub fn events(&self) -> &[GateEvent] {
        &self.events
    }

    /// Drain and return all emitted gate events.
    pub fn drain_events(&mut self) -> Vec<GateEvent> {
        std::mem::take(&mut self.events)
    }

    /// Return current gate metrics.
    pub fn metrics(&self) -> &GateMetrics {
        &self.metrics
    }

    /// Return the current policy.
    pub fn policy(&self) -> &GatePolicy {
        &self.policy
    }

    // ── internal helpers ────────────────────────────────────────────────

    fn emit_event(
        &mut self,
        event_code: &str,
        request_id: &str,
        transition_type: TransitionType,
        trace_id: &str,
        detail: String,
    ) {
        self.events.push(GateEvent {
            event_code: event_code.to_string(),
            request_id: request_id.to_string(),
            transition_type,
            trace_id: trace_id.to_string(),
            detail,
            timestamp_millis: self.now_millis,
        });
    }

    fn deny(
        &mut self,
        request_id: &str,
        tt: TransitionType,
        trace_id: &str,
        error_code: &str,
        event_code: &str,
        message: String,
    ) -> AuthorizationDecision {
        // INV-CTL-DENY-LOGGED: emit denial event.
        self.emit_event(event_code, request_id, tt, trace_id, message.clone());

        self.metrics.denied_count += 1;
        match error_code {
            error_codes::ERR_CTL_MISSING_EVIDENCE => {
                self.metrics.denied_missing_evidence += 1;
            }
            error_codes::ERR_CTL_EXPIRED_EVIDENCE => {
                self.metrics.denied_expired_evidence += 1;
            }
            error_codes::ERR_CTL_SCOPE_MISMATCH => {
                self.metrics.denied_scope_mismatch += 1;
            }
            error_codes::ERR_CTL_INVALID_HASH => {
                self.metrics.denied_invalid_hash += 1;
            }
            error_codes::ERR_CTL_INSUFFICIENT_TRUST => {
                self.metrics.denied_insufficient_trust += 1;
            }
            _ => {}
        }
        if let Some(tm) = self.metrics.per_transition_type.get_mut(&tt) {
            tm.denied += 1;
        }

        AuthorizationDecision::Denied {
            reason: DenialReason {
                error_code: error_code.to_string(),
                event_code: event_code.to_string(),
                message,
                transition_type: tt,
            },
            detail: format!("Denied by ControlTransitionGate for {}", tt),
        }
    }

    fn authorize(
        &mut self,
        request_id: &str,
        tt: TransitionType,
        trace_id: &str,
        evidence_ids: Vec<String>,
    ) -> AuthorizationDecision {
        self.emit_event(
            event_codes::CTL_002_AUTHORIZED,
            request_id,
            tt,
            trace_id,
            format!(
                "Transition {} authorized with {} evidence entries",
                tt,
                evidence_ids.len()
            ),
        );

        self.metrics.authorized_count += 1;
        if let Some(tm) = self.metrics.per_transition_type.get_mut(&tt) {
            tm.authorized += 1;
        }

        AuthorizationDecision::Authorized {
            evidence_ids,
            detail: format!("Authorized: valid VEF evidence for {}", tt),
        }
    }

    fn pend(
        &mut self,
        request_id: &str,
        tt: TransitionType,
        trace_id: &str,
        pending_evidence_ids: Vec<String>,
    ) -> AuthorizationDecision {
        self.emit_event(
            event_codes::CTL_006_PENDING_VERIFICATION,
            request_id,
            tt,
            trace_id,
            format!(
                "Transition {} pending verification of {} evidence entries",
                tt,
                pending_evidence_ids.len()
            ),
        );

        self.metrics.pending_count += 1;
        if let Some(tm) = self.metrics.per_transition_type.get_mut(&tt) {
            tm.pending += 1;
        }

        AuthorizationDecision::PendingVerification {
            pending_evidence_ids,
            detail: format!(
                "Pending: evidence not yet verified for {}",
                tt
            ),
        }
    }
}

// ── Unit tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_000_000;

    fn default_gate() -> ControlTransitionGate {
        ControlTransitionGate::new(GatePolicy::default(), NOW)
    }

    fn valid_evidence(
        id: &str,
        scope: Vec<TransitionType>,
    ) -> VefEvidenceRef {
        VefEvidenceRef {
            evidence_id: id.to_string(),
            evidence_hash: "sha256:abcdef0123456789".to_string(),
            scope,
            state: VerificationState::Verified,
            created_at_millis: NOW - 1000,
            expires_at_millis: NOW + 3_600_000,
            trace_id: "trace-test".to_string(),
        }
    }

    fn make_request(
        id: &str,
        tt: TransitionType,
        evidence: Vec<VefEvidenceRef>,
    ) -> TransitionRequest {
        TransitionRequest {
            request_id: id.to_string(),
            transition_type: tt,
            actor_identity: "actor-1".to_string(),
            target_identity: "target-1".to_string(),
            evidence_refs: evidence,
            context: BTreeMap::new(),
            trace_id: "trace-test".to_string(),
            requested_at_millis: NOW,
        }
    }

    fn default_trust_ctx() -> ActorTrustContext {
        ActorTrustContext {
            actor_identity: "actor-1".to_string(),
            trust_level: 50,
            capabilities: vec!["cap-1".to_string()],
        }
    }

    // Test 1: Transition with valid evidence is authorized.
    #[test]
    fn test_authorize_with_valid_evidence() {
        let mut gate = default_gate();
        let ev = valid_evidence("ev-1", vec![TransitionType::CapabilityGrant]);
        let req = make_request("req-1", TransitionType::CapabilityGrant, vec![ev]);
        let ctx = default_trust_ctx();

        let decision = gate.evaluate(&req, &ctx);
        assert!(decision.is_authorized(), "Expected Authorized, got {:?}", decision);
        assert_eq!(gate.metrics().authorized_count, 1);
    }

    // Test 2: Transition without evidence is denied (INV-CTL-EVIDENCE-REQUIRED).
    #[test]
    fn test_deny_missing_evidence() {
        let mut gate = default_gate();
        let req = make_request("req-2", TransitionType::TrustLevelChange, vec![]);
        let ctx = default_trust_ctx();

        let decision = gate.evaluate(&req, &ctx);
        assert!(decision.is_denied(), "Expected Denied, got {:?}", decision);
        if let AuthorizationDecision::Denied { reason, .. } = &decision {
            assert_eq!(reason.error_code, error_codes::ERR_CTL_MISSING_EVIDENCE);
            assert_eq!(reason.event_code, event_codes::CTL_003_DENIED_MISSING_EVIDENCE);
        }
        assert_eq!(gate.metrics().denied_missing_evidence, 1);
    }

    // Test 3: Transition with expired evidence is denied.
    #[test]
    fn test_deny_expired_evidence() {
        let mut gate = default_gate();
        let ev = VefEvidenceRef {
            evidence_id: "ev-expired".to_string(),
            evidence_hash: "sha256:expired".to_string(),
            scope: vec![TransitionType::ArtifactPromotion],
            state: VerificationState::Verified,
            created_at_millis: NOW - 100_000,
            expires_at_millis: NOW - 1, // already expired
            trace_id: "trace-test".to_string(),
        };
        let req = make_request("req-3", TransitionType::ArtifactPromotion, vec![ev]);
        let ctx = default_trust_ctx();

        let decision = gate.evaluate(&req, &ctx);
        assert!(decision.is_denied(), "Expected Denied, got {:?}", decision);
        if let AuthorizationDecision::Denied { reason, .. } = &decision {
            assert_eq!(reason.error_code, error_codes::ERR_CTL_EXPIRED_EVIDENCE);
        }
        assert_eq!(gate.metrics().denied_expired_evidence, 1);
    }

    // Test 4: Transition with scope mismatch is denied.
    #[test]
    fn test_deny_scope_mismatch() {
        let mut gate = default_gate();
        // Evidence covers CapabilityGrant, but request is for PolicyOverride
        let ev = valid_evidence("ev-scope", vec![TransitionType::CapabilityGrant]);
        let req = make_request("req-4", TransitionType::PolicyOverride, vec![ev]);
        let ctx = default_trust_ctx();

        let decision = gate.evaluate(&req, &ctx);
        assert!(decision.is_denied(), "Expected Denied, got {:?}", decision);
        if let AuthorizationDecision::Denied { reason, .. } = &decision {
            assert_eq!(reason.error_code, error_codes::ERR_CTL_SCOPE_MISMATCH);
        }
        assert_eq!(gate.metrics().denied_scope_mismatch, 1);
    }

    // Test 5: Transition with invalid evidence state is denied.
    #[test]
    fn test_deny_invalid_evidence_state() {
        let mut gate = default_gate();
        let ev = VefEvidenceRef {
            evidence_id: "ev-invalid".to_string(),
            evidence_hash: "sha256:invalid".to_string(),
            scope: vec![TransitionType::TrustLevelChange],
            state: VerificationState::Invalid,
            created_at_millis: NOW - 1000,
            expires_at_millis: NOW + 3_600_000,
            trace_id: "trace-test".to_string(),
        };
        let req = make_request("req-5", TransitionType::TrustLevelChange, vec![ev]);
        let ctx = default_trust_ctx();

        let decision = gate.evaluate(&req, &ctx);
        assert!(decision.is_denied(), "Expected Denied, got {:?}", decision);
        if let AuthorizationDecision::Denied { reason, .. } = &decision {
            assert_eq!(reason.error_code, error_codes::ERR_CTL_INVALID_HASH);
        }
        assert_eq!(gate.metrics().denied_invalid_hash, 1);
    }

    // Test 6: Unverified evidence yields PendingVerification.
    #[test]
    fn test_pending_verification_for_unverified() {
        let mut gate = default_gate();
        let ev = VefEvidenceRef {
            evidence_id: "ev-unverified".to_string(),
            evidence_hash: "sha256:pending".to_string(),
            scope: vec![TransitionType::CapabilityGrant],
            state: VerificationState::Unverified,
            created_at_millis: NOW - 500,
            expires_at_millis: NOW + 3_600_000,
            trace_id: "trace-test".to_string(),
        };
        let req = make_request("req-6", TransitionType::CapabilityGrant, vec![ev]);
        let ctx = default_trust_ctx();

        let decision = gate.evaluate(&req, &ctx);
        assert!(decision.is_pending(), "Expected PendingVerification, got {:?}", decision);
        assert_eq!(gate.metrics().pending_count, 1);
    }

    // Test 7: All transition types require evidence (INV-CTL-NO-BYPASS).
    #[test]
    fn test_all_transition_types_require_evidence() {
        for tt in TransitionType::ALL {
            assert!(
                tt.requires_evidence(),
                "INV-CTL-NO-BYPASS: {:?} must require evidence",
                tt
            );
        }
    }

    // Test 8: Denial always emits events (INV-CTL-DENY-LOGGED).
    #[test]
    fn test_denial_emits_events() {
        let mut gate = default_gate();
        let req = make_request("req-8", TransitionType::PolicyOverride, vec![]);
        let ctx = default_trust_ctx();

        let _ = gate.evaluate(&req, &ctx);

        let deny_events: Vec<&GateEvent> = gate
            .events()
            .iter()
            .filter(|e| e.event_code == event_codes::CTL_003_DENIED_MISSING_EVIDENCE)
            .collect();
        assert!(
            !deny_events.is_empty(),
            "INV-CTL-DENY-LOGGED: denial must emit event"
        );
        assert_eq!(deny_events[0].transition_type, TransitionType::PolicyOverride);
    }

    // Test 9: Multiple evidence entries — one valid is sufficient.
    #[test]
    fn test_multiple_evidence_one_valid() {
        let mut gate = default_gate();
        let ev_bad = VefEvidenceRef {
            evidence_id: "ev-bad".to_string(),
            evidence_hash: "sha256:bad".to_string(),
            scope: vec![TransitionType::ArtifactPromotion],
            state: VerificationState::Invalid,
            created_at_millis: NOW - 1000,
            expires_at_millis: NOW + 3_600_000,
            trace_id: "trace-test".to_string(),
        };
        let ev_good = valid_evidence("ev-good", vec![TransitionType::ArtifactPromotion]);
        let req = make_request(
            "req-9",
            TransitionType::ArtifactPromotion,
            vec![ev_bad, ev_good],
        );
        let ctx = default_trust_ctx();

        let decision = gate.evaluate(&req, &ctx);
        assert!(decision.is_authorized(), "Expected Authorized with one valid evidence");
    }

    // Test 10: Evidence with empty hash is rejected.
    #[test]
    fn test_empty_hash_rejected() {
        let mut gate = default_gate();
        let ev = VefEvidenceRef {
            evidence_id: "ev-nohash".to_string(),
            evidence_hash: String::new(),
            scope: vec![TransitionType::CapabilityGrant],
            state: VerificationState::Verified,
            created_at_millis: NOW - 500,
            expires_at_millis: NOW + 3_600_000,
            trace_id: "trace-test".to_string(),
        };
        let req = make_request("req-10", TransitionType::CapabilityGrant, vec![ev]);
        let ctx = default_trust_ctx();

        let decision = gate.evaluate(&req, &ctx);
        // Should be denied because the only evidence has an empty hash
        assert!(decision.is_denied(), "Expected Denied for empty hash evidence");
    }

    // Test 11: Policy override with higher min_evidence_count.
    #[test]
    fn test_policy_override_min_evidence() {
        let mut overrides = BTreeMap::new();
        overrides.insert(
            TransitionType::PolicyOverride,
            TransitionOverride {
                min_evidence_count: Some(2),
                max_evidence_age_millis: None,
                min_trust_level: None,
            },
        );
        let policy = GatePolicy {
            transition_overrides: overrides,
            ..GatePolicy::default()
        };
        let mut gate = ControlTransitionGate::new(policy, NOW);

        // Only one evidence entry — should be denied for PolicyOverride
        let ev = valid_evidence("ev-11", vec![TransitionType::PolicyOverride]);
        let req = make_request("req-11", TransitionType::PolicyOverride, vec![ev]);
        let ctx = default_trust_ctx();

        let decision = gate.evaluate(&req, &ctx);
        assert!(
            decision.is_denied(),
            "Expected Denied when min_evidence=2 but only 1 provided"
        );
    }

    // Test 12: Policy override satisfied with enough evidence.
    #[test]
    fn test_policy_override_min_evidence_satisfied() {
        let mut overrides = BTreeMap::new();
        overrides.insert(
            TransitionType::PolicyOverride,
            TransitionOverride {
                min_evidence_count: Some(2),
                max_evidence_age_millis: None,
                min_trust_level: None,
            },
        );
        let policy = GatePolicy {
            transition_overrides: overrides,
            ..GatePolicy::default()
        };
        let mut gate = ControlTransitionGate::new(policy, NOW);

        let ev1 = valid_evidence("ev-12a", vec![TransitionType::PolicyOverride]);
        let ev2 = valid_evidence("ev-12b", vec![TransitionType::PolicyOverride]);
        let req = make_request(
            "req-12",
            TransitionType::PolicyOverride,
            vec![ev1, ev2],
        );
        let ctx = default_trust_ctx();

        let decision = gate.evaluate(&req, &ctx);
        assert!(
            decision.is_authorized(),
            "Expected Authorized when min_evidence=2 and 2 provided"
        );
    }

    // Test 13: Trust level below minimum is denied.
    #[test]
    fn test_deny_insufficient_trust_level() {
        let mut overrides = BTreeMap::new();
        overrides.insert(
            TransitionType::CapabilityGrant,
            TransitionOverride {
                min_evidence_count: None,
                max_evidence_age_millis: None,
                min_trust_level: Some(80),
            },
        );
        let policy = GatePolicy {
            transition_overrides: overrides,
            ..GatePolicy::default()
        };
        let mut gate = ControlTransitionGate::new(policy, NOW);
        let ev = valid_evidence("ev-13", vec![TransitionType::CapabilityGrant]);
        let req = make_request("req-13", TransitionType::CapabilityGrant, vec![ev]);
        let ctx = ActorTrustContext {
            actor_identity: "actor-low".to_string(),
            trust_level: 30,
            capabilities: vec![],
        };

        let decision = gate.evaluate(&req, &ctx);
        assert!(decision.is_denied());
        if let AuthorizationDecision::Denied { reason, .. } = &decision {
            assert_eq!(reason.error_code, error_codes::ERR_CTL_INSUFFICIENT_TRUST);
        }
        assert_eq!(gate.metrics().denied_insufficient_trust, 1);
    }

    // Test 14: Evidence that is too old (age > max) is rejected.
    #[test]
    fn test_deny_evidence_too_old() {
        let policy = GatePolicy {
            max_evidence_age_millis: 5_000, // 5 seconds
            ..GatePolicy::default()
        };
        let mut gate = ControlTransitionGate::new(policy, NOW);
        let ev = VefEvidenceRef {
            evidence_id: "ev-old".to_string(),
            evidence_hash: "sha256:old".to_string(),
            scope: vec![TransitionType::TrustLevelChange],
            state: VerificationState::Verified,
            created_at_millis: NOW - 10_000, // 10 seconds old
            expires_at_millis: NOW + 3_600_000,
            trace_id: "trace-test".to_string(),
        };
        let req = make_request("req-14", TransitionType::TrustLevelChange, vec![ev]);
        let ctx = default_trust_ctx();

        let decision = gate.evaluate(&req, &ctx);
        assert!(decision.is_denied());
    }

    // Test 15: Metrics are tracked per transition type.
    #[test]
    fn test_per_transition_type_metrics() {
        let mut gate = default_gate();
        let ev = valid_evidence("ev-15", vec![TransitionType::ArtifactPromotion]);
        let req = make_request("req-15", TransitionType::ArtifactPromotion, vec![ev]);
        let ctx = default_trust_ctx();

        let _ = gate.evaluate(&req, &ctx);
        let tm = gate
            .metrics()
            .per_transition_type
            .get(&TransitionType::ArtifactPromotion)
            .unwrap();
        assert_eq!(tm.authorized, 1);
        assert_eq!(tm.total, 1);
    }

    // Test 16: Batch evaluation works correctly.
    #[test]
    fn test_batch_evaluate() {
        let mut gate = default_gate();
        let ev1 = valid_evidence("ev-b1", vec![TransitionType::CapabilityGrant]);
        let req1 = make_request("req-b1", TransitionType::CapabilityGrant, vec![ev1]);
        let req2 = make_request("req-b2", TransitionType::TrustLevelChange, vec![]);
        let ctx = default_trust_ctx();

        let decisions = gate.evaluate_batch(&[(req1, ctx.clone()), (req2, ctx)]);
        assert_eq!(decisions.len(), 2);
        assert!(decisions[0].is_authorized());
        assert!(decisions[1].is_denied());
    }

    // Test 17: drain_events clears the event list.
    #[test]
    fn test_drain_events() {
        let mut gate = default_gate();
        let req = make_request("req-17", TransitionType::PolicyOverride, vec![]);
        let ctx = default_trust_ctx();

        let _ = gate.evaluate(&req, &ctx);
        assert!(!gate.events().is_empty());

        let drained = gate.drain_events();
        assert!(!drained.is_empty());
        assert!(gate.events().is_empty());
    }

    // Test 18: Schema version constant is defined.
    #[test]
    fn test_schema_version_defined() {
        assert_eq!(CONTROL_INTEGRATION_SCHEMA_VERSION, "vef-control-integration-v1");
    }

    // Test 19: Invariant constants are defined.
    #[test]
    fn test_invariant_constants_defined() {
        assert_eq!(INV_CTL_EVIDENCE_REQUIRED, "INV-CTL-EVIDENCE-REQUIRED");
        assert_eq!(INV_CTL_DENY_LOGGED, "INV-CTL-DENY-LOGGED");
        assert_eq!(INV_CTL_NO_BYPASS, "INV-CTL-NO-BYPASS");
    }

    // Test 20: TransitionType Display works.
    #[test]
    fn test_transition_type_display() {
        assert_eq!(TransitionType::CapabilityGrant.to_string(), "capability_grant");
        assert_eq!(TransitionType::TrustLevelChange.to_string(), "trust_level_change");
        assert_eq!(TransitionType::ArtifactPromotion.to_string(), "artifact_promotion");
        assert_eq!(TransitionType::PolicyOverride.to_string(), "policy_override");
    }

    // Test 21: VerificationState validity checks.
    #[test]
    fn test_verification_state_validity() {
        assert!(VerificationState::Verified.is_valid());
        assert!(!VerificationState::Unverified.is_valid());
        assert!(!VerificationState::Expired.is_valid());
        assert!(!VerificationState::Invalid.is_valid());
    }

    // Test 22: VefEvidenceRef expiration check.
    #[test]
    fn test_evidence_ref_expiration() {
        let ev = valid_evidence("ev-22", vec![TransitionType::CapabilityGrant]);
        assert!(!ev.is_expired_at(NOW));
        assert!(ev.is_expired_at(NOW + 4_000_000));
    }

    // Test 23: VefEvidenceRef scope coverage check.
    #[test]
    fn test_evidence_ref_scope_coverage() {
        let ev = valid_evidence(
            "ev-23",
            vec![TransitionType::CapabilityGrant, TransitionType::TrustLevelChange],
        );
        assert!(ev.covers_transition(TransitionType::CapabilityGrant));
        assert!(ev.covers_transition(TransitionType::TrustLevelChange));
        assert!(!ev.covers_transition(TransitionType::ArtifactPromotion));
    }

    // Test 24: set_now_millis advances gate time.
    #[test]
    fn test_set_now_millis() {
        let mut gate = default_gate();
        let ev = VefEvidenceRef {
            evidence_id: "ev-24".to_string(),
            evidence_hash: "sha256:timed".to_string(),
            scope: vec![TransitionType::CapabilityGrant],
            state: VerificationState::Verified,
            created_at_millis: NOW - 500,
            expires_at_millis: NOW + 2000,
            trace_id: "trace-test".to_string(),
        };
        let req = make_request("req-24", TransitionType::CapabilityGrant, vec![ev.clone()]);
        let ctx = default_trust_ctx();

        // Should be authorized at NOW
        let d1 = gate.evaluate(&req, &ctx);
        assert!(d1.is_authorized());

        // Advance time past expiration
        gate.set_now_millis(NOW + 3000);
        let req2 = make_request("req-24b", TransitionType::CapabilityGrant, vec![ev]);
        let d2 = gate.evaluate(&req2, &ctx);
        assert!(d2.is_denied(), "Should be denied after expiration");
    }

    // Test 25: GatePolicy default values are reasonable.
    #[test]
    fn test_gate_policy_defaults() {
        let policy = GatePolicy::default();
        assert_eq!(policy.max_evidence_age_millis, 3_600_000);
        assert_eq!(policy.min_evidence_count, 1);
        assert_eq!(policy.min_trust_level, 0);
        assert!(policy.transition_overrides.is_empty());
    }

    // Test 26: AuthorizationDecision predicate helpers.
    #[test]
    fn test_authorization_decision_predicates() {
        let auth = AuthorizationDecision::Authorized {
            evidence_ids: vec!["e1".to_string()],
            detail: "ok".to_string(),
        };
        assert!(auth.is_authorized());
        assert!(!auth.is_denied());
        assert!(!auth.is_pending());

        let denied = AuthorizationDecision::Denied {
            reason: DenialReason {
                error_code: "ERR".to_string(),
                event_code: "EVT".to_string(),
                message: "no".to_string(),
                transition_type: TransitionType::CapabilityGrant,
            },
            detail: "denied".to_string(),
        };
        assert!(!denied.is_authorized());
        assert!(denied.is_denied());
        assert!(!denied.is_pending());

        let pending = AuthorizationDecision::PendingVerification {
            pending_evidence_ids: vec!["p1".to_string()],
            detail: "wait".to_string(),
        };
        assert!(!pending.is_authorized());
        assert!(!pending.is_denied());
        assert!(pending.is_pending());
    }

    // Test 27: Expired verification state evidence is rejected.
    #[test]
    fn test_expired_verification_state_rejected() {
        let mut gate = default_gate();
        let ev = VefEvidenceRef {
            evidence_id: "ev-27".to_string(),
            evidence_hash: "sha256:exp-state".to_string(),
            scope: vec![TransitionType::PolicyOverride],
            state: VerificationState::Expired,
            created_at_millis: NOW - 500,
            expires_at_millis: NOW + 3_600_000,
            trace_id: "trace-test".to_string(),
        };
        let req = make_request("req-27", TransitionType::PolicyOverride, vec![ev]);
        let ctx = default_trust_ctx();

        let decision = gate.evaluate(&req, &ctx);
        assert!(decision.is_denied());
    }

    // Test 28: DenialReason Display trait.
    #[test]
    fn test_denial_reason_display() {
        let reason = DenialReason {
            error_code: error_codes::ERR_CTL_MISSING_EVIDENCE.to_string(),
            event_code: event_codes::CTL_003_DENIED_MISSING_EVIDENCE.to_string(),
            message: "No evidence".to_string(),
            transition_type: TransitionType::CapabilityGrant,
        };
        let display = format!("{}", reason);
        assert!(display.contains(error_codes::ERR_CTL_MISSING_EVIDENCE));
        assert!(display.contains("capability_grant"));
    }

    // Test 29: Serde round-trip for TransitionRequest.
    #[test]
    fn test_serde_roundtrip_transition_request() {
        let ev = valid_evidence("ev-rt", vec![TransitionType::CapabilityGrant]);
        let req = make_request("req-rt", TransitionType::CapabilityGrant, vec![ev]);
        let json = serde_json::to_string(&req).expect("serialize");
        let req2: TransitionRequest = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(req, req2);
    }

    // Test 30: Serde round-trip for AuthorizationDecision.
    #[test]
    fn test_serde_roundtrip_authorization_decision() {
        let decision = AuthorizationDecision::Authorized {
            evidence_ids: vec!["e1".to_string()],
            detail: "ok".to_string(),
        };
        let json = serde_json::to_string(&decision).expect("serialize");
        let d2: AuthorizationDecision = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(decision, d2);
    }

    // Test 31: GateEvent contains correct trace_id.
    #[test]
    fn test_gate_event_trace_id_propagation() {
        let mut gate = default_gate();
        let ev = valid_evidence("ev-31", vec![TransitionType::CapabilityGrant]);
        let req = TransitionRequest {
            request_id: "req-31".to_string(),
            transition_type: TransitionType::CapabilityGrant,
            actor_identity: "actor-1".to_string(),
            target_identity: "target-1".to_string(),
            evidence_refs: vec![ev],
            context: BTreeMap::new(),
            trace_id: "unique-trace-42".to_string(),
            requested_at_millis: NOW,
        };
        let ctx = default_trust_ctx();

        let _ = gate.evaluate(&req, &ctx);
        assert!(
            gate.events()
                .iter()
                .all(|e| e.trace_id == "unique-trace-42"),
            "All events should propagate trace_id"
        );
    }
}
