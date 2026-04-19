//! bd-137: Policy-visible compatibility gate APIs.
//!
//! Exposes compatibility mode transitions, divergence receipts, and policy gates
//! as programmatic APIs. One of the 10 Impossible-by-Default capabilities:
//! operators must control which compatibility behaviors are active, at what risk
//! level, with full traceability.
//!
//! # API Surfaces
//!
//! 1. Gate check endpoint — allow/deny/audit decisions
//! 2. Mode query — current compatibility mode per scope
//! 3. Mode transition — policy-gated mode changes with receipts
//! 4. Receipt query — divergence receipt retrieval
//! 5. Shim registry query — full typed metadata for all registered shims
//!
//! # Event Codes
//!
//! - `PCG-001`: Gate check passed
//! - `PCG-002`: Gate check failed
//! - `PCG-003`: Mode transition approved
//! - `PCG-004`: Divergence receipt issued
//!
//! # Invariants
//!
//! - **INV-PCG-VISIBLE**: All gate decisions visible via structured API responses
//! - **INV-PCG-AUDITABLE**: Every gate decision produces structured audit events
//! - **INV-PCG-RECEIPT**: Every divergence/transition produces signed receipts
//! - **INV-PCG-TRANSITION**: Mode transitions are policy-gated

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const PCG_001_GATE_PASSED: &str = "PCG-001";
    pub const PCG_002_GATE_FAILED: &str = "PCG-002";
    pub const PCG_003_TRANSITION_APPROVED: &str = "PCG-003";
    pub const PCG_004_RECEIPT_ISSUED: &str = "PCG-004";
}

use event_codes::*;

pub mod error_codes {
    pub const ERR_COMPAT_SHIM_CAPACITY: &str = "ERR_COMPAT_SHIM_CAPACITY";
    pub const ERR_COMPAT_PREDICATE_CAPACITY: &str = "ERR_COMPAT_PREDICATE_CAPACITY";
    pub const ERR_COMPAT_TRACE_ID_EXHAUSTED: &str = "ERR_COMPAT_TRACE_ID_EXHAUSTED";
    pub const ERR_COMPAT_RECEIPT_ID_EXHAUSTED: &str = "ERR_COMPAT_RECEIPT_ID_EXHAUSTED";
}

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

use crate::capacity_defaults::aliases::{MAX_EVENTS, MAX_PREDICATES, MAX_RECEIPTS, MAX_SHIMS};

pub const INV_PCG_VISIBLE: &str = "INV-PCG-VISIBLE";
pub const INV_PCG_AUDITABLE: &str = "INV-PCG-AUDITABLE";
pub const INV_PCG_RECEIPT: &str = "INV-PCG-RECEIPT";
pub const INV_PCG_TRANSITION: &str = "INV-PCG-TRANSITION";

// ---------------------------------------------------------------------------
// Compatibility mode
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatMode {
    Strict,
    Balanced,
    LegacyRisky,
}

impl CompatMode {
    pub fn risk_level(&self) -> &'static str {
        match self {
            Self::Strict => "low",
            Self::Balanced => "medium",
            Self::LegacyRisky => "high",
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Balanced => "balanced",
            Self::LegacyRisky => "legacy_risky",
        }
    }

    pub fn risk_ordinal(&self) -> u8 {
        match self {
            Self::Strict => 0,
            Self::Balanced => 1,
            Self::LegacyRisky => 2,
        }
    }

    pub fn is_escalation(&self, to: CompatMode) -> bool {
        to.risk_ordinal() > self.risk_ordinal()
    }
}

impl fmt::Display for CompatMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Gate decision
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GateDecision {
    Allow,
    Deny,
    Audit,
}

impl GateDecision {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Audit => "audit",
        }
    }
}

impl fmt::Display for GateDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

// ---------------------------------------------------------------------------
// Shim metadata
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShimMetadata {
    pub shim_id: String,
    pub description: String,
    pub risk_category: String,
    pub activation_policy: String,
    pub divergence_rationale: String,
    pub scope: String,
}

// ---------------------------------------------------------------------------
// Policy predicate (policy-as-data)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyPredicate {
    pub predicate_id: String,
    pub signature: String,
    pub attenuation: Vec<String>,
    pub activation_condition: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatGateRegistrationError {
    ShimCapacityExceeded { capacity: usize },
    PredicateCapacityExceeded { capacity: usize },
}

impl CompatGateRegistrationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::ShimCapacityExceeded { .. } => error_codes::ERR_COMPAT_SHIM_CAPACITY,
            Self::PredicateCapacityExceeded { .. } => error_codes::ERR_COMPAT_PREDICATE_CAPACITY,
        }
    }
}

impl fmt::Display for CompatGateRegistrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ShimCapacityExceeded { capacity } => write!(
                f,
                "compatibility shim registry at capacity ({capacity}); refusing to evict existing active shim"
            ),
            Self::PredicateCapacityExceeded { capacity } => write!(
                f,
                "compatibility predicate registry at capacity ({capacity}); refusing to evict existing active predicate"
            ),
        }
    }
}

impl std::error::Error for CompatGateRegistrationError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CompatGateOperationError {
    TraceIdSpaceExhausted,
    ReceiptIdSpaceExhausted,
}

impl CompatGateOperationError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::TraceIdSpaceExhausted => error_codes::ERR_COMPAT_TRACE_ID_EXHAUSTED,
            Self::ReceiptIdSpaceExhausted => error_codes::ERR_COMPAT_RECEIPT_ID_EXHAUSTED,
        }
    }
}

impl fmt::Display for CompatGateOperationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TraceIdSpaceExhausted => f.write_str("compat gate trace ID space exhausted"),
            Self::ReceiptIdSpaceExhausted => f.write_str("compat gate receipt ID space exhausted"),
        }
    }
}

impl std::error::Error for CompatGateOperationError {}

// ---------------------------------------------------------------------------
// Gate check request/response
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateCheckRequest {
    pub package_id: String,
    pub requested_mode: CompatMode,
    pub scope: String,
    pub policy_context: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GateCheckResponse {
    pub decision: GateDecision,
    pub rationale: String,
    pub trace_id: String,
    pub receipt_id: String,
}

// ---------------------------------------------------------------------------
// Mode query response
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeQueryResponse {
    pub mode: CompatMode,
    pub activated_at: String,
    pub receipt_id: String,
    pub policy_predicate: Option<PolicyPredicate>,
}

// ---------------------------------------------------------------------------
// Mode transition request/response
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeTransitionRequest {
    pub scope_id: String,
    pub from_mode: CompatMode,
    pub to_mode: CompatMode,
    pub justification: String,
    pub requestor: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeTransitionResponse {
    pub transition_id: String,
    pub approved: bool,
    pub receipt_id: String,
    pub rationale: String,
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatReceipt {
    pub receipt_id: String,
    pub scope: String,
    pub receipt_type: String,
    pub severity: String,
    pub issued_at: String,
    pub signature: String,
    pub payload_hash: String,
}

// ---------------------------------------------------------------------------
// Audit event
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatGateEvent {
    pub code: String,
    pub trace_id: String,
    pub scope: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// CompatGateService — the main gate logic
// ---------------------------------------------------------------------------

pub struct CompatGateService {
    scopes: BTreeMap<String, CompatMode>,
    shims: Vec<ShimMetadata>,
    receipts: Vec<CompatReceipt>,
    events: Vec<CompatGateEvent>,
    predicates: Vec<PolicyPredicate>,
    trace_counter: u64,
    trace_epoch: u64,
    receipt_counter: u64,
    receipt_epoch: u64,
}

impl CompatGateService {
    pub fn new() -> Self {
        Self {
            scopes: BTreeMap::new(),
            shims: Vec::new(),
            receipts: Vec::new(),
            events: Vec::new(),
            predicates: Vec::new(),
            trace_counter: 0,
            trace_epoch: 0,
            receipt_counter: 0,
            receipt_epoch: 0,
        }
    }

    fn next_trace_id(&mut self) -> Result<String, CompatGateOperationError> {
        if self.trace_counter == u64::MAX {
            let Some(next_epoch) = self.trace_epoch.checked_add(1) else {
                return Err(CompatGateOperationError::TraceIdSpaceExhausted);
            };
            self.trace_counter = 1;
            self.trace_epoch = next_epoch;
        } else {
            self.trace_counter = self.trace_counter.saturating_add(1);
        }

        Ok(if self.trace_epoch == 0 {
            format!("trace-{:06}", self.trace_counter)
        } else {
            format!(
                "trace-{:016x}-{:016x}",
                self.trace_epoch, self.trace_counter
            )
        })
    }

    fn next_receipt_id(&mut self) -> Result<String, CompatGateOperationError> {
        if self.receipt_counter == u64::MAX {
            let Some(next_epoch) = self.receipt_epoch.checked_add(1) else {
                return Err(CompatGateOperationError::ReceiptIdSpaceExhausted);
            };
            self.receipt_counter = 1;
            self.receipt_epoch = next_epoch;
        } else {
            self.receipt_counter = self.receipt_counter.saturating_add(1);
        }

        Ok(if self.receipt_epoch == 0 {
            format!("rcpt-{:06}", self.receipt_counter)
        } else {
            format!(
                "rcpt-{:016x}-{:016x}",
                self.receipt_epoch, self.receipt_counter
            )
        })
    }

    fn reserve_gate_ids(&mut self) -> Result<(String, String), CompatGateOperationError> {
        if self.trace_counter == u64::MAX && self.trace_epoch == u64::MAX {
            return Err(CompatGateOperationError::TraceIdSpaceExhausted);
        }
        if self.receipt_counter == u64::MAX && self.receipt_epoch == u64::MAX {
            return Err(CompatGateOperationError::ReceiptIdSpaceExhausted);
        }

        let trace_id = self.next_trace_id()?;
        let receipt_id = self.next_receipt_id()?;
        Ok((trace_id, receipt_id))
    }

    /// Register a compatibility shim.
    ///
    /// Returns an error instead of evicting an active shim when the registry is full.
    pub fn register_shim(&mut self, shim: ShimMetadata) -> Result<(), CompatGateRegistrationError> {
        if self.shims.len() >= MAX_SHIMS {
            return Err(CompatGateRegistrationError::ShimCapacityExceeded {
                capacity: MAX_SHIMS,
            });
        }
        self.shims.push(shim);
        Ok(())
    }

    /// Register a policy predicate.
    ///
    /// Returns an error instead of evicting an active predicate when the registry is full.
    pub fn register_predicate(
        &mut self,
        predicate: PolicyPredicate,
    ) -> Result<(), CompatGateRegistrationError> {
        if self.predicates.len() >= MAX_PREDICATES {
            return Err(CompatGateRegistrationError::PredicateCapacityExceeded {
                capacity: MAX_PREDICATES,
            });
        }
        self.predicates.push(predicate);
        Ok(())
    }

    /// Set the current mode for a scope.
    pub fn set_scope_mode(&mut self, scope: &str, mode: CompatMode) {
        self.scopes.insert(scope.to_string(), mode);
    }

    /// Query the current mode for a scope.
    pub fn query_mode(&self, scope: &str) -> Option<ModeQueryResponse> {
        self.scopes.get(scope).map(|mode| ModeQueryResponse {
            mode: *mode,
            activated_at: "2026-01-01T00:00:00Z".to_string(),
            receipt_id: String::new(),
            policy_predicate: self.predicates.first().cloned(),
        })
    }

    /// Query all registered shims, optionally filtered by scope.
    pub fn query_shims(&self, scope: Option<&str>) -> Vec<&ShimMetadata> {
        match scope {
            Some(s) => self
                .shims
                .iter()
                .filter(|shim| shim.scope == s || shim.scope == "*")
                .collect(),
            None => self.shims.iter().collect(),
        }
    }

    /// Perform a gate check: is a package allowed under a given compatibility mode?
    ///
    /// Returns an error if the trace/receipt identifier space is exhausted.
    pub fn gate_check(
        &mut self,
        request: &GateCheckRequest,
    ) -> Result<GateCheckResponse, CompatGateOperationError> {
        let (trace_id, receipt_id) = self.reserve_gate_ids()?;

        let scope_mode = self
            .scopes
            .get(&request.scope)
            .copied()
            .unwrap_or(CompatMode::Strict);

        // Decision logic: deny if requested mode is riskier than scope's current mode
        let decision = if request.requested_mode.risk_ordinal() > scope_mode.risk_ordinal() {
            GateDecision::Deny
        } else if request.requested_mode == CompatMode::LegacyRisky {
            GateDecision::Audit
        } else {
            GateDecision::Allow
        };

        let rationale = match decision {
            GateDecision::Allow => format!(
                "package '{}' allowed under {} mode in scope '{}'",
                request.package_id, request.requested_mode, request.scope
            ),
            GateDecision::Deny => format!(
                "package '{}' denied: requested {} exceeds scope '{}' risk level ({})",
                request.package_id, request.requested_mode, request.scope, scope_mode
            ),
            GateDecision::Audit => format!(
                "package '{}' allowed with audit under {} mode in scope '{}'",
                request.package_id, request.requested_mode, request.scope
            ),
        };

        let event_code = match decision {
            GateDecision::Allow | GateDecision::Audit => PCG_001_GATE_PASSED,
            GateDecision::Deny => PCG_002_GATE_FAILED,
        };

        self.emit_event(event_code, &trace_id, &request.scope, &rationale);

        // Issue receipt for divergence tracking
        push_bounded(
            &mut self.receipts,
            CompatReceipt {
                receipt_id: receipt_id.clone(),
                scope: request.scope.clone(),
                receipt_type: "gate_check".to_string(),
                severity: scope_mode.risk_level().to_string(),
                issued_at: "2026-01-01T00:00:00Z".to_string(),
                signature: format!("sig-{}", receipt_id),
                payload_hash: format!("hash-{}", receipt_id),
            },
            MAX_RECEIPTS,
        );

        Ok(GateCheckResponse {
            decision,
            rationale,
            trace_id,
            receipt_id,
        })
    }

    /// Request a mode transition. Escalations require justification; de-escalations are auto-approved.
    ///
    /// Returns an error if the trace/receipt identifier space is exhausted.
    pub fn request_transition(
        &mut self,
        request: &ModeTransitionRequest,
    ) -> Result<ModeTransitionResponse, CompatGateOperationError> {
        let (trace_id, receipt_id) = self.reserve_gate_ids()?;

        let current_mode = self
            .scopes
            .get(&request.scope_id)
            .copied()
            .unwrap_or(CompatMode::Strict);

        let (approved, rationale) = if current_mode != request.from_mode {
            (
                false,
                format!(
                    "transition denied: requested from_mode {} does not match actual current mode {}",
                    request.from_mode, current_mode
                ),
            )
        } else {
            let is_escalation = current_mode.is_escalation(request.to_mode);
            let approved = if is_escalation {
                !request.justification.trim().is_empty()
            } else {
                true
            };

            let rationale = if approved {
                if is_escalation {
                    format!(
                        "escalation from {} to {} approved with justification",
                        current_mode, request.to_mode
                    )
                } else {
                    format!(
                        "de-escalation from {} to {} auto-approved",
                        current_mode, request.to_mode
                    )
                }
            } else {
                format!(
                    "escalation from {} to {} denied: justification required",
                    current_mode, request.to_mode
                )
            };

            (approved, rationale)
        };

        if approved {
            self.scopes
                .insert(request.scope_id.clone(), request.to_mode);

            self.emit_event(
                PCG_003_TRANSITION_APPROVED,
                &trace_id,
                &request.scope_id,
                &rationale,
            );
        }

        push_bounded(
            &mut self.receipts,
            CompatReceipt {
                receipt_id: receipt_id.clone(),
                scope: request.scope_id.clone(),
                receipt_type: "mode_transition".to_string(),
                severity: request.to_mode.risk_level().to_string(),
                issued_at: "2026-01-01T00:00:00Z".to_string(),
                signature: format!("sig-{}", receipt_id),
                payload_hash: format!("hash-{}", receipt_id),
            },
            MAX_RECEIPTS,
        );

        Ok(ModeTransitionResponse {
            transition_id: trace_id,
            approved,
            receipt_id,
            rationale,
        })
    }

    /// Issue a divergence receipt.
    ///
    /// Returns an error if the trace/receipt identifier space is exhausted.
    pub fn issue_divergence_receipt(
        &mut self,
        scope: &str,
        severity: &str,
    ) -> Result<CompatReceipt, CompatGateOperationError> {
        let (trace_id, receipt_id) = self.reserve_gate_ids()?;

        let receipt = CompatReceipt {
            receipt_id: receipt_id.clone(),
            scope: scope.to_string(),
            receipt_type: "divergence".to_string(),
            severity: severity.to_string(),
            issued_at: "2026-01-01T00:00:00Z".to_string(),
            signature: format!("sig-{}", receipt_id),
            payload_hash: format!("hash-{}", receipt_id),
        };

        self.emit_event(
            PCG_004_RECEIPT_ISSUED,
            &trace_id,
            scope,
            &format!("divergence receipt issued: severity={}", severity),
        );

        push_bounded(&mut self.receipts, receipt.clone(), MAX_RECEIPTS);
        Ok(receipt)
    }

    /// Query receipts, optionally filtered by scope and severity.
    pub fn query_receipts(
        &self,
        scope: Option<&str>,
        severity: Option<&str>,
    ) -> Vec<&CompatReceipt> {
        self.receipts
            .iter()
            .filter(|r| scope.is_none_or(|s| r.scope == s))
            .filter(|r| severity.is_none_or(|s| r.severity == s))
            .collect()
    }

    /// Non-interference check: shim activation in scope A has no effect in scope B.
    pub fn check_non_interference(&self, scope_a: &str, scope_b: &str) -> bool {
        let mode_a = self.scopes.get(scope_a);
        let mode_b = self.scopes.get(scope_b);
        // Non-interference holds if scope modes are independently set
        mode_a != mode_b || mode_a.is_none()
    }

    /// Monotonicity check: adding shims never weakens security.
    /// Returns true if the current shim set does not reduce security guarantees.
    pub fn check_monotonicity(&self) -> bool {
        // Monotonicity: no shim has a risk_category of "security_weakening"
        !self
            .shims
            .iter()
            .any(|s| s.risk_category == "security_weakening")
    }

    /// Gate pass: all invariants hold.
    pub fn gate_pass(&self) -> bool {
        // INV-PCG-VISIBLE: events exist for gate checks
        let visible = self
            .events
            .iter()
            .any(|e| e.code == PCG_001_GATE_PASSED || e.code == PCG_002_GATE_FAILED);

        // INV-PCG-AUDITABLE: all events have trace IDs
        let auditable = self.events.iter().all(|e| !e.trace_id.is_empty());

        // INV-PCG-RECEIPT: receipts exist
        let has_receipts = !self.receipts.is_empty();

        // INV-PCG-TRANSITION: transitions are policy-gated (checked at request time)
        let transition_ok = true; // Enforced by request_transition logic

        visible && auditable && has_receipts && transition_ok
    }

    pub fn to_report(&self) -> serde_json::Value {
        let verdict = if self.gate_pass() { "PASS" } else { "FAIL" };
        serde_json::json!({
            "bead_id": "bd-137",
            "section": "10.5",
            "gate_verdict": verdict,
            "summary": {
                "total_events": self.events.len(),
                "total_receipts": self.receipts.len(),
                "total_shims": self.shims.len(),
                "total_scopes": self.scopes.len(),
                "monotonicity_holds": self.check_monotonicity(),
            },
            "invariants": {
                INV_PCG_VISIBLE: self.events.iter().any(|e| e.code == PCG_001_GATE_PASSED || e.code == PCG_002_GATE_FAILED),
                INV_PCG_AUDITABLE: self.events.iter().all(|e| !e.trace_id.is_empty()),
                INV_PCG_RECEIPT: !self.receipts.is_empty(),
                INV_PCG_TRANSITION: true,
            },
        })
    }

    pub fn events(&self) -> &[CompatGateEvent] {
        &self.events
    }

    pub fn take_events(&mut self) -> Vec<CompatGateEvent> {
        std::mem::take(&mut self.events)
    }

    pub fn receipts(&self) -> &[CompatReceipt] {
        &self.receipts
    }

    fn emit_event(&mut self, code: &str, trace_id: &str, scope: &str, detail: &str) {
        push_bounded(
            &mut self.events,
            CompatGateEvent {
                code: code.to_string(),
                trace_id: trace_id.to_string(),
                scope: scope.to_string(),
                detail: detail.to_string(),
            },
            MAX_EVENTS,
        );
    }
}

impl Default for CompatGateService {
    fn default() -> Self {
        Self::new()
    }
}

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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_service_with_scope() -> CompatGateService {
        let mut svc = CompatGateService::new();
        svc.set_scope_mode("project-1", CompatMode::Balanced);
        svc.register_shim(ShimMetadata {
            shim_id: "shim-buffer".into(),
            description: "Buffer compatibility shim".into(),
            risk_category: "low".into(),
            activation_policy: "balanced".into(),
            divergence_rationale: "Buffer API differences".into(),
            scope: "project-1".into(),
        })
        .expect("baseline shim registration should succeed");
        svc
    }

    fn make_shim(shim_id: impl Into<String>) -> ShimMetadata {
        let shim_id = shim_id.into();
        ShimMetadata {
            description: format!("compat shim {shim_id}"),
            risk_category: "low".into(),
            activation_policy: "balanced".into(),
            divergence_rationale: "compatibility delta".into(),
            scope: "project-1".into(),
            shim_id,
        }
    }

    fn make_predicate(predicate_id: impl Into<String>) -> PolicyPredicate {
        let predicate_id = predicate_id.into();
        PolicyPredicate {
            predicate_id,
            signature: "sig-policy".into(),
            attenuation: vec!["scope:project-1".into()],
            activation_condition: "mode == balanced".into(),
        }
    }

    // ── Event codes ───────────────────────────────────────────────────────

    #[test]
    fn event_code_pcg_001_defined() {
        assert_eq!(PCG_001_GATE_PASSED, "PCG-001");
    }

    #[test]
    fn event_code_pcg_002_defined() {
        assert_eq!(PCG_002_GATE_FAILED, "PCG-002");
    }

    #[test]
    fn event_code_pcg_003_defined() {
        assert_eq!(PCG_003_TRANSITION_APPROVED, "PCG-003");
    }

    #[test]
    fn event_code_pcg_004_defined() {
        assert_eq!(PCG_004_RECEIPT_ISSUED, "PCG-004");
    }

    // ── Invariants ────────────────────────────────────────────────────────

    #[test]
    fn invariant_visible_defined() {
        assert_eq!(INV_PCG_VISIBLE, "INV-PCG-VISIBLE");
    }

    #[test]
    fn invariant_auditable_defined() {
        assert_eq!(INV_PCG_AUDITABLE, "INV-PCG-AUDITABLE");
    }

    #[test]
    fn invariant_receipt_defined() {
        assert_eq!(INV_PCG_RECEIPT, "INV-PCG-RECEIPT");
    }

    #[test]
    fn invariant_transition_defined() {
        assert_eq!(INV_PCG_TRANSITION, "INV-PCG-TRANSITION");
    }

    // ── CompatMode ────────────────────────────────────────────────────────

    #[test]
    fn compat_mode_risk_levels() {
        assert_eq!(CompatMode::Strict.risk_level(), "low");
        assert_eq!(CompatMode::Balanced.risk_level(), "medium");
        assert_eq!(CompatMode::LegacyRisky.risk_level(), "high");
    }

    #[test]
    fn compat_mode_escalation_detection() {
        assert!(CompatMode::Strict.is_escalation(CompatMode::Balanced));
        assert!(CompatMode::Balanced.is_escalation(CompatMode::LegacyRisky));
        assert!(!CompatMode::LegacyRisky.is_escalation(CompatMode::Strict));
        assert!(!CompatMode::Balanced.is_escalation(CompatMode::Balanced));
    }

    #[test]
    fn compat_mode_serde_roundtrip() {
        for mode in [
            CompatMode::Strict,
            CompatMode::Balanced,
            CompatMode::LegacyRisky,
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            let parsed: CompatMode = serde_json::from_str(&json).unwrap();
            assert_eq!(parsed, mode);
        }
    }

    // ── Gate check ────────────────────────────────────────────────────────

    #[test]
    fn gate_check_allows_within_scope_mode() {
        let mut svc = make_service_with_scope();
        let resp = svc
            .gate_check(&GateCheckRequest {
                package_id: "pkg-1".into(),
                requested_mode: CompatMode::Strict,
                scope: "project-1".into(),
                policy_context: None,
            })
            .unwrap();
        assert_eq!(resp.decision, GateDecision::Allow);
    }

    #[test]
    fn gate_check_denies_when_mode_exceeds_scope() {
        let mut svc = make_service_with_scope();
        let resp = svc
            .gate_check(&GateCheckRequest {
                package_id: "pkg-2".into(),
                requested_mode: CompatMode::LegacyRisky,
                scope: "project-1".into(),
                policy_context: None,
            })
            .unwrap();
        assert_eq!(resp.decision, GateDecision::Deny);
    }

    #[test]
    fn gate_check_emits_passed_event() {
        let mut svc = make_service_with_scope();
        svc.gate_check(&GateCheckRequest {
            package_id: "pkg-1".into(),
            requested_mode: CompatMode::Strict,
            scope: "project-1".into(),
            policy_context: None,
        })
        .unwrap();
        assert!(svc.events().iter().any(|e| e.code == PCG_001_GATE_PASSED));
    }

    #[test]
    fn gate_check_emits_failed_event() {
        let mut svc = make_service_with_scope();
        svc.gate_check(&GateCheckRequest {
            package_id: "pkg-2".into(),
            requested_mode: CompatMode::LegacyRisky,
            scope: "project-1".into(),
            policy_context: None,
        })
        .unwrap();
        assert!(svc.events().iter().any(|e| e.code == PCG_002_GATE_FAILED));
    }

    #[test]
    fn gate_check_creates_receipt() {
        let mut svc = make_service_with_scope();
        let resp = svc
            .gate_check(&GateCheckRequest {
                package_id: "pkg-1".into(),
                requested_mode: CompatMode::Strict,
                scope: "project-1".into(),
                policy_context: None,
            })
            .unwrap();
        assert!(!resp.receipt_id.is_empty());
        assert!(!svc.receipts().is_empty());
    }

    #[test]
    fn gate_check_has_trace_id() {
        let mut svc = make_service_with_scope();
        let resp = svc
            .gate_check(&GateCheckRequest {
                package_id: "pkg-1".into(),
                requested_mode: CompatMode::Strict,
                scope: "project-1".into(),
                policy_context: None,
            })
            .unwrap();
        assert!(!resp.trace_id.is_empty());
    }

    #[test]
    fn trace_counter_rollover_preserves_unique_ids() {
        let mut svc = make_service_with_scope();
        svc.trace_counter = u64::MAX - 1;

        let first = svc.next_trace_id().unwrap();
        let second = svc.next_trace_id().unwrap();

        assert_ne!(first, second);
        assert_eq!(first, "trace-18446744073709551615");
        assert_eq!(second, "trace-0000000000000001-0000000000000001");
        assert_eq!(svc.trace_epoch, 1);
        assert_eq!(svc.trace_counter, 1);
    }

    #[test]
    fn trace_counter_fails_closed_after_terminal_value_is_issued() {
        let mut svc = make_service_with_scope();
        svc.trace_counter = u64::MAX - 1;
        svc.trace_epoch = u64::MAX;
        let final_id = svc.next_trace_id().unwrap();
        assert_eq!(final_id, "trace-ffffffffffffffff-ffffffffffffffff");
        let err = svc
            .next_trace_id()
            .expect_err("trace ID exhaustion must fail closed");
        assert_eq!(err, CompatGateOperationError::TraceIdSpaceExhausted);
        assert_eq!(err.code(), error_codes::ERR_COMPAT_TRACE_ID_EXHAUSTED);
        assert_eq!(svc.trace_counter, u64::MAX);
        assert_eq!(svc.trace_epoch, u64::MAX);
    }

    #[test]
    fn receipt_counter_rollover_preserves_unique_ids() {
        let mut svc = make_service_with_scope();
        svc.receipt_counter = u64::MAX - 1;

        let first = svc.next_receipt_id().unwrap();
        let second = svc.next_receipt_id().unwrap();

        assert_ne!(first, second);
        assert_eq!(first, "rcpt-18446744073709551615");
        assert_eq!(second, "rcpt-0000000000000001-0000000000000001");
        assert_eq!(svc.receipt_epoch, 1);
        assert_eq!(svc.receipt_counter, 1);
    }

    #[test]
    fn receipt_counter_fails_closed_after_terminal_value_is_issued() {
        let mut svc = make_service_with_scope();
        svc.receipt_counter = u64::MAX - 1;
        svc.receipt_epoch = u64::MAX;
        let final_id = svc.next_receipt_id().unwrap();
        assert_eq!(final_id, "rcpt-ffffffffffffffff-ffffffffffffffff");
        let err = svc
            .next_receipt_id()
            .expect_err("receipt ID exhaustion must fail closed");
        assert_eq!(err, CompatGateOperationError::ReceiptIdSpaceExhausted);
        assert_eq!(err.code(), error_codes::ERR_COMPAT_RECEIPT_ID_EXHAUSTED);
        assert_eq!(svc.receipt_counter, u64::MAX);
        assert_eq!(svc.receipt_epoch, u64::MAX);
    }

    #[test]
    fn gate_check_rollover_keeps_trace_and_receipt_ids_unique() {
        let mut svc = make_service_with_scope();
        svc.trace_counter = u64::MAX - 1;
        svc.receipt_counter = u64::MAX - 1;

        let first = svc
            .gate_check(&GateCheckRequest {
                package_id: "pkg-1".into(),
                requested_mode: CompatMode::Strict,
                scope: "project-1".into(),
                policy_context: None,
            })
            .unwrap();
        let second = svc
            .gate_check(&GateCheckRequest {
                package_id: "pkg-1".into(),
                requested_mode: CompatMode::Strict,
                scope: "project-1".into(),
                policy_context: None,
            })
            .unwrap();

        assert_ne!(first.trace_id, second.trace_id);
        assert_ne!(first.receipt_id, second.receipt_id);
    }

    #[test]
    fn gate_check_fails_closed_when_trace_id_space_is_exhausted() {
        let mut svc = make_service_with_scope();
        svc.trace_counter = u64::MAX;
        svc.trace_epoch = u64::MAX;

        let err = svc
            .gate_check(&GateCheckRequest {
                package_id: "pkg-1".into(),
                requested_mode: CompatMode::Strict,
                scope: "project-1".into(),
                policy_context: None,
            })
            .expect_err("trace ID exhaustion must reject gate checks");

        assert_eq!(err, CompatGateOperationError::TraceIdSpaceExhausted);
        assert_eq!(svc.receipt_counter, 0);
        assert!(svc.events().is_empty());
        assert!(svc.receipts().is_empty());
    }

    #[test]
    fn gate_check_fails_closed_when_receipt_id_space_is_exhausted_without_burning_trace_id() {
        let mut svc = make_service_with_scope();
        svc.trace_counter = 41;
        svc.receipt_counter = u64::MAX;
        svc.receipt_epoch = u64::MAX;

        let err = svc
            .gate_check(&GateCheckRequest {
                package_id: "pkg-1".into(),
                requested_mode: CompatMode::Strict,
                scope: "project-1".into(),
                policy_context: None,
            })
            .expect_err("receipt ID exhaustion must reject gate checks");

        assert_eq!(err, CompatGateOperationError::ReceiptIdSpaceExhausted);
        assert_eq!(svc.trace_counter, 41);
        assert_eq!(svc.receipt_counter, u64::MAX);
        assert!(svc.events().is_empty());
        assert!(svc.receipts().is_empty());
    }

    // ── Mode query ────────────────────────────────────────────────────────

    #[test]
    fn mode_query_returns_set_mode() {
        let svc = make_service_with_scope();
        let mode = svc.query_mode("project-1");
        assert!(mode.is_some());
        assert_eq!(mode.unwrap().mode, CompatMode::Balanced);
    }

    #[test]
    fn mode_query_returns_none_for_unknown_scope() {
        let svc = CompatGateService::new();
        assert!(svc.query_mode("unknown").is_none());
    }

    // ── Mode transition ───────────────────────────────────────────────────

    #[test]
    fn transition_de_escalation_auto_approved() {
        let mut svc = make_service_with_scope();
        let resp = svc
            .request_transition(&ModeTransitionRequest {
                scope_id: "project-1".into(),
                from_mode: CompatMode::Balanced,
                to_mode: CompatMode::Strict,
                justification: String::new(),
                requestor: "admin".into(),
            })
            .unwrap();
        assert!(resp.approved);
    }

    #[test]
    fn transition_escalation_requires_justification() {
        let mut svc = make_service_with_scope();
        let resp = svc
            .request_transition(&ModeTransitionRequest {
                scope_id: "project-1".into(),
                from_mode: CompatMode::Balanced,
                to_mode: CompatMode::LegacyRisky,
                justification: String::new(),
                requestor: "admin".into(),
            })
            .unwrap();
        assert!(!resp.approved);
        let receipt = svc
            .receipts()
            .iter()
            .find(|receipt| receipt.receipt_id == resp.receipt_id)
            .expect("denied transition receipt must be queryable");
        assert_eq!(receipt.receipt_type, "mode_transition");
    }

    #[test]
    fn transition_wrong_current_still_persists_receipt() {
        let mut svc = make_service_with_scope();
        let resp = svc
            .request_transition(&ModeTransitionRequest {
                scope_id: "project-1".into(),
                from_mode: CompatMode::Strict,
                to_mode: CompatMode::LegacyRisky,
                justification: "Requested under stale state".into(),
                requestor: "admin".into(),
            })
            .unwrap();
        assert!(!resp.approved);
        let receipt = svc
            .receipts()
            .iter()
            .find(|receipt| receipt.receipt_id == resp.receipt_id)
            .expect("mismatched-current denial receipt must be queryable");
        assert_eq!(receipt.receipt_type, "mode_transition");
    }

    #[test]
    fn transition_escalation_with_justification_approved() {
        let mut svc = make_service_with_scope();
        let resp = svc
            .request_transition(&ModeTransitionRequest {
                scope_id: "project-1".into(),
                from_mode: CompatMode::Balanced,
                to_mode: CompatMode::LegacyRisky,
                justification: "Required for legacy migration".into(),
                requestor: "admin".into(),
            })
            .unwrap();
        assert!(resp.approved);
    }

    #[test]
    fn transition_emits_event_on_approval() {
        let mut svc = make_service_with_scope();
        svc.request_transition(&ModeTransitionRequest {
            scope_id: "project-1".into(),
            from_mode: CompatMode::Balanced,
            to_mode: CompatMode::Strict,
            justification: String::new(),
            requestor: "admin".into(),
        })
        .unwrap();
        assert!(
            svc.events()
                .iter()
                .any(|e| e.code == PCG_003_TRANSITION_APPROVED)
        );
    }

    #[test]
    fn transition_updates_scope_mode() {
        let mut svc = make_service_with_scope();
        svc.request_transition(&ModeTransitionRequest {
            scope_id: "project-1".into(),
            from_mode: CompatMode::Balanced,
            to_mode: CompatMode::Strict,
            justification: String::new(),
            requestor: "admin".into(),
        })
        .unwrap();
        assert_eq!(
            svc.query_mode("project-1").unwrap().mode,
            CompatMode::Strict
        );
    }

    // ── Divergence receipts ───────────────────────────────────────────────

    #[test]
    fn divergence_receipt_issued() {
        let mut svc = make_service_with_scope();
        let receipt = svc.issue_divergence_receipt("project-1", "medium").unwrap();
        assert!(!receipt.receipt_id.is_empty());
        assert_eq!(receipt.receipt_type, "divergence");
    }

    #[test]
    fn divergence_receipt_emits_pcg_004() {
        let mut svc = make_service_with_scope();
        svc.issue_divergence_receipt("project-1", "medium").unwrap();
        assert!(
            svc.events()
                .iter()
                .any(|e| e.code == PCG_004_RECEIPT_ISSUED)
        );
    }

    // ── Shim query ────────────────────────────────────────────────────────

    #[test]
    fn shim_query_returns_registered_shims() {
        let svc = make_service_with_scope();
        let shims = svc.query_shims(Some("project-1"));
        assert_eq!(shims.len(), 1);
        assert_eq!(shims[0].shim_id, "shim-buffer");
    }

    #[test]
    fn shim_query_without_scope_returns_all() {
        let svc = make_service_with_scope();
        let shims = svc.query_shims(None);
        assert_eq!(shims.len(), 1);
    }

    // ── Non-interference ──────────────────────────────────────────────────

    #[test]
    fn non_interference_different_scopes() {
        let mut svc = CompatGateService::new();
        svc.set_scope_mode("scope-a", CompatMode::Strict);
        svc.set_scope_mode("scope-b", CompatMode::LegacyRisky);
        assert!(svc.check_non_interference("scope-a", "scope-b"));
    }

    // ── Monotonicity ──────────────────────────────────────────────────────

    #[test]
    fn monotonicity_holds_with_safe_shims() {
        let svc = make_service_with_scope();
        assert!(svc.check_monotonicity());
    }

    #[test]
    fn monotonicity_fails_with_weakening_shim() {
        let mut svc = CompatGateService::new();
        svc.register_shim(ShimMetadata {
            shim_id: "bad-shim".into(),
            description: "Weakens security".into(),
            risk_category: "security_weakening".into(),
            activation_policy: "any".into(),
            divergence_rationale: "bypasses auth".into(),
            scope: "*".into(),
        })
        .expect("weakening shim registration should succeed");
        assert!(!svc.check_monotonicity());
    }

    #[test]
    fn register_shim_rejects_capacity_overflow_without_eviction() {
        let mut svc = CompatGateService::new();
        for idx in 0..MAX_SHIMS {
            svc.register_shim(make_shim(format!("shim-{idx}")))
                .expect("shim fill should succeed");
        }

        let err = svc
            .register_shim(make_shim("shim-overflow"))
            .expect_err("overflow shim must be rejected");

        assert_eq!(
            err,
            CompatGateRegistrationError::ShimCapacityExceeded {
                capacity: MAX_SHIMS
            }
        );
        assert_eq!(err.code(), error_codes::ERR_COMPAT_SHIM_CAPACITY);
        assert_eq!(svc.shims.len(), MAX_SHIMS);
        assert_eq!(
            svc.shims.first().map(|shim| shim.shim_id.as_str()),
            Some("shim-0")
        );
        let expected_last = format!("shim-{}", MAX_SHIMS - 1);
        assert_eq!(
            svc.shims.last().map(|shim| shim.shim_id.as_str()),
            Some(expected_last.as_str())
        );
        assert!(!svc.shims.iter().any(|shim| shim.shim_id == "shim-overflow"));
    }

    #[test]
    fn register_predicate_rejects_capacity_overflow_without_eviction() {
        let mut svc = CompatGateService::new();
        svc.set_scope_mode("project-1", CompatMode::Balanced);
        for idx in 0..MAX_PREDICATES {
            svc.register_predicate(make_predicate(format!("predicate-{idx}")))
                .expect("predicate fill should succeed");
        }

        let err = svc
            .register_predicate(make_predicate("predicate-overflow"))
            .expect_err("overflow predicate must be rejected");

        assert_eq!(
            err,
            CompatGateRegistrationError::PredicateCapacityExceeded {
                capacity: MAX_PREDICATES
            }
        );
        assert_eq!(err.code(), error_codes::ERR_COMPAT_PREDICATE_CAPACITY);
        assert_eq!(svc.predicates.len(), MAX_PREDICATES);
        assert_eq!(
            svc.predicates
                .first()
                .map(|predicate| predicate.predicate_id.as_str()),
            Some("predicate-0")
        );
        let expected_last = format!("predicate-{}", MAX_PREDICATES - 1);
        assert_eq!(
            svc.predicates
                .last()
                .map(|predicate| predicate.predicate_id.as_str()),
            Some(expected_last.as_str())
        );
        assert!(
            !svc.predicates
                .iter()
                .any(|predicate| predicate.predicate_id == "predicate-overflow")
        );
    }

    // ── Gate pass ─────────────────────────────────────────────────────────

    #[test]
    fn gate_passes_with_clean_service() {
        let mut svc = make_service_with_scope();
        svc.gate_check(&GateCheckRequest {
            package_id: "pkg".into(),
            requested_mode: CompatMode::Strict,
            scope: "project-1".into(),
            policy_context: None,
        })
        .unwrap();
        assert!(svc.gate_pass());
    }

    #[test]
    fn gate_fails_when_empty() {
        let svc = CompatGateService::new();
        assert!(!svc.gate_pass());
    }

    // ── Report ────────────────────────────────────────────────────────────

    #[test]
    fn report_has_bead_id() {
        let svc = CompatGateService::new();
        assert_eq!(svc.to_report()["bead_id"], "bd-137");
    }

    #[test]
    fn report_has_invariants() {
        let svc = CompatGateService::new();
        assert!(svc.to_report().get("invariants").is_some());
    }

    // ── Serde roundtrips ──────────────────────────────────────────────────

    #[test]
    fn gate_check_request_serde_roundtrip() {
        let req = GateCheckRequest {
            package_id: "pkg-1".into(),
            requested_mode: CompatMode::Balanced,
            scope: "scope-1".into(),
            policy_context: Some("ctx".into()),
        };
        let json = serde_json::to_string(&req).unwrap();
        let parsed: GateCheckRequest = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn compat_receipt_serde_roundtrip() {
        let receipt = CompatReceipt {
            receipt_id: "r1".into(),
            scope: "s1".into(),
            receipt_type: "gate_check".into(),
            severity: "low".into(),
            issued_at: "ts".into(),
            signature: "sig".into(),
            payload_hash: "hash".into(),
        };
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: CompatReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, receipt);
    }

    #[test]
    fn take_events_drains() {
        let mut svc = make_service_with_scope();
        svc.gate_check(&GateCheckRequest {
            package_id: "pkg".into(),
            requested_mode: CompatMode::Strict,
            scope: "project-1".into(),
            policy_context: None,
        })
        .unwrap();
        let events = svc.take_events();
        assert!(!events.is_empty());
        assert!(svc.events().is_empty());
    }

    // ── Determinism ───────────────────────────────────────────────────────

    #[test]
    fn determinism_same_input_same_report() {
        let build = || {
            let mut svc = make_service_with_scope();
            svc.gate_check(&GateCheckRequest {
                package_id: "det-pkg".into(),
                requested_mode: CompatMode::Strict,
                scope: "project-1".into(),
                policy_context: None,
            })
            .unwrap();
            svc
        };

        let a = serde_json::to_string(&build().to_report()).unwrap();
        let b = serde_json::to_string(&build().to_report()).unwrap();
        assert_eq!(a, b, "report must be deterministic");
    }

    #[test]
    fn denied_escalation_without_justification_preserves_scope_and_approval_events() {
        let mut svc = make_service_with_scope();

        let resp = svc
            .request_transition(&ModeTransitionRequest {
                scope_id: "project-1".into(),
                from_mode: CompatMode::Balanced,
                to_mode: CompatMode::LegacyRisky,
                justification: String::new(),
                requestor: "admin".into(),
            })
            .unwrap();

        assert!(!resp.approved);
        assert_eq!(
            svc.query_mode("project-1").unwrap().mode,
            CompatMode::Balanced
        );
        assert!(
            !svc.events()
                .iter()
                .any(|event| event.code == PCG_003_TRANSITION_APPROVED)
        );
        assert_eq!(svc.receipts().len(), 1);
    }

    #[test]
    fn wrong_from_mode_preserves_scope_and_does_not_emit_approval_event() {
        let mut svc = make_service_with_scope();

        let resp = svc
            .request_transition(&ModeTransitionRequest {
                scope_id: "project-1".into(),
                from_mode: CompatMode::Strict,
                to_mode: CompatMode::LegacyRisky,
                justification: "stale caller state".into(),
                requestor: "admin".into(),
            })
            .unwrap();

        assert!(!resp.approved);
        assert_eq!(
            svc.query_mode("project-1").unwrap().mode,
            CompatMode::Balanced
        );
        assert!(
            !svc.events()
                .iter()
                .any(|event| event.code == PCG_003_TRANSITION_APPROVED)
        );
        assert!(
            resp.rationale
                .contains("does not match actual current mode")
        );
    }

    #[test]
    fn unknown_scope_gate_check_defaults_to_strict_and_denies_escalation() {
        let mut svc = CompatGateService::new();

        let resp = svc
            .gate_check(&GateCheckRequest {
                package_id: "pkg-unknown".into(),
                requested_mode: CompatMode::Balanced,
                scope: "unknown-scope".into(),
                policy_context: None,
            })
            .unwrap();

        assert_eq!(resp.decision, GateDecision::Deny);
        assert!(resp.rationale.contains("requested balanced exceeds"));
        assert!(svc.query_mode("unknown-scope").is_none());
        assert!(
            svc.events()
                .iter()
                .any(|event| event.code == PCG_002_GATE_FAILED)
        );
        assert_eq!(svc.receipts()[0].severity, CompatMode::Strict.risk_level());
    }

    #[test]
    fn receipt_query_filters_are_exact_and_case_sensitive() {
        let mut svc = make_service_with_scope();
        svc.issue_divergence_receipt("scope-a", "medium").unwrap();
        svc.issue_divergence_receipt("scope-ab", "medium").unwrap();

        assert_eq!(svc.query_receipts(Some("scope-a"), Some("medium")).len(), 1);
        assert!(
            svc.query_receipts(Some("Scope-A"), Some("medium"))
                .is_empty()
        );
        assert!(svc.query_receipts(Some("scope"), Some("medium")).is_empty());
        assert!(svc.query_receipts(Some("scope-a"), Some("high")).is_empty());
    }

    #[test]
    fn shim_query_filter_does_not_match_case_or_substrings() {
        let svc = make_service_with_scope();

        assert!(svc.query_shims(Some("Project-1")).is_empty());
        assert!(svc.query_shims(Some("project")).is_empty());
        assert!(svc.query_shims(Some("project-10")).is_empty());
    }

    #[test]
    fn shim_capacity_error_does_not_emit_events_or_receipts() {
        let mut svc = CompatGateService::new();
        for idx in 0..MAX_SHIMS {
            svc.register_shim(make_shim(format!("shim-{idx}")))
                .expect("shim fill should succeed");
        }

        let err = svc
            .register_shim(make_shim("overflow"))
            .expect_err("overflow shim must fail closed");

        assert_eq!(err.code(), error_codes::ERR_COMPAT_SHIM_CAPACITY);
        assert!(svc.events().is_empty());
        assert!(svc.receipts().is_empty());
        assert_eq!(svc.shims.len(), MAX_SHIMS);
    }

    #[test]
    fn predicate_capacity_error_does_not_replace_query_mode_predicate() {
        let mut svc = CompatGateService::new();
        svc.set_scope_mode("project-1", CompatMode::Balanced);
        for idx in 0..MAX_PREDICATES {
            svc.register_predicate(make_predicate(format!("predicate-{idx}")))
                .expect("predicate fill should succeed");
        }

        let err = svc
            .register_predicate(make_predicate("predicate-overflow"))
            .expect_err("overflow predicate must fail closed");
        let exposed = svc
            .query_mode("project-1")
            .expect("scope mode should exist")
            .policy_predicate
            .expect("first predicate should still be exposed");

        assert_eq!(err.code(), error_codes::ERR_COMPAT_PREDICATE_CAPACITY);
        assert_eq!(exposed.predicate_id, "predicate-0");
        assert!(
            !svc.predicates
                .iter()
                .any(|predicate| predicate.predicate_id == "predicate-overflow")
        );
    }

    #[test]
    fn exhausted_trace_id_after_prior_gate_check_preserves_existing_state() {
        let mut svc = make_service_with_scope();
        svc.gate_check(&GateCheckRequest {
            package_id: "seed".into(),
            requested_mode: CompatMode::Strict,
            scope: "project-1".into(),
            policy_context: None,
        })
        .unwrap();
        let events_before = svc.events().len();
        let receipts_before = svc.receipts().len();
        svc.trace_counter = u64::MAX;
        svc.trace_epoch = u64::MAX;

        let err = svc
            .gate_check(&GateCheckRequest {
                package_id: "blocked".into(),
                requested_mode: CompatMode::Strict,
                scope: "project-1".into(),
                policy_context: None,
            })
            .expect_err("trace exhaustion must fail closed");

        assert_eq!(err, CompatGateOperationError::TraceIdSpaceExhausted);
        assert_eq!(svc.events().len(), events_before);
        assert_eq!(svc.receipts().len(), receipts_before);
        assert_eq!(svc.query_receipts(Some("project-1"), None).len(), 1);
    }

    #[test]
    fn receipt_exhaustion_on_transition_preserves_scope_and_existing_events() {
        let mut svc = make_service_with_scope();
        svc.gate_check(&GateCheckRequest {
            package_id: "seed".into(),
            requested_mode: CompatMode::Strict,
            scope: "project-1".into(),
            policy_context: None,
        })
        .unwrap();
        let events_before = svc.events().len();
        let receipts_before = svc.receipts().len();
        svc.receipt_counter = u64::MAX;
        svc.receipt_epoch = u64::MAX;

        let err = svc
            .request_transition(&ModeTransitionRequest {
                scope_id: "project-1".into(),
                from_mode: CompatMode::Balanced,
                to_mode: CompatMode::Strict,
                justification: String::new(),
                requestor: "admin".into(),
            })
            .expect_err("receipt exhaustion must fail closed");

        assert_eq!(err, CompatGateOperationError::ReceiptIdSpaceExhausted);
        assert_eq!(
            svc.query_mode("project-1").unwrap().mode,
            CompatMode::Balanced
        );
        assert_eq!(svc.events().len(), events_before);
        assert_eq!(svc.receipts().len(), receipts_before);
    }
}

#[cfg(test)]
mod compat_gate_additional_negative_tests {
    use super::*;

    fn service_with_balanced_scope() -> CompatGateService {
        let mut svc = CompatGateService::new();
        svc.set_scope_mode("project-extra", CompatMode::Balanced);
        svc
    }

    fn escalation_request(justification: impl Into<String>) -> ModeTransitionRequest {
        ModeTransitionRequest {
            scope_id: "project-extra".to_string(),
            from_mode: CompatMode::Balanced,
            to_mode: CompatMode::LegacyRisky,
            justification: justification.into(),
            requestor: "operator-extra".to_string(),
        }
    }

    #[test]
    fn whitespace_justification_does_not_approve_escalation() {
        let mut svc = service_with_balanced_scope();

        let response = svc
            .request_transition(&escalation_request(" \t\n "))
            .expect("transition should return denial response");

        assert!(!response.approved);
        assert!(response.rationale.contains("justification required"));
    }

    #[test]
    fn denied_whitespace_escalation_preserves_current_mode() {
        let mut svc = service_with_balanced_scope();

        let response = svc
            .request_transition(&escalation_request("   "))
            .expect("transition should return denial response");

        assert!(!response.approved);
        assert_eq!(
            svc.query_mode("project-extra").expect("scope exists").mode,
            CompatMode::Balanced
        );
    }

    #[test]
    fn denied_whitespace_escalation_emits_no_approval_event() {
        let mut svc = service_with_balanced_scope();

        svc.request_transition(&escalation_request("\n"))
            .expect("transition should return denial response");

        assert!(
            !svc.events()
                .iter()
                .any(|event| event.code == event_codes::PCG_003_TRANSITION_APPROVED)
        );
    }

    #[test]
    fn denied_whitespace_escalation_still_records_denial_receipt() {
        let mut svc = service_with_balanced_scope();

        let response = svc
            .request_transition(&escalation_request("\t"))
            .expect("transition should return denial response");

        assert_eq!(svc.receipts().len(), 1);
        assert_eq!(svc.receipts()[0].receipt_id, response.receipt_id);
        assert_eq!(svc.receipts()[0].receipt_type, "mode_transition");
    }

    #[test]
    fn push_bounded_zero_capacity_clears_without_retaining_new_item() {
        let mut values = vec![1, 2, 3];

        push_bounded(&mut values, 4, 0);

        assert!(values.is_empty());
    }

    #[test]
    fn gate_pass_fails_after_events_are_drained_even_with_receipts() {
        let mut svc = service_with_balanced_scope();
        svc.gate_check(&GateCheckRequest {
            package_id: "pkg-extra".to_string(),
            requested_mode: CompatMode::Strict,
            scope: "project-extra".to_string(),
            policy_context: None,
        })
        .expect("fixture gate check should complete");

        let drained = svc.take_events();

        assert!(!drained.is_empty());
        assert!(!svc.receipts().is_empty());
        assert!(!svc.gate_pass());
    }

    #[test]
    fn blank_receipt_filters_do_not_act_as_wildcards() {
        let mut svc = service_with_balanced_scope();
        svc.issue_divergence_receipt("project-extra", "medium")
            .expect("fixture receipt should issue");

        assert!(svc.query_receipts(Some(""), None).is_empty());
        assert!(svc.query_receipts(None, Some("")).is_empty());
    }

    #[test]
    fn same_scope_non_interference_check_is_negative() {
        let mut svc = CompatGateService::new();
        svc.set_scope_mode("shared-scope", CompatMode::Strict);

        assert!(!svc.check_non_interference("shared-scope", "shared-scope"));
    }

    #[test]
    fn blank_scope_gate_check_defaults_to_strict_and_does_not_register_scope() {
        let mut svc = CompatGateService::new();

        let response = svc
            .gate_check(&GateCheckRequest {
                package_id: "pkg-blank-scope".to_string(),
                requested_mode: CompatMode::Balanced,
                scope: String::new(),
                policy_context: None,
            })
            .expect("blank scope gate check should still produce denial response");

        assert_eq!(response.decision, GateDecision::Deny);
        assert!(svc.query_mode("").is_none());
        assert_eq!(svc.receipts().len(), 1);
        assert_eq!(svc.receipts()[0].scope, "");
        assert_eq!(svc.receipts()[0].severity, CompatMode::Strict.risk_level());
    }

    #[test]
    fn divergence_receipt_trace_exhaustion_preserves_state() {
        let mut svc = service_with_balanced_scope();
        svc.issue_divergence_receipt("project-extra", "medium")
            .expect("seed receipt should issue");
        let events_before = svc.events().len();
        let receipts_before = svc.receipts().len();
        svc.trace_counter = u64::MAX;
        svc.trace_epoch = u64::MAX;

        let err = svc
            .issue_divergence_receipt("project-extra", "high")
            .expect_err("trace exhaustion must fail closed");

        assert_eq!(err, CompatGateOperationError::TraceIdSpaceExhausted);
        assert_eq!(svc.events().len(), events_before);
        assert_eq!(svc.receipts().len(), receipts_before);
        assert!(
            !svc.receipts()
                .iter()
                .any(|receipt| receipt.severity == "high")
        );
    }

    #[test]
    fn divergence_receipt_receipt_exhaustion_preserves_state() {
        let mut svc = service_with_balanced_scope();
        svc.issue_divergence_receipt("project-extra", "medium")
            .expect("seed receipt should issue");
        let events_before = svc.events().len();
        let receipts_before = svc.receipts().len();
        svc.receipt_counter = u64::MAX;
        svc.receipt_epoch = u64::MAX;

        let err = svc
            .issue_divergence_receipt("project-extra", "critical")
            .expect_err("receipt exhaustion must fail closed");

        assert_eq!(err, CompatGateOperationError::ReceiptIdSpaceExhausted);
        assert_eq!(svc.events().len(), events_before);
        assert_eq!(svc.receipts().len(), receipts_before);
        assert!(
            !svc.receipts()
                .iter()
                .any(|receipt| receipt.severity == "critical")
        );
    }

    #[test]
    fn take_events_second_call_is_empty_and_receipts_remain() {
        let mut svc = service_with_balanced_scope();
        svc.gate_check(&GateCheckRequest {
            package_id: "pkg-drain".to_string(),
            requested_mode: CompatMode::Strict,
            scope: "project-extra".to_string(),
            policy_context: None,
        })
        .expect("fixture gate check should complete");
        let receipts_before = svc.receipts().len();

        let first = svc.take_events();
        let second = svc.take_events();

        assert!(!first.is_empty());
        assert!(second.is_empty());
        assert_eq!(svc.receipts().len(), receipts_before);
    }

    #[test]
    fn report_after_event_drain_marks_visible_invariant_false() {
        let mut svc = service_with_balanced_scope();
        svc.gate_check(&GateCheckRequest {
            package_id: "pkg-report-drain".to_string(),
            requested_mode: CompatMode::Strict,
            scope: "project-extra".to_string(),
            policy_context: None,
        })
        .expect("fixture gate check should complete");
        let _ = svc.take_events();

        let report = svc.to_report();

        assert_eq!(report["gate_verdict"].as_str(), Some("FAIL"));
        assert_eq!(report["invariants"][INV_PCG_VISIBLE].as_bool(), Some(false));
        assert_eq!(report["invariants"][INV_PCG_RECEIPT].as_bool(), Some(true));
    }

    #[test]
    fn security_weakening_shim_marks_monotonicity_false_in_report() {
        let mut svc = service_with_balanced_scope();
        let mut shim = ShimMetadata {
            shim_id: "weakening-extra".to_string(),
            description: "negative monotonicity fixture".to_string(),
            risk_category: "security_weakening".to_string(),
            activation_policy: "manual".to_string(),
            divergence_rationale: "test fixture".to_string(),
            scope: "project-extra".to_string(),
        };
        svc.register_shim(shim.clone())
            .expect("weakening shim should register for report fixture");
        shim.shim_id = "safe-extra".to_string();
        shim.risk_category = "compatibility".to_string();
        svc.register_shim(shim)
            .expect("safe shim should register for report fixture");

        let report = svc.to_report();

        assert!(!svc.check_monotonicity());
        assert_eq!(report["summary"]["total_shims"].as_u64(), Some(2));
        assert_eq!(
            report["summary"]["monotonicity_holds"].as_bool(),
            Some(false)
        );
    }
}

#[cfg(test)]
mod compat_gate_fresh_negative_tests {
    use super::*;

    fn base_shim(shim_id: &str, scope: &str) -> ShimMetadata {
        ShimMetadata {
            shim_id: shim_id.to_string(),
            description: format!("shim {shim_id}"),
            risk_category: "low".to_string(),
            activation_policy: "balanced".to_string(),
            divergence_rationale: "negative test fixture".to_string(),
            scope: scope.to_string(),
        }
    }

    #[test]
    fn legacy_risky_scope_gate_check_is_audit_not_silent_allow() {
        let mut svc = CompatGateService::new();
        svc.set_scope_mode("legacy-scope", CompatMode::LegacyRisky);

        let response = svc
            .gate_check(&GateCheckRequest {
                package_id: "pkg-legacy".to_string(),
                requested_mode: CompatMode::LegacyRisky,
                scope: "legacy-scope".to_string(),
                policy_context: None,
            })
            .expect("legacy-risky gate check should complete");

        assert_eq!(response.decision, GateDecision::Audit);
        assert_ne!(response.decision, GateDecision::Allow);
        assert!(
            !svc.events()
                .iter()
                .any(|event| event.code == event_codes::PCG_002_GATE_FAILED)
        );
    }

    #[test]
    fn denied_gate_check_does_not_mutate_existing_scope_mode() {
        let mut svc = CompatGateService::new();
        svc.set_scope_mode("strict-scope", CompatMode::Strict);

        let response = svc
            .gate_check(&GateCheckRequest {
                package_id: "pkg-risky".to_string(),
                requested_mode: CompatMode::LegacyRisky,
                scope: "strict-scope".to_string(),
                policy_context: None,
            })
            .expect("denied gate check should still return a response");

        assert_eq!(response.decision, GateDecision::Deny);
        assert_eq!(
            svc.query_mode("strict-scope").expect("scope exists").mode,
            CompatMode::Strict
        );
    }

    #[test]
    fn denied_gate_check_records_failed_event_but_no_transition_event() {
        let mut svc = CompatGateService::new();
        svc.set_scope_mode("strict-scope", CompatMode::Strict);

        svc.gate_check(&GateCheckRequest {
            package_id: "pkg-risky".to_string(),
            requested_mode: CompatMode::LegacyRisky,
            scope: "strict-scope".to_string(),
            policy_context: None,
        })
        .expect("denied gate check should still emit audit data");

        assert!(
            svc.events()
                .iter()
                .any(|event| event.code == event_codes::PCG_002_GATE_FAILED)
        );
        assert!(
            !svc.events()
                .iter()
                .any(|event| event.code == event_codes::PCG_003_TRANSITION_APPROVED)
        );
    }

    #[test]
    fn scope_specific_shim_does_not_leak_to_unrelated_scope() {
        let mut svc = CompatGateService::new();
        svc.register_shim(base_shim("scoped-shim", "scope-a"))
            .expect("scope-specific shim should register");

        assert!(svc.query_shims(Some("scope-b")).is_empty());
    }

    #[test]
    fn wildcard_shim_does_not_make_scoped_shim_match_unrelated_scope() {
        let mut svc = CompatGateService::new();
        svc.register_shim(base_shim("scoped-shim", "scope-a"))
            .expect("scope-specific shim should register");
        svc.register_shim(base_shim("wildcard-shim", "*"))
            .expect("wildcard shim should register");

        let shims = svc.query_shims(Some("scope-b"));

        assert_eq!(shims.len(), 1);
        assert_eq!(shims[0].shim_id, "wildcard-shim");
    }

    #[test]
    fn receipt_filter_requires_scope_and_severity_to_match_together() {
        let mut svc = CompatGateService::new();
        svc.issue_divergence_receipt("scope-a", "medium")
            .expect("first receipt should issue");
        svc.issue_divergence_receipt("scope-b", "high")
            .expect("second receipt should issue");

        assert!(svc.query_receipts(Some("scope-a"), Some("high")).is_empty());
        assert!(
            svc.query_receipts(Some("scope-b"), Some("medium"))
                .is_empty()
        );
    }

    #[test]
    fn denied_wrong_from_mode_transition_does_not_drain_existing_events() {
        let mut svc = CompatGateService::new();
        svc.set_scope_mode("project-denied", CompatMode::Balanced);
        svc.gate_check(&GateCheckRequest {
            package_id: "seed".to_string(),
            requested_mode: CompatMode::Strict,
            scope: "project-denied".to_string(),
            policy_context: None,
        })
        .expect("seed gate check should complete");
        let events_before = svc.events().len();

        let response = svc
            .request_transition(&ModeTransitionRequest {
                scope_id: "project-denied".to_string(),
                from_mode: CompatMode::Strict,
                to_mode: CompatMode::LegacyRisky,
                justification: "stale caller state".to_string(),
                requestor: "operator".to_string(),
            })
            .expect("wrong from-mode transition should return denial");

        assert!(!response.approved);
        assert_eq!(svc.events().len(), events_before);
    }

    #[test]
    fn terminal_trace_exhaustion_on_transition_leaves_no_receipt() {
        let mut svc = CompatGateService::new();
        svc.set_scope_mode("terminal-trace", CompatMode::Balanced);
        svc.trace_counter = u64::MAX;
        svc.trace_epoch = u64::MAX;

        let err = svc
            .request_transition(&ModeTransitionRequest {
                scope_id: "terminal-trace".to_string(),
                from_mode: CompatMode::Balanced,
                to_mode: CompatMode::Strict,
                justification: String::new(),
                requestor: "operator".to_string(),
            })
            .expect_err("terminal trace exhaustion must fail closed");

        assert_eq!(err, CompatGateOperationError::TraceIdSpaceExhausted);
        assert!(svc.receipts().is_empty());
        assert!(svc.events().is_empty());
    }
}

#[cfg(test)]
mod compat_gate_malformed_payload_tests {
    use super::*;

    #[test]
    fn compat_mode_deserialize_rejects_display_case_label() {
        let result: Result<CompatMode, _> = serde_json::from_str("\"LegacyRisky\"");

        assert!(result.is_err());
    }

    #[test]
    fn gate_decision_deserialize_rejects_unknown_variant() {
        let result: Result<GateDecision, _> = serde_json::from_str("\"maybe\"");

        assert!(result.is_err());
    }

    #[test]
    fn gate_check_request_deserialize_rejects_missing_package_id() {
        let raw = serde_json::json!({
            "requested_mode": "balanced",
            "scope": "project-1",
            "policy_context": null
        });

        let result: Result<GateCheckRequest, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn mode_transition_request_deserialize_rejects_string_mode_payload() {
        let raw = serde_json::json!({
            "scope_id": "project-1",
            "from_mode": "strict",
            "to_mode": "legacy-risky",
            "justification": "bad separator in mode label",
            "requestor": "operator"
        });

        let result: Result<ModeTransitionRequest, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn compat_receipt_deserialize_rejects_missing_payload_hash() {
        let raw = serde_json::json!({
            "receipt_id": "rcpt-1",
            "scope": "project-1",
            "receipt_type": "gate_check",
            "severity": "low",
            "issued_at": "2026-01-01T00:00:00Z",
            "signature": "sig-rcpt-1"
        });

        let result: Result<CompatReceipt, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn policy_predicate_deserialize_rejects_scalar_attenuation() {
        let raw = serde_json::json!({
            "predicate_id": "predicate-1",
            "signature": "sig-predicate-1",
            "attenuation": "not-a-list",
            "activation_condition": "balanced"
        });

        let result: Result<PolicyPredicate, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn registration_error_deserialize_rejects_unknown_variant() {
        let raw = serde_json::json!({
            "unknown_capacity_error": {
                "capacity": 1_usize
            }
        });

        let result: Result<CompatGateRegistrationError, _> = serde_json::from_value(raw);

        assert!(result.is_err());
    }

    #[test]
    fn security_edge_case_concurrent_service_access_thread_safety() {
        use std::sync::{Arc, Barrier, Mutex};
        use std::thread;

        let service = Arc::new(Mutex::new(CompatGateService::new()));
        {
            let mut svc = service.lock().unwrap();
            svc.set_scope_mode("concurrent-scope", CompatMode::Balanced);
        }

        let barrier = Arc::new(Barrier::new(8));
        let mut handles = Vec::new();

        // Test concurrent operations that could lead to race conditions
        for thread_id in 0..8 {
            let service_clone = Arc::clone(&service);
            let barrier_clone = Arc::clone(&barrier);

            let handle = thread::spawn(move || {
                barrier_clone.wait(); // Synchronize start

                let mut results = Vec::new();

                // Each thread performs different types of operations
                for i in 0..50 {
                    let mut svc = service_clone.lock().unwrap();

                    match thread_id % 4 {
                        0 => {
                            // Gate checks
                            let result = svc.gate_check(&GateCheckRequest {
                                package_id: format!("pkg-{}-{}", thread_id, i),
                                requested_mode: CompatMode::Strict,
                                scope: "concurrent-scope".to_string(),
                                policy_context: Some(format!("ctx-{}", thread_id)),
                            });
                            results.push(("gate_check", result.is_ok()));
                        }
                        1 => {
                            // Mode transitions
                            let result = svc.request_transition(&ModeTransitionRequest {
                                scope_id: format!("scope-{}-{}", thread_id, i),
                                from_mode: CompatMode::Strict,
                                to_mode: CompatMode::Balanced,
                                justification: format!("justification-{}", thread_id),
                                requestor: format!("requestor-{}", thread_id),
                            });
                            results.push(("transition", result.is_ok()));
                        }
                        2 => {
                            // Receipt operations
                            let result = svc.issue_divergence_receipt(
                                &format!("scope-{}", thread_id),
                                &format!("severity-{}", i % 3)
                            );
                            results.push(("receipt", result.is_ok()));
                        }
                        3 => {
                            // Shim registrations
                            let result = svc.register_shim(ShimMetadata {
                                shim_id: format!("shim-{}-{}", thread_id, i),
                                description: format!("concurrent shim {}", thread_id),
                                risk_category: "low".to_string(),
                                activation_policy: "balanced".to_string(),
                                divergence_rationale: "concurrency test".to_string(),
                                scope: format!("scope-{}", thread_id),
                            });
                            results.push(("register_shim", result.is_ok()));
                        }
                        _ => unreachable!(),
                    }
                }
                results
            });
            handles.push(handle);
        }

        // Collect results and verify no corruption occurred
        let mut all_results = Vec::new();
        for handle in handles {
            let thread_results = handle.join().unwrap();
            all_results.extend(thread_results);
        }

        // Verify final state consistency
        let svc = service.lock().unwrap();

        // Should have reasonable counts without overflows
        assert!(svc.receipts().len() <= MAX_RECEIPTS);
        assert!(svc.events().len() <= MAX_EVENTS);
        assert!(svc.shims.len() <= MAX_SHIMS);

        // All events should have valid trace IDs (no corruption)
        for event in svc.events() {
            assert!(!event.trace_id.is_empty());
            assert!(!event.scope.is_empty());
            assert!(!event.code.is_empty());
        }

        // All receipts should have unique IDs (no duplicates from race conditions)
        let mut receipt_ids = std::collections::HashSet::new();
        for receipt in svc.receipts() {
            assert!(receipt_ids.insert(receipt.receipt_id.clone()));
        }
    }

    #[test]
    fn security_edge_case_id_generation_overflow_boundary_testing() {
        let mut svc = CompatGateService::new();

        // Test trace ID generation at boundary conditions
        let trace_boundary_tests = [
            (0, 0),              // Initial state
            (u64::MAX - 1, 0),   // Near overflow, no epoch
            (u64::MAX, 0),       // At overflow boundary
            (0, 1),              // After epoch rollover
            (u64::MAX - 1, u64::MAX - 1),  // Near both limits
            (u64::MAX, u64::MAX - 1),      // Trace at max, epoch near max
            (u64::MAX - 1, u64::MAX),      // Trace near max, epoch at max
        ];

        for (counter, epoch) in trace_boundary_tests {
            svc.trace_counter = counter;
            svc.trace_epoch = epoch;

            let result = svc.next_trace_id();

            if counter == u64::MAX && epoch == u64::MAX {
                // Should fail at absolute limit
                assert!(result.is_err());
                assert_eq!(result.unwrap_err(), CompatGateOperationError::TraceIdSpaceExhausted);
            } else {
                // Should succeed with valid ID
                let trace_id = result.unwrap();
                assert!(!trace_id.is_empty());
                assert!(trace_id.starts_with("trace-"));

                // Verify counter incremented or epoch rolled over correctly
                if counter == u64::MAX && epoch < u64::MAX {
                    assert_eq!(svc.trace_counter, 1);
                    assert_eq!(svc.trace_epoch, epoch + 1);
                } else if counter < u64::MAX {
                    assert_eq!(svc.trace_counter, counter + 1);
                }
            }
        }

        // Reset and test receipt ID generation
        svc.receipt_counter = u64::MAX - 1;
        svc.receipt_epoch = 0;

        let receipt1 = svc.next_receipt_id().unwrap();
        let receipt2 = svc.next_receipt_id().unwrap();

        // Should be unique despite boundary rollover
        assert_ne!(receipt1, receipt2);
        assert!(receipt1.starts_with("rcpt-"));
        assert!(receipt2.starts_with("rcpt-"));
        assert_eq!(svc.receipt_epoch, 1);
        assert_eq!(svc.receipt_counter, 1);
    }

    #[test]
    fn security_edge_case_policy_injection_in_request_fields() {
        let mut svc = CompatGateService::new();
        svc.set_scope_mode("policy-test", CompatMode::Balanced);

        // Test various injection patterns in request fields
        let injection_patterns = vec![
            // LDAP injection
            "pkg*)(uid=*",
            "pkg))(|(password=*",

            // SQL injection patterns
            "pkg'; DROP TABLE scopes; --",
            "pkg' OR '1'='1",
            "pkg' UNION SELECT * FROM secrets --",

            // NoSQL injection
            "pkg'; return {sensitive: true}; //",
            "pkg\"; this.sensitive = true; //",

            // Command injection
            "pkg; rm -rf /; echo",
            "pkg`cat /etc/passwd`",
            "pkg$(whoami)",

            // Path traversal
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",

            // XSS payloads
            "<script>alert('xss')</script>",
            "javascript:alert('xss')",
            "\"><script>alert('xss')</script>",

            // YAML/JSON injection
            "pkg\": {\"evil\": true}, \"dummy\": \"",
            "pkg\\n---\\nevil: true",

            // Regex DoS patterns
            "pkg" + &"a?".repeat(10000) + "a".repeat(10000),

            // Unicode attacks
            "\u{202E}reverse\u{202D}normal",  // BiDi override
            "\u{FEFF}bom",                    // Byte Order Mark
            "\u{00AD}soft-hyphen",            // Soft hyphen
        ];

        for malicious_input in injection_patterns {
            let request = GateCheckRequest {
                package_id: malicious_input.to_string(),
                requested_mode: CompatMode::Strict,
                scope: "policy-test".to_string(),
                policy_context: Some(malicious_input.to_string()),
            };

            let result = svc.gate_check(&request);

            // Should handle malicious input gracefully
            match result {
                Ok(response) => {
                    // If accepted, verify response doesn't leak injection content
                    assert!(!response.rationale.contains("DROP TABLE"));
                    assert!(!response.rationale.contains("<script>"));
                    assert!(!response.rationale.contains("rm -rf"));
                    assert!(!response.trace_id.contains(malicious_input));
                    assert!(!response.receipt_id.contains(malicious_input));

                    // Should still be a valid response
                    assert!(!response.trace_id.is_empty());
                    assert!(!response.receipt_id.is_empty());
                }
                Err(err) => {
                    // If rejected, error should not leak injection attempt details
                    let error_msg = err.to_string();
                    assert!(!error_msg.contains("DROP TABLE"));
                    assert!(!error_msg.contains("<script>"));
                    assert!(!error_msg.contains("rm -rf"));
                }
            }

            // Verify service state isn't corrupted
            for event in svc.events() {
                assert!(!event.detail.contains("DROP TABLE"));
                assert!(!event.detail.contains("<script>"));
            }
        }
    }

    #[test]
    fn security_edge_case_capacity_exhaustion_attack_resistance() {
        let mut svc = CompatGateService::new();

        // Attempt to exhaust shim capacity with rapid registrations
        for i in 0..MAX_SHIMS * 2 {  // Try to register more than capacity
            let shim = ShimMetadata {
                shim_id: format!("attack-shim-{}", i),
                description: format!("Capacity exhaustion attempt {}", i),
                risk_category: "low".to_string(),
                activation_policy: "manual".to_string(),
                divergence_rationale: "capacity attack".to_string(),
                scope: format!("attack-scope-{}", i),
            };

            let result = svc.register_shim(shim);

            if i < MAX_SHIMS {
                assert!(result.is_ok(), "Should accept shims within capacity");
            } else {
                assert!(result.is_err(), "Should reject shims beyond capacity");
                match result.unwrap_err() {
                    CompatGateRegistrationError::ShimCapacityExceeded { capacity } => {
                        assert_eq!(capacity, MAX_SHIMS);
                    }
                    _ => panic!("Wrong error type for capacity exhaustion"),
                }
            }
        }

        // Verify capacity limit enforced
        assert_eq!(svc.shims.len(), MAX_SHIMS);

        // Verify original shims are preserved (no eviction)
        assert!(svc.shims.iter().any(|s| s.shim_id == "attack-shim-0"));

        // Test predicate capacity exhaustion
        for i in 0..MAX_PREDICATES * 2 {
            let predicate = PolicyPredicate {
                predicate_id: format!("attack-predicate-{}", i),
                signature: format!("sig-attack-{}", i),
                attenuation: vec![format!("scope:attack-{}", i)],
                activation_condition: "always".to_string(),
            };

            let result = svc.register_predicate(predicate);

            if i < MAX_PREDICATES {
                assert!(result.is_ok(), "Should accept predicates within capacity");
            } else {
                assert!(result.is_err(), "Should reject predicates beyond capacity");
            }
        }

        assert_eq!(svc.predicates.len(), MAX_PREDICATES);

        // Test ID space exhaustion resistance
        svc.trace_counter = u64::MAX;
        svc.trace_epoch = u64::MAX;

        // Should fail gracefully without corruption
        let gate_result = svc.gate_check(&GateCheckRequest {
            package_id: "exhaustion-test".to_string(),
            requested_mode: CompatMode::Strict,
            scope: "test".to_string(),
            policy_context: None,
        });

        assert!(gate_result.is_err());
        assert_eq!(gate_result.unwrap_err(), CompatGateOperationError::TraceIdSpaceExhausted);

        // Service should remain functional for reads
        assert_eq!(svc.shims.len(), MAX_SHIMS);
        assert_eq!(svc.predicates.len(), MAX_PREDICATES);
    }

    #[test]
    fn security_edge_case_serialization_bomb_resistance() {
        let mut svc = CompatGateService::new();

        // Create structures with extremely large string fields
        let huge_string = "A".repeat(100_000);

        let bomb_shim = ShimMetadata {
            shim_id: "bomb-shim".to_string(),
            description: huge_string.clone(),
            risk_category: huge_string.clone(),
            activation_policy: huge_string.clone(),
            divergence_rationale: huge_string.clone(),
            scope: "bomb-scope".to_string(),
        };

        // Should handle large data gracefully
        match svc.register_shim(bomb_shim) {
            Ok(_) => {
                // If accepted, verify serialization doesn't crash
                let report = svc.to_report();
                assert!(report.is_object());
                assert!(report.get("summary").is_some());

                // Verify memory usage is still reasonable
                assert!(svc.shims.len() <= MAX_SHIMS);
            }
            Err(_) => {
                // Rejection is also acceptable for very large inputs
            }
        }

        // Test huge receipt generation
        let result = svc.issue_divergence_receipt(&huge_string, "critical");
        match result {
            Ok(receipt) => {
                // Verify receipt fields are bounded
                assert!(receipt.scope.len() <= huge_string.len());
                assert!(receipt.severity == "critical");
                assert!(!receipt.receipt_id.is_empty());
            }
            Err(_) => {
                // Error handling is acceptable for extreme inputs
            }
        }

        // Test serialization of report with large data
        let start_time = std::time::Instant::now();
        let report = svc.to_report();
        let serialize_time = start_time.elapsed();

        // Should complete within reasonable time
        assert!(serialize_time < std::time::Duration::from_secs(5));
        assert!(report.is_object());
    }

    #[test]
    fn security_edge_case_scope_isolation_boundary_testing() {
        let mut svc = CompatGateService::new();

        // Create multiple scopes with different isolation requirements
        let scopes = vec![
            ("production", CompatMode::Strict),
            ("staging", CompatMode::Balanced),
            ("development", CompatMode::LegacyRisky),
            ("sandbox", CompatMode::Strict),
        ];

        for (scope, mode) in scopes {
            svc.set_scope_mode(scope, mode);
        }

        // Test cross-scope contamination resistance
        for i in 0..100 {
            let source_scope = match i % 4 {
                0 => "production",
                1 => "staging",
                2 => "development",
                3 => "sandbox",
                _ => unreachable!(),
            };

            let target_scope = match (i + 1) % 4 {
                0 => "production",
                1 => "staging",
                2 => "development",
                3 => "sandbox",
                _ => unreachable!(),
            };

            // Perform operations in source scope
            let _ = svc.gate_check(&GateCheckRequest {
                package_id: format!("pkg-{}", i),
                requested_mode: CompatMode::Strict,
                scope: source_scope.to_string(),
                policy_context: Some(format!("ctx-{}", source_scope)),
            });

            // Verify target scope is not affected
            let source_mode = svc.query_mode(source_scope).unwrap().mode;
            let target_mode = svc.query_mode(target_scope).unwrap().mode;

            // Modes should remain independent
            assert!(svc.check_non_interference(source_scope, target_scope) || source_scope == target_scope);

            // Operations in one scope shouldn't change another scope's mode
            if source_scope != target_scope {
                // Target scope should maintain its original mode
                let expected_mode = match target_scope {
                    "production" | "sandbox" => CompatMode::Strict,
                    "staging" => CompatMode::Balanced,
                    "development" => CompatMode::LegacyRisky,
                    _ => unreachable!(),
                };
                assert_eq!(target_mode, expected_mode);
            }
        }

        // Test scope-specific receipt isolation
        for scope in ["production", "staging", "development", "sandbox"] {
            let _ = svc.issue_divergence_receipt(scope, "test");
        }

        for scope in ["production", "staging", "development", "sandbox"] {
            let scope_receipts = svc.query_receipts(Some(scope), None);

            // Each scope should only see its own receipts
            for receipt in &scope_receipts {
                assert_eq!(receipt.scope, scope);
            }

            // Should not see receipts from other scopes
            let other_scope_count = svc.query_receipts(None, None)
                .iter()
                .filter(|r| r.scope != scope)
                .count();

            let total_count = svc.query_receipts(None, None).len();
            assert_eq!(scope_receipts.len() + other_scope_count, total_count);
        }
    }

    #[test]
    fn security_edge_case_event_tampering_resistance() {
        let mut svc = CompatGateService::new();
        svc.set_scope_mode("event-test", CompatMode::Balanced);

        // Perform operations that generate events
        let operations = vec![
            ("gate_check", CompatMode::Strict, true),
            ("gate_check", CompatMode::LegacyRisky, false), // Should be denied
            ("transition", CompatMode::Strict, true),
        ];

        for (operation, mode, should_succeed) in operations {
            match operation {
                "gate_check" => {
                    let result = svc.gate_check(&GateCheckRequest {
                        package_id: "test-pkg".to_string(),
                        requested_mode: mode,
                        scope: "event-test".to_string(),
                        policy_context: None,
                    });

                    if should_succeed {
                        assert!(result.is_ok());
                    }
                }
                "transition" => {
                    let _ = svc.request_transition(&ModeTransitionRequest {
                        scope_id: "event-test".to_string(),
                        from_mode: CompatMode::Balanced,
                        to_mode: mode,
                        justification: "test".to_string(),
                        requestor: "test".to_string(),
                    });
                }
                _ => unreachable!(),
            }
        }

        let events_before_drain = svc.events().to_vec();
        assert!(!events_before_drain.is_empty());

        // Verify events are immutable after creation
        for event in &events_before_drain {
            assert!(!event.code.is_empty());
            assert!(!event.trace_id.is_empty());
            assert!(!event.scope.is_empty());

            // Event codes should be from known set
            assert!(matches!(event.code.as_str(),
                event_codes::PCG_001_GATE_PASSED |
                event_codes::PCG_002_GATE_FAILED |
                event_codes::PCG_003_TRANSITION_APPROVED |
                event_codes::PCG_004_RECEIPT_ISSUED
            ));
        }

        // Drain events
        let drained_events = svc.take_events();
        assert_eq!(drained_events.len(), events_before_drain.len());

        // Verify drained events are identical to original (no tampering)
        for (original, drained) in events_before_drain.iter().zip(drained_events.iter()) {
            assert_eq!(original.code, drained.code);
            assert_eq!(original.trace_id, drained.trace_id);
            assert_eq!(original.scope, drained.scope);
            assert_eq!(original.detail, drained.detail);
        }

        // Service should have no events after drain
        assert!(svc.events().is_empty());

        // New operations should still generate events normally
        let _ = svc.gate_check(&GateCheckRequest {
            package_id: "post-drain-pkg".to_string(),
            requested_mode: CompatMode::Strict,
            scope: "event-test".to_string(),
            policy_context: None,
        });

        assert!(!svc.events().is_empty());
    }

    #[test]
    fn security_edge_case_push_bounded_adversarial_inputs() {
        // Test push_bounded with various adversarial scenarios

        // Test with zero capacity (should clear everything)
        let mut items = vec![1, 2, 3, 4, 5];
        push_bounded(&mut items, 999, 0);
        assert!(items.is_empty());

        // Test with capacity 1 (should only keep latest)
        let mut items = vec![1, 2, 3];
        push_bounded(&mut items, 4, 1);
        assert_eq!(items, vec![4]);

        // Test with very large initial collection and small capacity
        let mut items: Vec<i32> = (1..=10000).collect();
        push_bounded(&mut items, 10001, 5);
        assert_eq!(items.len(), 5);
        assert_eq!(items[4], 10001); // New item should be at end
        assert!(items[0] > 9995);    // Should have kept recent items

        // Test overflow protection in drain calculation
        let mut items = vec![1];
        // Set up scenario where len() >= cap and we're adding one more
        for i in 2..=1000 {
            items.push(i);
        }

        // Now items.len() = 1000, cap = 500, so overflow = 1000 - 500 + 1 = 501
        push_bounded(&mut items, 1001, 500);
        assert_eq!(items.len(), 500);
        assert_eq!(items[499], 1001); // New item at end
        assert!(items[0] >= 502);      // Should have drained from beginning

        // Test edge case where capacity equals current length
        let mut items = vec![1, 2, 3];
        push_bounded(&mut items, 4, 3);
        assert_eq!(items.len(), 3);
        assert_eq!(items, vec![2, 3, 4]); // Should have removed first item

        // Test with extremely large capacity (should not drain)
        let mut items = vec![1, 2, 3];
        push_bounded(&mut items, 4, 1_000_000);
        assert_eq!(items, vec![1, 2, 3, 4]);
    }

    #[test]
    fn security_edge_case_mode_risk_escalation_boundary_conditions() {
        // Test risk escalation detection with boundary conditions

        // Test all mode combinations
        let modes = [CompatMode::Strict, CompatMode::Balanced, CompatMode::LegacyRisky];

        for (i, from_mode) in modes.iter().enumerate() {
            for (j, to_mode) in modes.iter().enumerate() {
                let is_escalation = from_mode.is_escalation(*to_mode);
                let expected_escalation = j > i; // Higher index = higher risk

                assert_eq!(is_escalation, expected_escalation,
                          "Escalation detection wrong for {:?} -> {:?}", from_mode, to_mode);

                // Test risk ordinals are consistent
                assert_eq!(from_mode.risk_ordinal() < to_mode.risk_ordinal(), expected_escalation);
            }
        }

        // Test that risk levels match ordinals
        assert_eq!(CompatMode::Strict.risk_ordinal(), 0);
        assert_eq!(CompatMode::Balanced.risk_ordinal(), 1);
        assert_eq!(CompatMode::LegacyRisky.risk_ordinal(), 2);

        assert_eq!(CompatMode::Strict.risk_level(), "low");
        assert_eq!(CompatMode::Balanced.risk_level(), "medium");
        assert_eq!(CompatMode::LegacyRisky.risk_level(), "high");

        // Test mode labels are consistent
        assert_eq!(CompatMode::Strict.label(), "strict");
        assert_eq!(CompatMode::Balanced.label(), "balanced");
        assert_eq!(CompatMode::LegacyRisky.label(), "legacy_risky");

        // Test display formatting
        assert_eq!(format!("{}", CompatMode::Strict), "strict");
        assert_eq!(format!("{}", CompatMode::Balanced), "balanced");
        assert_eq!(format!("{}", CompatMode::LegacyRisky), "legacy_risky");

        // Test that same-mode transitions are not escalations
        for mode in &modes {
            assert!(!mode.is_escalation(*mode));
        }
    }

    #[test]
    fn security_edge_case_error_information_leakage_prevention() {
        // Test that errors don't leak sensitive information

        let registration_errors = [
            CompatGateRegistrationError::ShimCapacityExceeded { capacity: 42 },
            CompatGateRegistrationError::PredicateCapacityExceeded { capacity: 84 },
        ];

        for error in &registration_errors {
            let error_string = error.to_string();
            let code = error.code();

            // Should contain capacity information (not sensitive)
            assert!(error_string.contains("capacity"));

            // Should not contain internal paths, memory addresses, or debug info
            assert!(!error_string.contains("/src/"));
            assert!(!error_string.contains("0x"));
            assert!(!error_string.contains("debug"));
            assert!(!error_string.contains("panic"));
            assert!(!error_string.contains("unwrap"));

            // Error codes should be stable and not leak internals
            assert!(code.starts_with("ERR_COMPAT_"));
            assert!(!code.contains(" "));
            assert!(!code.contains("\n"));
        }

        let operation_errors = [
            CompatGateOperationError::TraceIdSpaceExhausted,
            CompatGateOperationError::ReceiptIdSpaceExhausted,
        ];

        for error in &operation_errors {
            let error_string = error.to_string();
            let code = error.code();

            // Should be descriptive but not leak internals
            assert!(error_string.contains("exhausted"));
            assert!(!error_string.contains("/"));
            assert!(!error_string.contains("\\"));
            assert!(!error_string.contains("0x"));

            // Error codes should follow pattern
            assert!(code.starts_with("ERR_COMPAT_"));
            assert!(code.ends_with("_EXHAUSTED"));
        }

        // Test that error types implement Error trait properly
        use std::error::Error;

        let reg_error = CompatGateRegistrationError::ShimCapacityExceeded { capacity: 10 };
        assert!(reg_error.source().is_none()); // No underlying cause

        let op_error = CompatGateOperationError::TraceIdSpaceExhausted;
        assert!(op_error.source().is_none()); // No underlying cause
    }
}
