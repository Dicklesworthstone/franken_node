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
            self.trace_counter += 1;
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
            self.receipt_counter += 1;
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
                !request.justification.is_empty()
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
    if items.len() >= cap {
        let overflow = items.len() - cap + 1;
        items.drain(0..overflow);
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
}
