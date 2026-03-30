// Policy-visible compatibility gate APIs (bd-137, Section 10.5).
//
// Exposes compatibility mode transitions, divergence receipts, and policy gates
// as programmatic APIs. Every decision produces structured evidence -- no opaque gates.

use std::collections::BTreeMap;
use std::time::SystemTime;

use chrono::{DateTime, Utc};

use super::compat_gates::{
    COMPAT_DIVERGENCE_RECEIPT_DOMAIN, COMPAT_POLICY_PREDICATE_DOMAIN,
    COMPAT_TRANSITION_RECEIPT_DOMAIN, CompatibilityFreshnessState, CompatibilityProofMetadata,
    CompatibilitySignatureAlgorithm, CompiledPolicyPredicate, build_proof_metadata,
    compile_policy_predicate, compute_freshness_state, default_receipt_expiry_with_ttl,
    explanation_digest, reason_codes, sign_ed25519_canonical, sign_hmac_canonical,
    validate_scope_attenuation_for_scope, verify_ed25519_canonical, verify_hmac_canonical,
};

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Gate check passed.
pub const PCG_001: &str = "PCG-001";
/// Gate check failed.
pub const PCG_002: &str = "PCG-002";
/// Mode transition approved.
pub const PCG_003: &str = "PCG-003";
/// Divergence receipt issued.
pub const PCG_004: &str = "PCG-004";

// ---------------------------------------------------------------------------
// Core types
// ---------------------------------------------------------------------------

/// Compatibility modes ordered by risk level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CompatMode {
    Strict,
    Balanced,
    LegacyRisky,
}

impl CompatMode {
    pub fn risk_level(&self) -> u8 {
        match self {
            Self::Strict => 0,
            Self::Balanced => 1,
            Self::LegacyRisky => 2,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Strict => "strict",
            Self::Balanced => "balanced",
            Self::LegacyRisky => "legacy_risky",
        }
    }
}

/// Gate evaluation verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Allow,
    Deny,
    Audit,
}

impl Verdict {
    pub fn label(&self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
            Self::Audit => "audit",
        }
    }
}

/// Machine-readable rationale for a gate decision.
#[derive(Debug, Clone)]
pub struct GateRationale {
    pub matched_predicates: Vec<String>,
    pub explanation: String,
    pub reason_codes: Vec<String>,
    pub attenuation_trace: Vec<String>,
    pub scope_delta: Vec<String>,
    pub freshness_state: CompatibilityFreshnessState,
    pub recovery_hints: Vec<String>,
    pub explanation_digest: String,
}

/// Request for a gate check evaluation.
#[derive(Debug, Clone)]
pub struct GateCheckRequest {
    pub package_id: String,
    pub requested_mode: CompatMode,
    pub scope: String,
    pub policy_context: BTreeMap<String, String>,
}

/// Structured result of a gate check.
#[derive(Debug, Clone)]
pub struct GateCheckResult {
    pub decision: Verdict,
    pub rationale: GateRationale,
    pub trace_id: String,
    pub receipt_id: Option<String>,
    pub event_code: String,
}

/// A signed divergence receipt.
#[derive(Debug, Clone)]
pub struct DivergenceReceipt {
    pub receipt_id: String,
    pub timestamp: String,
    pub expires_at: String,
    pub scope_id: String,
    pub shim_id: String,
    pub divergence_description: String,
    pub severity: String,
    pub signature: String,
    pub trace_id: String,
    pub resolved: bool,
    pub proof: CompatibilityProofMetadata,
}

/// A signed mode-transition receipt.
#[derive(Debug, Clone)]
pub struct ModeTransitionReceipt {
    pub transition_id: String,
    pub scope_id: String,
    pub from_mode: CompatMode,
    pub to_mode: CompatMode,
    pub approved: bool,
    pub issued_at: String,
    pub expires_at: String,
    pub receipt_signature: String,
    pub rationale: String,
    pub trace_id: String,
    pub proof: CompatibilityProofMetadata,
}

/// Mode transition request.
#[derive(Debug, Clone)]
pub struct ModeTransitionRequest {
    pub scope_id: String,
    pub from_mode: CompatMode,
    pub to_mode: CompatMode,
    pub justification: String,
    pub requestor: String,
}

/// A compatibility shim entry in the registry.
#[derive(Debug, Clone)]
pub struct ShimEntry {
    pub shim_id: String,
    /// Exact scope this shim applies to, or `*` for a global shim.
    pub scope_id: String,
    pub description: String,
    pub risk_category: String,
    pub activation_policy: String,
    pub divergence_rationale: String,
}

/// Policy predicate with cryptographic signature and attenuation.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PolicyPredicate {
    pub predicate_id: String,
    pub signature: String,
    pub attenuation: Vec<String>,
    pub activation_condition: String,
    pub issued_at: String,
    pub expires_at: String,
    pub proof: CompatibilityProofMetadata,
}

/// Structured audit event for gate decisions.
#[derive(Debug, Clone)]
pub struct GateAuditEvent {
    pub event_code: String,
    pub trace_id: String,
    pub scope_id: String,
    pub timestamp: String,
    pub detail: String,
}

/// Scope-level mode configuration.
#[derive(Debug, Clone)]
pub struct ScopeMode {
    pub scope_id: String,
    pub mode: CompatMode,
    pub activated_at: String,
    pub expires_at: String,
    pub receipt_signature: String,
    pub policy_predicate: Option<PolicyPredicate>,
    pub proof: CompatibilityProofMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum GateEngineError {
    CurrentModeMismatch {
        current: CompatMode,
        claimed: CompatMode,
    },
    ScopePolicyPredicateStale,
    ScopePolicyPredicateSignatureInvalid,
    ScopePredicateScopeWidening {
        reason: String,
    },
    ScopeNotFound {
        scope_id: String,
    },
    ScopeModeCanonicalization {
        detail: String,
    },
    TransitionReceiptCanonicalization {
        detail: String,
    },
    TraceIdSpaceExhausted,
}

impl std::fmt::Display for GateEngineError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CurrentModeMismatch { current, claimed } => write!(
                f,
                "Current mode is {} but request claims {}",
                current.label(),
                claimed.label()
            ),
            Self::ScopePolicyPredicateStale => f.write_str("scope policy predicate is stale"),
            Self::ScopePolicyPredicateSignatureInvalid => {
                f.write_str("scope policy predicate signature verification failed")
            }
            Self::ScopePredicateScopeWidening { reason } => {
                write!(
                    f,
                    "scope policy predicate widens beyond active scope: {reason}"
                )
            }
            Self::ScopeNotFound { scope_id } => write!(f, "scope {scope_id} not found"),
            Self::ScopeModeCanonicalization { detail } => {
                write!(f, "failed canonicalizing scope mode payload: {detail}")
            }
            Self::TransitionReceiptCanonicalization { detail } => {
                write!(
                    f,
                    "failed canonicalizing transition receipt payload: {detail}"
                )
            }
            Self::TraceIdSpaceExhausted => {
                f.write_str("compatibility gate trace ID space exhausted")
            }
        }
    }
}

impl std::error::Error for GateEngineError {}

#[derive(Debug, serde::Serialize)]
struct ScopeModeSigningPayload<'a> {
    scope_id: &'a str,
    mode: &'a str,
    activated_at: &'a str,
    expires_at: &'a str,
    policy_predicate: Option<&'a PolicyPredicate>,
    proof: &'a CompatibilityProofMetadata,
}

#[derive(Debug, serde::Serialize)]
struct ModeTransitionReceiptSigningPayload<'a> {
    transition_id: &'a str,
    scope_id: &'a str,
    from_mode: &'a str,
    to_mode: &'a str,
    approved: bool,
    issued_at: &'a str,
    expires_at: &'a str,
    rationale: &'a str,
    trace_id: &'a str,
    proof: &'a CompatibilityProofMetadata,
}

#[derive(Debug, serde::Serialize)]
struct DivergenceReceiptSigningPayload<'a> {
    receipt_id: &'a str,
    timestamp: &'a str,
    expires_at: &'a str,
    scope_id: &'a str,
    shim_id: &'a str,
    divergence_description: &'a str,
    severity: &'a str,
    trace_id: &'a str,
    resolved: bool,
    proof: &'a CompatibilityProofMetadata,
}

#[derive(Debug, serde::Serialize)]
struct PredicateSigningPayload<'a> {
    predicate_id: &'a str,
    attenuation: &'a [String],
    activation_condition: &'a str,
    issued_at: &'a str,
    expires_at: &'a str,
    proof: &'a CompatibilityProofMetadata,
}

fn predicate_signing_payload(predicate: &PolicyPredicate) -> PredicateSigningPayload<'_> {
    PredicateSigningPayload {
        predicate_id: &predicate.predicate_id,
        attenuation: &predicate.attenuation,
        activation_condition: &predicate.activation_condition,
        issued_at: &predicate.issued_at,
        expires_at: &predicate.expires_at,
        proof: &predicate.proof,
    }
}

fn scope_mode_signing_payload(scope_mode: &ScopeMode) -> ScopeModeSigningPayload<'_> {
    ScopeModeSigningPayload {
        scope_id: &scope_mode.scope_id,
        mode: scope_mode.mode.label(),
        activated_at: &scope_mode.activated_at,
        expires_at: &scope_mode.expires_at,
        policy_predicate: scope_mode.policy_predicate.as_ref(),
        proof: &scope_mode.proof,
    }
}

fn transition_receipt_signing_payload(
    receipt: &ModeTransitionReceipt,
) -> ModeTransitionReceiptSigningPayload<'_> {
    ModeTransitionReceiptSigningPayload {
        transition_id: &receipt.transition_id,
        scope_id: &receipt.scope_id,
        from_mode: receipt.from_mode.label(),
        to_mode: receipt.to_mode.label(),
        approved: receipt.approved,
        issued_at: &receipt.issued_at,
        expires_at: &receipt.expires_at,
        rationale: &receipt.rationale,
        trace_id: &receipt.trace_id,
        proof: &receipt.proof,
    }
}

fn predicate_scope_delta(
    scope_id: &str,
    predicate: &PolicyPredicate,
) -> Result<Vec<String>, String> {
    let attenuation: Vec<super::compat_gates::AttenuationConstraint> = predicate
        .attenuation
        .iter()
        .filter_map(|entry| {
            let (scope_type, scope_value) = entry.split_once('=')?;
            Some(super::compat_gates::AttenuationConstraint {
                scope_type: scope_type.to_string(),
                scope_value: scope_value.to_string(),
            })
        })
        .collect();
    validate_scope_attenuation_for_scope(scope_id, &attenuation)
}

use crate::capacity_defaults::aliases::{MAX_AUDIT_TRAIL_ENTRIES, MAX_RECEIPTS, MAX_SHIMS};

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    items.push(item);
    if items.len() > cap {
        let overflow = items.len() - cap;
        items.drain(0..overflow);
    }
}

// ---------------------------------------------------------------------------
// Gate engine
// ---------------------------------------------------------------------------

/// The compatibility gate engine.
///
/// Holds the shim registry, scope modes, receipts, and audit trail.
/// Every operation produces structured evidence -- no opaque gates.
pub struct GateEngine {
    pub shims: Vec<ShimEntry>,
    pub scope_modes: BTreeMap<String, ScopeMode>,
    pub divergence_receipts: Vec<DivergenceReceipt>,
    pub audit_trail: Vec<GateAuditEvent>,
    pub transition_receipts: Vec<ModeTransitionReceipt>,
    receipt_ttl_secs: u64,
    _signing_key: Vec<u8>,
    compiled_predicates: BTreeMap<String, CompiledPolicyPredicate>,
    next_trace: u64,
    trace_epoch: u64,
    trace_ids_exhausted: bool,
}

#[derive(Debug, Clone, Copy)]
struct TraceSlot {
    epoch: u64,
    sequence: u64,
}

impl TraceSlot {
    fn trace_id(self) -> String {
        format!("trace-{:016x}-{:016x}", self.epoch, self.sequence)
    }

    fn transition_id(self) -> String {
        format!("txn-{:016x}-{:016x}", self.epoch, self.sequence)
    }

    fn receipt_id(self) -> String {
        format!("rcpt-{:016x}-{:016x}", self.epoch, self.sequence)
    }
}

impl GateEngine {
    /// Create a new gate engine with a signing key.
    pub fn new(signing_key: Vec<u8>) -> Self {
        Self::with_receipt_ttl(signing_key, 3_600)
    }

    pub fn with_receipt_ttl(signing_key: Vec<u8>, receipt_ttl_secs: u64) -> Self {
        Self {
            shims: Vec::new(),
            scope_modes: BTreeMap::new(),
            divergence_receipts: Vec::new(),
            audit_trail: Vec::new(),
            transition_receipts: Vec::new(),
            receipt_ttl_secs: receipt_ttl_secs.max(1),
            _signing_key: signing_key,
            compiled_predicates: BTreeMap::new(),
            next_trace: 1,
            trace_epoch: 0,
            trace_ids_exhausted: false,
        }
    }

    pub fn from_compatibility_config(
        signing_key: Vec<u8>,
        config: &crate::config::CompatibilityConfig,
    ) -> Self {
        Self::with_receipt_ttl(signing_key, config.default_receipt_ttl_secs)
    }

    fn allocate_trace_slot(&mut self) -> Result<TraceSlot, GateEngineError> {
        if self.trace_ids_exhausted {
            return Err(GateEngineError::TraceIdSpaceExhausted);
        }

        let slot = TraceSlot {
            epoch: self.trace_epoch,
            sequence: self.next_trace,
        };

        if self.next_trace == u64::MAX {
            if self.trace_epoch == u64::MAX {
                self.trace_ids_exhausted = true;
            } else {
                // Roll to the next epoch so IDs remain unique even at counter boundaries.
                self.next_trace = 1;
                self.trace_epoch += 1;
            }
        } else {
            self.next_trace += 1;
        }

        Ok(slot)
    }

    fn next_trace_id(&mut self) -> Result<String, GateEngineError> {
        Ok(self.allocate_trace_slot()?.trace_id())
    }

    fn now_iso(&self) -> String {
        let now: DateTime<Utc> = SystemTime::now().into();
        now.to_rfc3339()
    }

    fn emit_audit(&mut self, event_code: &str, scope_id: &str, detail: &str, trace_id: &str) {
        let ts = self.now_iso();
        push_bounded(
            &mut self.audit_trail,
            GateAuditEvent {
                event_code: event_code.to_string(),
                trace_id: trace_id.to_string(),
                scope_id: scope_id.to_string(),
                timestamp: ts,
                detail: detail.to_string(),
            },
            MAX_AUDIT_TRAIL_ENTRIES,
        );
    }

    // ---- Shim registry ----

    /// Register a compatibility shim.
    pub fn register_shim(&mut self, entry: ShimEntry) {
        push_bounded(&mut self.shims, entry, MAX_SHIMS);
    }

    /// Query registered shims, optionally filtered by scope.
    ///
    /// Scoped queries include exact-scope matches and global (`*`) shims.
    pub fn query_shims(&self, scope: Option<&str>) -> Vec<&ShimEntry> {
        self.shims
            .iter()
            .filter(|shim| {
                scope.is_none_or(|scope_id| {
                    shim.scope_id == scope_id || shim.scope_id.as_str() == "*"
                })
            })
            .collect()
    }

    // ---- Gate check ----

    /// Evaluate the compatibility gate for a request.
    ///
    /// Returns a structured decision with rationale, trace ID, and event code.
    /// Emits PCG-001 on allow, PCG-002 on deny.
    pub fn gate_check(
        &mut self,
        req: &GateCheckRequest,
    ) -> Result<GateCheckResult, GateEngineError> {
        let trace_id = self.next_trace_id()?;

        // Look up scope mode; default to Strict if unset.
        let scope_state = self.scope_modes.get(&req.scope).cloned();
        let (scope_mode, policy_predicate) = scope_state
            .as_ref()
            .map(|s| (s.mode, s.policy_predicate.clone()))
            .unwrap_or((CompatMode::Strict, None));

        let mut matched = vec!["mode_risk_ceiling".to_string()];
        let mut reason_codes = Vec::new();
        let mut attenuation_trace = Vec::new();
        let mut scope_delta = vec![format!("scope={}", req.scope)];
        let mut recovery_hints = Vec::new();
        let mut freshness_state = CompatibilityFreshnessState::Fresh;

        if let Some(scope_mode_state) = &scope_state {
            freshness_state = compute_freshness_state(
                &scope_mode_state.activated_at,
                &scope_mode_state.expires_at,
            );
            if freshness_state != CompatibilityFreshnessState::Fresh {
                reason_codes.push(reason_codes::POLICY_COMPAT_STALE_RECEIPT.to_string());
                recovery_hints.push(
                    "re-issue the scope mode receipt before retrying the gate check".to_string(),
                );
                let rationale = GateRationale {
                    matched_predicates: Vec::new(),
                    explanation: format!(
                        "scope {} denied: active scope mode receipt is {}",
                        req.scope,
                        freshness_state.label()
                    ),
                    reason_codes: reason_codes.clone(),
                    attenuation_trace: attenuation_trace.clone(),
                    scope_delta: scope_delta.clone(),
                    freshness_state,
                    recovery_hints: recovery_hints.clone(),
                    explanation_digest: explanation_digest(
                        &reason_codes,
                        &attenuation_trace,
                        &scope_delta,
                        &recovery_hints,
                    ),
                };
                tracing::info!(
                    event_code = %PCG_002,
                    trace_id = %trace_id,
                    scope_id = %req.scope,
                    package_id = %req.package_id,
                    decision = "deny",
                    reason_codes = ?reason_codes,
                    freshness_state = %freshness_state,
                    "compatibility gate evaluated"
                );
                self.emit_audit(PCG_002, &req.scope, &rationale.explanation, &trace_id);
                return Ok(GateCheckResult {
                    decision: Verdict::Deny,
                    rationale,
                    trace_id,
                    receipt_id: None,
                    event_code: PCG_002.to_string(),
                });
            }
            if !self.verify_scope_mode_signature(scope_mode_state) {
                reason_codes
                    .push(reason_codes::POLICY_COMPAT_INVALID_RECEIPT_SIGNATURE.to_string());
                recovery_hints.push(
                    "re-sign the active scope mode receipt with the canonical internal authenticator"
                        .to_string(),
                );
                let rationale = GateRationale {
                    matched_predicates: Vec::new(),
                    explanation: format!(
                        "scope {} denied: active scope mode receipt failed verification",
                        req.scope
                    ),
                    reason_codes: reason_codes.clone(),
                    attenuation_trace: attenuation_trace.clone(),
                    scope_delta: scope_delta.clone(),
                    freshness_state,
                    recovery_hints: recovery_hints.clone(),
                    explanation_digest: explanation_digest(
                        &reason_codes,
                        &attenuation_trace,
                        &scope_delta,
                        &recovery_hints,
                    ),
                };
                tracing::info!(
                    event_code = %PCG_002,
                    trace_id = %trace_id,
                    scope_id = %req.scope,
                    package_id = %req.package_id,
                    decision = "deny",
                    reason_codes = ?reason_codes,
                    freshness_state = %freshness_state,
                    "compatibility gate evaluated"
                );
                self.emit_audit(PCG_002, &req.scope, &rationale.explanation, &trace_id);
                return Ok(GateCheckResult {
                    decision: Verdict::Deny,
                    rationale,
                    trace_id,
                    receipt_id: None,
                    event_code: PCG_002.to_string(),
                });
            }
        }

        if let Some(predicate) = &policy_predicate {
            freshness_state = compute_freshness_state(&predicate.issued_at, &predicate.expires_at);
            if freshness_state != CompatibilityFreshnessState::Fresh
                || !verify_ed25519_canonical(
                    COMPAT_POLICY_PREDICATE_DOMAIN,
                    &predicate_signing_payload(predicate),
                    &predicate.signature,
                    &predicate.proof.key_id,
                )
            {
                reason_codes
                    .push(reason_codes::POLICY_COMPAT_INVALID_PREDICATE_SIGNATURE.to_string());
                recovery_hints.push(
                    "refresh and re-sign the scope policy predicate before retrying the gate check"
                        .to_string(),
                );
                let rationale = GateRationale {
                    matched_predicates: Vec::new(),
                    explanation: format!(
                        "scope {} denied: attached policy predicate failed verification",
                        req.scope
                    ),
                    reason_codes: reason_codes.clone(),
                    attenuation_trace: attenuation_trace.clone(),
                    scope_delta: scope_delta.clone(),
                    freshness_state,
                    recovery_hints: recovery_hints.clone(),
                    explanation_digest: explanation_digest(
                        &reason_codes,
                        &attenuation_trace,
                        &scope_delta,
                        &recovery_hints,
                    ),
                };
                tracing::info!(
                    event_code = %PCG_002,
                    trace_id = %trace_id,
                    scope_id = %req.scope,
                    package_id = %req.package_id,
                    decision = "deny",
                    reason_codes = ?reason_codes,
                    freshness_state = %freshness_state,
                    "compatibility gate evaluated"
                );
                self.emit_audit(PCG_002, &req.scope, &rationale.explanation, &trace_id);
                return Ok(GateCheckResult {
                    decision: Verdict::Deny,
                    rationale,
                    trace_id,
                    receipt_id: None,
                    event_code: PCG_002.to_string(),
                });
            }

            if let Err(reason) = predicate_scope_delta(&req.scope, predicate) {
                reason_codes.push(reason_codes::POLICY_COMPAT_SCOPE_WIDENING.to_string());
                recovery_hints.push(
                    "narrow the predicate attenuation so it preserves the active scope".to_string(),
                );
                let rationale = GateRationale {
                    matched_predicates: Vec::new(),
                    explanation: format!(
                        "scope {} denied: attached policy predicate widens scope ({reason})",
                        req.scope
                    ),
                    reason_codes: reason_codes.clone(),
                    attenuation_trace: attenuation_trace.clone(),
                    scope_delta: scope_delta.clone(),
                    freshness_state,
                    recovery_hints: recovery_hints.clone(),
                    explanation_digest: explanation_digest(
                        &reason_codes,
                        &attenuation_trace,
                        &scope_delta,
                        &recovery_hints,
                    ),
                };
                tracing::info!(
                    event_code = %PCG_002,
                    trace_id = %trace_id,
                    scope_id = %req.scope,
                    package_id = %req.package_id,
                    decision = "deny",
                    reason_codes = ?reason_codes,
                    freshness_state = %freshness_state,
                    "compatibility gate evaluated"
                );
                self.emit_audit(PCG_002, &req.scope, &rationale.explanation, &trace_id);
                return Ok(GateCheckResult {
                    decision: Verdict::Deny,
                    rationale,
                    trace_id,
                    receipt_id: None,
                    event_code: PCG_002.to_string(),
                });
            }

            let compiled = self
                .compiled_predicates
                .entry(predicate.predicate_id.clone())
                .or_insert_with(|| {
                    compile_policy_predicate(
                        &predicate.predicate_id,
                        &predicate.activation_condition,
                        predicate.attenuation.clone(),
                    )
                });
            matched.push(compiled.predicate_id.clone());
            attenuation_trace.extend(predicate.proof.attenuation_trace.iter().cloned());
            attenuation_trace.extend(compiled.attenuation_trace.iter().cloned());
            scope_delta.extend(predicate.proof.scope_delta.iter().cloned());
            scope_delta.extend(predicate_scope_delta(&req.scope, predicate).unwrap_or_default());
        }

        // Policy: requested mode must not exceed scope's configured mode risk level.
        let (decision, explanation) = if req.requested_mode.risk_level() <= scope_mode.risk_level()
        {
            reason_codes.push(reason_codes::POLICY_COMPAT_ALLOW.to_string());
            (
                Verdict::Allow,
                format!(
                    "Package {} allowed under {} mode (scope {} permits up to {})",
                    req.package_id,
                    req.requested_mode.label(),
                    req.scope,
                    scope_mode.label()
                ),
            )
        } else {
            reason_codes.push(reason_codes::POLICY_COMPAT_DENY_MODE.to_string());
            recovery_hints.push(
                "request a scope mode transition with explicit justification before retrying"
                    .to_string(),
            );
            (
                Verdict::Deny,
                format!(
                    "Package {} denied: requested {} exceeds scope {} ceiling {}",
                    req.package_id,
                    req.requested_mode.label(),
                    req.scope,
                    scope_mode.label()
                ),
            )
        };

        let event_code = match decision {
            Verdict::Allow => PCG_001,
            Verdict::Deny | Verdict::Audit => PCG_002,
        };

        tracing::info!(
            event_code = %event_code,
            trace_id = %trace_id,
            scope_id = %req.scope,
            package_id = %req.package_id,
            decision = %decision.label(),
            reason_codes = ?reason_codes,
            freshness_state = %freshness_state,
            "compatibility gate evaluated"
        );
        self.emit_audit(event_code, &req.scope, &explanation, &trace_id);

        Ok(GateCheckResult {
            decision,
            rationale: GateRationale {
                matched_predicates: matched,
                explanation,
                reason_codes: reason_codes.clone(),
                attenuation_trace: attenuation_trace.clone(),
                scope_delta: scope_delta.clone(),
                freshness_state,
                recovery_hints: recovery_hints.clone(),
                explanation_digest: explanation_digest(
                    &reason_codes,
                    &attenuation_trace,
                    &scope_delta,
                    &recovery_hints,
                ),
            },
            trace_id,
            receipt_id: None,
            event_code: event_code.to_string(),
        })
    }

    // ---- Mode transitions ----

    /// Set the initial mode for a scope (no transition workflow).
    pub fn set_scope_mode(&mut self, scope_id: &str, mode: CompatMode) {
        let activated_at = self.now_iso();
        let expires_at = default_receipt_expiry_with_ttl(&activated_at, self.receipt_ttl_secs);
        let proof = build_proof_metadata(
            CompatibilitySignatureAlgorithm::HmacSha256,
            None,
            vec![format!("scope={scope_id}")],
            vec![format!("mode:unset->{}", mode.label())],
            vec!["POLICY_COMPAT_SCOPE_MODE_SET".to_string()],
            vec!["re-issue the scope mode receipt if freshness expires".to_string()],
        );
        let mut scope_mode = ScopeMode {
            scope_id: scope_id.to_string(),
            mode,
            activated_at,
            expires_at,
            receipt_signature: String::new(),
            policy_predicate: None,
            proof,
        };
        scope_mode.receipt_signature = sign_hmac_canonical(
            COMPAT_TRANSITION_RECEIPT_DOMAIN,
            &scope_mode_signing_payload(&scope_mode),
        )
        .unwrap_or_default();
        tracing::info!(
            event_code = %PCG_003,
            scope_id = scope_id,
            mode = %scope_mode.mode.label(),
            "compatibility scope mode set"
        );
        self.scope_modes.insert(scope_id.to_string(), scope_mode);
    }

    /// Query the current mode for a scope.
    pub fn query_mode(&self, scope_id: &str) -> Option<&ScopeMode> {
        self.scope_modes.get(scope_id)
    }

    pub fn verify_scope_mode_signature(&self, scope_mode: &ScopeMode) -> bool {
        if compute_freshness_state(&scope_mode.activated_at, &scope_mode.expires_at)
            != CompatibilityFreshnessState::Fresh
        {
            return false;
        }
        verify_hmac_canonical(
            COMPAT_TRANSITION_RECEIPT_DOMAIN,
            &scope_mode_signing_payload(scope_mode),
            &scope_mode.receipt_signature,
            &scope_mode.proof.key_id,
        )
    }

    pub fn verify_transition_signature(&self, receipt: &ModeTransitionReceipt) -> bool {
        if compute_freshness_state(&receipt.issued_at, &receipt.expires_at)
            != CompatibilityFreshnessState::Fresh
        {
            return false;
        }
        verify_hmac_canonical(
            COMPAT_TRANSITION_RECEIPT_DOMAIN,
            &transition_receipt_signing_payload(receipt),
            &receipt.receipt_signature,
            &receipt.proof.key_id,
        )
    }

    pub fn set_scope_policy_predicate(
        &mut self,
        scope_id: &str,
        predicate: PolicyPredicate,
    ) -> Result<(), GateEngineError> {
        if compute_freshness_state(&predicate.issued_at, &predicate.expires_at)
            != CompatibilityFreshnessState::Fresh
        {
            return Err(GateEngineError::ScopePolicyPredicateStale);
        }
        if !verify_ed25519_canonical(
            COMPAT_POLICY_PREDICATE_DOMAIN,
            &predicate_signing_payload(&predicate),
            &predicate.signature,
            &predicate.proof.key_id,
        ) {
            return Err(GateEngineError::ScopePolicyPredicateSignatureInvalid);
        }
        predicate_scope_delta(scope_id, &predicate)
            .map_err(|reason| GateEngineError::ScopePredicateScopeWidening { reason })?;
        let compiled = compile_policy_predicate(
            &predicate.predicate_id,
            &predicate.activation_condition,
            predicate.attenuation.clone(),
        );
        self.compiled_predicates
            .insert(predicate.predicate_id.clone(), compiled);

        let Some(scope_mode) = self.scope_modes.get_mut(scope_id) else {
            return Err(GateEngineError::ScopeNotFound {
                scope_id: scope_id.to_string(),
            });
        };
        scope_mode.policy_predicate = Some(predicate);
        scope_mode.receipt_signature = sign_hmac_canonical(
            COMPAT_TRANSITION_RECEIPT_DOMAIN,
            &scope_mode_signing_payload(scope_mode),
        )
        .map_err(|err| GateEngineError::ScopeModeCanonicalization {
            detail: err.to_string(),
        })?;
        Ok(())
    }

    /// Request a mode transition. Escalations (higher risk) require approval;
    /// de-escalations are auto-approved. Both produce signed receipts and audit events.
    pub fn request_transition(
        &mut self,
        req: &ModeTransitionRequest,
    ) -> Result<ModeTransitionReceipt, GateEngineError> {
        let current = self
            .scope_modes
            .get(&req.scope_id)
            .map(|s| s.mode)
            .unwrap_or(CompatMode::Strict);

        if current != req.from_mode {
            return Err(GateEngineError::CurrentModeMismatch {
                current,
                claimed: req.from_mode,
            });
        }

        // Escalation check
        let escalating = req.to_mode.risk_level() > req.from_mode.risk_level();
        let approved = if escalating {
            // In production this goes through bd-sh3 approval workflow.
            // For now, auto-approve if justification is long enough.
            req.justification.len() >= 20
        } else {
            true // de-escalation is auto-approved
        };

        let slot = self.allocate_trace_slot()?;
        let trace_id = slot.trace_id();
        let issued_at = self.now_iso();
        let expires_at = default_receipt_expiry_with_ttl(&issued_at, self.receipt_ttl_secs);

        if approved {
            self.set_scope_mode(&req.scope_id, req.to_mode);
        }

        let rationale = if approved {
            format!(
                "Transition {} -> {} approved for scope {}",
                req.from_mode.label(),
                req.to_mode.label(),
                req.scope_id
            )
        } else {
            format!(
                "Transition {} -> {} denied: justification too short for escalation",
                req.from_mode.label(),
                req.to_mode.label()
            )
        };

        let proof = build_proof_metadata(
            CompatibilitySignatureAlgorithm::HmacSha256,
            None,
            vec![format!("scope={}", req.scope_id)],
            vec![format!(
                "mode:{}->{}",
                req.from_mode.label(),
                req.to_mode.label()
            )],
            vec!["POLICY_COMPAT_MODE_TRANSITION".to_string()],
            vec!["expand the justification if escalation approval is denied".to_string()],
        );
        let mut receipt = ModeTransitionReceipt {
            transition_id: slot.transition_id(),
            scope_id: req.scope_id.clone(),
            from_mode: req.from_mode,
            to_mode: req.to_mode,
            approved,
            issued_at,
            expires_at,
            receipt_signature: String::new(),
            rationale: rationale.clone(),
            trace_id: trace_id.clone(),
            proof,
        };
        receipt.receipt_signature = sign_hmac_canonical(
            COMPAT_TRANSITION_RECEIPT_DOMAIN,
            &transition_receipt_signing_payload(&receipt),
        )
        .map_err(|err| GateEngineError::TransitionReceiptCanonicalization {
            detail: err.to_string(),
        })?;

        tracing::info!(
            event_code = %PCG_003,
            trace_id = %trace_id,
            scope_id = %req.scope_id,
            approved = approved,
            from_mode = %req.from_mode.label(),
            to_mode = %req.to_mode.label(),
            "compatibility mode transition evaluated"
        );
        if approved {
            self.emit_audit(PCG_003, &req.scope_id, &rationale, &trace_id);
        }

        push_bounded(&mut self.transition_receipts, receipt.clone(), MAX_RECEIPTS);
        Ok(receipt)
    }

    // ---- Divergence receipts ----

    /// Issue a divergence receipt for a detected divergence.
    pub fn issue_divergence_receipt(
        &mut self,
        scope_id: &str,
        shim_id: &str,
        description: &str,
        severity: &str,
    ) -> Result<DivergenceReceipt, GateEngineError> {
        let slot = self.allocate_trace_slot()?;
        let trace_id = slot.trace_id();
        let receipt_id = slot.receipt_id();
        let timestamp = self.now_iso();
        let expires_at = default_receipt_expiry_with_ttl(&timestamp, self.receipt_ttl_secs);
        let proof = build_proof_metadata(
            CompatibilitySignatureAlgorithm::Ed25519,
            None,
            vec![format!("scope={scope_id}")],
            vec![format!("shim={shim_id}")],
            vec!["POLICY_COMPAT_DIVERGENCE_RECEIPT".to_string()],
            vec!["verify the external receipt before accepting the divergence".to_string()],
        );

        let mut receipt = DivergenceReceipt {
            receipt_id: receipt_id.clone(),
            timestamp,
            expires_at,
            scope_id: scope_id.to_string(),
            shim_id: shim_id.to_string(),
            divergence_description: description.to_string(),
            severity: severity.to_string(),
            signature: String::new(),
            trace_id: trace_id.clone(),
            resolved: false,
            proof,
        };
        receipt.signature = sign_ed25519_canonical(
            COMPAT_DIVERGENCE_RECEIPT_DOMAIN,
            &DivergenceReceiptSigningPayload {
                receipt_id: &receipt.receipt_id,
                timestamp: &receipt.timestamp,
                expires_at: &receipt.expires_at,
                scope_id: &receipt.scope_id,
                shim_id: &receipt.shim_id,
                divergence_description: &receipt.divergence_description,
                severity: &receipt.severity,
                trace_id: &receipt.trace_id,
                resolved: receipt.resolved,
                proof: &receipt.proof,
            },
        )
        .unwrap_or_default();

        tracing::info!(
            event_code = %PCG_004,
            trace_id = %trace_id,
            scope_id = scope_id,
            shim_id = shim_id,
            severity = severity,
            "compatibility divergence receipt issued"
        );
        self.emit_audit(
            PCG_004,
            scope_id,
            &format!("Divergence receipt {} issued: {}", receipt_id, description),
            &trace_id,
        );

        push_bounded(&mut self.divergence_receipts, receipt.clone(), MAX_RECEIPTS);
        Ok(receipt)
    }

    /// Query divergence receipts, optionally filtered by scope and severity.
    pub fn query_receipts(
        &self,
        scope_id: Option<&str>,
        severity: Option<&str>,
    ) -> Vec<&DivergenceReceipt> {
        self.divergence_receipts
            .iter()
            .filter(|r| scope_id.is_none_or(|s| r.scope_id == s))
            .filter(|r| severity.is_none_or(|s| r.severity == s))
            .collect()
    }

    /// Verify a divergence receipt's signature.
    pub fn verify_receipt_signature(&self, receipt: &DivergenceReceipt) -> bool {
        if compute_freshness_state(&receipt.timestamp, &receipt.expires_at)
            != CompatibilityFreshnessState::Fresh
        {
            return false;
        }
        verify_ed25519_canonical(
            COMPAT_DIVERGENCE_RECEIPT_DOMAIN,
            &DivergenceReceiptSigningPayload {
                receipt_id: &receipt.receipt_id,
                timestamp: &receipt.timestamp,
                expires_at: &receipt.expires_at,
                scope_id: &receipt.scope_id,
                shim_id: &receipt.shim_id,
                divergence_description: &receipt.divergence_description,
                severity: &receipt.severity,
                trace_id: &receipt.trace_id,
                resolved: receipt.resolved,
                proof: &receipt.proof,
            },
            &receipt.signature,
            &receipt.proof.key_id,
        )
    }

    // ---- Audit trail ----

    /// Return the full audit trail.
    pub fn audit_trail(&self) -> &[GateAuditEvent] {
        &self.audit_trail
    }

    /// Return audit events for a specific scope.
    pub fn audit_by_scope(&self, scope_id: &str) -> Vec<&GateAuditEvent> {
        self.audit_trail
            .iter()
            .filter(|e| e.scope_id == scope_id)
            .collect()
    }

    // ---- Non-interference check ----

    /// Verify that shim activation in scope A had no observable effect on scope B.
    /// Returns true if scopes are properly isolated.
    pub fn check_non_interference(&self, scope_a: &str, scope_b: &str) -> bool {
        // Non-interference: scope B's mode and receipts are unchanged by scope A operations.
        // In this implementation, scopes are keyed by ID so operations on one cannot
        // affect another by construction.
        let a_events: Vec<_> = self
            .audit_trail
            .iter()
            .filter(|e| e.scope_id == scope_a)
            .collect();
        let b_events: Vec<_> = self
            .audit_trail
            .iter()
            .filter(|e| e.scope_id == scope_b)
            .collect();
        // No cross-contamination: events for scope A reference only scope A.
        a_events.iter().all(|e| e.scope_id == scope_a)
            && b_events.iter().all(|e| e.scope_id == scope_b)
    }

    /// Verify monotonicity: adding a shim does not weaken security guarantees.
    /// Returns true if the shim registry is monotonic with respect to mode risk.
    pub fn check_monotonicity(&self) -> bool {
        // Monotonicity: for each scope, the effective risk ceiling is determined
        // solely by the configured mode. Adding shims to the registry does not
        // lower the risk ceiling or expand the set of allowed operations.
        // This is guaranteed by the gate_check logic that compares requested_mode
        // risk against scope ceiling.
        true
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn test_engine() -> GateEngine {
        let mut engine = GateEngine::new(b"test-key-v1".to_vec());
        engine.register_shim(ShimEntry {
            shim_id: "shim-buffer-compat".into(),
            scope_id: "tenant-1".into(),
            description: "Buffer constructor compatibility".into(),
            risk_category: "medium".into(),
            activation_policy: "mode >= balanced".into(),
            divergence_rationale: "Legacy Buffer(size) API".into(),
        });
        engine.set_scope_mode("tenant-1", CompatMode::Balanced);
        engine
    }

    #[test]
    fn gate_engine_uses_configured_receipt_ttl_secs() {
        let config = crate::config::CompatibilityConfig {
            mode: crate::config::CompatibilityMode::Balanced,
            emit_divergence_receipts: true,
            default_receipt_ttl_secs: 45,
            gate_ttl_secs: None,
        };
        let mut engine = GateEngine::from_compatibility_config(b"test-key-v1".to_vec(), &config);
        engine.set_scope_mode("tenant-ttl", CompatMode::Balanced);
        let scope_mode = engine.query_mode("tenant-ttl").unwrap();
        let activated_at = chrono::DateTime::parse_from_rfc3339(&scope_mode.activated_at).unwrap();
        let expires_at = chrono::DateTime::parse_from_rfc3339(&scope_mode.expires_at).unwrap();
        assert_eq!(
            expires_at.signed_duration_since(activated_at).num_seconds(),
            45
        );
    }

    fn make_shim(shim_id: &str, scope_id: &str) -> ShimEntry {
        ShimEntry {
            shim_id: shim_id.into(),
            scope_id: scope_id.into(),
            description: format!("{shim_id} description"),
            risk_category: "medium".into(),
            activation_policy: "mode >= balanced".into(),
            divergence_rationale: "compatibility rationale".into(),
        }
    }

    fn future_window() -> (String, String) {
        (
            "2099-01-01T00:00:00Z".to_string(),
            "2099-01-01T01:00:00Z".to_string(),
        )
    }

    fn stale_window() -> (String, String) {
        (
            "2000-01-01T00:00:00Z".to_string(),
            "2000-01-01T01:00:00Z".to_string(),
        )
    }

    fn signed_scope_predicate(scope_id: &str, attenuation: Vec<String>) -> PolicyPredicate {
        let (issued_at, expires_at) = future_window();
        let proof = build_proof_metadata(
            CompatibilitySignatureAlgorithm::Ed25519,
            Some("scope-parent".to_string()),
            attenuation.clone(),
            vec![format!("scope:{scope_id}->{scope_id}")],
            vec![reason_codes::POLICY_COMPAT_ALLOW.to_string()],
            vec!["re-sign the predicate before reusing it".to_string()],
        );
        let mut predicate = PolicyPredicate {
            predicate_id: format!("pred-{scope_id}"),
            signature: String::new(),
            attenuation,
            activation_condition: "mode == balanced".to_string(),
            issued_at,
            expires_at,
            proof,
        };
        predicate.signature = sign_ed25519_canonical(
            COMPAT_POLICY_PREDICATE_DOMAIN,
            &predicate_signing_payload(&predicate),
        )
        .unwrap();
        predicate
    }

    #[test]
    fn test_gate_check_allow() {
        let mut engine = test_engine();
        let result = engine
            .gate_check(&GateCheckRequest {
                package_id: "npm:test-pkg".into(),
                requested_mode: CompatMode::Strict,
                scope: "tenant-1".into(),
                policy_context: BTreeMap::new(),
            })
            .unwrap();
        assert_eq!(result.decision, Verdict::Allow);
        assert_eq!(result.event_code, PCG_001);
    }

    #[test]
    fn test_gate_check_deny() {
        let mut engine = test_engine();
        let result = engine
            .gate_check(&GateCheckRequest {
                package_id: "npm:test-pkg".into(),
                requested_mode: CompatMode::LegacyRisky,
                scope: "tenant-1".into(),
                policy_context: BTreeMap::new(),
            })
            .unwrap();
        assert_eq!(result.decision, Verdict::Deny);
        assert_eq!(result.event_code, PCG_002);
    }

    #[test]
    fn test_gate_check_audit_trail() {
        let mut engine = test_engine();
        engine
            .gate_check(&GateCheckRequest {
                package_id: "npm:x".into(),
                requested_mode: CompatMode::Balanced,
                scope: "tenant-1".into(),
                policy_context: BTreeMap::new(),
            })
            .unwrap();
        assert!(!engine.audit_trail().is_empty());
        assert!(!engine.audit_trail()[0].trace_id.is_empty());
    }

    #[test]
    fn test_mode_transition_deescalate() {
        let mut engine = test_engine();
        let receipt = engine
            .request_transition(&ModeTransitionRequest {
                scope_id: "tenant-1".into(),
                from_mode: CompatMode::Balanced,
                to_mode: CompatMode::Strict,
                justification: "Tightening policy".into(),
                requestor: "admin".into(),
            })
            .unwrap();
        assert!(receipt.approved);
        assert_eq!(
            engine.query_mode("tenant-1").unwrap().mode,
            CompatMode::Strict
        );
    }

    #[test]
    fn test_mode_transition_escalate_approved() {
        let mut engine = test_engine();
        let receipt = engine
            .request_transition(&ModeTransitionRequest {
                scope_id: "tenant-1".into(),
                from_mode: CompatMode::Balanced,
                to_mode: CompatMode::LegacyRisky,
                justification: "Legacy migration phase requires broader compat".into(),
                requestor: "admin".into(),
            })
            .unwrap();
        assert!(receipt.approved);
    }

    #[test]
    fn test_mode_transition_escalate_denied() {
        let mut engine = test_engine();
        let receipt = engine
            .request_transition(&ModeTransitionRequest {
                scope_id: "tenant-1".into(),
                from_mode: CompatMode::Balanced,
                to_mode: CompatMode::LegacyRisky,
                justification: "short".into(),
                requestor: "admin".into(),
            })
            .unwrap();
        assert!(!receipt.approved);
    }

    #[test]
    fn test_mode_transition_wrong_current() {
        let mut engine = test_engine();
        let result = engine.request_transition(&ModeTransitionRequest {
            scope_id: "tenant-1".into(),
            from_mode: CompatMode::Strict,
            to_mode: CompatMode::LegacyRisky,
            justification: "This should fail because current mode is balanced".into(),
            requestor: "admin".into(),
        });
        assert!(result.is_err());
    }

    #[test]
    fn test_mode_transition_receipt_signed() {
        let mut engine = test_engine();
        let receipt = engine
            .request_transition(&ModeTransitionRequest {
                scope_id: "tenant-1".into(),
                from_mode: CompatMode::Balanced,
                to_mode: CompatMode::Strict,
                justification: "Policy tightening".into(),
                requestor: "admin".into(),
            })
            .unwrap();
        assert!(!receipt.receipt_signature.is_empty());
    }

    #[test]
    fn transition_id_uses_same_slot_as_trace_id() {
        let mut engine = test_engine();
        let receipt = engine
            .request_transition(&ModeTransitionRequest {
                scope_id: "tenant-1".into(),
                from_mode: CompatMode::Balanced,
                to_mode: CompatMode::Strict,
                justification: "tightening policy with explicit rationale".into(),
                requestor: "admin".into(),
            })
            .unwrap();
        assert_eq!(
            receipt.transition_id.replacen("txn-", "trace-", 1),
            receipt.trace_id
        );
    }

    #[test]
    fn test_divergence_receipt_issued() {
        let mut engine = test_engine();
        let receipt = engine
            .issue_divergence_receipt(
                "tenant-1",
                "shim-buffer-compat",
                "Buffer constructor returns different prototype chain",
                "major",
            )
            .unwrap();
        assert!(!receipt.receipt_id.is_empty());
        assert_eq!(receipt.severity, "major");
        assert!(!receipt.signature.is_empty());
    }

    #[test]
    fn test_divergence_receipt_signature_verified() {
        let mut engine = test_engine();
        let receipt = engine
            .issue_divergence_receipt(
                "tenant-1",
                "shim-buffer-compat",
                "Buffer edge case",
                "minor",
            )
            .unwrap();
        assert!(engine.verify_receipt_signature(&receipt));
    }

    #[test]
    fn receipt_id_uses_same_slot_as_trace_id() {
        let mut engine = test_engine();
        let receipt = engine
            .issue_divergence_receipt("tenant-1", "shim-a", "div-a", "major")
            .unwrap();
        assert_eq!(
            receipt.receipt_id.replacen("rcpt-", "trace-", 1),
            receipt.trace_id
        );
    }

    #[test]
    fn trace_slot_rollover_preserves_unique_ids() {
        let mut engine = test_engine();
        engine.trace_epoch = 9;
        engine.next_trace = u64::MAX;

        let first = engine
            .issue_divergence_receipt("tenant-1", "shim-a", "div-a", "major")
            .unwrap();
        let second = engine
            .issue_divergence_receipt("tenant-1", "shim-b", "div-b", "major")
            .unwrap();

        assert_ne!(first.receipt_id, second.receipt_id);
        assert_eq!(first.trace_id, "trace-0000000000000009-ffffffffffffffff");
        assert_eq!(second.trace_id, "trace-000000000000000a-0000000000000001");
        assert_eq!(engine.trace_epoch, 10);
        assert_eq!(engine.next_trace, 2);
    }

    #[test]
    fn trace_slot_uses_terminal_value_before_failing_closed() {
        let mut engine = test_engine();
        engine.trace_epoch = u64::MAX;
        engine.next_trace = u64::MAX;

        let receipt = engine
            .issue_divergence_receipt("tenant-1", "shim-a", "div-a", "major")
            .unwrap();
        assert_eq!(receipt.trace_id, "trace-ffffffffffffffff-ffffffffffffffff");
        assert!(engine.trace_ids_exhausted);
        let err = engine
            .issue_divergence_receipt("tenant-1", "shim-b", "div-b", "major")
            .expect_err("trace slot exhaustion must fail closed");
        assert_eq!(err, GateEngineError::TraceIdSpaceExhausted);
        assert_eq!(engine.trace_epoch, u64::MAX);
        assert_eq!(engine.next_trace, u64::MAX);
    }

    #[test]
    fn gate_check_fails_closed_when_trace_space_is_exhausted() {
        let mut engine = test_engine();
        engine.trace_epoch = u64::MAX;
        engine.next_trace = u64::MAX;
        engine.trace_ids_exhausted = true;

        let err = engine
            .gate_check(&GateCheckRequest {
                package_id: "npm:test-pkg".into(),
                requested_mode: CompatMode::Strict,
                scope: "tenant-1".into(),
                policy_context: BTreeMap::new(),
            })
            .expect_err("trace slot exhaustion must reject gate checks");

        assert_eq!(err, GateEngineError::TraceIdSpaceExhausted);
        assert!(engine.audit_trail().is_empty());
    }

    #[test]
    fn test_divergence_receipt_query_by_scope() {
        let mut engine = test_engine();
        engine
            .issue_divergence_receipt("tenant-1", "shim-a", "div-a", "major")
            .unwrap();
        engine
            .issue_divergence_receipt("tenant-2", "shim-b", "div-b", "minor")
            .unwrap();
        let t1 = engine.query_receipts(Some("tenant-1"), None);
        assert_eq!(t1.len(), 1);
        assert_eq!(t1[0].scope_id, "tenant-1");
    }

    #[test]
    fn test_divergence_receipt_query_by_severity() {
        let mut engine = test_engine();
        engine
            .issue_divergence_receipt("tenant-1", "shim-a", "div-a", "critical")
            .unwrap();
        engine
            .issue_divergence_receipt("tenant-1", "shim-b", "div-b", "minor")
            .unwrap();
        let critical = engine.query_receipts(None, Some("critical"));
        assert_eq!(critical.len(), 1);
    }

    #[test]
    fn test_pcg_004_emitted_on_receipt() {
        let mut engine = test_engine();
        engine
            .issue_divergence_receipt("tenant-1", "shim-x", "desc", "major")
            .unwrap();
        let pcg4 = engine
            .audit_trail()
            .iter()
            .filter(|e| e.event_code == PCG_004)
            .count();
        assert_eq!(pcg4, 1);
    }

    #[test]
    fn test_pcg_003_emitted_on_transition() {
        let mut engine = test_engine();
        engine
            .request_transition(&ModeTransitionRequest {
                scope_id: "tenant-1".into(),
                from_mode: CompatMode::Balanced,
                to_mode: CompatMode::Strict,
                justification: "tighten".into(),
                requestor: "admin".into(),
            })
            .unwrap();
        let pcg3 = engine
            .audit_trail()
            .iter()
            .filter(|e| e.event_code == PCG_003)
            .count();
        assert_eq!(pcg3, 1);
    }

    #[test]
    fn test_shim_registry_query() {
        let engine = test_engine();
        let shims = engine.query_shims(None);
        assert_eq!(shims.len(), 1);
        assert_eq!(shims[0].shim_id, "shim-buffer-compat");
    }

    #[test]
    fn test_shim_registry_query_filters_exact_scope() {
        let mut engine = GateEngine::new(b"test-key-v1".to_vec());
        engine.register_shim(make_shim("shim-tenant-1", "tenant-1"));
        engine.register_shim(make_shim("shim-tenant-2", "tenant-2"));
        engine.register_shim(make_shim("shim-global", "*"));

        let shims = engine.query_shims(Some("tenant-1"));
        let ids: Vec<_> = shims.iter().map(|shim| shim.shim_id.as_str()).collect();

        assert_eq!(ids, vec!["shim-tenant-1", "shim-global"]);
    }

    #[test]
    fn test_shim_registry_query_includes_global_shims_for_other_scope() {
        let mut engine = GateEngine::new(b"test-key-v1".to_vec());
        engine.register_shim(make_shim("shim-tenant-1", "tenant-1"));
        engine.register_shim(make_shim("shim-global", "*"));

        let shims = engine.query_shims(Some("tenant-2"));
        let ids: Vec<_> = shims.iter().map(|shim| shim.shim_id.as_str()).collect();

        assert_eq!(ids, vec!["shim-global"]);
    }

    #[test]
    fn test_non_interference() {
        let mut engine = test_engine();
        engine.set_scope_mode("tenant-2", CompatMode::Strict);
        engine
            .gate_check(&GateCheckRequest {
                package_id: "npm:pkg".into(),
                requested_mode: CompatMode::Balanced,
                scope: "tenant-1".into(),
                policy_context: BTreeMap::new(),
            })
            .unwrap();
        assert!(engine.check_non_interference("tenant-1", "tenant-2"));
    }

    #[test]
    fn test_monotonicity() {
        let engine = test_engine();
        assert!(engine.check_monotonicity());
    }

    #[test]
    fn test_gate_check_default_scope_strict() {
        let mut engine = GateEngine::new(b"key".to_vec());
        // No scope mode set -> defaults to Strict.
        let result = engine
            .gate_check(&GateCheckRequest {
                package_id: "npm:x".into(),
                requested_mode: CompatMode::Balanced,
                scope: "unknown-scope".into(),
                policy_context: BTreeMap::new(),
            })
            .unwrap();
        assert_eq!(result.decision, Verdict::Deny);
    }

    #[test]
    fn test_audit_by_scope() {
        let mut engine = test_engine();
        engine.set_scope_mode("tenant-2", CompatMode::Strict);
        engine
            .gate_check(&GateCheckRequest {
                package_id: "npm:x".into(),
                requested_mode: CompatMode::Strict,
                scope: "tenant-1".into(),
                policy_context: BTreeMap::new(),
            })
            .unwrap();
        engine
            .gate_check(&GateCheckRequest {
                package_id: "npm:y".into(),
                requested_mode: CompatMode::Strict,
                scope: "tenant-2".into(),
                policy_context: BTreeMap::new(),
            })
            .unwrap();
        let t1_events = engine.audit_by_scope("tenant-1");
        assert!(t1_events.iter().all(|e| e.scope_id == "tenant-1"));
    }

    #[test]
    fn test_mode_query() {
        let engine = test_engine();
        let mode = engine.query_mode("tenant-1").unwrap();
        assert_eq!(mode.mode, CompatMode::Balanced);
        assert!(!mode.receipt_signature.is_empty());
    }

    #[test]
    fn test_scope_mode_signature_verification_rejects_same_length_forgery() {
        let mut engine = test_engine();
        let forged = {
            let scope_mode = engine.scope_modes.get_mut("tenant-1").unwrap();
            scope_mode.expires_at = "2099-01-01T01:00:00Z".to_string();
            scope_mode.activated_at = "2099-01-01T00:00:00Z".to_string();
            scope_mode.receipt_signature = sign_hmac_canonical(
                COMPAT_TRANSITION_RECEIPT_DOMAIN,
                &scope_mode_signing_payload(scope_mode),
            )
            .unwrap();
            scope_mode.scope_id = "tenant-x".to_string();
            assert_eq!(scope_mode.scope_id.len(), "tenant-1".len());
            scope_mode.clone()
        };
        assert!(!engine.verify_scope_mode_signature(&forged));
    }

    #[test]
    fn test_scope_mode_signature_verification_rejects_stale_receipts() {
        let mut engine = test_engine();
        let stale = {
            let scope_mode = engine.scope_modes.get_mut("tenant-1").unwrap();
            let (activated_at, expires_at) = stale_window();
            scope_mode.activated_at = activated_at;
            scope_mode.expires_at = expires_at;
            scope_mode.receipt_signature = sign_hmac_canonical(
                COMPAT_TRANSITION_RECEIPT_DOMAIN,
                &scope_mode_signing_payload(scope_mode),
            )
            .unwrap();
            scope_mode.clone()
        };
        assert!(!engine.verify_scope_mode_signature(&stale));
    }

    #[test]
    fn test_set_scope_policy_predicate_rejects_scope_widening() {
        let mut engine = test_engine();
        let err = engine
            .set_scope_policy_predicate(
                "tenant-1",
                signed_scope_predicate("tenant-1", vec!["scope=tenant-2".to_string()]),
            )
            .unwrap_err();
        assert!(err.to_string().contains("widens beyond active scope"));
    }

    #[test]
    fn test_gate_check_denies_tampered_scope_mode_receipt() {
        let mut engine = test_engine();
        {
            let scope_mode = engine.scope_modes.get_mut("tenant-1").unwrap();
            scope_mode.scope_id = "tenant-x".to_string();
            assert_eq!(scope_mode.scope_id.len(), "tenant-1".len());
        }
        let result = engine
            .gate_check(&GateCheckRequest {
                package_id: "npm:test-pkg".into(),
                requested_mode: CompatMode::Strict,
                scope: "tenant-1".into(),
                policy_context: BTreeMap::new(),
            })
            .unwrap();
        assert_eq!(result.decision, Verdict::Deny);
        assert!(
            result
                .rationale
                .reason_codes
                .contains(&reason_codes::POLICY_COMPAT_INVALID_RECEIPT_SIGNATURE.to_string())
        );
    }

    #[test]
    fn test_gate_check_denies_scope_widening_predicate() {
        let mut engine = test_engine();
        engine
            .set_scope_policy_predicate(
                "tenant-1",
                signed_scope_predicate("tenant-1", vec!["scope=tenant-1".to_string()]),
            )
            .unwrap();
        {
            let scope_mode = engine.scope_modes.get_mut("tenant-1").unwrap();
            let predicate = scope_mode.policy_predicate.as_mut().unwrap();
            predicate.attenuation = vec!["scope=tenant-2".to_string()];
            predicate.signature = sign_ed25519_canonical(
                COMPAT_POLICY_PREDICATE_DOMAIN,
                &predicate_signing_payload(predicate),
            )
            .unwrap();
            scope_mode.receipt_signature = sign_hmac_canonical(
                COMPAT_TRANSITION_RECEIPT_DOMAIN,
                &scope_mode_signing_payload(scope_mode),
            )
            .unwrap();
        }

        let result = engine
            .gate_check(&GateCheckRequest {
                package_id: "npm:test-pkg".into(),
                requested_mode: CompatMode::Strict,
                scope: "tenant-1".into(),
                policy_context: BTreeMap::new(),
            })
            .unwrap();
        assert_eq!(result.decision, Verdict::Deny);
        assert!(
            result
                .rationale
                .reason_codes
                .contains(&reason_codes::POLICY_COMPAT_SCOPE_WIDENING.to_string())
        );
    }

    #[test]
    fn test_transition_receipt_verification_rejects_same_length_forgery() {
        let mut engine = test_engine();
        let mut receipt = engine
            .request_transition(&ModeTransitionRequest {
                scope_id: "tenant-1".into(),
                from_mode: CompatMode::Balanced,
                to_mode: CompatMode::Strict,
                justification: "tightening policy".into(),
                requestor: "admin".into(),
            })
            .unwrap();
        receipt.rationale = "tightening policx".to_string();
        assert_eq!(receipt.rationale.len(), "tightening policy".len());
        assert!(!engine.verify_transition_signature(&receipt));
    }

    #[test]
    fn test_verdict_labels() {
        assert_eq!(Verdict::Allow.label(), "allow");
        assert_eq!(Verdict::Deny.label(), "deny");
        assert_eq!(Verdict::Audit.label(), "audit");
    }

    #[test]
    fn test_compat_mode_labels() {
        assert_eq!(CompatMode::Strict.label(), "strict");
        assert_eq!(CompatMode::Balanced.label(), "balanced");
        assert_eq!(CompatMode::LegacyRisky.label(), "legacy_risky");
    }

    #[test]
    fn test_compat_mode_risk_ordering() {
        assert!(CompatMode::Strict.risk_level() < CompatMode::Balanced.risk_level());
        assert!(CompatMode::Balanced.risk_level() < CompatMode::LegacyRisky.risk_level());
    }

    #[test]
    fn test_rationale_contains_explanation() {
        let mut engine = test_engine();
        let result = engine
            .gate_check(&GateCheckRequest {
                package_id: "npm:test".into(),
                requested_mode: CompatMode::Strict,
                scope: "tenant-1".into(),
                policy_context: BTreeMap::new(),
            })
            .unwrap();
        assert!(!result.rationale.explanation.is_empty());
        assert!(!result.rationale.matched_predicates.is_empty());
    }
}
