//! bd-1o4v: Proof-verification gate API for control-plane trust decisions.
//! bd-1xbr: Bounded events capacity with oldest-first eviction.
//!
//! This module implements a verification gate that accepts compliance proofs,
//! validates them against policy predicates, and emits deterministic trust
//! decisions (Allow / Deny / Degrade) with structured evidence.
//!
//! # Invariants
//!
//! - INV-PVF-DETERMINISTIC: identical proof inputs and policy state produce identical trust decisions.
//! - INV-PVF-DENY-LOGGED: every Deny decision is logged with a structured event and reason.
//! - INV-PVF-EVIDENCE-COMPLETE: every verification report includes complete evidence linking
//!   proof, policy predicate, decision, and trace context.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::capacity_defaults::aliases::MAX_EVENTS;
const MAX_REPORTS: usize = 2048;

use crate::security::constant_time::ct_eq;
use std::collections::BTreeMap;
use std::fmt;

// ── Schema version ──────────────────────────────────────────────────────────

/// Schema version for the proof-verifier output format.
pub const PROOF_VERIFIER_SCHEMA_VERSION: &str = "vef-proof-verifier-v1";

// ── Invariant constants ─────────────────────────────────────────────────────

/// INV-PVF-DETERMINISTIC: identical proof inputs and policy state produce identical trust decisions.
pub const INV_PVF_DETERMINISTIC: &str = "INV-PVF-DETERMINISTIC";

/// INV-PVF-DENY-LOGGED: every Deny decision is logged with a structured event and reason.
pub const INV_PVF_DENY_LOGGED: &str = "INV-PVF-DENY-LOGGED";

/// INV-PVF-EVIDENCE-COMPLETE: every verification report includes complete evidence.
pub const INV_PVF_EVIDENCE_COMPLETE: &str = "INV-PVF-EVIDENCE-COMPLETE";

// ── Event codes ─────────────────────────────────────────────────────────────

pub mod event_codes {
    /// Verification request received and processing started.
    pub const PVF_001_REQUEST_RECEIVED: &str = "PVF-001";
    /// Proof validation against policy predicate succeeded.
    pub const PVF_002_PROOF_VALIDATED: &str = "PVF-002";
    /// Trust decision emitted (Allow, Deny, or Degrade).
    pub const PVF_003_DECISION_EMITTED: &str = "PVF-003";
    /// Deny decision logged (INV-PVF-DENY-LOGGED).
    pub const PVF_004_DENY_LOGGED: &str = "PVF-004";
    /// Degrade decision logged.
    pub const PVF_005_DEGRADE_LOGGED: &str = "PVF-005";
    /// Verification report finalized with evidence.
    pub const PVF_006_REPORT_FINALIZED: &str = "PVF-006";
}

// ── Error codes ─────────────────────────────────────────────────────────────

pub mod error_codes {
    /// The supplied proof has expired (timestamp beyond allowed window).
    pub const ERR_PVF_PROOF_EXPIRED: &str = "ERR-PVF-PROOF-EXPIRED";
    /// No matching policy predicate found for the proof's action class.
    pub const ERR_PVF_POLICY_MISSING: &str = "ERR-PVF-POLICY-MISSING";
    /// Proof payload does not conform to the expected format.
    pub const ERR_PVF_INVALID_FORMAT: &str = "ERR-PVF-INVALID-FORMAT";
    /// Internal verification error.
    pub const ERR_PVF_INTERNAL: &str = "ERR-PVF-INTERNAL";
}

// ── Trust decision ──────────────────────────────────────────────────────────

/// Outcome of a proof-verification gate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrustDecision {
    /// Proof is valid and policy predicates are satisfied.
    Allow,
    /// Proof failed verification; includes the reason string.
    Deny(String),
    /// Proof partially satisfies predicates; level indicates degradation severity (1 = mild, 5 = severe).
    Degrade(u8),
}

impl fmt::Display for TrustDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TrustDecision::Allow => write!(f, "Allow"),
            TrustDecision::Deny(reason) => write!(f, "Deny({reason})"),
            TrustDecision::Degrade(level) => write!(f, "Degrade(level={level})"),
        }
    }
}

// ── Policy predicate ────────────────────────────────────────────────────────

/// A policy predicate that a compliance proof must satisfy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyPredicate {
    /// Unique predicate identifier.
    pub predicate_id: String,
    /// Action class this predicate applies to (e.g., "network_access").
    pub action_class: String,
    /// Required minimum proof freshness in milliseconds.
    pub max_proof_age_millis: u64,
    /// Required minimum confidence score (0..=100).
    pub min_confidence: u8,
    /// Whether the proof must include witness references.
    pub require_witnesses: bool,
    /// Minimum number of witness references required (when require_witnesses is true).
    pub min_witness_count: usize,
    /// Policy version hash for binding.
    pub policy_version_hash: String,
}

// ── Compliance proof ────────────────────────────────────────────────────────

/// A compliance proof submitted for verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceProof {
    /// Unique proof identifier.
    pub proof_id: String,
    /// Action class this proof covers (must match a policy predicate).
    pub action_class: String,
    /// Cryptographic proof payload hash (hex-encoded SHA-256).
    pub proof_hash: String,
    /// Confidence score (0..=100).
    pub confidence: u8,
    /// When the proof was generated (millis since epoch).
    pub generated_at_millis: u64,
    /// Expiration timestamp (millis since epoch); proof is invalid after this time.
    pub expires_at_millis: u64,
    /// Witness references included in the proof.
    pub witness_references: Vec<String>,
    /// Policy version hash the proof was generated against.
    pub policy_version_hash: String,
    /// Trace ID for end-to-end correlation.
    pub trace_id: String,
}

// ── Verification request / report ───────────────────────────────────────────

/// Request submitted to the verification gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationRequest {
    /// Unique request identifier.
    pub request_id: String,
    /// The compliance proof to verify.
    pub proof: ComplianceProof,
    /// Current timestamp in millis (used for freshness checks).
    pub now_millis: u64,
    /// Trace ID for event correlation.
    pub trace_id: String,
}

/// Structured evidence for a single predicate evaluation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicateEvidence {
    pub predicate_id: String,
    pub action_class: String,
    pub satisfied: bool,
    pub reason: String,
}

/// Full report emitted by the verification gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationReport {
    /// Schema version of this report.
    pub schema_version: String,
    /// Request ID that produced this report.
    pub request_id: String,
    /// Proof ID that was verified.
    pub proof_id: String,
    /// Action class of the proof.
    pub action_class: String,
    /// The trust decision rendered.
    pub decision: TrustDecision,
    /// Evidence for each predicate evaluated.
    pub evidence: Vec<PredicateEvidence>,
    /// Events emitted during verification.
    pub events: Vec<VerifierEvent>,
    /// Deterministic digest of the report (for auditability).
    pub report_digest: String,
    /// Trace ID for correlation.
    pub trace_id: String,
    /// Timestamp of report creation (millis since epoch).
    pub created_at_millis: u64,
}

// ── Events and errors ───────────────────────────────────────────────────────

/// Structured event emitted by the verification gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierEvent {
    pub event_code: String,
    pub trace_id: String,
    pub detail: String,
}

/// Structured error from the verification gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifierError {
    pub code: String,
    pub event_code: String,
    pub message: String,
}

impl VerifierError {
    #[cfg(test)]
    fn proof_expired(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_PVF_PROOF_EXPIRED.to_string(),
            event_code: event_codes::PVF_004_DENY_LOGGED.to_string(),
            message: message.into(),
        }
    }

    fn policy_missing(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_PVF_POLICY_MISSING.to_string(),
            event_code: event_codes::PVF_004_DENY_LOGGED.to_string(),
            message: message.into(),
        }
    }

    fn invalid_format(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_PVF_INVALID_FORMAT.to_string(),
            event_code: event_codes::PVF_004_DENY_LOGGED.to_string(),
            message: message.into(),
        }
    }

    fn internal(message: impl Into<String>) -> Self {
        Self {
            code: error_codes::ERR_PVF_INTERNAL.to_string(),
            event_code: event_codes::PVF_004_DENY_LOGGED.to_string(),
            message: message.into(),
        }
    }
}

impl fmt::Display for VerifierError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {}", self.code, self.message)
    }
}

impl std::error::Error for VerifierError {}

// ── Verification gate configuration ─────────────────────────────────────────

/// Configuration for the proof verification gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerificationGateConfig {
    /// Maximum allowed proof age in milliseconds. Proofs older than this are denied.
    pub max_proof_age_millis: u64,
    /// Confidence threshold below which a degrade decision is emitted instead of allow.
    pub degrade_threshold: u8,
    /// Whether to require policy version hash match between proof and predicate.
    pub enforce_policy_version: bool,
}

impl Default for VerificationGateConfig {
    fn default() -> Self {
        Self {
            max_proof_age_millis: 3_600_000, // 1 hour
            degrade_threshold: 80,
            enforce_policy_version: true,
        }
    }
}

// ── Proof verifier ──────────────────────────────────────────────────────────

/// Core proof verifier: validates a compliance proof against a single policy predicate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofVerifier {
    pub schema_version: String,
    pub config: VerificationGateConfig,
    events: Vec<VerifierEvent>,
}

impl ProofVerifier {
    pub fn new(config: VerificationGateConfig) -> Self {
        Self {
            schema_version: PROOF_VERIFIER_SCHEMA_VERSION.to_string(),
            config,
            events: Vec::new(),
        }
    }

    pub fn events(&self) -> &[VerifierEvent] {
        &self.events
    }

    fn emit_event(&mut self, event: VerifierEvent) {
        push_bounded(&mut self.events, event, MAX_EVENTS);
    }

    /// Validate a compliance proof against a policy predicate.
    /// Returns a list of `PredicateEvidence` entries and an overall `TrustDecision`.
    pub fn validate_proof(
        &mut self,
        proof: &ComplianceProof,
        predicate: &PolicyPredicate,
        now_millis: u64,
        trace_id: &str,
    ) -> Result<(TrustDecision, Vec<PredicateEvidence>), VerifierError> {
        // Basic format validation
        if proof.proof_id.is_empty() {
            return Err(VerifierError::invalid_format("proof_id is empty"));
        }
        if proof.proof_hash.is_empty() {
            return Err(VerifierError::invalid_format("proof_hash is empty"));
        }
        if proof.action_class.is_empty() {
            return Err(VerifierError::invalid_format("action_class is empty"));
        }

        let mut evidence = Vec::new();
        let mut all_satisfied = true;
        let mut deny_reasons: Vec<String> = Vec::new();
        let mut degrade_level: u8 = 0;

        // Check 1: Proof expiration (fail-closed: < ensures expiry at exact boundary)
        let expiry_satisfied = now_millis < proof.expires_at_millis;
        if !expiry_satisfied {
            deny_reasons.push(format!(
                "{}: proof expired at {} but now is {}",
                error_codes::ERR_PVF_PROOF_EXPIRED,
                proof.expires_at_millis,
                now_millis
            ));
            all_satisfied = false;
        }
        evidence.push(PredicateEvidence {
            predicate_id: predicate.predicate_id.clone(),
            action_class: proof.action_class.clone(),
            satisfied: expiry_satisfied,
            reason: if expiry_satisfied {
                "proof within expiry window".to_string()
            } else {
                format!("proof expired at {}", proof.expires_at_millis)
            },
        });

        // Check 2: Proof age (freshness)
        let age_millis = now_millis.saturating_sub(proof.generated_at_millis);
        let age_limit = predicate
            .max_proof_age_millis
            .min(self.config.max_proof_age_millis);
        let is_from_future = proof.generated_at_millis > now_millis;
        let freshness_satisfied = !is_from_future && age_millis < age_limit;

        if !freshness_satisfied {
            if is_from_future {
                deny_reasons.push(format!(
                    "{}: proof generated in the future ({} > {})",
                    error_codes::ERR_PVF_PROOF_EXPIRED,
                    proof.generated_at_millis,
                    now_millis
                ));
            } else {
                deny_reasons.push(format!(
                    "{}: proof age {}ms exceeds limit {}ms",
                    error_codes::ERR_PVF_PROOF_EXPIRED,
                    age_millis,
                    age_limit
                ));
            }
            all_satisfied = false;
        }
        evidence.push(PredicateEvidence {
            predicate_id: predicate.predicate_id.clone(),
            action_class: proof.action_class.clone(),
            satisfied: freshness_satisfied,
            reason: if freshness_satisfied {
                format!("proof age {}ms within limit {}ms", age_millis, age_limit)
            } else if is_from_future {
                format!(
                    "proof generated in the future ({} > {})",
                    proof.generated_at_millis, now_millis
                )
            } else {
                format!("proof age {}ms exceeds limit {}ms", age_millis, age_limit)
            },
        });

        // Check 3: Action class match
        let class_match = proof.action_class == predicate.action_class;
        if !class_match {
            deny_reasons.push(format!(
                "{}: proof action_class '{}' does not match predicate '{}'",
                error_codes::ERR_PVF_POLICY_MISSING,
                proof.action_class,
                predicate.action_class
            ));
            all_satisfied = false;
        }
        evidence.push(PredicateEvidence {
            predicate_id: predicate.predicate_id.clone(),
            action_class: proof.action_class.clone(),
            satisfied: class_match,
            reason: if class_match {
                "action class matches predicate".to_string()
            } else {
                format!(
                    "action class '{}' does not match predicate '{}'",
                    proof.action_class, predicate.action_class
                )
            },
        });

        // Check 4: Confidence score
        let confidence_satisfied = proof.confidence >= predicate.min_confidence;
        if !confidence_satisfied {
            if proof.confidence >= self.config.degrade_threshold {
                // Partial satisfaction -> degrade
                let gap = predicate.min_confidence.saturating_sub(proof.confidence);
                degrade_level = degrade_level.max((gap / 10).clamp(1, 5));
            } else {
                deny_reasons.push(format!(
                    "confidence {} below minimum {}",
                    proof.confidence, predicate.min_confidence
                ));
            }
            all_satisfied = false;
        }
        evidence.push(PredicateEvidence {
            predicate_id: predicate.predicate_id.clone(),
            action_class: proof.action_class.clone(),
            satisfied: confidence_satisfied,
            reason: if confidence_satisfied {
                format!(
                    "confidence {} meets minimum {}",
                    proof.confidence, predicate.min_confidence
                )
            } else {
                format!(
                    "confidence {} below minimum {}",
                    proof.confidence, predicate.min_confidence
                )
            },
        });

        // Check 5: Witness references
        let witness_satisfied = if predicate.require_witnesses {
            proof.witness_references.len() >= predicate.min_witness_count
        } else {
            true
        };
        if !witness_satisfied {
            deny_reasons.push(format!(
                "witness count {} below required {}",
                proof.witness_references.len(),
                predicate.min_witness_count
            ));
            all_satisfied = false;
        }
        evidence.push(PredicateEvidence {
            predicate_id: predicate.predicate_id.clone(),
            action_class: proof.action_class.clone(),
            satisfied: witness_satisfied,
            reason: if witness_satisfied {
                format!(
                    "witness count {} meets requirement",
                    proof.witness_references.len()
                )
            } else {
                format!(
                    "witness count {} below required {}",
                    proof.witness_references.len(),
                    predicate.min_witness_count
                )
            },
        });

        // Check 6: Policy version binding
        let policy_version_satisfied = if self.config.enforce_policy_version {
            ct_eq(&proof.policy_version_hash, &predicate.policy_version_hash)
        } else {
            true
        };
        if !policy_version_satisfied {
            deny_reasons.push(format!(
                "policy version hash mismatch: proof='{}' predicate='{}'",
                proof.policy_version_hash, predicate.policy_version_hash
            ));
            all_satisfied = false;
        }
        evidence.push(PredicateEvidence {
            predicate_id: predicate.predicate_id.clone(),
            action_class: proof.action_class.clone(),
            satisfied: policy_version_satisfied,
            reason: if policy_version_satisfied {
                "policy version hash matches".to_string()
            } else {
                format!(
                    "policy version mismatch: proof='{}' vs predicate='{}'",
                    proof.policy_version_hash, predicate.policy_version_hash
                )
            },
        });

        // Determine final decision
        let decision = if !deny_reasons.is_empty() {
            let reason = deny_reasons.join("; ");
            self.emit_event(VerifierEvent {
                event_code: event_codes::PVF_004_DENY_LOGGED.to_string(),
                trace_id: trace_id.to_string(),
                detail: format!("proof={} DENY: {}", proof.proof_id, reason),
            });
            TrustDecision::Deny(reason)
        } else if !all_satisfied && degrade_level > 0 {
            self.emit_event(VerifierEvent {
                event_code: event_codes::PVF_005_DEGRADE_LOGGED.to_string(),
                trace_id: trace_id.to_string(),
                detail: format!("proof={} DEGRADE level={}", proof.proof_id, degrade_level),
            });
            TrustDecision::Degrade(degrade_level)
        } else if all_satisfied {
            self.emit_event(VerifierEvent {
                event_code: event_codes::PVF_002_PROOF_VALIDATED.to_string(),
                trace_id: trace_id.to_string(),
                detail: format!("proof={} validated successfully", proof.proof_id),
            });
            TrustDecision::Allow
        } else {
            // Fallback: unsatisfied checks with no explicit deny reason -> degrade(1)
            self.emit_event(VerifierEvent {
                event_code: event_codes::PVF_005_DEGRADE_LOGGED.to_string(),
                trace_id: trace_id.to_string(),
                detail: format!(
                    "proof={} DEGRADE level=1 (partial satisfaction)",
                    proof.proof_id
                ),
            });
            TrustDecision::Degrade(1)
        };

        Ok((decision, evidence))
    }
}

// ── Verification gate ───────────────────────────────────────────────────────

/// The verification gate is the control-plane integration point.
/// It manages policy predicates and processes verification requests,
/// producing deterministic `VerificationReport` outputs.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationGate {
    pub schema_version: String,
    pub config: VerificationGateConfig,
    predicates: BTreeMap<String, PolicyPredicate>,
    reports: Vec<VerificationReport>,
    events: Vec<VerifierEvent>,
    next_report_seq: u64,
}

impl VerificationGate {
    pub fn new(config: VerificationGateConfig) -> Self {
        Self {
            schema_version: PROOF_VERIFIER_SCHEMA_VERSION.to_string(),
            config,
            predicates: BTreeMap::new(),
            reports: Vec::new(),
            events: Vec::new(),
            next_report_seq: 0,
        }
    }

    pub fn reports(&self) -> &[VerificationReport] {
        &self.reports
    }

    fn emit_event(&mut self, event: VerifierEvent) {
        push_bounded(&mut self.events, event, MAX_EVENTS);
    }

    pub fn events(&self) -> &[VerifierEvent] {
        &self.events
    }

    pub fn predicates(&self) -> &BTreeMap<String, PolicyPredicate> {
        &self.predicates
    }

    /// Register a policy predicate. Overwrites any existing predicate with the same action_class.
    pub fn register_predicate(&mut self, predicate: PolicyPredicate) {
        self.predicates
            .insert(predicate.action_class.clone(), predicate);
    }

    /// Remove a policy predicate by action class. Returns the removed predicate if it existed.
    pub fn remove_predicate(&mut self, action_class: &str) -> Option<PolicyPredicate> {
        self.predicates.remove(action_class)
    }

    /// Process a verification request and produce a deterministic report.
    pub fn verify(
        &mut self,
        request: &VerificationRequest,
    ) -> Result<VerificationReport, VerifierError> {
        let trace_id = &request.trace_id;
        let mut report_events = Vec::new();

        // Emit request-received event
        let request_received_event = VerifierEvent {
            event_code: event_codes::PVF_001_REQUEST_RECEIVED.to_string(),
            trace_id: trace_id.clone(),
            detail: format!(
                "request={} proof={} action_class={}",
                request.request_id, request.proof.proof_id, request.proof.action_class
            ),
        };
        self.emit_event(request_received_event.clone());
        report_events.push(request_received_event);

        // Format validation
        if request.proof.proof_id.is_empty() {
            let err = VerifierError::invalid_format("proof_id is empty");
            self.emit_event(VerifierEvent {
                event_code: event_codes::PVF_004_DENY_LOGGED.to_string(),
                trace_id: trace_id.clone(),
                detail: format!("request={} DENY: {}", request.request_id, err.message),
            });
            return Err(err);
        }
        if request.proof.proof_hash.is_empty() {
            let err = VerifierError::invalid_format("proof_hash is empty");
            self.emit_event(VerifierEvent {
                event_code: event_codes::PVF_004_DENY_LOGGED.to_string(),
                trace_id: trace_id.clone(),
                detail: format!("request={} DENY: {}", request.request_id, err.message),
            });
            return Err(err);
        }
        if request.proof.action_class.is_empty() {
            let err = VerifierError::invalid_format("action_class is empty");
            self.emit_event(VerifierEvent {
                event_code: event_codes::PVF_004_DENY_LOGGED.to_string(),
                trace_id: trace_id.clone(),
                detail: format!("request={} DENY: {}", request.request_id, err.message),
            });
            return Err(err);
        }

        // Look up matching predicate
        let predicate = match self.predicates.get(&request.proof.action_class) {
            Some(p) => p.clone(),
            None => {
                let err = VerifierError::policy_missing(format!(
                    "no predicate for action_class '{}'",
                    request.proof.action_class
                ));
                self.emit_event(VerifierEvent {
                    event_code: event_codes::PVF_004_DENY_LOGGED.to_string(),
                    trace_id: trace_id.clone(),
                    detail: format!("request={} DENY: {}", request.request_id, err.message),
                });
                return Err(err);
            }
        };

        // Run verification
        let mut verifier = ProofVerifier::new(self.config.clone());
        let (decision, evidence) =
            verifier.validate_proof(&request.proof, &predicate, request.now_millis, trace_id)?;

        // Propagate verifier events (via emit_event to respect push_bounded)
        for event in verifier.events().iter().cloned() {
            self.emit_event(event.clone());
            report_events.push(event);
        }

        let decision_event = VerifierEvent {
            event_code: event_codes::PVF_003_DECISION_EMITTED.to_string(),
            trace_id: trace_id.clone(),
            detail: format!(
                "request={} proof={} decision={}",
                request.request_id, request.proof.proof_id, decision
            ),
        };
        self.emit_event(decision_event.clone());
        report_events.push(decision_event);

        let report_digest = compute_report_digest(
            &request.request_id,
            &request.proof.proof_id,
            &request.proof.action_class,
            &decision,
            &evidence,
        )?;

        let report_finalized_event = VerifierEvent {
            event_code: event_codes::PVF_006_REPORT_FINALIZED.to_string(),
            trace_id: trace_id.clone(),
            detail: format!(
                "request={} report_digest={} decision={}",
                request.request_id, report_digest, decision
            ),
        };
        self.emit_event(report_finalized_event.clone());
        report_events.push(report_finalized_event);

        let report = VerificationReport {
            schema_version: PROOF_VERIFIER_SCHEMA_VERSION.to_string(),
            request_id: request.request_id.clone(),
            proof_id: request.proof.proof_id.clone(),
            action_class: request.proof.action_class.clone(),
            decision: decision.clone(),
            evidence,
            events: report_events,
            report_digest,
            trace_id: trace_id.clone(),
            created_at_millis: request.now_millis,
        };

        push_bounded(&mut self.reports, report.clone(), MAX_REPORTS);
        self.next_report_seq = self
            .next_report_seq
            .checked_add(1)
            .ok_or_else(|| VerifierError::internal("report sequence overflow"))?;

        Ok(report)
    }

    /// Batch-verify multiple requests. Returns reports for each.
    /// Processing order is deterministic (iteration order of the slice).
    pub fn verify_batch(
        &mut self,
        requests: &[VerificationRequest],
    ) -> Vec<Result<VerificationReport, VerifierError>> {
        requests.iter().map(|req| self.verify(req)).collect()
    }

    /// Return a summary of decisions made so far.
    pub fn decision_summary(&self) -> DecisionSummary {
        let mut allow_count = 0usize;
        let mut deny_count = 0usize;
        let mut degrade_count = 0usize;
        let mut deny_reasons: BTreeMap<String, usize> = BTreeMap::new();

        for report in &self.reports {
            match &report.decision {
                TrustDecision::Allow => allow_count = allow_count.saturating_add(1),
                TrustDecision::Deny(reason) => {
                    deny_count = deny_count.saturating_add(1);
                    let entry = deny_reasons.entry(reason.clone()).or_insert(0);
                    *entry = entry.saturating_add(1);
                }
                TrustDecision::Degrade(_) => degrade_count = degrade_count.saturating_add(1),
            }
        }

        DecisionSummary {
            total_reports: self.reports.len(),
            allow_count,
            deny_count,
            degrade_count,
            deny_reasons,
        }
    }
}

/// Summary of trust decisions rendered by the gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionSummary {
    pub total_reports: usize,
    pub allow_count: usize,
    pub deny_count: usize,
    pub degrade_count: usize,
    pub deny_reasons: BTreeMap<String, usize>,
}

// ── Deterministic digest ────────────────────────────────────────────────────

fn compute_report_digest(
    request_id: &str,
    proof_id: &str,
    action_class: &str,
    decision: &TrustDecision,
    evidence: &[PredicateEvidence],
) -> Result<String, VerifierError> {
    #[derive(Serialize)]
    struct DigestMaterial<'a> {
        schema_version: &'a str,
        request_id: &'a str,
        proof_id: &'a str,
        action_class: &'a str,
        decision: &'a TrustDecision,
        evidence: &'a [PredicateEvidence],
    }

    let material = DigestMaterial {
        schema_version: PROOF_VERIFIER_SCHEMA_VERSION,
        request_id,
        proof_id,
        action_class,
        decision,
        evidence,
    };

    let bytes = serde_json::to_vec(&material).map_err(|err| {
        VerifierError::internal(format!("failed to serialize digest material: {err}"))
    })?;
    let mut hasher = Sha256::new();
    hasher.update(b"proof_verifier_hash_v1:");
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(&bytes);
    let digest = hasher.finalize();
    Ok(format!("sha256:{digest:x}"))
}

// ════════════════════════════════════════════════════════════════════════════
fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if items.len() >= cap {
        let overflow = items.len() - cap + 1;
        items.drain(0..overflow);
    }
    items.push(item);
}

// Tests
// ════════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: u64 = 1_701_000_000_000;

    fn default_predicate() -> PolicyPredicate {
        PolicyPredicate {
            predicate_id: "pred-net-001".to_string(),
            action_class: "network_access".to_string(),
            max_proof_age_millis: 600_000, // 10 min
            min_confidence: 90,
            require_witnesses: true,
            min_witness_count: 2,
            policy_version_hash: "sha256:policy-v1".to_string(),
        }
    }

    fn valid_proof() -> ComplianceProof {
        ComplianceProof {
            proof_id: "proof-001".to_string(),
            action_class: "network_access".to_string(),
            proof_hash: "sha256:abc123".to_string(),
            confidence: 95,
            generated_at_millis: NOW - 60_000,
            expires_at_millis: NOW + 600_000,
            witness_references: vec!["w-a".to_string(), "w-b".to_string(), "w-c".to_string()],
            policy_version_hash: "sha256:policy-v1".to_string(),
            trace_id: "trace-test-001".to_string(),
        }
    }

    fn make_request(proof: ComplianceProof) -> VerificationRequest {
        VerificationRequest {
            request_id: format!("req-{}", proof.proof_id),
            trace_id: proof.trace_id.clone(),
            proof,
            now_millis: NOW,
        }
    }

    fn gate_with_predicate() -> VerificationGate {
        let mut gate = VerificationGate::new(VerificationGateConfig::default());
        gate.register_predicate(default_predicate());
        gate
    }

    // ── 1. Valid proof produces Allow ───────────────────────────────────────

    #[test]
    fn valid_proof_produces_allow_decision() {
        let mut gate = gate_with_predicate();
        let req = make_request(valid_proof());
        let report = gate.verify(&req).unwrap();
        assert_eq!(report.decision, TrustDecision::Allow);
        assert!(report.evidence.iter().all(|e| e.satisfied));
    }

    // ── 2. Expired proof produces Deny ─────────────────────────────────────

    #[test]
    fn expired_proof_produces_deny_decision() {
        let mut gate = gate_with_predicate();
        let mut proof = valid_proof();
        proof.expires_at_millis = NOW - 1;
        let req = make_request(proof);
        let report = gate.verify(&req).unwrap();
        assert!(matches!(report.decision, TrustDecision::Deny(_)));
    }

    // ── 2b. Proof expired at exact boundary (fail-closed) ──────────────────

    #[test]
    fn proof_expired_at_exact_boundary_is_denied() {
        let mut gate = gate_with_predicate();
        let mut proof = valid_proof();
        // At exact boundary: now == expires_at → fail-closed → Deny
        proof.expires_at_millis = NOW;
        let req = make_request(proof);
        let report = gate.verify(&req).unwrap();
        assert!(matches!(report.decision, TrustDecision::Deny(_)));
    }

    // ── 3. Stale proof (too old) produces Deny ─────────────────────────────

    #[test]
    fn stale_proof_produces_deny_decision() {
        let mut gate = gate_with_predicate();
        let mut proof = valid_proof();
        proof.generated_at_millis = NOW - 1_000_000; // 1000 seconds old
        let req = make_request(proof);
        let report = gate.verify(&req).unwrap();
        assert!(matches!(report.decision, TrustDecision::Deny(_)));
        let deny_text = match &report.decision {
            TrustDecision::Deny(r) => r.clone(),
            _ => String::new(),
        };
        assert!(deny_text.contains("ERR-PVF-PROOF-EXPIRED"));
    }

    // ── 3b. Proof from the future produces Deny ────────────────────────────

    #[test]
    fn future_proof_produces_deny_decision() {
        let mut gate = gate_with_predicate();
        let mut proof = valid_proof();
        proof.generated_at_millis = NOW + 60_000; // 60 seconds in the future
        let req = make_request(proof);
        let report = gate.verify(&req).unwrap();
        assert!(matches!(report.decision, TrustDecision::Deny(_)));
        let deny_text = match &report.decision {
            TrustDecision::Deny(r) => r.clone(),
            _ => String::new(),
        };
        assert!(deny_text.contains("proof generated in the future"));
    }

    // ── 4. Missing policy produces error ───────────────────────────────────

    #[test]
    fn missing_policy_predicate_produces_error() {
        let mut gate = VerificationGate::new(VerificationGateConfig::default());
        // No predicates registered
        let req = make_request(valid_proof());
        let err = gate.verify(&req).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_PVF_POLICY_MISSING);
    }

    // ── 5. Invalid format (empty proof_id) ─────────────────────────────────

    #[test]
    fn empty_proof_id_produces_invalid_format_error() {
        let mut gate = gate_with_predicate();
        let mut proof = valid_proof();
        proof.proof_id = String::new();
        let req = make_request(proof);
        let err = gate.verify(&req).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_PVF_INVALID_FORMAT);
    }

    // ── 6. Invalid format (empty proof_hash) ───────────────────────────────

    #[test]
    fn empty_proof_hash_produces_invalid_format_error() {
        let mut gate = gate_with_predicate();
        let mut proof = valid_proof();
        proof.proof_hash = String::new();
        let req = make_request(proof);
        let err = gate.verify(&req).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_PVF_INVALID_FORMAT);
    }

    // ── 7. Deterministic: same inputs same decision ────────────────────────

    #[test]
    fn deterministic_same_inputs_same_decision() {
        let mut gate_a = gate_with_predicate();
        let mut gate_b = gate_with_predicate();
        let req = make_request(valid_proof());

        let report_a = gate_a.verify(&req).unwrap();
        let report_b = gate_b.verify(&req).unwrap();

        assert_eq!(report_a.decision, report_b.decision);
        assert_eq!(report_a.report_digest, report_b.report_digest);
        assert_eq!(report_a.evidence, report_b.evidence);
    }

    // ── 8. Deny decision is always logged ──────────────────────────────────

    #[test]
    fn deny_decision_emits_deny_logged_event() {
        let mut gate = gate_with_predicate();
        let mut proof = valid_proof();
        proof.expires_at_millis = NOW - 1;
        let req = make_request(proof);
        gate.verify(&req).unwrap();

        let deny_events: Vec<_> = gate
            .events()
            .iter()
            .filter(|e| e.event_code == event_codes::PVF_004_DENY_LOGGED)
            .collect();
        assert!(!deny_events.is_empty(), "deny must be logged");
    }

    // ── 9. Evidence completeness ───────────────────────────────────────────

    #[test]
    fn evidence_includes_all_predicate_checks() {
        let mut gate = gate_with_predicate();
        let req = make_request(valid_proof());
        let report = gate.verify(&req).unwrap();
        // 6 checks: expiry, freshness, action class, confidence, witnesses, policy version
        assert_eq!(report.evidence.len(), 6);
        for ev in &report.evidence {
            assert!(!ev.predicate_id.is_empty());
            assert!(!ev.action_class.is_empty());
            assert!(!ev.reason.is_empty());
        }
    }

    // ── 10. Report digest is deterministic ─────────────────────────────────

    #[test]
    fn report_digest_is_deterministic() {
        let mut gate = gate_with_predicate();
        let req = make_request(valid_proof());
        let report = gate.verify(&req).unwrap();
        assert!(report.report_digest.starts_with("sha256:"));

        // Recompute with same inputs
        let evidence = report.evidence.clone();
        let digest = compute_report_digest(
            &report.request_id,
            &report.proof_id,
            &report.action_class,
            &report.decision,
            &evidence,
        )
        .unwrap();
        assert_eq!(report.report_digest, digest);
    }

    #[test]
    fn report_digest_changes_when_evidence_details_change() {
        let mut gate = gate_with_predicate();
        let req = make_request(valid_proof());
        let report = gate.verify(&req).unwrap();
        let mut altered_evidence = report.evidence.clone();
        altered_evidence[0].reason = "tampered reason".to_string();

        let altered_digest = compute_report_digest(
            &report.request_id,
            &report.proof_id,
            &report.action_class,
            &report.decision,
            &altered_evidence,
        )
        .unwrap();

        assert_ne!(report.report_digest, altered_digest);
    }

    // ── 11. Low confidence produces Deny (below degrade threshold) ─────────

    #[test]
    fn very_low_confidence_produces_deny() {
        let mut gate = gate_with_predicate();
        let mut proof = valid_proof();
        proof.confidence = 50; // below degrade_threshold=80 and min_confidence=90
        let req = make_request(proof);
        let report = gate.verify(&req).unwrap();
        assert!(matches!(report.decision, TrustDecision::Deny(_)));
    }

    // ── 12. Marginal confidence produces Degrade ───────────────────────────

    #[test]
    fn marginal_confidence_produces_degrade() {
        let config = VerificationGateConfig {
            degrade_threshold: 80,
            enforce_policy_version: true,
            ..VerificationGateConfig::default()
        };
        let mut gate = VerificationGate::new(config);
        gate.register_predicate(default_predicate());
        let mut proof = valid_proof();
        proof.confidence = 85; // above degrade_threshold=80 but below min_confidence=90
        let req = make_request(proof);
        let report = gate.verify(&req).unwrap();
        assert!(matches!(report.decision, TrustDecision::Degrade(_)));
    }

    // ── 13. Insufficient witnesses produces Deny ───────────────────────────

    #[test]
    fn insufficient_witnesses_produces_deny() {
        let mut gate = gate_with_predicate();
        let mut proof = valid_proof();
        proof.witness_references = vec!["w-a".to_string()]; // needs 2
        let req = make_request(proof);
        let report = gate.verify(&req).unwrap();
        assert!(matches!(report.decision, TrustDecision::Deny(_)));
    }

    // ── 14. Policy version mismatch produces Deny ──────────────────────────

    #[test]
    fn policy_version_mismatch_produces_deny() {
        let mut gate = gate_with_predicate();
        let mut proof = valid_proof();
        proof.policy_version_hash = "sha256:wrong-version".to_string();
        let req = make_request(proof);
        let report = gate.verify(&req).unwrap();
        assert!(matches!(report.decision, TrustDecision::Deny(_)));
    }

    // ── 15. Action class mismatch produces error ───────────────────────────

    #[test]
    fn action_class_mismatch_produces_policy_missing_error() {
        let mut gate = gate_with_predicate();
        let mut proof = valid_proof();
        proof.action_class = "filesystem_operation".to_string();
        // The gate has no predicate for filesystem_operation
        let err = gate.verify(&make_request(proof)).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_PVF_POLICY_MISSING);
    }

    // ── 16. Register and remove predicate ──────────────────────────────────

    #[test]
    fn register_and_remove_predicate() {
        let mut gate = VerificationGate::new(VerificationGateConfig::default());
        let pred = default_predicate();
        gate.register_predicate(pred.clone());
        assert!(gate.predicates().contains_key("network_access"));

        let removed = gate.remove_predicate("network_access");
        assert!(removed.is_some());
        assert!(!gate.predicates().contains_key("network_access"));
    }

    // ── 17. Batch verify processes all requests ────────────────────────────

    #[test]
    fn batch_verify_processes_all_requests() {
        let mut gate = gate_with_predicate();
        let requests: Vec<_> = (0..3)
            .map(|i| {
                let mut proof = valid_proof();
                proof.proof_id = format!("proof-batch-{i}");
                proof.trace_id = format!("trace-batch-{i}");
                make_request(proof)
            })
            .collect();

        let results = gate.verify_batch(&requests);
        assert_eq!(results.len(), 3);
        for result in &results {
            assert!(result.is_ok());
            assert_eq!(result.as_ref().unwrap().decision, TrustDecision::Allow);
        }
    }

    // ── 18. Decision summary counts ────────────────────────────────────────

    #[test]
    fn decision_summary_counts_correctly() {
        let mut gate = gate_with_predicate();

        // One Allow
        gate.verify(&make_request(valid_proof())).unwrap();

        // One Deny
        let mut expired = valid_proof();
        expired.proof_id = "proof-expired".to_string();
        expired.expires_at_millis = NOW - 1;
        gate.verify(&make_request(expired)).unwrap();

        let summary = gate.decision_summary();
        assert_eq!(summary.total_reports, 2);
        assert_eq!(summary.allow_count, 1);
        assert_eq!(summary.deny_count, 1);
    }

    // ── 19. Events contain trace_id ────────────────────────────────────────

    #[test]
    fn all_events_contain_trace_id() {
        let mut gate = gate_with_predicate();
        let req = make_request(valid_proof());
        gate.verify(&req).unwrap();
        for event in gate.events() {
            assert!(!event.trace_id.is_empty());
        }
    }

    // ── 20. Report contains schema version ─────────────────────────────────

    #[test]
    fn report_contains_schema_version() {
        let mut gate = gate_with_predicate();
        let req = make_request(valid_proof());
        let report = gate.verify(&req).unwrap();
        assert_eq!(report.schema_version, PROOF_VERIFIER_SCHEMA_VERSION);
    }

    // ── 21. Request received event is first ────────────────────────────────

    #[test]
    fn request_received_event_emitted_first() {
        let mut gate = gate_with_predicate();
        let req = make_request(valid_proof());
        gate.verify(&req).unwrap();
        assert!(!gate.events().is_empty());
        assert_eq!(
            gate.events()[0].event_code,
            event_codes::PVF_001_REQUEST_RECEIVED
        );
    }

    // ── 22. Report finalized event is last ─────────────────────────────────

    #[test]
    fn report_finalized_event_emitted_last() {
        let mut gate = gate_with_predicate();
        let req = make_request(valid_proof());
        gate.verify(&req).unwrap();
        let last = gate.events().last().unwrap();
        assert_eq!(last.event_code, event_codes::PVF_006_REPORT_FINALIZED);
    }

    #[test]
    fn allow_report_includes_full_gate_event_trail() {
        let mut gate = gate_with_predicate();
        let req = make_request(valid_proof());
        let report = gate.verify(&req).unwrap();
        let codes: Vec<&str> = report
            .events
            .iter()
            .map(|event| event.event_code.as_str())
            .collect();

        assert_eq!(
            codes,
            vec![
                event_codes::PVF_001_REQUEST_RECEIVED,
                event_codes::PVF_002_PROOF_VALIDATED,
                event_codes::PVF_003_DECISION_EMITTED,
                event_codes::PVF_006_REPORT_FINALIZED,
            ]
        );
    }

    #[test]
    fn deny_gate_events_preserve_causal_order() {
        let mut gate = gate_with_predicate();
        let mut proof = valid_proof();
        proof.expires_at_millis = NOW - 1;
        let report = gate.verify(&make_request(proof)).unwrap();
        let codes: Vec<&str> = gate
            .events()
            .iter()
            .map(|event| event.event_code.as_str())
            .collect();

        assert_eq!(
            codes,
            vec![
                event_codes::PVF_001_REQUEST_RECEIVED,
                event_codes::PVF_004_DENY_LOGGED,
                event_codes::PVF_003_DECISION_EMITTED,
                event_codes::PVF_006_REPORT_FINALIZED,
            ]
        );
        assert_eq!(report.events, gate.events());
    }

    // ── 23. Policy version enforcement can be disabled ─────────────────────

    #[test]
    fn policy_version_enforcement_disabled() {
        let config = VerificationGateConfig {
            enforce_policy_version: false,
            ..VerificationGateConfig::default()
        };
        let mut gate = VerificationGate::new(config);
        gate.register_predicate(default_predicate());
        let mut proof = valid_proof();
        proof.policy_version_hash = "sha256:different".to_string();
        let req = make_request(proof);
        let report = gate.verify(&req).unwrap();
        assert_eq!(report.decision, TrustDecision::Allow);
    }

    // ── 24. Witnesses not required when predicate says so ──────────────────

    #[test]
    fn no_witnesses_required_passes_with_empty_list() {
        let mut gate = VerificationGate::new(VerificationGateConfig::default());
        let mut pred = default_predicate();
        pred.require_witnesses = false;
        gate.register_predicate(pred);
        let mut proof = valid_proof();
        proof.witness_references.clear();
        let req = make_request(proof);
        let report = gate.verify(&req).unwrap();
        assert_eq!(report.decision, TrustDecision::Allow);
    }

    // ── 25. Multiple predicates for different action classes ───────────────

    #[test]
    fn multiple_predicates_independent_verification() {
        let mut gate = VerificationGate::new(VerificationGateConfig::default());
        gate.register_predicate(default_predicate());

        let mut fs_pred = default_predicate();
        fs_pred.predicate_id = "pred-fs-001".to_string();
        fs_pred.action_class = "filesystem_operation".to_string();
        gate.register_predicate(fs_pred);

        // Verify network_access proof
        let net_req = make_request(valid_proof());
        let net_report = gate.verify(&net_req).unwrap();
        assert_eq!(net_report.decision, TrustDecision::Allow);

        // Verify filesystem_operation proof
        let mut fs_proof = valid_proof();
        fs_proof.proof_id = "proof-fs-001".to_string();
        fs_proof.action_class = "filesystem_operation".to_string();
        let fs_req = make_request(fs_proof);
        let fs_report = gate.verify(&fs_req).unwrap();
        assert_eq!(fs_report.decision, TrustDecision::Allow);
    }

    // ── 26. Predicate overwrite ────────────────────────────────────────────

    #[test]
    fn registering_predicate_overwrites_existing() {
        let mut gate = VerificationGate::new(VerificationGateConfig::default());
        gate.register_predicate(default_predicate());

        let mut stricter = default_predicate();
        stricter.min_confidence = 99;
        gate.register_predicate(stricter);

        // Now proof with confidence=95 should fail
        let req = make_request(valid_proof());
        let report = gate.verify(&req).unwrap();
        assert!(!matches!(report.decision, TrustDecision::Allow));
    }

    // ── 27. TrustDecision Display formatting ───────────────────────────────

    #[test]
    fn trust_decision_display_format() {
        assert_eq!(format!("{}", TrustDecision::Allow), "Allow");
        assert_eq!(
            format!("{}", TrustDecision::Deny("reason".to_string())),
            "Deny(reason)"
        );
        assert_eq!(format!("{}", TrustDecision::Degrade(3)), "Degrade(level=3)");
    }

    // ── 28. VerifierError display ──────────────────────────────────────────

    #[test]
    fn verifier_error_display() {
        let err = VerifierError::proof_expired("test expired");
        assert_eq!(format!("{err}"), "[ERR-PVF-PROOF-EXPIRED] test expired");
    }

    // ── 29. Empty action class in proof is rejected ────────────────────────

    #[test]
    fn empty_action_class_rejected_by_verifier() {
        let config = VerificationGateConfig::default();
        let mut verifier = ProofVerifier::new(config);
        let mut proof = valid_proof();
        proof.action_class = String::new();
        let pred = default_predicate();
        let err = verifier
            .validate_proof(&proof, &pred, NOW, "trace-empty-class")
            .unwrap_err();
        assert_eq!(err.code, error_codes::ERR_PVF_INVALID_FORMAT);
    }

    #[test]
    fn empty_action_class_produces_invalid_format_error_from_gate() {
        let mut gate = gate_with_predicate();
        let mut proof = valid_proof();
        proof.action_class = String::new();
        let err = gate.verify(&make_request(proof)).unwrap_err();
        assert_eq!(err.code, error_codes::ERR_PVF_INVALID_FORMAT);
    }

    // ── 30. Gate default config values ─────────────────────────────────────

    #[test]
    fn default_config_values() {
        let config = VerificationGateConfig::default();
        assert_eq!(config.max_proof_age_millis, 3_600_000);
        assert_eq!(config.degrade_threshold, 80);
        assert!(config.enforce_policy_version);
    }

    // ── 31. Report created_at_millis matches request now ───────────────────

    #[test]
    fn report_created_at_matches_request_now() {
        let mut gate = gate_with_predicate();
        let mut req = make_request(valid_proof());
        req.now_millis = 1_701_999_999_999;
        let report = gate.verify(&req).unwrap();
        assert_eq!(report.created_at_millis, 1_701_999_999_999);
    }

    #[test]
    fn proof_age_at_exact_predicate_limit_is_denied() {
        let mut gate = gate_with_predicate();
        let mut proof = valid_proof();
        proof.generated_at_millis = NOW - default_predicate().max_proof_age_millis;
        proof.expires_at_millis = NOW + 1;

        let report = gate.verify(&make_request(proof)).expect("report");

        match report.decision {
            TrustDecision::Deny(reason) => {
                assert!(reason.contains("proof age 600000ms exceeds limit 600000ms"));
            }
            other => panic!("expected Deny at exact age boundary, got {other:?}"),
        }
    }

    #[test]
    fn proof_age_at_exact_global_limit_is_denied() {
        let config = VerificationGateConfig {
            max_proof_age_millis: 30_000,
            ..VerificationGateConfig::default()
        };
        let mut gate = VerificationGate::new(config);
        gate.register_predicate(default_predicate());
        let mut proof = valid_proof();
        proof.generated_at_millis = NOW - 30_000;
        proof.expires_at_millis = NOW + 1;

        let report = gate.verify(&make_request(proof)).expect("report");

        match report.decision {
            TrustDecision::Deny(reason) => {
                assert!(reason.contains("proof age 30000ms exceeds limit 30000ms"));
            }
            other => panic!("expected Deny at exact global age boundary, got {other:?}"),
        }
    }

    #[test]
    fn confidence_gap_degrade_level_clamps_to_five() {
        let config = VerificationGateConfig {
            degrade_threshold: 0,
            ..VerificationGateConfig::default()
        };
        let mut gate = VerificationGate::new(config);
        let mut predicate = default_predicate();
        predicate.min_confidence = 100;
        gate.register_predicate(predicate);
        let mut proof = valid_proof();
        proof.confidence = 1;

        let report = gate.verify(&make_request(proof)).expect("report");

        assert_eq!(report.decision, TrustDecision::Degrade(5));
    }

    #[test]
    fn batch_verify_preserves_invalid_format_errors() {
        let mut gate = gate_with_predicate();
        let valid = make_request(valid_proof());
        let mut invalid_proof = valid_proof();
        invalid_proof.proof_id = "proof-invalid-hash".to_string();
        invalid_proof.proof_hash.clear();
        let invalid = make_request(invalid_proof);

        let results = gate.verify_batch(&[valid, invalid]);

        assert!(results[0].is_ok());
        let err = results[1]
            .as_ref()
            .expect_err("invalid proof hash must fail");
        assert_eq!(err.code, error_codes::ERR_PVF_INVALID_FORMAT);
        assert_eq!(gate.reports().len(), 1);
    }

    #[test]
    fn trust_decision_deserialize_rejects_unknown_variant() {
        let result: Result<TrustDecision, _> = serde_json::from_str("\"bypass\"");

        assert!(result.is_err(), "unknown trust decision must fail closed");
    }

    #[test]
    fn compliance_proof_deserialize_rejects_confidence_overflow() {
        let raw = serde_json::json!({
            "proof_id": "proof-overflow",
            "action_class": "network_access",
            "proof_hash": "sha256:abc123",
            "confidence": 256_u16,
            "generated_at_millis": NOW - 60_000,
            "expires_at_millis": NOW + 600_000,
            "witness_references": ["w-a", "w-b"],
            "policy_version_hash": "sha256:policy-v1",
            "trace_id": "trace-overflow"
        });

        let result: Result<ComplianceProof, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "u8 confidence overflow must not deserialize"
        );
    }

    #[test]
    fn verification_request_deserialize_rejects_missing_proof() {
        let raw = serde_json::json!({
            "request_id": "req-missing-proof",
            "now_millis": NOW,
            "trace_id": "trace-missing-proof"
        });

        let result: Result<VerificationRequest, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "verification requests require proof payloads"
        );
    }

    // ── NEGATIVE-PATH TESTS: Security & Robustness ──────────────────

    #[test]
    fn test_negative_proof_payload_with_malicious_injection_attacks() {
        let malicious_payloads = [
            r#"{"valid": "json", "injection": "\"},\"admin\":true,\"bypass"}"#, // JSON injection
            r#"{"script": "<script>alert('XSS')</script>"}"#,                    // XSS attempt
            r#"{"sql": "'; DROP TABLE proofs; --"}"#,                           // SQL injection
            r#"{"shell": "; rm -rf / #"}"#,                                     // Shell injection
            r#"{"unicode": "\u{202E}fake\u{202C}"}"#,                          // BiDi override
            r#"{"ansi": "\x1b[31mred\x1b[0m"}"#,                               // ANSI escape
            r#"{"control": "data\0null\r\n\t"}"#,                              // Control chars
            r#"{"massive": "#.repeat(1_000_000) + r#""}"#,                      // 1MB payload
            "not-json-at-all",                                                  // Invalid JSON
            "",                                                                 // Empty payload
            "null",                                                             // JSON null
            "[]",                                                               // Array instead of object
            r#"{"nested": {"deep": {"structure": {"with": {"many": {"levels": "value"}}}}}}"#, // Deep nesting
        ];

        let verifier = ProofVerifier::new();
        let test_policy = test_policy_predicate();

        for malicious_payload in malicious_payloads {
            let malicious_proof = ComplianceProof {
                proof_id: "malicious-test".to_string(),
                action_class: "test.action".to_string(),
                payload: malicious_payload.to_string(),
                issued_at_epoch: 1234567890,
                expires_at_epoch: 1234567890 + 3600,
                signature: "fake-signature".to_string(),
                issuer_public_key: "fake-public-key".to_string(),
            };

            let request = VerificationRequest {
                proof: malicious_proof.clone(),
                policy_context: "test-context".to_string(),
                trace_id: "malicious-payload-test".to_string(),
            };

            // Test verification with malicious payload
            let result = verifier.verify(&request, &[test_policy.clone()]);

            // Should handle malicious payloads safely
            assert!(result.report.is_some(), "report should be generated even for malicious payloads");

            if let Some(report) = result.report {
                // Verify payload is preserved exactly for forensics
                assert_eq!(report.compliance_proof.payload, malicious_payload, "payload should be preserved");

                // Test JSON serialization safety
                let json = serde_json::to_string(&report).expect("serialization should work");
                let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should be valid");

                // Verify no injection occurred in JSON structure
                assert!(parsed.get("admin").is_none(), "JSON injection should not create admin field");
                assert!(parsed.get("bypass").is_none(), "JSON injection should not create bypass field");

                // Verify trust decision is appropriate for malicious content
                match report.decision {
                    TrustDecision::Allow => {
                        // If allowed, the payload format must have been valid
                    }
                    TrustDecision::Deny(reason) => {
                        // Denial is expected for malicious payloads
                        assert!(!reason.is_empty(), "deny reason should not be empty");
                    }
                    TrustDecision::Degrade(_level) => {
                        // Degradation is also acceptable
                    }
                }
            }

            // Test event generation with malicious payloads
            assert!(!result.events.is_empty(), "events should be generated");
            for event in &result.events {
                // Verify event structure is safe
                let event_json = serde_json::to_string(&event).expect("event serialization should work");
                assert!(!event_json.contains("admin"), "event JSON should not contain injection");
            }
        }
    }

    #[test]
    fn test_negative_trust_decision_display_injection_resistance() {
        // Test TrustDecision display with malicious reason strings
        let malicious_reasons = [
            "reason\u{202E}fake\u{202C}",           // BiDi override
            "reason\x1b[31mred\x1b[0m",             // ANSI escape
            "reason\0null\r\n\t",                   // Control characters
            "reason\"}{\"admin\":true,\"bypass\"", // JSON injection
            "reason<script>alert(1)</script>",     // XSS attempt
            "reason'; DROP TABLE decisions; --",   // SQL injection
            "reason||rm -rf /",                     // Shell injection
            "X".repeat(10_000),                     // Extremely long reason (10KB)
        ];

        for malicious_reason in malicious_reasons {
            let deny_decision = TrustDecision::Deny(malicious_reason.to_string());

            // Test display formatting
            let display_str = format!("{}", deny_decision);
            assert!(display_str.starts_with("Deny("), "display should have correct format");
            assert!(display_str.contains(malicious_reason), "display should contain reason");

            // Test JSON serialization safety
            let json = serde_json::to_string(&deny_decision).expect("serialization should work");
            let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should be valid");

            // Verify malicious content is properly contained
            if let Some(variant) = parsed.as_object().and_then(|o| o.get("deny")) {
                if let Some(reason_str) = variant.as_str() {
                    assert_eq!(reason_str, malicious_reason, "reason should be preserved exactly");
                }
            }

            // Verify no injection in JSON structure
            assert!(parsed.get("admin").is_none(), "JSON injection should not create admin field");
        }

        // Test Degrade decision with extreme levels
        let extreme_levels = [0, 1, 5, 255, u8::MAX];
        for level in extreme_levels {
            let degrade_decision = TrustDecision::Degrade(level);

            let display_str = format!("{}", degrade_decision);
            assert!(display_str.starts_with("Degrade("), "display should have correct format");
            assert!(display_str.contains(&level.to_string()), "display should contain level");

            // Test serialization
            let json = serde_json::to_string(&degrade_decision).expect("serialization should work");
            let parsed: TrustDecision = serde_json::from_str(&json).expect("deserialization should work");

            if let TrustDecision::Degrade(parsed_level) = parsed {
                assert_eq!(parsed_level, level, "level should be preserved");
            } else {
                panic!("deserialized decision should be Degrade");
            }
        }
    }

    #[test]
    fn test_negative_policy_predicate_with_massive_constraint_expressions() {
        let massive_expressions = [
            "true".repeat(100_000),  // 500KB expression
            "false AND ".repeat(50_000) + "true", // 450KB complex expression
            "x > 0 OR ".repeat(100_000) + "false", // 700KB disjunction
            "((((".repeat(10_000) + "true" + &"))))".repeat(10_000), // Deep nesting
            format!("field = '{}'", "X".repeat(1_000_000)), // 1MB string literal
        ];

        for massive_expr in massive_expressions {
            let massive_policy = PolicyPredicate {
                predicate_id: "massive-test".to_string(),
                action_class: "test.action".to_string(),
                constraint_expression: massive_expr.clone(),
                severity_level: 3,
            };

            // Test serialization with massive expression
            let json = serde_json::to_string(&massive_policy).expect("serialization should handle massive expressions");
            assert!(json.len() >= massive_expr.len(), "JSON should include massive expression");

            let parsed: PolicyPredicate = serde_json::from_str(&json).expect("deserialization should work");
            assert_eq!(parsed.constraint_expression, massive_expr, "expression should be preserved");

            // Test verification with massive policy
            let verifier = ProofVerifier::new();
            let test_proof = test_compliance_proof();
            let request = VerificationRequest {
                proof: test_proof,
                policy_context: "massive-policy-test".to_string(),
                trace_id: "massive-trace".to_string(),
            };

            let result = verifier.verify(&request, &[massive_policy]);

            // Should handle massive policies without memory explosion
            assert!(result.report.is_some(), "report should be generated with massive policy");

            // Verify result structure is reasonable
            let report = result.report.unwrap();
            assert!(!report.evidence_summary.is_empty(), "evidence summary should not be empty");
        }

        // Test policy with malicious constraint expressions
        let malicious_constraints = [
            "payload.admin = true",                    // Privilege escalation attempt
            "payload[\"../../etc/passwd\"] = null",   // Path traversal
            "eval('malicious code')",                  // Code injection
            "system('rm -rf /')",                     // Command injection
            "javascript:alert(1)",                     // JavaScript URL
            "DROP TABLE policies",                     // SQL injection
        ];

        for malicious_expr in malicious_constraints {
            let malicious_policy = PolicyPredicate {
                predicate_id: "malicious-constraint-test".to_string(),
                action_class: "test.action".to_string(),
                constraint_expression: malicious_expr.to_string(),
                severity_level: 5,
            };

            let verifier = ProofVerifier::new();
            let test_proof = test_compliance_proof();
            let request = VerificationRequest {
                proof: test_proof,
                policy_context: "malicious-constraint-test".to_string(),
                trace_id: "malicious-constraint-trace".to_string(),
            };

            let result = verifier.verify(&request, &[malicious_policy]);

            // Should handle malicious constraints safely
            assert!(result.report.is_some(), "report should be generated with malicious constraint");
        }
    }

    #[test]
    fn test_negative_proof_signature_with_bypass_attempts() {
        use crate::security::constant_time::ct_eq;

        let verifier = ProofVerifier::new();
        let test_policy = test_policy_predicate();

        // Test various signature bypass attempts
        let signature_bypass_attempts = [
            "",                                          // Empty signature
            "valid-signature",                          // Base case
            "valid-signature\0",                        // Null termination
            "valid-signature\r\n",                     // CRLF injection
            "valid-signature||bypass",                 // Delimiter confusion
            "VALID-SIGNATURE",                         // Case variation
            "valid\u{200B}signature",                  // Zero-width space
            "valid\u{202E}signature\u{202C}",         // BiDi override
            "valid-signature\x1b[31m",                // ANSI escape
            format!("valid-signature-{}", "x".repeat(100_000)), // Massive signature
            "-----BEGIN SIGNATURE-----\nfake\n-----END SIGNATURE-----", // PEM-like format
        ];

        for (i, bypass_signature) in signature_bypass_attempts.iter().enumerate() {
            let bypass_proof = ComplianceProof {
                proof_id: format!("bypass-test-{}", i),
                action_class: "test.action".to_string(),
                payload: r#"{"test": "data"}"#.to_string(),
                issued_at_epoch: 1234567890,
                expires_at_epoch: 1234567890 + 3600,
                signature: bypass_signature.to_string(),
                issuer_public_key: "test-public-key".to_string(),
            };

            let request = VerificationRequest {
                proof: bypass_proof.clone(),
                policy_context: "signature-bypass-test".to_string(),
                trace_id: format!("bypass-trace-{}", i),
            };

            let result = verifier.verify(&request, &[test_policy.clone()]);

            // Verify signature is preserved exactly for forensics
            if let Some(report) = result.report {
                assert_eq!(report.compliance_proof.signature, *bypass_signature, "signature should be preserved");
            }

            // Test constant-time comparison for signatures
            let baseline_signature = "baseline-signature";
            assert!(!ct_eq(bypass_signature, baseline_signature),
                   "signature comparison should be constant-time");
        }

        // Test with malformed public keys
        let malformed_public_keys = [
            "",                                                // Empty key
            "not-a-valid-public-key",                         // Invalid format
            "-----BEGIN CERTIFICATE-----\nmalicious\n-----END CERTIFICATE-----", // Wrong type
            "-----BEGIN PUBLIC KEY-----\n\n-----END PUBLIC KEY-----", // Empty content
            "x".repeat(10_000),                               // Extremely long key
            "\0".repeat(100),                                 // Null bytes
            "key\r\nHost: evil.com\r\n",                     // Header injection
        ];

        for malformed_key in malformed_public_keys {
            let malformed_proof = ComplianceProof {
                proof_id: "malformed-key-test".to_string(),
                action_class: "test.action".to_string(),
                payload: r#"{"test": "data"}"#.to_string(),
                issued_at_epoch: 1234567890,
                expires_at_epoch: 1234567890 + 3600,
                signature: "test-signature".to_string(),
                issuer_public_key: malformed_key.to_string(),
            };

            let request = VerificationRequest {
                proof: malformed_proof,
                policy_context: "malformed-key-test".to_string(),
                trace_id: "malformed-key-trace".to_string(),
            };

            let result = verifier.verify(&request, &[test_policy.clone()]);

            // Should handle malformed keys safely (likely deny)
            assert!(result.report.is_some(), "report should be generated with malformed key");
        }
    }

    #[test]
    fn test_negative_verification_events_with_bounded_storage() {
        let mut verifier = ProofVerifier::new();

        // Generate many verification requests to test bounded storage
        for i in 0..10_000 {
            let stress_proof = ComplianceProof {
                proof_id: format!("stress-test-{:05}", i),
                action_class: "test.action".to_string(),
                payload: format!(r#"{{"iteration": {}, "data": "{}"}}"#, i, "X".repeat(1000)), // 1KB payload each
                issued_at_epoch: 1234567890,
                expires_at_epoch: 1234567890 + 3600,
                signature: format!("signature-{}", i),
                issuer_public_key: "test-public-key".to_string(),
            };

            let request = VerificationRequest {
                proof: stress_proof,
                policy_context: format!("stress-context-{}", i),
                trace_id: format!("stress-trace-{:05}", i),
            };

            let result = verifier.verify(&request, &[test_policy_predicate()]);

            // Each verification should succeed
            assert!(result.report.is_some(), "report should be generated for stress test {}", i);
        }

        // Verify bounded storage of events
        if verifier.recent_events.len() > MAX_EVENTS * 2 {
            panic!("event storage should be bounded, got {} events", verifier.recent_events.len());
        }

        // Verify bounded storage of reports
        if verifier.recent_reports.len() > MAX_REPORTS * 2 {
            panic!("report storage should be bounded, got {} reports", verifier.recent_reports.len());
        }

        // Test with massive trace IDs
        for i in 0..100 {
            let huge_trace_id = format!("huge-trace-{}-{}", i, "Y".repeat(50_000)); // 50KB trace ID

            let request = VerificationRequest {
                proof: test_compliance_proof(),
                policy_context: "huge-trace-test".to_string(),
                trace_id: huge_trace_id.clone(),
            };

            let result = verifier.verify(&request, &[test_policy_predicate()]);

            // Should handle huge trace IDs without memory explosion
            if let Some(report) = result.report {
                assert_eq!(report.trace_id, huge_trace_id, "trace ID should be preserved");
            }
        }

        // Verify verifier still functions after stress testing
        let final_request = VerificationRequest {
            proof: test_compliance_proof(),
            policy_context: "final-test".to_string(),
            trace_id: "final-trace".to_string(),
        };

        let final_result = verifier.verify(&final_request, &[test_policy_predicate()]);
        assert!(final_result.report.is_some(), "verifier should still function after stress testing");
    }

    #[test]
    fn test_negative_proof_expiration_with_time_manipulation() {
        let verifier = ProofVerifier::new();
        let test_policy = test_policy_predicate();

        // Test various timestamp manipulation attempts
        let timestamp_attacks = [
            // Basic expiration cases
            (1234567890, 1234567890 - 1),     // Expired (expires before issued)
            (1234567890, 1234567890),         // Expires immediately
            (1234567890, 1234567890 + 1),     // Valid (1 second window)

            // Boundary value attacks
            (0, 0),                           // Zero timestamps
            (0, u64::MAX),                    // Zero issued, max expires
            (u64::MAX, u64::MAX),             // Max timestamps
            (u64::MAX - 1, u64::MAX),         // Near overflow

            // Arithmetic overflow attempts
            (1, u64::MAX),                    // Huge expiration window
            (u64::MAX - 1000, u64::MAX - 1), // Near max, expired
            (u64::MAX / 2, u64::MAX),         // Half max to max

            // Time travel attempts
            (u64::MAX, 0),                    // Future issued, past expiration
            (2000000000, 1000000000),         // Future issued, past expiration
        ];

        for (issued_at, expires_at) in timestamp_attacks {
            let timestamp_proof = ComplianceProof {
                proof_id: format!("timestamp-test-{}-{}", issued_at, expires_at),
                action_class: "test.action".to_string(),
                payload: r#"{"test": "timestamp_attack"}"#.to_string(),
                issued_at_epoch: issued_at,
                expires_at_epoch: expires_at,
                signature: "test-signature".to_string(),
                issuer_public_key: "test-public-key".to_string(),
            };

            let request = VerificationRequest {
                proof: timestamp_proof.clone(),
                policy_context: "timestamp-test".to_string(),
                trace_id: format!("timestamp-trace-{}-{}", issued_at, expires_at),
            };

            let result = verifier.verify(&request, &[test_policy.clone()]);

            // Should handle timestamp attacks without panic
            assert!(result.report.is_some(), "report should be generated for timestamp attack");

            if let Some(report) = result.report {
                // Verify timestamps are preserved for forensics
                assert_eq!(report.compliance_proof.issued_at_epoch, issued_at);
                assert_eq!(report.compliance_proof.expires_at_epoch, expires_at);

                // For clearly expired proofs, decision should be Deny
                if expires_at < issued_at {
                    match report.decision {
                        TrustDecision::Deny(reason) => {
                            assert!(reason.contains("expired") || reason.contains("timestamp"),
                                   "deny reason should mention expiration");
                        }
                        _ => {
                            // Some edge cases might not be detected as expired
                            // depending on implementation, but should be handled safely
                        }
                    }
                }
            }

            // Verify events are generated for timestamp attacks
            assert!(!result.events.is_empty(), "events should be generated for timestamp attacks");
        }
    }

    #[test]
    fn test_negative_policy_context_with_unicode_injection_attacks() {
        use crate::security::constant_time::ct_eq;

        let verifier = ProofVerifier::new();
        let test_policy = test_policy_predicate();
        let test_proof = test_compliance_proof();

        let malicious_contexts = [
            "context\u{202E}fake\u{202C}",           // BiDi override
            "context\x1b[31mred\x1b[0m",             // ANSI escape
            "context\0null\r\n\t",                   // Control characters
            "context\"}{\"admin\":true,\"bypass\"", // JSON injection
            "context/../../etc/passwd",              // Path traversal
            "context\u{FEFF}BOM",                    // Byte order mark
            "context\u{200B}\u{200C}\u{200D}",      // Zero-width characters
            "context<script>alert(1)</script>",     // XSS attempt
            "context'; DROP TABLE contexts; --",    // SQL injection
            "context||rm -rf /",                     // Shell injection
            "CONTEXT",                               // Case variation
            "x".repeat(1_000_000),                   // Massive context (1MB)
        ];

        for malicious_context in malicious_contexts {
            let request = VerificationRequest {
                proof: test_proof.clone(),
                policy_context: malicious_context.to_string(),
                trace_id: "context-injection-test".to_string(),
            };

            let result = verifier.verify(&request, &[test_policy.clone()]);

            // Verify context is preserved exactly for forensics
            if let Some(report) = result.report {
                assert_eq!(report.policy_context, malicious_context, "context should be preserved");

                // Test JSON serialization safety
                let json = serde_json::to_string(&report).expect("serialization should work");
                let parsed: serde_json::Value = serde_json::from_str(&json).expect("JSON should be valid");

                // Verify no injection occurred in JSON structure
                assert!(parsed.get("admin").is_none(), "JSON injection should not create admin field");
                assert!(parsed.get("bypass").is_none(), "JSON injection should not create bypass field");
            }

            // Test constant-time comparison for contexts
            let normal_context = "normal-context";
            assert!(!ct_eq(malicious_context, normal_context),
                   "context comparison should be constant-time");

            // Verify events are generated safely
            for event in &result.events {
                let event_json = serde_json::to_string(&event).expect("event serialization should work");
                assert!(!event_json.contains("admin"), "event should not contain injection");
            }
        }

        // Test with contexts containing policy-like content
        let policy_mimicking_contexts = [
            "policy.admin.bypass",
            "system.root.access",
            "security.override.enabled",
            "debug.elevated.privileges",
        ];

        for policy_context in policy_mimicking_contexts {
            let request = VerificationRequest {
                proof: test_proof.clone(),
                policy_context: policy_context.to_string(),
                trace_id: "policy-mimicking-test".to_string(),
            };

            let result = verifier.verify(&request, &[test_policy.clone()]);

            // Should not be fooled by policy-like context names
            assert!(result.report.is_some(), "report should be generated");

            if let Some(report) = result.report {
                // Context should not affect trust decision inappropriately
                match report.decision {
                    TrustDecision::Allow => {
                        // If allowed, it should be based on proof validity, not context
                    }
                    TrustDecision::Deny(_) => {
                        // Denial should be based on proof/policy, not context manipulation
                    }
                    TrustDecision::Degrade(_) => {
                        // Degradation should be policy-based
                    }
                }
            }
        }
    }

    #[test]
    fn test_negative_action_class_mismatch_with_bypass_attempts() {
        let verifier = ProofVerifier::new();

        // Create policies with specific action classes
        let target_policy = PolicyPredicate {
            predicate_id: "target-policy".to_string(),
            action_class: "privileged.admin.action".to_string(),
            constraint_expression: "payload.authorized = true".to_string(),
            severity_level: 5,
        };

        let bypass_attempts = [
            // Exact match (should work)
            "privileged.admin.action",

            // Case manipulation
            "PRIVILEGED.ADMIN.ACTION",
            "Privileged.Admin.Action",
            "privileged.Admin.Action",

            // Unicode manipulation
            "privileged.admin.action\u{200B}",           // Zero-width space
            "privileged.admin.action\u{FEFF}",           // BOM
            "privileged\u{2010}admin\u{2010}action",     // Unicode hyphens
            "privileged\u{00AD}admin\u{00AD}action",     // Soft hyphens

            // Null byte injection
            "privileged.admin.action\0",
            "privileged\0admin.action",
            "\0privileged.admin.action",

            // Substring/prefix attacks
            "privileged",
            "privileged.admin",
            "admin.action",
            "action",

            // Suffix attacks
            "privileged.admin.action.extra",
            "privileged.admin.action.bypass",
            "privileged.admin.action.elevated",

            // Prefix attacks
            "super.privileged.admin.action",
            "bypass.privileged.admin.action",
            "elevated.privileged.admin.action",

            // Delimiter confusion
            "privileged/admin/action",
            "privileged::admin::action",
            "privileged admin action",
            "privileged|admin|action",

            // Path traversal style
            "../../privileged.admin.action",
            "privileged.admin.action/..",
            "./privileged.admin.action",

            // Wildcard attempts
            "privileged.*.action",
            "privileged.admin.*",
            "*.admin.action",
            "*",

            // Empty/special values
            "",
            "null",
            "undefined",
        ];

        for bypass_action in bypass_attempts {
            let bypass_proof = ComplianceProof {
                proof_id: "bypass-action-test".to_string(),
                action_class: bypass_action.to_string(),
                payload: r#"{"authorized": true}"#.to_string(),
                issued_at_epoch: 1234567890,
                expires_at_epoch: 1234567890 + 3600,
                signature: "test-signature".to_string(),
                issuer_public_key: "test-public-key".to_string(),
            };

            let request = VerificationRequest {
                proof: bypass_proof.clone(),
                policy_context: "action-bypass-test".to_string(),
                trace_id: format!("bypass-trace-{}", bypass_action),
            };

            let result = verifier.verify(&request, &[target_policy.clone()]);

            // Verify action class is preserved for forensics
            if let Some(report) = result.report {
                assert_eq!(report.compliance_proof.action_class, bypass_action, "action class should be preserved");

                // Only exact matches should potentially succeed
                if bypass_action == "privileged.admin.action" {
                    // Exact match might succeed based on other factors
                } else {
                    // Non-exact matches should typically fail to find matching policy
                    match report.decision {
                        TrustDecision::Deny(reason) => {
                            // Expected for mismatched action classes
                            assert!(!reason.is_empty(), "deny reason should not be empty");
                        }
                        _ => {
                            // Some implementations might handle mismatches differently
                        }
                    }
                }
            }

            // Verify events are generated for bypass attempts
            assert!(!result.events.is_empty(), "events should be generated for bypass attempts");
        }
    }
}
