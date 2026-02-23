//! bd-1o4v: Proof-verification gate API for control-plane trust decisions.
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

        // Check 1: Proof expiration
        let expiry_satisfied = now_millis <= proof.expires_at_millis;
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
        let freshness_satisfied = age_millis <= age_limit;
        if !freshness_satisfied {
            deny_reasons.push(format!(
                "{}: proof age {}ms exceeds limit {}ms",
                error_codes::ERR_PVF_PROOF_EXPIRED,
                age_millis,
                age_limit
            ));
            all_satisfied = false;
        }
        evidence.push(PredicateEvidence {
            predicate_id: predicate.predicate_id.clone(),
            action_class: proof.action_class.clone(),
            satisfied: freshness_satisfied,
            reason: if freshness_satisfied {
                format!("proof age {}ms within limit {}ms", age_millis, age_limit)
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
            proof.policy_version_hash == predicate.policy_version_hash
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
            self.events.push(VerifierEvent {
                event_code: event_codes::PVF_004_DENY_LOGGED.to_string(),
                trace_id: trace_id.to_string(),
                detail: format!("proof={} DENY: {}", proof.proof_id, reason),
            });
            TrustDecision::Deny(reason)
        } else if !all_satisfied && degrade_level > 0 {
            self.events.push(VerifierEvent {
                event_code: event_codes::PVF_005_DEGRADE_LOGGED.to_string(),
                trace_id: trace_id.to_string(),
                detail: format!("proof={} DEGRADE level={}", proof.proof_id, degrade_level),
            });
            TrustDecision::Degrade(degrade_level)
        } else if all_satisfied {
            self.events.push(VerifierEvent {
                event_code: event_codes::PVF_002_PROOF_VALIDATED.to_string(),
                trace_id: trace_id.to_string(),
                detail: format!("proof={} validated successfully", proof.proof_id),
            });
            TrustDecision::Allow
        } else {
            // Fallback: unsatisfied checks with no explicit deny reason -> degrade(1)
            self.events.push(VerifierEvent {
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

        // Emit request-received event
        self.events.push(VerifierEvent {
            event_code: event_codes::PVF_001_REQUEST_RECEIVED.to_string(),
            trace_id: trace_id.clone(),
            detail: format!(
                "request={} proof={} action_class={}",
                request.request_id, request.proof.proof_id, request.proof.action_class
            ),
        });

        // Format validation
        if request.proof.proof_id.is_empty() {
            let err = VerifierError::invalid_format("proof_id is empty");
            self.events.push(VerifierEvent {
                event_code: event_codes::PVF_004_DENY_LOGGED.to_string(),
                trace_id: trace_id.clone(),
                detail: format!("request={} DENY: {}", request.request_id, err.message),
            });
            return Err(err);
        }
        if request.proof.proof_hash.is_empty() {
            let err = VerifierError::invalid_format("proof_hash is empty");
            self.events.push(VerifierEvent {
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
                self.events.push(VerifierEvent {
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

        // Emit decision event
        self.events.push(VerifierEvent {
            event_code: event_codes::PVF_003_DECISION_EMITTED.to_string(),
            trace_id: trace_id.clone(),
            detail: format!(
                "request={} proof={} decision={}",
                request.request_id, request.proof.proof_id, decision
            ),
        });

        // Propagate verifier events
        self.events.extend(verifier.events().iter().cloned());

        // Build report
        let report_digest = compute_report_digest(
            &request.request_id,
            &request.proof.proof_id,
            &request.proof.action_class,
            &decision,
            &evidence,
        )?;

        let report = VerificationReport {
            schema_version: PROOF_VERIFIER_SCHEMA_VERSION.to_string(),
            request_id: request.request_id.clone(),
            proof_id: request.proof.proof_id.clone(),
            action_class: request.proof.action_class.clone(),
            decision: decision.clone(),
            evidence,
            events: verifier.events().to_vec(),
            report_digest,
            trace_id: trace_id.clone(),
            created_at_millis: request.now_millis,
        };

        // Emit report-finalized event
        self.events.push(VerifierEvent {
            event_code: event_codes::PVF_006_REPORT_FINALIZED.to_string(),
            trace_id: trace_id.clone(),
            detail: format!(
                "request={} report_digest={} decision={}",
                request.request_id, report.report_digest, decision
            ),
        });

        self.reports.push(report.clone());
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
                TrustDecision::Allow => allow_count += 1,
                TrustDecision::Deny(reason) => {
                    deny_count += 1;
                    *deny_reasons.entry(reason.clone()).or_insert(0) += 1;
                }
                TrustDecision::Degrade(_) => degrade_count += 1,
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
        evidence_count: usize,
        evidence_satisfied: Vec<bool>,
    }

    let material = DigestMaterial {
        schema_version: PROOF_VERIFIER_SCHEMA_VERSION,
        request_id,
        proof_id,
        action_class,
        decision,
        evidence_count: evidence.len(),
        evidence_satisfied: evidence.iter().map(|e| e.satisfied).collect(),
    };

    let bytes = serde_json::to_vec(&material).map_err(|err| {
        VerifierError::internal(format!("failed to serialize digest material: {err}"))
    })?;
    let digest = Sha256::digest([b"proof_verifier_hash_v1:" as &[u8], &bytes[..]].concat());
    Ok(format!("sha256:{digest:x}"))
}

// ════════════════════════════════════════════════════════════════════════════
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
}
