// Operator intelligence recommendation engine with rollback proofs.
//
// Produces expected-loss-scored recommendations with deterministic replay
// artifacts and a full audit trail.
//
// bd-y0v — Section 10.12

use hex::encode as hex_encode;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, VecDeque};

use crate::security::constant_time;

use crate::capacity_defaults::aliases::{MAX_AUDIT_TRAIL_ENTRIES, MAX_EVENTS};
const MAX_MISSING_SOURCES: usize = 256;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub const EVT_RECOMMENDATION_GENERATED: &str = "OIR-001";
pub const EVT_RECOMMENDATION_ACCEPTED: &str = "OIR-002";
pub const EVT_RECOMMENDATION_REJECTED: &str = "OIR-003";
pub const EVT_ACTION_EXECUTED: &str = "OIR-004";
pub const EVT_ROLLBACK_PROOF_CREATED: &str = "OIR-005";
pub const EVT_ROLLBACK_PROOF_VERIFIED: &str = "OIR-006";
pub const EVT_ROLLBACK_EXECUTED: &str = "OIR-007";
pub const EVT_REPLAY_ARTIFACT_CREATED: &str = "OIR-008";
pub const EVT_DEGRADED_MODE_ENTERED: &str = "OIR-009";
pub const EVT_DEGRADED_MODE_WARNING: &str = "OIR-010";

// ---------------------------------------------------------------------------
// Error codes
// ---------------------------------------------------------------------------

pub const ERR_OIR_INVALID_CONFIG: &str = "ERR_OIR_INVALID_CONFIG";
pub const ERR_OIR_NO_CONTEXT: &str = "ERR_OIR_NO_CONTEXT";
pub const ERR_OIR_SCORE_OVERFLOW: &str = "ERR_OIR_SCORE_OVERFLOW";
pub const ERR_OIR_ROLLBACK_FAILED: &str = "ERR_OIR_ROLLBACK_FAILED";
pub const ERR_OIR_REPLAY_MISMATCH: &str = "ERR_OIR_REPLAY_MISMATCH";
pub const ERR_OIR_DEGRADED: &str = "ERR_OIR_DEGRADED";

// ---------------------------------------------------------------------------
// Invariant constants
// ---------------------------------------------------------------------------

pub const INV_OIR_DETERMINISTIC: &str = "INV-OIR-DETERMINISTIC";
pub const INV_OIR_ROLLBACK_SOUND: &str = "INV-OIR-ROLLBACK-SOUND";
pub const INV_OIR_BUDGET: &str = "INV-OIR-BUDGET";
pub const INV_OIR_AUDIT: &str = "INV-OIR-AUDIT";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct RecommendationConfig {
    /// Maximum number of recommendations per query.
    pub max_recommendations: usize,
    /// Minimum confidence to emit a recommendation.
    pub confidence_threshold: f64,
    /// Maximum cumulative expected-loss budget.
    pub risk_budget: f64,
    /// Confidence multiplier when in degraded mode.
    pub degraded_confidence_penalty: f64,
}

impl Default for RecommendationConfig {
    fn default() -> Self {
        Self {
            max_recommendations: 10,
            confidence_threshold: 0.5,
            risk_budget: 100.0,
            degraded_confidence_penalty: 0.5,
        }
    }
}

impl RecommendationConfig {
    pub fn validate(&self) -> Result<(), OIError> {
        if self.max_recommendations == 0 {
            return Err(OIError::InvalidConfig(
                "max_recommendations must be > 0".into(),
            ));
        }
        if !(0.0..=1.0).contains(&self.confidence_threshold) {
            return Err(OIError::InvalidConfig(
                "confidence_threshold must be in [0.0, 1.0]".into(),
            ));
        }
        if !self.risk_budget.is_finite() || self.risk_budget <= 0.0 {
            return Err(OIError::InvalidConfig("risk_budget must be > 0".into()));
        }
        if !(0.0..=1.0).contains(&self.degraded_confidence_penalty) {
            return Err(OIError::InvalidConfig(
                "degraded_confidence_penalty must be in [0.0, 1.0]".into(),
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum OIError {
    InvalidConfig(String),
    NoContext(String),
    ScoreOverflow { cumulative: f64, budget: f64 },
    RollbackFailed(String),
    ReplayMismatch { expected: String, actual: String },
    Degraded(String),
}

impl std::fmt::Display for OIError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidConfig(msg) => write!(f, "{ERR_OIR_INVALID_CONFIG}: {msg}"),
            Self::NoContext(msg) => write!(f, "{ERR_OIR_NO_CONTEXT}: {msg}"),
            Self::ScoreOverflow { cumulative, budget } => {
                write!(
                    f,
                    "{ERR_OIR_SCORE_OVERFLOW}: cumulative {cumulative} > budget {budget}"
                )
            }
            Self::RollbackFailed(msg) => write!(f, "{ERR_OIR_ROLLBACK_FAILED}: {msg}"),
            Self::ReplayMismatch { expected, actual } => {
                write!(
                    f,
                    "{ERR_OIR_REPLAY_MISMATCH}: expected={expected}, actual={actual}"
                )
            }
            Self::Degraded(msg) => write!(f, "{ERR_OIR_DEGRADED}: {msg}"),
        }
    }
}

impl std::error::Error for OIError {}

// ---------------------------------------------------------------------------
// Operator context
// ---------------------------------------------------------------------------

/// Snapshot of the operator's current system state.
#[derive(Debug, Clone)]
pub struct OperatorContext {
    /// Compatibility test pass rate [0.0, 1.0].
    pub compatibility_pass: f64,
    /// Migration success rate [0.0, 1.0].
    pub migration_success: f64,
    /// Trust artifact validity rate [0.0, 1.0].
    pub trust_valid: f64,
    /// Current error rate [0.0, 1.0].
    pub error_rate: f64,
    /// Number of pending operations.
    pub pending_ops: usize,
    /// Number of active alerts.
    pub active_alerts: usize,
}

impl OperatorContext {
    pub fn validate(&self) -> Result<(), OIError> {
        if !(0.0..=1.0).contains(&self.compatibility_pass)
            || !(0.0..=1.0).contains(&self.migration_success)
            || !(0.0..=1.0).contains(&self.trust_valid)
            || !(0.0..=1.0).contains(&self.error_rate)
        {
            return Err(OIError::NoContext(
                "rate values must be in [0.0, 1.0]".into(),
            ));
        }
        Ok(())
    }

    /// Compute a fingerprint of this context for audit trail.
    pub fn fingerprint(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"operator_intelligence_ctx_v1:");
        hasher.update(self.compatibility_pass.to_le_bytes());
        hasher.update(self.migration_success.to_le_bytes());
        hasher.update(self.trust_valid.to_le_bytes());
        hasher.update(self.error_rate.to_le_bytes());
        hasher.update(self.pending_ops.to_le_bytes());
        hasher.update(self.active_alerts.to_le_bytes());
        hasher.finalize().into()
    }
}

// ---------------------------------------------------------------------------
// Recommendation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Recommendation {
    pub id: String,
    pub action: String,
    pub expected_loss: f64,
    pub confidence: f64,
    pub priority: u32,
    pub prerequisites: Vec<String>,
    pub estimated_time_ms: u64,
    pub degraded_warning: Option<String>,
}

// ---------------------------------------------------------------------------
// Rollback proof
// ---------------------------------------------------------------------------

/// Proves that an action can be reversed to a known-good state.
#[derive(Debug, Clone)]
pub struct RollbackProof {
    /// Content-addressed pre-action state hash.
    pub pre_state_hash: [u8; 32],
    /// Deterministic action command sequence.
    pub action_spec: String,
    /// Expected post-action state hash.
    pub post_state_hash: [u8; 32],
    /// Rollback command sequence to restore pre-action state.
    pub rollback_spec: String,
}

impl RollbackProof {
    /// Compute the content hash of the proof for integrity verification.
    pub fn content_hash(&self) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(b"rollback_proof_content_v1:");
        hasher.update(self.pre_state_hash);
        hasher.update((self.action_spec.len() as u64).to_le_bytes());
        hasher.update(self.action_spec.as_bytes());
        hasher.update(self.post_state_hash);
        hasher.update((self.rollback_spec.len() as u64).to_le_bytes());
        hasher.update(self.rollback_spec.as_bytes());
        hasher.finalize().into()
    }

    /// Verify structural and cryptographic soundness of the rollback proof.
    /// INV-OIR-ROLLBACK-SOUND
    pub fn verify(&self) -> Result<bool, OIError> {
        if self.action_spec.is_empty() {
            return Err(OIError::RollbackFailed("empty action spec".into()));
        }
        if self.rollback_spec.is_empty() {
            return Err(OIError::RollbackFailed("empty rollback spec".into()));
        }
        if constant_time::ct_eq_bytes(&self.pre_state_hash, &self.post_state_hash) {
            return Err(OIError::RollbackFailed(
                "pre and post states identical".into(),
            ));
        }
        // Verify rollback spec references the correct action (INV-OIR-ROLLBACK-SOUND).
        let expected_rollback = format!("rollback:{}", self.action_spec);
        if self.rollback_spec != expected_rollback {
            return Err(OIError::RollbackFailed(
                "rollback spec does not match action spec".into(),
            ));
        }
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Replay artifact
// ---------------------------------------------------------------------------

/// Deterministic replay artifact capturing full input-to-output trace.
#[derive(Debug, Clone)]
pub struct ReplayArtifact {
    pub recommendation_id: String,
    pub input_context_fingerprint: [u8; 32],
    pub action_executed: String,
    pub outcome: String,
    pub rollback_proof: Option<RollbackProof>,
}

// ---------------------------------------------------------------------------
// Audit entry
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RecommendationDecision {
    #[default]
    Pending,
    Accepted,
    Rejected,
}

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub recommendation_id: String,
    pub action: String,
    pub decision: RecommendationDecision,
    pub expected_loss: f64,
    pub context_fingerprint: [u8; 32],
}

// ---------------------------------------------------------------------------
// Events
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct OIEvent {
    pub code: String,
    pub detail: String,
}

// ---------------------------------------------------------------------------
// Recommendation engine
// ---------------------------------------------------------------------------

/// Expected-loss scoring model.
fn compute_expected_loss(ctx: &OperatorContext) -> f64 {
    // Weighted risk from context signals.
    // Higher error rate, lower pass rates, more alerts = higher expected loss.
    let compat_risk = (1.0 - ctx.compatibility_pass) * 30.0;
    let migration_risk = (1.0 - ctx.migration_success) * 25.0;
    let trust_risk = (1.0 - ctx.trust_valid) * 20.0;
    let error_risk = ctx.error_rate * 15.0;
    let alert_risk = (ctx.active_alerts as f64).min(10.0);
    compat_risk + migration_risk + trust_risk + error_risk + alert_risk
}

/// Compute confidence from context signals.
fn compute_confidence(ctx: &OperatorContext) -> f64 {
    // Average of positive signals.
    let signals = [
        ctx.compatibility_pass,
        ctx.migration_success,
        ctx.trust_valid,
        1.0 - ctx.error_rate,
    ];
    signals.iter().sum::<f64>() / signals.len() as f64
}

/// Generate action recommendations based on context.
fn generate_actions(ctx: &OperatorContext) -> Vec<(String, String, Vec<String>, u64)> {
    let mut actions = Vec::new();

    if ctx.compatibility_pass < 0.9 {
        actions.push((
            "run_compat_suite".into(),
            "Run full compatibility test suite to identify regressions".into(),
            vec!["compat_tests_available".into()],
            30_000,
        ));
    }

    if ctx.migration_success < 0.8 {
        actions.push((
            "dry_run_migration".into(),
            "Execute dry-run migration to validate upgrade path".into(),
            vec!["migration_plan_ready".into()],
            60_000,
        ));
    }

    if ctx.trust_valid < 0.95 {
        actions.push((
            "refresh_trust_state".into(),
            "Refresh trust artifacts and re-validate certificate chain".into(),
            vec!["trust_anchor_accessible".into()],
            15_000,
        ));
    }

    if ctx.error_rate > 0.05 {
        actions.push((
            "investigate_errors".into(),
            "Analyze error rate spike and identify root cause".into(),
            vec![],
            45_000,
        ));
    }

    if ctx.active_alerts > 3 {
        actions.push((
            "triage_alerts".into(),
            "Triage active alerts and prioritize response".into(),
            vec![],
            20_000,
        ));
    }

    if ctx.pending_ops > 10 {
        actions.push((
            "flush_pending_ops".into(),
            "Process pending operations queue to reduce backlog".into(),
            vec!["operator_capacity_available".into()],
            120_000,
        ));
    }

    // Always suggest a health check.
    actions.push((
        "health_check".into(),
        "Run comprehensive system health check".into(),
        vec![],
        10_000,
    ));

    actions
}

/// Recommendation engine core.
#[derive(Debug)]
pub struct RecommendationEngine {
    config: RecommendationConfig,
    degraded: bool,
    missing_sources: Vec<String>,
    audit_trail: Vec<AuditEntry>,
    closed_audit_entries: BTreeMap<String, AuditEntry>,
    closed_audit_order: VecDeque<String>,
    events: Vec<OIEvent>,
    cumulative_loss: f64,
}

impl RecommendationEngine {
    pub fn new(config: RecommendationConfig) -> Result<Self, OIError> {
        config.validate()?;
        Ok(Self {
            config,
            degraded: false,
            missing_sources: Vec::new(),
            audit_trail: Vec::new(),
            closed_audit_entries: BTreeMap::new(),
            closed_audit_order: VecDeque::new(),
            events: Vec::new(),
            cumulative_loss: 0.0,
        })
    }

    /// Mark a data source as unavailable (triggers degraded mode).
    pub fn mark_source_unavailable(&mut self, source: &str) {
        if !self.missing_sources.contains(&source.to_string()) {
            push_bounded(
                &mut self.missing_sources,
                source.into(),
                MAX_MISSING_SOURCES,
            );
        }
        if !self.degraded {
            self.degraded = true;
            push_bounded(
                &mut self.events,
                OIEvent {
                    code: EVT_DEGRADED_MODE_ENTERED.to_string(),
                    detail: format!("source unavailable: {source}"),
                },
                MAX_EVENTS,
            );
        }
    }

    /// Clear degraded state.
    pub fn clear_degraded(&mut self) {
        self.degraded = false;
        self.missing_sources.clear();
    }

    /// Whether engine is in degraded mode.
    pub fn is_degraded(&self) -> bool {
        self.degraded
    }

    fn audit_entry(&self, recommendation_id: &str) -> Result<&AuditEntry, OIError> {
        self.audit_trail
            .iter()
            .rev()
            .find(|entry| entry.recommendation_id == recommendation_id)
            .ok_or_else(|| {
                OIError::NoContext(format!(
                    "recommendation {recommendation_id} not present in audit trail"
                ))
            })
    }

    fn audit_entry_mut(&mut self, recommendation_id: &str) -> Result<&mut AuditEntry, OIError> {
        self.audit_trail
            .iter_mut()
            .rev()
            .find(|entry| entry.recommendation_id == recommendation_id)
            .ok_or_else(|| {
                OIError::NoContext(format!(
                    "recommendation {recommendation_id} not present in audit trail"
                ))
            })
    }

    fn recommendation_id(action_key: &str, timestamp: u64, context_fp: [u8; 32]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"operator_intelligence_recommendation_id_v1:");
        hasher.update((action_key.len() as u64).to_le_bytes());
        hasher.update(action_key.as_bytes());
        hasher.update(timestamp.to_le_bytes());
        hasher.update(context_fp);
        format!("{action_key}@{}", hex_encode(hasher.finalize()))
    }

    fn closed_entry(&self, recommendation_id: &str) -> Option<&AuditEntry> {
        self.closed_audit_entries.get(recommendation_id)
    }

    fn closed_decision(&self, recommendation_id: &str) -> Option<RecommendationDecision> {
        self.closed_entry(recommendation_id)
            .map(|entry| entry.decision)
    }

    fn remember_closed_entry(&mut self, entry: AuditEntry) {
        if entry.decision == RecommendationDecision::Pending {
            return;
        }

        if let Some(existing) = self.closed_audit_entries.get_mut(&entry.recommendation_id) {
            *existing = entry;
            return;
        }

        let recommendation_id = entry.recommendation_id.clone();
        self.closed_audit_entries
            .insert(recommendation_id.clone(), entry);
        while self.closed_audit_order.len() >= MAX_AUDIT_TRAIL_ENTRIES {
            if let Some(oldest) = self.closed_audit_order.pop_front() {
                self.closed_audit_entries.remove(&oldest);
            }
        }
        self.closed_audit_order.push_back(recommendation_id);
    }

    /// Generate recommendations for the given context.
    /// INV-OIR-DETERMINISTIC: same inputs produce identical outputs.
    pub fn recommend(
        &mut self,
        ctx: &OperatorContext,
        timestamp: u64,
    ) -> Result<Vec<Recommendation>, OIError> {
        ctx.validate()?;

        let base_loss = compute_expected_loss(ctx);
        let base_confidence = compute_confidence(ctx);

        let actions = generate_actions(ctx);
        let context_fp = ctx.fingerprint();

        let mut candidates = Vec::new();
        for (i, (action_key, action, prereqs, time_ms)) in actions.iter().enumerate() {
            // Scale expected loss per action: base loss * action-specific weight.
            let action_loss = base_loss * (1.0 / (i as f64 + 1.0));

            // Apply degraded-mode confidence penalty.
            let mut confidence = base_confidence;
            let mut degraded_warning = None;
            if self.degraded {
                confidence *= self.config.degraded_confidence_penalty;
                let warning = format!(
                    "degraded mode: missing sources {:?}; confidence reduced",
                    self.missing_sources
                );
                degraded_warning = Some(warning.clone());
                push_bounded(
                    &mut self.events,
                    OIEvent {
                        code: EVT_DEGRADED_MODE_WARNING.to_string(),
                        detail: warning,
                    },
                    MAX_EVENTS,
                );
            }

            // Skip recommendations below confidence threshold.
            if confidence < self.config.confidence_threshold {
                continue;
            }

            candidates.push((
                action_key.clone(),
                action.clone(),
                prereqs.clone(),
                *time_ms,
                action_loss,
                confidence,
                degraded_warning,
            ));
        }

        // Sort by expected loss (highest first) for ranking.
        candidates.sort_by(|a, b| b.4.partial_cmp(&a.4).unwrap_or(std::cmp::Ordering::Equal));

        // Only surfaced recommendations get authoritative IDs and audit entries.
        candidates.truncate(self.config.max_recommendations);

        let mut recommendations = Vec::with_capacity(candidates.len());
        for (
            i,
            (
                action_key,
                action,
                prerequisites,
                estimated_time_ms,
                expected_loss,
                confidence,
                degraded_warning,
            ),
        ) in candidates.into_iter().enumerate()
        {
            let rec = Recommendation {
                id: Self::recommendation_id(&action_key, timestamp, context_fp),
                action,
                expected_loss,
                confidence,
                priority: u32::try_from(i + 1).unwrap_or(u32::MAX),
                prerequisites,
                estimated_time_ms,
                degraded_warning,
            };

            push_bounded(
                &mut self.events,
                OIEvent {
                    code: EVT_RECOMMENDATION_GENERATED.to_string(),
                    detail: format!(
                        "id={}, loss={:.2}, confidence={:.2}",
                        rec.id, rec.expected_loss, rec.confidence
                    ),
                },
                MAX_EVENTS,
            );

            if self.closed_decision(&rec.id).is_none()
                && self
                    .audit_trail
                    .iter()
                    .all(|entry| entry.recommendation_id != rec.id)
            {
                push_bounded(
                    &mut self.audit_trail,
                    AuditEntry {
                        timestamp,
                        recommendation_id: rec.id.clone(),
                        action: rec.action.clone(),
                        decision: RecommendationDecision::Pending,
                        expected_loss: rec.expected_loss,
                        context_fingerprint: context_fp,
                    },
                    MAX_AUDIT_TRAIL_ENTRIES,
                );
            }

            recommendations.push(rec);
        }

        Ok(recommendations)
    }

    /// Accept a recommendation generated by this engine.
    ///
    /// INV-OIR-BUDGET: check cumulative loss against budget.
    /// INV-OIR-AUDIT: acceptance must map to an existing audit entry and
    /// use acceptance-time timestamp.
    pub fn accept_recommendation(
        &mut self,
        rec: &Recommendation,
        timestamp: u64,
    ) -> Result<(), OIError> {
        if let Some(decision) = self.closed_decision(&rec.id) {
            return match decision {
                RecommendationDecision::Accepted => Err(OIError::NoContext(format!(
                    "recommendation {} already accepted",
                    rec.id
                ))),
                RecommendationDecision::Rejected => Err(OIError::NoContext(format!(
                    "recommendation {} already rejected",
                    rec.id
                ))),
                RecommendationDecision::Pending => unreachable!("pending decisions are not cached"),
            };
        }

        let expected_loss = {
            let entry = self.audit_entry(&rec.id)?;
            match entry.decision {
                RecommendationDecision::Pending => {}
                RecommendationDecision::Accepted => {
                    return Err(OIError::NoContext(format!(
                        "recommendation {} already accepted",
                        rec.id
                    )));
                }
                RecommendationDecision::Rejected => {
                    return Err(OIError::NoContext(format!(
                        "recommendation {} already rejected",
                        rec.id
                    )));
                }
            }
            entry.expected_loss
        };

        if !expected_loss.is_finite() {
            return Err(OIError::ScoreOverflow {
                cumulative: self.cumulative_loss,
                budget: self.config.risk_budget,
            });
        }
        let new_cumulative = self.cumulative_loss + expected_loss;
        if !new_cumulative.is_finite() || new_cumulative > self.config.risk_budget {
            return Err(OIError::ScoreOverflow {
                cumulative: new_cumulative,
                budget: self.config.risk_budget,
            });
        }

        let accepted_entry = {
            let entry = self.audit_entry_mut(&rec.id)?;
            entry.decision = RecommendationDecision::Accepted;
            entry.timestamp = timestamp;
            entry.clone()
        };
        self.cumulative_loss = new_cumulative;
        self.remember_closed_entry(accepted_entry);

        push_bounded(
            &mut self.events,
            OIEvent {
                code: EVT_RECOMMENDATION_ACCEPTED.to_string(),
                detail: format!("id={}, cumulative_loss={:.2}", rec.id, self.cumulative_loss),
            },
            MAX_EVENTS,
        );

        Ok(())
    }

    /// Reject a recommendation.
    pub fn reject_recommendation(
        &mut self,
        rec: &Recommendation,
        timestamp: u64,
    ) -> Result<(), OIError> {
        if let Some(decision) = self.closed_decision(&rec.id) {
            return match decision {
                RecommendationDecision::Accepted => Err(OIError::NoContext(format!(
                    "recommendation {} already accepted",
                    rec.id
                ))),
                RecommendationDecision::Rejected => Err(OIError::NoContext(format!(
                    "recommendation {} already rejected",
                    rec.id
                ))),
                RecommendationDecision::Pending => unreachable!("pending decisions are not cached"),
            };
        }

        let rejected_entry = {
            let entry = self.audit_entry_mut(&rec.id)?;
            match entry.decision {
                RecommendationDecision::Pending => {
                    entry.decision = RecommendationDecision::Rejected;
                    entry.timestamp = timestamp;
                    entry.clone()
                }
                RecommendationDecision::Accepted => {
                    return Err(OIError::NoContext(format!(
                        "recommendation {} already accepted",
                        rec.id
                    )));
                }
                RecommendationDecision::Rejected => {
                    return Err(OIError::NoContext(format!(
                        "recommendation {} already rejected",
                        rec.id
                    )));
                }
            }
        };
        self.remember_closed_entry(rejected_entry);

        push_bounded(
            &mut self.events,
            OIEvent {
                code: EVT_RECOMMENDATION_REJECTED.to_string(),
                detail: format!("id={}", rec.id),
            },
            MAX_EVENTS,
        );

        Ok(())
    }

    fn authoritative_audit_entry(&self, recommendation_id: &str) -> Result<&AuditEntry, OIError> {
        if let Ok(entry) = self.audit_entry(recommendation_id) {
            return Ok(entry);
        }
        if let Some(entry) = self.closed_entry(recommendation_id) {
            return Ok(entry);
        }
        Err(OIError::NoContext(format!(
            "recommendation {recommendation_id} not present in audit trail"
        )))
    }

    /// Execute an accepted recommendation and produce rollback proof.
    pub fn execute_recommendation(
        &mut self,
        rec: &Recommendation,
        pre_state: [u8; 32],
        post_state: [u8; 32],
        ctx: &OperatorContext,
    ) -> Result<(RollbackProof, ReplayArtifact), OIError> {
        let context_fp = ctx.fingerprint();
        let (recommendation_id, action, expected_context_fp) = {
            let entry = self.authoritative_audit_entry(&rec.id)?;
            match entry.decision {
                RecommendationDecision::Accepted => {}
                RecommendationDecision::Pending => {
                    return Err(OIError::NoContext(format!(
                        "recommendation {} not accepted",
                        rec.id
                    )));
                }
                RecommendationDecision::Rejected => {
                    return Err(OIError::NoContext(format!(
                        "recommendation {} was rejected",
                        rec.id
                    )));
                }
            }

            (
                entry.recommendation_id.clone(),
                entry.action.clone(),
                entry.context_fingerprint,
            )
        };

        if !constant_time::ct_eq_bytes(&expected_context_fp, &context_fp) {
            return Err(OIError::ReplayMismatch {
                expected: hex_encode(expected_context_fp),
                actual: hex_encode(context_fp),
            });
        }

        let rollback_proof = RollbackProof {
            pre_state_hash: pre_state,
            action_spec: action.clone(),
            post_state_hash: post_state,
            rollback_spec: format!("rollback:{action}"),
        };

        rollback_proof.verify()?;

        push_bounded(
            &mut self.events,
            OIEvent {
                code: EVT_ACTION_EXECUTED.to_string(),
                detail: format!("id={}", rec.id),
            },
            MAX_EVENTS,
        );
        push_bounded(
            &mut self.events,
            OIEvent {
                code: EVT_ROLLBACK_PROOF_CREATED.to_string(),
                detail: format!("id={}", rec.id),
            },
            MAX_EVENTS,
        );

        let replay = ReplayArtifact {
            recommendation_id,
            input_context_fingerprint: context_fp,
            action_executed: action,
            outcome: "success".into(),
            rollback_proof: Some(rollback_proof.clone()),
        };

        push_bounded(
            &mut self.events,
            OIEvent {
                code: EVT_REPLAY_ARTIFACT_CREATED.to_string(),
                detail: format!("id={}", rec.id),
            },
            MAX_EVENTS,
        );

        Ok((rollback_proof, replay))
    }

    /// Execute rollback using a proof.
    pub fn execute_rollback(&mut self, proof: &RollbackProof) -> Result<(), OIError> {
        proof.verify()?;
        push_bounded(
            &mut self.events,
            OIEvent {
                code: EVT_ROLLBACK_PROOF_VERIFIED.to_string(),
                detail: "rollback proof verified".into(),
            },
            MAX_EVENTS,
        );
        push_bounded(
            &mut self.events,
            OIEvent {
                code: EVT_ROLLBACK_EXECUTED.to_string(),
                detail: format!(
                    "restored to pre-state hash {:?}",
                    &proof.pre_state_hash[..proof.pre_state_hash.len().min(4)]
                ),
            },
            MAX_EVENTS,
        );
        Ok(())
    }

    /// Get cumulative expected loss.
    pub fn cumulative_loss(&self) -> f64 {
        self.cumulative_loss
    }

    /// Get audit trail.
    pub fn audit_trail(&self) -> &[AuditEntry] {
        &self.audit_trail
    }

    /// Get events.
    pub fn events(&self) -> &[OIEvent] {
        &self.events
    }

    /// Get config.
    pub fn config(&self) -> &RecommendationConfig {
        &self.config
    }
}

// ---------------------------------------------------------------------------
// Bounded push helper
// ---------------------------------------------------------------------------

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

    fn default_config() -> RecommendationConfig {
        RecommendationConfig::default()
    }

    fn test_context() -> OperatorContext {
        OperatorContext {
            compatibility_pass: 0.85,
            migration_success: 0.75,
            trust_valid: 0.90,
            error_rate: 0.08,
            pending_ops: 5,
            active_alerts: 2,
        }
    }

    fn make_engine() -> RecommendationEngine {
        RecommendationEngine::new(default_config()).unwrap()
    }

    // -- Config validation --

    #[test]
    fn test_default_config_valid() {
        assert!(default_config().validate().is_ok());
    }

    #[test]
    fn test_invalid_max_recommendations() {
        let mut cfg = default_config();
        cfg.max_recommendations = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_invalid_confidence_threshold() {
        let mut cfg = default_config();
        cfg.confidence_threshold = 1.5;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_invalid_risk_budget() {
        let mut cfg = default_config();
        cfg.risk_budget = 0.0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_invalid_degraded_penalty() {
        let mut cfg = default_config();
        cfg.degraded_confidence_penalty = -0.1;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_invalid_confidence_threshold_nan() {
        let mut cfg = default_config();
        cfg.confidence_threshold = f64::NAN;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_invalid_risk_budget_infinity() {
        let mut cfg = default_config();
        cfg.risk_budget = f64::INFINITY;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_invalid_degraded_penalty_nan() {
        let mut cfg = default_config();
        cfg.degraded_confidence_penalty = f64::NAN;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_invalid_confidence_threshold_negative() {
        let mut cfg = default_config();
        cfg.confidence_threshold = -0.01;

        let err = cfg.validate().unwrap_err();

        assert!(matches!(err, OIError::InvalidConfig(_)));
    }

    #[test]
    fn test_engine_new_rejects_invalid_config() {
        let mut cfg = default_config();
        cfg.max_recommendations = 0;

        let err = RecommendationEngine::new(cfg).unwrap_err();

        assert!(matches!(err, OIError::InvalidConfig(_)));
    }

    // -- Context validation --

    #[test]
    fn test_context_valid() {
        assert!(test_context().validate().is_ok());
    }

    #[test]
    fn test_context_invalid_rate() {
        let mut ctx = test_context();
        ctx.compatibility_pass = 1.5;
        assert!(ctx.validate().is_err());
    }

    #[test]
    fn test_context_invalid_nan_migration_success() {
        let mut ctx = test_context();
        ctx.migration_success = f64::NAN;
        assert!(ctx.validate().is_err());
    }

    #[test]
    fn test_context_invalid_negative_error_rate() {
        let mut ctx = test_context();
        ctx.error_rate = -f64::EPSILON;
        assert!(ctx.validate().is_err());
    }

    #[test]
    fn test_context_invalid_trust_rate_above_one() {
        let mut ctx = test_context();
        ctx.trust_valid = 1.0 + f64::EPSILON;
        assert!(ctx.validate().is_err());
    }

    #[test]
    fn test_context_fingerprint_deterministic() {
        // INV-OIR-DETERMINISTIC
        let ctx = test_context();
        let fp1 = ctx.fingerprint();
        let fp2 = ctx.fingerprint();
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn test_context_fingerprint_differs() {
        let ctx1 = test_context();
        let mut ctx2 = test_context();
        ctx2.error_rate = 0.5;
        assert_ne!(ctx1.fingerprint(), ctx2.fingerprint());
    }

    // -- Expected loss scoring --

    #[test]
    fn test_expected_loss_computation() {
        let ctx = test_context();
        let loss = compute_expected_loss(&ctx);
        assert!(loss > 0.0);
    }

    #[test]
    fn test_expected_loss_deterministic() {
        // INV-OIR-DETERMINISTIC
        let ctx = test_context();
        let l1 = compute_expected_loss(&ctx);
        let l2 = compute_expected_loss(&ctx);
        assert!((l1 - l2).abs() < f64::EPSILON);
    }

    #[test]
    fn test_expected_loss_increases_with_error_rate() {
        let mut ctx1 = test_context();
        ctx1.error_rate = 0.01;
        let mut ctx2 = test_context();
        ctx2.error_rate = 0.50;
        assert!(compute_expected_loss(&ctx2) > compute_expected_loss(&ctx1));
    }

    #[test]
    fn test_confidence_computation() {
        let ctx = test_context();
        let conf = compute_confidence(&ctx);
        assert!(conf > 0.0 && conf <= 1.0);
    }

    // -- Recommendation generation --

    #[test]
    fn test_recommend_produces_results() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        assert!(!recs.is_empty());
    }

    #[test]
    fn test_recommend_deterministic() {
        // INV-OIR-DETERMINISTIC
        let mut engine1 = make_engine();
        let mut engine2 = make_engine();
        let ctx = test_context();
        let recs1 = engine1.recommend(&ctx, 1000).unwrap();
        let recs2 = engine2.recommend(&ctx, 1000).unwrap();
        assert_eq!(recs1.len(), recs2.len());
        for (r1, r2) in recs1.iter().zip(recs2.iter()) {
            assert_eq!(r1.id, r2.id);
            assert!((r1.expected_loss - r2.expected_loss).abs() < f64::EPSILON);
        }
    }

    #[test]
    fn test_recommend_repeated_same_inputs_remains_deterministic() {
        let mut engine = make_engine();
        let ctx = test_context();

        let first = engine.recommend(&ctx, 1000).unwrap();
        let second = engine.recommend(&ctx, 1000).unwrap();

        assert_eq!(first.len(), second.len());
        for (left, right) in first.iter().zip(second.iter()) {
            assert_eq!(left.id, right.id);
            assert_eq!(left.action, right.action);
            assert_eq!(left.priority, right.priority);
            assert!((left.expected_loss - right.expected_loss).abs() < f64::EPSILON);
            assert!((left.confidence - right.confidence).abs() < f64::EPSILON);
        }
        assert_eq!(
            engine.audit_trail().len(),
            first.len(),
            "repeated deterministic recommendation runs must reuse audit entries"
        );
    }

    #[test]
    fn test_recommend_sorted_by_loss() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        for w in recs.windows(2) {
            assert!(w[0].expected_loss >= w[1].expected_loss);
        }
    }

    #[test]
    fn test_recommend_max_truncation() {
        let mut cfg = default_config();
        cfg.max_recommendations = 2;
        let mut engine = RecommendationEngine::new(cfg).unwrap();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        assert!(recs.len() <= 2);
    }

    #[test]
    fn test_recommend_rejects_invalid_context_without_side_effects() {
        let mut engine = make_engine();
        let mut ctx = test_context();
        ctx.migration_success = f64::NAN;

        let err = engine.recommend(&ctx, 1000).unwrap_err();

        assert!(matches!(err, OIError::NoContext(_)));
        assert!(engine.audit_trail().is_empty());
        assert!(engine.events().is_empty());
    }

    #[test]
    fn test_high_confidence_threshold_filters_all_recommendations() {
        let mut cfg = default_config();
        cfg.confidence_threshold = 1.0;
        let mut engine = RecommendationEngine::new(cfg).unwrap();
        let ctx = test_context();

        let recs = engine.recommend(&ctx, 1000).unwrap();

        assert!(recs.is_empty());
        assert!(engine.audit_trail().is_empty());
    }

    #[test]
    fn test_degraded_penalty_can_filter_all_recommendations() {
        let mut cfg = default_config();
        cfg.confidence_threshold = 0.1;
        cfg.degraded_confidence_penalty = 0.0;
        let mut engine = RecommendationEngine::new(cfg).unwrap();
        engine.mark_source_unavailable("trust_store");
        let ctx = test_context();

        let recs = engine.recommend(&ctx, 1000).unwrap();

        assert!(recs.is_empty());
        assert!(engine.audit_trail().is_empty());
        assert!(
            engine
                .events()
                .iter()
                .any(|event| event.code == EVT_DEGRADED_MODE_WARNING)
        );
    }

    #[test]
    fn test_audit_trail_only_records_emitted_recommendations() {
        let mut cfg = default_config();
        cfg.max_recommendations = 1;
        let mut engine = RecommendationEngine::new(cfg).unwrap();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();

        assert_eq!(recs.len(), 1);
        assert_eq!(engine.audit_trail().len(), 1);
        assert_eq!(engine.audit_trail()[0].recommendation_id, recs[0].id);
    }

    #[test]
    fn test_recommend_priority_assigned() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        for (i, rec) in recs.iter().enumerate() {
            assert_eq!(rec.priority, (i + 1) as u32);
        }
    }

    // -- Audit trail --

    #[test]
    fn test_audit_trail_recorded() {
        // INV-OIR-AUDIT
        let mut engine = make_engine();
        let ctx = test_context();
        let _ = engine.recommend(&ctx, 1000).unwrap();
        assert!(!engine.audit_trail().is_empty());
    }

    #[test]
    fn test_audit_trail_has_context_fingerprint() {
        let mut engine = make_engine();
        let ctx = test_context();
        let _ = engine.recommend(&ctx, 1000).unwrap();
        let fp = ctx.fingerprint();
        for entry in engine.audit_trail() {
            assert_eq!(entry.context_fingerprint, fp);
        }
    }

    #[test]
    fn test_audit_trail_has_timestamp() {
        let mut engine = make_engine();
        let ctx = test_context();
        let _ = engine.recommend(&ctx, 42).unwrap();
        for entry in engine.audit_trail() {
            assert_eq!(entry.timestamp, 42);
        }
    }

    // -- Accept / reject --

    #[test]
    fn test_accept_recommendation() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        let rec = &recs[0];
        assert!(engine.accept_recommendation(rec, 1001).is_ok());
        assert!(engine.cumulative_loss() > 0.0);
    }

    #[test]
    fn test_accept_updates_audit() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        let rec = &recs[0];
        engine.accept_recommendation(rec, 1001).unwrap();
        let accepted = engine
            .audit_trail()
            .iter()
            .filter(|entry| entry.decision == RecommendationDecision::Accepted)
            .count();
        assert!(accepted > 0);
    }

    #[test]
    fn test_accept_updates_audit_timestamp() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        let rec = &recs[0];

        engine.accept_recommendation(rec, 2000).unwrap();

        let entry = engine
            .audit_trail()
            .iter()
            .find(|e| e.recommendation_id == rec.id)
            .expect("accepted recommendation must exist in audit trail");
        assert_eq!(entry.timestamp, 2000);
        assert_eq!(entry.decision, RecommendationDecision::Accepted);
    }

    #[test]
    fn test_accept_rejects_unknown_recommendation() {
        let mut engine = make_engine();
        let unknown = Recommendation {
            id: "unknown-rec".into(),
            action: "noop".into(),
            expected_loss: 0.1,
            confidence: 0.9,
            priority: 1,
            prerequisites: Vec::new(),
            estimated_time_ms: 1,
            degraded_warning: None,
        };

        let err = engine.accept_recommendation(&unknown, 1234).unwrap_err();
        assert!(matches!(err, OIError::NoContext(_)));
    }

    #[test]
    fn test_accept_rejects_duplicate_acceptance() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        let rec = &recs[0];

        engine.accept_recommendation(rec, 1001).unwrap();
        let loss_after_first = engine.cumulative_loss();
        let err = engine.accept_recommendation(rec, 1002).unwrap_err();
        assert!(matches!(err, OIError::NoContext(_)));
        assert!(
            (engine.cumulative_loss() - loss_after_first).abs() < f64::EPSILON,
            "duplicate acceptance must not change cumulative loss"
        );
    }

    #[test]
    fn test_accept_uses_authoritative_audit_expected_loss() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        let mut forged = recs[0].clone();
        let expected_loss = engine
            .audit_trail()
            .iter()
            .find(|entry| entry.recommendation_id == forged.id)
            .expect("generated recommendation must exist in audit trail")
            .expected_loss;
        forged.expected_loss = 0.0;

        engine.accept_recommendation(&forged, 1001).unwrap();

        assert!(
            (engine.cumulative_loss() - expected_loss).abs() < f64::EPSILON,
            "acceptance must use the audit-trail expected loss"
        );
    }

    #[test]
    fn test_accept_rejects_non_finite_authoritative_loss() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        let rec = recs[0].clone();
        let entry = engine
            .audit_trail
            .iter_mut()
            .find(|entry| entry.recommendation_id == rec.id)
            .expect("generated recommendation should have audit entry");
        entry.expected_loss = f64::INFINITY;

        let err = engine.accept_recommendation(&rec, 1001).unwrap_err();

        assert!(matches!(err, OIError::ScoreOverflow { .. }));
        assert_eq!(engine.cumulative_loss(), 0.0);
    }

    #[test]
    fn test_recommendation_ids_do_not_alias_across_generations() {
        let mut engine = make_engine();
        let first_ctx = test_context();
        let mut second_ctx = test_context();
        second_ctx.error_rate = 0.30;
        second_ctx.active_alerts = 6;

        let first_recs = engine.recommend(&first_ctx, 1000).unwrap();
        let first_health_check = first_recs
            .iter()
            .find(|rec| rec.action == "Run comprehensive system health check")
            .expect("health check recommendation must always be present")
            .clone();

        let second_recs = engine.recommend(&second_ctx, 2000).unwrap();
        let second_health_check = second_recs
            .iter()
            .find(|rec| rec.action == "Run comprehensive system health check")
            .expect("health check recommendation must always be present");

        assert_ne!(first_health_check.id, second_health_check.id);

        engine
            .accept_recommendation(&first_health_check, 3000)
            .unwrap();
        let (_, replay) = engine
            .execute_recommendation(&first_health_check, [1u8; 32], [2u8; 32], &first_ctx)
            .expect("original recommendation should still bind to its original context");
        assert_eq!(replay.input_context_fingerprint, first_ctx.fingerprint());
    }

    #[test]
    fn test_repeated_deterministic_recommendation_does_not_reopen_accepted_entry() {
        let mut engine = make_engine();
        let ctx = test_context();

        let first = engine.recommend(&ctx, 1000).unwrap();
        let rec = first[0].clone();
        engine.accept_recommendation(&rec, 1001).unwrap();

        let repeated = engine.recommend(&ctx, 1000).unwrap();
        let err = engine
            .accept_recommendation(&repeated[0], 1002)
            .unwrap_err();
        assert!(matches!(err, OIError::NoContext(_)));
    }

    #[test]
    fn test_accepted_recommendation_stays_closed_after_audit_eviction() {
        let mut engine = make_engine();
        let ctx = test_context();

        let first = engine.recommend(&ctx, 1000).unwrap();
        let rec = first[0].clone();
        engine.accept_recommendation(&rec, 1001).unwrap();

        let mut churn_timestamp = 2000;
        while engine
            .audit_trail()
            .iter()
            .any(|entry| entry.recommendation_id == rec.id)
        {
            let _ = engine.recommend(&ctx, churn_timestamp).unwrap();
            churn_timestamp = churn_timestamp.saturating_add(1);
        }

        let repeated = engine.recommend(&ctx, 1000).unwrap();
        let err = engine
            .accept_recommendation(&repeated[0], churn_timestamp)
            .unwrap_err();
        assert!(matches!(err, OIError::NoContext(_)));
    }

    #[test]
    fn test_accepted_recommendation_remains_executable_after_audit_eviction() {
        let mut engine = make_engine();
        let ctx = test_context();

        let first = engine.recommend(&ctx, 1000).unwrap();
        let rec = first[0].clone();
        engine.accept_recommendation(&rec, 1001).unwrap();

        let mut churn_timestamp = 2000;
        while engine
            .audit_trail()
            .iter()
            .any(|entry| entry.recommendation_id == rec.id)
        {
            let _ = engine.recommend(&ctx, churn_timestamp).unwrap();
            churn_timestamp = churn_timestamp.saturating_add(1);
        }

        let (_, replay) = engine
            .execute_recommendation(&rec, [0x11; 32], [0x22; 32], &ctx)
            .expect("accepted recommendation should still execute after audit eviction");
        assert_eq!(replay.recommendation_id, rec.id);
        assert_eq!(replay.input_context_fingerprint, ctx.fingerprint());
    }

    #[test]
    fn test_rejected_recommendation_stays_closed_after_audit_eviction() {
        let mut engine = make_engine();
        let ctx = test_context();

        let first = engine.recommend(&ctx, 1000).unwrap();
        let rec = first[0].clone();
        engine.reject_recommendation(&rec, 1001).unwrap();

        let mut churn_timestamp = 2000;
        while engine
            .audit_trail()
            .iter()
            .any(|entry| entry.recommendation_id == rec.id)
        {
            let _ = engine.recommend(&ctx, churn_timestamp).unwrap();
            churn_timestamp = churn_timestamp.saturating_add(1);
        }

        let repeated = engine.recommend(&ctx, 1000).unwrap();
        let err = engine
            .reject_recommendation(&repeated[0], churn_timestamp)
            .unwrap_err();
        assert!(matches!(err, OIError::NoContext(_)));
    }

    #[test]
    fn test_reject_recommendation() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        let rec = &recs[0];

        engine.reject_recommendation(rec, 1001).unwrap();

        let entry = engine
            .audit_trail()
            .iter()
            .find(|entry| entry.recommendation_id == rec.id)
            .expect("rejected recommendation must exist in audit trail");
        assert_eq!(entry.decision, RecommendationDecision::Rejected);
        assert_eq!(entry.timestamp, 1001);
        let has_reject = engine
            .events()
            .iter()
            .any(|e| e.code == EVT_RECOMMENDATION_REJECTED);
        assert!(has_reject);
    }

    #[test]
    fn test_reject_rejects_unknown_recommendation() {
        let mut engine = make_engine();
        let unknown = Recommendation {
            id: "unknown-rec".into(),
            action: "noop".into(),
            expected_loss: 0.1,
            confidence: 0.9,
            priority: 1,
            prerequisites: Vec::new(),
            estimated_time_ms: 1,
            degraded_warning: None,
        };

        let err = engine.reject_recommendation(&unknown, 1234).unwrap_err();
        assert!(matches!(err, OIError::NoContext(_)));
    }

    #[test]
    fn test_reject_rejects_accepted_recommendation() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        let rec = &recs[0];

        engine.accept_recommendation(rec, 1001).unwrap();
        let err = engine.reject_recommendation(rec, 1002).unwrap_err();
        assert!(matches!(err, OIError::NoContext(_)));
    }

    #[test]
    fn test_accept_rejects_previously_rejected_recommendation() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        let rec = &recs[0];

        engine.reject_recommendation(rec, 1001).unwrap();
        let err = engine.accept_recommendation(rec, 1002).unwrap_err();
        assert!(matches!(err, OIError::NoContext(_)));
    }

    #[test]
    fn test_reject_rejects_duplicate_rejection() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        let rec = &recs[0];

        engine.reject_recommendation(rec, 1001).unwrap();
        let err = engine.reject_recommendation(rec, 1002).unwrap_err();

        assert!(matches!(err, OIError::NoContext(_)));
    }

    // -- Budget enforcement --

    #[test]
    fn test_budget_enforcement() {
        // INV-OIR-BUDGET
        let mut cfg = default_config();
        cfg.risk_budget = 1.0; // Very small budget.
        let mut engine = RecommendationEngine::new(cfg).unwrap();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        // Try to accept all — should hit budget.
        let mut hit_budget = false;
        for rec in &recs {
            match engine.accept_recommendation(rec, 1001) {
                Ok(_) => {}
                Err(OIError::ScoreOverflow { .. }) => {
                    hit_budget = true;
                    break;
                }
                Err(e) => unreachable!("Unexpected error: {e}"),
            }
        }
        assert!(hit_budget, "Should have hit budget limit");
    }

    // -- Rollback proof --

    #[test]
    fn test_rollback_proof_verify() {
        // INV-OIR-ROLLBACK-SOUND
        let proof = RollbackProof {
            pre_state_hash: [1u8; 32],
            action_spec: "migrate v2".into(),
            post_state_hash: [2u8; 32],
            rollback_spec: "rollback:migrate v2".into(),
        };
        assert!(proof.verify().unwrap());
    }

    #[test]
    fn test_rollback_proof_empty_action() {
        let proof = RollbackProof {
            pre_state_hash: [1u8; 32],
            action_spec: "".into(),
            post_state_hash: [2u8; 32],
            rollback_spec: "rollback".into(),
        };
        assert!(proof.verify().is_err());
    }

    #[test]
    fn test_rollback_proof_identical_states() {
        let proof = RollbackProof {
            pre_state_hash: [1u8; 32],
            action_spec: "migrate".into(),
            post_state_hash: [1u8; 32],
            rollback_spec: "rollback".into(),
        };
        assert!(proof.verify().is_err());
    }

    #[test]
    fn test_rollback_proof_empty_rollback_spec() {
        let proof = RollbackProof {
            pre_state_hash: [1u8; 32],
            action_spec: "migrate".into(),
            post_state_hash: [2u8; 32],
            rollback_spec: String::new(),
        };
        let err = proof.verify().unwrap_err();
        assert!(matches!(err, OIError::RollbackFailed(_)));
    }

    #[test]
    fn test_rollback_proof_mismatched_rollback_spec() {
        let proof = RollbackProof {
            pre_state_hash: [1u8; 32],
            action_spec: "migrate".into(),
            post_state_hash: [2u8; 32],
            rollback_spec: "rollback:other-action".into(),
        };
        let err = proof.verify().unwrap_err();
        assert!(matches!(err, OIError::RollbackFailed(_)));
    }

    // -- Execute recommendation --

    #[test]
    fn test_execute_recommendation() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        let rec = &recs[0];
        engine.accept_recommendation(rec, 1001).unwrap();
        let result = engine.execute_recommendation(rec, [1u8; 32], [2u8; 32], &ctx);
        assert!(result.is_ok());
        let (proof, replay) = result.unwrap();
        assert_eq!(proof.pre_state_hash, [1u8; 32]);
        assert_eq!(replay.recommendation_id, rec.id);
        assert_eq!(replay.input_context_fingerprint, ctx.fingerprint());
    }

    #[test]
    fn test_execute_recommendation_rejects_unaccepted() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();

        let err = engine
            .execute_recommendation(&recs[0], [1u8; 32], [2u8; 32], &ctx)
            .unwrap_err();
        assert!(matches!(err, OIError::NoContext(_)));
    }

    #[test]
    fn test_execute_recommendation_rejects_rejected_recommendation() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        let rec = &recs[0];

        engine.reject_recommendation(rec, 1001).unwrap();
        let err = engine
            .execute_recommendation(rec, [1u8; 32], [2u8; 32], &ctx)
            .unwrap_err();
        assert!(matches!(err, OIError::NoContext(_)));
    }

    #[test]
    fn test_execute_recommendation_rejects_context_mismatch() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        let rec = &recs[0];
        engine.accept_recommendation(rec, 1001).unwrap();

        let mut mismatched_ctx = test_context();
        mismatched_ctx.error_rate = 0.42;

        let err = engine
            .execute_recommendation(rec, [1u8; 32], [2u8; 32], &mismatched_ctx)
            .unwrap_err();
        assert!(matches!(err, OIError::ReplayMismatch { .. }));
    }

    #[test]
    fn test_execute_recommendation_uses_authoritative_audit_action() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        let rec = &recs[0];
        let expected_action = rec.action.clone();
        engine.accept_recommendation(rec, 1001).unwrap();

        let mut forged = rec.clone();
        forged.action = "tampered".into();

        let (proof, replay) = engine
            .execute_recommendation(&forged, [1u8; 32], [2u8; 32], &ctx)
            .unwrap();
        assert_eq!(proof.action_spec, expected_action);
        assert_eq!(replay.action_executed, expected_action);
    }

    #[test]
    fn test_execute_recommendation_rejects_identical_pre_post_state() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        let rec = &recs[0];
        engine.accept_recommendation(rec, 1001).unwrap();

        let err = engine
            .execute_recommendation(rec, [7u8; 32], [7u8; 32], &ctx)
            .unwrap_err();

        assert!(matches!(err, OIError::RollbackFailed(_)));
    }

    #[test]
    fn test_execute_rollback() {
        let mut engine = make_engine();
        let proof = RollbackProof {
            pre_state_hash: [1u8; 32],
            action_spec: "migrate".into(),
            post_state_hash: [2u8; 32],
            rollback_spec: "rollback:migrate".into(),
        };
        assert!(engine.execute_rollback(&proof).is_ok());
        let has_verified = engine
            .events()
            .iter()
            .any(|e| e.code == EVT_ROLLBACK_PROOF_VERIFIED);
        let has_executed = engine
            .events()
            .iter()
            .any(|e| e.code == EVT_ROLLBACK_EXECUTED);
        assert!(has_verified);
        assert!(has_executed);
    }

    #[test]
    fn test_execute_rollback_rejects_invalid_proof_without_events() {
        let mut engine = make_engine();
        let proof = RollbackProof {
            pre_state_hash: [1u8; 32],
            action_spec: "migrate".into(),
            post_state_hash: [2u8; 32],
            rollback_spec: "rollback:wrong".into(),
        };

        let err = engine.execute_rollback(&proof).unwrap_err();

        assert!(matches!(err, OIError::RollbackFailed(_)));
        assert!(
            !engine
                .events()
                .iter()
                .any(|e| e.code == EVT_ROLLBACK_PROOF_VERIFIED)
        );
        assert!(
            !engine
                .events()
                .iter()
                .any(|e| e.code == EVT_ROLLBACK_EXECUTED)
        );
    }

    // -- Replay artifact --

    #[test]
    fn test_replay_artifact_created() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        let rec = &recs[0];
        engine.accept_recommendation(rec, 1001).unwrap();
        let (_, replay) = engine
            .execute_recommendation(rec, [1u8; 32], [2u8; 32], &ctx)
            .unwrap();
        assert_eq!(replay.recommendation_id, rec.id);
        assert!(replay.rollback_proof.is_some());
    }

    // -- Degraded mode --

    #[test]
    fn test_degraded_mode_entry() {
        let mut engine = make_engine();
        assert!(!engine.is_degraded());
        engine.mark_source_unavailable("historical_data");
        assert!(engine.is_degraded());
    }

    #[test]
    fn test_degraded_mode_confidence_penalty() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs_normal = engine.recommend(&ctx, 1000).unwrap();

        let mut engine2 = make_engine();
        engine2.mark_source_unavailable("historical_data");
        let recs_degraded = engine2.recommend(&ctx, 1000).unwrap();

        // Degraded recommendations should have lower confidence.
        if let (Some(r1), Some(r2)) = (recs_normal.first(), recs_degraded.first()) {
            assert!(r2.confidence <= r1.confidence);
        }
    }

    #[test]
    fn test_degraded_mode_warning_present() {
        let mut engine = make_engine();
        engine.mark_source_unavailable("historical_data");
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        for rec in &recs {
            assert!(rec.degraded_warning.is_some());
        }
    }

    #[test]
    fn test_degraded_mode_clear() {
        let mut engine = make_engine();
        engine.mark_source_unavailable("historical_data");
        assert!(engine.is_degraded());
        engine.clear_degraded();
        assert!(!engine.is_degraded());
    }

    // -- Events --

    #[test]
    fn test_events_recorded() {
        let mut engine = make_engine();
        let ctx = test_context();
        let _ = engine.recommend(&ctx, 1000).unwrap();
        assert!(!engine.events().is_empty());
    }

    #[test]
    fn test_events_contain_recommendation_generated() {
        let mut engine = make_engine();
        let ctx = test_context();
        let _ = engine.recommend(&ctx, 1000).unwrap();
        let has_gen = engine
            .events()
            .iter()
            .any(|e| e.code == EVT_RECOMMENDATION_GENERATED);
        assert!(has_gen);
    }

    // -- Error display --

    #[test]
    fn test_error_display() {
        let err = OIError::InvalidConfig("bad".into());
        assert!(format!("{err}").contains(ERR_OIR_INVALID_CONFIG));

        let err = OIError::NoContext("missing".into());
        assert!(format!("{err}").contains(ERR_OIR_NO_CONTEXT));

        let err = OIError::ScoreOverflow {
            cumulative: 150.0,
            budget: 100.0,
        };
        assert!(format!("{err}").contains(ERR_OIR_SCORE_OVERFLOW));

        let err = OIError::RollbackFailed("bad proof".into());
        assert!(format!("{err}").contains(ERR_OIR_ROLLBACK_FAILED));

        let err = OIError::ReplayMismatch {
            expected: "a".into(),
            actual: "b".into(),
        };
        assert!(format!("{err}").contains(ERR_OIR_REPLAY_MISMATCH));

        let err = OIError::Degraded("source down".into());
        assert!(format!("{err}").contains(ERR_OIR_DEGRADED));
    }

    // -- Generate actions --

    #[test]
    fn test_generate_actions_always_includes_health_check() {
        let ctx = OperatorContext {
            compatibility_pass: 1.0,
            migration_success: 1.0,
            trust_valid: 1.0,
            error_rate: 0.0,
            pending_ops: 0,
            active_alerts: 0,
        };
        let actions = generate_actions(&ctx);
        assert!(actions.iter().any(|(id, _, _, _)| id == "health_check"));
    }

    #[test]
    fn test_generate_actions_compat_trigger() {
        let ctx = test_context(); // compat_pass = 0.85 < 0.9
        let actions = generate_actions(&ctx);
        assert!(actions.iter().any(|(id, _, _, _)| id == "run_compat_suite"));
    }

    #[test]
    fn negative_push_bounded_zero_capacity_drops_existing_items_without_panic() {
        let mut items = vec!["old", "older"];

        push_bounded(&mut items, "new", 0);

        assert!(items.is_empty());
    }

    #[test]
    fn negative_config_rejects_nan_risk_budget() {
        let mut cfg = default_config();
        cfg.risk_budget = f64::NAN;

        let err = cfg.validate().unwrap_err();

        assert!(matches!(err, OIError::InvalidConfig(_)));
    }

    #[test]
    fn negative_config_rejects_negative_infinite_confidence_threshold() {
        let mut cfg = default_config();
        cfg.confidence_threshold = f64::NEG_INFINITY;

        let err = cfg.validate().unwrap_err();

        assert!(matches!(err, OIError::InvalidConfig(_)));
    }

    #[test]
    fn negative_context_rejects_infinite_compatibility_rate_without_fingerprint_side_effects() {
        let mut engine = make_engine();
        let mut ctx = test_context();
        ctx.compatibility_pass = f64::INFINITY;

        let err = engine.recommend(&ctx, 1000).unwrap_err();

        assert!(matches!(err, OIError::NoContext(_)));
        assert!(engine.audit_trail().is_empty());
        assert!(engine.events().is_empty());
    }

    #[test]
    fn negative_duplicate_missing_source_does_not_duplicate_degraded_state() {
        let mut engine = make_engine();

        engine.mark_source_unavailable("metrics");
        engine.mark_source_unavailable("metrics");

        assert!(engine.is_degraded());
        assert_eq!(engine.missing_sources, vec!["metrics".to_string()]);
        assert_eq!(
            engine
                .events()
                .iter()
                .filter(|event| event.code == EVT_DEGRADED_MODE_ENTERED)
                .count(),
            1
        );
    }

    #[test]
    fn negative_clear_degraded_removes_all_missing_sources_without_clearing_audit() {
        let mut engine = make_engine();
        let ctx = test_context();
        let _ = engine.recommend(&ctx, 1000).unwrap();
        let audit_len = engine.audit_trail().len();

        engine.mark_source_unavailable("metrics");
        engine.mark_source_unavailable("history");
        engine.clear_degraded();

        assert!(!engine.is_degraded());
        assert!(engine.missing_sources.is_empty());
        assert_eq!(engine.audit_trail().len(), audit_len);
    }

    #[test]
    fn negative_reject_after_forged_acceptance_uses_authoritative_closed_decision() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        let mut forged = recs[0].clone();
        engine.accept_recommendation(&forged, 1001).unwrap();
        forged.expected_loss = 0.0;
        forged.action = "forged-action".to_string();

        let err = engine.reject_recommendation(&forged, 1002).unwrap_err();

        assert!(matches!(err, OIError::NoContext(_)));
    }

    #[test]
    fn negative_rollback_proof_content_changes_when_rollback_spec_is_tampered() {
        let proof = RollbackProof {
            pre_state_hash: [1u8; 32],
            action_spec: "migrate".to_string(),
            post_state_hash: [2u8; 32],
            rollback_spec: "rollback:migrate".to_string(),
        };
        let mut tampered = proof.clone();
        tampered.rollback_spec = "rollback:other".to_string();

        assert_ne!(proof.content_hash(), tampered.content_hash());
        assert!(tampered.verify().is_err());
    }
}
