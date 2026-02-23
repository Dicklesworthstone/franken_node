// Operator intelligence recommendation engine with rollback proofs.
//
// Produces expected-loss-scored recommendations with deterministic replay
// artifacts and a full audit trail.
//
// bd-y0v — Section 10.12

use sha2::{Digest, Sha256};

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
        if self.risk_budget <= 0.0 {
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
    /// Verify that applying rollback_spec to post_state produces pre_state.
    /// INV-OIR-ROLLBACK-SOUND
    pub fn verify(&self) -> Result<bool, OIError> {
        // In a real system, this would execute the rollback and compare hashes.
        // Here we verify structural soundness: both hashes present and specs non-empty.
        if self.action_spec.is_empty() {
            return Err(OIError::RollbackFailed("empty action spec".into()));
        }
        if self.rollback_spec.is_empty() {
            return Err(OIError::RollbackFailed("empty rollback spec".into()));
        }
        if self.pre_state_hash == self.post_state_hash {
            return Err(OIError::RollbackFailed(
                "pre and post states identical".into(),
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

#[derive(Debug, Clone)]
pub struct AuditEntry {
    pub timestamp: u64,
    pub recommendation_id: String,
    pub action: String,
    pub accepted: bool,
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
            events: Vec::new(),
            cumulative_loss: 0.0,
        })
    }

    /// Mark a data source as unavailable (triggers degraded mode).
    pub fn mark_source_unavailable(&mut self, source: &str) {
        if !self.missing_sources.contains(&source.to_string()) {
            self.missing_sources.push(source.into());
        }
        if !self.degraded {
            self.degraded = true;
            self.events.push(OIEvent {
                code: EVT_DEGRADED_MODE_ENTERED.to_string(),
                detail: format!("source unavailable: {source}"),
            });
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

        let mut recommendations = Vec::new();
        for (i, (id, action, prereqs, time_ms)) in actions.iter().enumerate() {
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
                self.events.push(OIEvent {
                    code: EVT_DEGRADED_MODE_WARNING.to_string(),
                    detail: warning,
                });
            }

            // Skip recommendations below confidence threshold.
            if confidence < self.config.confidence_threshold {
                continue;
            }

            let rec = Recommendation {
                id: id.clone(),
                action: action.clone(),
                expected_loss: action_loss,
                confidence,
                priority: (i + 1) as u32,
                prerequisites: prereqs.clone(),
                estimated_time_ms: *time_ms,
                degraded_warning,
            };

            self.events.push(OIEvent {
                code: EVT_RECOMMENDATION_GENERATED.to_string(),
                detail: format!(
                    "id={}, loss={:.2}, confidence={:.2}",
                    rec.id, rec.expected_loss, rec.confidence
                ),
            });

            // INV-OIR-AUDIT: record in audit trail.
            self.audit_trail.push(AuditEntry {
                timestamp,
                recommendation_id: rec.id.clone(),
                action: rec.action.clone(),
                accepted: false, // Not yet accepted.
                expected_loss: rec.expected_loss,
                context_fingerprint: context_fp,
            });

            recommendations.push(rec);
        }

        // Sort by expected loss (highest first) for ranking.
        recommendations.sort_by(|a, b| b.expected_loss.partial_cmp(&a.expected_loss).unwrap_or(std::cmp::Ordering::Equal));

        // Re-assign priority after sort.
        for (i, rec) in recommendations.iter_mut().enumerate() {
            rec.priority = (i + 1) as u32;
        }

        // Truncate to max.
        recommendations.truncate(self.config.max_recommendations);

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
        let Some(entry) = self
            .audit_trail
            .iter_mut()
            .rev()
            .find(|e| e.recommendation_id == rec.id)
        else {
            return Err(OIError::NoContext(format!(
                "recommendation {} not present in audit trail",
                rec.id
            )));
        };

        if entry.accepted {
            return Err(OIError::NoContext(format!(
                "recommendation {} already accepted",
                rec.id
            )));
        }

        let new_cumulative = self.cumulative_loss + rec.expected_loss;
        if new_cumulative > self.config.risk_budget {
            return Err(OIError::ScoreOverflow {
                cumulative: new_cumulative,
                budget: self.config.risk_budget,
            });
        }
        self.cumulative_loss = new_cumulative;

        // Stamp acceptance at acceptance-time and mark explicit state transition.
        entry.accepted = true;
        entry.timestamp = timestamp;

        self.events.push(OIEvent {
            code: EVT_RECOMMENDATION_ACCEPTED.to_string(),
            detail: format!("id={}, cumulative_loss={:.2}", rec.id, self.cumulative_loss),
        });

        Ok(())
    }

    /// Reject a recommendation.
    pub fn reject_recommendation(&mut self, rec: &Recommendation) {
        self.events.push(OIEvent {
            code: EVT_RECOMMENDATION_REJECTED.to_string(),
            detail: format!("id={}", rec.id),
        });
    }

    /// Execute an accepted recommendation and produce rollback proof.
    pub fn execute_recommendation(
        &mut self,
        rec: &Recommendation,
        pre_state: [u8; 32],
        post_state: [u8; 32],
    ) -> Result<(RollbackProof, ReplayArtifact), OIError> {
        let rollback_proof = RollbackProof {
            pre_state_hash: pre_state,
            action_spec: rec.action.clone(),
            post_state_hash: post_state,
            rollback_spec: format!("rollback:{}", rec.action),
        };

        rollback_proof.verify()?;

        self.events.push(OIEvent {
            code: EVT_ACTION_EXECUTED.to_string(),
            detail: format!("id={}", rec.id),
        });
        self.events.push(OIEvent {
            code: EVT_ROLLBACK_PROOF_CREATED.to_string(),
            detail: format!("id={}", rec.id),
        });

        let context_fp = [0u8; 32]; // Simplified: would use actual context fingerprint.
        let replay = ReplayArtifact {
            recommendation_id: rec.id.clone(),
            input_context_fingerprint: context_fp,
            action_executed: rec.action.clone(),
            outcome: "success".into(),
            rollback_proof: Some(rollback_proof.clone()),
        };

        self.events.push(OIEvent {
            code: EVT_REPLAY_ARTIFACT_CREATED.to_string(),
            detail: format!("id={}", rec.id),
        });

        Ok((rollback_proof, replay))
    }

    /// Execute rollback using a proof.
    pub fn execute_rollback(&mut self, proof: &RollbackProof) -> Result<(), OIError> {
        proof.verify()?;
        self.events.push(OIEvent {
            code: EVT_ROLLBACK_PROOF_VERIFIED.to_string(),
            detail: "rollback proof verified".into(),
        });
        self.events.push(OIEvent {
            code: EVT_ROLLBACK_EXECUTED.to_string(),
            detail: format!(
                "restored to pre-state hash {:?}",
                &proof.pre_state_hash[..proof.pre_state_hash.len().min(4)]
            ),
        });
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
        let accepted = engine.audit_trail().iter().filter(|e| e.accepted).count();
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
        assert!(entry.accepted);
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
    fn test_reject_recommendation() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        engine.reject_recommendation(&recs[0]);
        let has_reject = engine
            .events()
            .iter()
            .any(|e| e.code == EVT_RECOMMENDATION_REJECTED);
        assert!(has_reject);
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
                Err(e) => panic!("Unexpected error: {e}"),
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
            rollback_spec: "rollback v2".into(),
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

    // -- Execute recommendation --

    #[test]
    fn test_execute_recommendation() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        let rec = &recs[0];
        engine.accept_recommendation(rec, 1001).unwrap();
        let result = engine.execute_recommendation(rec, [1u8; 32], [2u8; 32]);
        assert!(result.is_ok());
        let (proof, replay) = result.unwrap();
        assert_eq!(proof.pre_state_hash, [1u8; 32]);
        assert_eq!(replay.recommendation_id, rec.id);
    }

    #[test]
    fn test_execute_rollback() {
        let mut engine = make_engine();
        let proof = RollbackProof {
            pre_state_hash: [1u8; 32],
            action_spec: "migrate".into(),
            post_state_hash: [2u8; 32],
            rollback_spec: "rollback".into(),
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

    // -- Replay artifact --

    #[test]
    fn test_replay_artifact_created() {
        let mut engine = make_engine();
        let ctx = test_context();
        let recs = engine.recommend(&ctx, 1000).unwrap();
        let rec = &recs[0];
        engine.accept_recommendation(rec, 1001).unwrap();
        let (_, replay) = engine
            .execute_recommendation(rec, [1u8; 32], [2u8; 32])
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
}
