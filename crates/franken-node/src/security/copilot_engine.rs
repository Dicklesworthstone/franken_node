//! bd-2yc: Operator copilot action recommendation API.
//!
//! Implements Section 10.5 operator copilot: VOI-based action ranking, expected-loss
//! vectors, uncertainty bands, confidence context, and deterministic rollback commands.
//! Consumes expected-loss scoring, integrates degraded-mode status, and records every
//! recommendation in the audit trail.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

// ── Event codes ──────────────────────────────────────────────────────────────

pub const COPILOT_RECOMMENDATION_REQUESTED: &str = "COPILOT_RECOMMENDATION_REQUESTED";
pub const COPILOT_RECOMMENDATION_SERVED: &str = "COPILOT_RECOMMENDATION_SERVED";
pub const COPILOT_ROLLBACK_VALIDATED: &str = "COPILOT_ROLLBACK_VALIDATED";
pub const COPILOT_DEGRADED_WARNING: &str = "COPILOT_DEGRADED_WARNING";
pub const COPILOT_STREAM_STARTED: &str = "COPILOT_STREAM_STARTED";
pub const COPILOT_STREAM_UPDATED: &str = "COPILOT_STREAM_UPDATED";

// ── Expected-loss vector ─────────────────────────────────────────────────────

/// Expected-loss vector with named dimensions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExpectedLossVector {
    /// Availability impact (non-negative).
    pub availability_loss: f64,
    /// Integrity impact (non-negative).
    pub integrity_loss: f64,
    /// Confidentiality impact (non-negative).
    pub confidentiality_loss: f64,
    /// Financial impact (non-negative).
    pub financial_loss: f64,
    /// Reputation impact (non-negative).
    pub reputation_loss: f64,
}

impl ExpectedLossVector {
    /// Validate all values are non-negative.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.availability_loss >= 0.0
            && self.integrity_loss >= 0.0
            && self.confidentiality_loss >= 0.0
            && self.financial_loss >= 0.0
            && self.reputation_loss >= 0.0
    }

    /// Total expected loss across all dimensions.
    #[must_use]
    pub fn total(&self) -> f64 {
        self.availability_loss
            + self.integrity_loss
            + self.confidentiality_loss
            + self.financial_loss
            + self.reputation_loss
    }

    /// Dominant loss dimension name.
    #[must_use]
    pub fn dominant_dimension(&self) -> &str {
        let dims = [
            ("availability", self.availability_loss),
            ("integrity", self.integrity_loss),
            ("confidentiality", self.confidentiality_loss),
            ("financial", self.financial_loss),
            ("reputation", self.reputation_loss),
        ];
        dims.iter()
            .max_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
            .map(|(name, _)| *name)
            .unwrap_or("unknown")
    }
}

// ── Confidence interval ──────────────────────────────────────────────────────

/// Confidence interval for uncertainty quantification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    /// Lower bound.
    pub lower_bound: f64,
    /// Upper bound.
    pub upper_bound: f64,
    /// Confidence level (0.0..=1.0), e.g., 0.95 for 95%.
    pub confidence_level: f64,
}

impl ConfidenceInterval {
    /// Check that the interval is non-degenerate (upper > lower).
    #[must_use]
    pub fn is_non_degenerate(&self) -> bool {
        self.upper_bound > self.lower_bound
    }
}

// ── Confidence context ───────────────────────────────────────────────────────

/// Structured confidence context explaining a recommendation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceContext {
    /// Data sources that informed this recommendation.
    pub data_sources: Vec<DataSourceInfo>,
    /// Key assumptions the scoring depends on.
    pub assumptions: Vec<String>,
    /// Sensitivity indicator: what change would flip the recommendation.
    pub sensitivity: String,
}

/// Information about a data source.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DataSourceInfo {
    /// Source identifier.
    pub source_id: String,
    /// Freshness timestamp (RFC 3339).
    pub freshness: String,
    /// Whether the source is stale.
    pub is_stale: bool,
    /// Staleness duration in seconds (0 if fresh).
    pub staleness_secs: u64,
}

// ── Action candidate (input) ─────────────────────────────────────────────────

/// An action candidate for the copilot to evaluate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionCandidate {
    /// Unique action identifier.
    pub action_id: String,
    /// Human-readable name.
    pub display_name: String,
    /// Description of the action.
    pub description: String,
    /// Expected loss if the action is taken.
    pub expected_loss_if_act: ExpectedLossVector,
    /// Expected loss if the operator waits (does not act).
    pub expected_loss_if_wait: ExpectedLossVector,
    /// Uncertainty band.
    pub uncertainty_band: ConfidenceInterval,
    /// Preconditions (gate passes required).
    pub preconditions: Vec<String>,
    /// Estimated duration.
    pub estimated_duration: Duration,
    /// Deterministic rollback command.
    pub rollback_command: String,
    /// Whether the rollback command has been validated.
    pub rollback_validated: bool,
    /// Confidence context.
    pub confidence: ConfidenceContext,
}

// ── System state (input) ─────────────────────────────────────────────────────

/// Current system state for the copilot engine.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SystemState {
    /// Whether the system is in degraded mode.
    pub degraded_mode: bool,
    /// Degraded-mode details (if applicable).
    pub degraded_details: Option<DegradedModeInfo>,
    /// Active incident IDs.
    pub active_incidents: Vec<String>,
    /// Trust state freshness (seconds since last update).
    pub trust_state_age_secs: u64,
    /// Pending operations.
    pub pending_operations: Vec<String>,
}

/// Degraded-mode information.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DegradedModeInfo {
    /// Stale inputs and their staleness.
    pub stale_inputs: Vec<StaleInput>,
    /// Overall degraded-mode reason.
    pub reason: String,
    /// When degraded mode was entered (RFC 3339).
    pub entered_at: String,
}

/// A single stale input that contributes to degraded mode.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StaleInput {
    /// Input identifier.
    pub input_id: String,
    /// Staleness duration in seconds.
    pub staleness_secs: u64,
    /// Expected refresh interval in seconds.
    pub expected_refresh_secs: u64,
}

// ── Recommended action (output) ──────────────────────────────────────────────

/// A recommended action from the copilot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RecommendedAction {
    /// Action identifier.
    pub action_id: String,
    /// Human-readable name.
    pub display_name: String,
    /// Description.
    pub description: String,
    /// VOI score (higher = more valuable to act on).
    pub voi_score: f64,
    /// Expected loss vector.
    pub expected_loss: ExpectedLossVector,
    /// Uncertainty band.
    pub uncertainty_band: ConfidenceInterval,
    /// Preconditions.
    pub preconditions: Vec<String>,
    /// Estimated duration.
    pub estimated_duration: Duration,
    /// Deterministic rollback command.
    pub rollback_command: String,
    /// Whether rollback command is validated.
    pub rollback_validated: bool,
    /// Human-readable rationale.
    pub rationale: String,
    /// Confidence context.
    pub confidence: ConfidenceContext,
    /// Whether this recommendation is affected by degraded mode.
    pub degraded_confidence: bool,
    /// Adjusted uncertainty if degraded.
    pub adjusted_uncertainty: Option<ConfidenceInterval>,
}

// ── Copilot response ─────────────────────────────────────────────────────────

/// Full copilot response.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CopilotResponse {
    /// Unique recommendation ID.
    pub recommendation_id: String,
    /// Ranked recommendations (highest VOI first).
    pub recommendations: Vec<RecommendedAction>,
    /// System state snapshot.
    pub system_degraded: bool,
    /// Degraded-mode warning block (if applicable).
    pub degraded_warning: Option<DegradedWarning>,
    /// Timestamp (RFC 3339).
    pub served_at: String,
    /// Trace ID.
    pub trace_id: String,
}

/// Degraded-mode warning block.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DegradedWarning {
    /// Warning message.
    pub message: String,
    /// Stale inputs.
    pub stale_inputs: Vec<StaleInput>,
    /// Overall staleness duration.
    pub max_staleness_secs: u64,
}

// ── Audit entry ──────────────────────────────────────────────────────────────

/// Audit record for a served recommendation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CopilotAuditEntry {
    /// Recommendation ID.
    pub recommendation_id: String,
    /// Operator identity.
    pub operator_identity: String,
    /// Trace ID.
    pub trace_id: String,
    /// Number of recommendations served.
    pub recommendation_count: usize,
    /// Top action ID.
    pub top_action_id: Option<String>,
    /// Top VOI score.
    pub top_voi_score: Option<f64>,
    /// Timestamp.
    pub served_at: String,
    /// Event code.
    pub event_code: String,
}

// ── VOI computation ──────────────────────────────────────────────────────────

/// Compute Value-of-Information for an action candidate.
///
/// VOI = expected_gain_if_act - expected_gain_if_wait
///     = expected_loss_if_wait.total() - expected_loss_if_act.total()
///
/// Higher VOI means the action is more valuable.
#[must_use]
pub fn compute_voi(action: &ActionCandidate, _state: &SystemState) -> f64 {
    let loss_if_wait = action.expected_loss_if_wait.total();
    let loss_if_act = action.expected_loss_if_act.total();
    loss_if_wait - loss_if_act
}

// ── Action recommendation engine ─────────────────────────────────────────────

/// The copilot recommendation engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActionRecommendationEngine {
    /// Maximum recommendations to return.
    top_k: usize,
    /// Audit trail.
    audit_trail: Vec<CopilotAuditEntry>,
    /// Total recommendations served.
    total_served: u64,
}

impl Default for ActionRecommendationEngine {
    fn default() -> Self {
        Self::new(5)
    }
}

impl ActionRecommendationEngine {
    /// Create with custom top_k.
    #[must_use]
    pub fn new(top_k: usize) -> Self {
        Self {
            top_k: top_k.max(1),
            audit_trail: Vec::new(),
            total_served: 0,
        }
    }

    /// Generate ranked action recommendations.
    pub fn recommend(
        &mut self,
        candidates: &[ActionCandidate],
        state: &SystemState,
        operator_identity: &str,
        recommendation_id: &str,
        trace_id: &str,
        timestamp: &str,
    ) -> CopilotResponse {
        // Score all candidates by VOI.
        let mut scored: Vec<(f64, &ActionCandidate)> = candidates
            .iter()
            .map(|c| (compute_voi(c, state), c))
            .collect();

        // Sort descending by VOI.
        scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));

        // Take top_k.
        scored.truncate(self.top_k);

        // Build recommendations.
        let recommendations: Vec<RecommendedAction> = scored
            .iter()
            .map(|(voi, candidate)| {
                let dominant = candidate.expected_loss_if_act.dominant_dimension();
                let degraded_confidence = state.degraded_mode;

                let adjusted_uncertainty = if degraded_confidence {
                    // Widen uncertainty band by 50% under degraded mode.
                    Some(ConfidenceInterval {
                        lower_bound: candidate.uncertainty_band.lower_bound * 0.75,
                        upper_bound: candidate.uncertainty_band.upper_bound * 1.5,
                        confidence_level: candidate.uncertainty_band.confidence_level * 0.8,
                    })
                } else {
                    None
                };

                let rationale = format!(
                    "VOI={voi:.2}: acting reduces expected loss by {voi:.2} units vs waiting. \
                     Dominant dimension: {dominant}."
                );

                RecommendedAction {
                    action_id: candidate.action_id.clone(),
                    display_name: candidate.display_name.clone(),
                    description: candidate.description.clone(),
                    voi_score: *voi,
                    expected_loss: candidate.expected_loss_if_act.clone(),
                    uncertainty_band: candidate.uncertainty_band.clone(),
                    preconditions: candidate.preconditions.clone(),
                    estimated_duration: candidate.estimated_duration,
                    rollback_command: candidate.rollback_command.clone(),
                    rollback_validated: candidate.rollback_validated,
                    rationale,
                    confidence: candidate.confidence.clone(),
                    degraded_confidence,
                    adjusted_uncertainty,
                }
            })
            .collect();

        // Degraded warning.
        let degraded_warning = if state.degraded_mode {
            state.degraded_details.as_ref().map(|d| DegradedWarning {
                message: format!("System in degraded mode: {}", d.reason),
                stale_inputs: d.stale_inputs.clone(),
                max_staleness_secs: d.stale_inputs.iter().map(|s| s.staleness_secs).max().unwrap_or(0),
            })
        } else {
            None
        };

        let response = CopilotResponse {
            recommendation_id: recommendation_id.to_owned(),
            recommendations: recommendations.clone(),
            system_degraded: state.degraded_mode,
            degraded_warning,
            served_at: timestamp.to_owned(),
            trace_id: trace_id.to_owned(),
        };

        // Audit trail.
        let audit = CopilotAuditEntry {
            recommendation_id: recommendation_id.to_owned(),
            operator_identity: operator_identity.to_owned(),
            trace_id: trace_id.to_owned(),
            recommendation_count: recommendations.len(),
            top_action_id: recommendations.first().map(|r| r.action_id.clone()),
            top_voi_score: recommendations.first().map(|r| r.voi_score),
            served_at: timestamp.to_owned(),
            event_code: COPILOT_RECOMMENDATION_SERVED.to_owned(),
        };
        self.audit_trail.push(audit);
        self.total_served += 1;

        response
    }

    /// Get the audit trail.
    #[must_use]
    pub fn audit_trail(&self) -> &[CopilotAuditEntry] {
        &self.audit_trail
    }

    /// Total recommendations served.
    #[must_use]
    pub fn total_served(&self) -> u64 {
        self.total_served
    }

    /// Get top_k setting.
    #[must_use]
    pub fn top_k(&self) -> usize {
        self.top_k
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn make_state(degraded: bool) -> SystemState {
        SystemState {
            degraded_mode: degraded,
            degraded_details: if degraded {
                Some(DegradedModeInfo {
                    stale_inputs: vec![StaleInput {
                        input_id: "trust-db".to_owned(),
                        staleness_secs: 300,
                        expected_refresh_secs: 60,
                    }],
                    reason: "Trust database stale".to_owned(),
                    entered_at: "2026-01-15T00:00:00Z".to_owned(),
                })
            } else {
                None
            },
            active_incidents: vec![],
            trust_state_age_secs: 10,
            pending_operations: vec![],
        }
    }

    fn make_candidate(id: &str, loss_act: f64, loss_wait: f64) -> ActionCandidate {
        ActionCandidate {
            action_id: id.to_owned(),
            display_name: format!("Action {id}"),
            description: format!("Test action {id}"),
            expected_loss_if_act: ExpectedLossVector {
                availability_loss: loss_act * 0.3,
                integrity_loss: loss_act * 0.2,
                confidentiality_loss: loss_act * 0.1,
                financial_loss: loss_act * 0.25,
                reputation_loss: loss_act * 0.15,
            },
            expected_loss_if_wait: ExpectedLossVector {
                availability_loss: loss_wait * 0.3,
                integrity_loss: loss_wait * 0.2,
                confidentiality_loss: loss_wait * 0.1,
                financial_loss: loss_wait * 0.25,
                reputation_loss: loss_wait * 0.15,
            },
            uncertainty_band: ConfidenceInterval {
                lower_bound: loss_act * 0.8,
                upper_bound: loss_wait * 1.2,
                confidence_level: 0.95,
            },
            preconditions: vec![],
            estimated_duration: Duration::from_secs(60),
            rollback_command: format!("rollback --action {id}"),
            rollback_validated: true,
            confidence: ConfidenceContext {
                data_sources: vec![DataSourceInfo {
                    source_id: "trust-db".to_owned(),
                    freshness: "2026-01-15T00:00:00Z".to_owned(),
                    is_stale: false,
                    staleness_secs: 0,
                }],
                assumptions: vec!["Trust data is fresh".to_owned()],
                sensitivity: "A 20% increase in trust staleness would change the ranking".to_owned(),
            },
        }
    }

    #[test]
    fn test_compute_voi() {
        let state = make_state(false);
        let candidate = make_candidate("a1", 10.0, 50.0);
        let voi = compute_voi(&candidate, &state);
        // VOI = loss_if_wait - loss_if_act = 50 - 10 = 40
        assert!((voi - 40.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_voi_ranking_order() {
        let mut engine = ActionRecommendationEngine::new(10);
        let state = make_state(false);
        let candidates = vec![
            make_candidate("low-voi", 40.0, 50.0),    // VOI = 10
            make_candidate("high-voi", 5.0, 100.0),   // VOI = 95
            make_candidate("mid-voi", 20.0, 60.0),    // VOI = 40
        ];

        let response = engine.recommend(&candidates, &state, "operator-1", "rec-001", "t-001", "2026-01-15T00:00:00Z");

        assert_eq!(response.recommendations[0].action_id, "high-voi");
        assert_eq!(response.recommendations[1].action_id, "mid-voi");
        assert_eq!(response.recommendations[2].action_id, "low-voi");
    }

    #[test]
    fn test_top_k_limiting() {
        let mut engine = ActionRecommendationEngine::new(2);
        let state = make_state(false);
        let candidates: Vec<_> = (0..10).map(|i| make_candidate(&format!("a{i}"), 10.0, 50.0 + i as f64)).collect();

        let response = engine.recommend(&candidates, &state, "op", "rec-001", "t-001", "2026-01-15T00:00:00Z");
        assert_eq!(response.recommendations.len(), 2);
    }

    #[test]
    fn test_empty_candidates() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);
        let response = engine.recommend(&[], &state, "op", "rec-001", "t-001", "2026-01-15T00:00:00Z");
        assert!(response.recommendations.is_empty());
    }

    #[test]
    fn test_degraded_mode_warning() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(true);
        let candidates = vec![make_candidate("a1", 10.0, 50.0)];

        let response = engine.recommend(&candidates, &state, "op", "rec-001", "t-001", "2026-01-15T00:00:00Z");
        assert!(response.system_degraded);
        assert!(response.degraded_warning.is_some());

        let warning = response.degraded_warning.unwrap();
        assert!(!warning.stale_inputs.is_empty());
        assert!(warning.max_staleness_secs > 0);
    }

    #[test]
    fn test_degraded_confidence_annotation() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(true);
        let candidates = vec![make_candidate("a1", 10.0, 50.0)];

        let response = engine.recommend(&candidates, &state, "op", "rec-001", "t-001", "2026-01-15T00:00:00Z");
        let rec = &response.recommendations[0];
        assert!(rec.degraded_confidence);
        assert!(rec.adjusted_uncertainty.is_some());
    }

    #[test]
    fn test_normal_mode_no_degraded_flag() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);
        let candidates = vec![make_candidate("a1", 10.0, 50.0)];

        let response = engine.recommend(&candidates, &state, "op", "rec-001", "t-001", "2026-01-15T00:00:00Z");
        let rec = &response.recommendations[0];
        assert!(!rec.degraded_confidence);
        assert!(rec.adjusted_uncertainty.is_none());
    }

    #[test]
    fn test_rationale_includes_dominant_dimension() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);
        let mut candidate = make_candidate("a1", 10.0, 50.0);
        candidate.expected_loss_if_act.availability_loss = 100.0;
        let candidates = vec![candidate];

        let response = engine.recommend(&candidates, &state, "op", "rec-001", "t-001", "2026-01-15T00:00:00Z");
        assert!(response.recommendations[0].rationale.contains("availability"));
    }

    #[test]
    fn test_rollback_command_included() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);
        let candidates = vec![make_candidate("a1", 10.0, 50.0)];

        let response = engine.recommend(&candidates, &state, "op", "rec-001", "t-001", "2026-01-15T00:00:00Z");
        assert!(response.recommendations[0].rollback_command.contains("rollback"));
        assert!(response.recommendations[0].rollback_validated);
    }

    #[test]
    fn test_audit_trail_recorded() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);
        let candidates = vec![make_candidate("a1", 10.0, 50.0)];

        engine.recommend(&candidates, &state, "operator-1", "rec-001", "t-001", "2026-01-15T00:00:00Z");

        assert_eq!(engine.audit_trail().len(), 1);
        assert_eq!(engine.audit_trail()[0].operator_identity, "operator-1");
        assert_eq!(engine.audit_trail()[0].recommendation_id, "rec-001");
        assert_eq!(engine.total_served(), 1);
    }

    #[test]
    fn test_expected_loss_vector_validation() {
        let valid = ExpectedLossVector {
            availability_loss: 1.0,
            integrity_loss: 2.0,
            confidentiality_loss: 0.5,
            financial_loss: 3.0,
            reputation_loss: 1.5,
        };
        assert!(valid.is_valid());

        let invalid = ExpectedLossVector {
            availability_loss: -1.0,
            integrity_loss: 2.0,
            confidentiality_loss: 0.0,
            financial_loss: 0.0,
            reputation_loss: 0.0,
        };
        assert!(!invalid.is_valid());
    }

    #[test]
    fn test_expected_loss_total() {
        let vec = ExpectedLossVector {
            availability_loss: 1.0,
            integrity_loss: 2.0,
            confidentiality_loss: 3.0,
            financial_loss: 4.0,
            reputation_loss: 5.0,
        };
        assert!((vec.total() - 15.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_confidence_interval_non_degenerate() {
        let good = ConfidenceInterval {
            lower_bound: 1.0,
            upper_bound: 5.0,
            confidence_level: 0.95,
        };
        assert!(good.is_non_degenerate());

        let degenerate = ConfidenceInterval {
            lower_bound: 5.0,
            upper_bound: 5.0,
            confidence_level: 0.95,
        };
        assert!(!degenerate.is_non_degenerate());
    }

    #[test]
    fn test_dominant_dimension() {
        let vec = ExpectedLossVector {
            availability_loss: 1.0,
            integrity_loss: 5.0,
            confidentiality_loss: 2.0,
            financial_loss: 3.0,
            reputation_loss: 4.0,
        };
        assert_eq!(vec.dominant_dimension(), "integrity");
    }

    #[test]
    fn test_tied_voi_stability() {
        let mut engine = ActionRecommendationEngine::new(10);
        let state = make_state(false);
        let candidates = vec![
            make_candidate("a1", 10.0, 50.0),
            make_candidate("a2", 10.0, 50.0),
        ];

        let response = engine.recommend(&candidates, &state, "op", "rec-001", "t-001", "2026-01-15T00:00:00Z");
        // Both have same VOI; should return both without crashing.
        assert_eq!(response.recommendations.len(), 2);
    }

    #[test]
    fn test_adjusted_uncertainty_widened() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(true);
        let candidates = vec![make_candidate("a1", 10.0, 50.0)];

        let response = engine.recommend(&candidates, &state, "op", "rec-001", "t-001", "2026-01-15T00:00:00Z");
        let rec = &response.recommendations[0];
        let adj = rec.adjusted_uncertainty.as_ref().unwrap();
        let orig = &rec.uncertainty_band;
        // Adjusted should be wider.
        assert!(adj.upper_bound > orig.upper_bound);
        assert!(adj.lower_bound < orig.lower_bound);
    }

    #[test]
    fn test_multiple_recommendations_served() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);
        let candidates = vec![make_candidate("a1", 10.0, 50.0)];

        engine.recommend(&candidates, &state, "op", "rec-001", "t-001", "2026-01-15T00:00:00Z");
        engine.recommend(&candidates, &state, "op", "rec-002", "t-002", "2026-01-15T00:01:00Z");

        assert_eq!(engine.total_served(), 2);
        assert_eq!(engine.audit_trail().len(), 2);
    }
}
