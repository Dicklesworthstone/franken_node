//! BPET economic integration: trajectory-derived compromise pricing
//! and operator copilot guidance (bd-3cbi).
//!
//! Connects behavioral phenotype evolution tracking to the economic
//! trust layer by pricing compromise propensity, computing intervention
//! ROI, matching historical motifs, and generating mitigation playbooks.

use chrono::Utc;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const BPET_RISK_PRICED: &str = "BPET-ECON-001";
    pub const BPET_ROI_COMPUTED: &str = "BPET-ECON-002";
    pub const BPET_MOTIF_MATCHED: &str = "BPET-ECON-003";
    pub const BPET_PLAYBOOK_GENERATED: &str = "BPET-ECON-004";
    pub const BPET_GUIDANCE_SERVED: &str = "BPET-ECON-005";
    pub const BPET_THRESHOLD_BREACHED: &str = "BPET-ECON-006";
    pub const BPET_TRAJECTORY_ASSESSED: &str = "BPET-ECON-007";
    pub const BPET_INTERVENTION_RECOMMENDED: &str = "BPET-ECON-008";
    pub const BPET_ECONOMIC_REPORT_EMITTED: &str = "BPET-ECON-009";
    pub const BPET_CALIBRATION_WARNING: &str = "BPET-ECON-010";
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum BpetEconError {
    #[error("invalid trajectory data: {0}")]
    InvalidTrajectory(String),
    #[error("no historical motifs available for matching")]
    NoMotifsAvailable,
    #[error("intervention cost must be positive: {0}")]
    InvalidCost(f64),
    #[error("package not found: {0}")]
    PackageNotFound(String),
}

// ---------------------------------------------------------------------------
// Trajectory phenotype data
// ---------------------------------------------------------------------------

/// A behavioral phenotype observation at a point in time.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhenotypeObservation {
    pub timestamp: String,
    pub maintainer_activity_score: f64,
    pub commit_velocity: f64,
    pub issue_response_time_hours: f64,
    pub dependency_churn_rate: f64,
    pub security_patch_latency_hours: f64,
    pub contributor_diversity_index: f64,
}

/// A trajectory is a time-ordered sequence of phenotype observations.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhenotypeTrajectory {
    pub package_name: String,
    pub observations: Vec<PhenotypeObservation>,
}

impl PhenotypeTrajectory {
    /// Compute the compromise propensity score from the trajectory.
    /// Higher values indicate greater risk of future compromise.
    pub fn compromise_propensity(&self) -> f64 {
        if self.observations.is_empty() {
            return 0.0;
        }

        let n = self.observations.len();
        if n < 2 {
            return self.single_observation_score(&self.observations[0]);
        }

        // Compute trend: are things getting worse?
        let recent = &self.observations[n - 1];
        let earlier = &self.observations[0];

        let activity_trend = earlier.maintainer_activity_score - recent.maintainer_activity_score;
        let velocity_trend = earlier.commit_velocity - recent.commit_velocity;
        let response_trend = recent.issue_response_time_hours - earlier.issue_response_time_hours;
        let diversity_trend =
            earlier.contributor_diversity_index - recent.contributor_diversity_index;

        // Normalize and combine: positive values = worsening
        let trend_score = (activity_trend.max(0.0) * 0.3
            + velocity_trend.max(0.0) * 0.2
            + (response_trend / 100.0).clamp(0.0, 1.0) * 0.25
            + diversity_trend.max(0.0) * 0.25)
            .min(1.0);

        // Combine with current state
        let current_score = self.single_observation_score(recent);
        (current_score * 0.4 + trend_score * 0.6).min(1.0)
    }

    fn single_observation_score(&self, obs: &PhenotypeObservation) -> f64 {
        let activity_risk = (1.0 - obs.maintainer_activity_score).max(0.0);
        let velocity_risk = (1.0 - (obs.commit_velocity / 10.0).min(1.0)).max(0.0);
        let response_risk = (obs.issue_response_time_hours / 720.0).min(1.0); // 30 days max
        let diversity_risk = (1.0 - obs.contributor_diversity_index).max(0.0);

        (activity_risk * 0.3 + velocity_risk * 0.2 + response_risk * 0.25 + diversity_risk * 0.25)
            .min(1.0)
    }
}

// ---------------------------------------------------------------------------
// Economic pricing
// ---------------------------------------------------------------------------

/// Economic pricing for trajectory-derived compromise risk.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompromisePricing {
    pub package_name: String,
    pub compromise_propensity: f64,
    pub expected_loss_if_compromised: f64,
    pub risk_adjusted_cost: f64,
    pub insurance_premium_equivalent: f64,
    pub confidence: f64,
}

impl CompromisePricing {
    /// Compute pricing from trajectory and loss estimate.
    pub fn compute(
        trajectory: &PhenotypeTrajectory,
        expected_loss: f64,
        confidence: f64,
    ) -> Result<Self, BpetEconError> {
        if trajectory.observations.is_empty() {
            return Err(BpetEconError::InvalidTrajectory(
                "no observations available".to_string(),
            ));
        }

        let propensity = trajectory.compromise_propensity();
        let risk_adjusted = propensity * expected_loss;
        let premium = risk_adjusted * 1.2; // 20% loading factor

        Ok(Self {
            package_name: trajectory.package_name.clone(),
            compromise_propensity: propensity,
            expected_loss_if_compromised: expected_loss,
            risk_adjusted_cost: risk_adjusted,
            insurance_premium_equivalent: premium,
            confidence,
        })
    }
}

// ---------------------------------------------------------------------------
// Intervention ROI
// ---------------------------------------------------------------------------

/// ROI calculation for a proposed intervention.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InterventionRoi {
    pub intervention_name: String,
    pub intervention_cost: f64,
    pub risk_reduction: f64,
    pub expected_loss_avoided: f64,
    pub roi_ratio: f64,
    pub payback_period_days: f64,
    pub recommendation: InterventionRecommendation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterventionRecommendation {
    StronglyRecommended,
    Recommended,
    Marginal,
    NotRecommended,
}

impl InterventionRoi {
    pub fn compute(
        name: &str,
        cost: f64,
        risk_reduction: f64,
        current_expected_loss: f64,
    ) -> Result<Self, BpetEconError> {
        if cost <= 0.0 {
            return Err(BpetEconError::InvalidCost(cost));
        }

        let loss_avoided = risk_reduction * current_expected_loss;
        let roi = loss_avoided / cost;
        let payback = if loss_avoided > 0.0 {
            cost / (loss_avoided / 365.0)
        } else {
            f64::INFINITY
        };

        let recommendation = if roi > 5.0 {
            InterventionRecommendation::StronglyRecommended
        } else if roi > 2.0 {
            InterventionRecommendation::Recommended
        } else if roi > 1.0 {
            InterventionRecommendation::Marginal
        } else {
            InterventionRecommendation::NotRecommended
        };

        Ok(Self {
            intervention_name: name.to_string(),
            intervention_cost: cost,
            risk_reduction,
            expected_loss_avoided: loss_avoided,
            roi_ratio: roi,
            payback_period_days: payback,
            recommendation,
        })
    }
}

// ---------------------------------------------------------------------------
// Historical motif matching
// ---------------------------------------------------------------------------

/// A historical compromise motif (pattern seen in past incidents).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CompromiseMotif {
    pub motif_id: String,
    pub name: String,
    pub description: String,
    pub indicators: Vec<MotifIndicator>,
    pub historical_frequency: f64,
    pub typical_time_to_compromise_days: f64,
}

/// An indicator within a motif.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MotifIndicator {
    pub indicator_name: String,
    pub threshold: f64,
    pub direction: ThresholdDirection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThresholdDirection {
    Above,
    Below,
}

/// Result of matching a trajectory against known motifs.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MotifMatch {
    pub motif_id: String,
    pub motif_name: String,
    pub match_score: f64,
    pub matched_indicators: Vec<String>,
    pub estimated_time_to_compromise_days: f64,
}

/// Match a trajectory against a library of known compromise motifs.
pub fn match_motifs(
    trajectory: &PhenotypeTrajectory,
    motifs: &[CompromiseMotif],
) -> Vec<MotifMatch> {
    if trajectory.observations.is_empty() || motifs.is_empty() {
        return Vec::new();
    }

    let latest = trajectory.observations.last().unwrap();
    let mut matches = Vec::new();

    for motif in motifs {
        let mut matched_indicators = Vec::new();
        let total = motif.indicators.len();

        for indicator in &motif.indicators {
            let value = match indicator.indicator_name.as_str() {
                "maintainer_activity" => latest.maintainer_activity_score,
                "commit_velocity" => latest.commit_velocity,
                "issue_response_time" => latest.issue_response_time_hours,
                "dependency_churn" => latest.dependency_churn_rate,
                "security_patch_latency" => latest.security_patch_latency_hours,
                "contributor_diversity" => latest.contributor_diversity_index,
                _ => continue,
            };

            let hit = match indicator.direction {
                ThresholdDirection::Above => value > indicator.threshold,
                ThresholdDirection::Below => value < indicator.threshold,
            };

            if hit {
                matched_indicators.push(indicator.indicator_name.clone());
            }
        }

        if !matched_indicators.is_empty() && total > 0 {
            let score = matched_indicators.len() as f64 / total as f64;
            if score >= 0.5 {
                matches.push(MotifMatch {
                    motif_id: motif.motif_id.clone(),
                    motif_name: motif.name.clone(),
                    match_score: score,
                    matched_indicators,
                    estimated_time_to_compromise_days: motif.typical_time_to_compromise_days,
                });
            }
        }
    }

    matches.sort_by(|a, b| {
        b.match_score
            .partial_cmp(&a.match_score)
            .unwrap_or(std::cmp::Ordering::Equal)
    });
    matches
}

// ---------------------------------------------------------------------------
// Operator guidance
// ---------------------------------------------------------------------------

/// BPET-aware operator guidance entry.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BpetGuidance {
    pub guidance_id: String,
    pub package_name: String,
    pub compromise_propensity: f64,
    pub pricing: CompromisePricing,
    pub motif_matches: Vec<MotifMatch>,
    pub top_interventions: Vec<InterventionRoi>,
    pub playbook: BpetMitigationPlaybook,
    pub summary: String,
    pub timestamp: String,
    pub trace_id: String,
}

/// BPET-specific mitigation playbook.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BpetMitigationPlaybook {
    pub playbook_id: String,
    pub urgency: PlaybookUrgency,
    pub recommended_actions: Vec<PlaybookAction>,
    pub monitoring_escalation: Vec<String>,
    pub fallback_strategy: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PlaybookUrgency {
    Routine,
    Elevated,
    Urgent,
    Critical,
}

/// Individual action in a playbook.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlaybookAction {
    pub action_name: String,
    pub description: String,
    pub priority: u8,
    pub estimated_effort_hours: f64,
}

// ---------------------------------------------------------------------------
// Audit log
// ---------------------------------------------------------------------------

/// Audit record for BPET economic interactions.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BpetAuditRecord {
    pub record_id: String,
    pub event_code: String,
    pub package_name: String,
    pub timestamp: String,
    pub trace_id: String,
    pub details: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// BPET economic integration engine.
#[derive(Debug, Clone)]
pub struct BpetEconomicEngine {
    motif_library: Vec<CompromiseMotif>,
    audit_log: Vec<BpetAuditRecord>,
}

impl Default for BpetEconomicEngine {
    fn default() -> Self {
        Self::new(default_motif_library())
    }
}

impl BpetEconomicEngine {
    pub fn new(motif_library: Vec<CompromiseMotif>) -> Self {
        Self {
            motif_library,
            audit_log: Vec::new(),
        }
    }

    /// Generate full operator guidance for a package's trajectory.
    pub fn generate_guidance(
        &mut self,
        trajectory: &PhenotypeTrajectory,
        expected_loss: f64,
        confidence: f64,
        trace_id: &str,
    ) -> Result<BpetGuidance, BpetEconError> {
        let pricing = CompromisePricing::compute(trajectory, expected_loss, confidence)?;
        let motif_matches = match_motifs(trajectory, &self.motif_library);

        let interventions =
            self.compute_intervention_options(&pricing, trajectory.compromise_propensity());

        let urgency = self.determine_urgency(&pricing, &motif_matches);
        let playbook = self.generate_playbook(&pricing, &motif_matches, urgency);

        let summary = self.generate_summary(&pricing, &motif_matches, &interventions);

        let guidance = BpetGuidance {
            guidance_id: Uuid::now_v7().to_string(),
            package_name: trajectory.package_name.clone(),
            compromise_propensity: pricing.compromise_propensity,
            pricing: pricing.clone(),
            motif_matches: motif_matches.clone(),
            top_interventions: interventions,
            playbook,
            summary,
            timestamp: Utc::now().to_rfc3339(),
            trace_id: trace_id.to_string(),
        };

        self.log(BpetAuditRecord {
            record_id: Uuid::now_v7().to_string(),
            event_code: event_codes::BPET_GUIDANCE_SERVED.to_string(),
            package_name: trajectory.package_name.clone(),
            timestamp: Utc::now().to_rfc3339(),
            trace_id: trace_id.to_string(),
            details: serde_json::json!({
                "propensity": pricing.compromise_propensity,
                "risk_adjusted_cost": pricing.risk_adjusted_cost,
                "motif_count": motif_matches.len(),
            }),
        });

        Ok(guidance)
    }

    /// Get the audit log.
    pub fn audit_log(&self) -> &[BpetAuditRecord] {
        &self.audit_log
    }

    /// Export audit log as JSONL.
    pub fn export_audit_log_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut lines = Vec::with_capacity(self.audit_log.len());
        for record in &self.audit_log {
            lines.push(serde_json::to_string(record)?);
        }
        Ok(lines.join("\n"))
    }

    // -----------------------------------------------------------------------
    // Internal
    // -----------------------------------------------------------------------

    fn compute_intervention_options(
        &self,
        pricing: &CompromisePricing,
        propensity: f64,
    ) -> Vec<InterventionRoi> {
        let mut interventions = Vec::new();

        // Fork and maintain internally
        if let Ok(roi) = InterventionRoi::compute(
            "fork_and_maintain",
            5000.0,
            propensity * 0.8,
            pricing.expected_loss_if_compromised,
        ) {
            interventions.push(roi);
        }

        // Sponsor additional maintainer
        if let Ok(roi) = InterventionRoi::compute(
            "sponsor_maintainer",
            2000.0,
            propensity * 0.5,
            pricing.expected_loss_if_compromised,
        ) {
            interventions.push(roi);
        }

        // Add sandbox barriers
        if let Ok(roi) = InterventionRoi::compute(
            "sandbox_barriers",
            500.0,
            propensity * 0.3,
            pricing.expected_loss_if_compromised,
        ) {
            interventions.push(roi);
        }

        // Replace with alternative
        if let Ok(roi) = InterventionRoi::compute(
            "replace_dependency",
            10000.0,
            propensity * 0.95,
            pricing.expected_loss_if_compromised,
        ) {
            interventions.push(roi);
        }

        interventions.sort_by(|a, b| {
            b.roi_ratio
                .partial_cmp(&a.roi_ratio)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        interventions
    }

    fn determine_urgency(
        &self,
        pricing: &CompromisePricing,
        motif_matches: &[MotifMatch],
    ) -> PlaybookUrgency {
        let has_high_match = motif_matches.iter().any(|m| m.match_score >= 0.8);

        if pricing.compromise_propensity >= 0.8 || has_high_match {
            PlaybookUrgency::Critical
        } else if pricing.compromise_propensity >= 0.6 {
            PlaybookUrgency::Urgent
        } else if pricing.compromise_propensity >= 0.3 {
            PlaybookUrgency::Elevated
        } else {
            PlaybookUrgency::Routine
        }
    }

    fn generate_playbook(
        &self,
        pricing: &CompromisePricing,
        motif_matches: &[MotifMatch],
        urgency: PlaybookUrgency,
    ) -> BpetMitigationPlaybook {
        let mut actions = Vec::new();

        if urgency >= PlaybookUrgency::Elevated {
            actions.push(PlaybookAction {
                action_name: "Activate enhanced monitoring".to_string(),
                description: "Increase observation frequency and alert sensitivity".to_string(),
                priority: 1,
                estimated_effort_hours: 1.0,
            });
        }

        if urgency >= PlaybookUrgency::Urgent {
            actions.push(PlaybookAction {
                action_name: "Evaluate fork or replacement".to_string(),
                description: "Assess feasibility of forking or replacing with safer alternative"
                    .to_string(),
                priority: 2,
                estimated_effort_hours: 8.0,
            });
            actions.push(PlaybookAction {
                action_name: "Apply sandbox escalation".to_string(),
                description: "Tighten sandbox to strict tier for this dependency".to_string(),
                priority: 3,
                estimated_effort_hours: 2.0,
            });
        }

        if urgency >= PlaybookUrgency::Critical {
            actions.push(PlaybookAction {
                action_name: "Prepare emergency rollback plan".to_string(),
                description: "Document and test rollback procedure for immediate use".to_string(),
                priority: 0,
                estimated_effort_hours: 4.0,
            });
        }

        let mut monitoring = vec!["phenotype_drift_score".to_string()];
        if !motif_matches.is_empty() {
            monitoring.push("motif_match_progression".to_string());
        }
        if pricing.compromise_propensity > 0.5 {
            monitoring.push("real_time_commit_analysis".to_string());
        }

        BpetMitigationPlaybook {
            playbook_id: Uuid::now_v7().to_string(),
            urgency,
            recommended_actions: actions,
            monitoring_escalation: monitoring,
            fallback_strategy: format!(
                "If propensity exceeds 0.9, auto-quarantine {} and notify operator",
                pricing.package_name
            ),
        }
    }

    fn generate_summary(
        &self,
        pricing: &CompromisePricing,
        motif_matches: &[MotifMatch],
        interventions: &[InterventionRoi],
    ) -> String {
        let motif_note = if motif_matches.is_empty() {
            "no historical motif matches".to_string()
        } else {
            format!(
                "{} motif match(es), top: {} (score {:.2})",
                motif_matches.len(),
                motif_matches[0].motif_name,
                motif_matches[0].match_score
            )
        };

        let top_intervention = interventions
            .first()
            .map(|i| format!("{} (ROI {:.1}x)", i.intervention_name, i.roi_ratio))
            .unwrap_or_else(|| "none".to_string());

        format!(
            "Package {}: propensity {:.3}, risk-adjusted cost ${:.0}, {}. Top intervention: {}.",
            pricing.package_name,
            pricing.compromise_propensity,
            pricing.risk_adjusted_cost,
            motif_note,
            top_intervention
        )
    }

    fn log(&mut self, record: BpetAuditRecord) {
        self.audit_log.push(record);
    }
}

/// Default motif library with common pre-compromise patterns.
pub fn default_motif_library() -> Vec<CompromiseMotif> {
    vec![
        CompromiseMotif {
            motif_id: "motif-abandoned-critical".to_string(),
            name: "Abandoned Critical Package".to_string(),
            description: "Maintainer activity drops while package remains widely depended upon"
                .to_string(),
            indicators: vec![
                MotifIndicator {
                    indicator_name: "maintainer_activity".to_string(),
                    threshold: 0.2,
                    direction: ThresholdDirection::Below,
                },
                MotifIndicator {
                    indicator_name: "issue_response_time".to_string(),
                    threshold: 168.0, // 7 days
                    direction: ThresholdDirection::Above,
                },
            ],
            historical_frequency: 0.03,
            typical_time_to_compromise_days: 180.0,
        },
        CompromiseMotif {
            motif_id: "motif-maintainer-turnover".to_string(),
            name: "Sudden Maintainer Turnover".to_string(),
            description: "New maintainer takes over with rapid, unexplained changes".to_string(),
            indicators: vec![
                MotifIndicator {
                    indicator_name: "contributor_diversity".to_string(),
                    threshold: 0.3,
                    direction: ThresholdDirection::Below,
                },
                MotifIndicator {
                    indicator_name: "dependency_churn".to_string(),
                    threshold: 0.5,
                    direction: ThresholdDirection::Above,
                },
            ],
            historical_frequency: 0.01,
            typical_time_to_compromise_days: 30.0,
        },
        CompromiseMotif {
            motif_id: "motif-slow-decay".to_string(),
            name: "Slow Quality Decay".to_string(),
            description: "Gradual decline in all health indicators over months".to_string(),
            indicators: vec![
                MotifIndicator {
                    indicator_name: "maintainer_activity".to_string(),
                    threshold: 0.4,
                    direction: ThresholdDirection::Below,
                },
                MotifIndicator {
                    indicator_name: "commit_velocity".to_string(),
                    threshold: 2.0,
                    direction: ThresholdDirection::Below,
                },
                MotifIndicator {
                    indicator_name: "security_patch_latency".to_string(),
                    threshold: 336.0, // 14 days
                    direction: ThresholdDirection::Above,
                },
            ],
            historical_frequency: 0.05,
            typical_time_to_compromise_days: 365.0,
        },
    ]
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trace() -> String {
        Uuid::now_v7().to_string()
    }

    fn make_healthy_observation() -> PhenotypeObservation {
        PhenotypeObservation {
            timestamp: Utc::now().to_rfc3339(),
            maintainer_activity_score: 0.9,
            commit_velocity: 15.0,
            issue_response_time_hours: 12.0,
            dependency_churn_rate: 0.05,
            security_patch_latency_hours: 24.0,
            contributor_diversity_index: 0.8,
        }
    }

    fn make_declining_observation() -> PhenotypeObservation {
        PhenotypeObservation {
            timestamp: Utc::now().to_rfc3339(),
            maintainer_activity_score: 0.15,
            commit_velocity: 0.5,
            issue_response_time_hours: 500.0,
            dependency_churn_rate: 0.8,
            security_patch_latency_hours: 720.0,
            contributor_diversity_index: 0.1,
        }
    }

    fn make_healthy_trajectory() -> PhenotypeTrajectory {
        PhenotypeTrajectory {
            package_name: "healthy-pkg".to_string(),
            observations: vec![make_healthy_observation(), make_healthy_observation()],
        }
    }

    fn make_declining_trajectory() -> PhenotypeTrajectory {
        PhenotypeTrajectory {
            package_name: "declining-pkg".to_string(),
            observations: vec![make_healthy_observation(), make_declining_observation()],
        }
    }

    // === Compromise propensity ===

    #[test]
    fn healthy_trajectory_has_low_propensity() {
        let traj = make_healthy_trajectory();
        assert!(traj.compromise_propensity() < 0.3);
    }

    #[test]
    fn declining_trajectory_has_high_propensity() {
        let traj = make_declining_trajectory();
        assert!(traj.compromise_propensity() > 0.3);
    }

    #[test]
    fn empty_trajectory_returns_zero_propensity() {
        let traj = PhenotypeTrajectory {
            package_name: "empty".to_string(),
            observations: Vec::new(),
        };
        assert!((traj.compromise_propensity() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn propensity_bounded_zero_to_one() {
        let traj = make_declining_trajectory();
        let p = traj.compromise_propensity();
        assert!((0.0..=1.0).contains(&p));
    }

    // === Compromise pricing ===

    #[test]
    fn pricing_computed_for_valid_trajectory() {
        let traj = make_healthy_trajectory();
        let pricing = CompromisePricing::compute(&traj, 100_000.0, 0.8).unwrap();
        assert_eq!(pricing.package_name, "healthy-pkg");
        assert!(pricing.risk_adjusted_cost >= 0.0);
        assert!(pricing.insurance_premium_equivalent > pricing.risk_adjusted_cost);
    }

    #[test]
    fn pricing_fails_for_empty_trajectory() {
        let traj = PhenotypeTrajectory {
            package_name: "empty".to_string(),
            observations: Vec::new(),
        };
        let result = CompromisePricing::compute(&traj, 100_000.0, 0.8);
        assert!(result.is_err());
    }

    #[test]
    fn high_risk_produces_higher_cost() {
        let healthy = make_healthy_trajectory();
        let declining = make_declining_trajectory();
        let p_healthy = CompromisePricing::compute(&healthy, 100_000.0, 0.8).unwrap();
        let p_declining = CompromisePricing::compute(&declining, 100_000.0, 0.8).unwrap();
        assert!(p_declining.risk_adjusted_cost > p_healthy.risk_adjusted_cost);
    }

    // === Intervention ROI ===

    #[test]
    fn intervention_roi_computed_correctly() {
        let roi = InterventionRoi::compute("sandbox", 500.0, 0.3, 100_000.0).unwrap();
        assert_eq!(roi.intervention_name, "sandbox");
        assert!((roi.expected_loss_avoided - 30_000.0).abs() < f64::EPSILON);
        assert!(roi.roi_ratio > 1.0);
    }

    #[test]
    fn intervention_rejects_zero_cost() {
        let result = InterventionRoi::compute("bad", 0.0, 0.5, 100_000.0);
        assert!(result.is_err());
    }

    #[test]
    fn high_roi_is_strongly_recommended() {
        let roi = InterventionRoi::compute("cheap-fix", 100.0, 0.5, 100_000.0).unwrap();
        assert_eq!(
            roi.recommendation,
            InterventionRecommendation::StronglyRecommended
        );
    }

    #[test]
    fn low_roi_is_not_recommended() {
        let roi = InterventionRoi::compute("expensive-fix", 200_000.0, 0.1, 100_000.0).unwrap();
        assert_eq!(
            roi.recommendation,
            InterventionRecommendation::NotRecommended
        );
    }

    // === Motif matching ===

    #[test]
    fn declining_trajectory_matches_motifs() {
        let traj = make_declining_trajectory();
        let motifs = default_motif_library();
        let matches = match_motifs(&traj, &motifs);
        assert!(!matches.is_empty());
    }

    #[test]
    fn healthy_trajectory_has_fewer_matches() {
        let traj = make_healthy_trajectory();
        let motifs = default_motif_library();
        let matches = match_motifs(&traj, &motifs);
        // Healthy trajectory should match fewer motifs
        let declining = make_declining_trajectory();
        let declining_matches = match_motifs(&declining, &motifs);
        assert!(matches.len() <= declining_matches.len());
    }

    #[test]
    fn empty_trajectory_no_motif_matches() {
        let traj = PhenotypeTrajectory {
            package_name: "empty".to_string(),
            observations: Vec::new(),
        };
        let matches = match_motifs(&traj, &default_motif_library());
        assert!(matches.is_empty());
    }

    #[test]
    fn motif_matches_sorted_by_score() {
        let traj = make_declining_trajectory();
        let matches = match_motifs(&traj, &default_motif_library());
        for w in matches.windows(2) {
            assert!(w[0].match_score >= w[1].match_score);
        }
    }

    // === Engine guidance ===

    #[test]
    fn engine_generates_guidance_for_healthy_pkg() {
        let mut engine = BpetEconomicEngine::default();
        let traj = make_healthy_trajectory();
        let guidance = engine
            .generate_guidance(&traj, 50_000.0, 0.8, &make_trace())
            .unwrap();

        assert_eq!(guidance.package_name, "healthy-pkg");
        assert!(!guidance.top_interventions.is_empty());
        assert!(!guidance.summary.is_empty());
    }

    #[test]
    fn engine_generates_critical_playbook_for_declining() {
        let mut engine = BpetEconomicEngine::default();
        let traj = make_declining_trajectory();
        let guidance = engine
            .generate_guidance(&traj, 500_000.0, 0.7, &make_trace())
            .unwrap();

        assert!(guidance.playbook.urgency >= PlaybookUrgency::Elevated);
        assert!(!guidance.playbook.recommended_actions.is_empty());
    }

    #[test]
    fn engine_logs_guidance_interaction() {
        let mut engine = BpetEconomicEngine::default();
        let traj = make_healthy_trajectory();
        engine
            .generate_guidance(&traj, 50_000.0, 0.8, &make_trace())
            .unwrap();

        assert_eq!(engine.audit_log().len(), 1);
        assert_eq!(
            engine.audit_log()[0].event_code,
            event_codes::BPET_GUIDANCE_SERVED
        );
    }

    #[test]
    fn engine_exports_jsonl() {
        let mut engine = BpetEconomicEngine::default();
        let traj = make_healthy_trajectory();
        engine
            .generate_guidance(&traj, 50_000.0, 0.8, &make_trace())
            .unwrap();

        let jsonl = engine.export_audit_log_jsonl().unwrap();
        let parsed: serde_json::Value =
            serde_json::from_str(jsonl.lines().next().unwrap()).unwrap();
        assert_eq!(parsed["event_code"], event_codes::BPET_GUIDANCE_SERVED);
    }

    // === Playbook urgency ===

    #[test]
    fn routine_urgency_for_low_risk() {
        let mut engine = BpetEconomicEngine::default();
        let traj = make_healthy_trajectory();
        let guidance = engine
            .generate_guidance(&traj, 50_000.0, 0.8, &make_trace())
            .unwrap();
        assert_eq!(guidance.playbook.urgency, PlaybookUrgency::Routine);
    }

    // === Default motif library ===

    #[test]
    fn default_library_has_motifs() {
        let lib = default_motif_library();
        assert!(lib.len() >= 3);
        for motif in &lib {
            assert!(!motif.indicators.is_empty());
        }
    }

    // === Summary format ===

    #[test]
    fn summary_includes_package_name() {
        let mut engine = BpetEconomicEngine::default();
        let traj = make_declining_trajectory();
        let guidance = engine
            .generate_guidance(&traj, 100_000.0, 0.7, &make_trace())
            .unwrap();
        assert!(guidance.summary.contains("declining-pkg"));
    }
}
