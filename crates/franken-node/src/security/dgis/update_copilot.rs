//! DGIS operator copilot for dependency update guidance (bd-1f8v).
//!
//! Translates DGIS intelligence into actionable recommendations for operators:
//! - Topology-aware risk delta reports (pre/post update scores)
//! - Containment recommendations (blast radius + barrier suggestions)
//! - Verifier-backed confidence outputs with uncertainty bounds
//! - Policy acknowledgement gates for high-risk updates
//! - Mitigation playbooks (barrier config, staged rollout, monitoring)

use chrono::Utc;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use uuid::Uuid;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

pub mod event_codes {
    pub const COPILOT_RECOMMENDATION_GENERATED: &str = "DGIS-COPILOT-001";
    pub const COPILOT_HIGH_RISK_FLAGGED: &str = "DGIS-COPILOT-002";
    pub const COPILOT_ACKNOWLEDGEMENT_REQUIRED: &str = "DGIS-COPILOT-003";
    pub const COPILOT_ACKNOWLEDGEMENT_RECEIVED: &str = "DGIS-COPILOT-004";
    pub const COPILOT_PLAYBOOK_GENERATED: &str = "DGIS-COPILOT-005";
    pub const COPILOT_UPDATE_APPROVED: &str = "DGIS-COPILOT-006";
    pub const COPILOT_UPDATE_REJECTED: &str = "DGIS-COPILOT-007";
    pub const COPILOT_CONFIDENCE_LOW: &str = "DGIS-COPILOT-008";
    pub const COPILOT_DELTA_COMPUTED: &str = "DGIS-COPILOT-009";
    pub const COPILOT_BLAST_RADIUS_ESTIMATED: &str = "DGIS-COPILOT-010";
    pub const COPILOT_BARRIER_SUGGESTED: &str = "DGIS-COPILOT-011";
    pub const COPILOT_INTERACTION_LOGGED: &str = "DGIS-COPILOT-012";
}

// ---------------------------------------------------------------------------
// Error types
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum CopilotError {
    #[error("high-risk update requires policy acknowledgement: {0}")]
    AcknowledgementRequired(String),
    #[error("acknowledgement rejected: {0}")]
    AcknowledgementRejected(String),
    #[error("invalid risk score: {0}")]
    InvalidRiskScore(String),
    #[error("proposal not found: {0}")]
    ProposalNotFound(String),
}

// ---------------------------------------------------------------------------
// Topology risk metrics
// ---------------------------------------------------------------------------

/// Per-metric risk score for a dependency graph node.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TopologyRiskMetrics {
    pub fan_out: f64,
    pub betweenness_centrality: f64,
    pub articulation_point: bool,
    pub trust_bottleneck_score: f64,
    pub transitive_dependency_count: u32,
    pub max_depth_in_graph: u32,
}

impl TopologyRiskMetrics {
    /// Compute an aggregate risk score from individual metrics.
    pub fn aggregate_risk(&self) -> f64 {
        let ap_weight = if self.articulation_point { 0.3 } else { 0.0 };
        let fan_out_norm = (self.fan_out / 100.0).min(1.0);
        let bc_norm = self.betweenness_centrality.min(1.0);
        let tb_norm = self.trust_bottleneck_score.min(1.0);

        let raw = fan_out_norm * 0.2 + bc_norm * 0.25 + ap_weight + tb_norm * 0.25;
        raw.min(1.0)
    }
}

/// Risk delta showing before/after topology metrics for a proposed update.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RiskDelta {
    pub package_name: String,
    pub from_version: String,
    pub to_version: String,
    pub pre_update: TopologyRiskMetrics,
    pub post_update: TopologyRiskMetrics,
    pub risk_delta: f64,
    pub risk_increased: bool,
    pub per_metric_deltas: BTreeMap<String, f64>,
}

impl RiskDelta {
    /// Compute risk delta from pre/post metrics.
    pub fn compute(
        package_name: &str,
        from_version: &str,
        to_version: &str,
        pre: TopologyRiskMetrics,
        post: TopologyRiskMetrics,
    ) -> Self {
        let pre_agg = pre.aggregate_risk();
        let post_agg = post.aggregate_risk();
        let delta = post_agg - pre_agg;

        let mut per_metric = BTreeMap::new();
        per_metric.insert("fan_out".to_string(), post.fan_out - pre.fan_out);
        per_metric.insert(
            "betweenness_centrality".to_string(),
            post.betweenness_centrality - pre.betweenness_centrality,
        );
        per_metric.insert(
            "trust_bottleneck_score".to_string(),
            post.trust_bottleneck_score - pre.trust_bottleneck_score,
        );
        per_metric.insert(
            "transitive_dependency_count".to_string(),
            f64::from(post.transitive_dependency_count)
                - f64::from(pre.transitive_dependency_count),
        );

        Self {
            package_name: package_name.to_string(),
            from_version: from_version.to_string(),
            to_version: to_version.to_string(),
            pre_update: pre,
            post_update: post,
            risk_delta: delta,
            risk_increased: delta > 0.0,
            per_metric_deltas: per_metric,
        }
    }
}

// ---------------------------------------------------------------------------
// Containment recommendation
// ---------------------------------------------------------------------------

/// Blast radius estimate for a dependency failure.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlastRadiusEstimate {
    pub directly_affected_nodes: Vec<String>,
    pub transitively_affected_count: u32,
    pub critical_path_affected: bool,
    pub estimated_recovery_time_seconds: u64,
}

/// Recommended barrier for containment.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BarrierRecommendation {
    pub barrier_type: String,
    pub target_node: String,
    pub configuration_summary: String,
    pub rationale: String,
}

/// Full containment recommendation for a dependency update.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContainmentRecommendation {
    pub blast_radius: BlastRadiusEstimate,
    pub recommended_barriers: Vec<BarrierRecommendation>,
    pub monitoring_intensification: Vec<String>,
}

// ---------------------------------------------------------------------------
// Confidence output
// ---------------------------------------------------------------------------

/// Verifier-backed confidence output with uncertainty bounds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceOutput {
    pub confidence_score: f64,
    pub lower_bound: f64,
    pub upper_bound: f64,
    pub data_quality_factors: BTreeMap<String, f64>,
    pub calibration_note: String,
}

impl ConfidenceOutput {
    pub fn is_low_confidence(&self) -> bool {
        self.confidence_score < 0.5
    }

    pub fn uncertainty_range(&self) -> f64 {
        self.upper_bound - self.lower_bound
    }
}

// ---------------------------------------------------------------------------
// Policy acknowledgement
// ---------------------------------------------------------------------------

/// Signed acknowledgement receipt for high-risk updates.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AcknowledgementReceipt {
    pub receipt_id: String,
    pub proposal_id: String,
    pub operator_identity: String,
    pub decision: AcknowledgementDecision,
    pub reason: String,
    pub timestamp: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcknowledgementDecision {
    Approved,
    Rejected,
    Deferred,
}

impl AcknowledgementReceipt {
    pub fn validate(&self) -> Result<(), CopilotError> {
        if self.operator_identity.is_empty() {
            return Err(CopilotError::AcknowledgementRejected(
                "operator_identity required".to_string(),
            ));
        }
        if self.signature_hex.is_empty() {
            return Err(CopilotError::AcknowledgementRejected(
                "signature required".to_string(),
            ));
        }
        Ok(())
    }

    pub fn content_hash(&self) -> String {
        let canonical = serde_json::to_string(self).unwrap_or_default();
        let digest = Sha256::digest(canonical.as_bytes());
        hex::encode(digest)
    }
}

// ---------------------------------------------------------------------------
// Mitigation playbook
// ---------------------------------------------------------------------------

/// Mitigation playbook for a high-risk dependency update.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MitigationPlaybook {
    pub playbook_id: String,
    pub proposal_id: String,
    pub barrier_configurations: Vec<BarrierRecommendation>,
    pub staged_rollout_plan: StagedRolloutPlan,
    pub monitoring_recommendations: Vec<MonitoringRecommendation>,
    pub rollback_instructions: String,
}

/// Staged rollout plan within a playbook.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StagedRolloutPlan {
    pub phases: Vec<RolloutPhaseSpec>,
    pub total_estimated_duration_seconds: u64,
}

/// Individual phase specification.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct RolloutPhaseSpec {
    pub phase_name: String,
    pub traffic_percentage: f64,
    pub min_soak_seconds: u64,
    pub success_criteria: String,
    pub rollback_trigger: String,
}

/// Monitoring recommendation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MonitoringRecommendation {
    pub metric_name: String,
    pub threshold: String,
    pub action_on_breach: String,
}

// ---------------------------------------------------------------------------
// Update proposal & recommendation
// ---------------------------------------------------------------------------

/// A proposed dependency update for copilot evaluation.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpdateProposal {
    pub proposal_id: String,
    pub package_name: String,
    pub from_version: String,
    pub to_version: String,
    pub pre_update_metrics: TopologyRiskMetrics,
    pub post_update_metrics: TopologyRiskMetrics,
    pub directly_affected_nodes: Vec<String>,
}

/// Risk level classification for update proposals.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateRiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl UpdateRiskLevel {
    pub fn requires_acknowledgement(&self) -> bool {
        matches!(self, Self::High | Self::Critical)
    }
}

/// Complete copilot recommendation for an update proposal.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UpdateRecommendation {
    pub recommendation_id: String,
    pub proposal_id: String,
    pub risk_delta: RiskDelta,
    pub risk_level: UpdateRiskLevel,
    pub containment: ContainmentRecommendation,
    pub confidence: ConfidenceOutput,
    pub requires_acknowledgement: bool,
    pub playbook: Option<MitigationPlaybook>,
    pub summary: String,
    pub timestamp: String,
}

// ---------------------------------------------------------------------------
// Copilot interaction log
// ---------------------------------------------------------------------------

/// Logged copilot interaction.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CopilotInteraction {
    pub interaction_id: String,
    pub event_code: String,
    pub proposal_id: String,
    pub timestamp: String,
    pub trace_id: String,
    pub recommendation_id: Option<String>,
    pub operator_decision: Option<AcknowledgementDecision>,
    pub risk_level: Option<UpdateRiskLevel>,
    pub risk_delta: Option<f64>,
    pub details: serde_json::Value,
}

// ---------------------------------------------------------------------------
// Copilot configuration
// ---------------------------------------------------------------------------

/// Configuration thresholds for the copilot.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CopilotConfig {
    pub high_risk_threshold: f64,
    pub critical_risk_threshold: f64,
    pub low_confidence_threshold: f64,
    pub require_ack_above_threshold: bool,
}

impl Default for CopilotConfig {
    fn default() -> Self {
        Self {
            high_risk_threshold: 0.3,
            critical_risk_threshold: 0.6,
            low_confidence_threshold: 0.5,
            require_ack_above_threshold: true,
        }
    }
}

// ---------------------------------------------------------------------------
// Copilot engine
// ---------------------------------------------------------------------------

/// The update copilot engine evaluates proposals and generates recommendations.
#[derive(Debug, Clone)]
pub struct UpdateCopilot {
    config: CopilotConfig,
    interactions: Vec<CopilotInteraction>,
    acknowledgements: BTreeMap<String, AcknowledgementReceipt>,
}

impl Default for UpdateCopilot {
    fn default() -> Self {
        Self::new(CopilotConfig::default())
    }
}

impl UpdateCopilot {
    pub fn new(config: CopilotConfig) -> Self {
        Self {
            config,
            interactions: Vec::new(),
            acknowledgements: BTreeMap::new(),
        }
    }

    /// Evaluate an update proposal and generate a recommendation.
    pub fn evaluate_proposal(
        &mut self,
        proposal: &UpdateProposal,
        trace_id: &str,
    ) -> UpdateRecommendation {
        let risk_delta = RiskDelta::compute(
            &proposal.package_name,
            &proposal.from_version,
            &proposal.to_version,
            proposal.pre_update_metrics.clone(),
            proposal.post_update_metrics.clone(),
        );

        let risk_level = self.classify_risk(&risk_delta);
        let containment = self.generate_containment(proposal, &risk_delta);
        let confidence = self.compute_confidence(proposal);
        let requires_ack =
            self.config.require_ack_above_threshold && risk_level.requires_acknowledgement();

        let playbook = if risk_level.requires_acknowledgement() {
            Some(self.generate_playbook(proposal, &risk_delta, &containment))
        } else {
            None
        };

        let summary = self.generate_summary(&risk_delta, &risk_level, &confidence);

        let recommendation = UpdateRecommendation {
            recommendation_id: Uuid::now_v7().to_string(),
            proposal_id: proposal.proposal_id.clone(),
            risk_delta: risk_delta.clone(),
            risk_level,
            containment,
            confidence: confidence.clone(),
            requires_acknowledgement: requires_ack,
            playbook,
            summary,
            timestamp: Utc::now().to_rfc3339(),
        };

        // Log the interaction
        let mut event_code = event_codes::COPILOT_RECOMMENDATION_GENERATED;
        if requires_ack {
            event_code = event_codes::COPILOT_ACKNOWLEDGEMENT_REQUIRED;
        }

        self.log_interaction(CopilotInteraction {
            interaction_id: Uuid::now_v7().to_string(),
            event_code: event_code.to_string(),
            proposal_id: proposal.proposal_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            trace_id: trace_id.to_string(),
            recommendation_id: Some(recommendation.recommendation_id.clone()),
            operator_decision: None,
            risk_level: Some(risk_level),
            risk_delta: Some(risk_delta.risk_delta),
            details: serde_json::json!({
                "package": proposal.package_name,
                "from": proposal.from_version,
                "to": proposal.to_version,
                "confidence": confidence.confidence_score,
            }),
        });

        recommendation
    }

    /// Process an operator acknowledgement for a high-risk update.
    pub fn process_acknowledgement(
        &mut self,
        receipt: AcknowledgementReceipt,
        trace_id: &str,
    ) -> Result<(), CopilotError> {
        receipt.validate()?;

        let event_code = match receipt.decision {
            AcknowledgementDecision::Approved => event_codes::COPILOT_UPDATE_APPROVED,
            AcknowledgementDecision::Rejected => event_codes::COPILOT_UPDATE_REJECTED,
            AcknowledgementDecision::Deferred => event_codes::COPILOT_ACKNOWLEDGEMENT_RECEIVED,
        };

        self.log_interaction(CopilotInteraction {
            interaction_id: Uuid::now_v7().to_string(),
            event_code: event_code.to_string(),
            proposal_id: receipt.proposal_id.clone(),
            timestamp: Utc::now().to_rfc3339(),
            trace_id: trace_id.to_string(),
            recommendation_id: None,
            operator_decision: Some(receipt.decision),
            risk_level: None,
            risk_delta: None,
            details: serde_json::json!({
                "operator": receipt.operator_identity,
                "reason": receipt.reason,
            }),
        });

        self.acknowledgements
            .insert(receipt.proposal_id.clone(), receipt);
        Ok(())
    }

    /// Check if a proposal has been acknowledged.
    pub fn is_acknowledged(&self, proposal_id: &str) -> bool {
        self.acknowledgements.contains_key(proposal_id)
    }

    /// Get the acknowledgement decision for a proposal.
    pub fn get_acknowledgement(&self, proposal_id: &str) -> Option<&AcknowledgementReceipt> {
        self.acknowledgements.get(proposal_id)
    }

    /// Get the interaction log.
    pub fn interactions(&self) -> &[CopilotInteraction] {
        &self.interactions
    }

    /// Export interaction log as JSONL.
    pub fn export_interactions_jsonl(&self) -> Result<String, serde_json::Error> {
        let mut lines = Vec::with_capacity(self.interactions.len());
        for interaction in &self.interactions {
            lines.push(serde_json::to_string(interaction)?);
        }
        Ok(lines.join("\n"))
    }

    // -----------------------------------------------------------------------
    // Internal methods
    // -----------------------------------------------------------------------

    fn classify_risk(&self, delta: &RiskDelta) -> UpdateRiskLevel {
        let abs_delta = delta.risk_delta.abs();
        if delta.risk_increased && abs_delta >= self.config.critical_risk_threshold {
            UpdateRiskLevel::Critical
        } else if delta.risk_increased && abs_delta >= self.config.high_risk_threshold {
            UpdateRiskLevel::High
        } else if delta.risk_increased {
            UpdateRiskLevel::Medium
        } else {
            UpdateRiskLevel::Low
        }
    }

    fn generate_containment(
        &self,
        proposal: &UpdateProposal,
        delta: &RiskDelta,
    ) -> ContainmentRecommendation {
        let blast_radius = BlastRadiusEstimate {
            directly_affected_nodes: proposal.directly_affected_nodes.clone(),
            transitively_affected_count: delta.post_update.transitive_dependency_count,
            critical_path_affected: delta.post_update.articulation_point,
            estimated_recovery_time_seconds: if delta.post_update.articulation_point {
                3600
            } else {
                600
            },
        };

        let mut barriers = Vec::new();
        if delta.risk_increased {
            barriers.push(BarrierRecommendation {
                barrier_type: "staged_rollout_fence".to_string(),
                target_node: proposal.package_name.clone(),
                configuration_summary: "Canary -> Limited -> Progressive -> General".to_string(),
                rationale: format!(
                    "Risk increased by {:.3}; staged rollout limits exposure",
                    delta.risk_delta
                ),
            });
        }
        if delta.post_update.articulation_point {
            barriers.push(BarrierRecommendation {
                barrier_type: "composition_firewall".to_string(),
                target_node: proposal.package_name.clone(),
                configuration_summary: "Block transitive capability propagation".to_string(),
                rationale: "Node is an articulation point; firewall prevents cascade".to_string(),
            });
        }
        if delta.post_update.trust_bottleneck_score > 0.7 {
            barriers.push(BarrierRecommendation {
                barrier_type: "sandbox_escalation".to_string(),
                target_node: proposal.package_name.clone(),
                configuration_summary: "Escalate to strict tier".to_string(),
                rationale: format!(
                    "Trust bottleneck score {:.2} exceeds threshold",
                    delta.post_update.trust_bottleneck_score
                ),
            });
        }

        let mut monitoring = vec!["error_rate_5m".to_string(), "latency_p99".to_string()];
        if delta.risk_increased {
            monitoring.push("dependency_health_score".to_string());
            monitoring.push("trust_degradation_events".to_string());
        }

        ContainmentRecommendation {
            blast_radius,
            recommended_barriers: barriers,
            monitoring_intensification: monitoring,
        }
    }

    fn compute_confidence(&self, proposal: &UpdateProposal) -> ConfidenceOutput {
        let mut factors = BTreeMap::new();

        // Data quality factors based on available metrics
        let provenance_score = if proposal.post_update_metrics.transitive_dependency_count > 0 {
            0.8
        } else {
            0.4
        };
        factors.insert("provenance_completeness".to_string(), provenance_score);

        let metric_calibration = if proposal.post_update_metrics.fan_out > 0.0 {
            0.75
        } else {
            0.5
        };
        factors.insert("metric_calibration".to_string(), metric_calibration);

        let history_depth = 0.7; // Placeholder; would check real history
        factors.insert("history_depth".to_string(), history_depth);

        let avg_quality: f64 = factors.values().sum::<f64>() / factors.len() as f64;
        let uncertainty = 1.0 - avg_quality;

        ConfidenceOutput {
            confidence_score: avg_quality,
            lower_bound: (avg_quality - uncertainty * 0.5).max(0.0),
            upper_bound: (avg_quality + uncertainty * 0.5).min(1.0),
            data_quality_factors: factors,
            calibration_note: if avg_quality < self.config.low_confidence_threshold {
                "Low confidence: recommendations should be treated as indicative only".to_string()
            } else {
                "Confidence within acceptable range".to_string()
            },
        }
    }

    fn generate_playbook(
        &self,
        proposal: &UpdateProposal,
        delta: &RiskDelta,
        containment: &ContainmentRecommendation,
    ) -> MitigationPlaybook {
        let phases = vec![
            RolloutPhaseSpec {
                phase_name: "canary".to_string(),
                traffic_percentage: 1.0,
                min_soak_seconds: 3600,
                success_criteria: "Error rate < 0.1%, no trust degradation events".to_string(),
                rollback_trigger: "Error rate > 1% or any critical trust event".to_string(),
            },
            RolloutPhaseSpec {
                phase_name: "limited".to_string(),
                traffic_percentage: 10.0,
                min_soak_seconds: 7200,
                success_criteria: "Error rate < 0.5%, latency p99 stable".to_string(),
                rollback_trigger: "Error rate > 2% or latency regression > 50%".to_string(),
            },
            RolloutPhaseSpec {
                phase_name: "progressive".to_string(),
                traffic_percentage: 50.0,
                min_soak_seconds: 14400,
                success_criteria: "All metrics within baseline envelopes".to_string(),
                rollback_trigger: "Any metric outside 2-sigma of baseline".to_string(),
            },
            RolloutPhaseSpec {
                phase_name: "general".to_string(),
                traffic_percentage: 100.0,
                min_soak_seconds: 86400,
                success_criteria: "Full production stability for 24 hours".to_string(),
                rollback_trigger: "Regression detected in any trust or perf metric".to_string(),
            },
        ];

        let monitoring = vec![
            MonitoringRecommendation {
                metric_name: "error_rate".to_string(),
                threshold: "< 0.1% (canary), < 0.5% (limited), < 1% (progressive/general)"
                    .to_string(),
                action_on_breach: "Auto-rollback to previous phase".to_string(),
            },
            MonitoringRecommendation {
                metric_name: "latency_p99".to_string(),
                threshold: "< 2x baseline".to_string(),
                action_on_breach: "Alert + manual review required".to_string(),
            },
            MonitoringRecommendation {
                metric_name: "trust_degradation_events".to_string(),
                threshold: "0 critical events".to_string(),
                action_on_breach: "Immediate rollback + quarantine".to_string(),
            },
        ];

        MitigationPlaybook {
            playbook_id: Uuid::now_v7().to_string(),
            proposal_id: proposal.proposal_id.clone(),
            barrier_configurations: containment.recommended_barriers.clone(),
            staged_rollout_plan: StagedRolloutPlan {
                phases,
                total_estimated_duration_seconds: 3600 + 7200 + 14400 + 86400,
            },
            monitoring_recommendations: monitoring,
            rollback_instructions: format!(
                "Revert {} from {} back to {} and re-apply previous barrier set",
                proposal.package_name, proposal.to_version, proposal.from_version
            ),
        }
    }

    fn generate_summary(
        &self,
        delta: &RiskDelta,
        risk_level: &UpdateRiskLevel,
        confidence: &ConfidenceOutput,
    ) -> String {
        let direction = if delta.risk_increased {
            "increases"
        } else {
            "decreases"
        };
        let ack_note = if risk_level.requires_acknowledgement() {
            " Operator acknowledgement required before proceeding."
        } else {
            ""
        };
        format!(
            "Update {} {} -> {} {} risk by {:.4} (level: {:?}, confidence: {:.2}).{}",
            delta.package_name,
            delta.from_version,
            delta.to_version,
            direction,
            delta.risk_delta.abs(),
            risk_level,
            confidence.confidence_score,
            ack_note,
        )
    }

    fn log_interaction(&mut self, interaction: CopilotInteraction) {
        self.interactions.push(interaction);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_trace_id() -> String {
        Uuid::now_v7().to_string()
    }

    fn make_low_risk_metrics() -> TopologyRiskMetrics {
        TopologyRiskMetrics {
            fan_out: 5.0,
            betweenness_centrality: 0.1,
            articulation_point: false,
            trust_bottleneck_score: 0.2,
            transitive_dependency_count: 10,
            max_depth_in_graph: 3,
        }
    }

    fn make_high_risk_metrics() -> TopologyRiskMetrics {
        TopologyRiskMetrics {
            fan_out: 80.0,
            betweenness_centrality: 0.8,
            articulation_point: true,
            trust_bottleneck_score: 0.9,
            transitive_dependency_count: 150,
            max_depth_in_graph: 12,
        }
    }

    fn make_low_risk_proposal() -> UpdateProposal {
        UpdateProposal {
            proposal_id: Uuid::now_v7().to_string(),
            package_name: "safe-lib".to_string(),
            from_version: "1.0.0".to_string(),
            to_version: "1.0.1".to_string(),
            pre_update_metrics: make_low_risk_metrics(),
            post_update_metrics: make_low_risk_metrics(),
            directly_affected_nodes: vec!["app-core".to_string()],
        }
    }

    fn make_high_risk_proposal() -> UpdateProposal {
        UpdateProposal {
            proposal_id: Uuid::now_v7().to_string(),
            package_name: "critical-dep".to_string(),
            from_version: "2.0.0".to_string(),
            to_version: "3.0.0".to_string(),
            pre_update_metrics: make_low_risk_metrics(),
            post_update_metrics: make_high_risk_metrics(),
            directly_affected_nodes: vec![
                "app-core".to_string(),
                "auth-service".to_string(),
                "data-pipeline".to_string(),
            ],
        }
    }

    fn make_valid_ack(proposal_id: &str) -> AcknowledgementReceipt {
        AcknowledgementReceipt {
            receipt_id: Uuid::now_v7().to_string(),
            proposal_id: proposal_id.to_string(),
            operator_identity: "admin@example.com".to_string(),
            decision: AcknowledgementDecision::Approved,
            reason: "Reviewed and accepted risk".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            signature_hex: "deadbeef01020304".to_string(),
        }
    }

    // === Risk delta computation ===

    #[test]
    fn risk_delta_computation_produces_correct_values() {
        let pre = make_low_risk_metrics();
        let post = make_high_risk_metrics();
        let delta = RiskDelta::compute("pkg", "1.0", "2.0", pre, post);

        assert!(delta.risk_increased);
        assert!(delta.risk_delta > 0.0);
        assert_eq!(delta.package_name, "pkg");
        assert!(delta.per_metric_deltas.contains_key("fan_out"));
        assert!(
            delta
                .per_metric_deltas
                .contains_key("betweenness_centrality")
        );
        assert!(
            delta
                .per_metric_deltas
                .contains_key("trust_bottleneck_score")
        );
    }

    #[test]
    fn risk_delta_shows_decrease_when_risk_drops() {
        let pre = make_high_risk_metrics();
        let post = make_low_risk_metrics();
        let delta = RiskDelta::compute("pkg", "2.0", "2.1", pre, post);

        assert!(!delta.risk_increased);
        assert!(delta.risk_delta < 0.0);
    }

    #[test]
    fn risk_delta_has_four_per_metric_entries() {
        let delta = RiskDelta::compute(
            "pkg",
            "1.0",
            "2.0",
            make_low_risk_metrics(),
            make_low_risk_metrics(),
        );
        assert_eq!(delta.per_metric_deltas.len(), 4);
    }

    // === Risk classification ===

    #[test]
    fn low_risk_update_classified_correctly() {
        let mut copilot = UpdateCopilot::default();
        let proposal = make_low_risk_proposal();
        let rec = copilot.evaluate_proposal(&proposal, &make_trace_id());

        assert_eq!(rec.risk_level, UpdateRiskLevel::Low);
        assert!(!rec.requires_acknowledgement);
        assert!(rec.playbook.is_none());
    }

    #[test]
    fn high_risk_update_classified_correctly() {
        let mut copilot = UpdateCopilot::default();
        let proposal = make_high_risk_proposal();
        let rec = copilot.evaluate_proposal(&proposal, &make_trace_id());

        assert!(matches!(
            rec.risk_level,
            UpdateRiskLevel::High | UpdateRiskLevel::Critical
        ));
        assert!(rec.requires_acknowledgement);
        assert!(rec.playbook.is_some());
    }

    // === Containment recommendations ===

    #[test]
    fn containment_includes_blast_radius() {
        let mut copilot = UpdateCopilot::default();
        let proposal = make_high_risk_proposal();
        let rec = copilot.evaluate_proposal(&proposal, &make_trace_id());

        assert!(
            !rec.containment
                .blast_radius
                .directly_affected_nodes
                .is_empty()
        );
        assert!(rec.containment.blast_radius.critical_path_affected);
    }

    #[test]
    fn containment_suggests_barriers_for_high_risk() {
        let mut copilot = UpdateCopilot::default();
        let proposal = make_high_risk_proposal();
        let rec = copilot.evaluate_proposal(&proposal, &make_trace_id());

        assert!(!rec.containment.recommended_barriers.is_empty());
        let barrier_types: Vec<&str> = rec
            .containment
            .recommended_barriers
            .iter()
            .map(|b| b.barrier_type.as_str())
            .collect();
        assert!(barrier_types.contains(&"staged_rollout_fence"));
    }

    #[test]
    fn containment_includes_monitoring_intensification() {
        let mut copilot = UpdateCopilot::default();
        let proposal = make_high_risk_proposal();
        let rec = copilot.evaluate_proposal(&proposal, &make_trace_id());

        assert!(!rec.containment.monitoring_intensification.is_empty());
    }

    // === Confidence output ===

    #[test]
    fn confidence_has_bounds_and_factors() {
        let mut copilot = UpdateCopilot::default();
        let proposal = make_high_risk_proposal();
        let rec = copilot.evaluate_proposal(&proposal, &make_trace_id());

        assert!(rec.confidence.confidence_score > 0.0);
        assert!(rec.confidence.lower_bound <= rec.confidence.confidence_score);
        assert!(rec.confidence.upper_bound >= rec.confidence.confidence_score);
        assert!(!rec.confidence.data_quality_factors.is_empty());
    }

    #[test]
    fn confidence_uncertainty_range_is_positive() {
        let conf = ConfidenceOutput {
            confidence_score: 0.75,
            lower_bound: 0.6,
            upper_bound: 0.9,
            data_quality_factors: BTreeMap::new(),
            calibration_note: String::new(),
        };
        assert!((conf.uncertainty_range() - 0.3).abs() < f64::EPSILON);
    }

    // === Policy acknowledgement ===

    #[test]
    fn high_risk_requires_acknowledgement() {
        let mut copilot = UpdateCopilot::default();
        let proposal = make_high_risk_proposal();
        let rec = copilot.evaluate_proposal(&proposal, &make_trace_id());

        assert!(rec.requires_acknowledgement);
    }

    #[test]
    fn acknowledgement_validation_rejects_empty_identity() {
        let ack = AcknowledgementReceipt {
            receipt_id: "r1".to_string(),
            proposal_id: "p1".to_string(),
            operator_identity: String::new(),
            decision: AcknowledgementDecision::Approved,
            reason: "ok".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            signature_hex: "abc".to_string(),
        };
        assert!(ack.validate().is_err());
    }

    #[test]
    fn acknowledgement_validation_rejects_empty_signature() {
        let ack = AcknowledgementReceipt {
            receipt_id: "r1".to_string(),
            proposal_id: "p1".to_string(),
            operator_identity: "admin".to_string(),
            decision: AcknowledgementDecision::Approved,
            reason: "ok".to_string(),
            timestamp: Utc::now().to_rfc3339(),
            signature_hex: String::new(),
        };
        assert!(ack.validate().is_err());
    }

    #[test]
    fn valid_acknowledgement_processes_successfully() {
        let mut copilot = UpdateCopilot::default();
        let proposal = make_high_risk_proposal();
        let proposal_id = proposal.proposal_id.clone();
        let trace = make_trace_id();
        copilot.evaluate_proposal(&proposal, &trace);

        let ack = make_valid_ack(&proposal_id);
        copilot.process_acknowledgement(ack, &trace).unwrap();

        assert!(copilot.is_acknowledged(&proposal_id));
        let stored = copilot.get_acknowledgement(&proposal_id).unwrap();
        assert_eq!(stored.decision, AcknowledgementDecision::Approved);
    }

    // === Mitigation playbook ===

    #[test]
    fn playbook_has_all_required_components() {
        let mut copilot = UpdateCopilot::default();
        let proposal = make_high_risk_proposal();
        let rec = copilot.evaluate_proposal(&proposal, &make_trace_id());

        let playbook = rec.playbook.unwrap();
        assert!(!playbook.barrier_configurations.is_empty());
        assert!(!playbook.staged_rollout_plan.phases.is_empty());
        assert!(!playbook.monitoring_recommendations.is_empty());
        assert!(!playbook.rollback_instructions.is_empty());
    }

    #[test]
    fn playbook_rollout_has_four_phases() {
        let mut copilot = UpdateCopilot::default();
        let proposal = make_high_risk_proposal();
        let rec = copilot.evaluate_proposal(&proposal, &make_trace_id());

        let playbook = rec.playbook.unwrap();
        assert_eq!(playbook.staged_rollout_plan.phases.len(), 4);
        let phase_names: Vec<&str> = playbook
            .staged_rollout_plan
            .phases
            .iter()
            .map(|p| p.phase_name.as_str())
            .collect();
        assert_eq!(
            phase_names,
            vec!["canary", "limited", "progressive", "general"]
        );
    }

    #[test]
    fn playbook_monitoring_covers_key_metrics() {
        let mut copilot = UpdateCopilot::default();
        let proposal = make_high_risk_proposal();
        let rec = copilot.evaluate_proposal(&proposal, &make_trace_id());

        let playbook = rec.playbook.unwrap();
        let metric_names: Vec<&str> = playbook
            .monitoring_recommendations
            .iter()
            .map(|m| m.metric_name.as_str())
            .collect();
        assert!(metric_names.contains(&"error_rate"));
        assert!(metric_names.contains(&"latency_p99"));
    }

    // === Interaction logging ===

    #[test]
    fn interactions_are_logged() {
        let mut copilot = UpdateCopilot::default();
        let proposal = make_high_risk_proposal();
        let trace = make_trace_id();
        copilot.evaluate_proposal(&proposal, &trace);

        assert_eq!(copilot.interactions().len(), 1);
        assert_eq!(copilot.interactions()[0].trace_id, trace);
    }

    #[test]
    fn acknowledgement_interaction_is_logged() {
        let mut copilot = UpdateCopilot::default();
        let proposal = make_high_risk_proposal();
        let proposal_id = proposal.proposal_id.clone();
        let trace = make_trace_id();
        copilot.evaluate_proposal(&proposal, &trace);

        let ack = make_valid_ack(&proposal_id);
        copilot.process_acknowledgement(ack, &trace).unwrap();

        assert_eq!(copilot.interactions().len(), 2);
    }

    #[test]
    fn jsonl_export_produces_valid_lines() {
        let mut copilot = UpdateCopilot::default();
        let proposal = make_low_risk_proposal();
        copilot.evaluate_proposal(&proposal, &make_trace_id());

        let jsonl = copilot.export_interactions_jsonl().unwrap();
        let lines: Vec<&str> = jsonl.lines().collect();
        assert_eq!(lines.len(), 1);
        let parsed: serde_json::Value = serde_json::from_str(lines[0]).unwrap();
        assert!(parsed["event_code"].is_string());
    }

    // === Summary generation ===

    #[test]
    fn summary_includes_key_information() {
        let mut copilot = UpdateCopilot::default();
        let proposal = make_high_risk_proposal();
        let rec = copilot.evaluate_proposal(&proposal, &make_trace_id());

        assert!(rec.summary.contains("critical-dep"));
        assert!(rec.summary.contains("2.0.0"));
        assert!(rec.summary.contains("3.0.0"));
        assert!(rec.summary.contains("increases") || rec.summary.contains("decreases"));
    }

    // === Content hash ===

    #[test]
    fn acknowledgement_content_hash_is_deterministic() {
        let ack = AcknowledgementReceipt {
            receipt_id: "fixed-id".to_string(),
            proposal_id: "prop-1".to_string(),
            operator_identity: "admin".to_string(),
            decision: AcknowledgementDecision::Approved,
            reason: "ok".to_string(),
            timestamp: "2026-02-21T00:00:00Z".to_string(),
            signature_hex: "aabb".to_string(),
        };
        let h1 = ack.content_hash();
        let h2 = ack.content_hash();
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64);
    }

    // === Topology risk aggregate ===

    #[test]
    fn aggregate_risk_is_bounded_zero_to_one() {
        let metrics = make_high_risk_metrics();
        let agg = metrics.aggregate_risk();
        assert!(agg >= 0.0);
        assert!(agg <= 1.0);
    }

    #[test]
    fn low_risk_metrics_have_low_aggregate() {
        let metrics = make_low_risk_metrics();
        assert!(metrics.aggregate_risk() < 0.3);
    }

    #[test]
    fn high_risk_metrics_have_high_aggregate() {
        let metrics = make_high_risk_metrics();
        assert!(metrics.aggregate_risk() > 0.5);
    }

    // === No playbook for low risk ===

    #[test]
    fn no_playbook_for_low_risk_updates() {
        let mut copilot = UpdateCopilot::default();
        let proposal = make_low_risk_proposal();
        let rec = copilot.evaluate_proposal(&proposal, &make_trace_id());

        assert!(rec.playbook.is_none());
    }
}
