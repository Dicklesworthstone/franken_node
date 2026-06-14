//! BPET trust-surface integration.
//!
//! Converts BPET trajectory guidance into deterministic trust-card mutations
//! and adversary-posterior update material. This keeps the trust surface from
//! depending on ad hoc string checks in `trust_card.rs` and gives verification
//! gates a dedicated integration point to cite.

use serde::{Deserialize, Serialize};

use crate::security::bpet::economic_integration::{BpetGuidance, PlaybookUrgency};
use crate::security::bpet::evolution_risk_scorer::ExplanationVector;
use crate::security::conformal::{ConformalRiskSet, LABEL_POSITIVE, MAX_BASIS_POINTS};
use crate::supply_chain::trust_card::{RiskAssessment, RiskLevel, TrustCardMutation};

pub const TRUST_SURFACE_SCHEMA_VERSION: &str = "bpet-trust-surface-integration-v1";
pub const MEDIUM_PROPENSITY_THRESHOLD: f64 = 0.30;
pub const HIGH_PROPENSITY_THRESHOLD: f64 = 0.60;
pub const CRITICAL_PROPENSITY_THRESHOLD: f64 = 0.85;
pub const CRITICAL_MOTIF_THRESHOLD: f64 = 0.90;
const MAX_REPUTATION_PENALTY_BPS: u16 = 5_000;
const BASIS_POINTS_SCALE: f64 = 10_000.0;

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum TrustSurfaceIntegrationError {
    #[error("BPET guidance package name is empty")]
    EmptyPackageName,
    #[error("BPET propensity `{field}` is not finite: {value}")]
    NonFinitePropensity { field: &'static str, value: f64 },
    #[error("BPET motif score is outside [0, 1]: {0}")]
    InvalidMotifScore(f64),
    #[error("BPET explanation contribution is not finite for `{0}`")]
    NonFiniteExplanation(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BpetTrustSurfaceAssessment {
    pub schema_version: String,
    pub package_name: String,
    pub risk_score_basis_points: u16,
    pub risk_level: RiskLevel,
    pub active_quarantine_recommended: bool,
    pub reputation_score_basis_points: u16,
    pub dominant_feature: Option<String>,
    pub matched_motif_count: usize,
    pub top_motif_id: Option<String>,
    pub calibrated_risk_set: Option<ConformalRiskSet>,
    pub empirical_coverage_basis_points: Option<u16>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdversaryPosteriorUpdate {
    pub schema_version: String,
    pub subject_id: String,
    pub posterior_basis_points: u16,
    pub confidence_basis_points: u16,
    pub evidence_summary: String,
}

/// Assess BPET guidance for trust-card and adversary-posterior consumers.
///
/// The conversion is fail-closed: non-finite headline scores or malformed
/// motif scores are rejected instead of being clamped into apparently safe
/// trust-card state. When the guidance carries multiple risk views, the bridge
/// uses the maximum finite value so stale or inconsistent projections cannot
/// lower the trust surface's risk.
pub fn assess_guidance_for_trust_surface(
    guidance: &BpetGuidance,
    current_reputation_basis_points: u16,
    explanation: Option<&ExplanationVector>,
) -> Result<BpetTrustSurfaceAssessment, TrustSurfaceIntegrationError> {
    if guidance.package_name.trim().is_empty() {
        return Err(TrustSurfaceIntegrationError::EmptyPackageName);
    }

    let score = max_guidance_propensity(guidance)?;
    validate_motif_scores(guidance)?;
    let top_motif = guidance.motif_matches.first();
    let has_critical_motif = top_motif
        .map(|motif| motif.match_score >= CRITICAL_MOTIF_THRESHOLD)
        .unwrap_or(false);
    let risk_level = risk_level_for(score, guidance.playbook.urgency, has_critical_motif);
    let score_bps = score_to_basis_points(score);
    let reputation = apply_reputation_penalty(current_reputation_basis_points, score);
    let dominant_feature = explanation.map(validated_dominant_feature).transpose()?;
    let summary = trust_surface_summary(guidance, risk_level, score, dominant_feature.as_deref());

    Ok(BpetTrustSurfaceAssessment {
        schema_version: TRUST_SURFACE_SCHEMA_VERSION.to_string(),
        package_name: guidance.package_name.clone(),
        risk_score_basis_points: score_bps,
        risk_level,
        active_quarantine_recommended: risk_level == RiskLevel::Critical,
        reputation_score_basis_points: reputation,
        dominant_feature,
        matched_motif_count: guidance.motif_matches.len(),
        top_motif_id: top_motif.map(|motif| motif.motif_id.clone()),
        calibrated_risk_set: None,
        empirical_coverage_basis_points: None,
        summary,
    })
}

/// Assess BPET guidance and attach calibrated conformal risk-set evidence.
///
/// Positive conformal sets bump the user-facing risk level to at least `High`
/// and append empirical coverage to the summary. The baseline guidance scoring
/// still comes from [`assess_guidance_for_trust_surface`].
pub fn assess_guidance_for_calibrated_trust_surface(
    guidance: &BpetGuidance,
    current_reputation_basis_points: u16,
    explanation: Option<&ExplanationVector>,
    risk_set: &ConformalRiskSet,
    empirical_coverage_basis_points: u16,
) -> Result<BpetTrustSurfaceAssessment, TrustSurfaceIntegrationError> {
    let mut assessment =
        assess_guidance_for_trust_surface(guidance, current_reputation_basis_points, explanation)?;
    apply_calibrated_risk_set(
        &mut assessment,
        risk_set,
        empirical_coverage_basis_points.min(MAX_BASIS_POINTS),
    );
    Ok(assessment)
}

/// Convert BPET guidance into a `TrustCardMutation` suitable for
/// `TrustCardRegistry::update`.
pub fn trust_card_mutation_from_guidance(
    guidance: &BpetGuidance,
    current_reputation_basis_points: u16,
    explanation: Option<&ExplanationVector>,
) -> Result<TrustCardMutation, TrustSurfaceIntegrationError> {
    let assessment =
        assess_guidance_for_trust_surface(guidance, current_reputation_basis_points, explanation)?;

    Ok(TrustCardMutation {
        certification_level: None,
        revocation_status: None,
        active_quarantine: Some(assessment.active_quarantine_recommended),
        reputation_score_basis_points: Some(assessment.reputation_score_basis_points),
        reputation_trend: None,
        user_facing_risk_assessment: Some(RiskAssessment {
            level: assessment.risk_level,
            summary: assessment.summary,
        }),
        last_verified_timestamp: Some(guidance.timestamp.clone()),
        evidence_refs: None,
    })
}

/// Convert BPET guidance plus a conformal risk set into a trust-card mutation.
pub fn trust_card_mutation_from_calibrated_guidance(
    guidance: &BpetGuidance,
    current_reputation_basis_points: u16,
    explanation: Option<&ExplanationVector>,
    risk_set: &ConformalRiskSet,
    empirical_coverage_basis_points: u16,
) -> Result<TrustCardMutation, TrustSurfaceIntegrationError> {
    let assessment = assess_guidance_for_calibrated_trust_surface(
        guidance,
        current_reputation_basis_points,
        explanation,
        risk_set,
        empirical_coverage_basis_points,
    )?;

    Ok(TrustCardMutation {
        certification_level: None,
        revocation_status: None,
        active_quarantine: Some(assessment.active_quarantine_recommended),
        reputation_score_basis_points: Some(assessment.reputation_score_basis_points),
        reputation_trend: None,
        user_facing_risk_assessment: Some(RiskAssessment {
            level: assessment.risk_level,
            summary: assessment.summary,
        }),
        last_verified_timestamp: Some(guidance.timestamp.clone()),
        evidence_refs: None,
    })
}

/// Convert BPET guidance into bounded adversary-posterior update material.
pub fn adversary_posterior_update_from_guidance(
    guidance: &BpetGuidance,
) -> Result<AdversaryPosteriorUpdate, TrustSurfaceIntegrationError> {
    if guidance.package_name.trim().is_empty() {
        return Err(TrustSurfaceIntegrationError::EmptyPackageName);
    }
    let score = max_guidance_propensity(guidance)?;
    validate_motif_scores(guidance)?;
    let confidence = finite_unit("pricing.confidence", guidance.pricing.confidence)?;

    Ok(AdversaryPosteriorUpdate {
        schema_version: TRUST_SURFACE_SCHEMA_VERSION.to_string(),
        subject_id: guidance.package_name.clone(),
        posterior_basis_points: score_to_basis_points(score),
        confidence_basis_points: score_to_basis_points(confidence),
        evidence_summary: format!(
            "BPET trust-surface update from {} motif(s), trace_id={}",
            guidance.motif_matches.len(),
            guidance.trace_id
        ),
    })
}

fn max_guidance_propensity(guidance: &BpetGuidance) -> Result<f64, TrustSurfaceIntegrationError> {
    let headline = finite_unit(
        "guidance.compromise_propensity",
        guidance.compromise_propensity,
    )?;
    let priced = finite_unit(
        "guidance.pricing.compromise_propensity",
        guidance.pricing.compromise_propensity,
    )?;
    Ok(headline.max(priced))
}

fn finite_unit(field: &'static str, value: f64) -> Result<f64, TrustSurfaceIntegrationError> {
    if !value.is_finite() {
        return Err(TrustSurfaceIntegrationError::NonFinitePropensity { field, value });
    }
    Ok(value.clamp(0.0, 1.0))
}

fn validate_motif_scores(guidance: &BpetGuidance) -> Result<(), TrustSurfaceIntegrationError> {
    for motif in &guidance.motif_matches {
        if !motif.match_score.is_finite() || !(0.0..=1.0).contains(&motif.match_score) {
            return Err(TrustSurfaceIntegrationError::InvalidMotifScore(
                motif.match_score,
            ));
        }
    }
    Ok(())
}

fn risk_level_for(score: f64, urgency: PlaybookUrgency, has_critical_motif: bool) -> RiskLevel {
    if score >= CRITICAL_PROPENSITY_THRESHOLD
        || urgency >= PlaybookUrgency::Critical
        || has_critical_motif
    {
        RiskLevel::Critical
    } else if score >= HIGH_PROPENSITY_THRESHOLD || urgency >= PlaybookUrgency::Urgent {
        RiskLevel::High
    } else if score >= MEDIUM_PROPENSITY_THRESHOLD || urgency >= PlaybookUrgency::Elevated {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

fn score_to_basis_points(score: f64) -> u16 {
    (score.clamp(0.0, 1.0) * BASIS_POINTS_SCALE).round() as u16
}

fn apply_reputation_penalty(current_reputation_basis_points: u16, score: f64) -> u16 {
    let penalty = (score.clamp(0.0, 1.0) * f64::from(MAX_REPUTATION_PENALTY_BPS)).round() as u16;
    current_reputation_basis_points.saturating_sub(penalty)
}

fn validated_dominant_feature(
    explanation: &ExplanationVector,
) -> Result<String, TrustSurfaceIntegrationError> {
    let non_finite_feature = explanation
        .feature_contributions
        .iter()
        .find(|(_, value)| !value.is_finite())
        .map(|(name, _)| name.clone());
    if let Some(name) = non_finite_feature {
        return Err(TrustSurfaceIntegrationError::NonFiniteExplanation(name));
    }
    Ok(explanation.dominant_feature.clone())
}

fn trust_surface_summary(
    guidance: &BpetGuidance,
    risk_level: RiskLevel,
    score: f64,
    dominant_feature: Option<&str>,
) -> String {
    let motif = guidance
        .motif_matches
        .first()
        .map(|motif| format!(" top_motif={}", motif.motif_id))
        .unwrap_or_default();
    let feature = dominant_feature
        .map(|feature| format!(" dominant_feature={feature}"))
        .unwrap_or_default();
    format!(
        "BPET trust-surface assessment: package={} level={risk_level:?} propensity={score:.3} motifs={}{}{}",
        guidance.package_name,
        guidance.motif_matches.len(),
        motif,
        feature,
    )
}

fn apply_calibrated_risk_set(
    assessment: &mut BpetTrustSurfaceAssessment,
    risk_set: &ConformalRiskSet,
    empirical_coverage_basis_points: u16,
) {
    if risk_set
        .included_labels
        .iter()
        .any(|label| label == LABEL_POSITIVE)
    {
        assessment.risk_level = assessment.risk_level.max(RiskLevel::High);
    }
    assessment.summary = calibrated_trust_surface_summary(
        &assessment.summary,
        risk_set,
        empirical_coverage_basis_points,
    );
    assessment.calibrated_risk_set = Some(risk_set.clone());
    assessment.empirical_coverage_basis_points = Some(empirical_coverage_basis_points);
}

fn calibrated_trust_surface_summary(
    base_summary: &str,
    risk_set: &ConformalRiskSet,
    empirical_coverage_basis_points: u16,
) -> String {
    let labels = if risk_set.included_labels.is_empty() {
        "none".to_string()
    } else {
        risk_set.included_labels.join("+")
    };
    format!(
        "{base_summary}; calibrated BPET risk set={labels} score_bp={} quantile_bp={} ({:.2}% empirical coverage)",
        risk_set.score_bp,
        risk_set.quantile_bp,
        f64::from(empirical_coverage_basis_points) / 100.0,
    )
}

/// Render calibrated trust-surface assessments as a deterministic transcript.
pub fn render_calibrated_trust_surface_transcript(
    assessments: &[BpetTrustSurfaceAssessment],
) -> String {
    assessments
        .iter()
        .filter_map(|assessment| {
            let risk_set = assessment.calibrated_risk_set.as_ref()?;
            let labels = if risk_set.included_labels.is_empty() {
                "none".to_string()
            } else {
                risk_set.included_labels.join("+")
            };
            Some(format!(
                "event={} package={} risk_class={} level={:?} labels={} score_bp={} quantile_bp={} coverage_bp={}",
                risk_set.event_code,
                assessment.package_name,
                risk_set.risk_class,
                assessment.risk_level,
                labels,
                risk_set.score_bp,
                risk_set.quantile_bp,
                assessment.empirical_coverage_basis_points.unwrap_or_default(),
            ))
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::bpet::economic_integration::{
        BpetMitigationPlaybook, CompromisePricing, InterventionRecommendation, InterventionRoi,
        MotifMatch, PlaybookAction,
    };
    use std::collections::BTreeMap;

    fn guidance(
        propensity: f64,
        urgency: PlaybookUrgency,
        motif_score: Option<f64>,
    ) -> BpetGuidance {
        let motif_matches = motif_score
            .map(|score| {
                vec![MotifMatch {
                    motif_id: "motif-maintainer-turnover".to_string(),
                    motif_name: "Sudden Maintainer Turnover".to_string(),
                    match_score: score,
                    matched_indicators: vec!["dependency_churn".to_string()],
                    estimated_time_to_compromise_days: 30.0,
                }]
            })
            .unwrap_or_default();

        BpetGuidance {
            guidance_id: "guidance-test".to_string(),
            package_name: "npm:@acme/suspicious".to_string(),
            compromise_propensity: propensity,
            pricing: CompromisePricing {
                package_name: "npm:@acme/suspicious".to_string(),
                compromise_propensity: propensity,
                expected_loss_if_compromised: 100_000.0,
                risk_adjusted_cost: propensity * 100_000.0,
                insurance_premium_equivalent: propensity * 120_000.0,
                confidence: 0.81,
            },
            motif_matches,
            top_interventions: vec![InterventionRoi {
                intervention_name: "sandbox_barriers".to_string(),
                intervention_cost: 500.0,
                risk_reduction: 0.3,
                expected_loss_avoided: 30_000.0,
                roi_ratio: 60.0,
                payback_period_days: 7.0,
                recommendation: InterventionRecommendation::StronglyRecommended,
            }],
            playbook: BpetMitigationPlaybook {
                playbook_id: "playbook-test".to_string(),
                urgency,
                recommended_actions: vec![PlaybookAction {
                    action_name: "Apply sandbox escalation".to_string(),
                    description: "Tighten sandbox tier".to_string(),
                    priority: 1,
                    estimated_effort_hours: 2.0,
                }],
                monitoring_escalation: vec!["phenotype_drift_score".to_string()],
                fallback_strategy: "auto-quarantine at critical threshold".to_string(),
            },
            summary: "test guidance".to_string(),
            timestamp: "2026-05-14T00:00:00Z".to_string(),
            trace_id: "trace-bpet-trust-surface".to_string(),
        }
    }

    fn explanation() -> ExplanationVector {
        ExplanationVector {
            schema_version: "evolution-risk-scorer-v1".to_string(),
            feature_contributions: BTreeMap::from([
                ("drift".to_string(), 0.35),
                ("hazard".to_string(), 0.27),
            ]),
            dominant_feature: "drift".to_string(),
            weighting_policy_version: "policy_v1".to_string(),
        }
    }

    fn positive_risk_set() -> ConformalRiskSet {
        ConformalRiskSet {
            event_code: "FN-CONFORMAL-001".to_string(),
            sample_id: "npm:@acme/suspicious@1.0.0".to_string(),
            risk_class: "bpet_evolution".to_string(),
            score_bp: 8_800,
            quantile_bp: 2_000,
            included_labels: vec!["positive".to_string()],
        }
    }

    #[test]
    fn critical_bpet_guidance_maps_to_quarantining_trust_card_mutation() {
        let guidance = guidance(0.91, PlaybookUrgency::Critical, Some(0.95));

        let mutation = trust_card_mutation_from_guidance(&guidance, 8_000, Some(&explanation()))
            .expect("critical BPET guidance should map to trust-card mutation");

        assert_eq!(mutation.active_quarantine, Some(true));
        assert_eq!(mutation.reputation_score_basis_points, Some(3_450));
        let risk = mutation
            .user_facing_risk_assessment
            .expect("risk assessment present");
        assert_eq!(risk.level, RiskLevel::Critical);
        assert!(risk.summary.contains("BPET trust-surface assessment"));
        assert!(risk.summary.contains("top_motif=motif-maintainer-turnover"));
        assert!(risk.summary.contains("dominant_feature=drift"));
    }

    #[test]
    fn routine_bpet_guidance_keeps_low_risk_without_quarantine() {
        let guidance = guidance(0.12, PlaybookUrgency::Routine, None);

        let assessment = assess_guidance_for_trust_surface(&guidance, 8_000, None)
            .expect("routine BPET guidance should assess");

        assert_eq!(assessment.risk_level, RiskLevel::Low);
        assert!(!assessment.active_quarantine_recommended);
        assert_eq!(assessment.reputation_score_basis_points, 7_400);
        assert_eq!(assessment.matched_motif_count, 0);
    }

    #[test]
    fn calibrated_positive_set_bumps_trust_card_risk_to_high_with_coverage() {
        let guidance = guidance(0.12, PlaybookUrgency::Routine, None);

        let mutation = trust_card_mutation_from_calibrated_guidance(
            &guidance,
            8_000,
            Some(&explanation()),
            &positive_risk_set(),
            9_500,
        )
        .expect("calibrated BPET guidance should map to trust-card mutation");

        let risk = mutation
            .user_facing_risk_assessment
            .expect("risk assessment present");
        assert_eq!(risk.level, RiskLevel::High);
        assert!(risk.summary.contains("calibrated BPET risk set=positive"));
        assert!(risk.summary.contains("95.00% empirical coverage"));
        assert_eq!(mutation.active_quarantine, Some(false));
    }

    #[test]
    fn non_finite_bpet_propensity_is_rejected_fail_closed() {
        let guidance = guidance(f64::NAN, PlaybookUrgency::Routine, None);

        let err = assess_guidance_for_trust_surface(&guidance, 8_000, None)
            .expect_err("NaN propensity must not reach trust cards");

        assert!(matches!(
            err,
            TrustSurfaceIntegrationError::NonFinitePropensity { .. }
        ));
    }

    #[test]
    fn adversary_posterior_update_uses_bounded_basis_points() {
        let guidance = guidance(1.4, PlaybookUrgency::Critical, Some(0.75));

        let update = adversary_posterior_update_from_guidance(&guidance)
            .expect("out-of-range finite propensity clamps for posterior export");

        assert_eq!(update.posterior_basis_points, 10_000);
        assert_eq!(update.confidence_basis_points, 8_100);
        assert_eq!(update.subject_id, "npm:@acme/suspicious");
        assert!(update.evidence_summary.contains("trace-bpet-trust-surface"));
    }
}
