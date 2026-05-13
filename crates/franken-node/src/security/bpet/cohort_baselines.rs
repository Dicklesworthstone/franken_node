//! Cohort-aware BPET baseline modeling.
//!
//! The model converts historical phenotype trajectories into deterministic
//! per-cohort baseline distributions that can be fed into the BPET drift
//! engine. All external numeric inputs are guarded before aggregation, cohort
//! ordering is stable through `BTreeMap`, and failures return typed errors
//! rather than partial baselines.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
use crate::push_bounded;

use super::drift_features::DriftEngine;
use super::economic_integration::{PhenotypeObservation, PhenotypeTrajectory};

pub const COHORT_BASELINE_SCHEMA_VERSION: &str = "bpet.cohort_baseline.v1";
pub const MIN_COHORT_BASELINE_BINS: usize = 2;
pub const MAX_COHORT_BASELINE_BINS: usize = 4096;

const PHENOTYPE_FIELDS: &[&str] = &[
    "commit_velocity",
    "contributor_diversity_index",
    "dependency_churn_rate",
    "issue_response_time_hours",
    "maintainer_activity_score",
    "security_patch_latency_hours",
];

pub mod event_codes {
    pub const BPET_COHORT_BASELINE_ACCEPTED: &str = "BPET-COHORT-001";
    pub const BPET_COHORT_BASELINE_REJECTED: &str = "BPET-COHORT-002";
    pub const BPET_COHORT_BASELINE_MODELED: &str = "BPET-COHORT-003";
    pub const BPET_COHORT_BASELINE_COMPARED: &str = "BPET-COHORT-004";
}

#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum CohortBaselineError {
    #[error("at least one cohort is required")]
    EmptyCohortSet,
    #[error("cohort id must not be empty")]
    EmptyCohortId,
    #[error("duplicate cohort id: {0}")]
    DuplicateCohort(String),
    #[error("cohort {0} has no trajectories")]
    EmptyTrajectorySet(String),
    #[error("cohort {0} has no finite phenotype observations")]
    EmptyObservationSet(String),
    #[error("invalid cohort baseline bin count: {0}")]
    InvalidBinCount(usize),
    #[error("cohort not found: {0}")]
    CohortNotFound(String),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CohortBaselineAuditEvent {
    pub event_code: String,
    pub cohort_id: String,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CohortBaseline {
    pub schema_version: String,
    pub cohort_id: String,
    pub package_count: usize,
    pub observation_count: usize,
    pub field_baselines: BTreeMap<String, Vec<f64>>,
    pub field_means: BTreeMap<String, f64>,
}

impl CohortBaseline {
    pub fn drift_baseline(&self) -> BTreeMap<String, Vec<f64>> {
        self.field_baselines.clone()
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CohortDeviation {
    pub cohort_id: String,
    pub package_name: String,
    pub field_deltas: BTreeMap<String, f64>,
    pub mean_absolute_delta: f64,
    pub event_code: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CohortBaselineModel {
    pub schema_version: String,
    pub bin_count: usize,
    pub baselines: BTreeMap<String, CohortBaseline>,
    audit_log: Vec<CohortBaselineAuditEvent>,
}

impl CohortBaselineModel {
    pub fn build<I, S>(bin_count: usize, cohorts: I) -> Result<Self, CohortBaselineError>
    where
        I: IntoIterator<Item = (S, Vec<PhenotypeTrajectory>)>,
        S: Into<String>,
    {
        validate_bin_count(bin_count)?;

        let mut model = Self {
            schema_version: COHORT_BASELINE_SCHEMA_VERSION.to_string(),
            bin_count,
            baselines: BTreeMap::new(),
            audit_log: Vec::new(),
        };
        let mut seen_cohort = false;

        for (raw_cohort_id, trajectories) in cohorts {
            seen_cohort = true;
            let cohort_id = raw_cohort_id.into();
            if cohort_id.trim().is_empty() {
                model.record_rejection("", "empty cohort id");
                return Err(CohortBaselineError::EmptyCohortId);
            }
            if model.baselines.contains_key(&cohort_id) {
                model.record_rejection(&cohort_id, "duplicate cohort id");
                return Err(CohortBaselineError::DuplicateCohort(cohort_id));
            }
            if trajectories.is_empty() {
                model.record_rejection(&cohort_id, "no trajectories");
                return Err(CohortBaselineError::EmptyTrajectorySet(cohort_id));
            }

            let baseline = match build_baseline(&cohort_id, trajectories, bin_count) {
                Ok(baseline) => baseline,
                Err(err) => {
                    model.record_rejection(&cohort_id, "baseline construction failed");
                    return Err(err);
                }
            };
            model.record_acceptance(&baseline);
            model.baselines.insert(cohort_id, baseline);
        }

        if !seen_cohort {
            return Err(CohortBaselineError::EmptyCohortSet);
        }

        Ok(model)
    }

    pub fn baseline_for(&self, cohort_id: &str) -> Option<&CohortBaseline> {
        self.baselines.get(cohort_id)
    }

    pub fn drift_baseline_for(
        &self,
        cohort_id: &str,
    ) -> Result<BTreeMap<String, Vec<f64>>, CohortBaselineError> {
        self.baseline_for(cohort_id)
            .map(CohortBaseline::drift_baseline)
            .ok_or_else(|| CohortBaselineError::CohortNotFound(cohort_id.to_string()))
    }

    pub fn drift_engine_for(&self, cohort_id: &str) -> Result<DriftEngine, CohortBaselineError> {
        let engine = DriftEngine::with_bin_count(self.bin_count)
            .map_err(|_| CohortBaselineError::InvalidBinCount(self.bin_count))?;
        Ok(engine.with_baseline(self.drift_baseline_for(cohort_id)?))
    }

    pub fn compare_trajectory(
        &self,
        cohort_id: &str,
        trajectory: &PhenotypeTrajectory,
    ) -> Result<CohortDeviation, CohortBaselineError> {
        let baseline = self
            .baseline_for(cohort_id)
            .ok_or_else(|| CohortBaselineError::CohortNotFound(cohort_id.to_string()))?;
        let observed = collect_field_values(&trajectory.observations);
        if observed.values().all(Vec::is_empty) {
            return Err(CohortBaselineError::EmptyObservationSet(
                cohort_id.to_string(),
            ));
        }

        let mut field_deltas = BTreeMap::new();
        let mut total = 0.0_f64;
        let mut count = 0_u64;
        for field in PHENOTYPE_FIELDS {
            let Some(values) = observed.get(*field) else {
                continue;
            };
            let Some(observed_mean) = finite_mean(values) else {
                continue;
            };
            let Some(baseline_mean) = baseline.field_means.get(*field) else {
                continue;
            };
            let delta = observed_mean - baseline_mean;
            if delta.is_finite() {
                field_deltas.insert((*field).to_string(), delta);
                total += delta.abs();
                count = count.saturating_add(1);
            }
        }

        let mean_absolute_delta = if count == 0 {
            0.0
        } else {
            total / count as f64
        };

        Ok(CohortDeviation {
            cohort_id: cohort_id.to_string(),
            package_name: trajectory.package_name.clone(),
            field_deltas,
            mean_absolute_delta: if mean_absolute_delta.is_finite() {
                mean_absolute_delta
            } else {
                0.0
            },
            event_code: event_codes::BPET_COHORT_BASELINE_COMPARED.to_string(),
        })
    }

    pub fn audit_log(&self) -> &[CohortBaselineAuditEvent] {
        &self.audit_log
    }

    fn record_acceptance(&mut self, baseline: &CohortBaseline) {
        push_bounded(
            &mut self.audit_log,
            CohortBaselineAuditEvent {
                event_code: event_codes::BPET_COHORT_BASELINE_ACCEPTED.to_string(),
                cohort_id: baseline.cohort_id.clone(),
                detail: format!(
                    "modeled {} packages and {} observations",
                    baseline.package_count, baseline.observation_count
                ),
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
    }

    fn record_rejection(&mut self, cohort_id: &str, detail: &str) {
        push_bounded(
            &mut self.audit_log,
            CohortBaselineAuditEvent {
                event_code: event_codes::BPET_COHORT_BASELINE_REJECTED.to_string(),
                cohort_id: cohort_id.to_string(),
                detail: detail.to_string(),
            },
            MAX_AUDIT_LOG_ENTRIES,
        );
    }
}

fn validate_bin_count(bin_count: usize) -> Result<(), CohortBaselineError> {
    if (MIN_COHORT_BASELINE_BINS..=MAX_COHORT_BASELINE_BINS).contains(&bin_count) {
        Ok(())
    } else {
        Err(CohortBaselineError::InvalidBinCount(bin_count))
    }
}

fn build_baseline(
    cohort_id: &str,
    trajectories: Vec<PhenotypeTrajectory>,
    bin_count: usize,
) -> Result<CohortBaseline, CohortBaselineError> {
    let package_count = trajectories.len();
    let mut observation_count = 0_usize;
    let mut field_values = BTreeMap::new();

    for field in PHENOTYPE_FIELDS {
        field_values.insert((*field).to_string(), Vec::new());
    }

    for trajectory in &trajectories {
        observation_count = observation_count.saturating_add(trajectory.observations.len());
        let observed = collect_field_values(&trajectory.observations);
        for (field, values) in observed {
            field_values.entry(field).or_default().extend(values);
        }
    }

    if field_values.values().all(Vec::is_empty) {
        return Err(CohortBaselineError::EmptyObservationSet(
            cohort_id.to_string(),
        ));
    }

    let mut field_baselines = BTreeMap::new();
    let mut field_means = BTreeMap::new();
    for (field, values) in field_values {
        if values.is_empty() {
            continue;
        }
        if let Some(mean) = finite_mean(&values) {
            field_means.insert(field.clone(), mean);
        }
        field_baselines.insert(field, histogram_probabilities(&values, bin_count));
    }

    Ok(CohortBaseline {
        schema_version: COHORT_BASELINE_SCHEMA_VERSION.to_string(),
        cohort_id: cohort_id.to_string(),
        package_count,
        observation_count,
        field_baselines,
        field_means,
    })
}

fn collect_field_values(observations: &[PhenotypeObservation]) -> BTreeMap<String, Vec<f64>> {
    let mut values = BTreeMap::new();
    for field in PHENOTYPE_FIELDS {
        values.insert((*field).to_string(), Vec::new());
    }

    for observation in observations {
        push_finite(
            &mut values,
            "maintainer_activity_score",
            observation.maintainer_activity_score,
        );
        push_finite(&mut values, "commit_velocity", observation.commit_velocity);
        push_finite(
            &mut values,
            "issue_response_time_hours",
            observation.issue_response_time_hours,
        );
        push_finite(
            &mut values,
            "dependency_churn_rate",
            observation.dependency_churn_rate,
        );
        push_finite(
            &mut values,
            "security_patch_latency_hours",
            observation.security_patch_latency_hours,
        );
        push_finite(
            &mut values,
            "contributor_diversity_index",
            observation.contributor_diversity_index,
        );
    }

    values
}

fn push_finite(values: &mut BTreeMap<String, Vec<f64>>, field: &str, value: f64) {
    if value.is_finite() {
        values.entry(field.to_string()).or_default().push(value);
    }
}

fn finite_mean(values: &[f64]) -> Option<f64> {
    let mut total = 0.0_f64;
    let mut count = 0_u64;
    for value in values {
        if value.is_finite() {
            total += *value;
            count = count.saturating_add(1);
        }
    }
    if count == 0 {
        return None;
    }
    let mean = total / count as f64;
    mean.is_finite().then_some(mean)
}

fn histogram_probabilities(values: &[f64], bin_count: usize) -> Vec<f64> {
    let bin_count = bin_count.clamp(MIN_COHORT_BASELINE_BINS, MAX_COHORT_BASELINE_BINS);
    let mut probs = vec![0.0_f64; bin_count];
    let finite: Vec<f64> = values.iter().copied().filter(|v| v.is_finite()).collect();
    if finite.is_empty() {
        return probs;
    }

    let min_v = finite.iter().copied().fold(f64::INFINITY, f64::min);
    let max_v = finite.iter().copied().fold(f64::NEG_INFINITY, f64::max);
    let range = max_v - min_v;
    if !range.is_finite() || range <= f64::EPSILON {
        if let Some(first) = probs.first_mut() {
            *first = 1.0;
        }
        return probs;
    }

    let bin_width = range / bin_count as f64;
    if !bin_width.is_finite() || bin_width <= 0.0 {
        if let Some(first) = probs.first_mut() {
            *first = 1.0;
        }
        return probs;
    }

    let mut counts = vec![0_u64; bin_count];
    for value in finite {
        let offset = (value - min_v) / bin_width;
        let mut index = if offset.is_finite() {
            offset.floor().max(0.0) as usize
        } else {
            0
        };
        if index >= bin_count {
            index = bin_count - 1;
        }
        if let Some(count) = counts.get_mut(index) {
            *count = count.saturating_add(1);
        }
    }

    let total: u64 = counts.iter().copied().fold(0_u64, u64::saturating_add);
    if total == 0 {
        return probs;
    }
    for (slot, count) in probs.iter_mut().zip(counts.iter()) {
        let p = *count as f64 / total as f64;
        *slot = if p.is_finite() {
            p.clamp(0.0, 1.0)
        } else {
            0.0
        };
    }
    probs
}

#[cfg(test)]
mod tests {
    use super::*;

    fn observation(activity: f64, velocity: f64, response: f64) -> PhenotypeObservation {
        PhenotypeObservation {
            timestamp: "2026-05-13T00:00:00Z".to_string(),
            maintainer_activity_score: activity,
            commit_velocity: velocity,
            issue_response_time_hours: response,
            dependency_churn_rate: 0.10,
            security_patch_latency_hours: 24.0,
            contributor_diversity_index: 0.75,
        }
    }

    fn trajectory(
        package_name: &str,
        observations: Vec<PhenotypeObservation>,
    ) -> PhenotypeTrajectory {
        PhenotypeTrajectory {
            package_name: package_name.to_string(),
            observations,
        }
    }

    fn model() -> CohortBaselineModel {
        CohortBaselineModel::build(
            4,
            [(
                "stable",
                vec![
                    trajectory(
                        "pkg-a",
                        vec![observation(0.90, 12.0, 8.0), observation(0.80, 10.0, 12.0)],
                    ),
                    trajectory("pkg-b", vec![observation(0.85, 11.0, 10.0)]),
                ],
            )],
        )
        .expect("fixture model builds")
    }

    #[test]
    fn cohort_baseline_rejects_too_few_bins() {
        let err = CohortBaselineModel::build(1, [("stable", Vec::new())])
            .expect_err("invalid bin count must fail before modeling");
        assert_eq!(err, CohortBaselineError::InvalidBinCount(1));
    }

    #[test]
    fn cohort_baseline_rejects_too_many_bins() {
        let err = CohortBaselineModel::build(4097, [("stable", Vec::new())])
            .expect_err("invalid bin count must fail before modeling");
        assert_eq!(err, CohortBaselineError::InvalidBinCount(4097));
    }

    #[test]
    fn cohort_baseline_rejects_empty_cohort_set() {
        let cohorts: Vec<(&str, Vec<PhenotypeTrajectory>)> = Vec::new();
        let err =
            CohortBaselineModel::build(4, cohorts).expect_err("empty cohort set must fail closed");
        assert_eq!(err, CohortBaselineError::EmptyCohortSet);
    }

    #[test]
    fn cohort_baseline_rejects_empty_cohort_id() {
        let err = CohortBaselineModel::build(4, [("", vec![trajectory("pkg", Vec::new())])])
            .expect_err("empty cohort id must fail closed");
        assert_eq!(err, CohortBaselineError::EmptyCohortId);
    }

    #[test]
    fn cohort_baseline_rejects_duplicate_cohort_id() {
        let err = CohortBaselineModel::build(
            4,
            [
                (
                    "stable",
                    vec![trajectory("pkg-a", vec![observation(0.8, 4.0, 1.0)])],
                ),
                (
                    "stable",
                    vec![trajectory("pkg-b", vec![observation(0.7, 3.0, 2.0)])],
                ),
            ],
        )
        .expect_err("duplicate cohort ids must fail closed");
        assert_eq!(
            err,
            CohortBaselineError::DuplicateCohort("stable".to_string())
        );
    }

    #[test]
    fn cohort_baseline_rejects_empty_trajectory_set() {
        let err = CohortBaselineModel::build(4, [("stable", Vec::new())])
            .expect_err("empty trajectory set must fail closed");
        assert_eq!(
            err,
            CohortBaselineError::EmptyTrajectorySet("stable".to_string())
        );
    }

    #[test]
    fn cohort_baseline_rejects_empty_observation_set() {
        let err = CohortBaselineModel::build(4, [("stable", vec![trajectory("pkg", Vec::new())])])
            .expect_err("empty observations must fail closed");
        assert_eq!(
            err,
            CohortBaselineError::EmptyObservationSet("stable".to_string())
        );
    }

    #[test]
    fn cohort_baseline_drops_non_finite_fields() {
        let model = CohortBaselineModel::build(
            4,
            [(
                "stable",
                vec![trajectory(
                    "pkg",
                    vec![observation(f64::NAN, 10.0, f64::INFINITY)],
                )],
            )],
        )
        .expect("finite fields still produce baseline");
        let baseline = model.baseline_for("stable").expect("baseline exists");
        assert!(
            !baseline
                .field_means
                .contains_key("maintainer_activity_score")
        );
        assert_eq!(baseline.field_means.get("commit_velocity"), Some(&10.0));
    }

    #[test]
    fn cohort_baseline_uses_stable_schema_version() {
        assert_eq!(model().schema_version, COHORT_BASELINE_SCHEMA_VERSION);
    }

    #[test]
    fn cohort_baseline_records_package_and_observation_counts() {
        let baseline = model()
            .baseline_for("stable")
            .expect("baseline exists")
            .clone();
        assert_eq!(baseline.package_count, 2);
        assert_eq!(baseline.observation_count, 3);
    }

    #[test]
    fn cohort_baseline_field_means_are_computed() {
        let baseline = model()
            .baseline_for("stable")
            .expect("baseline exists")
            .clone();
        assert_eq!(baseline.field_means.get("commit_velocity"), Some(&11.0));
        assert_eq!(
            baseline.field_means.get("issue_response_time_hours"),
            Some(&10.0)
        );
    }

    #[test]
    fn cohort_baseline_histograms_are_normalized() {
        let baseline = model()
            .baseline_for("stable")
            .expect("baseline exists")
            .clone();
        assert!(
            matches!(baseline.field_baselines.get("commit_velocity"), Some(probs) if {
                let sum: f64 = probs.iter().sum();
                (sum - 1.0).abs() < f64::EPSILON
            })
        );
    }

    #[test]
    fn cohort_baseline_degenerate_values_concentrate_first_bin() {
        let model = CohortBaselineModel::build(
            4,
            [(
                "flat",
                vec![trajectory(
                    "pkg",
                    vec![observation(0.8, 5.0, 1.0), observation(0.8, 5.0, 1.0)],
                )],
            )],
        )
        .expect("flat baseline builds");
        assert_eq!(
            model
                .baseline_for("flat")
                .and_then(|baseline| baseline.field_baselines.get("commit_velocity")),
            Some(&vec![1.0, 0.0, 0.0, 0.0])
        );
    }

    #[test]
    fn cohort_baseline_order_is_deterministic() {
        let model = CohortBaselineModel::build(
            4,
            [
                (
                    "zeta",
                    vec![trajectory("pkg-z", vec![observation(0.8, 5.0, 1.0)])],
                ),
                (
                    "alpha",
                    vec![trajectory("pkg-a", vec![observation(0.9, 6.0, 2.0)])],
                ),
            ],
        )
        .expect("model builds");
        let keys: Vec<&str> = model.baselines.keys().map(String::as_str).collect();
        assert_eq!(keys, vec!["alpha", "zeta"]);
    }

    #[test]
    fn cohort_baseline_drift_baseline_returns_clone() {
        let baseline = model()
            .drift_baseline_for("stable")
            .expect("drift baseline exists");
        assert!(baseline.contains_key("commit_velocity"));
    }

    #[test]
    fn cohort_baseline_drift_engine_uses_requested_bin_count() {
        let engine = model()
            .drift_engine_for("stable")
            .expect("drift engine exists");
        assert_eq!(engine.bin_count(), 4);
        assert_eq!(
            engine
                .baseline_for("commit_velocity")
                .map(|baseline| baseline.len()),
            Some(4)
        );
    }

    #[test]
    fn cohort_baseline_unknown_cohort_is_error() {
        let err = model()
            .drift_baseline_for("missing")
            .expect_err("missing cohort must fail closed");
        assert_eq!(
            err,
            CohortBaselineError::CohortNotFound("missing".to_string())
        );
    }

    #[test]
    fn cohort_baseline_compare_matching_trajectory_has_low_delta() {
        let deviation = model()
            .compare_trajectory(
                "stable",
                &trajectory("pkg-c", vec![observation(0.85, 11.0, 10.0)]),
            )
            .expect("comparison succeeds");
        assert!(deviation.mean_absolute_delta < 0.001);
    }

    #[test]
    fn cohort_baseline_compare_shifted_trajectory_has_positive_delta() {
        let deviation = model()
            .compare_trajectory(
                "stable",
                &trajectory("pkg-c", vec![observation(0.10, 1.0, 400.0)]),
            )
            .expect("comparison succeeds");
        assert!(deviation.mean_absolute_delta > 10.0);
    }

    #[test]
    fn cohort_baseline_compare_rejects_empty_observed_trajectory() {
        let err = model()
            .compare_trajectory("stable", &trajectory("empty", Vec::new()))
            .expect_err("empty comparison must fail closed");
        assert_eq!(
            err,
            CohortBaselineError::EmptyObservationSet("stable".to_string())
        );
    }

    #[test]
    fn cohort_baseline_compare_emits_stable_event_code() {
        let deviation = model()
            .compare_trajectory(
                "stable",
                &trajectory("pkg-c", vec![observation(0.85, 11.0, 10.0)]),
            )
            .expect("comparison succeeds");
        assert_eq!(
            deviation.event_code,
            event_codes::BPET_COHORT_BASELINE_COMPARED
        );
    }

    #[test]
    fn cohort_baseline_audit_log_records_acceptance() {
        let model = model();
        assert_eq!(model.audit_log().len(), 1);
        assert_eq!(
            model.audit_log()[0].event_code,
            event_codes::BPET_COHORT_BASELINE_ACCEPTED
        );
    }

    #[test]
    fn cohort_baseline_serde_roundtrip_preserves_model() {
        let model = model();
        let encoded = serde_json::to_string(&model).expect("model serializes");
        let decoded: CohortBaselineModel =
            serde_json::from_str(&encoded).expect("model deserializes");
        assert_eq!(decoded, model);
    }
}
