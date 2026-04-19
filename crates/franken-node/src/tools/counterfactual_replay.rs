//! bd-2fa: Counterfactual replay mode for policy simulation.
//!
//! Replays a deterministic incident bundle under an alternate policy without
//! side effects, then compares original vs counterfactual outcomes.
//!
//! Invariants:
//! - INV-CF-DETERMINISTIC: same bundle + policies => identical output.
//! - INV-CF-SANDBOXED: replay executor is pure computation only.
//! - INV-CF-BOUNDED: replay enforces step and wall-clock bounds.

use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::replay_bundle::{
    EventType, ReplayBundle, ReplayBundleError, TimelineEvent, validate_bundle_integrity,
};

const MAX_SWEEP_VALUES: usize = 20;
const DEFAULT_ENGINE_VERSION: &str = "counterfactual-v1";

// Security: bounds for push_bounded to prevent memory exhaustion
const MAX_POLICY_OVERRIDE_DIFFS: usize = 32;
const MAX_REPLAY_OUTCOMES: usize = 1_000_000;
const MAX_SWEEP_RESULTS: usize = MAX_SWEEP_VALUES;
const MAX_DIVERGENCE_POINTS: usize = 100_000;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if items.len() < cap {
        items.push(item);
    }
}

pub const COUNTERFACTUAL_REPLAY_STARTED: &str = "COUNTERFACTUAL_REPLAY_STARTED";
pub const COUNTERFACTUAL_REPLAY_COMPLETED: &str = "COUNTERFACTUAL_REPLAY_COMPLETED";
pub const COUNTERFACTUAL_BUNDLE_INVALID: &str = "COUNTERFACTUAL_BUNDLE_INVALID";
pub const COUNTERFACTUAL_OVERRIDE_INVALID: &str = "COUNTERFACTUAL_OVERRIDE_INVALID";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyConfig {
    pub policy_name: String,
    pub quarantine_threshold: u64,
    pub observe_threshold: u64,
    pub degraded_mode_bias: i64,
}

impl Default for PolicyConfig {
    fn default() -> Self {
        Self {
            policy_name: "baseline".to_string(),
            quarantine_threshold: 85,
            observe_threshold: 55,
            degraded_mode_bias: 10,
        }
    }
}

impl PolicyConfig {
    #[must_use]
    pub fn from_bundle(bundle: &ReplayBundle) -> Self {
        Self {
            policy_name: bundle.policy_version.clone(),
            ..Self::default()
        }
    }

    pub fn validate(&self) -> Result<(), CounterfactualReplayError> {
        if self.quarantine_threshold > 100 {
            return Err(CounterfactualReplayError::InvalidPolicyOverride {
                message: "quarantine_threshold must be <= 100".to_string(),
            });
        }
        if self.observe_threshold > 100 {
            return Err(CounterfactualReplayError::InvalidPolicyOverride {
                message: "observe_threshold must be <= 100".to_string(),
            });
        }
        if self.observe_threshold > self.quarantine_threshold {
            return Err(CounterfactualReplayError::InvalidPolicyOverride {
                message: "observe_threshold cannot exceed quarantine_threshold".to_string(),
            });
        }
        Ok(())
    }

    pub fn from_cli_spec(
        spec: &str,
        baseline: &PolicyConfig,
    ) -> Result<SimulationMode, CounterfactualReplayError> {
        let trimmed = spec.trim();
        if let Some(rest) = trimmed.strip_prefix("sweep:") {
            return parse_sweep_spec(rest, baseline);
        }

        if trimmed.contains('=') {
            let override_policy = parse_override_spec(trimmed, baseline)?;
            return Ok(SimulationMode::SinglePolicySwap {
                alternate_policy: override_policy,
            });
        }

        let profile = match trimmed {
            "" | "baseline" | "balanced" => baseline.clone(),
            "strict" => PolicyConfig {
                policy_name: "strict".to_string(),
                quarantine_threshold: 70,
                observe_threshold: 45,
                degraded_mode_bias: 20,
            },
            "permissive" => PolicyConfig {
                policy_name: "permissive".to_string(),
                quarantine_threshold: 95,
                observe_threshold: 75,
                degraded_mode_bias: 0,
            },
            _ => {
                return Err(CounterfactualReplayError::InvalidPolicyOverride {
                    message: format!(
                        "unsupported policy profile `{trimmed}`; use strict|balanced|permissive or key=value overrides"
                    ),
                });
            }
        };

        Ok(SimulationMode::SinglePolicySwap {
            alternate_policy: profile,
        })
    }

    pub fn with_numeric_parameter(
        &self,
        parameter: &str,
        value: i64,
    ) -> Result<Self, CounterfactualReplayError> {
        let mut next = self.clone();
        match parameter {
            "quarantine_threshold" => {
                let parsed = u64::try_from(value).map_err(|_| {
                    CounterfactualReplayError::InvalidPolicyOverride {
                        message: format!("quarantine_threshold must be non-negative: {value}"),
                    }
                })?;
                next.quarantine_threshold = parsed;
            }
            "observe_threshold" => {
                let parsed = u64::try_from(value).map_err(|_| {
                    CounterfactualReplayError::InvalidPolicyOverride {
                        message: format!("observe_threshold must be non-negative: {value}"),
                    }
                })?;
                next.observe_threshold = parsed;
            }
            "degraded_mode_bias" => {
                next.degraded_mode_bias = value;
            }
            _ => {
                return Err(CounterfactualReplayError::UnsupportedSweepParameter {
                    parameter: parameter.to_string(),
                });
            }
        }
        next.validate()?;
        Ok(next)
    }

    #[must_use]
    pub fn diff_from(&self, baseline: &PolicyConfig) -> Vec<PolicyOverrideDiffEntry> {
        let mut out = Vec::new();
        if self.policy_name != baseline.policy_name {
            push_bounded(&mut out, PolicyOverrideDiffEntry {
                field: "policy_name".to_string(),
                original: baseline.policy_name.clone(),
                counterfactual: self.policy_name.clone(),
            }, MAX_POLICY_OVERRIDE_DIFFS);
        }
        if self.quarantine_threshold != baseline.quarantine_threshold {
            push_bounded(&mut out, PolicyOverrideDiffEntry {
                field: "quarantine_threshold".to_string(),
                original: baseline.quarantine_threshold.to_string(),
                counterfactual: self.quarantine_threshold.to_string(),
            }, MAX_POLICY_OVERRIDE_DIFFS);
        }
        if self.observe_threshold != baseline.observe_threshold {
            push_bounded(&mut out, PolicyOverrideDiffEntry {
                field: "observe_threshold".to_string(),
                original: baseline.observe_threshold.to_string(),
                counterfactual: self.observe_threshold.to_string(),
            }, MAX_POLICY_OVERRIDE_DIFFS);
        }
        if self.degraded_mode_bias != baseline.degraded_mode_bias {
            push_bounded(&mut out, PolicyOverrideDiffEntry {
                field: "degraded_mode_bias".to_string(),
                original: baseline.degraded_mode_bias.to_string(),
                counterfactual: self.degraded_mode_bias.to_string(),
            }, MAX_POLICY_OVERRIDE_DIFFS);
        }
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionPoint {
    pub sequence_number: u64,
    pub event_type: EventType,
    pub decision: String,
    pub rationale: String,
    pub expected_loss: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ImpactEstimate {
    None,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DivergenceRecord {
    pub sequence_number: u64,
    pub original_decision: String,
    pub counterfactual_decision: String,
    pub original_rationale: String,
    pub counterfactual_rationale: String,
    pub impact_estimate: ImpactEstimate,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SummaryStatistics {
    pub total_decisions: usize,
    pub changed_decisions: usize,
    pub severity_delta: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyOverrideDiffEntry {
    pub field: String,
    pub original: String,
    pub counterfactual: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualMetadata {
    pub bundle_hash: String,
    pub policy_override_diff: Vec<PolicyOverrideDiffEntry>,
    pub replay_timestamp: String,
    pub engine_version: String,
    pub invocation_event_codes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualResult {
    pub scenario_id: String,
    pub original_outcomes: Vec<DecisionPoint>,
    pub counterfactual_outcomes: Vec<DecisionPoint>,
    pub divergence_points: Vec<DivergenceRecord>,
    pub summary_statistics: SummaryStatistics,
    pub metadata: CounterfactualMetadata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum CounterfactualSimulationOutput {
    Single(CounterfactualResult),
    Sweep {
        parameter: String,
        results: Vec<CounterfactualResult>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SimulationMode {
    SinglePolicySwap {
        alternate_policy: PolicyConfig,
    },
    ParameterSweep {
        parameter: String,
        values: Vec<i64>,
        template_policy: PolicyConfig,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayExecutionBounds {
    pub max_replay_steps: usize,
    pub max_wall_clock_millis: u64,
}

impl Default for ReplayExecutionBounds {
    fn default() -> Self {
        Self {
            max_replay_steps: 100_000,
            max_wall_clock_millis: 30_000,
        }
    }
}

impl ReplayExecutionBounds {
    #[must_use]
    pub fn max_duration(self) -> Duration {
        Duration::from_millis(self.max_wall_clock_millis)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum CounterfactualReplayError {
    #[error("{COUNTERFACTUAL_BUNDLE_INVALID}: replay bundle integrity check failed")]
    BundleIntegrityInvalid,
    #[error("{COUNTERFACTUAL_BUNDLE_INVALID}: failed while validating bundle integrity: {message}")]
    BundleIntegrityCheck { message: String },
    #[error("{COUNTERFACTUAL_OVERRIDE_INVALID}: {message}")]
    InvalidPolicyOverride { message: String },
    #[error("{COUNTERFACTUAL_OVERRIDE_INVALID}: unsupported sweep parameter `{parameter}`")]
    UnsupportedSweepParameter { parameter: String },
    #[error(
        "{COUNTERFACTUAL_OVERRIDE_INVALID}: parameter sweep requires 1..={MAX_SWEEP_VALUES} values (got {count})"
    )]
    InvalidSweepCardinality { count: usize },
    #[error(
        "{COUNTERFACTUAL_REPLAY_COMPLETED}: replay step limit exceeded (max={max_replay_steps}, processed={processed_steps})"
    )]
    StepLimitExceeded {
        max_replay_steps: usize,
        processed_steps: usize,
        partial_result: Box<CounterfactualResult>,
    },
    #[error(
        "{COUNTERFACTUAL_REPLAY_COMPLETED}: replay wall-clock exceeded (max_ms={max_wall_clock_millis}, elapsed_ms={elapsed_ms})"
    )]
    WallClockExceeded {
        max_wall_clock_millis: u64,
        elapsed_ms: u128,
        partial_result: Box<CounterfactualResult>,
    },
}

impl CounterfactualReplayError {
    #[must_use]
    pub fn partial_result(&self) -> Option<&CounterfactualResult> {
        match self {
            Self::StepLimitExceeded { partial_result, .. }
            | Self::WallClockExceeded { partial_result, .. } => Some(partial_result),
            _ => None,
        }
    }
}

pub trait SandboxedExecutor {
    fn evaluate_event(&self, event: &TimelineEvent, policy: &PolicyConfig) -> DecisionPoint;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct PureSandboxedExecutor;

impl SandboxedExecutor for PureSandboxedExecutor {
    fn evaluate_event(&self, event: &TimelineEvent, policy: &PolicyConfig) -> DecisionPoint {
        let mut risk = base_risk_score(event);
        if event_indicates_degraded_mode(event) {
            risk = risk.saturating_add(policy.degraded_mode_bias);
        }

        let clamped = risk.clamp(0, 100);
        let decision = if u64::try_from(clamped).unwrap_or(0) >= policy.quarantine_threshold {
            "quarantine"
        } else if u64::try_from(clamped).unwrap_or(0) >= policy.observe_threshold {
            "observe"
        } else {
            "allow"
        };

        let expected_loss = expected_loss_from_decision(decision, clamped);
        let rationale = format!(
            "event={} risk={} policy={} thresholds=({}, {})",
            event.event_type.as_str(),
            clamped,
            policy.policy_name,
            policy.observe_threshold,
            policy.quarantine_threshold
        );

        DecisionPoint {
            sequence_number: event.sequence_number,
            event_type: event.event_type,
            decision: decision.to_string(),
            rationale,
            expected_loss,
        }
    }
}

#[derive(Debug, Clone)]
pub struct CounterfactualReplayEngine<E = PureSandboxedExecutor> {
    executor: E,
    bounds: ReplayExecutionBounds,
    engine_version: String,
}

impl Default for CounterfactualReplayEngine<PureSandboxedExecutor> {
    fn default() -> Self {
        Self {
            executor: PureSandboxedExecutor,
            bounds: ReplayExecutionBounds::default(),
            engine_version: DEFAULT_ENGINE_VERSION.to_string(),
        }
    }
}

impl<E> CounterfactualReplayEngine<E>
where
    E: SandboxedExecutor,
{
    #[must_use]
    pub fn new(executor: E, bounds: ReplayExecutionBounds) -> Self {
        Self {
            executor,
            bounds,
            engine_version: DEFAULT_ENGINE_VERSION.to_string(),
        }
    }

    #[must_use]
    pub fn with_engine_version(mut self, engine_version: impl Into<String>) -> Self {
        self.engine_version = engine_version.into();
        self
    }

    pub fn replay(
        &self,
        bundle: &ReplayBundle,
        alternate_policy: &PolicyConfig,
    ) -> Result<CounterfactualResult, CounterfactualReplayError> {
        let baseline = PolicyConfig::from_bundle(bundle);
        self.replay_with_baseline(bundle, &baseline, alternate_policy)
    }

    pub fn replay_with_baseline(
        &self,
        bundle: &ReplayBundle,
        baseline_policy: &PolicyConfig,
        alternate_policy: &PolicyConfig,
    ) -> Result<CounterfactualResult, CounterfactualReplayError> {
        ensure_bundle_integrity(bundle)?;
        baseline_policy.validate()?;
        alternate_policy.validate()?;

        let started = Instant::now();
        let mut original_outcomes = Vec::with_capacity(bundle.timeline.len());
        let mut counterfactual_outcomes = Vec::with_capacity(bundle.timeline.len());

        for (idx, event) in bundle.timeline.iter().enumerate() {
            if started.elapsed() >= self.bounds.max_duration() {
                let partial = self.build_result(
                    bundle,
                    baseline_policy,
                    alternate_policy,
                    original_outcomes,
                    counterfactual_outcomes,
                );
                return Err(CounterfactualReplayError::WallClockExceeded {
                    max_wall_clock_millis: self.bounds.max_wall_clock_millis,
                    elapsed_ms: started.elapsed().as_millis(),
                    partial_result: Box::new(partial),
                });
            }

            let step_number = idx.saturating_add(1);
            if step_number > self.bounds.max_replay_steps {
                let partial = self.build_result(
                    bundle,
                    baseline_policy,
                    alternate_policy,
                    original_outcomes,
                    counterfactual_outcomes,
                );
                return Err(CounterfactualReplayError::StepLimitExceeded {
                    max_replay_steps: self.bounds.max_replay_steps,
                    processed_steps: idx,
                    partial_result: Box::new(partial),
                });
            }

            push_bounded(&mut original_outcomes, self.executor.evaluate_event(event, baseline_policy), MAX_REPLAY_OUTCOMES);
            push_bounded(&mut counterfactual_outcomes, self.executor.evaluate_event(event, alternate_policy), MAX_REPLAY_OUTCOMES);
        }

        Ok(self.build_result(
            bundle,
            baseline_policy,
            alternate_policy,
            original_outcomes,
            counterfactual_outcomes,
        ))
    }

    pub fn simulate(
        &self,
        bundle: &ReplayBundle,
        baseline_policy: &PolicyConfig,
        mode: SimulationMode,
    ) -> Result<CounterfactualSimulationOutput, CounterfactualReplayError> {
        match mode {
            SimulationMode::SinglePolicySwap { alternate_policy } => {
                let result =
                    self.replay_with_baseline(bundle, baseline_policy, &alternate_policy)?;
                Ok(CounterfactualSimulationOutput::Single(result))
            }
            SimulationMode::ParameterSweep {
                parameter,
                values,
                template_policy,
            } => {
                if values.is_empty() || values.len() > MAX_SWEEP_VALUES {
                    return Err(CounterfactualReplayError::InvalidSweepCardinality {
                        count: values.len(),
                    });
                }

                let mut results = Vec::with_capacity(values.len());
                for value in values {
                    let mut policy = template_policy.with_numeric_parameter(&parameter, value)?;
                    policy.policy_name =
                        format!("{}:{}={value}", template_policy.policy_name, parameter);
                    push_bounded(&mut results, self.replay_with_baseline(bundle, baseline_policy, &policy)?, MAX_SWEEP_RESULTS);
                }

                Ok(CounterfactualSimulationOutput::Sweep { parameter, results })
            }
        }
    }

    fn build_result(
        &self,
        bundle: &ReplayBundle,
        baseline_policy: &PolicyConfig,
        alternate_policy: &PolicyConfig,
        original_outcomes: Vec<DecisionPoint>,
        counterfactual_outcomes: Vec<DecisionPoint>,
    ) -> CounterfactualResult {
        let mut divergence_points = Vec::new();
        let mut changed_decisions = 0_usize;
        let mut original_loss_total: i64 = 0;
        let mut counterfactual_loss_total: i64 = 0;

        for (original, counterfactual) in
            original_outcomes.iter().zip(counterfactual_outcomes.iter())
        {
            original_loss_total = original_loss_total
                .saturating_add(i64::try_from(original.expected_loss).unwrap_or(i64::MAX));
            counterfactual_loss_total = counterfactual_loss_total
                .saturating_add(i64::try_from(counterfactual.expected_loss).unwrap_or(i64::MAX));

            if original.decision != counterfactual.decision {
                changed_decisions = changed_decisions.saturating_add(1);
                let delta = i64::try_from(counterfactual.expected_loss)
                    .unwrap_or(i64::MAX)
                    .saturating_sub(i64::try_from(original.expected_loss).unwrap_or(i64::MAX));
                push_bounded(&mut divergence_points, DivergenceRecord {
                    sequence_number: original.sequence_number,
                    original_decision: original.decision.clone(),
                    counterfactual_decision: counterfactual.decision.clone(),
                    original_rationale: original.rationale.clone(),
                    counterfactual_rationale: counterfactual.rationale.clone(),
                    impact_estimate: classify_impact(delta),
                }, MAX_DIVERGENCE_POINTS);
            }
        }

        let severity_delta = counterfactual_loss_total.saturating_sub(original_loss_total);
        CounterfactualResult {
            scenario_id: format!("{}::{}", bundle.incident_id, alternate_policy.policy_name),
            summary_statistics: SummaryStatistics {
                total_decisions: original_outcomes.len(),
                changed_decisions,
                severity_delta,
            },
            metadata: CounterfactualMetadata {
                bundle_hash: bundle.integrity_hash.clone(),
                policy_override_diff: alternate_policy.diff_from(baseline_policy),
                replay_timestamp: bundle.created_at.clone(),
                engine_version: self.engine_version.clone(),
                invocation_event_codes: vec![
                    COUNTERFACTUAL_REPLAY_STARTED.to_string(),
                    COUNTERFACTUAL_REPLAY_COMPLETED.to_string(),
                ],
            },
            original_outcomes,
            counterfactual_outcomes,
            divergence_points,
        }
    }
}

fn ensure_bundle_integrity(bundle: &ReplayBundle) -> Result<(), CounterfactualReplayError> {
    match validate_bundle_integrity(bundle) {
        Ok(true) => Ok(()),
        Ok(false) => Err(CounterfactualReplayError::BundleIntegrityInvalid),
        Err(err) => Err(CounterfactualReplayError::BundleIntegrityCheck {
            message: err.to_string(),
        }),
    }
}

fn parse_override_spec(
    spec: &str,
    baseline: &PolicyConfig,
) -> Result<PolicyConfig, CounterfactualReplayError> {
    let mut next = baseline.clone();
    for segment in spec.split(',') {
        let part = segment.trim();
        if part.is_empty() {
            continue;
        }
        let (raw_key, raw_value) = part.split_once('=').ok_or_else(|| {
            CounterfactualReplayError::InvalidPolicyOverride {
                message: format!("invalid override segment `{part}`"),
            }
        })?;
        let key = raw_key.trim();
        let value = raw_value.trim();
        match key {
            "policy_name" | "name" => {
                if value.is_empty() {
                    return Err(CounterfactualReplayError::InvalidPolicyOverride {
                        message: "policy name cannot be empty".to_string(),
                    });
                }
                next.policy_name = value.to_string();
            }
            "quarantine_threshold" => {
                next.quarantine_threshold = parse_u64(value, key)?;
            }
            "observe_threshold" => {
                next.observe_threshold = parse_u64(value, key)?;
            }
            "degraded_mode_bias" => {
                next.degraded_mode_bias = parse_i64(value, key)?;
            }
            _ => {
                return Err(CounterfactualReplayError::InvalidPolicyOverride {
                    message: format!("unsupported override key `{key}`"),
                });
            }
        }
    }
    next.validate()?;
    Ok(next)
}

fn parse_sweep_spec(
    spec: &str,
    baseline: &PolicyConfig,
) -> Result<SimulationMode, CounterfactualReplayError> {
    let (raw_parameter, raw_values) =
        spec.split_once('=')
            .ok_or_else(|| CounterfactualReplayError::InvalidPolicyOverride {
                message: "sweep spec must be `sweep:<parameter>=v1|v2|...`".to_string(),
            })?;
    let parameter = raw_parameter.trim().to_string();
    if parameter.is_empty() {
        return Err(CounterfactualReplayError::InvalidPolicyOverride {
            message: "sweep parameter cannot be empty".to_string(),
        });
    }

    let values: Result<Vec<i64>, CounterfactualReplayError> = raw_values
        .split('|')
        .map(str::trim)
        .filter(|segment| !segment.is_empty())
        .map(|segment| parse_i64(segment, &parameter))
        .collect();
    let parsed = values?;
    if parsed.is_empty() || parsed.len() > MAX_SWEEP_VALUES {
        return Err(CounterfactualReplayError::InvalidSweepCardinality {
            count: parsed.len(),
        });
    }

    Ok(SimulationMode::ParameterSweep {
        parameter,
        values: parsed,
        template_policy: baseline.clone(),
    })
}

fn parse_u64(value: &str, key: &str) -> Result<u64, CounterfactualReplayError> {
    value
        .parse::<u64>()
        .map_err(|_| CounterfactualReplayError::InvalidPolicyOverride {
            message: format!("failed parsing `{key}` as u64: {value}"),
        })
}

fn parse_i64(value: &str, key: &str) -> Result<i64, CounterfactualReplayError> {
    value
        .parse::<i64>()
        .map_err(|_| CounterfactualReplayError::InvalidPolicyOverride {
            message: format!("failed parsing `{key}` as i64: {value}"),
        })
}

fn base_risk_score(event: &TimelineEvent) -> i64 {
    let payload = &event.payload;
    extract_integer(payload, "confidence")
        .or_else(|| extract_integer(payload, "risk_score"))
        .or_else(|| {
            extract_string(payload, "severity").map(|severity| match severity {
                "critical" => 97,
                "high" => 84,
                "medium" => 62,
                "low" => 30,
                _ => 50,
            })
        })
        .or_else(|| {
            extract_string(payload, "decision").map(|decision| match decision {
                "quarantine" => 90,
                "block" => 88,
                "observe" => 60,
                "allow" => 35,
                _ => 50,
            })
        })
        .unwrap_or(50)
}

fn event_indicates_degraded_mode(event: &TimelineEvent) -> bool {
    extract_bool(&event.payload, "degraded_mode").unwrap_or(false)
        || extract_string(&event.payload, "mode").is_some_and(|mode| mode == "degraded")
}

fn extract_integer(payload: &Value, key: &str) -> Option<i64> {
    payload.as_object()?.get(key)?.as_i64()
}

fn extract_string<'a>(payload: &'a Value, key: &str) -> Option<&'a str> {
    payload.as_object()?.get(key)?.as_str()
}

fn extract_bool(payload: &Value, key: &str) -> Option<bool> {
    payload.as_object()?.get(key)?.as_bool()
}

fn expected_loss_from_decision(decision: &str, risk: i64) -> u64 {
    let risk_clamped = risk.clamp(0, 100);
    let penalty = match decision {
        "quarantine" => (100_i64.saturating_sub(risk_clamped)) / 2,
        "observe" => risk_clamped / 4,
        "allow" => risk_clamped / 2,
        _ => 0,
    };
    let base = match decision {
        "quarantine" => 8_i64,
        "observe" => 24_i64,
        "allow" => 58_i64,
        _ => 35_i64,
    };
    u64::try_from(base.saturating_add(penalty)).unwrap_or(0)
}

fn classify_impact(delta: i64) -> ImpactEstimate {
    let abs_delta = delta.unsigned_abs();
    match abs_delta {
        0 => ImpactEstimate::None,
        1..=9 => ImpactEstimate::Low,
        10..=24 => ImpactEstimate::Medium,
        25..=49 => ImpactEstimate::High,
        _ => ImpactEstimate::Critical,
    }
}

pub fn to_canonical_json<T>(value: &T) -> Result<String, CounterfactualReplayError>
where
    T: Serialize,
{
    let value = serde_json::to_value(value).map_err(|err| {
        CounterfactualReplayError::InvalidPolicyOverride {
            message: format!("failed to serialize counterfactual output: {err}"),
        }
    })?;
    let canonical = canonicalize_json(&value);
    serde_json::to_string(&canonical).map_err(|err| {
        CounterfactualReplayError::InvalidPolicyOverride {
            message: format!("failed to encode counterfactual output as json: {err}"),
        }
    })
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            let mut out = serde_json::Map::with_capacity(map.len());
            for key in keys {
                out.insert(key.to_string(), canonicalize_json(&map[key]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json).collect()),
        _ => value.clone(),
    }
}

pub fn summarize_output(output: &CounterfactualSimulationOutput) -> (usize, usize, i64) {
    match output {
        CounterfactualSimulationOutput::Single(result) => (
            result.summary_statistics.total_decisions,
            result.summary_statistics.changed_decisions,
            result.summary_statistics.severity_delta,
        ),
        CounterfactualSimulationOutput::Sweep { results, .. } => {
            let total = results
                .iter()
                .map(|r| r.summary_statistics.total_decisions)
                .fold(0usize, |a, b| a.saturating_add(b));
            let changed = results
                .iter()
                .map(|r| r.summary_statistics.changed_decisions)
                .fold(0usize, |a, b| a.saturating_add(b));
            let delta = results
                .iter()
                .map(|r| r.summary_statistics.severity_delta)
                .fold(0i64, |a, b| a.saturating_add(b));
            (total, changed, delta)
        }
    }
}

pub fn error_from_bundle(err: ReplayBundleError) -> CounterfactualReplayError {
    CounterfactualReplayError::BundleIntegrityCheck {
        message: err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tools::replay_bundle::{RawEvent, generate_replay_bundle};

    fn fixture_bundle() -> ReplayBundle {
        let events = vec![
            RawEvent::new(
                "2026-02-20T12:00:00.000001Z",
                EventType::ExternalSignal,
                serde_json::json!({
                    "severity": "high",
                    "degraded_mode": true,
                    "signal": "risk-spike"
                }),
            )
            .with_policy_version("1.0.0")
            .with_state_snapshot(serde_json::json!({"epoch": 44, "mode": "degraded"})),
            RawEvent::new(
                "2026-02-20T12:00:00.000250Z",
                EventType::PolicyEval,
                serde_json::json!({
                    "confidence": 68_u64,
                    "decision": "observe",
                    "rule_id": "policy.rule.recheck"
                }),
            )
            .with_causal_parent(1),
            RawEvent::new(
                "2026-02-20T12:00:00.000500Z",
                EventType::OperatorAction,
                serde_json::json!({
                    "confidence": 46_u64,
                    "action": "continue",
                    "result": "accepted"
                }),
            )
            .with_causal_parent(2),
        ];
        generate_replay_bundle("INC-CF-001", &events).expect("bundle")
    }

    #[test]
    fn single_policy_swap_diverges() {
        let bundle = fixture_bundle();
        let engine = CounterfactualReplayEngine::default();
        let baseline = PolicyConfig::from_bundle(&bundle);
        let alternate = PolicyConfig {
            policy_name: "strict".to_string(),
            quarantine_threshold: 65,
            observe_threshold: 35,
            degraded_mode_bias: 30,
        };
        let result = engine
            .replay_with_baseline(&bundle, &baseline, &alternate)
            .expect("single replay");
        assert_eq!(result.summary_statistics.total_decisions, 3);
        assert!(!result.divergence_points.is_empty());
    }

    #[test]
    fn replay_is_deterministic() {
        let bundle = fixture_bundle();
        let engine = CounterfactualReplayEngine::default();
        let baseline = PolicyConfig::from_bundle(&bundle);
        let alternate = PolicyConfig {
            policy_name: "strict".to_string(),
            quarantine_threshold: 65,
            observe_threshold: 35,
            degraded_mode_bias: 30,
        };
        let first = engine
            .replay_with_baseline(&bundle, &baseline, &alternate)
            .expect("first");
        let second = engine
            .replay_with_baseline(&bundle, &baseline, &alternate)
            .expect("second");
        assert_eq!(first, second);
        let first_json = to_canonical_json(&first).expect("json first");
        let second_json = to_canonical_json(&second).expect("json second");
        assert_eq!(first_json, second_json);
    }

    #[test]
    fn parameter_sweep_runs_multiple_scenarios() {
        let bundle = fixture_bundle();
        let engine = CounterfactualReplayEngine::default();
        let baseline = PolicyConfig::from_bundle(&bundle);
        let output = engine
            .simulate(
                &bundle,
                &baseline,
                SimulationMode::ParameterSweep {
                    parameter: "quarantine_threshold".to_string(),
                    values: vec![60, 75, 90],
                    template_policy: PolicyConfig {
                        policy_name: "sweep".to_string(),
                        ..baseline.clone()
                    },
                },
            )
            .expect("sweep");

        match output {
            CounterfactualSimulationOutput::Sweep { parameter, results } => {
                assert_eq!(parameter, "quarantine_threshold");
                assert_eq!(results.len(), 3);
                assert!(results.iter().any(|r| !r.divergence_points.is_empty()));
            }
            CounterfactualSimulationOutput::Single(_) => unreachable!("expected sweep output"),
        }
    }

    #[test]
    fn step_limit_returns_partial_result() {
        let bundle = fixture_bundle();
        let baseline = PolicyConfig::from_bundle(&bundle);
        let alternate = PolicyConfig {
            policy_name: "strict".to_string(),
            quarantine_threshold: 65,
            observe_threshold: 35,
            degraded_mode_bias: 30,
        };
        let engine = CounterfactualReplayEngine::new(
            PureSandboxedExecutor,
            ReplayExecutionBounds {
                max_replay_steps: 1,
                max_wall_clock_millis: 30_000,
            },
        );
        let err = engine
            .replay_with_baseline(&bundle, &baseline, &alternate)
            .expect_err("step limit");
        match err {
            CounterfactualReplayError::StepLimitExceeded {
                processed_steps,
                partial_result,
                ..
            } => {
                assert_eq!(processed_steps, 1);
                assert_eq!(partial_result.summary_statistics.total_decisions, 1);
            }
            _ => unreachable!("expected step limit error"),
        }
    }

    #[test]
    fn wall_clock_limit_returns_partial_result() {
        let bundle = fixture_bundle();
        let baseline = PolicyConfig::from_bundle(&bundle);
        let alternate = PolicyConfig {
            policy_name: "strict".to_string(),
            quarantine_threshold: 65,
            observe_threshold: 35,
            degraded_mode_bias: 30,
        };
        let engine = CounterfactualReplayEngine::new(
            PureSandboxedExecutor,
            ReplayExecutionBounds {
                max_replay_steps: 100_000,
                max_wall_clock_millis: 0,
            },
        );
        let err = engine
            .replay_with_baseline(&bundle, &baseline, &alternate)
            .expect_err("wall clock limit");
        match err {
            CounterfactualReplayError::WallClockExceeded { partial_result, .. } => {
                assert_eq!(partial_result.summary_statistics.total_decisions, 0);
            }
            _ => unreachable!("expected wall clock error"),
        }
    }

    #[test]
    fn parse_single_override() {
        let baseline = PolicyConfig::default();
        let mode =
            PolicyConfig::from_cli_spec("policy_name=trial,quarantine_threshold=61", &baseline)
                .expect("parsed");
        match mode {
            SimulationMode::SinglePolicySwap { alternate_policy } => {
                assert_eq!(alternate_policy.policy_name, "trial");
                assert_eq!(alternate_policy.quarantine_threshold, 61);
            }
            SimulationMode::ParameterSweep { .. } => unreachable!("expected single mode"),
        }
    }

    #[test]
    fn parse_sweep_override() {
        let baseline = PolicyConfig::default();
        let mode = PolicyConfig::from_cli_spec("sweep:observe_threshold=40|50|60", &baseline)
            .expect("sweep parsed");
        match mode {
            SimulationMode::ParameterSweep {
                parameter, values, ..
            } => {
                assert_eq!(parameter, "observe_threshold");
                assert_eq!(values, vec![40, 50, 60]);
            }
            SimulationMode::SinglePolicySwap { .. } => unreachable!("expected sweep mode"),
        }
    }

    #[test]
    fn invalid_sweep_cardinality_rejected() {
        let baseline = PolicyConfig::default();
        let spec = format!(
            "sweep:quarantine_threshold={}",
            (0..=MAX_SWEEP_VALUES)
                .map(|v| v.to_string())
                .collect::<Vec<_>>()
                .join("|")
        );
        let err = PolicyConfig::from_cli_spec(&spec, &baseline).expect_err("must fail");
        assert!(matches!(
            err,
            CounterfactualReplayError::InvalidSweepCardinality { .. }
        ));
    }

    fn assert_invalid_policy(err: CounterfactualReplayError, expected: &str) {
        match err {
            CounterfactualReplayError::InvalidPolicyOverride { message } => {
                assert!(
                    message.contains(expected),
                    "expected `{message}` to mention `{expected}`"
                );
            }
            _ => unreachable!("expected invalid policy override error"),
        }
    }

    #[test]
    fn validation_rejects_quarantine_threshold_above_cap() {
        let policy = PolicyConfig {
            quarantine_threshold: 101,
            ..PolicyConfig::default()
        };

        let err = policy.validate().expect_err("quarantine cap must fail");

        assert_invalid_policy(err, "quarantine_threshold");
    }

    #[test]
    fn validation_rejects_observe_threshold_above_cap() {
        let policy = PolicyConfig {
            observe_threshold: 101,
            ..PolicyConfig::default()
        };

        let err = policy.validate().expect_err("observe cap must fail");

        assert_invalid_policy(err, "observe_threshold");
    }

    #[test]
    fn validation_rejects_observe_threshold_above_quarantine_threshold() {
        let policy = PolicyConfig {
            quarantine_threshold: 40,
            observe_threshold: 41,
            ..PolicyConfig::default()
        };

        let err = policy
            .validate()
            .expect_err("inverted thresholds must fail");

        assert_invalid_policy(err, "observe_threshold cannot exceed");
    }

    #[test]
    fn cli_spec_rejects_unknown_policy_profile() {
        let baseline = PolicyConfig::default();

        let err = PolicyConfig::from_cli_spec("unknown-profile", &baseline)
            .expect_err("unknown profile must fail");

        assert_invalid_policy(err, "unsupported policy profile");
    }

    #[test]
    fn cli_spec_rejects_override_segment_without_equals() {
        let baseline = PolicyConfig::default();

        let err = PolicyConfig::from_cli_spec("quarantine_threshold=70,badsegment", &baseline)
            .expect_err("malformed override segment must fail");

        assert_invalid_policy(err, "invalid override segment");
    }

    #[test]
    fn cli_spec_rejects_empty_policy_name_override() {
        let baseline = PolicyConfig::default();

        let err =
            PolicyConfig::from_cli_spec("policy_name=   ", &baseline).expect_err("empty name");

        assert_invalid_policy(err, "policy name cannot be empty");
    }

    #[test]
    fn cli_spec_rejects_non_numeric_threshold_override() {
        let baseline = PolicyConfig::default();

        let err = PolicyConfig::from_cli_spec("observe_threshold=not-a-number", &baseline)
            .expect_err("non numeric threshold must fail");

        assert_invalid_policy(err, "failed parsing `observe_threshold` as u64");
    }

    #[test]
    fn sweep_spec_rejects_missing_parameter_name() {
        let baseline = PolicyConfig::default();

        let err = PolicyConfig::from_cli_spec("sweep:=40|50", &baseline)
            .expect_err("missing sweep parameter must fail");

        assert_invalid_policy(err, "sweep parameter cannot be empty");
    }

    #[test]
    fn sweep_spec_rejects_blank_value_list() {
        let baseline = PolicyConfig::default();

        let err = PolicyConfig::from_cli_spec("sweep:observe_threshold= | ", &baseline)
            .expect_err("blank sweep values must fail");

        assert!(matches!(
            err,
            CounterfactualReplayError::InvalidSweepCardinality { count: 0 }
        ));
    }

    #[test]
    fn numeric_parameter_rejects_negative_unsigned_threshold() {
        let baseline = PolicyConfig::default();

        let err = baseline
            .with_numeric_parameter("quarantine_threshold", -1)
            .expect_err("negative unsigned threshold must fail");

        assert_invalid_policy(err, "must be non-negative");
    }

    #[test]
    fn numeric_parameter_rejects_unsupported_parameter() {
        let baseline = PolicyConfig::default();

        let err = baseline
            .with_numeric_parameter("unsupported_threshold", 1)
            .expect_err("unsupported parameter must fail");

        assert!(matches!(
            err,
            CounterfactualReplayError::UnsupportedSweepParameter { parameter }
                if parameter == "unsupported_threshold"
        ));
    }

    #[test]
    fn cli_spec_rejects_unsupported_override_key() {
        let baseline = PolicyConfig::default();

        let err = PolicyConfig::from_cli_spec("unsupported_threshold=90", &baseline)
            .expect_err("unsupported override key must fail");

        assert_invalid_policy(err, "unsupported override key `unsupported_threshold`");
    }

    #[test]
    fn cli_spec_rejects_negative_unsigned_threshold_override() {
        let baseline = PolicyConfig::default();

        let err = PolicyConfig::from_cli_spec("quarantine_threshold=-1", &baseline)
            .expect_err("negative threshold override must fail");

        assert_invalid_policy(err, "failed parsing `quarantine_threshold` as u64");
    }

    #[test]
    fn sweep_spec_rejects_missing_equals_separator() {
        let baseline = PolicyConfig::default();

        let err = PolicyConfig::from_cli_spec("sweep:quarantine_threshold", &baseline)
            .expect_err("sweep spec without equals must fail");

        assert_invalid_policy(err, "sweep spec must be");
    }

    #[test]
    fn direct_sweep_mode_rejects_empty_values() {
        let bundle = fixture_bundle();
        let baseline = PolicyConfig::from_bundle(&bundle);
        let engine = CounterfactualReplayEngine::default();

        let err = engine
            .simulate(
                &bundle,
                &baseline,
                SimulationMode::ParameterSweep {
                    parameter: "observe_threshold".to_string(),
                    values: vec![],
                    template_policy: baseline.clone(),
                },
            )
            .expect_err("empty sweep values must fail");

        assert!(matches!(
            err,
            CounterfactualReplayError::InvalidSweepCardinality { count: 0 }
        ));
    }

    #[test]
    fn direct_sweep_mode_rejects_too_many_values() {
        let bundle = fixture_bundle();
        let baseline = PolicyConfig::from_bundle(&bundle);
        let engine = CounterfactualReplayEngine::default();
        let values = (0..=MAX_SWEEP_VALUES)
            .map(|value| i64::try_from(value).unwrap_or(i64::MAX))
            .collect::<Vec<_>>();

        let err = engine
            .simulate(
                &bundle,
                &baseline,
                SimulationMode::ParameterSweep {
                    parameter: "degraded_mode_bias".to_string(),
                    values,
                    template_policy: baseline.clone(),
                },
            )
            .expect_err("oversized sweep values must fail");

        assert!(matches!(
            err,
            CounterfactualReplayError::InvalidSweepCardinality { count }
                if count == MAX_SWEEP_VALUES + 1
        ));
    }

    #[test]
    fn direct_sweep_mode_rejects_negative_unsigned_parameter_value() {
        let bundle = fixture_bundle();
        let baseline = PolicyConfig::from_bundle(&bundle);
        let engine = CounterfactualReplayEngine::default();

        let err = engine
            .simulate(
                &bundle,
                &baseline,
                SimulationMode::ParameterSweep {
                    parameter: "observe_threshold".to_string(),
                    values: vec![-1],
                    template_policy: baseline.clone(),
                },
            )
            .expect_err("negative unsigned sweep value must fail");

        assert_invalid_policy(err, "observe_threshold must be non-negative");
    }

    #[test]
    fn summarize_output_works_for_single() {
        let bundle = fixture_bundle();
        let engine = CounterfactualReplayEngine::default();
        let baseline = PolicyConfig::from_bundle(&bundle);
        let alt = PolicyConfig {
            policy_name: "strict".to_string(),
            quarantine_threshold: 65,
            observe_threshold: 35,
            degraded_mode_bias: 30,
        };
        let result = engine
            .simulate(
                &bundle,
                &baseline,
                SimulationMode::SinglePolicySwap {
                    alternate_policy: alt,
                },
            )
            .expect("simulate");
        let (total, changed, _delta) = summarize_output(&result);
        assert_eq!(total, 3);
        assert!(changed >= 1);
    }
}
