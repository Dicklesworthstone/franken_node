//! Critical-node immunization planner for DGIS.
//!
//! The planner turns topology risk metrics into enforceable barrier plans. It
//! keeps the scoring model deterministic and bounded: candidate barriers are
//! synthesized from graph-structure signals, sorted by cost effectiveness, and
//! searched within a configured candidate window for the lowest-cost plan that
//! reduces expected cascade loss below the target.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::runtime::clock;
use crate::security::dgis::barrier_primitives::{
    Barrier, BarrierConfig, BarrierPlan, BarrierType, CompositionFirewallConfig,
    ProgressionCriteria, RiskLevel, RolloutPhase, SandboxEscalationConfig, SandboxTier,
    StagedRolloutFenceConfig, VerifiedForkPinConfig,
};
use crate::security::dgis::update_copilot::TopologyRiskMetrics;

const MAX_NODE_ID_BYTES: usize = 512;
const DEFAULT_TARGET_CASCADE_LOSS: f64 = 0.25;
const DEFAULT_MAX_TOTAL_OVERHEAD_MS: u32 = 24;
const DEFAULT_MAX_BARRIERS_PER_PLAN: usize = 8;
const DEFAULT_MAX_PLANS: usize = 5;
const DEFAULT_MAX_CANDIDATE_SEARCH: usize = 18;
const MAX_CANDIDATE_SEARCH: usize = 22;
const RESULT_RETAIN_CAP: usize = 2048;
const EPSILON: f64 = 1.0e-9;

/// Stable event codes emitted in machine-readable planner output.
pub mod event_codes {
    pub const CATALOG_GENERATED: &str = "DGIS-IMMUNE-001";
    pub const CANDIDATE_SYNTHESIZED: &str = "DGIS-IMMUNE-002";
    pub const POLICY_EXCLUSION_APPLIED: &str = "DGIS-IMMUNE-003";
    pub const TARGET_ALREADY_MET: &str = "DGIS-IMMUNE-004";
    pub const INCREMENTAL_REPLAN_SCOPED: &str = "DGIS-IMMUNE-005";
}

#[derive(Debug, thiserror::Error, Clone, PartialEq)]
pub enum ImmunizationPlannerError {
    #[error("invalid immunization planner config: {0}")]
    InvalidConfig(String),
    #[error("invalid immunization planner input: {0}")]
    InvalidInput(String),
    #[error("immunization input has no candidate nodes")]
    EmptyInput,
    #[error("duplicate critical node id: {0}")]
    DuplicateNode(String),
    #[error("node '{node_id}' has invalid metric '{metric}': {value}")]
    InvalidMetric {
        node_id: String,
        metric: &'static str,
        value: f64,
    },
    #[error(
        "no feasible immunization plan: required_reduction={required_reduction:.6}, available_reduction={available_reduction:.6}, max_overhead_ms={max_overhead_ms}"
    )]
    NoFeasiblePlan {
        required_reduction: f64,
        available_reduction: f64,
        max_overhead_ms: u32,
    },
}

/// Tuning knobs for bounded deterministic planning.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImmunizationPlannerConfig {
    pub target_cascade_loss: f64,
    pub max_total_overhead_ms: u32,
    pub max_barriers_per_plan: usize,
    pub max_plans: usize,
    pub max_candidate_search: usize,
}

impl Default for ImmunizationPlannerConfig {
    fn default() -> Self {
        Self {
            target_cascade_loss: DEFAULT_TARGET_CASCADE_LOSS,
            max_total_overhead_ms: DEFAULT_MAX_TOTAL_OVERHEAD_MS,
            max_barriers_per_plan: DEFAULT_MAX_BARRIERS_PER_PLAN,
            max_plans: DEFAULT_MAX_PLANS,
            max_candidate_search: DEFAULT_MAX_CANDIDATE_SEARCH,
        }
    }
}

impl ImmunizationPlannerConfig {
    pub fn validate(&self) -> Result<(), ImmunizationPlannerError> {
        validate_non_negative_finite("target_cascade_loss", self.target_cascade_loss)?;
        if self.max_total_overhead_ms == 0 {
            return Err(ImmunizationPlannerError::InvalidConfig(
                "max_total_overhead_ms must be greater than zero".to_string(),
            ));
        }
        if self.max_barriers_per_plan == 0 {
            return Err(ImmunizationPlannerError::InvalidConfig(
                "max_barriers_per_plan must be greater than zero".to_string(),
            ));
        }
        if self.max_plans == 0 {
            return Err(ImmunizationPlannerError::InvalidConfig(
                "max_plans must be greater than zero".to_string(),
            ));
        }
        if self.max_candidate_search == 0 || self.max_candidate_search > MAX_CANDIDATE_SEARCH {
            return Err(ImmunizationPlannerError::InvalidConfig(format!(
                "max_candidate_search must be within 1..={MAX_CANDIDATE_SEARCH}"
            )));
        }
        Ok(())
    }
}

/// Barrier primitives available to the planner.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BarrierInventory {
    pub sandbox_escalation: bool,
    pub composition_firewall: bool,
    pub staged_rollout_fence: bool,
    pub verified_fork_pins: BTreeMap<String, VerifiedForkPinConfig>,
}

impl Default for BarrierInventory {
    fn default() -> Self {
        Self {
            sandbox_escalation: true,
            composition_firewall: true,
            staged_rollout_fence: true,
            verified_fork_pins: BTreeMap::new(),
        }
    }
}

/// Policy constraints that the planner must respect.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PolicyConstraints {
    pub excluded_nodes: BTreeSet<String>,
}

/// Per-node planner input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CriticalNodeInput {
    pub node_id: String,
    pub metrics: TopologyRiskMetrics,
    pub expected_cascade_loss: f64,
}

impl CriticalNodeInput {
    pub fn new(
        node_id: impl Into<String>,
        metrics: TopologyRiskMetrics,
        expected_cascade_loss: f64,
    ) -> Self {
        Self {
            node_id: node_id.into(),
            metrics,
            expected_cascade_loss,
        }
    }
}

/// Full planner input.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlanningInput {
    pub nodes: Vec<CriticalNodeInput>,
    pub constraints: PolicyConstraints,
    pub barrier_inventory: BarrierInventory,
}

impl PlanningInput {
    pub fn new(nodes: Vec<CriticalNodeInput>) -> Self {
        Self {
            nodes,
            constraints: PolicyConstraints::default(),
            barrier_inventory: BarrierInventory::default(),
        }
    }
}

/// Request metadata for a scoped replan after graph changes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalReplanRequest {
    pub changed_nodes: BTreeSet<String>,
    pub reason: String,
}

/// Summary proving an incremental replan was scoped to the changed nodes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncrementalReplanSummary {
    pub changed_nodes: BTreeSet<String>,
    pub scoped_node_count: usize,
    pub skipped_node_count: usize,
    pub reason: String,
}

/// Structured event emitted in the plan catalog.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlanningEvent {
    pub event_code: String,
    pub node_id: Option<String>,
    pub detail: String,
}

/// Machine-readable explanation for one planned barrier.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BarrierRationale {
    pub mitigated_metric: String,
    pub metric_value: f64,
    pub risk_reduction: f64,
    pub cost_units: u32,
    pub overhead_ms: u32,
    pub explanation: String,
}

/// A barrier with planner cost, overhead, and replayable rationale.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PlannedBarrier {
    pub barrier: Barrier,
    pub cost_units: u32,
    pub overhead_ms: u32,
    pub risk_reduction: f64,
    pub rationale: BarrierRationale,
}

/// One ranked immunization plan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImmunizationPlan {
    pub rank: usize,
    pub plan_id: String,
    pub barrier_plan: BarrierPlan,
    pub planned_barriers: Vec<PlannedBarrier>,
    pub total_cost_units: u32,
    pub total_overhead_ms: u32,
    pub baseline_cascade_loss: f64,
    pub expected_cascade_loss: f64,
    pub cumulative_risk_reduction: f64,
    pub cost_effectiveness: f64,
    pub meets_target: bool,
}

/// Ranked catalog emitted by the planner.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BarrierPlanCatalog {
    pub generated_at: String,
    pub target_cascade_loss: f64,
    pub baseline_cascade_loss: f64,
    pub plans: Vec<ImmunizationPlan>,
    pub events: Vec<PlanningEvent>,
    pub incremental: Option<IncrementalReplanSummary>,
}

/// Deterministic, bounded critical-node immunization planner.
#[derive(Debug, Clone)]
pub struct ImmunizationPlanner {
    config: ImmunizationPlannerConfig,
}

impl Default for ImmunizationPlanner {
    fn default() -> Self {
        Self {
            config: ImmunizationPlannerConfig::default(),
        }
    }
}

impl ImmunizationPlanner {
    pub fn new(config: ImmunizationPlannerConfig) -> Result<Self, ImmunizationPlannerError> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn config(&self) -> &ImmunizationPlannerConfig {
        &self.config
    }

    pub fn plan_catalog(
        &self,
        input: &PlanningInput,
    ) -> Result<BarrierPlanCatalog, ImmunizationPlannerError> {
        self.plan_catalog_inner(input, None)
    }

    pub fn plan_incremental(
        &self,
        input: &PlanningInput,
        request: IncrementalReplanRequest,
    ) -> Result<BarrierPlanCatalog, ImmunizationPlannerError> {
        if request.changed_nodes.is_empty() {
            return Err(ImmunizationPlannerError::InvalidInput(
                "changed_nodes must not be empty".to_string(),
            ));
        }
        for node_id in &request.changed_nodes {
            validate_node_id(node_id)?;
        }

        let scoped_nodes: Vec<CriticalNodeInput> = input
            .nodes
            .iter()
            .filter(|node| request.changed_nodes.contains(&node.node_id))
            .cloned()
            .collect();
        if scoped_nodes.is_empty() {
            return Err(ImmunizationPlannerError::InvalidInput(
                "changed_nodes did not match any planner input node".to_string(),
            ));
        }

        let skipped_node_count = input.nodes.len().saturating_sub(scoped_nodes.len());
        let scoped_input = PlanningInput {
            nodes: scoped_nodes,
            constraints: input.constraints.clone(),
            barrier_inventory: input.barrier_inventory.clone(),
        };
        let summary = IncrementalReplanSummary {
            changed_nodes: request.changed_nodes,
            scoped_node_count: scoped_input.nodes.len(),
            skipped_node_count,
            reason: request.reason,
        };

        self.plan_catalog_inner(&scoped_input, Some(summary))
    }

    fn plan_catalog_inner(
        &self,
        input: &PlanningInput,
        incremental: Option<IncrementalReplanSummary>,
    ) -> Result<BarrierPlanCatalog, ImmunizationPlannerError> {
        self.validate_input(input)?;
        let generated_at = clock::wall_now().to_rfc3339();
        let baseline_cascade_loss = baseline_cascade_loss(&input.nodes);
        let mut events = Vec::new();

        if let Some(summary) = &incremental {
            events.push(PlanningEvent {
                event_code: event_codes::INCREMENTAL_REPLAN_SCOPED.to_string(),
                node_id: None,
                detail: format!(
                    "incremental replan scoped to {} changed node(s), skipped {} unchanged node(s)",
                    summary.scoped_node_count, summary.skipped_node_count
                ),
            });
        }

        if baseline_cascade_loss <= self.config.target_cascade_loss + EPSILON {
            events.push(PlanningEvent {
                event_code: event_codes::TARGET_ALREADY_MET.to_string(),
                node_id: None,
                detail: "baseline cascade loss already satisfies target".to_string(),
            });
            events.push(PlanningEvent {
                event_code: event_codes::CATALOG_GENERATED.to_string(),
                node_id: None,
                detail: "generated no-op immunization plan".to_string(),
            });
            return Ok(BarrierPlanCatalog {
                generated_at: generated_at.clone(),
                target_cascade_loss: self.config.target_cascade_loss,
                baseline_cascade_loss,
                plans: vec![self.noop_plan(&generated_at, baseline_cascade_loss)],
                events,
                incremental,
            });
        }

        let required_reduction = baseline_cascade_loss - self.config.target_cascade_loss;
        let mut candidates = self.synthesize_candidates(input, &generated_at, &mut events)?;
        candidates.sort_by(compare_candidates);
        candidates.truncate(self.config.max_candidate_search);

        let available_reduction = candidates.iter().map(|c| c.risk_reduction).sum::<f64>();
        if candidates.is_empty() || available_reduction + EPSILON < required_reduction {
            return Err(ImmunizationPlannerError::NoFeasiblePlan {
                required_reduction,
                available_reduction,
                max_overhead_ms: self.config.max_total_overhead_ms,
            });
        }

        let mut selections = Vec::new();
        let mut selected = Vec::new();
        enumerate_feasible(
            &candidates,
            &self.config,
            required_reduction,
            0,
            &mut selected,
            SelectionState::default(),
            &mut selections,
        );

        if selections.is_empty() {
            return Err(ImmunizationPlannerError::NoFeasiblePlan {
                required_reduction,
                available_reduction,
                max_overhead_ms: self.config.max_total_overhead_ms,
            });
        }

        sort_selections(&mut selections, &candidates);
        selections.truncate(self.config.max_plans);
        events.push(PlanningEvent {
            event_code: event_codes::CATALOG_GENERATED.to_string(),
            node_id: None,
            detail: format!(
                "generated {} feasible immunization plan(s)",
                selections.len()
            ),
        });

        let plans = selections
            .into_iter()
            .enumerate()
            .map(|(idx, selection)| {
                build_plan(
                    idx.saturating_add(1),
                    &generated_at,
                    baseline_cascade_loss,
                    self.config.target_cascade_loss,
                    &candidates,
                    &selection,
                )
            })
            .collect();

        Ok(BarrierPlanCatalog {
            generated_at,
            target_cascade_loss: self.config.target_cascade_loss,
            baseline_cascade_loss,
            plans,
            events,
            incremental,
        })
    }

    fn validate_input(&self, input: &PlanningInput) -> Result<(), ImmunizationPlannerError> {
        if input.nodes.is_empty() {
            return Err(ImmunizationPlannerError::EmptyInput);
        }

        for node_id in &input.constraints.excluded_nodes {
            validate_node_id(node_id)?;
        }
        for node_id in input.barrier_inventory.verified_fork_pins.keys() {
            validate_node_id(node_id)?;
        }

        let mut seen = BTreeSet::new();
        for node in &input.nodes {
            validate_node_id(&node.node_id)?;
            if !seen.insert(node.node_id.clone()) {
                return Err(ImmunizationPlannerError::DuplicateNode(
                    node.node_id.clone(),
                ));
            }
            validate_node_metrics(node)?;
        }
        Ok(())
    }

    fn synthesize_candidates(
        &self,
        input: &PlanningInput,
        generated_at: &str,
        events: &mut Vec<PlanningEvent>,
    ) -> Result<Vec<CandidateBarrier>, ImmunizationPlannerError> {
        let mut nodes = input.nodes.clone();
        nodes.sort_by(|a, b| a.node_id.cmp(&b.node_id));

        let mut candidates = Vec::new();
        for node in &nodes {
            if input.constraints.excluded_nodes.contains(&node.node_id) {
                events.push(PlanningEvent {
                    event_code: event_codes::POLICY_EXCLUSION_APPLIED.to_string(),
                    node_id: Some(node.node_id.clone()),
                    detail: "node skipped because policy constraints exclude it".to_string(),
                });
                continue;
            }
            if node.expected_cascade_loss <= EPSILON {
                continue;
            }

            if input.barrier_inventory.composition_firewall {
                push_candidate(
                    &mut candidates,
                    composition_firewall_candidate(node, generated_at),
                    events,
                );
            }
            if input.barrier_inventory.sandbox_escalation {
                push_candidate(
                    &mut candidates,
                    sandbox_escalation_candidate(node, generated_at),
                    events,
                );
            }
            if input.barrier_inventory.staged_rollout_fence {
                push_candidate(
                    &mut candidates,
                    staged_rollout_candidate(node, generated_at)?,
                    events,
                );
            }
            if let Some(config) = input
                .barrier_inventory
                .verified_fork_pins
                .get(&node.node_id)
            {
                push_candidate(
                    &mut candidates,
                    verified_fork_pin_candidate(node, config.clone(), generated_at),
                    events,
                );
            }
        }
        Ok(candidates)
    }

    fn noop_plan(&self, generated_at: &str, baseline_cascade_loss: f64) -> ImmunizationPlan {
        let plan_id = stable_id(
            "dgis-immune-plan",
            &[
                "noop",
                &format_loss(baseline_cascade_loss),
                &format_loss(self.config.target_cascade_loss),
            ],
        );
        ImmunizationPlan {
            rank: 1,
            plan_id: plan_id.clone(),
            barrier_plan: BarrierPlan {
                plan_id,
                created_at: generated_at.to_string(),
                barriers: Vec::new(),
            },
            planned_barriers: Vec::new(),
            total_cost_units: 0,
            total_overhead_ms: 0,
            baseline_cascade_loss,
            expected_cascade_loss: baseline_cascade_loss,
            cumulative_risk_reduction: 0.0,
            cost_effectiveness: 0.0,
            meets_target: true,
        }
    }
}

fn push_candidate(
    candidates: &mut Vec<CandidateBarrier>,
    candidate: Option<CandidateBarrier>,
    events: &mut Vec<PlanningEvent>,
) {
    if let Some(candidate) = candidate {
        events.push(PlanningEvent {
            event_code: event_codes::CANDIDATE_SYNTHESIZED.to_string(),
            node_id: Some(candidate.node_id.clone()),
            detail: format!(
                "{} reduces {} by {:.6} at cost {} and overhead {}ms",
                candidate.barrier_type.as_str(),
                candidate.rationale.mitigated_metric,
                candidate.risk_reduction,
                candidate.cost_units,
                candidate.overhead_ms
            ),
        });
        candidates.push(candidate);
    }
}

#[derive(Debug, Clone)]
struct CandidateBarrier {
    candidate_id: String,
    node_id: String,
    barrier_type: BarrierType,
    risk_reduction: f64,
    cost_units: u32,
    overhead_ms: u32,
    rationale: BarrierRationale,
    barrier: Barrier,
}

impl CandidateBarrier {
    fn cost_effectiveness(&self) -> f64 {
        let denominator = self.cost_units.saturating_add(self.overhead_ms).max(1);
        self.risk_reduction / f64::from(denominator)
    }

    fn planned_barrier(&self) -> PlannedBarrier {
        PlannedBarrier {
            barrier: self.barrier.clone(),
            cost_units: self.cost_units,
            overhead_ms: self.overhead_ms,
            risk_reduction: self.risk_reduction,
            rationale: self.rationale.clone(),
        }
    }
}

fn composition_firewall_candidate(
    node: &CriticalNodeInput,
    generated_at: &str,
) -> Option<CandidateBarrier> {
    let metrics = &node.metrics;
    if !metrics.articulation_point && metrics.betweenness_centrality < 0.45 {
        return None;
    }

    let metric_value = if metrics.articulation_point {
        1.0
    } else {
        metrics.betweenness_centrality
    };
    let reduction_fraction = if metrics.articulation_point {
        0.72
    } else {
        (0.48 + metrics.betweenness_centrality * 0.20).clamp(0.35, 0.74)
    };
    let risk_reduction = bounded_reduction(node.expected_cascade_loss, reduction_fraction);
    let cost_units = 4u32.saturating_add(ceil_div_f64(metrics.fan_out, 80.0));
    let overhead_ms = 5;
    let config = BarrierConfig::CompositionFirewall(CompositionFirewallConfig {
        boundary_id: format!("dgis-chokepoint-{}", node.node_id),
        blocked_capabilities: vec![
            "exec_child".to_string(),
            "network_raw".to_string(),
            "secret_export".to_string(),
        ],
        allow_list: vec!["metrics_read".to_string()],
    });
    Some(make_candidate(
        node,
        generated_at,
        CandidateSpec {
            barrier_type: BarrierType::CompositionFirewall,
            config,
            risk_reduction,
            cost_units,
            overhead_ms,
            mitigated_metric: "articulation_point_or_betweenness",
            metric_value,
            explanation: "composition firewall blocks capability propagation across a dependency choke point",
        },
    ))
}

fn sandbox_escalation_candidate(
    node: &CriticalNodeInput,
    generated_at: &str,
) -> Option<CandidateBarrier> {
    let metrics = &node.metrics;
    let aggregate = metrics.aggregate_risk();
    if metrics.trust_bottleneck_score < 0.65 && aggregate < 0.65 {
        return None;
    }

    let reduction_fraction =
        (0.46 + metrics.trust_bottleneck_score.clamp(0.0, 1.0) * 0.25).clamp(0.46, 0.75);
    let risk_reduction = bounded_reduction(node.expected_cascade_loss, reduction_fraction);
    let cost_units = 3u32.saturating_add(ceil_div_f64(metrics.trust_bottleneck_score * 4.0, 1.0));
    let overhead_ms = 4;
    let tier = if metrics.trust_bottleneck_score >= 0.9 {
        SandboxTier::Isolated
    } else {
        SandboxTier::Strict
    };
    let config = BarrierConfig::SandboxEscalation(SandboxEscalationConfig {
        min_tier: tier,
        denied_capabilities: vec![
            "exec_child".to_string(),
            "fs_write_root".to_string(),
            "network_raw".to_string(),
        ],
        risk_threshold: RiskLevel::High,
    });
    Some(make_candidate(
        node,
        generated_at,
        CandidateSpec {
            barrier_type: BarrierType::SandboxEscalation,
            config,
            risk_reduction,
            cost_units,
            overhead_ms,
            mitigated_metric: "trust_bottleneck_score",
            metric_value: metrics.trust_bottleneck_score,
            explanation: "sandbox escalation constrains high-trust-bottleneck execution authority",
        },
    ))
}

fn staged_rollout_candidate(
    node: &CriticalNodeInput,
    generated_at: &str,
) -> Result<Option<CandidateBarrier>, ImmunizationPlannerError> {
    let metrics = &node.metrics;
    let aggregate = metrics.aggregate_risk();
    if metrics.fan_out < 10.0 && aggregate < 0.25 {
        return Ok(None);
    }

    let mut progression_criteria = BTreeMap::new();
    progression_criteria.insert(
        "canary".to_string(),
        ProgressionCriteria::new(3600, 0.001, 50).map_err(|err| {
            ImmunizationPlannerError::InvalidConfig(format!(
                "static canary progression criteria invalid: {err}"
            ))
        })?,
    );
    progression_criteria.insert(
        "limited".to_string(),
        ProgressionCriteria::new(7200, 0.005, 200).map_err(|err| {
            ImmunizationPlannerError::InvalidConfig(format!(
                "static limited progression criteria invalid: {err}"
            ))
        })?,
    );
    let reduction_fraction = (0.30 + (metrics.fan_out / 500.0).clamp(0.0, 0.20)).clamp(0.30, 0.50);
    let risk_reduction = bounded_reduction(node.expected_cascade_loss, reduction_fraction);
    let cost_units = 2;
    let overhead_ms = 2;
    let config = BarrierConfig::StagedRolloutFence(StagedRolloutFenceConfig {
        initial_phase: RolloutPhase::Canary,
        progression_criteria,
        auto_rollback_on_breach: true,
    });
    Ok(Some(make_candidate(
        node,
        generated_at,
        CandidateSpec {
            barrier_type: BarrierType::StagedRolloutFence,
            config,
            risk_reduction,
            cost_units,
            overhead_ms,
            mitigated_metric: "fan_out_or_aggregate_risk",
            metric_value: metrics.fan_out.max(aggregate),
            explanation: "staged rollout fence limits exposure while topology risk is observed",
        },
    )))
}

fn verified_fork_pin_candidate(
    node: &CriticalNodeInput,
    config: VerifiedForkPinConfig,
    generated_at: &str,
) -> Option<CandidateBarrier> {
    let metrics = &node.metrics;
    if metrics.transitive_dependency_count < 20 && metrics.max_depth_in_graph < 4 {
        return None;
    }

    let transitive_signal = f64::from(metrics.transitive_dependency_count) / 500.0;
    let reduction_fraction = (0.22 + transitive_signal.clamp(0.0, 0.18)).clamp(0.22, 0.40);
    let risk_reduction = bounded_reduction(node.expected_cascade_loss, reduction_fraction);
    Some(make_candidate(
        node,
        generated_at,
        CandidateSpec {
            barrier_type: BarrierType::VerifiedForkPin,
            config: BarrierConfig::VerifiedForkPin(config),
            risk_reduction,
            cost_units: 1,
            overhead_ms: 1,
            mitigated_metric: "transitive_dependency_count",
            metric_value: f64::from(metrics.transitive_dependency_count),
            explanation: "verified fork pinning narrows deep transitive supply-chain exposure",
        },
    ))
}

struct CandidateSpec {
    barrier_type: BarrierType,
    config: BarrierConfig,
    risk_reduction: f64,
    cost_units: u32,
    overhead_ms: u32,
    mitigated_metric: &'static str,
    metric_value: f64,
    explanation: &'static str,
}

fn make_candidate(
    node: &CriticalNodeInput,
    generated_at: &str,
    spec: CandidateSpec,
) -> CandidateBarrier {
    let candidate_id = stable_id(
        "dgis-immune-candidate",
        &[
            &node.node_id,
            spec.barrier_type.as_str(),
            spec.mitigated_metric,
            &format_loss(spec.metric_value),
            &format_loss(spec.risk_reduction),
        ],
    );
    let barrier = Barrier {
        barrier_id: stable_id("dgis-immune-barrier", &[&candidate_id]),
        node_id: node.node_id.clone(),
        barrier_type: spec.barrier_type,
        config: spec.config,
        applied_at: generated_at.to_string(),
        expires_at: None,
        source_plan_id: None,
    };
    CandidateBarrier {
        candidate_id,
        node_id: node.node_id.clone(),
        barrier_type: spec.barrier_type,
        risk_reduction: spec.risk_reduction,
        cost_units: spec.cost_units,
        overhead_ms: spec.overhead_ms,
        rationale: BarrierRationale {
            mitigated_metric: spec.mitigated_metric.to_string(),
            metric_value: spec.metric_value,
            risk_reduction: spec.risk_reduction,
            cost_units: spec.cost_units,
            overhead_ms: spec.overhead_ms,
            explanation: spec.explanation.to_string(),
        },
        barrier,
    }
}

#[derive(Debug, Clone, Copy, Default)]
struct SelectionState {
    total_cost_units: u32,
    total_overhead_ms: u32,
    total_reduction: f64,
}

#[derive(Debug, Clone)]
struct PlanSelection {
    candidate_indexes: Vec<usize>,
    total_cost_units: u32,
    total_overhead_ms: u32,
    total_reduction: f64,
}

fn enumerate_feasible(
    candidates: &[CandidateBarrier],
    config: &ImmunizationPlannerConfig,
    required_reduction: f64,
    index: usize,
    selected: &mut Vec<usize>,
    state: SelectionState,
    selections: &mut Vec<PlanSelection>,
) {
    if state.total_reduction + EPSILON >= required_reduction {
        selections.push(PlanSelection {
            candidate_indexes: selected.clone(),
            total_cost_units: state.total_cost_units,
            total_overhead_ms: state.total_overhead_ms,
            total_reduction: state.total_reduction,
        });
        trim_selection_results(selections, candidates);
        return;
    }
    if index >= candidates.len() || selected.len() >= config.max_barriers_per_plan {
        return;
    }

    let remaining_reduction = candidates[index..]
        .iter()
        .map(|candidate| candidate.risk_reduction)
        .sum::<f64>();
    if state.total_reduction + remaining_reduction + EPSILON < required_reduction {
        return;
    }

    let candidate = &candidates[index];
    let next_overhead = state
        .total_overhead_ms
        .saturating_add(candidate.overhead_ms);
    if next_overhead <= config.max_total_overhead_ms {
        selected.push(index);
        enumerate_feasible(
            candidates,
            config,
            required_reduction,
            index.saturating_add(1),
            selected,
            SelectionState {
                total_cost_units: state.total_cost_units.saturating_add(candidate.cost_units),
                total_overhead_ms: next_overhead,
                total_reduction: state.total_reduction + candidate.risk_reduction,
            },
            selections,
        );
        selected.pop();
    }

    enumerate_feasible(
        candidates,
        config,
        required_reduction,
        index.saturating_add(1),
        selected,
        state,
        selections,
    );
}

fn trim_selection_results(selections: &mut Vec<PlanSelection>, candidates: &[CandidateBarrier]) {
    if selections.len() <= RESULT_RETAIN_CAP.saturating_mul(2) {
        return;
    }
    sort_selections(selections, candidates);
    selections.truncate(RESULT_RETAIN_CAP);
}

fn build_plan(
    rank: usize,
    generated_at: &str,
    baseline_cascade_loss: f64,
    target_cascade_loss: f64,
    candidates: &[CandidateBarrier],
    selection: &PlanSelection,
) -> ImmunizationPlan {
    let candidate_ids: Vec<&str> = selection
        .candidate_indexes
        .iter()
        .map(|idx| candidates[*idx].candidate_id.as_str())
        .collect();
    let plan_id = stable_id("dgis-immune-plan", &candidate_ids);
    let planned_barriers: Vec<PlannedBarrier> = selection
        .candidate_indexes
        .iter()
        .map(|idx| candidates[*idx].planned_barrier())
        .collect();
    let barriers = planned_barriers
        .iter()
        .map(|planned| planned.barrier.clone())
        .collect();
    let expected_cascade_loss =
        (baseline_cascade_loss - selection.total_reduction).clamp(0.0, baseline_cascade_loss);
    let denominator = selection
        .total_cost_units
        .saturating_add(selection.total_overhead_ms)
        .max(1);

    ImmunizationPlan {
        rank,
        plan_id: plan_id.clone(),
        barrier_plan: BarrierPlan {
            plan_id,
            created_at: generated_at.to_string(),
            barriers,
        },
        planned_barriers,
        total_cost_units: selection.total_cost_units,
        total_overhead_ms: selection.total_overhead_ms,
        baseline_cascade_loss,
        expected_cascade_loss,
        cumulative_risk_reduction: selection.total_reduction,
        cost_effectiveness: selection.total_reduction / f64::from(denominator),
        meets_target: expected_cascade_loss <= target_cascade_loss + EPSILON,
    }
}

fn compare_candidates(a: &CandidateBarrier, b: &CandidateBarrier) -> Ordering {
    b.cost_effectiveness()
        .total_cmp(&a.cost_effectiveness())
        .then_with(|| a.cost_units.cmp(&b.cost_units))
        .then_with(|| a.overhead_ms.cmp(&b.overhead_ms))
        .then_with(|| a.node_id.cmp(&b.node_id))
        .then_with(|| a.barrier_type.as_str().cmp(b.barrier_type.as_str()))
        .then_with(|| a.candidate_id.cmp(&b.candidate_id))
}

fn sort_selections(selections: &mut [PlanSelection], candidates: &[CandidateBarrier]) {
    selections.sort_by(|a, b| {
        a.total_cost_units
            .cmp(&b.total_cost_units)
            .then_with(|| a.total_overhead_ms.cmp(&b.total_overhead_ms))
            .then_with(|| a.candidate_indexes.len().cmp(&b.candidate_indexes.len()))
            .then_with(|| b.total_reduction.total_cmp(&a.total_reduction))
            .then_with(|| selection_key(a, candidates).cmp(&selection_key(b, candidates)))
    });
}

fn selection_key(selection: &PlanSelection, candidates: &[CandidateBarrier]) -> Vec<String> {
    selection
        .candidate_indexes
        .iter()
        .map(|idx| candidates[*idx].candidate_id.clone())
        .collect()
}

fn validate_node_metrics(node: &CriticalNodeInput) -> Result<(), ImmunizationPlannerError> {
    validate_node_metric(
        &node.node_id,
        "expected_cascade_loss",
        node.expected_cascade_loss,
    )?;
    validate_node_metric(&node.node_id, "fan_out", node.metrics.fan_out)?;
    validate_node_metric(
        &node.node_id,
        "betweenness_centrality",
        node.metrics.betweenness_centrality,
    )?;
    validate_node_metric(
        &node.node_id,
        "trust_bottleneck_score",
        node.metrics.trust_bottleneck_score,
    )?;
    Ok(())
}

fn validate_node_metric(
    node_id: &str,
    metric: &'static str,
    value: f64,
) -> Result<(), ImmunizationPlannerError> {
    if !value.is_finite() || value < 0.0 {
        return Err(ImmunizationPlannerError::InvalidMetric {
            node_id: node_id.to_string(),
            metric,
            value,
        });
    }
    Ok(())
}

fn validate_non_negative_finite(field: &str, value: f64) -> Result<(), ImmunizationPlannerError> {
    if !value.is_finite() || value < 0.0 {
        return Err(ImmunizationPlannerError::InvalidConfig(format!(
            "{field} must be finite and non-negative"
        )));
    }
    Ok(())
}

fn validate_node_id(node_id: &str) -> Result<(), ImmunizationPlannerError> {
    if node_id.trim().is_empty() {
        return Err(ImmunizationPlannerError::InvalidInput(
            "node_id must not be empty".to_string(),
        ));
    }
    if node_id.len() > MAX_NODE_ID_BYTES {
        return Err(ImmunizationPlannerError::InvalidInput(format!(
            "node_id exceeds {MAX_NODE_ID_BYTES} bytes"
        )));
    }
    if node_id.contains('\0') {
        return Err(ImmunizationPlannerError::InvalidInput(
            "node_id contains NUL byte".to_string(),
        ));
    }
    Ok(())
}

fn baseline_cascade_loss(nodes: &[CriticalNodeInput]) -> f64 {
    nodes
        .iter()
        .map(|node| node.expected_cascade_loss)
        .sum::<f64>()
}

fn bounded_reduction(expected_cascade_loss: f64, reduction_fraction: f64) -> f64 {
    (expected_cascade_loss * reduction_fraction).clamp(0.0, expected_cascade_loss)
}

fn ceil_div_f64(value: f64, divisor: f64) -> u32 {
    if !value.is_finite() || !divisor.is_finite() || divisor <= 0.0 || value <= 0.0 {
        return 0;
    }
    let scaled = (value / divisor).ceil();
    if scaled >= f64::from(u32::MAX) {
        u32::MAX
    } else {
        match format!("{scaled:.0}").parse::<u32>() {
            Ok(parsed) => parsed,
            Err(_) => u32::MAX,
        }
    }
}

fn format_loss(value: f64) -> String {
    format!("{value:.9}")
}

fn stable_id(prefix: &str, parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"dgis_immunization_planner_id_v1:");
    hasher.update(prefix.as_bytes());
    for part in parts {
        let bytes = part.as_bytes();
        let len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        hasher.update(len.to_le_bytes());
        hasher.update(bytes);
    }
    let digest = hasher.finalize();
    let hex = hex::encode(digest);
    format!("{prefix}-{}", &hex[..16])
}
