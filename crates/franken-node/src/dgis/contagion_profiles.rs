//! Adversarial campaign profiles for the contagion simulator (sub-task 3 of bd-1q38).
//!
//! Sub-tasks 1 and 2 built [`ContagionGraph`] and the
//! [`simulate`](super::contagion_simulator::simulate) state machine. This
//! module provides:
//!
//! * Serde-friendly *profile* descriptions (the actual JSON fixtures live
//!   under `tests/security/contagion_profiles/`).
//! * Loader and graph-builder helpers that translate a profile into the
//!   in-memory simulator inputs while enforcing the project's hardening
//!   conventions (bounded growth, finite f64s, no panics on malformed input).
//! * An evaluator that runs the simulator against a profile's
//!   `expected` block and returns a structured [`ProfileVerdict`] for use
//!   by the integration test (sub-task 4) and verification gate
//!   (sub-task 5).
//!
//! Design constraints kept consistent with sub-tasks 1 + 2:
//!
//! * Every f64 (`weight`, etc.) is `is_finite()`-guarded before it is
//!   accepted into a profile or built into the graph.
//! * `nodes.len() <= MAX_PROFILE_NODES` (1024) and total
//!   `edges.len() <= MAX_PROFILE_EDGES` (4096) per the prompt; both caps
//!   surface a typed [`ProfileError::BoundedGrowthExceeded`] rather than
//!   silently truncating, so a malformed fixture cannot pass validation
//!   by being too large.
//! * Counters use `saturating_add` per the project's hardening pattern.
//! * No `unwrap`/`panic!` on parsed input — every fallible operation maps
//!   to [`ProfileError`].
//! * The simulator types `EdgeKind` and `TerminationReason` are not yet
//!   `Serialize`/`Deserialize`. Rather than retro-fitting them in this
//!   sub-task (which would touch sub-tasks 1 + 2's frozen surface), we
//!   mirror them with serde-friendly wire enums and convert at the loader
//!   boundary.

use serde::{Deserialize, Serialize};

use super::contagion_graph::{
    ContagionEdge, ContagionGraph, EdgeKind, GraphError, NodeId, validate_node_id,
};
use super::contagion_simulator::{
    SimulationTrace, SimulatorConfig, SimulatorError, TerminationReason, simulate,
};

/// Maximum number of nodes accepted in any single profile.
///
/// Matches the bounded-growth ceiling called out in the prompt and aligns
/// with the simulator's `MAX_SIMULATION_STEPS`-driven memory budget.
pub const MAX_PROFILE_NODES: usize = 1024;

/// Maximum number of edges accepted across an entire profile.
///
/// Independently bounded (rather than per-node) so a "hub" node cannot
/// dominate the edge budget while keeping the total under control.
pub const MAX_PROFILE_EDGES: usize = 4096;

/// Maximum number of `initial_infected` entries.
///
/// In practice campaign profiles seed 1–5 nodes; the cap keeps the loader
/// safe against malformed fixtures that try to inject huge seed lists.
pub const MAX_INITIAL_INFECTED: usize = 256;

/// Serde-friendly mirror of [`EdgeKind`].
///
/// Kept identical to the simulator enum so JSON authoring is "obvious":
/// `"DependencyImport"`, `"MaintainerOverlap"`, etc.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireEdgeKind {
    DependencyImport,
    MaintainerOverlap,
    OrgOverlap,
    NamespaceShadow,
}

impl From<WireEdgeKind> for EdgeKind {
    fn from(v: WireEdgeKind) -> Self {
        match v {
            WireEdgeKind::DependencyImport => EdgeKind::DependencyImport,
            WireEdgeKind::MaintainerOverlap => EdgeKind::MaintainerOverlap,
            WireEdgeKind::OrgOverlap => EdgeKind::OrgOverlap,
            WireEdgeKind::NamespaceShadow => EdgeKind::NamespaceShadow,
        }
    }
}

impl From<EdgeKind> for WireEdgeKind {
    fn from(v: EdgeKind) -> Self {
        match v {
            EdgeKind::DependencyImport => WireEdgeKind::DependencyImport,
            EdgeKind::MaintainerOverlap => WireEdgeKind::MaintainerOverlap,
            EdgeKind::OrgOverlap => WireEdgeKind::OrgOverlap,
            EdgeKind::NamespaceShadow => WireEdgeKind::NamespaceShadow,
        }
    }
}

/// Serde-friendly mirror of [`TerminationReason`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WireTerminationReason {
    Converged,
    ReachedMaxSteps,
    FullSpread,
    NoSpread,
}

impl From<WireTerminationReason> for TerminationReason {
    fn from(v: WireTerminationReason) -> Self {
        match v {
            WireTerminationReason::Converged => TerminationReason::Converged,
            WireTerminationReason::ReachedMaxSteps => TerminationReason::ReachedMaxSteps,
            WireTerminationReason::FullSpread => TerminationReason::FullSpread,
            WireTerminationReason::NoSpread => TerminationReason::NoSpread,
        }
    }
}

impl From<TerminationReason> for WireTerminationReason {
    fn from(v: TerminationReason) -> Self {
        match v {
            TerminationReason::Converged => WireTerminationReason::Converged,
            TerminationReason::ReachedMaxSteps => WireTerminationReason::ReachedMaxSteps,
            TerminationReason::FullSpread => WireTerminationReason::FullSpread,
            TerminationReason::NoSpread => WireTerminationReason::NoSpread,
        }
    }
}

/// JSON shape for a single edge entry inside a profile's `graph.edges` list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileEdgeSpec {
    pub from: NodeId,
    pub to: NodeId,
    pub weight: f64,
    pub edge_kind: WireEdgeKind,
}

/// JSON shape for the `graph` block of a profile.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileGraphSpec {
    pub nodes: Vec<NodeId>,
    pub edges: Vec<ProfileEdgeSpec>,
    pub seed: u64,
}

/// JSON shape for the `expected` block of a profile.
///
/// `min_infected_count` and `max_infected_count` form a closed interval (both
/// endpoints are accepted). `terminated_by_step` is an upper bound on the
/// simulator's `terminated_at`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExpectedOutcome {
    pub termination_reason: WireTerminationReason,
    pub min_infected_count: usize,
    pub max_infected_count: usize,
    pub terminated_by_step: u32,
}

/// JSON shape for the simulator config carried inside a profile.
///
/// Mirrors [`SimulatorConfig`] one-for-one — kept as its own struct so the
/// JSON file format is decoupled from any future field renames in the
/// simulator's public type.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProfileSimulatorConfig {
    pub max_steps: u32,
    pub infection_threshold: f64,
    pub decay_factor: f64,
    pub seed: u64,
}

impl From<ProfileSimulatorConfig> for SimulatorConfig {
    fn from(v: ProfileSimulatorConfig) -> Self {
        SimulatorConfig {
            max_steps: v.max_steps,
            infection_threshold: v.infection_threshold,
            decay_factor: v.decay_factor,
            seed: v.seed,
        }
    }
}

/// Full profile description, as deserialised from a JSON fixture.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContagionProfile {
    pub name: String,
    pub description: String,
    pub graph: ProfileGraphSpec,
    pub initial_infected: Vec<NodeId>,
    pub config: ProfileSimulatorConfig,
    pub expected: ExpectedOutcome,
}

/// Outcome of running a profile through the simulator and comparing the
/// trace against the profile's `expected` block.
#[derive(Debug, Clone, PartialEq)]
pub struct ProfileVerdict {
    pub passed: bool,
    pub actual_termination_reason: TerminationReason,
    pub actual_infected_count: usize,
    pub actual_terminated_at: u32,
    pub divergences: Vec<String>,
}

/// Typed errors raised by the profile loader / evaluator.
#[derive(Debug, Clone, PartialEq)]
pub enum ProfileError {
    /// `serde_json` failed to parse or shape-check the JSON input.
    ParseError(String),
    /// A `weight` field was NaN, +/-infinity, or negative.
    InvalidWeight,
    /// An `initial_infected` or edge endpoint references an id that is not
    /// in the profile's `graph.nodes` list.
    UnknownNode,
    /// The profile exceeded a bounded-growth cap (nodes / edges / seeds).
    BoundedGrowthExceeded,
    /// The profile has zero nodes, an empty `initial_infected`, or an
    /// otherwise degenerate shape that cannot be simulated.
    EmptyProfile,
    /// `min_infected_count > max_infected_count`, or a similar
    /// internally-inconsistent `expected` block.
    InvalidExpected,
    /// Simulator config fields were finite but outside the accepted range.
    InvalidConfig,
    /// The simulator surfaced an error while running the profile (config
    /// out of range, exposure went non-finite, etc.).
    SimulatorFailure(SimulatorError),
    /// The underlying graph rejected an edge (unknown target, etc.).
    GraphFailure(GraphError),
}

impl From<SimulatorError> for ProfileError {
    fn from(value: SimulatorError) -> Self {
        ProfileError::SimulatorFailure(value)
    }
}

impl From<GraphError> for ProfileError {
    fn from(value: GraphError) -> Self {
        ProfileError::GraphFailure(value)
    }
}

/// Parse a JSON profile and run the *loader-side* validations that don't
/// need a graph (size caps, finite weights, sensible `expected` block).
///
/// Note: full cross-checks (initial_infected ⊆ nodes, edges reference known
/// nodes) live in [`build_graph_from_spec`] so a caller that only wants to
/// inspect metadata can stop here.
pub fn load_profile_from_json(json: &str) -> Result<ContagionProfile, ProfileError> {
    let profile: ContagionProfile =
        serde_json::from_str(json).map_err(|e| ProfileError::ParseError(format!("{e}")))?;

    if profile.graph.nodes.is_empty() {
        return Err(ProfileError::EmptyProfile);
    }
    if profile.initial_infected.is_empty() {
        return Err(ProfileError::EmptyProfile);
    }

    if profile.graph.nodes.len() > MAX_PROFILE_NODES {
        return Err(ProfileError::BoundedGrowthExceeded);
    }
    if profile.graph.edges.len() > MAX_PROFILE_EDGES {
        return Err(ProfileError::BoundedGrowthExceeded);
    }
    if profile.initial_infected.len() > MAX_INITIAL_INFECTED {
        return Err(ProfileError::BoundedGrowthExceeded);
    }

    for edge in &profile.graph.edges {
        if !edge.weight.is_finite() || edge.weight < 0.0 || edge.weight > 1.0 {
            return Err(ProfileError::InvalidWeight);
        }
    }

    if !profile.config.infection_threshold.is_finite() || !profile.config.decay_factor.is_finite() {
        return Err(ProfileError::InvalidWeight);
    }
    if !(0.0..=1.0).contains(&profile.config.infection_threshold)
        || !(0.0..=1.0).contains(&profile.config.decay_factor)
        || profile.config.max_steps == 0
    {
        return Err(ProfileError::InvalidConfig);
    }

    if profile.expected.min_infected_count > profile.expected.max_infected_count {
        return Err(ProfileError::InvalidExpected);
    }
    if profile.expected.max_infected_count > profile.graph.nodes.len() {
        return Err(ProfileError::InvalidExpected);
    }
    if profile.expected.terminated_by_step > profile.config.max_steps {
        return Err(ProfileError::InvalidExpected);
    }

    Ok(profile)
}

/// Build the in-memory [`ContagionGraph`] for a profile, performing the
/// full referential-integrity check that the loader skipped.
pub fn build_graph_from_spec(spec: &ProfileGraphSpec) -> Result<ContagionGraph, ProfileError> {
    if spec.nodes.is_empty() {
        return Err(ProfileError::EmptyProfile);
    }
    if spec.nodes.len() > MAX_PROFILE_NODES {
        return Err(ProfileError::BoundedGrowthExceeded);
    }
    if spec.edges.len() > MAX_PROFILE_EDGES {
        return Err(ProfileError::BoundedGrowthExceeded);
    }

    let mut graph = ContagionGraph::new(spec.seed);
    for node in &spec.nodes {
        validate_node_id(node)?;
        graph.add_node(node.clone());
    }
    let known: std::collections::BTreeSet<&NodeId> = spec.nodes.iter().collect();

    let mut edge_count: usize = 0;
    for spec_edge in &spec.edges {
        if !spec_edge.weight.is_finite() || spec_edge.weight < 0.0 || spec_edge.weight > 1.0 {
            return Err(ProfileError::InvalidWeight);
        }
        validate_node_id(&spec_edge.from)?;
        validate_node_id(&spec_edge.to)?;
        if !known.contains(&spec_edge.from) || !known.contains(&spec_edge.to) {
            return Err(ProfileError::UnknownNode);
        }
        let edge = ContagionEdge::new(
            spec_edge.to.clone(),
            spec_edge.weight,
            EdgeKind::from(spec_edge.edge_kind),
        )?;
        graph.add_edge(&spec_edge.from, edge)?;
        edge_count = edge_count.saturating_add(1);
        if edge_count > MAX_PROFILE_EDGES {
            return Err(ProfileError::BoundedGrowthExceeded);
        }
    }

    Ok(graph)
}

/// Run a profile through the simulator and compare the produced trace
/// against the profile's `expected` block.
///
/// The returned [`ProfileVerdict`] is structured (`divergences: Vec<String>`)
/// so the integration test and verification gate can quote each failed
/// invariant rather than logging a bare `passed=false`.
pub fn evaluate_profile(profile: &ContagionProfile) -> Result<ProfileVerdict, ProfileError> {
    let graph = build_graph_from_spec(&profile.graph)?;

    // Every initial-infected id must be in the node set; the simulator also
    // checks this, but doing it here yields a typed ProfileError::UnknownNode
    // instead of a SimulatorFailure(SimulatorError::UnknownNode) which is
    // less informative for fixture authors.
    let known: std::collections::BTreeSet<&NodeId> = profile.graph.nodes.iter().collect();
    for n in &profile.initial_infected {
        if !known.contains(n) {
            return Err(ProfileError::UnknownNode);
        }
    }

    let cfg: SimulatorConfig = profile.config.clone().into();
    let trace: SimulationTrace = simulate(&graph, &profile.initial_infected, &cfg)?;
    let last_state = match trace.states_per_step.last() {
        Some(s) => s,
        None => return Err(ProfileError::SimulatorFailure(SimulatorError::BadConfig)),
    };

    let actual_termination_reason = trace.termination_reason;
    let actual_infected_count = last_state.infected_count();
    let actual_terminated_at = trace.terminated_at;
    let expected_termination_reason: TerminationReason = profile.expected.termination_reason.into();

    let mut divergences: Vec<String> = Vec::new();
    if actual_termination_reason != expected_termination_reason {
        push_bounded_div(
            &mut divergences,
            format!(
                "termination_reason: expected {:?}, got {:?}",
                expected_termination_reason, actual_termination_reason
            ),
        );
    }
    if actual_infected_count < profile.expected.min_infected_count {
        push_bounded_div(
            &mut divergences,
            format!(
                "infected_count: {} below min {}",
                actual_infected_count, profile.expected.min_infected_count
            ),
        );
    }
    if actual_infected_count > profile.expected.max_infected_count {
        push_bounded_div(
            &mut divergences,
            format!(
                "infected_count: {} above max {}",
                actual_infected_count, profile.expected.max_infected_count
            ),
        );
    }
    if actual_terminated_at > profile.expected.terminated_by_step {
        push_bounded_div(
            &mut divergences,
            format!(
                "terminated_at: {} exceeds terminated_by_step {}",
                actual_terminated_at, profile.expected.terminated_by_step
            ),
        );
    }

    Ok(ProfileVerdict {
        passed: divergences.is_empty(),
        actual_termination_reason,
        actual_infected_count,
        actual_terminated_at,
        divergences,
    })
}

/// Cap on divergence strings stored on a [`ProfileVerdict`].
///
/// `evaluate_profile` only pushes four well-defined divergence kinds, but
/// the bounded-growth guard is here in case future invariants are added.
const MAX_DIVERGENCES: usize = 32;

/// Inline equivalent of `crate::push_bounded` so this module remains usable
/// from inside `#[cfg(test)]` mods (where `lib.rs` is gated out by the
/// crate's `#![cfg(not(test))]`).
fn push_bounded_div(items: &mut Vec<String>, item: String) {
    if MAX_DIVERGENCES == 0 {
        items.clear();
        return;
    }
    if items.len() >= MAX_DIVERGENCES {
        let overflow = items
            .len()
            .saturating_sub(MAX_DIVERGENCES)
            .saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

#[cfg(test)]
mod tests {
    use super::*;

    const XZ_STYLE_JSON: &str =
        include_str!("../../../../tests/security/contagion_profiles/xz_style.json");
    const DEP_CONFUSION_JSON: &str =
        include_str!("../../../../tests/security/contagion_profiles/dependency_confusion.json");
    const TYPOSQUAT_JSON: &str =
        include_str!("../../../../tests/security/contagion_profiles/typosquat.json");

    fn must_load(json: &str) -> ContagionProfile {
        load_profile_from_json(json).expect("profile should parse")
    }

    #[test]
    fn xz_style_profile_evaluates_to_pass() {
        let profile = must_load(XZ_STYLE_JSON);
        assert_eq!(profile.name, "xz_style");
        assert_eq!(profile.graph.nodes.len(), 20);
        assert_eq!(profile.initial_infected.len(), 1);
        let verdict = evaluate_profile(&profile).expect("evaluate");
        assert!(
            verdict.passed,
            "xz_style verdict diverged: {:?}",
            verdict.divergences
        );
        assert_eq!(
            verdict.actual_termination_reason,
            TerminationReason::Converged
        );
        assert!(verdict.actual_infected_count >= profile.expected.min_infected_count);
        assert!(verdict.actual_infected_count <= profile.expected.max_infected_count);
        assert!(verdict.actual_terminated_at <= profile.expected.terminated_by_step);
    }

    #[test]
    fn dependency_confusion_profile_evaluates_to_pass() {
        let profile = must_load(DEP_CONFUSION_JSON);
        assert_eq!(profile.name, "dependency_confusion");
        assert_eq!(profile.graph.nodes.len(), 15);
        let verdict = evaluate_profile(&profile).expect("evaluate");
        assert!(
            verdict.passed,
            "dependency_confusion verdict diverged: {:?}",
            verdict.divergences
        );
        assert_eq!(
            verdict.actual_termination_reason,
            TerminationReason::Converged
        );
        // Internal scope is the 8 internal:* packages plus the typosquat seed.
        assert!(verdict.actual_infected_count >= profile.expected.min_infected_count);
        assert!(verdict.actual_infected_count <= profile.expected.max_infected_count);
    }

    #[test]
    fn typosquat_profile_evaluates_to_pass() {
        let profile = must_load(TYPOSQUAT_JSON);
        assert_eq!(profile.name, "typosquat");
        assert_eq!(profile.graph.nodes.len(), 30);
        assert_eq!(profile.initial_infected.len(), 5);
        let verdict = evaluate_profile(&profile).expect("evaluate");
        assert!(
            verdict.passed,
            "typosquat verdict diverged: {:?}",
            verdict.divergences
        );
        assert_eq!(
            verdict.actual_termination_reason,
            TerminationReason::Converged
        );
        assert!(verdict.actual_infected_count >= profile.expected.min_infected_count);
        assert!(verdict.actual_infected_count <= profile.expected.max_infected_count);
    }

    #[test]
    fn evaluate_is_deterministic_for_same_seed() {
        let profile = must_load(XZ_STYLE_JSON);
        let v1 = evaluate_profile(&profile).expect("first evaluate");
        let v2 = evaluate_profile(&profile).expect("second evaluate");
        assert_eq!(v1, v2, "same profile must produce byte-identical verdict");
    }

    #[test]
    fn build_graph_validates_round_trip() {
        // Every shipped fixture must produce a graph that the simulator's
        // own validator accepts — no dangling edges, no NaN weights, no
        // empty node set.
        for json in [XZ_STYLE_JSON, DEP_CONFUSION_JSON, TYPOSQUAT_JSON] {
            let profile = must_load(json);
            let g = build_graph_from_spec(&profile.graph).expect("build graph");
            assert!(
                g.validate().is_ok(),
                "graph for {} failed validate",
                profile.name
            );
            assert_eq!(g.seed(), profile.graph.seed);
            assert_eq!(g.nodes().len(), profile.graph.nodes.len());
        }
    }

    #[test]
    fn loader_rejects_nan_weight() {
        let bad = r#"{
            "name":"bad","description":"nan weight",
            "graph":{"nodes":["a","b"],"edges":[{"from":"a","to":"b","weight":NaN,"edge_kind":"DependencyImport"}],"seed":1},
            "initial_infected":["a"],
            "config":{"max_steps":4,"infection_threshold":0.5,"decay_factor":0.5,"seed":1},
            "expected":{"termination_reason":"Converged","min_infected_count":0,"max_infected_count":2,"terminated_by_step":4}
        }"#;
        // Serde's default JSON parser rejects bare NaN tokens, so this comes
        // back as ParseError — that's still a "loader rejected" outcome.
        let err = load_profile_from_json(bad).expect_err("NaN weight must not load");
        assert!(matches!(
            err,
            ProfileError::ParseError(_) | ProfileError::InvalidWeight
        ));
    }

    #[test]
    fn loader_rejects_infinite_weight_via_synthesised_profile() {
        // Build the profile programmatically and skip JSON entirely so we can
        // smuggle a +inf past serde and confirm `build_graph_from_spec`
        // surfaces it as InvalidWeight.
        let spec = ProfileGraphSpec {
            nodes: vec!["a".to_string(), "b".to_string()],
            edges: vec![ProfileEdgeSpec {
                from: "a".to_string(),
                to: "b".to_string(),
                weight: f64::INFINITY,
                edge_kind: WireEdgeKind::DependencyImport,
            }],
            seed: 0,
        };
        let err = build_graph_from_spec(&spec).expect_err("infinite weight must reject");
        assert_eq!(err, ProfileError::InvalidWeight);
    }

    #[test]
    fn loader_rejects_negative_weight() {
        let spec = ProfileGraphSpec {
            nodes: vec!["a".to_string(), "b".to_string()],
            edges: vec![ProfileEdgeSpec {
                from: "a".to_string(),
                to: "b".to_string(),
                weight: -0.1,
                edge_kind: WireEdgeKind::DependencyImport,
            }],
            seed: 0,
        };
        let err = build_graph_from_spec(&spec).expect_err("negative weight must reject");
        assert_eq!(err, ProfileError::InvalidWeight);
    }

    #[test]
    fn loader_rejects_weight_above_one() {
        let spec = ProfileGraphSpec {
            nodes: vec!["a".to_string(), "b".to_string()],
            edges: vec![ProfileEdgeSpec {
                from: "a".to_string(),
                to: "b".to_string(),
                weight: 1.001,
                edge_kind: WireEdgeKind::DependencyImport,
            }],
            seed: 0,
        };
        let err = build_graph_from_spec(&spec).expect_err("over-one weight must reject");
        assert_eq!(err, ProfileError::InvalidWeight);
    }

    #[test]
    fn loader_rejects_unknown_node_in_edges() {
        let spec = ProfileGraphSpec {
            nodes: vec!["a".to_string(), "b".to_string()],
            edges: vec![ProfileEdgeSpec {
                from: "a".to_string(),
                to: "ghost".to_string(),
                weight: 0.5,
                edge_kind: WireEdgeKind::DependencyImport,
            }],
            seed: 0,
        };
        let err = build_graph_from_spec(&spec).expect_err("unknown node must reject");
        assert_eq!(err, ProfileError::UnknownNode);
    }

    #[test]
    fn evaluate_rejects_unknown_initial_infected() {
        let mut profile = must_load(XZ_STYLE_JSON);
        profile.initial_infected = vec!["pkg:does_not_exist".to_string()];
        let err = evaluate_profile(&profile).expect_err("unknown seed must reject");
        assert_eq!(err, ProfileError::UnknownNode);
    }

    #[test]
    fn loader_rejects_empty_profile() {
        let bad = r#"{
            "name":"empty","description":"no nodes",
            "graph":{"nodes":[],"edges":[],"seed":1},
            "initial_infected":[],
            "config":{"max_steps":4,"infection_threshold":0.5,"decay_factor":0.5,"seed":1},
            "expected":{"termination_reason":"Converged","min_infected_count":0,"max_infected_count":0,"terminated_by_step":4}
        }"#;
        let err = load_profile_from_json(bad).expect_err("empty must reject");
        assert_eq!(err, ProfileError::EmptyProfile);
    }

    #[test]
    fn loader_rejects_bounded_growth_overflow() {
        // Build a spec just over MAX_PROFILE_NODES.
        let mut nodes: Vec<NodeId> = Vec::with_capacity(MAX_PROFILE_NODES + 1);
        for i in 0..(MAX_PROFILE_NODES + 1) {
            nodes.push(format!("n{i}"));
        }
        let spec = ProfileGraphSpec {
            nodes,
            edges: vec![],
            seed: 0,
        };
        let err = build_graph_from_spec(&spec).expect_err("over-cap must reject");
        assert_eq!(err, ProfileError::BoundedGrowthExceeded);
    }

    #[test]
    fn loader_rejects_inconsistent_expected_block() {
        let bad = r#"{
            "name":"bad","description":"min > max",
            "graph":{"nodes":["a","b"],"edges":[],"seed":1},
            "initial_infected":["a"],
            "config":{"max_steps":4,"infection_threshold":0.5,"decay_factor":0.5,"seed":1},
            "expected":{"termination_reason":"Converged","min_infected_count":5,"max_infected_count":2,"terminated_by_step":4}
        }"#;
        let err = load_profile_from_json(bad).expect_err("min>max must reject");
        assert_eq!(err, ProfileError::InvalidExpected);
    }

    #[test]
    fn loader_rejects_expected_termination_after_configured_max_step() {
        let bad = r#"{
            "name":"bad","description":"non-load-bearing termination bound",
            "graph":{"nodes":["a","b"],"edges":[],"seed":1},
            "initial_infected":["a"],
            "config":{"max_steps":4,"infection_threshold":0.5,"decay_factor":0.5,"seed":1},
            "expected":{"termination_reason":"Converged","min_infected_count":1,"max_infected_count":2,"terminated_by_step":5}
        }"#;
        let err = load_profile_from_json(bad)
            .expect_err("terminated_by_step past max_steps must reject");
        assert_eq!(err, ProfileError::InvalidExpected);
    }

    #[test]
    fn loader_rejects_out_of_range_config_before_simulation() {
        let bad = r#"{
            "name":"bad","description":"invalid threshold",
            "graph":{"nodes":["a","b"],"edges":[],"seed":1},
            "initial_infected":["a"],
            "config":{"max_steps":4,"infection_threshold":1.5,"decay_factor":0.5,"seed":1},
            "expected":{"termination_reason":"Converged","min_infected_count":0,"max_infected_count":2,"terminated_by_step":4}
        }"#;
        let err = load_profile_from_json(bad).expect_err("out-of-range config must reject");
        assert_eq!(err, ProfileError::InvalidConfig);
    }

    #[test]
    fn wire_enum_round_trip_preserves_identity() {
        for k in [
            EdgeKind::DependencyImport,
            EdgeKind::MaintainerOverlap,
            EdgeKind::OrgOverlap,
            EdgeKind::NamespaceShadow,
        ] {
            let wire: WireEdgeKind = k.into();
            let back: EdgeKind = wire.into();
            assert_eq!(back, k);
        }
        for r in [
            TerminationReason::Converged,
            TerminationReason::ReachedMaxSteps,
            TerminationReason::FullSpread,
            TerminationReason::NoSpread,
        ] {
            let wire: WireTerminationReason = r.into();
            let back: TerminationReason = wire.into();
            assert_eq!(back, r);
        }
    }
}
