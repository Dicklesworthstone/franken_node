//! Adversarial contagion simulator step function.
//!
//! Sub-task 2 of bd-1q38.1: given a [`ContagionGraph`] and an initial-infected
//! set, deterministically propagate "infection" through the graph one step at
//! a time. The eventual sub-tasks 3-5 layer xz-style campaign profiles,
//! integration tests, and a verification gate on top of this state machine.
//!
//! Design constraints (per bd-1q38 acceptance criteria and the project's
//! standing hardening conventions):
//!
//! * Determinism. Identical `(graph, initial_infected, config)` triples must
//!   produce identical [`SimulationTrace`] outputs. No floating-point fan-in
//!   order ambiguity: nodes are scanned via [`ContagionGraph::nodes()`] order
//!   and neighbors via their stored slice order (both already deterministic
//!   in sub-task 1).
//! * Every f64 (config field, accumulated exposure, weighted contribution)
//!   is `is_finite()`-guarded. Non-finite intermediates surface as
//!   [`SimulatorError::NonFiniteFloat`] rather than poisoning the trace.
//! * Counters use `saturating_add` so a runaway loop cannot wrap the step
//!   counter and bypass the `max_steps` guard.
//! * `max_steps` is capped at [`MAX_SIMULATION_STEPS`] to bound memory of
//!   `states_per_step` regardless of caller input.
//! * The simulator never panics on a malformed graph: every error path
//!   returns a typed [`SimulatorError`].

use std::collections::{BTreeMap, BTreeSet};

use super::contagion_graph::{ContagionGraph, NodeId};

/// Hard ceiling on `SimulatorConfig.max_steps`. Empirically the campaigns we
/// care about (xz-style, dependency-confusion, typosquat) converge in well
/// under 10k steps; this cap prevents a malicious config from forcing the
/// simulator to allocate an arbitrarily large `states_per_step` vector.
pub const MAX_SIMULATION_STEPS: u32 = 10_000;

/// Maximum number of [`InfectionState`] snapshots retained in a
/// [`SimulationTrace`]. `max_steps + 1` because the step-0 snapshot is also
/// retained (`states_per_step[0]` is the initial state).
const MAX_TRACE_SNAPSHOTS: usize = (MAX_SIMULATION_STEPS as usize).saturating_add(1);

/// Per-step infection state.
///
/// Invariants enforced at construction and after every [`step`]:
///
/// * Every value in `exposure_level` is `is_finite()`.
/// * `step` only increases via `saturating_add`.
/// * `infected` is a subset of the graph's node ids when the state is
///   produced by [`step`] / [`simulate`].
#[derive(Debug, Clone, PartialEq)]
pub struct InfectionState {
    infected: BTreeSet<NodeId>,
    exposure_level: BTreeMap<NodeId, f64>,
    step: u32,
}

impl InfectionState {
    /// Construct an initial (step-0) state from a slice of seed infections.
    ///
    /// Rejects duplicates silently (BTreeSet semantics) but does NOT check
    /// membership in any graph; that check lives in [`simulate`] /
    /// [`step`] which take a graph reference.
    pub fn new(initial_infected: &[NodeId]) -> Self {
        let mut infected = BTreeSet::new();
        for node in initial_infected {
            infected.insert(node.clone());
        }
        Self {
            infected,
            exposure_level: BTreeMap::new(),
            step: 0,
        }
    }

    /// Sorted snapshot of currently-infected node ids.
    pub fn infected(&self) -> &BTreeSet<NodeId> {
        &self.infected
    }

    /// Read the accumulated exposure level for a node. Returns 0.0 for nodes
    /// that have never received exposure (and for already-infected nodes,
    /// which we deliberately do not track exposure for after infection).
    pub fn exposure_of(&self, node: &NodeId) -> f64 {
        match self.exposure_level.get(node).copied() {
            Some(v) if v.is_finite() => v,
            _ => 0.0,
        }
    }

    /// Borrow the full exposure map (mainly for tests + verification gate).
    pub fn exposure_level(&self) -> &BTreeMap<NodeId, f64> {
        &self.exposure_level
    }

    /// Current step index. Step 0 is the initial state.
    pub fn step(&self) -> u32 {
        self.step
    }

    /// Number of infected nodes in this snapshot.
    pub fn infected_count(&self) -> usize {
        self.infected.len()
    }
}

/// Tunable parameters for a single simulation run.
///
/// All fields are sanity-checked by [`SimulatorConfig::validate`] before use:
///
/// * `max_steps` is clamped down to [`MAX_SIMULATION_STEPS`].
/// * `infection_threshold` and `decay_factor` must be finite and in
///   `[0.0, 1.0]`.
/// * `seed` is opaque and accepted as-is.
#[derive(Debug, Clone, PartialEq)]
pub struct SimulatorConfig {
    pub max_steps: u32,
    pub infection_threshold: f64,
    pub decay_factor: f64,
    pub seed: u64,
}

impl Default for SimulatorConfig {
    fn default() -> Self {
        Self {
            max_steps: 256,
            infection_threshold: 0.5,
            decay_factor: 0.8,
            seed: 0,
        }
    }
}

impl SimulatorConfig {
    /// Verify the config is internally consistent.
    ///
    /// Returns [`SimulatorError::NonFiniteFloat`] if any f64 field is NaN or
    /// infinite, and [`SimulatorError::BadConfig`] if a finite value lies
    /// outside its required range.
    pub fn validate(&self) -> Result<(), SimulatorError> {
        if !self.infection_threshold.is_finite() {
            return Err(SimulatorError::NonFiniteFloat);
        }
        if !self.decay_factor.is_finite() {
            return Err(SimulatorError::NonFiniteFloat);
        }
        if self.infection_threshold < 0.0 || self.infection_threshold > 1.0 {
            return Err(SimulatorError::BadConfig);
        }
        if self.decay_factor < 0.0 || self.decay_factor > 1.0 {
            return Err(SimulatorError::BadConfig);
        }
        if self.max_steps == 0 {
            return Err(SimulatorError::BadConfig);
        }
        Ok(())
    }

    /// Return a defensive copy of `self` with `max_steps` clamped to
    /// [`MAX_SIMULATION_STEPS`]. The original is left unchanged so callers
    /// can still display what they passed in for diagnostics.
    fn clamped(&self) -> Self {
        let max_steps = self.max_steps.min(MAX_SIMULATION_STEPS);
        Self {
            max_steps,
            infection_threshold: self.infection_threshold,
            decay_factor: self.decay_factor,
            seed: self.seed,
        }
    }
}

/// Why a [`simulate`] run stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminationReason {
    /// Two consecutive steps produced identical state (no churn).
    Converged,
    /// Reached the configured `max_steps` budget without converging.
    ReachedMaxSteps,
    /// Every node in the graph is infected.
    FullSpread,
    /// The initial-infected set is empty AND the graph has no edges from a
    /// seed, so no propagation is possible. Treated as a distinct terminal
    /// reason for clearer reporting.
    NoSpread,
}

/// Full record of a simulation run.
///
/// `states_per_step[i]` is the system state after step `i`. `states_per_step[0]`
/// is the initial state (pre-step). Length is always `terminated_at + 1`.
#[derive(Debug, Clone, PartialEq)]
pub struct SimulationTrace {
    pub config: SimulatorConfig,
    pub states_per_step: Vec<InfectionState>,
    pub terminated_at: u32,
    pub termination_reason: TerminationReason,
}

/// Typed errors from the simulator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SimulatorError {
    /// A finite-float invariant was violated (config field, edge weight, or
    /// accumulated exposure went non-finite).
    NonFiniteFloat,
    /// Configured `max_steps` was exceeded — only returned by helpers that
    /// treat the cap as an error rather than a soft termination.
    MaxStepsExceeded,
    /// The caller passed an empty initial-infected set to [`simulate`].
    EmptyInitialInfected,
    /// An initial-infected node id is not present in the graph.
    UnknownNode,
    /// `infection_threshold` or `decay_factor` is outside `[0.0, 1.0]`, or
    /// `max_steps == 0`.
    BadConfig,
}

/// Execute one step of the contagion process.
///
/// Semantics:
///
/// 1. Already-infected nodes stay infected.
/// 2. Each non-infected node accumulates exposure from infected in-neighbors
///    (i.e. infected sources that have an edge pointing at this node),
///    weighted by [`super::contagion_graph::ContagionEdge::weight`].
/// 3. Prior exposure is decayed by `config.decay_factor` before new
///    contributions are added — so `decay_factor == 0.0` is "memoryless"
///    and `decay_factor == 1.0` is "perfect memory" (with f64::MAX
///    saturation).
/// 4. Nodes whose post-decay-plus-contribution exposure is
///    `>= config.infection_threshold` become infected in the returned
///    state.
///
/// Deterministic: the iteration order over nodes is fixed by the graph's
/// `nodes()` slice (which sub-task 1 documents as stable). No random tie
/// breaking is needed because the rule is a deterministic threshold.
pub fn step(
    graph: &ContagionGraph,
    state: &InfectionState,
    config: &SimulatorConfig,
) -> Result<InfectionState, SimulatorError> {
    config.validate()?;

    // Pre-compute the in-edges for each node so we can scan "infected sources
    // pointing at me" in a single pass per node. Building this map per step
    // is O(E); given the campaign sizes we care about (≤ a few thousand
    // edges) and the modest step budget, this is well within budget and
    // keeps the simulator API graph-shape-agnostic.
    let in_edges = build_in_edges(graph);

    let mut next_exposure: BTreeMap<NodeId, f64> = BTreeMap::new();
    let mut next_infected: BTreeSet<NodeId> = state.infected.clone();

    for node in graph.nodes() {
        if state.infected.contains(node) {
            // Infected stays infected; we do not track exposure for them.
            continue;
        }

        // Start from decayed prior exposure.
        let prior = state.exposure_of(node);
        if !prior.is_finite() {
            return Err(SimulatorError::NonFiniteFloat);
        }
        let mut exposure = prior * config.decay_factor;
        if !exposure.is_finite() {
            return Err(SimulatorError::NonFiniteFloat);
        }

        // Add weighted contributions from infected in-neighbors.
        if let Some(sources) = in_edges.get(node) {
            for (src_id, weight) in sources {
                if !state.infected.contains(src_id) {
                    continue;
                }
                if !weight.is_finite() {
                    return Err(SimulatorError::NonFiniteFloat);
                }
                // Saturating add via clamp to f64::MAX so decay_factor=1.0 with
                // a perpetually-infected source cannot blow up to +inf.
                let candidate = exposure + weight;
                exposure = if candidate.is_finite() {
                    candidate
                } else {
                    f64::MAX
                };
            }
        }

        if !exposure.is_finite() {
            return Err(SimulatorError::NonFiniteFloat);
        }

        if exposure >= config.infection_threshold {
            next_infected.insert(node.clone());
            // Once infected, we stop tracking exposure for this node.
        } else if exposure > 0.0 {
            next_exposure.insert(node.clone(), exposure);
        }
    }

    Ok(InfectionState {
        infected: next_infected,
        exposure_level: next_exposure,
        step: state.step.saturating_add(1),
    })
}

/// Run the simulator until termination.
///
/// Termination is decided by [`detect_termination`]; the run is also bounded
/// by `config.max_steps` (capped at [`MAX_SIMULATION_STEPS`]).
pub fn simulate(
    graph: &ContagionGraph,
    initial_infected: &[NodeId],
    config: &SimulatorConfig,
) -> Result<SimulationTrace, SimulatorError> {
    config.validate()?;
    // Validate graph shape first so a malformed graph never produces a
    // partially-populated trace.
    graph.validate().map_err(|_| SimulatorError::UnknownNode)?;
    if initial_infected.is_empty() {
        return Err(SimulatorError::EmptyInitialInfected);
    }

    let node_set: BTreeSet<&NodeId> = graph.nodes().iter().collect();
    for n in initial_infected {
        if !node_set.contains(n) {
            return Err(SimulatorError::UnknownNode);
        }
    }

    let clamped = config.clamped();
    let mut current = InfectionState::new(initial_infected);
    let mut states_per_step: Vec<InfectionState> = Vec::with_capacity(8);
    crate::push_bounded(&mut states_per_step, current.clone(), MAX_TRACE_SNAPSHOTS);

    let total_nodes = graph.nodes().len();
    let mut terminated_at: u32 = 0;
    let mut termination_reason: TerminationReason = if current.infected.len() == total_nodes {
        TerminationReason::FullSpread
    } else {
        TerminationReason::ReachedMaxSteps
    };

    // Early-out: if the very first state already covers every node, return now.
    if current.infected.len() == total_nodes {
        return Ok(SimulationTrace {
            config: clamped,
            states_per_step,
            terminated_at,
            termination_reason: TerminationReason::FullSpread,
        });
    }

    let mut step_idx: u32 = 0;
    while step_idx < clamped.max_steps {
        let next = step(graph, &current, &clamped)?;
        step_idx = step_idx.saturating_add(1);

        if let Some(reason) = detect_termination(&current, &next, graph, &clamped) {
            crate::push_bounded(&mut states_per_step, next, MAX_TRACE_SNAPSHOTS);
            terminated_at = step_idx;
            termination_reason = reason;
            return Ok(SimulationTrace {
                config: clamped,
                states_per_step,
                terminated_at,
                termination_reason,
            });
        }

        crate::push_bounded(&mut states_per_step, next.clone(), MAX_TRACE_SNAPSHOTS);
        current = next;
        terminated_at = step_idx;
    }

    Ok(SimulationTrace {
        config: clamped,
        states_per_step,
        terminated_at,
        termination_reason,
    })
}

/// Classify whether the simulation should stop after `cur`.
///
/// Order of precedence (matches [`simulate`]'s assumptions):
///
/// 1. `FullSpread` — every node is infected.
/// 2. `NoSpread` — `prev` and `cur` are both empty AND there were no
///    newly-infected nodes in `cur` relative to `prev`.
///    (Used only when the seed set was empty — defensive,
///    since [`simulate`] rejects empty seeds, but the
///    [`step`] surface allows it.)
/// 3. `Converged` — `infected` and `exposure_level` are identical across
///    `prev` and `cur`.
/// 4. otherwise `None`.
pub fn detect_termination(
    prev: &InfectionState,
    cur: &InfectionState,
    graph: &ContagionGraph,
    _config: &SimulatorConfig,
) -> Option<TerminationReason> {
    let total = graph.nodes().len();
    if total > 0 && cur.infected.len() == total {
        return Some(TerminationReason::FullSpread);
    }
    if prev.infected.is_empty() && cur.infected.is_empty() && cur.exposure_level.is_empty() {
        return Some(TerminationReason::NoSpread);
    }
    if prev.infected == cur.infected && prev.exposure_level == cur.exposure_level {
        return Some(TerminationReason::Converged);
    }
    None
}

/// Build the reverse-adjacency view: for each node, the list of `(source,
/// weight)` pairs pointing at it. Used by [`step`] to do a single pass over
/// "who could have infected me this step".
fn build_in_edges(graph: &ContagionGraph) -> BTreeMap<NodeId, Vec<(NodeId, f64)>> {
    let mut in_edges: BTreeMap<NodeId, Vec<(NodeId, f64)>> = BTreeMap::new();
    for src in graph.nodes() {
        for edge in graph.neighbors(src) {
            in_edges
                .entry(edge.target.clone())
                .or_default()
                .push((src.clone(), edge.weight));
        }
    }
    in_edges
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dgis::contagion_graph::{ContagionEdge, EdgeKind};

    fn id(s: &str) -> NodeId {
        s.to_string()
    }

    fn linear_chain(seed: u64, n: usize, weight: f64) -> ContagionGraph {
        let mut g = ContagionGraph::new(seed);
        for i in 0..n {
            g.add_node(format!("n{i}"));
        }
        for i in 0..n.saturating_sub(1) {
            g.add_edge(
                &format!("n{i}"),
                ContagionEdge::new(format!("n{}", i + 1), weight, EdgeKind::DependencyImport)
                    .unwrap(),
            )
            .unwrap();
        }
        g
    }

    fn isolated_nodes(seed: u64, n: usize) -> ContagionGraph {
        let mut g = ContagionGraph::new(seed);
        for i in 0..n {
            g.add_node(format!("n{i}"));
        }
        g
    }

    fn dense_graph(seed: u64, n: usize, weight: f64) -> ContagionGraph {
        let mut g = ContagionGraph::new(seed);
        for i in 0..n {
            g.add_node(format!("n{i}"));
        }
        for i in 0..n {
            for j in 0..n {
                if i == j {
                    continue;
                }
                g.add_edge(
                    &format!("n{i}"),
                    ContagionEdge::new(format!("n{j}"), weight, EdgeKind::DependencyImport)
                        .unwrap(),
                )
                .unwrap();
            }
        }
        g
    }

    #[test]
    fn convergence_small_graph_reaches_fixed_point() {
        // 5-node chain n0 -> n1 -> n2 -> n3 -> n4, weight 1.0, threshold 0.5,
        // decay 1.0 (perfect memory). Seeded at n0, infection should ripple
        // one node per step and then converge once n4 is infected.
        let g = linear_chain(1, 5, 1.0);
        let cfg = SimulatorConfig {
            max_steps: 64,
            infection_threshold: 0.5,
            decay_factor: 1.0,
            seed: 0,
        };
        let trace = simulate(&g, &[id("n0")], &cfg).unwrap();
        let last = trace.states_per_step.last().unwrap();
        assert_eq!(last.infected_count(), 5);
        // Termination should be FullSpread (every node infected) which takes
        // strict precedence over Converged in detect_termination.
        assert_eq!(trace.termination_reason, TerminationReason::FullSpread);
        // states_per_step length matches terminated_at + 1.
        assert_eq!(
            trace.states_per_step.len(),
            (trace.terminated_at as usize).saturating_add(1)
        );
    }

    #[test]
    fn no_spread_base_case_zero_edges() {
        // Graph with isolated nodes and no edges. Single seed; nothing
        // propagates, simulator should converge after one step with only
        // the seed infected.
        let g = isolated_nodes(2, 4);
        let cfg = SimulatorConfig {
            max_steps: 16,
            infection_threshold: 0.5,
            decay_factor: 0.5,
            seed: 0,
        };
        let trace = simulate(&g, &[id("n0")], &cfg).unwrap();
        assert_eq!(trace.termination_reason, TerminationReason::Converged);
        let last = trace.states_per_step.last().unwrap();
        assert_eq!(last.infected_count(), 1);
        assert!(last.infected.contains("n0"));
    }

    #[test]
    fn full_spread_dense_graph_threshold_zero_infects_all_step_one() {
        // Dense complete digraph; threshold 0 means any nonzero exposure
        // flips a node. With seed = n0 and all edges weight 1.0, the rest
        // of the nodes all get exposure 1.0 on step 1.
        let g = dense_graph(7, 5, 1.0);
        let cfg = SimulatorConfig {
            max_steps: 8,
            infection_threshold: 0.0,
            decay_factor: 0.0,
            seed: 0,
        };
        let trace = simulate(&g, &[id("n0")], &cfg).unwrap();
        assert_eq!(trace.termination_reason, TerminationReason::FullSpread);
        assert!(trace.terminated_at <= 1);
        let last = trace.states_per_step.last().unwrap();
        assert_eq!(last.infected_count(), 5);
    }

    #[test]
    fn empty_initial_infected_rejected() {
        let g = linear_chain(3, 3, 0.5);
        let cfg = SimulatorConfig::default();
        let err = simulate(&g, &[], &cfg).unwrap_err();
        assert_eq!(err, SimulatorError::EmptyInitialInfected);
    }

    #[test]
    fn unknown_initial_infected_rejected() {
        let g = linear_chain(3, 3, 0.5);
        let cfg = SimulatorConfig::default();
        let err = simulate(&g, &[id("ghost")], &cfg).unwrap_err();
        assert_eq!(err, SimulatorError::UnknownNode);
    }

    #[test]
    fn decay_factor_zero_is_memoryless() {
        // Star graph: n0 -> n1 with weight 0.4 (below threshold 0.5).
        // decay_factor 0 means prior exposure is forgotten each step, so
        // exposure stays at 0.4 forever — n1 never infects.
        let mut g = ContagionGraph::new(4);
        g.add_node(id("n0"));
        g.add_node(id("n1"));
        g.add_edge(
            &id("n0"),
            ContagionEdge::new(id("n1"), 0.4, EdgeKind::OrgOverlap).unwrap(),
        )
        .unwrap();
        let cfg = SimulatorConfig {
            max_steps: 10,
            infection_threshold: 0.5,
            decay_factor: 0.0,
            seed: 0,
        };
        let trace = simulate(&g, &[id("n0")], &cfg).unwrap();
        assert_eq!(trace.termination_reason, TerminationReason::Converged);
        let last = trace.states_per_step.last().unwrap();
        assert_eq!(last.infected_count(), 1);
        // n1 has exposure exactly 0.4 every step under decay 0.
        assert!((last.exposure_of(&id("n1")) - 0.4).abs() < 1e-12);
    }

    #[test]
    fn decay_factor_one_accumulates_exposure_to_saturation() {
        // n0 -> n1 weight 0.1, threshold 1.01 (unreachable in one step but
        // reachable after enough accumulation). decay 1.0 keeps prior
        // exposure intact; n1 should infect within ~11 steps.
        let mut g = ContagionGraph::new(5);
        g.add_node(id("n0"));
        g.add_node(id("n1"));
        g.add_edge(
            &id("n0"),
            ContagionEdge::new(id("n1"), 0.1, EdgeKind::MaintainerOverlap).unwrap(),
        )
        .unwrap();
        let cfg = SimulatorConfig {
            max_steps: 50,
            infection_threshold: 1.0,
            decay_factor: 1.0,
            seed: 0,
        };
        let trace = simulate(&g, &[id("n0")], &cfg).unwrap();
        assert_eq!(trace.termination_reason, TerminationReason::FullSpread);
        // Should take ~10 steps to accumulate from 0 to >= 1.0 in 0.1 chunks.
        assert!(trace.terminated_at >= 9 && trace.terminated_at <= 11);
        // No exposure value ever went non-finite.
        for s in &trace.states_per_step {
            for v in s.exposure_level().values() {
                assert!(v.is_finite());
            }
        }
    }

    #[test]
    fn max_steps_termination() {
        // Chain where exposure never crosses threshold and decay keeps it
        // pinned below — simulator should hit max_steps without converging
        // to a fixed point. Use a very short max_steps to keep the test fast.
        // Threshold 0.5, weight 0.1, decay 0.9 → asymptote at 0.1/(1-0.9) = 1.0
        // which would cross threshold eventually, so we cap max_steps below
        // the crossing point (and confirm we still see ReachedMaxSteps).
        let g = linear_chain(6, 3, 0.1);
        let cfg = SimulatorConfig {
            max_steps: 3,
            infection_threshold: 0.99,
            decay_factor: 0.9,
            seed: 0,
        };
        let trace = simulate(&g, &[id("n0")], &cfg).unwrap();
        assert_eq!(trace.termination_reason, TerminationReason::ReachedMaxSteps);
        assert_eq!(trace.terminated_at, 3);
        assert_eq!(trace.states_per_step.len(), 4);
    }

    #[test]
    fn deterministic_same_config_same_trace() {
        let g = dense_graph(9, 6, 0.3);
        let cfg = SimulatorConfig {
            max_steps: 32,
            infection_threshold: 0.5,
            decay_factor: 0.7,
            seed: 0xABCD_1234,
        };
        let t1 = simulate(&g, &[id("n0"), id("n2")], &cfg).unwrap();
        let t2 = simulate(&g, &[id("n0"), id("n2")], &cfg).unwrap();
        assert_eq!(t1, t2);
    }

    #[test]
    fn non_finite_config_field_rejected() {
        let g = linear_chain(11, 2, 0.5);
        let bad_threshold = SimulatorConfig {
            max_steps: 4,
            infection_threshold: f64::NAN,
            decay_factor: 0.5,
            seed: 0,
        };
        assert_eq!(
            simulate(&g, &[id("n0")], &bad_threshold).unwrap_err(),
            SimulatorError::NonFiniteFloat
        );
        let bad_decay = SimulatorConfig {
            max_steps: 4,
            infection_threshold: 0.5,
            decay_factor: f64::INFINITY,
            seed: 0,
        };
        assert_eq!(
            simulate(&g, &[id("n0")], &bad_decay).unwrap_err(),
            SimulatorError::NonFiniteFloat
        );
        let out_of_range = SimulatorConfig {
            max_steps: 4,
            infection_threshold: 1.5,
            decay_factor: 0.5,
            seed: 0,
        };
        assert_eq!(
            simulate(&g, &[id("n0")], &out_of_range).unwrap_err(),
            SimulatorError::BadConfig
        );
        let zero_steps = SimulatorConfig {
            max_steps: 0,
            infection_threshold: 0.5,
            decay_factor: 0.5,
            seed: 0,
        };
        assert_eq!(
            simulate(&g, &[id("n0")], &zero_steps).unwrap_err(),
            SimulatorError::BadConfig
        );
    }

    #[test]
    fn exposure_level_always_finite_after_step() {
        // Even with decay 1.0 and many infected neighbors hammering one
        // target, exposure must stay finite (clamped at f64::MAX).
        let g = dense_graph(13, 8, 1.0);
        let cfg = SimulatorConfig {
            max_steps: 32,
            infection_threshold: 0.5,
            decay_factor: 1.0,
            seed: 0,
        };
        let trace = simulate(&g, &[id("n0")], &cfg).unwrap();
        for snapshot in &trace.states_per_step {
            for v in snapshot.exposure_level().values() {
                assert!(
                    v.is_finite(),
                    "non-finite exposure at step {}",
                    snapshot.step()
                );
            }
        }
    }

    #[test]
    fn trace_length_matches_terminated_at_plus_one() {
        // Run several different scenarios and check the invariant holds.
        let scenarios: Vec<(ContagionGraph, Vec<NodeId>, SimulatorConfig)> = vec![
            (
                linear_chain(21, 4, 0.6),
                vec![id("n0")],
                SimulatorConfig {
                    max_steps: 20,
                    infection_threshold: 0.5,
                    decay_factor: 0.0,
                    seed: 1,
                },
            ),
            (
                isolated_nodes(22, 3),
                vec![id("n0")],
                SimulatorConfig {
                    max_steps: 5,
                    infection_threshold: 0.5,
                    decay_factor: 0.5,
                    seed: 2,
                },
            ),
            (
                dense_graph(23, 4, 1.0),
                vec![id("n0")],
                SimulatorConfig {
                    max_steps: 20,
                    infection_threshold: 0.0,
                    decay_factor: 0.0,
                    seed: 3,
                },
            ),
        ];
        for (g, seeds, cfg) in scenarios {
            let trace = simulate(&g, &seeds, &cfg).unwrap();
            assert_eq!(
                trace.states_per_step.len(),
                (trace.terminated_at as usize).saturating_add(1),
                "trace length mismatch for termination={:?}",
                trace.termination_reason,
            );
        }
    }

    #[test]
    fn max_steps_capped_at_simulation_ceiling() {
        // Passing a max_steps > MAX_SIMULATION_STEPS must not allocate an
        // outsized trace. We verify by inspecting the returned config.
        let g = isolated_nodes(31, 2);
        let cfg = SimulatorConfig {
            max_steps: u32::MAX,
            infection_threshold: 0.5,
            decay_factor: 0.5,
            seed: 0,
        };
        let trace = simulate(&g, &[id("n0")], &cfg).unwrap();
        assert!(trace.config.max_steps <= MAX_SIMULATION_STEPS);
        // Should converge immediately (no edges).
        assert_eq!(trace.termination_reason, TerminationReason::Converged);
    }

    #[test]
    fn step_function_is_pure_and_does_not_mutate_input_state() {
        let g = linear_chain(41, 4, 0.6);
        let cfg = SimulatorConfig {
            max_steps: 10,
            infection_threshold: 0.5,
            decay_factor: 0.5,
            seed: 0,
        };
        let s0 = InfectionState::new(&[id("n0")]);
        let s1 = step(&g, &s0, &cfg).unwrap();
        // s0 is untouched.
        assert_eq!(s0.step(), 0);
        assert_eq!(s0.infected_count(), 1);
        // s1 reflects propagation.
        assert_eq!(s1.step(), 1);
        assert!(s1.infected.contains("n0"));
        assert!(s1.infected.contains("n1"));
    }
}
