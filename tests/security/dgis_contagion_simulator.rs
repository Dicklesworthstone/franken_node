//! Integration test for the DGIS adversarial contagion simulator.
//!
//! Sub-task 4 of bd-1q38.1: load each shipped campaign profile fixture
//! (xz_style, dependency_confusion, typosquat), run it through the
//! [`evaluate_profile`] entry point, and assert the
//! [`ProfileVerdict`] matches the profile's own `expected` block.
//!
//! Builds on the three earlier sub-tasks:
//!   1. `contagion_graph.rs` (graph + edge types, deterministic generation)
//!   2. `contagion_simulator.rs` (`step` / `simulate` / `detect_termination`)
//!   3. `contagion_profiles.rs` (JSON profile loader, `evaluate_profile`)
//!
//! The fixtures live under
//! `tests/security/contagion_profiles/<name>.json` (relative to the
//! workspace root). `load_profile` here resolves that path relative to
//! `CARGO_MANIFEST_DIR` so the test runs identically whether invoked as
//! `cargo test -p frankenengine-node --test dgis_contagion_simulator`
//! or from inside `rch exec`.
//!
//! Per project conventions: REAL types from the production module, no
//! mocks, no `unwrap` on fallible-but-user-controlled paths (only on
//! truly-impossible internal invariants documented inline).

use std::fs;
use std::path::PathBuf;

use frankenengine_node::dgis::contagion_graph::{ContagionEdge, ContagionGraph, EdgeKind, NodeId};
use frankenengine_node::dgis::contagion_profiles::{
    ContagionProfile, ExpectedOutcome, ProfileEdgeSpec, ProfileError, ProfileGraphSpec,
    ProfileSimulatorConfig, WireEdgeKind, WireTerminationReason, build_graph_from_spec,
    evaluate_profile, load_profile_from_json,
};
use frankenengine_node::dgis::contagion_simulator::{
    InfectionState, SimulatorConfig, TerminationReason, detect_termination, simulate,
};

type TestResult = Result<(), String>;

/// Resolve the absolute path to a profile fixture from the per-crate
/// `CARGO_MANIFEST_DIR` (which is `crates/franken-node/` at test time)
/// up to `tests/security/contagion_profiles/<name>.json` at the
/// workspace root.
fn profile_path(name: &str) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("..")
        .join("..")
        .join("tests")
        .join("security")
        .join("contagion_profiles")
        .join(format!("{name}.json"))
}

/// Load and validate a shipped profile fixture by name.
///
/// Returns a descriptive error that names the failing fixture on I/O or
/// validation failure.
fn load_profile(name: &str) -> Result<ContagionProfile, String> {
    let path = profile_path(name);
    let json =
        fs::read_to_string(&path).map_err(|e| format!("read fixture {}: {e}", path.display()))?;
    load_profile_from_json(&json).map_err(|e| format!("load profile {name}: {e:?}"))
}

#[test]
fn test_xz_style_profile_evaluates_to_pass() -> TestResult {
    let profile = load_profile("xz_style")?;
    assert_eq!(profile.name, "xz_style");
    let verdict =
        evaluate_profile(&profile).map_err(|e| format!("xz_style evaluate failed: {e:?}"))?;
    assert!(
        verdict.passed,
        "xz_style verdict diverged from expected: {:?}",
        verdict.divergences,
    );
    assert!(verdict.divergences.is_empty());
    // Sanity-check the verdict matches the profile's own `expected` block.
    assert!(verdict.actual_infected_count >= profile.expected.min_infected_count);
    assert!(verdict.actual_infected_count <= profile.expected.max_infected_count);
    assert!(verdict.actual_terminated_at <= profile.expected.terminated_by_step);
    let expected_reason: TerminationReason = profile.expected.termination_reason.into();
    assert_eq!(verdict.actual_termination_reason, expected_reason);
    Ok(())
}

#[test]
fn test_dependency_confusion_profile_evaluates_to_pass() -> TestResult {
    let profile = load_profile("dependency_confusion")?;
    assert_eq!(profile.name, "dependency_confusion");
    let verdict = evaluate_profile(&profile)
        .map_err(|e| format!("dependency_confusion evaluate failed: {e:?}"))?;
    assert!(
        verdict.passed,
        "dependency_confusion verdict diverged: {:?}",
        verdict.divergences,
    );
    assert!(verdict.actual_infected_count >= profile.expected.min_infected_count);
    assert!(verdict.actual_infected_count <= profile.expected.max_infected_count);
    assert!(verdict.actual_terminated_at <= profile.expected.terminated_by_step);
    let expected_reason: TerminationReason = profile.expected.termination_reason.into();
    assert_eq!(verdict.actual_termination_reason, expected_reason);
    Ok(())
}

#[test]
fn test_typosquat_profile_evaluates_to_pass() -> TestResult {
    let profile = load_profile("typosquat")?;
    assert_eq!(profile.name, "typosquat");
    let verdict =
        evaluate_profile(&profile).map_err(|e| format!("typosquat evaluate failed: {e:?}"))?;
    assert!(
        verdict.passed,
        "typosquat verdict diverged: {:?}",
        verdict.divergences,
    );
    assert!(verdict.actual_infected_count >= profile.expected.min_infected_count);
    assert!(verdict.actual_infected_count <= profile.expected.max_infected_count);
    assert!(verdict.actual_terminated_at <= profile.expected.terminated_by_step);
    let expected_reason: TerminationReason = profile.expected.termination_reason.into();
    assert_eq!(verdict.actual_termination_reason, expected_reason);
    Ok(())
}

#[test]
fn test_all_profiles_deterministic_across_two_runs() -> TestResult {
    // For each shipped fixture: load and evaluate twice, then assert the
    // two `ProfileVerdict`s are byte-identical. This guards against any
    // accidentally-introduced non-determinism (HashMap iteration order,
    // wall-clock seeds, etc.) anywhere in the load + simulate + compare
    // pipeline.
    for name in ["xz_style", "dependency_confusion", "typosquat"] {
        let profile = load_profile(name)?;
        let v1 = evaluate_profile(&profile)
            .map_err(|e| format!("{name}: first evaluate failed {e:?}"))?;
        let v2 = evaluate_profile(&profile)
            .map_err(|e| format!("{name}: second evaluate failed {e:?}"))?;
        assert_eq!(
            v1, v2,
            "{name}: two evaluations of the same profile must be byte-identical",
        );

        // Also confirm trace-level determinism by running `simulate`
        // directly twice and comparing the full SimulationTrace.
        let graph = build_graph_from_spec(&profile.graph)
            .map_err(|e| format!("{name}: build_graph_from_spec failed {e:?}"))?;
        let cfg: SimulatorConfig = profile.config.clone().into();
        let t1 = simulate(&graph, &profile.initial_infected, &cfg)
            .map_err(|e| format!("{name}: first simulate failed {e:?}"))?;
        let t2 = simulate(&graph, &profile.initial_infected, &cfg)
            .map_err(|e| format!("{name}: second simulate failed {e:?}"))?;
        assert_eq!(
            t1, t2,
            "{name}: two simulations must produce identical traces"
        );
        // Trace length invariant: states_per_step.len() == terminated_at + 1.
        assert_eq!(
            t1.states_per_step.len(),
            (t1.terminated_at as usize).saturating_add(1),
            "{name}: trace length must equal terminated_at + 1",
        );
    }
    Ok(())
}

#[test]
fn test_profile_with_missing_node_fails_evaluation() -> TestResult {
    // Synthesize a profile where `initial_infected` references a node id
    // that is NOT in `graph.nodes`. `evaluate_profile` must surface this
    // as `ProfileError::UnknownNode` rather than panicking or producing a
    // misleading verdict.
    let mut profile = load_profile("xz_style")?;
    profile.initial_infected = vec!["pkg:does_not_exist_in_graph".to_string()];
    let err = evaluate_profile(&profile).expect_err("missing initial_infected must reject");
    assert_eq!(err, ProfileError::UnknownNode);

    // Independently: a profile whose `graph.edges` references an unknown
    // endpoint must also fail at the graph-building stage rather than
    // poisoning the simulator with a dangling target.
    let bad_spec = ProfileGraphSpec {
        nodes: vec!["a".to_string(), "b".to_string()],
        edges: vec![ProfileEdgeSpec {
            from: "a".to_string(),
            to: "ghost_node".to_string(),
            weight: 0.5,
            edge_kind: WireEdgeKind::DependencyImport,
        }],
        seed: 0,
    };
    let err = build_graph_from_spec(&bad_spec).expect_err("dangling edge must reject");
    assert_eq!(err, ProfileError::UnknownNode);
    Ok(())
}

#[test]
fn test_profile_with_nan_weight_rejected_at_load() {
    // Two paths exercise the "NaN/non-finite weight rejected at load"
    // contract:
    //
    //   1. `build_graph_from_spec` on a programmatically-constructed
    //      ProfileGraphSpec carrying f64::NAN — this is the entry point
    //      that the JSON loader uses internally, so a smuggled non-finite
    //      weight (e.g. from a future binary-format loader) must reject
    //      with `ProfileError::InvalidWeight`.
    //   2. The same for f64::INFINITY, since both are non-finite.
    //
    // We deliberately do NOT try to push raw `NaN` through JSON: serde_json
    // rejects bare `NaN` at the parse layer (covered by a unit test
    // inside `contagion_profiles.rs`).
    let nan_spec = ProfileGraphSpec {
        nodes: vec!["a".to_string(), "b".to_string()],
        edges: vec![ProfileEdgeSpec {
            from: "a".to_string(),
            to: "b".to_string(),
            weight: f64::NAN,
            edge_kind: WireEdgeKind::DependencyImport,
        }],
        seed: 0,
    };
    let err = build_graph_from_spec(&nan_spec).expect_err("NaN weight must reject");
    assert_eq!(err, ProfileError::InvalidWeight);

    let inf_spec = ProfileGraphSpec {
        nodes: vec!["a".to_string(), "b".to_string()],
        edges: vec![ProfileEdgeSpec {
            from: "a".to_string(),
            to: "b".to_string(),
            weight: f64::INFINITY,
            edge_kind: WireEdgeKind::DependencyImport,
        }],
        seed: 0,
    };
    let err = build_graph_from_spec(&inf_spec).expect_err("INFINITY weight must reject");
    assert_eq!(err, ProfileError::InvalidWeight);

    // Negative weight is also "non-finite-or-out-of-range" per the
    // simulator's contract — verify the loader catches it as InvalidWeight
    // as well so a corrupted fixture cannot smuggle a negative
    // propagation probability into the simulator.
    let neg_spec = ProfileGraphSpec {
        nodes: vec!["a".to_string(), "b".to_string()],
        edges: vec![ProfileEdgeSpec {
            from: "a".to_string(),
            to: "b".to_string(),
            weight: -0.001,
            edge_kind: WireEdgeKind::DependencyImport,
        }],
        seed: 0,
    };
    let err = build_graph_from_spec(&neg_spec).expect_err("negative weight must reject");
    assert_eq!(err, ProfileError::InvalidWeight);
}

#[test]
fn test_full_spread_termination_reached() -> TestResult {
    // Construct a small dense profile programmatically (no JSON) so the
    // FullSpread reach is unambiguous: 4 nodes, every (src,dst) pair with
    // src!=dst, weight 1.0, threshold 0.0 — every non-infected node gets
    // exposure 1.0 on step 1, crossing the threshold instantly.
    let nodes: Vec<NodeId> = (0..4).map(|i| format!("n{i}")).collect();
    let mut edges: Vec<ProfileEdgeSpec> = Vec::new();
    for i in 0..nodes.len() {
        for j in 0..nodes.len() {
            if i == j {
                continue;
            }
            edges.push(ProfileEdgeSpec {
                from: nodes[i].clone(),
                to: nodes[j].clone(),
                weight: 1.0,
                edge_kind: WireEdgeKind::DependencyImport,
            });
        }
    }
    let profile = ContagionProfile {
        name: "test_full_spread_dense".to_string(),
        description: "synthetic dense graph; threshold 0 forces FullSpread on step 1".to_string(),
        graph: ProfileGraphSpec {
            nodes: nodes.clone(),
            edges,
            seed: 0xFFFF_FFFF,
        },
        initial_infected: vec![nodes[0].clone()],
        config: ProfileSimulatorConfig {
            max_steps: 16,
            infection_threshold: 0.0,
            decay_factor: 0.0,
            seed: 0,
        },
        expected: ExpectedOutcome {
            termination_reason: WireTerminationReason::FullSpread,
            min_infected_count: nodes.len(),
            max_infected_count: nodes.len(),
            terminated_by_step: 4,
        },
    };
    let verdict = evaluate_profile(&profile)
        .map_err(|e| format!("dense profile evaluation failed: {e:?}"))?;
    assert!(
        verdict.passed,
        "dense profile must pass; divergences={:?}",
        verdict.divergences,
    );
    assert_eq!(
        verdict.actual_termination_reason,
        TerminationReason::FullSpread,
    );
    assert_eq!(verdict.actual_infected_count, nodes.len());
    assert!(
        verdict.actual_terminated_at <= 1,
        "FullSpread on a dense threshold-0 graph must complete in <= 1 step (got {})",
        verdict.actual_terminated_at,
    );
    Ok(())
}

#[test]
fn test_no_spread_termination_when_no_edges() -> TestResult {
    // Two assertions cover the "no spread" contract:
    //
    //   (a) The supported entry point: `simulate` with one seed on a
    //       graph with zero edges. Per the simulator's contract, this
    //       converges immediately with only the seed infected
    //       (`Converged`, since `prev.infected` is non-empty so
    //       `NoSpread` is never returned).
    //   (b) The `detect_termination` API directly with an *empty*
    //       previous-and-current state on an edgeless graph — that is
    //       the exact precondition for the `NoSpread` reason, which the
    //       `simulate` wrapper deliberately precludes by rejecting empty
    //       seed sets.
    let mut g = ContagionGraph::new(99);
    for i in 0..4 {
        g.add_node(format!("n{i}"));
    }
    // Sanity: graph really has zero edges.
    assert_eq!(g.edge_count(), 0);

    // (a) simulate path → Converged with infected_count == 1.
    let cfg = SimulatorConfig {
        max_steps: 8,
        infection_threshold: 0.5,
        decay_factor: 0.5,
        seed: 0,
    };
    let trace = simulate(&g, &["n0".to_string()], &cfg)
        .map_err(|e| format!("simulate on isolated graph failed: {e:?}"))?;
    assert_eq!(trace.termination_reason, TerminationReason::Converged);
    let last = trace
        .states_per_step
        .last()
        .ok_or_else(|| "trace must contain at least step 0".to_string())?;
    assert_eq!(last.infected_count(), 1);

    // (b) detect_termination path → NoSpread when prev and cur are both
    //     empty AND cur.exposure_level is empty. Construct two empty
    //     states (the `step` function happens to leave both fields
    //     empty when called on an edgeless graph with no seeds).
    let empty_state = InfectionState::new(&[]);
    let reason = detect_termination(&empty_state, &empty_state, &g, &cfg);
    assert_eq!(reason, Some(TerminationReason::NoSpread));

    // Bonus: when neighbors() is called on every node, none of them
    // report any out-edges, confirming the "0 edges" invariant the
    // simulator relied on above. Use real types only (no mocks).
    for node in g.nodes() {
        assert!(
            g.neighbors(node).is_empty(),
            "node {node} unexpectedly had edges"
        );
        // The ContagionEdge type is reachable in this scope to satisfy
        // the "use REAL types from contagion_*" contract; we materialise
        // (but do not insert) one to ensure the import is not dead-code
        // pruned by a future cleanup pass.
        let _sample: ContagionEdge =
            ContagionEdge::new(node.clone(), 0.0, EdgeKind::DependencyImport)
                .map_err(|e| format!("zero-weight edge should be constructible: {e:?}"))?;
    }
    Ok(())
}

/// Regression: `ContagionGraph::add_node` must silently cap at the internal
/// `MAX_NODES` limit (currently 1024, matching `MAX_PROFILE_NODES`) so a
/// caller that bypasses the profile loader cannot balloon memory. The cap
/// is intentionally not exported; we observe it via the public `nodes()`
/// slice after pushing well past it.
#[test]
fn contagion_graph_add_node_caps_memory_below_max_nodes_plus_overflow() -> TestResult {
    const OVERFLOW: usize = 5_000;
    let mut g = ContagionGraph::new(0);
    for i in 0..OVERFLOW {
        g.add_node(format!("n{i:08}"));
    }
    // The cap is private; assert the observable shape: nodes() length is
    // strictly less than what we tried to insert, AND is non-empty (so the
    // graph still validates with at least the cap's worth of nodes).
    let nodes_len: NodeId = format!("nodes_len={}", g.nodes().len());
    assert!(
        g.nodes().len() < OVERFLOW,
        "add_node failed to bound: {nodes_len}"
    );
    assert!(
        g.nodes().len() >= 1024,
        "add_node bounded below the documented cap: {nodes_len}"
    );
    // Idempotent re-add of an already-present id is still a no-op even at
    // cap (does not double-insert, does not panic).
    let last_count = g.nodes().len();
    g.add_node("n00000000".to_string());
    assert_eq!(g.nodes().len(), last_count);
    Ok(())
}

/// Regression: `generate_deterministic` must clamp `n_nodes` so the
/// edge-generation loop (which indexes `graph.nodes[src_idx]`) cannot
/// panic when the caller passes an unbounded value. Before the cap was
/// added, `n_nodes >> MAX_NODES` would either OOM or panic on index OOB
/// once add_node started silently refusing.
#[test]
fn generate_deterministic_clamps_n_nodes_without_panic() -> TestResult {
    // 8 * MAX_NODES; would OOM the test runner pre-fix.
    let g = ContagionGraph::generate_deterministic(0xC0DE_FACE, 8192, 0.01);
    assert!(
        g.nodes().len() <= 1024,
        "generate_deterministic exceeded MAX_NODES: {}",
        g.nodes().len()
    );
    assert!(g.validate().is_ok(), "clamped graph must still validate");
    Ok(())
}
