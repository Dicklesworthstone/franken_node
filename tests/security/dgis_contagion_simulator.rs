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

use frankenengine_node::dgis::contagion_graph::{
    ContagionEdge, ContagionGraph, EdgeKind, GraphError, NodeId, validate_node_id,
};
use frankenengine_node::dgis::contagion_profiles::{
    ContagionProfile, ExpectedOutcome, ProfileEdgeSpec, ProfileError, ProfileGraphSpec,
    ProfileSimulatorConfig, WireEdgeKind, WireTerminationReason, build_graph_from_spec,
    evaluate_profile, load_profile_from_json,
};
use frankenengine_node::dgis::contagion_simulator::{
    InfectionState, SimulationTrace, SimulatorConfig, TerminationReason, detect_termination,
    simulate, step,
};
use frankenengine_node::dgis::node_interner::{InternError, NODE_INTERNER_MAX_NODES, NodeInterner};
use proptest::prelude::*;
use proptest::test_runner::{Config as ProptestConfig, TestRunner};
use serde::Deserialize;

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

fn golden_trace_path(name: &str) -> PathBuf {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .join("..")
        .join("..")
        .join("tests")
        .join("golden")
        .join("dgis_traces")
        .join(format!("{name}.golden.json"))
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct GoldenTrace {
    campaign: String,
    terminated_at: u32,
    termination_reason: String,
    states: Vec<GoldenState>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct GoldenState {
    step: u32,
    infected: Vec<String>,
    exposure: Vec<GoldenExposure>,
}

#[derive(Debug, Deserialize, PartialEq, Eq)]
struct GoldenExposure {
    node: String,
    value: String,
}

fn golden_trace(name: &str) -> Result<GoldenTrace, String> {
    let path = golden_trace_path(name);
    let json =
        fs::read_to_string(&path).map_err(|e| format!("read golden {}: {e}", path.display()))?;
    serde_json::from_str(&json).map_err(|e| format!("parse golden {name}: {e}"))
}

fn trace_projection(name: &str, trace: &SimulationTrace) -> GoldenTrace {
    GoldenTrace {
        campaign: name.to_string(),
        terminated_at: trace.terminated_at,
        termination_reason: format!("{:?}", trace.termination_reason),
        states: trace
            .states_per_step
            .iter()
            .map(|state| GoldenState {
                step: state.step(),
                infected: state.infected().iter().cloned().collect(),
                exposure: state
                    .exposure_level()
                    .iter()
                    .map(|(node, value)| GoldenExposure {
                        node: node.clone(),
                        value: format!("{value:.12}"),
                    })
                    .collect(),
            })
            .collect(),
    }
}

fn campaign_trace(name: &str) -> Result<SimulationTrace, String> {
    let profile = load_profile(name)?;
    let graph = build_graph_from_spec(&profile.graph)
        .map_err(|e| format!("{name}: build_graph_from_spec failed {e:?}"))?;
    let cfg: SimulatorConfig = profile.config.into();
    simulate(&graph, &profile.initial_infected, &cfg)
        .map_err(|e| format!("{name}: simulate failed {e:?}"))
}

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn intern_same_string_returns_same_id() {
    let mut interner = NodeInterner::new();
    let a = interner.intern("npm:@scope/pkg").unwrap();
    let b = interner.intern("npm:@scope/pkg").unwrap();

    assert_eq!(a, b);
    assert_eq!(interner.len(), 1);
}

#[test]
fn intern_different_strings_return_distinct_ids() {
    let mut interner = NodeInterner::new();
    let a = interner.intern("foo").unwrap();
    let b = interner.intern("bar").unwrap();

    assert_ne!(a, b);
    assert_eq!(interner.len(), 2);
}

#[test]
fn resolve_round_trip() {
    let mut interner = NodeInterner::new();
    for node in ["foo", "bar", "baz"] {
        let id = interner.intern(node).unwrap();
        assert_eq!(interner.resolve(id), Some(node));
    }
}

#[test]
fn intern_capacity_bound() {
    let mut interner = NodeInterner::new();
    for i in 0..NODE_INTERNER_MAX_NODES {
        interner
            .intern(&format!("node-{i}"))
            .expect("under cap must succeed");
    }

    assert_eq!(
        interner.intern("one-too-many").unwrap_err(),
        InternError::CapacityExceeded {
            max: NODE_INTERNER_MAX_NODES,
        }
    );
}

#[test]
fn intern_empty_string() {
    let mut interner = NodeInterner::new();

    assert_eq!(interner.intern("").unwrap_err(), InternError::InvalidNodeId);
    assert_eq!(
        interner.intern(" \t ").unwrap_err(),
        InternError::InvalidNodeId
    );
    assert_eq!(
        interner.intern("pkg\nsplit").unwrap_err(),
        InternError::InvalidNodeId
    );
    assert!(interner.is_empty());
}

#[test]
fn intern_order_drives_node_id_assignment() {
    let mut interner = NodeInterner::new();
    let a = interner.intern("a").unwrap();
    let b = interner.intern("b").unwrap();

    assert_eq!(a.as_u32(), 0);
    assert_eq!(b.as_u32(), 1);
}

#[test]
fn interner_send_sync_bounds() {
    assert_send_sync::<NodeInterner>();
}

#[test]
fn graph_nodes_iter_matches_legacy_string_view() {
    let mut graph = ContagionGraph::new(101);
    for node in ["pkg:root", "pkg:dep-a", "pkg:dep-b"] {
        graph.add_node(node.to_string());
    }

    assert_eq!(
        graph.nodes(),
        &[
            "pkg:root".to_string(),
            "pkg:dep-a".to_string(),
            "pkg:dep-b".to_string()
        ]
    );
}

#[test]
fn graph_add_edge_with_intern_creates_correct_adjacency() -> TestResult {
    let mut graph = ContagionGraph::new(102);
    graph.add_node("pkg:root".to_string());
    graph.add_node("pkg:dep-a".to_string());
    graph.add_node("pkg:dep-b".to_string());

    graph
        .add_edge(
            &"pkg:root".to_string(),
            ContagionEdge::new("pkg:dep-a".to_string(), 0.75, EdgeKind::DependencyImport)
                .map_err(|e| format!("edge rejected: {e:?}"))?,
        )
        .map_err(|e| format!("add edge dep-a failed: {e:?}"))?;
    graph
        .add_edge(
            &"pkg:root".to_string(),
            ContagionEdge::new("pkg:dep-b".to_string(), 0.25, EdgeKind::MaintainerOverlap)
                .map_err(|e| format!("edge rejected: {e:?}"))?,
        )
        .map_err(|e| format!("add edge dep-b failed: {e:?}"))?;

    let neighbors = graph.neighbors(&"pkg:root".to_string());
    assert_eq!(neighbors.len(), 2);
    assert_eq!(neighbors[0].target, "pkg:dep-a");
    assert_eq!(neighbors[0].weight, 0.75);
    assert_eq!(neighbors[0].edge_kind, EdgeKind::DependencyImport);
    assert_eq!(neighbors[1].target, "pkg:dep-b");
    assert_eq!(neighbors[1].weight, 0.25);
    assert_eq!(neighbors[1].edge_kind, EdgeKind::MaintainerOverlap);
    Ok(())
}

#[test]
fn simulator_uses_interned_graph_edges_without_changing_trace_strings() -> TestResult {
    let mut graph = ContagionGraph::new(104);
    graph.add_node("pkg:root".to_string());
    graph.add_node("pkg:dep-a".to_string());
    graph
        .add_edge(
            &"pkg:root".to_string(),
            ContagionEdge::new("pkg:dep-a".to_string(), 1.0, EdgeKind::DependencyImport)
                .map_err(|e| format!("edge rejected: {e:?}"))?,
        )
        .map_err(|e| format!("add edge failed: {e:?}"))?;

    let config = SimulatorConfig {
        max_steps: 4,
        infection_threshold: 1.0,
        decay_factor: 0.0,
        seed: 0xD615,
    };
    let trace = simulate(&graph, &["pkg:root".to_string()], &config)
        .map_err(|e| format!("simulation failed: {e:?}"))?;
    let last = trace
        .states_per_step
        .last()
        .ok_or_else(|| "simulation returned no states".to_string())?;

    assert_eq!(trace.termination_reason, TerminationReason::FullSpread);
    assert_eq!(trace.terminated_at, 1);
    assert_eq!(last.infected_count(), 2);
    assert!(last.infected().contains("pkg:root"));
    assert!(last.infected().contains("pkg:dep-a"));
    assert_eq!(
        graph.neighbors(&"pkg:root".to_string())[0].target,
        "pkg:dep-a"
    );
    Ok(())
}

#[test]
fn simulator_step_fast_path_uses_cached_in_edges_after_edge_mutation() -> TestResult {
    let mut graph = ContagionGraph::new(105);
    graph.add_node("pkg:root".to_string());
    graph.add_node("pkg:middle".to_string());
    graph.add_node("pkg:leaf".to_string());
    graph
        .add_edge(
            &"pkg:root".to_string(),
            ContagionEdge::new("pkg:middle".to_string(), 1.0, EdgeKind::DependencyImport)
                .map_err(|e| format!("edge rejected: {e:?}"))?,
        )
        .map_err(|e| format!("add edge middle failed: {e:?}"))?;
    let config = SimulatorConfig {
        max_steps: 3,
        infection_threshold: 1.0,
        decay_factor: 0.0,
        seed: 0xD617,
    };

    let initial = InfectionState::new(&["pkg:root".to_string()]);
    let after_first =
        step(&graph, &initial, &config).map_err(|e| format!("first cached step failed: {e:?}"))?;
    assert!(after_first.infected().contains("pkg:middle"));
    assert!(!after_first.infected().contains("pkg:leaf"));

    graph
        .add_edge(
            &"pkg:middle".to_string(),
            ContagionEdge::new("pkg:leaf".to_string(), 1.0, EdgeKind::DependencyImport)
                .map_err(|e| format!("edge rejected: {e:?}"))?,
        )
        .map_err(|e| format!("add edge leaf failed: {e:?}"))?;

    let after_mutation = step(&graph, &after_first, &config)
        .map_err(|e| format!("second cached step failed: {e:?}"))?;
    assert!(after_mutation.infected().contains("pkg:leaf"));
    assert_eq!(after_mutation.infected_count(), 3);
    Ok(())
}

#[test]
fn graph_validate_rejects_dangling_edge() -> TestResult {
    let mut graph = ContagionGraph::new(103);
    graph.add_node("pkg:root".to_string());

    let dangling = ContagionEdge::new("pkg:ghost".to_string(), 0.5, EdgeKind::NamespaceShadow)
        .map_err(|e| format!("edge rejected: {e:?}"))?;

    assert_eq!(
        graph
            .add_edge(&"pkg:root".to_string(), dangling)
            .unwrap_err(),
        GraphError::UnknownTarget("pkg:ghost".to_string())
    );
    graph
        .validate()
        .map_err(|e| format!("validate failed: {e:?}"))
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
fn prop_simulation_trace_deterministic_under_interning() {
    let campaigns = ["xz_style", "dependency_confusion", "typosquat"];
    let goldens = campaigns
        .iter()
        .map(|campaign| {
            (
                *campaign,
                golden_trace(campaign).expect("golden trace loads"),
            )
        })
        .collect::<Vec<_>>();
    let mut runner = TestRunner::new(ProptestConfig {
        cases: 1000,
        ..ProptestConfig::default()
    });

    runner
        .run(&any::<u64>(), |seed| {
            let len = u64::try_from(goldens.len()).expect("campaign count fits u64");
            let offset = usize::try_from(seed % len).expect("modulo campaign count fits usize");
            for (campaign, golden) in goldens.iter().cycle().skip(offset).take(goldens.len()) {
                let first = campaign_trace(campaign).map_err(TestCaseError::fail)?;
                let second = campaign_trace(campaign).map_err(TestCaseError::fail)?;

                prop_assert_eq!(&first, &second);
                let projected = trace_projection(campaign, &first);
                prop_assert_eq!(&projected, golden);
            }
            Ok(())
        })
        .expect("DGIS campaign traces remain deterministic under interning");
}

fn fuzz_edge_kind(tag: u8) -> EdgeKind {
    match tag % 4 {
        0 => EdgeKind::DependencyImport,
        1 => EdgeKind::MaintainerOverlap,
        2 => EdgeKind::OrgOverlap,
        _ => EdgeKind::NamespaceShadow,
    }
}

#[test]
fn fuzz_structured_graphs_preserve_simulator_step_invariants() {
    let mut runner = TestRunner::new(ProptestConfig {
        cases: 256,
        ..ProptestConfig::default()
    });
    let strategy = (
        1usize..=12,
        prop::collection::vec((0u8..12, 0u8..12, 0u16..=1000, any::<u8>()), 0..64),
        any::<u16>(),
        any::<u16>(),
        1u32..=32,
        any::<u64>(),
        any::<u16>(),
    );

    runner
        .run(
            &strategy,
            |(
                node_count,
                edges,
                threshold_raw,
                decay_raw,
                max_steps,
                graph_seed,
                infected_mask,
            )| {
                let nodes: Vec<NodeId> = (0..node_count)
                    .map(|index| format!("pkg:fuzz-{index}"))
                    .collect();
                let graph_nodes = nodes
                    .iter()
                    .cloned()
                    .collect::<std::collections::BTreeSet<_>>();
                let mut graph = ContagionGraph::new(graph_seed);
                for node in &nodes {
                    graph.add_node(node.clone());
                }
                for (src_raw, dst_raw, weight_raw, kind_raw) in edges {
                    let src = usize::from(src_raw) % node_count;
                    let dst = usize::from(dst_raw) % node_count;
                    let edge = ContagionEdge::new(
                        nodes[dst].clone(),
                        f64::from(weight_raw) / 1000.0,
                        fuzz_edge_kind(kind_raw),
                    )
                    .map_err(|err| {
                        TestCaseError::fail(format!("edge construction failed: {err:?}"))
                    })?;
                    graph
                        .add_edge(&nodes[src], edge)
                        .map_err(|err| TestCaseError::fail(format!("edge rejected: {err:?}")))?;
                }
                prop_assert!(graph.validate().is_ok());

                let mut initial = Vec::new();
                for (index, node) in nodes.iter().enumerate() {
                    if ((infected_mask >> index) & 1) == 1 {
                        initial.push(node.clone());
                    }
                }
                if initial.is_empty() {
                    initial.push(nodes[usize::from(infected_mask) % node_count].clone());
                }
                let config = SimulatorConfig {
                    max_steps,
                    infection_threshold: f64::from(threshold_raw % 1001) / 1000.0,
                    decay_factor: f64::from(decay_raw % 1001) / 1000.0,
                    seed: graph_seed ^ 0xD617_1549,
                };

                let trace = simulate(&graph, &initial, &config)
                    .map_err(|err| TestCaseError::fail(format!("simulate failed: {err:?}")))?;
                let replay = simulate(&graph, &initial, &config)
                    .map_err(|err| TestCaseError::fail(format!("replay failed: {err:?}")))?;
                prop_assert_eq!(&trace, &replay);
                prop_assert_eq!(
                    trace.states_per_step.len(),
                    (trace.terminated_at as usize).saturating_add(1)
                );
                prop_assert!(trace.terminated_at <= config.max_steps);

                let mut previous_infected = 0usize;
                for state in &trace.states_per_step {
                    prop_assert!(state.step() <= config.max_steps);
                    prop_assert!(state.infected().is_subset(&graph_nodes));
                    prop_assert!(state.infected_count() >= previous_infected);
                    previous_infected = state.infected_count();
                    for (node, exposure) in state.exposure_level() {
                        prop_assert!(graph_nodes.contains(node));
                        prop_assert!(exposure.is_finite());
                        prop_assert!(*exposure >= 0.0);
                    }
                }
                Ok(())
            },
        )
        .expect("structured DGIS simulator fuzz cases preserve step invariants");
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
fn test_profile_with_null_byte_node_id_rejected_at_graph_boundary() {
    let bad_spec = ProfileGraphSpec {
        nodes: vec!["pkg\0shadow".to_string()],
        edges: Vec::new(),
        seed: 0,
    };
    let err = build_graph_from_spec(&bad_spec).expect_err("NUL node id must reject");
    assert_eq!(
        err,
        ProfileError::GraphFailure(GraphError::InvalidNodeId("pkg\0shadow".to_string()))
    );

    let bad_edge_spec = ProfileGraphSpec {
        nodes: vec!["a".to_string(), "b".to_string()],
        edges: vec![ProfileEdgeSpec {
            from: "a".to_string(),
            to: "b\0shadow".to_string(),
            weight: 0.5,
            edge_kind: WireEdgeKind::DependencyImport,
        }],
        seed: 0,
    };
    let err = build_graph_from_spec(&bad_edge_spec).expect_err("NUL edge id must reject");
    assert_eq!(
        err,
        ProfileError::GraphFailure(GraphError::InvalidNodeId("b\0shadow".to_string()))
    );
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

#[test]
fn overlong_node_id_rejection_does_not_clone_payload() -> TestResult {
    let overlong = "x".repeat(600);
    match validate_node_id(&overlong) {
        Err(GraphError::InvalidNodeId(rejected)) => {
            assert!(
                rejected.len() < overlong.len(),
                "overlong rejection must not clone attacker-controlled payload"
            );
            assert!(
                rejected.contains("exceeds"),
                "bounded rejection should explain the length cap: {rejected}"
            );
        }
        other => {
            return Err(format!(
                "expected overlong InvalidNodeId rejection, got {other:?}"
            ));
        }
    }

    match ContagionEdge::new(overlong.clone(), 0.5, EdgeKind::DependencyImport) {
        Err(GraphError::InvalidNodeId(rejected)) => assert!(
            rejected.len() < overlong.len(),
            "edge construction must not clone overlong target id"
        ),
        other => {
            return Err(format!(
                "expected overlong target rejection from ContagionEdge::new, got {other:?}"
            ));
        }
    }

    let mut graph = ContagionGraph::new(31);
    graph.add_node(overlong);
    assert!(
        graph.nodes().is_empty(),
        "overlong node id must not enter graph"
    );
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
