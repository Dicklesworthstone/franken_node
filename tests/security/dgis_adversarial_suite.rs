//! DGIS adversarial validation suite.
//!
//! This is the concrete integration artifact for bd-cclm.1. It exercises the
//! existing DGIS contagion graph and simulator APIs against deterministic
//! adversarial campaign fixtures: graph poisoning, edge obfuscation,
//! fake-low-risk pivots, and delayed activation.

use std::collections::BTreeMap;

use frankenengine_node::dgis::contagion_graph::{
    ContagionEdge, ContagionGraph, EdgeKind, GraphError, NodeId,
};
use frankenengine_node::dgis::contagion_simulator::{SimulatorConfig, TerminationReason, simulate};

fn id(value: &str) -> NodeId {
    value.to_string()
}

fn add_node(graph: &mut ContagionGraph, value: &str) {
    graph.add_node(id(value));
}

fn add_edge(graph: &mut ContagionGraph, from: &str, to: &str, weight: f64, kind: EdgeKind) {
    let from_id = id(from);
    let edge = ContagionEdge::new(id(to), weight, kind)
        .expect("adversarial fixture edge weights are finite and non-negative");
    graph
        .add_edge(&from_id, edge)
        .expect("adversarial fixture endpoints are declared before edges");
}

#[derive(Debug, Clone)]
struct CampaignFixture {
    name: &'static str,
    attack_class: &'static str,
    graph: ContagionGraph,
    initial_infected: Vec<NodeId>,
    config: SimulatorConfig,
    expected_final_infected: usize,
    expected_reason: TerminationReason,
    max_terminated_at: u32,
    failure_class: &'static str,
    remediation_hint: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CampaignVerdict {
    attack_class: &'static str,
    final_infected: usize,
    terminated_at: u32,
    reason: TerminationReason,
    failure_class: &'static str,
    remediation_hint: &'static str,
    passed: bool,
}

fn edge_obfuscation_fixture() -> CampaignFixture {
    let mut graph = ContagionGraph::new(0xD615_E006);
    for node in ["pkg:legit-core", "pkg:leglt-core", "pkg:payload"] {
        add_node(&mut graph, node);
    }
    add_edge(
        &mut graph,
        "pkg:legit-core",
        "pkg:leglt-core",
        0.49,
        EdgeKind::NamespaceShadow,
    );
    add_edge(
        &mut graph,
        "pkg:leglt-core",
        "pkg:payload",
        1.0,
        EdgeKind::DependencyImport,
    );
    CampaignFixture {
        name: "edge_obfuscation_shadow_package",
        attack_class: "edge_obfuscation",
        graph,
        initial_infected: vec![id("pkg:legit-core")],
        config: SimulatorConfig {
            max_steps: 8,
            infection_threshold: 0.5,
            decay_factor: 0.0,
            seed: 0xE006,
        },
        expected_final_infected: 1,
        expected_reason: TerminationReason::Converged,
        max_terminated_at: 3,
        failure_class: "DGIS-ADV-EDGE-OBFUSCATION-BOUNDED",
        remediation_hint: "quarantine namespace-shadow edges below activation threshold",
    }
}

fn fake_low_risk_pivot_fixture() -> CampaignFixture {
    let mut graph = ContagionGraph::new(0xFA1E_10);
    for node in [
        "pkg:seed-a",
        "pkg:seed-b",
        "pkg:quiet-pivot",
        "pkg:critical-service",
    ] {
        add_node(&mut graph, node);
    }
    add_edge(
        &mut graph,
        "pkg:seed-a",
        "pkg:quiet-pivot",
        0.30,
        EdgeKind::MaintainerOverlap,
    );
    add_edge(
        &mut graph,
        "pkg:seed-b",
        "pkg:quiet-pivot",
        0.30,
        EdgeKind::OrgOverlap,
    );
    add_edge(
        &mut graph,
        "pkg:quiet-pivot",
        "pkg:critical-service",
        0.20,
        EdgeKind::DependencyImport,
    );
    CampaignFixture {
        name: "fake_low_risk_pivot_aggregate_exposure",
        attack_class: "fake_low_risk_pivot",
        graph,
        initial_infected: vec![id("pkg:seed-a"), id("pkg:seed-b")],
        config: SimulatorConfig {
            max_steps: 8,
            infection_threshold: 0.5,
            decay_factor: 0.0,
            seed: 0xFA1E,
        },
        expected_final_infected: 3,
        expected_reason: TerminationReason::Converged,
        max_terminated_at: 4,
        failure_class: "DGIS-ADV-FAKE-LOW-RISK-PIVOT-ESCALATED",
        remediation_hint: "aggregate weak independent edges before assigning low-risk status",
    }
}

fn delayed_activation_fixture() -> CampaignFixture {
    let mut graph = ContagionGraph::new(0xDE1A_7ED);
    for node in ["pkg:maintainer-shell", "pkg:dormant-payload"] {
        add_node(&mut graph, node);
    }
    add_edge(
        &mut graph,
        "pkg:maintainer-shell",
        "pkg:dormant-payload",
        0.25,
        EdgeKind::MaintainerOverlap,
    );
    CampaignFixture {
        name: "delayed_activation_accumulation",
        attack_class: "delayed_activation",
        graph,
        initial_infected: vec![id("pkg:maintainer-shell")],
        config: SimulatorConfig {
            max_steps: 8,
            infection_threshold: 0.75,
            decay_factor: 1.0,
            seed: 0xDE1A,
        },
        expected_final_infected: 2,
        expected_reason: TerminationReason::FullSpread,
        max_terminated_at: 3,
        failure_class: "DGIS-ADV-DELAYED-ACTIVATION-CAUGHT",
        remediation_hint: "retain exposure memory for dormant-to-active activation chains",
    }
}

fn all_campaign_fixtures() -> Vec<CampaignFixture> {
    vec![
        delayed_activation_fixture(),
        edge_obfuscation_fixture(),
        fake_low_risk_pivot_fixture(),
    ]
}

fn evaluate_campaign(fixture: &CampaignFixture) -> CampaignVerdict {
    let trace = simulate(&fixture.graph, &fixture.initial_infected, &fixture.config)
        .expect("deterministic adversarial fixture must simulate");
    let final_state = trace
        .states_per_step
        .last()
        .expect("simulation trace always retains the final state");

    for state in &trace.states_per_step {
        for exposure in state.exposure_level().values() {
            assert!(
                exposure.is_finite(),
                "{} produced non-finite exposure",
                fixture.name
            );
        }
    }

    let passed = final_state.infected_count() == fixture.expected_final_infected
        && trace.termination_reason == fixture.expected_reason
        && trace.terminated_at <= fixture.max_terminated_at;

    CampaignVerdict {
        attack_class: fixture.attack_class,
        final_infected: final_state.infected_count(),
        terminated_at: trace.terminated_at,
        reason: trace.termination_reason,
        failure_class: fixture.failure_class,
        remediation_hint: fixture.remediation_hint,
        passed,
    }
}

fn replay_all_campaigns() -> BTreeMap<&'static str, CampaignVerdict> {
    let mut verdicts = BTreeMap::new();
    for fixture in all_campaign_fixtures() {
        verdicts.insert(fixture.name, evaluate_campaign(&fixture));
    }
    verdicts
}

#[test]
fn graph_poisoning_rejects_non_finite_edge_weights() {
    let nan = ContagionEdge::new(id("pkg:target"), f64::NAN, EdgeKind::DependencyImport)
        .expect_err("NaN edge weight must be rejected before graph admission");
    assert_eq!(nan, GraphError::NonFiniteWeight);

    let inf = ContagionEdge::new(id("pkg:target"), f64::INFINITY, EdgeKind::OrgOverlap)
        .expect_err("infinite edge weight must be rejected before graph admission");
    assert_eq!(inf, GraphError::NonFiniteWeight);

    let mut graph = ContagionGraph::new(0x9015_0DED);
    add_node(&mut graph, "pkg:known");
    let dangling = ContagionEdge::new(id("pkg:ghost"), 0.5, EdgeKind::NamespaceShadow)
        .expect("finite edge with unknown endpoint constructs before graph validation");
    let err = graph
        .add_edge(&id("pkg:known"), dangling)
        .expect_err("dangling poisoned target must be rejected by graph admission");
    assert!(matches!(err, GraphError::UnknownTarget(target) if target == "pkg:ghost"));
}

#[test]
fn edge_obfuscation_shadow_edge_is_bounded() {
    let fixture = edge_obfuscation_fixture();
    let verdict = evaluate_campaign(&fixture);
    assert!(verdict.passed, "{verdict:?}");
    assert_eq!(verdict.final_infected, 1);
    assert_eq!(verdict.failure_class, "DGIS-ADV-EDGE-OBFUSCATION-BOUNDED");
}

#[test]
fn fake_low_risk_pivot_uses_aggregate_exposure() {
    let fixture = fake_low_risk_pivot_fixture();
    let verdict = evaluate_campaign(&fixture);
    assert!(verdict.passed, "{verdict:?}");
    assert_eq!(verdict.final_infected, 3);
    assert_eq!(
        verdict.failure_class,
        "DGIS-ADV-FAKE-LOW-RISK-PIVOT-ESCALATED"
    );
}

#[test]
fn delayed_activation_accumulation_is_caught() {
    let fixture = delayed_activation_fixture();
    let verdict = evaluate_campaign(&fixture);
    assert!(verdict.passed, "{verdict:?}");
    assert_eq!(verdict.final_infected, 2);
    assert_eq!(verdict.terminated_at, 3);
    assert_eq!(verdict.failure_class, "DGIS-ADV-DELAYED-ACTIVATION-CAUGHT");
}

#[test]
fn campaign_verdicts_are_deterministic_and_replayable() {
    let first = replay_all_campaigns();
    let second = replay_all_campaigns();
    assert_eq!(first, second);
    assert_eq!(
        first.keys().copied().collect::<Vec<_>>(),
        vec![
            "delayed_activation_accumulation",
            "edge_obfuscation_shadow_package",
            "fake_low_risk_pivot_aggregate_exposure",
        ]
    );
    assert!(first.values().all(|verdict| verdict.passed));
}
