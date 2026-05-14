use std::collections::BTreeSet;

use frankenengine_node::security::dgis::barrier_primitives::BarrierType;
use frankenengine_node::security::dgis::immunization_planner::{
    BarrierInventory, CriticalNodeInput, ImmunizationPlanner, ImmunizationPlannerConfig,
    ImmunizationPlannerError, IncrementalReplanRequest, PlanningInput, PolicyConstraints,
};
use frankenengine_node::security::dgis::update_copilot::TopologyRiskMetrics;

fn metrics(
    fan_out: f64,
    betweenness_centrality: f64,
    articulation_point: bool,
    trust_bottleneck_score: f64,
    transitive_dependency_count: u32,
    max_depth_in_graph: u32,
) -> TopologyRiskMetrics {
    TopologyRiskMetrics {
        fan_out,
        betweenness_centrality,
        articulation_point,
        trust_bottleneck_score,
        transitive_dependency_count,
        max_depth_in_graph,
    }
}

fn planner(target_cascade_loss: f64, max_total_overhead_ms: u32) -> ImmunizationPlanner {
    ImmunizationPlanner::new(ImmunizationPlannerConfig {
        target_cascade_loss,
        max_total_overhead_ms,
        max_barriers_per_plan: 4,
        max_plans: 4,
        max_candidate_search: 12,
    })
    .expect("test planner config must be valid")
}

#[test]
fn chooses_lowest_cost_feasible_chokepoint_plan() {
    let input = PlanningInput::new(vec![CriticalNodeInput::new(
        "pkg-critical",
        metrics(80.0, 0.91, true, 0.15, 12, 3),
        1.0,
    )]);

    let catalog = planner(0.30, 12)
        .plan_catalog(&input)
        .expect("critical articulation point should have a feasible firewall plan");

    let best = &catalog.plans[0];
    assert!(best.meets_target);
    assert_eq!(best.total_cost_units, 5);
    assert_eq!(best.planned_barriers.len(), 1);
    assert_eq!(
        best.planned_barriers[0].barrier.barrier_type,
        BarrierType::CompositionFirewall
    );
    assert_eq!(
        best.planned_barriers[0].rationale.mitigated_metric,
        "articulation_point_or_betweenness"
    );
}

#[test]
fn respects_policy_exclusions_and_uses_allowed_nodes() {
    let mut excluded_nodes = BTreeSet::new();
    excluded_nodes.insert("pkg-excluded".to_string());
    let input = PlanningInput {
        nodes: vec![
            CriticalNodeInput::new("pkg-excluded", metrics(120.0, 0.97, true, 0.95, 80, 6), 0.6),
            CriticalNodeInput::new("pkg-allowed", metrics(90.0, 0.90, true, 0.70, 40, 5), 1.0),
        ],
        constraints: PolicyConstraints { excluded_nodes },
        barrier_inventory: BarrierInventory::default(),
    };

    let catalog = planner(0.90, 12)
        .plan_catalog(&input)
        .expect("allowed node should satisfy the target without fencing excluded node");

    assert!(
        catalog
            .events
            .iter()
            .any(|event| event.node_id.as_deref() == Some("pkg-excluded"))
    );
    assert!(
        catalog.plans[0]
            .planned_barriers
            .iter()
            .all(|planned| planned.barrier.node_id != "pkg-excluded")
    );
}

#[test]
fn fails_closed_when_budget_prevents_required_reduction() {
    let input = PlanningInput::new(vec![CriticalNodeInput::new(
        "pkg-budgeted",
        metrics(75.0, 0.88, true, 0.82, 60, 5),
        1.0,
    )]);

    let err = planner(0.10, 1)
        .plan_catalog(&input)
        .expect_err("1ms overhead budget cannot apply any useful barrier");

    assert!(matches!(
        err,
        ImmunizationPlannerError::NoFeasiblePlan {
            max_overhead_ms: 1,
            ..
        }
    ));
}

#[test]
fn incremental_replan_scores_only_changed_nodes() {
    let input = PlanningInput::new(vec![
        CriticalNodeInput::new(
            "pkg-unchanged",
            metrics(100.0, 0.95, true, 0.20, 30, 4),
            1.0,
        ),
        CriticalNodeInput::new("pkg-changed", metrics(80.0, 0.90, true, 0.30, 40, 4), 1.0),
    ]);
    let mut changed_nodes = BTreeSet::new();
    changed_nodes.insert("pkg-changed".to_string());

    let catalog = planner(0.30, 12)
        .plan_incremental(
            &input,
            IncrementalReplanRequest {
                changed_nodes,
                reason: "new dependency edge reached pkg-changed".to_string(),
            },
        )
        .expect("changed node has a feasible incremental plan");

    let incremental = catalog
        .incremental
        .as_ref()
        .expect("catalog should record incremental scope");
    assert_eq!(incremental.scoped_node_count, 1);
    assert_eq!(incremental.skipped_node_count, 1);
    assert!(
        catalog.plans[0]
            .planned_barriers
            .iter()
            .all(|planned| planned.barrier.node_id == "pkg-changed")
    );
}
