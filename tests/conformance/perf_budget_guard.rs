//! Conformance tests for bd-1xwz: Performance budget guard.
//!
//! Validates that the overhead gate correctly evaluates hot-path measurements
//! against budget policy, emits correct events, and enforces invariants.

use frankenengine_node::connector::perf_budget_guard::{
    event_codes, BudgetPolicy, GateDecision, HotPath, HotPathBudget, MeasurementResult,
    OverheadGate, INV_PBG_BUDGET, INV_PBG_COLD_START, INV_PBG_FLAMEGRAPH, INV_PBG_GATE,
};

fn make_budget(hp: HotPath) -> HotPathBudget {
    BudgetPolicy::default_policy()
        .budget_for(hp)
        .cloned()
        .unwrap()
}

fn within_budget(hp: HotPath) -> MeasurementResult {
    let budget = make_budget(hp);
    MeasurementResult::from_measurements(
        hp,
        100.0, 110.0, 120.0,
        105.0, 118.0, 130.0,
        15.0,
        &budget,
        Some("flamegraph.svg".into()),
    )
}

fn over_budget(hp: HotPath) -> MeasurementResult {
    let budget = make_budget(hp);
    MeasurementResult::from_measurements(
        hp,
        100.0, 100.0, 100.0,
        200.0, 200.0, 200.0,
        100.0,
        &budget,
        Some("flamegraph.svg".into()),
    )
}

// ── Per-hot-path evaluation ──────────────────────────────────────

#[test]
fn test_lifecycle_transition_within_budget() {
    let mut gate = OverheadGate::with_default_policy();
    let d = gate.evaluate(within_budget(HotPath::LifecycleTransition));
    assert!(d.is_pass());
}

#[test]
fn test_health_gate_evaluation_within_budget() {
    let mut gate = OverheadGate::with_default_policy();
    let d = gate.evaluate(within_budget(HotPath::HealthGateEvaluation));
    assert!(d.is_pass());
}

#[test]
fn test_rollout_state_change_within_budget() {
    let mut gate = OverheadGate::with_default_policy();
    let d = gate.evaluate(within_budget(HotPath::RolloutStateChange));
    assert!(d.is_pass());
}

#[test]
fn test_fencing_token_op_within_budget() {
    let mut gate = OverheadGate::with_default_policy();
    let d = gate.evaluate(within_budget(HotPath::FencingTokenOp));
    assert!(d.is_pass());
}

// ── Over budget blocks gate ──────────────────────────────────────

#[test]
fn test_over_budget_fails_gate() {
    let mut gate = OverheadGate::with_default_policy();
    let d = gate.evaluate(over_budget(HotPath::HealthGateEvaluation));
    assert!(d.is_fail());
    assert!(!gate.gate_pass());
}

#[test]
fn test_over_budget_has_violations() {
    let mut gate = OverheadGate::with_default_policy();
    let d = gate.evaluate(over_budget(HotPath::HealthGateEvaluation));
    if let GateDecision::Fail { violations } = d {
        assert!(!violations.is_empty());
    } else {
        panic!("Expected Fail");
    }
}

// ── Cold-start separate measurement ──────────────────────────────

#[test]
fn test_cold_start_over_budget_fails() {
    let budget = HotPathBudget {
        hot_path: HotPath::FencingTokenOp,
        p95_overhead_pct: 100.0,
        p99_overhead_pct: 100.0,
        cold_start_ms: 5.0,
    };
    let r = MeasurementResult::from_measurements(
        HotPath::FencingTokenOp,
        100.0, 100.0, 100.0,
        100.0, 100.0, 100.0,
        10.0, // cold-start over budget
        &budget,
        None,
    );
    assert!(!r.within_budget);
}

// ── Batch evaluation ─────────────────────────────────────────────

#[test]
fn test_batch_all_hot_paths_within() {
    let mut gate = OverheadGate::with_default_policy();
    let results: Vec<_> = HotPath::all().iter().map(|hp| within_budget(*hp)).collect();
    let decisions = gate.evaluate_batch(results);
    assert_eq!(decisions.len(), 4);
    assert!(decisions.iter().all(|d| d.is_pass()));
    assert!(gate.gate_pass());
}

#[test]
fn test_batch_mixed_results() {
    let mut gate = OverheadGate::with_default_policy();
    let results = vec![
        within_budget(HotPath::LifecycleTransition),
        over_budget(HotPath::FencingTokenOp),
    ];
    let decisions = gate.evaluate_batch(results);
    assert!(decisions[0].is_pass());
    assert!(decisions[1].is_fail());
    assert!(!gate.gate_pass());
}

// ── Event codes ──────────────────────────────────────────────────

#[test]
fn test_event_codes_emitted() {
    let mut gate = OverheadGate::with_default_policy();
    gate.evaluate(within_budget(HotPath::HealthGateEvaluation));
    let events = gate.events();
    let codes: Vec<&str> = events.iter().map(|e| e.code.as_str()).collect();
    assert!(codes.contains(&event_codes::PRF_001_BENCHMARK_STARTED));
    assert!(codes.contains(&event_codes::PRF_002_WITHIN_BUDGET));
    assert!(codes.contains(&event_codes::PRF_005_COLD_START));
}

#[test]
fn test_over_budget_emits_prf003() {
    let mut gate = OverheadGate::with_default_policy();
    gate.evaluate(over_budget(HotPath::HealthGateEvaluation));
    let has_prf003 = gate.events().iter().any(|e| e.code == event_codes::PRF_003_OVER_BUDGET);
    assert!(has_prf003);
}

#[test]
fn test_flamegraph_emits_prf004() {
    let mut gate = OverheadGate::with_default_policy();
    gate.evaluate(within_budget(HotPath::HealthGateEvaluation));
    let has_prf004 = gate.events().iter().any(|e| e.code == event_codes::PRF_004_FLAMEGRAPH_CAPTURED);
    assert!(has_prf004);
}

// ── Invariants ───────────────────────────────────────────────────

#[test]
fn test_invariant_budget_machine_readable() {
    // INV-PBG-BUDGET: policy is serializable to JSON (machine-readable)
    assert!(!INV_PBG_BUDGET.is_empty());
    let policy = BudgetPolicy::default_policy();
    let json = serde_json::to_string(&policy).unwrap();
    assert!(json.contains("p95_overhead_pct"));
}

#[test]
fn test_invariant_gate_blocks_violations() {
    // INV-PBG-GATE: over-budget blocks gate
    assert!(!INV_PBG_GATE.is_empty());
    let mut gate = OverheadGate::with_default_policy();
    gate.evaluate(over_budget(HotPath::HealthGateEvaluation));
    assert!(!gate.gate_pass());
}

#[test]
fn test_invariant_flamegraph_tracked() {
    // INV-PBG-FLAMEGRAPH: flamegraph path preserved in results
    assert!(!INV_PBG_FLAMEGRAPH.is_empty());
    let mut gate = OverheadGate::with_default_policy();
    gate.evaluate(within_budget(HotPath::HealthGateEvaluation));
    assert!(gate.results()[0].flamegraph_path.is_some());
}

#[test]
fn test_invariant_cold_start_separate() {
    // INV-PBG-COLD-START: cold_start_ms is a distinct field
    assert!(!INV_PBG_COLD_START.is_empty());
    let r = within_budget(HotPath::HealthGateEvaluation);
    assert!(r.cold_start_ms > 0.0);
}

// ── Summary and report ───────────────────────────────────────────

#[test]
fn test_summary_after_batch() {
    let mut gate = OverheadGate::with_default_policy();
    for hp in HotPath::all() {
        gate.evaluate(within_budget(*hp));
    }
    let s = gate.summary();
    assert_eq!(s.total, 4);
    assert_eq!(s.within_budget, 4);
    assert!(s.gate_pass());
}

#[test]
fn test_csv_report_format() {
    let mut gate = OverheadGate::with_default_policy();
    gate.evaluate(within_budget(HotPath::HealthGateEvaluation));
    let csv = gate.to_csv();
    assert!(csv.starts_with("hot_path,"));
    assert!(csv.contains("health_gate_evaluation"));
}

#[test]
fn test_json_report_structure() {
    let mut gate = OverheadGate::with_default_policy();
    for hp in HotPath::all() {
        gate.evaluate(within_budget(*hp));
    }
    let report = gate.to_report();
    assert_eq!(report["bead_id"], "bd-1xwz");
    assert!(report["gate_pass"].as_bool().unwrap());
    assert_eq!(report["results"].as_array().unwrap().len(), 4);
}

// ── Determinism ──────────────────────────────────────────────────

#[test]
fn test_deterministic_overhead_calculation() {
    let budget = make_budget(HotPath::HealthGateEvaluation);
    let results: Vec<_> = (0..10)
        .map(|_| {
            MeasurementResult::from_measurements(
                HotPath::HealthGateEvaluation,
                100.0, 100.0, 100.0,
                110.0, 110.0, 110.0,
                10.0,
                &budget,
                None,
            )
        })
        .collect();
    let first = &results[0];
    for r in &results[1..] {
        assert_eq!(r.overhead_p95_pct, first.overhead_p95_pct);
        assert_eq!(r.within_budget, first.within_budget);
    }
}
