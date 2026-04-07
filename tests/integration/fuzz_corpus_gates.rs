//! Integration tests for bd-29ct: Adversarial fuzz corpus gates.

use frankenengine_node::connector::fuzz_corpus::*;
use std::path::PathBuf;

fn populated_fixture_adapter() -> DeterministicFuzzTestAdapter {
    let mut c = DeterministicFuzzTestAdapter::new(3);
    c.add_target(DeterministicFuzzTarget {
        name: "parser_fuzz".into(),
        category: FuzzCategory::ParserInput,
        description: "parser input fuzzing".into(),
    });
    c.add_target(DeterministicFuzzTarget {
        name: "handshake_fuzz".into(),
        category: FuzzCategory::HandshakeReplay,
        description: "handshake replay/splice".into(),
    });
    c.add_target(DeterministicFuzzTarget {
        name: "token_fuzz".into(),
        category: FuzzCategory::TokenValidation,
        description: "token validation".into(),
    });
    c.add_target(DeterministicFuzzTarget {
        name: "dos_fuzz".into(),
        category: FuzzCategory::DecodeDos,
        description: "decode DoS".into(),
    });

    for target in ["parser_fuzz", "handshake_fuzz", "token_fuzz", "dos_fuzz"] {
        for i in 0..3 {
            c.add_seed(DeterministicFuzzSeed {
                target: target.to_string(),
                input_data: format!("input_{i}"),
                expected: DeterministicSeedOutcome::Handled,
            })
            .unwrap();
        }
    }
    c
}

#[test]
fn inv_fcg_targets() {
    let c = populated_fixture_adapter();
    assert_eq!(c.target_count(), 4);
    c.validate().unwrap();
}

#[test]
fn inv_fcg_corpus() {
    let c = populated_fixture_adapter();
    for target in ["parser_fuzz", "handshake_fuzz", "token_fuzz", "dos_fuzz"] {
        assert!(
            c.seed_count(target) >= 3,
            "target {target} needs >= 3 seeds"
        );
    }
}

#[test]
fn inv_fcg_triage() {
    let mut c = populated_fixture_adapter();
    c.add_seed(DeterministicFuzzSeed {
        target: "parser_fuzz".into(),
        input_data: "crash_trigger".into(),
        expected: DeterministicSeedOutcome::Rejected,
    })
    .unwrap();
    let verdict = c.run_fixture_gate();
    assert_eq!(verdict.verdict, "FAIL");
    assert!(!verdict.triaged_crashes.is_empty());
    assert!(
        verdict.triaged_crashes[0]
            .reproducer
            .contains("parser_fuzz")
    );
}

#[test]
fn inv_fcg_gate() {
    let c = populated_fixture_adapter();
    let verdict = c.run_fixture_gate();
    assert_eq!(verdict.verdict, "PASS");
    assert!(verdict.triaged_crashes.is_empty());
}

#[test]
fn fixture_gate_reports_explicit_test_adapter_marker() {
    let c = populated_fixture_adapter();
    let verdict = c.run_fixture_gate();
    assert_eq!(
        verdict.adapter_kind,
        "deterministic_fixture_test_adapter".to_string()
    );
    assert_eq!(verdict.execution_mode, "synthetic_test_fixture".to_string());
    assert!(verdict.runner_detail.contains("fixture_marker"));
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repo root")
}

#[test]
fn truthful_gate_executes_checked_in_targets() {
    let report = run_truthful_fuzz_gate(repo_root());
    assert_eq!(report.verdict, "PASS");
    assert_eq!(report.targets_total, 5);
    assert_eq!(report.targets_executed, 5);
    assert_eq!(report.seeds_total, report.seeds_executed);
    assert!(report.triaged_failures.is_empty());
    assert!(report.targets.iter().all(|target| target.outcome == "pass"));
}

#[test]
fn truthful_gate_reports_explicit_coverage_and_relative_artifacts() {
    let report = run_truthful_fuzz_gate(repo_root());
    assert!(report.coverage_summary.iter().all(|coverage| {
        coverage.coverage_status == "measured"
            && coverage.coverage_pct.unwrap_or(0.0) > 0.0
            && coverage.coverage_scope.starts_with("category:")
    }));
    assert!(
        report
            .artifact_refs
            .iter()
            .any(|artifact| artifact.artifact_kind == "coverage_report")
    );
    assert!(
        report
            .artifact_refs
            .iter()
            .all(|artifact| !artifact.artifact_location.starts_with('/'))
    );
}
