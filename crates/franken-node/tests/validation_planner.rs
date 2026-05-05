use frankenengine_node::ops::validation_planner::{
    GateStrength, PlannedCommandKind, PlannerInput, VALIDATION_PLANNER_SCHEMA_VERSION,
    parse_registered_tests_from_manifest, plan_validation,
};
use serde::Deserialize;

fn registered_tests() -> Vec<frankenengine_node::ops::validation_planner::RegisteredTest> {
    parse_registered_tests_from_manifest(include_str!("../Cargo.toml"))
        .expect("crate Cargo.toml should parse")
}

fn plan_for(
    bead_id: &str,
    changed_paths: &[&str],
    labels: &[&str],
    acceptance: &str,
) -> frankenengine_node::ops::validation_planner::ValidationPlan {
    plan_validation(
        &PlannerInput::new(bead_id, changed_paths.iter().copied(), registered_tests())
            .with_labels(labels.iter().copied())
            .with_acceptance(acceptance),
    )
}

#[test]
fn cargo_manifest_parser_reads_registered_tests_and_features() {
    let tests = registered_tests();

    assert!(tests.iter().any(|test| test.name == "validation_planner"));
    let fleet = tests
        .iter()
        .find(|test| test.name == "fleet_cli_e2e")
        .expect("fleet_cli_e2e is registered");
    assert_eq!(fleet.path, "tests/fleet_cli_e2e.rs");
    assert_eq!(fleet.required_features, vec!["test-support"]);
}

#[test]
fn direct_test_file_maps_to_exact_rch_test_command() {
    let plan = plan_for(
        "bd-direct",
        &["crates/franken-node/tests/rch_adapter_classification.rs"],
        &["testing"],
        "Run the exact registered test target.",
    );

    let command = plan
        .command("cargo-test-rch_adapter_classification")
        .expect("direct test file should map to registered test");
    assert_eq!(command.kind, PlannedCommandKind::RchCargo);
    assert_eq!(command.strength, GateStrength::Required);
    assert!(command.shell.contains("rch exec -- env"));
    assert!(command.shell.contains("--test rch_adapter_classification"));
    assert!(command.shell.contains("RCH_REQUIRE_REMOTE=1"));
    assert!(!plan.source_only_allowed);
}

#[test]
fn feature_gated_integration_test_preserves_required_features() {
    let plan = plan_for(
        "bd-feature",
        &["crates/franken-node/tests/fleet_cli_e2e.rs"],
        &["testing"],
        "Run the focused feature-gated integration test.",
    );

    let command = plan
        .command("cargo-test-fleet_cli_e2e")
        .expect("feature gated test should be planned");
    assert!(command.shell.contains("--no-default-features"));
    assert!(command.shell.contains("--features test-support"));
    assert!(command.shell.contains("--test fleet_cli_e2e"));
}

#[test]
fn docs_and_validation_artifacts_use_source_only_contract_gates() {
    let plan = plan_for(
        "bd-docs",
        &[
            "docs/specs/validation_broker.md",
            "artifacts/validation_broker/validation_broker_fixtures.v1.json",
        ],
        &["validation"],
        "Contract artifact update.",
    );

    assert!(plan.source_only_allowed);
    assert!(plan.command("python-validation-broker-contract").is_some());
    assert!(plan.commands.iter().any(|command| {
        command.kind == PlannedCommandKind::SourceOnly && command.shell.contains("json.tool")
    }));
    assert_eq!(plan.rch_commands().count(), 0);
    assert!(plan.skipped_gates.iter().any(|gate| {
        gate.gate == "rch cargo test" && gate.reason.contains("docs or contract artifacts")
    }));
}

#[test]
fn cli_surface_keeps_first_recommendation_focused() {
    let plan = plan_for(
        "bd-cli",
        &["crates/franken-node/src/cli.rs"],
        &["cli"],
        "CLI output shape changed.",
    );

    let command = plan
        .command("cargo-test-cli_arg_validation")
        .expect("cli surface should run the CLI argument contract first");
    assert!(command.shell.contains("--test cli_arg_validation"));
    assert!(
        !plan
            .commands
            .iter()
            .any(|command| command.command_id == "cargo-test-fleet_cli_e2e")
    );
}

#[test]
fn sibling_dependency_drift_escalates_to_package_check() {
    let plan = plan_for(
        "bd-sibling",
        &["../franken_engine/crates/franken-engine/src/proof_artifact.rs"],
        &["validation"],
        "Sibling franken_engine compile drift blocked proof.",
    );

    let command = plan
        .command("cargo-check-sibling-drift")
        .expect("sibling drift should force package check");
    assert!(command.shell.contains("cargo +nightly-2026-02-19 check"));
    assert!(command.shell.contains("-p frankenengine-node --tests"));
    assert!(
        plan.escalation_conditions
            .iter()
            .any(|condition| condition.contains("sibling blocker bead"))
    );
}

#[derive(Debug, Deserialize)]
struct FixtureCatalog {
    schema_version: String,
    fixtures: Vec<Fixture>,
}

#[derive(Debug, Deserialize)]
struct Fixture {
    name: String,
    bead_id: String,
    changed_paths: Vec<String>,
    labels: Vec<String>,
    acceptance: String,
    expect_command_ids: Vec<String>,
    expect_shell_contains: Vec<String>,
    source_only_allowed: bool,
}

#[test]
fn checked_in_fixture_catalog_matches_planner_output() {
    let catalog: FixtureCatalog = serde_json::from_str(include_str!(
        "../../../artifacts/validation_broker/bd-7ik2n/validation_planner_fixtures.v1.json"
    ))
    .expect("planner fixture catalog parses");
    assert_eq!(catalog.schema_version, VALIDATION_PLANNER_SCHEMA_VERSION);

    let tests = registered_tests();
    for fixture in catalog.fixtures {
        let changed_paths = fixture.changed_paths.iter().map(String::as_str);
        let labels = fixture.labels.iter().map(String::as_str);
        let plan = plan_validation(
            &PlannerInput::new(&fixture.bead_id, changed_paths, tests.clone())
                .with_labels(labels)
                .with_acceptance(&fixture.acceptance),
        );

        assert_eq!(
            plan.source_only_allowed, fixture.source_only_allowed,
            "{} source_only_allowed",
            fixture.name
        );
        for command_id in &fixture.expect_command_ids {
            assert!(
                plan.command(command_id).is_some(),
                "{} expected command_id {command_id}",
                fixture.name
            );
        }
        let joined_shell = plan
            .commands
            .iter()
            .map(|command| command.shell.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        for expected in &fixture.expect_shell_contains {
            assert!(
                joined_shell.contains(expected),
                "{} expected shell to contain {expected}",
                fixture.name
            );
        }
    }
}
