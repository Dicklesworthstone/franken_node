use frankenengine_node::ops::validation_planner::{
    GateStrength, PlannedCommandKind, PlannerInput, SIBLING_DRIFT_PREFLIGHT_SCHEMA_VERSION,
    SiblingBlockerRef, SiblingBlockerStatus, SiblingDriftDecision, SiblingDriftDiagnosticSeverity,
    SiblingDriftPreflightInput, SiblingRepoDriftInput, VALIDATION_PLANNER_SCHEMA_VERSION,
    ValidationPlannerError, build_sibling_drift_preflight, parse_registered_tests_from_manifest,
    plan_validation, sibling_drift_reason_codes,
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

    let cache_lookup = plan
        .command("cache-lookup")
        .expect("Rust validation plan should check proof cache first");
    assert_eq!(cache_lookup.kind, PlannedCommandKind::ProofCacheLookup);
    assert!(cache_lookup.shell.contains("validation-proof-cache lookup"));
    let coalescer_lookup = plan
        .command("cache-proof-coalescer-lookup")
        .expect("Rust validation plan should check proof coalescer before RCH");
    assert_eq!(
        coalescer_lookup.kind,
        PlannedCommandKind::ProofCoalescerLookup
    );
    assert!(
        coalescer_lookup
            .shell
            .contains("validation-proof-coalescer lookup")
    );

    let command = plan
        .command("cargo-test-rch_adapter_classification")
        .expect("direct test file should map to registered test");
    assert_eq!(command.kind, PlannedCommandKind::RchCargo);
    assert_eq!(command.strength, GateStrength::Required);
    assert!(command.shell.contains("rch exec -- env"));
    assert!(command.shell.contains("--test rch_adapter_classification"));
    assert!(command.shell.contains("RCH_REQUIRE_REMOTE=1"));
    let cache_index = plan
        .commands
        .iter()
        .position(|command| command.command_id == "cache-lookup")
        .expect("cache lookup command index");
    let cargo_index = plan
        .commands
        .iter()
        .position(|command| command.command_id == "cargo-test-rch_adapter_classification")
        .expect("cargo command index");
    let coalescer_index = plan
        .commands
        .iter()
        .position(|command| command.command_id == "cache-proof-coalescer-lookup")
        .expect("coalescer lookup command index");
    assert!(cache_index < cargo_index);
    assert!(cache_index < coalescer_index);
    assert!(coalescer_index < cargo_index);
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

fn healthy_franken_engine() -> SiblingRepoDriftInput {
    SiblingRepoDriftInput::new(
        "franken_engine",
        "/data/projects/franken_engine",
        "/data/projects/franken_engine",
        "/data/projects/franken_engine/Cargo.toml",
    )
    .with_head_sha("0123456789abcdef")
    .with_dependency_paths(["/data/projects/franken_engine"])
    .with_required_features(["asupersync-integration"])
    .with_available_features(["asupersync-integration", "legacy_lib_tests_bd_2j7uk"])
}

#[test]
fn sibling_drift_preflight_allows_healthy_side_by_side_checkout() {
    let report = build_sibling_drift_preflight(SiblingDriftPreflightInput::new(
        "/data/projects/franken_node",
        [healthy_franken_engine()],
    ))
    .expect("healthy preflight should build");

    assert_eq!(
        report.schema_version,
        SIBLING_DRIFT_PREFLIGHT_SCHEMA_VERSION
    );
    assert_eq!(report.decision, SiblingDriftDecision::AllowBroadValidation);
    assert_eq!(
        report.decision_reason_code,
        sibling_drift_reason_codes::HEALTHY
    );
    assert!(report.diagnostics.is_empty());
    assert_eq!(report.siblings[0].repo_id, "franken_engine");
    assert_eq!(
        report.siblings[0].head_sha.as_deref(),
        Some("0123456789abcdef")
    );
}

#[test]
fn sibling_drift_preflight_blocks_missing_checkout() {
    let report = build_sibling_drift_preflight(SiblingDriftPreflightInput::new(
        "/data/projects/franken_node",
        [healthy_franken_engine().missing()],
    ))
    .expect("missing checkout report should build");

    assert_eq!(report.decision, SiblingDriftDecision::BlockBroadValidation);
    assert!(report.blocks_broad_validation());
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.reason_code == sibling_drift_reason_codes::MISSING_CHECKOUT
            && diagnostic.severity == SiblingDriftDiagnosticSeverity::Blocker
    }));
}

#[test]
fn sibling_drift_preflight_blocks_dirty_sibling_source() {
    let report = build_sibling_drift_preflight(SiblingDriftPreflightInput::new(
        "/data/projects/franken_node",
        [healthy_franken_engine().with_dirty_paths([
            "/data/projects/franken_engine/crates/franken-engine/src/lib.rs",
            "/data/projects/franken_engine/Cargo.toml",
        ])],
    ))
    .expect("dirty sibling report should build");

    assert_eq!(report.decision, SiblingDriftDecision::BlockBroadValidation);
    assert_eq!(
        report.diagnostics[0].reason_code,
        sibling_drift_reason_codes::DIRTY_SOURCE
    );
    assert_eq!(
        report.siblings[0].dirty_paths,
        vec![
            "/data/projects/franken_engine/Cargo.toml",
            "/data/projects/franken_engine/crates/franken-engine/src/lib.rs",
        ]
    );
}

#[test]
fn sibling_drift_preflight_blocks_manifest_path_mismatch_and_feature_gap() {
    let report = build_sibling_drift_preflight(SiblingDriftPreflightInput::new(
        "/data/projects/franken_node",
        [healthy_franken_engine()
            .with_dependency_paths(["/tmp/stale/franken_engine"])
            .with_required_features(["engine", "missing-feature"])
            .with_available_features(["engine"])],
    ))
    .expect("mismatch report should build");

    assert_eq!(report.decision, SiblingDriftDecision::BlockBroadValidation);
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.reason_code == sibling_drift_reason_codes::MANIFEST_PATH_MISMATCH
    }));
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.reason_code == sibling_drift_reason_codes::FEATURE_MISMATCH
            && diagnostic.summary.contains("missing-feature")
    }));
}

#[test]
fn sibling_drift_preflight_rejects_invalid_feature_text() {
    let err = build_sibling_drift_preflight(SiblingDriftPreflightInput::new(
        "/data/projects/franken_node",
        [healthy_franken_engine().with_required_features(["engine", "bad\0feature"])],
    ))
    .expect_err("invalid feature text should fail closed");

    assert!(matches!(
        err,
        ValidationPlannerError::SiblingPreflightText {
            field: "sibling.feature"
        }
    ));
}

#[test]
fn sibling_drift_preflight_records_closed_blocker_without_blocking() {
    let report = build_sibling_drift_preflight(
        SiblingDriftPreflightInput::new("/data/projects/franken_node", [healthy_franken_engine()])
            .with_known_blockers([SiblingBlockerRef::new(
                "franken_engine",
                "bd-v2bb1",
                SiblingBlockerStatus::Closed,
                "previous franken_engine compile drift is closed",
            )]),
    )
    .expect("closed blocker report should build");

    assert_eq!(report.decision, SiblingDriftDecision::AllowBroadValidation);
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.reason_code == sibling_drift_reason_codes::CLOSED_BLOCKER
            && diagnostic.severity == SiblingDriftDiagnosticSeverity::Info
            && diagnostic.bead_id.as_deref() == Some("bd-v2bb1")
    }));
}

#[test]
fn sibling_drift_preflight_blocks_active_and_stale_blockers() {
    let report = build_sibling_drift_preflight(
        SiblingDriftPreflightInput::new("/data/projects/franken_node", [healthy_franken_engine()])
            .with_known_blockers([
                SiblingBlockerRef::new(
                    "franken_engine",
                    "bd-active",
                    SiblingBlockerStatus::Active,
                    "active sibling proof failure",
                ),
                SiblingBlockerRef::new(
                    "franken_engine",
                    "bd-stale",
                    SiblingBlockerStatus::Stale,
                    "stale blocker comment needs refresh",
                ),
            ]),
    )
    .expect("blocker report should build");

    assert_eq!(report.decision, SiblingDriftDecision::BlockBroadValidation);
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.reason_code == sibling_drift_reason_codes::ACTIVE_BLOCKER
            && diagnostic.bead_id.as_deref() == Some("bd-active")
    }));
    assert!(report.diagnostics.iter().any(|diagnostic| {
        diagnostic.reason_code == sibling_drift_reason_codes::STALE_BLOCKER
            && diagnostic.bead_id.as_deref() == Some("bd-stale")
    }));
}

#[test]
fn sibling_drift_preflight_blocks_planner_broad_validation() {
    let preflight = build_sibling_drift_preflight(
        SiblingDriftPreflightInput::new("/data/projects/franken_node", [healthy_franken_engine()])
            .with_known_blockers([SiblingBlockerRef::new(
                "franken_engine",
                "bd-active",
                SiblingBlockerStatus::Active,
                "active sibling proof failure",
            )]),
    )
    .expect("preflight should build");
    let plan = plan_validation(
        &PlannerInput::new(
            "bd-preflight",
            ["crates/franken-node/src/runtime/resource_governor.rs"],
            registered_tests(),
        )
        .with_sibling_preflight(preflight),
    );

    assert!(plan.source_only_allowed);
    assert_eq!(plan.rch_commands().count(), 0);
    assert!(plan.skipped_gates.iter().any(|gate| {
        gate.gate == "rch cargo validation"
            && gate
                .reason
                .contains(sibling_drift_reason_codes::ACTIVE_BLOCKER)
    }));
    assert!(plan.escalation_conditions.iter().any(|condition| {
        condition.contains("resolve sibling drift SDP_ACTIVE_BLOCKER")
            && condition.contains("franken_engine")
    }));
}

#[test]
fn sibling_drift_preflight_json_order_is_deterministic() {
    let report = build_sibling_drift_preflight(
        SiblingDriftPreflightInput::new(
            "/data/projects/franken_node",
            [
                SiblingRepoDriftInput::new(
                    "sqlmodel",
                    "/data/projects/sqlmodel_rust",
                    "/data/projects/sqlmodel_rust",
                    "/data/projects/sqlmodel_rust/Cargo.toml",
                )
                .with_dependency_paths(["/data/projects/sqlmodel_rust"])
                .with_dirty_paths([
                    "/data/projects/sqlmodel_rust/z.rs",
                    "/data/projects/sqlmodel_rust/a.rs",
                ]),
                healthy_franken_engine(),
            ],
        )
        .with_known_blockers([
            SiblingBlockerRef::new(
                "sqlmodel",
                "bd-z",
                SiblingBlockerStatus::Closed,
                "closed sqlmodel blocker",
            ),
            SiblingBlockerRef::new(
                "franken_engine",
                "bd-a",
                SiblingBlockerStatus::Closed,
                "closed franken_engine blocker",
            ),
        ]),
    )
    .expect("deterministic report should build");
    let json = serde_json::to_string(&report).expect("report serializes");

    let franken_index = json.find("\"repo_id\":\"franken_engine\"").unwrap();
    let sqlmodel_index = json.find("\"repo_id\":\"sqlmodel\"").unwrap();
    assert!(franken_index < sqlmodel_index);
    assert!(
        json.find("/data/projects/sqlmodel_rust/a.rs").unwrap()
            < json.find("/data/projects/sqlmodel_rust/z.rs").unwrap()
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
