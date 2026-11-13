use clap::{CommandFactory, Parser, error::ErrorKind};
use frankenengine_node::cli::{
    Cli, Command, MigrateCommand, MigrateRolloutAction, MigrateRolloutStage, VerifyCommand,
};
use std::path::PathBuf;

/// Trigger every clap debug-assertion (argument-name uniqueness, group
/// invariants, etc.) across the entire `Cli` tree.
///
/// This integration test keeps the CLI contract pinned through the public
/// crate surface as well as inline module coverage. It regression-protects the
/// fix where `RegistryPublishArgs::version` collided with clap's
/// auto-generated `--version` flag.
#[test]
fn cli_structure_passes_clap_debug_assertions() {
    Cli::command().debug_assert();
}

fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
    Cli::try_parse_from(args)
}

fn rollout_command(project: &std::path::Path) -> std::process::Command {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_franken-node"));
    command
        .current_dir(project)
        .env_remove("FRANKEN_NODE_ROLLOUT_SIGNING_KEY")
        .env_remove("FRANKEN_NODE_ROLLOUT_EXPECTED_HEAD_SHA256")
        .args(["migrate", "rollout"])
        .arg(project)
        .arg("--json");
    command
}

fn assert_rollout_error(output: &std::process::Output) {
    assert!(
        !output.status.success(),
        "unexpected rollout success: {output:?}"
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("expected structured rollout refusal: {error}; {output:?}"));
    assert_eq!(
        report["schema_version"],
        "franken-node/migrate-error-cli/v1"
    );
    assert_eq!(report["command"], "migrate.rollout");
    assert_eq!(report["ok"], false);
    assert!(!report["error"].as_str().unwrap().is_empty());
}

#[test]
fn rollout_parser_distinguishes_automatic_progression_from_explicit_stages() {
    let Command::Migrate(MigrateCommand::Rollout(defaults)) =
        parse(&["franken-node", "migrate", "rollout", "project"])
            .unwrap()
            .command
    else {
        panic!("expected rollout");
    };
    assert_eq!(defaults.action, MigrateRolloutAction::Promote);
    assert!(defaults.stage.is_none());
    defaults.validate_intent().unwrap();
    for (text, expected) in [
        ("shadow", MigrateRolloutStage::Shadow),
        ("canary", MigrateRolloutStage::Canary),
        ("RAMP", MigrateRolloutStage::Ramp),
        ("default", MigrateRolloutStage::Default),
    ] {
        let Command::Migrate(MigrateCommand::Rollout(args)) = parse(&[
            "franken-node",
            "migrate",
            "rollout",
            "project",
            "--stage",
            text,
        ])
        .unwrap()
        .command
        else {
            panic!("expected rollout");
        };
        assert_eq!(args.stage, Some(expected));
        args.validate_intent().unwrap();
    }
    for stage in ["canry", "defualt", "aborted", "rollback", ""] {
        assert!(
            parse(&[
                "franken-node",
                "migrate",
                "rollout",
                "project",
                "--stage",
                stage,
            ])
            .is_err(),
            "invalid stage {stage:?} must never become automatic progression"
        );
    }
}

#[test]
fn rollout_cli_rejects_invalid_intent_before_creating_storage() {
    let mut cases: Vec<Vec<&str>> = vec![
        vec!["--stage", "canry", "--force"],
        vec!["--stage", "defualt"],
        vec!["--stage", "aborted"],
        vec!["--action", "rollbak"],
        vec!["--ramp-pct", "0"],
        vec!["--ramp-pct", "101"],
        vec!["--stage", "shadow", "--ramp-pct", "25"],
        vec!["--stage", "canary", "--ramp-pct", "25"],
        vec!["--stage", "default", "--ramp-pct", "25", "--force"],
    ];
    for action in ["status", "rollback"] {
        for flags in [
            vec!["--stage", "ramp"],
            vec!["--ramp-pct", "25"],
            vec!["--force"],
            vec!["--no-auto-rollback"],
            vec!["--lockstep-report", "unread-evidence.json"],
        ] {
            let mut arguments = vec!["--action", action];
            arguments.extend(flags);
            cases.push(arguments);
        }
    }
    for arguments in cases {
        let project = tempfile::tempdir().unwrap();
        let output = rollout_command(project.path())
            .args(&arguments)
            .output()
            .unwrap();
        assert_rollout_error(&output);
        assert!(
            !project.path().join(".franken-node").exists(),
            "invalid intent {arguments:?} must be refused before opening storage"
        );
    }
}

#[test]
fn rollout_cli_rejected_initial_transitions_do_not_create_a_state_record() {
    for arguments in [
        vec!["--stage", "default"],
        vec!["--stage", "ramp", "--ramp-pct", "25"],
        vec!["--ramp-pct", "25", "--force"],
    ] {
        let project = tempfile::tempdir().unwrap();
        let output = rollout_command(project.path())
            .args(["--migration-id", "invalid-transition"])
            .args(&arguments)
            .output()
            .unwrap();
        assert_rollout_error(&output);
        assert!(
            !project
                .path()
                .join(".franken-node/state/rollout/invalid-transition.json")
                .exists(),
            "invalid transition {arguments:?} must not persist admission"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn rollout_cli_invalid_intent_cannot_restore_an_applied_source_transaction() {
    use frankenengine_node::migration::{
        rollback::{self, TransactionState},
        rollout::{RolloutConfig, RolloutManager},
        run_rewrite,
    };
    let project = tempfile::tempdir().unwrap();
    let source = "const fs = require('fs');\nconsole.log(fs.existsSync('package.json'));\n";
    std::fs::write(project.path().join("app.js"), source).unwrap();
    std::fs::write(
        project.path().join("package.json"),
        r#"{"name":"rollout-intent","version":"1.0.0","engines":{"node":">=20"}}"#,
    )
    .unwrap();
    assert!(run_rewrite(project.path(), true).unwrap().rewrites_applied > 0);
    let rewritten = std::fs::read(project.path().join("app.js")).unwrap();
    assert_ne!(rewritten, source.as_bytes());
    let history = rollback::run(project.path(), None, false);
    let transaction = &history
        .history
        .iter()
        .find(|entry| entry.state == TransactionState::Applied)
        .unwrap()
        .transaction_id;
    let manager = RolloutManager::new(project.path(), Some(transaction));
    manager
        .promote(
            &RolloutConfig {
                force: true,
                ..RolloutConfig::default()
            },
            None,
            None,
        )
        .unwrap();
    // A misspelled stage used to select an automatic promotion, which in this
    // state triggers real source restoration through the confidence gate.
    let mut state = manager.load_or_init().unwrap();
    state.confidence_score = 0.2;
    manager.persist(&state).unwrap();
    let state_path = project
        .path()
        .join(format!(".franken-node/state/rollout/{transaction}.json"));
    let retained_state = std::fs::read(&state_path).unwrap();
    for arguments in [
        vec!["--stage", "canry"],
        vec!["--stage", "defualt", "--force"],
        vec!["--action", "rollback", "--stage", "ramp"],
        vec!["--action", "rollback", "--ramp-pct", "25"],
        vec!["--action", "rollback", "--force"],
        vec!["--action", "rollback", "--no-auto-rollback"],
        vec![
            "--action",
            "rollback",
            "--lockstep-report",
            "unread-evidence.json",
        ],
    ] {
        let output = rollout_command(project.path())
            .args(["--migration-id", transaction])
            .args(&arguments)
            .output()
            .unwrap();
        assert_rollout_error(&output);
        assert_eq!(
            std::fs::read(&state_path).unwrap(),
            retained_state,
            "{arguments:?}"
        );
        assert_eq!(
            std::fs::read(project.path().join("app.js")).unwrap(),
            rewritten,
            "{arguments:?}"
        );
    }
    let restored = rollout_command(project.path())
        .args(["--migration-id", transaction, "--action", "rollback"])
        .output()
        .unwrap();
    assert!(restored.status.success(), "{restored:?}");
    let report: serde_json::Value = serde_json::from_slice(&restored.stdout).unwrap();
    assert_eq!(report["status"], "rolled_back");
    assert_eq!(report["source_rollback"]["restoration_recorded"], true);
    assert_eq!(
        std::fs::read_to_string(project.path().join("app.js")).unwrap(),
        source
    );
}

#[test]
fn rollout_cli_valid_actions_preserve_progression_and_inferred_ramp() {
    let project = tempfile::tempdir().unwrap();
    for (arguments, stage, percentage) in [
        (vec!["--action", "status"], "shadow", 0),
        (vec!["--force"], "canary", 5),
        (vec!["--force", "--ramp-pct", "40"], "ramp", 40),
        (
            vec!["--force", "--stage", "RAMP", "--ramp-pct", "100"],
            "ramp",
            100,
        ),
        (vec!["--force"], "default", 100),
        (vec!["--action", "status"], "default", 100),
        (vec!["--action", "rollback"], "aborted", 0),
    ] {
        let output = rollout_command(project.path())
            .args(["--migration-id", "valid-progression"])
            .args(&arguments)
            .output()
            .unwrap();
        assert!(output.status.success(), "{arguments:?}: {output:?}");
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["stage"], stage);
        assert_eq!(report["ramp_pct"], percentage);
        assert_eq!(report["lockstep_verified"], false);
    }
}

#[test]
fn source_graph_capture_arguments_preserve_the_explicit_symlink_choice() {
    for (extra, expected) in [(None, false), (Some("--allow-contained-symlinks"), true)] {
        let mut arguments = vec![
            "franken-node",
            "verify",
            "source-graph",
            "project",
            "src/main.mjs",
            "--json",
        ];
        arguments.extend(extra);
        let Command::Verify(VerifyCommand::SourceGraph(args)) = parse(&arguments).unwrap().command
        else {
            panic!("expected source graph verification");
        };
        assert_eq!(args.project_path, PathBuf::from("project"));
        assert_eq!(args.entrypoint, "src/main.mjs");
        assert_eq!(args.allow_contained_symlinks, expected);
        assert!(args.json);
    }
}

#[test]
fn registry_source_admission_requires_an_explicit_independent_key() {
    let Command::Run(defaults) = parse(&["franken-node", "run", "app.cjs"]).unwrap().command else {
        panic!("expected run");
    };
    assert!(defaults.registry_artifact.is_none());
    assert!(defaults.publisher_public_key.is_none());
    for missing_pair in [
        ["--registry-artifact", "artifact.manifest.json"],
        ["--publisher-public-key", "publisher.pub"],
    ] {
        let mut arguments = vec!["franken-node", "run", "app.cjs"];
        arguments.extend(missing_pair);
        let Command::Run(args) = parse(&arguments).unwrap().command else {
            panic!("expected run");
        };
        assert!(
            args.validate_paths()
                .unwrap_err()
                .to_string()
                .contains("must be supplied together")
        );
    }
}

#[test]
#[cfg(unix)]
fn registry_source_admission_accepts_absolute_external_paths_without_traversal() {
    let Command::Run(args) = parse(&[
        "franken-node",
        "run",
        "app.cjs",
        "--frozen-modules",
        "--registry-artifact",
        "/operator/registry/artifact.manifest.json",
        "--publisher-public-key",
        "/operator/keys/publisher.pub",
    ])
    .unwrap()
    .command
    else {
        panic!("expected run");
    };
    args.validate_paths().unwrap();
    assert_eq!(
        args.publisher_public_key,
        Some(PathBuf::from("/operator/keys/publisher.pub"))
    );
    let Command::Verify(VerifyCommand::SourceGraph(args)) = parse(&[
        "franken-node",
        "verify",
        "source-graph",
        "project",
        "app.cjs",
        "--write-source-capsule",
        "/operator/review/source.capsule",
    ])
    .unwrap()
    .command
    else {
        panic!("expected source graph");
    };
    assert_eq!(
        args.write_source_capsule,
        Some(PathBuf::from("/operator/review/source.capsule"))
    );
    assert!(
        parse(&[
            "franken-node",
            "run",
            "app.cjs",
            "--registry-artifact",
            "/operator/../artifact.json",
            "--publisher-public-key",
            "/operator/key.pub",
        ])
        .is_err()
    );
}

#[test]
#[cfg(unix)]
fn source_graph_capsule_export_is_explicit_private_and_does_not_overwrite() {
    use frankenengine_node::supply_chain::module_resolution_graph::file_resolution::source_graph::capsule;
    use std::os::unix::fs::PermissionsExt;
    let project = tempfile::tempdir().unwrap();
    std::fs::write(
        project.path().join("app.cjs"),
        "console.log('PRIVATE_CAPSULE_SOURCE');\n",
    )
    .unwrap();
    let output_dir = tempfile::tempdir().unwrap();
    let destination = output_dir.path().join("source.capsule");
    let invoke = || {
        std::process::Command::new(env!("CARGO_BIN_EXE_franken-node"))
            .args(["verify", "source-graph"])
            .arg(project.path())
            .arg("app.cjs")
            .arg("--write-source-capsule")
            .arg(&destination)
            .arg("--json")
            .output()
            .unwrap()
    };
    let exported = invoke();
    assert!(
        exported.status.success(),
        "{}",
        String::from_utf8_lossy(&exported.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&exported.stdout).unwrap();
    assert!(!String::from_utf8_lossy(&exported.stdout).contains("PRIVATE_CAPSULE_SOURCE"));
    assert_eq!(
        std::fs::metadata(&destination)
            .unwrap()
            .permissions()
            .mode()
            & 0o077,
        0
    );
    let retained = std::fs::read(&destination).unwrap();
    let graph = capsule::replay(&retained, report["capsule_digest"].as_str().unwrap()).unwrap();
    assert_eq!(
        graph.report().input_hash,
        report["input_hash"].as_str().unwrap()
    );
    std::fs::write(
        project.path().join("app.cjs"),
        "console.log('REPLACEMENT_SOURCE');\n",
    )
    .unwrap();
    let refused = invoke();
    assert!(!refused.status.success());
    assert_eq!(std::fs::read(&destination).unwrap(), retained);
    let error: serde_json::Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(
        error["schema_version"],
        "franken-node/verify-source-graph-error-cli/v1"
    );
}

#[test]
fn source_graph_is_listed_in_the_reviewed_verification_help_contract() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_franken-node"))
        .args(["verify", "--help"])
        .env("NO_COLOR", "1")
        .env("CLICOLOR", "0")
        .env("CLICOLOR_FORCE", "0")
        .env_remove("FORCE_COLOR")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stderr.is_empty());
    let (_, expected) = include_str!("goldens/verify_cli/verify_help.snap")
        .split_once("\n---\n")
        .expect("reviewed help golden has a metadata header");
    assert_eq!(String::from_utf8(output.stdout).unwrap(), expected);
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn source_capsule_export_distinguishes_native_closure_from_source_resolution() {
    use frankenengine_node::supply_chain::module_resolution_graph::file_resolution::source_graph::capsule;

    let project = tempfile::tempdir().unwrap();
    std::fs::write(project.path().join("app.cjs"),
        "require('node:path'); try { require('./optional.cjs'); } catch (error) {} throw new Error('CAPTURE_MUST_NOT_EXECUTE');\n").unwrap();
    let (inspection, original) = inspect_source_graph(project.path(), "app.cjs", false);
    assert_eq!(inspection.status.code(), Some(1));
    assert_eq!(original["fully_resolved"], false);
    let destination = project.path().join("source.capsule");
    let exported = std::process::Command::new(env!("CARGO_BIN_EXE_franken-node"))
        .args(["verify", "source-graph"])
        .arg(project.path())
        .arg("app.cjs")
        .arg("--write-source-capsule")
        .arg(&destination)
        .arg("--json")
        .output()
        .unwrap();
    assert!(
        exported.status.success(),
        "{}\n{}",
        String::from_utf8_lossy(&exported.stdout),
        String::from_utf8_lossy(&exported.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&exported.stdout).unwrap();
    assert_eq!(report["fully_resolved"], false);
    assert_eq!(report["capsule_closure_verified"], true);
    assert_eq!(report["execution_performed"], false);
    assert_eq!(report["runtime_completeness"], false);
    assert_eq!(report["release_certification"], false);
    assert_eq!(report["input_hash"], original["input_hash"]);
    assert!(!String::from_utf8_lossy(&exported.stdout).contains("CAPTURE_MUST_NOT_EXECUTE"));
    let replayed = capsule::replay(
        &std::fs::read(&destination).unwrap(),
        report["capsule_digest"].as_str().unwrap(),
    )
    .unwrap();
    assert_eq!(
        replayed.report().input_hash,
        original["input_hash"].as_str().unwrap()
    );
    assert!(!replayed.report().fully_resolved);
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn source_capsule_export_refuses_unproved_native_routes_without_creating_output() {
    for source in [
        "import 'node:unimplemented';",
        "import 'node:path'; import './absent.mjs';",
        "import 'node:path'; import(globalThis.request);",
        "import 'node:path'; const invalid = ;",
    ] {
        let project = tempfile::tempdir().unwrap();
        std::fs::write(project.path().join("app.mjs"), source).unwrap();
        let destination = project.path().join("source.capsule");
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_franken-node"))
            .args(["verify", "source-graph"])
            .arg(project.path())
            .arg("app.mjs")
            .arg("--write-source-capsule")
            .arg(&destination)
            .arg("--json")
            .output()
            .unwrap();
        assert!(!output.status.success(), "unexpected export for {source}");
        assert!(
            !destination.exists(),
            "refused export wrote a capsule for {source}"
        );
        let error: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            error["schema_version"],
            "franken-node/verify-source-graph-error-cli/v1"
        );
        assert!(
            error["error"]
                .as_str()
                .unwrap()
                .contains("ERR_MODULE_REGISTRY_INCOMPLETE")
        );
    }
}

#[test]
#[cfg(unix)]
fn source_graph_cli_captures_without_evaluation_and_preserves_incomplete_evidence() {
    let project = tempfile::TempDir::new().unwrap();
    let entry = project.path().join("app.cjs");
    std::fs::write(
        &entry,
        "const value = require('./side.cjs'); console.log(value);\n",
    )
    .unwrap();
    std::fs::write(
        project.path().join("side.cjs"),
        "throw new Error('SOURCE_BODY_MUST_NEVER_EXECUTE'); module.exports = 42;\n",
    )
    .unwrap();
    let (captured, report) = inspect_source_graph(project.path(), "app.cjs", false);
    assert!(
        captured.status.success(),
        "{}",
        String::from_utf8_lossy(&captured.stderr)
    );
    assert_eq!(
        report["schema_version"],
        "franken-node/module-source-graph/v2"
    );
    assert_eq!(report["fully_resolved"], true);
    assert_eq!(report["execution_performed"], false);
    assert_eq!(report["runtime_completeness"], false);
    assert_eq!(report["release_certification"], false);
    assert_eq!(report["modules"].as_array().unwrap().len(), 2);
    assert!(!String::from_utf8_lossy(&captured.stdout).contains("SOURCE_BODY_MUST_NEVER_EXECUTE"));
    let initial_pin = report["input_hash"].as_str().unwrap().to_string();
    assert_eq!(initial_pin.len(), 71);
    assert!(initial_pin.starts_with("sha256:"));

    let human = std::process::Command::new(env!("CARGO_BIN_EXE_franken-node"))
        .args(["verify", "source-graph"])
        .arg(project.path())
        .arg("app.cjs")
        .output()
        .unwrap();
    assert!(human.status.success());
    let human_report = String::from_utf8(human.stdout).unwrap();
    assert!(human_report.contains(&format!("Graph pin: {initial_pin}")));
    assert!(human_report.contains("no guest execution"));

    std::fs::write(&entry, "require(globalThis.unboundedRequest);\n").unwrap();
    let (incomplete, report) = inspect_source_graph(project.path(), "app.cjs", false);
    assert_eq!(incomplete.status.code(), Some(1));
    assert_eq!(report["fully_resolved"], false);
    assert_eq!(report["execution_performed"], false);
    assert_ne!(report["input_hash"], initial_pin);
    assert!(
        report["edges"]
            .as_array()
            .unwrap()
            .iter()
            .any(|edge| edge["state"] == "non_literal")
    );
}

#[cfg(unix)]
fn inspect_source_graph(
    project: &std::path::Path,
    entrypoint: &str,
    allow_links: bool,
) -> (std::process::Output, serde_json::Value) {
    let mut command = std::process::Command::new(env!("CARGO_BIN_EXE_franken-node"));
    command
        .args(["verify", "source-graph"])
        .arg(project)
        .arg(entrypoint)
        .arg("--json");
    if allow_links {
        command.arg("--allow-contained-symlinks");
    }
    let output = command.output().unwrap();
    let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{error}: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    (output, report)
}

#[test]
#[cfg(unix)]
fn source_graph_cli_checks_entrypoint_and_contained_symlink_boundaries() {
    let project = tempfile::TempDir::new().unwrap();
    std::fs::write(project.path().join("side.cjs"), "module.exports = 42;\n").unwrap();

    for invalid in ["../outside.cjs", "/outside.cjs"] {
        let (denied, report) = inspect_source_graph(project.path(), invalid, false);
        assert_eq!(denied.status.code(), Some(1));
        assert_eq!(
            report["schema_version"],
            "franken-node/verify-source-graph-error-cli/v1"
        );
        assert_eq!(report["command"], "verify.source-graph");
        assert_eq!(report["ok"], false);
    }
    std::os::unix::fs::symlink("side.cjs", project.path().join("linked.cjs")).unwrap();
    let (denied, _) = inspect_source_graph(project.path(), "linked.cjs", false);
    assert_eq!(denied.status.code(), Some(1));
    let (allowed, report) = inspect_source_graph(project.path(), "linked.cjs", true);
    assert!(allowed.status.success(), "{report}");
    assert_eq!(report["execution_performed"], false);
}

#[test]
fn source_graph_cli_missing_inputs_emit_one_json_error() {
    for arguments in [
        vec!["verify", "source-graph", "--json"],
        vec!["verify", "source-graph", "--not-a-real-option", "--json"],
    ] {
        let output = std::process::Command::new(env!("CARGO_BIN_EXE_franken-node"))
            .args(arguments)
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            report["schema_version"],
            "franken-node/verify-source-graph-error-cli/v1"
        );
        assert_eq!(report["ok"], false);
        assert!(
            output.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn frozen_module_symlink_flag_preserves_configuration_unless_explicit() {
    for (extra, expected) in [
        (None, None),
        (Some("--frozen-module-symlinks"), Some(true)),
        (Some("--frozen-module-symlinks=false"), Some(false)),
    ] {
        let mut args = vec!["franken-node", "run", "app.cjs"];
        args.extend(extra);
        let Command::Run(run) = parse(&args).unwrap().command else {
            panic!("expected run command");
        };
        assert_eq!(run.frozen_module_symlinks, expected);
    }
    assert!(
        parse(&[
            "franken-node",
            "run",
            "app.cjs",
            "--frozen-module-symlinks=outside",
        ])
        .is_err()
    );
}

#[test]
fn run_conditions_are_repeatable_and_do_not_consume_guest_arguments() {
    let Command::Run(defaults) = parse(&["franken-node", "run", "app.mjs"]).unwrap().command else {
        panic!("expected run command");
    };
    assert!(defaults.module_conditions.is_empty());
    let Command::Run(selected) = parse(&[
        "franken-node",
        "run",
        "app.mjs",
        "--conditions",
        "development",
        "-C",
        "react-server",
        "--",
        "--conditions",
        "guest-value",
    ])
    .unwrap()
    .command
    else {
        panic!("expected run command");
    };
    assert_eq!(selected.module_conditions, ["development", "react-server"]);
    assert_eq!(selected.app_args, ["--conditions", "guest-value"]);
    let Command::Verify(VerifyCommand::SourceGraph(inspection)) = parse(&[
        "franken-node",
        "verify",
        "source-graph",
        ".",
        "app.mjs",
        "--conditions",
        "development",
        "-C",
        "react-server",
        "--json",
    ])
    .unwrap()
    .command
    else {
        panic!("expected verify command");
    };
    assert_eq!(
        inspection.module_conditions,
        ["development", "react-server"]
    );
}

#[test]
fn frozen_module_graph_pin_preserves_omission_and_accepts_explicit_cli_selection() {
    let Command::Run(defaults) = parse(&["franken-node", "run", "app.cjs"]).unwrap().command else {
        panic!("expected run command");
    };
    assert_eq!(defaults.frozen_module_graph_hash, None);
    let pin = format!("sha256:{}", "ab".repeat(32));
    let Command::Run(selected) = parse(&[
        "franken-node",
        "run",
        "app.cjs",
        "--frozen-module-graph-hash",
        &pin,
    ])
    .unwrap()
    .command
    else {
        panic!("expected run command");
    };
    assert_eq!(
        selected.frozen_module_graph_hash.as_deref(),
        Some(pin.as_str())
    );
}

#[test]
fn frozen_module_graph_pin_profile_config_and_worker_serialization() {
    use frankenengine_node::config::{CliOverrides, Config, Profile};

    let directory = tempfile::TempDir::new().unwrap();
    let path = directory.path().join("franken_node.toml");
    let mut config = Config::for_profile(Profile::Balanced);
    let _synthesis = config.synthesize_init_security_defaults();
    let base_pin = format!("sha256:{}", "ab".repeat(32));
    let profile_pin = format!("sha256:{}", "cd".repeat(32));
    config.runtime.frozen_modules = Some(true);
    config.runtime.frozen_module_graph_hash = Some(base_pin);
    std::fs::write(
        &path,
        format!(
            "{}\n[profiles.balanced.runtime]\nfrozen_module_graph_hash = '{profile_pin}'\n",
            config.to_toml().unwrap()
        ),
    )
    .unwrap();
    let resolved =
        Config::resolve_with_env(Some(&path), CliOverrides::default(), &|_| None).unwrap();
    assert_eq!(
        resolved.config.runtime.frozen_module_graph_hash.as_deref(),
        Some(profile_pin.as_str())
    );
    let serialized = serde_json::to_vec(&resolved.config).unwrap();
    let worker_config: Config = serde_json::from_slice(&serialized).unwrap();
    assert_eq!(
        worker_config.runtime.frozen_module_graph_hash.as_deref(),
        Some(profile_pin.as_str())
    );
    for invalid in ["", "sha256:short", "sha256:UPPERCASE"] {
        let mut rejected = worker_config.clone();
        rejected.runtime.frozen_module_graph_hash = Some(invalid.to_owned());
        std::fs::write(&path, rejected.to_toml().unwrap()).unwrap();
        let error = Config::resolve_with_env(Some(&path), CliOverrides::default(), &|_| None)
            .expect_err("malformed graph pins cannot reach native capture");
        assert!(
            error
                .to_string()
                .contains("runtime.frozen_module_graph_hash")
        );
    }
}

#[test]
fn migrate_audit_rejects_sarif_to_json_output() {
    let err = parse(&[
        "franken-node",
        "migrate",
        "audit",
        "fixture-app",
        "--format",
        "sarif",
        "--out",
        "audit.json",
    ])
    .expect_err("sarif output must not be written to a .json target");

    assert_eq!(err.kind(), ErrorKind::ValueValidation);
}

#[test]
fn migrate_audit_requires_sarif_output_target_for_sarif_format() {
    let err = parse(&[
        "franken-node",
        "migrate",
        "audit",
        "fixture-app",
        "--format",
        "sarif",
    ])
    .expect_err("sarif output must require an explicit .sarif target");

    assert_eq!(err.kind(), ErrorKind::MissingRequiredArgument);
}

#[test]
fn migrate_audit_accepts_matching_json_output_target() {
    let cli = parse(&[
        "franken-node",
        "migrate",
        "audit",
        "fixture-app",
        "--format",
        "json",
        "--out",
        "audit.json",
    ])
    .expect("json output should accept a .json target");

    let Command::Migrate(MigrateCommand::Audit(args)) = cli.command else {
        panic!("expected migrate audit command");
    };
    assert_eq!(args.project_path, PathBuf::from("fixture-app"));
    assert_eq!(args.format, "json");
    assert_eq!(args.out, Some(PathBuf::from("audit.json")));
}

#[test]
fn migrate_audit_json_flag_selects_json_format() {
    let cli = parse(&["franken-node", "migrate", "audit", "fixture-app", "--json"])
        .expect("--json should select json format");

    let Command::Migrate(MigrateCommand::Audit(args)) = cli.command else {
        panic!("expected migrate audit command");
    };
    assert_eq!(args.format, "json");
}

#[test]
fn migrate_audit_json_conflicts_with_non_json_format() {
    let err = parse(&[
        "franken-node",
        "migrate",
        "audit",
        "fixture-app",
        "--format",
        "sarif",
        "--json",
        "--out",
        "audit.sarif",
    ])
    .expect_err("--json must not silently override --format sarif");

    assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
}

#[test]
fn migrate_validate_json_flag_parses() {
    let cli = parse(&[
        "franken-node",
        "migrate",
        "validate",
        "fixture-app",
        "--json",
    ])
    .expect("--json should parse on migrate validate");

    let Command::Migrate(MigrateCommand::Validate(args)) = cli.command else {
        panic!("expected migrate validate command");
    };
    assert!(args.json);
}

#[test]
fn migrate_report_json_flag_parses() {
    let cli = parse(&["franken-node", "migrate-report", "fixture-app", "--json"])
        .expect("--json should parse on migrate-report");

    let Command::MigrateReport(args) = cli.command else {
        panic!("expected migrate-report command");
    };
    assert!(args.json);
    assert_eq!(args.format, "json");
}

#[test]
fn migrate_report_json_conflicts_with_html_format() {
    let cli = parse(&[
        "franken-node",
        "migrate-report",
        "fixture-app",
        "--format",
        "html",
        "--json",
    ])
    .expect("clap should accept both flags; handler fail-closes the conflict");

    let Command::MigrateReport(args) = cli.command else {
        panic!("expected migrate-report command");
    };
    assert!(args.json);
    assert_eq!(args.format, "html");
}
