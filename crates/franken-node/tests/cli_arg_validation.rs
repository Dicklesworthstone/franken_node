use clap::{CommandFactory, Parser, error::ErrorKind};
use frankenengine_node::cli::{Cli, Command, MigrateCommand, VerifyCommand};
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
    assert!(parse(&[
        "franken-node", "run", "app.cjs", "--frozen-module-symlinks=outside",
    ]).is_err());
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
