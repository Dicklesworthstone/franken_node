use clap::{CommandFactory, Parser, error::ErrorKind};
use frankenengine_node::cli::{Cli, Command, MigrateCommand};
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
