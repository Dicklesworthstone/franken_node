use clap::{Parser, error::ErrorKind};
use frankenengine_node::cli::{Cli, Command, MigrateCommand};
use std::path::PathBuf;

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
