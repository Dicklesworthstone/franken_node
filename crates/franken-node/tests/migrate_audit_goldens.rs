use assert_cmd::Command;
use insta::assert_snapshot;

#[path = "migrate_golden_helpers.rs"]
mod migrate_golden_helpers;

use migrate_golden_helpers::{
    fixture_path, pretty_json_stdout, with_scrubbed_snapshot_settings,
};

fn audit_fixture_json(fixture: &str) -> String {
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = command
        .args([
            "migrate",
            "audit",
            fixture_path(fixture).to_str().expect("utf-8 fixture path"),
            "--format",
            "json",
        ])
        .assert()
        .success();

    pretty_json_stdout("migrate audit", &assertion.get_output().stdout)
}

#[test]
fn migrate_audit_risky_fixture_json_matches_golden() {
    let stdout_json = audit_fixture_json("risky");
    with_scrubbed_snapshot_settings("migrate_audit", || {
        assert_snapshot!("risky", stdout_json);
    });
}

#[test]
fn migrate_audit_hardened_fixture_json_matches_golden() {
    let stdout_json = audit_fixture_json("hardened");
    with_scrubbed_snapshot_settings("migrate_audit", || {
        assert_snapshot!("hardened", stdout_json);
    });
}
