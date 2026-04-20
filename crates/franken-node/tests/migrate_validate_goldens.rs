use assert_cmd::Command;
use insta::assert_snapshot;

#[path = "migrate_golden_helpers.rs"]
mod migrate_golden_helpers;

use migrate_golden_helpers::{
    fixture_path, pretty_json_stdout, with_scrubbed_snapshot_settings,
};

fn validate_fixture_json(fixture: &str, expect_success: bool) -> String {
    let mut command = Command::cargo_bin("franken-node").expect("franken-node binary");
    let assertion = command
        .args([
            "migrate",
            "validate",
            fixture_path(fixture).to_str().expect("utf-8 fixture path"),
            "--format",
            "json",
        ])
        .assert();

    let assertion = if expect_success {
        assertion.success()
    } else {
        assertion.failure()
    };

    pretty_json_stdout("migrate validate", &assertion.get_output().stdout)
}

#[test]
fn migrate_validate_risky_fixture_json_matches_golden() {
    let stdout_json = validate_fixture_json("risky", false);
    with_scrubbed_snapshot_settings("migrate_validate", || {
        assert_snapshot!("risky", stdout_json);
    });
}

#[test]
fn migrate_validate_hardened_fixture_json_matches_golden() {
    let stdout_json = validate_fixture_json("hardened", true);
    with_scrubbed_snapshot_settings("migrate_validate", || {
        assert_snapshot!("hardened", stdout_json);
    });
}
