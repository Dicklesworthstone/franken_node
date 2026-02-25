use serde_json::Value;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn fixture_path(name: &str) -> PathBuf {
    repo_root().join("fixtures/policy_activation").join(name)
}

fn run_doctor(policy_input_path: &Path, trace_id: &str) -> Value {
    let repo = repo_root();

    let output = if let Some(exe) = std::env::var_os("CARGO_BIN_EXE_frankenengine-node")
        .or_else(|| std::env::var_os("CARGO_BIN_EXE_franken-node"))
    {
        Command::new(exe)
            .current_dir(&repo)
            .args([
                "doctor",
                "--json",
                "--trace-id",
                trace_id,
                "--policy-activation-input",
                policy_input_path
                    .to_str()
                    .expect("policy fixture path must be utf-8"),
            ])
            .output()
            .expect("failed to run franken-node doctor")
    } else if repo.join("target/debug/frankenengine-node").is_file() {
        Command::new(repo.join("target/debug/frankenengine-node"))
            .current_dir(&repo)
            .args([
                "doctor",
                "--json",
                "--trace-id",
                trace_id,
                "--policy-activation-input",
                policy_input_path
                    .to_str()
                    .expect("policy fixture path must be utf-8"),
            ])
            .output()
            .expect("failed to run franken-node doctor from target/debug")
    } else {
        Command::new("cargo")
            .current_dir(&repo)
            .args([
                "run",
                "-q",
                "-p",
                "frankenengine-node",
                "--",
                "doctor",
                "--json",
                "--trace-id",
                trace_id,
                "--policy-activation-input",
                policy_input_path
                    .to_str()
                    .expect("policy fixture path must be utf-8"),
            ])
            .output()
            .expect("failed to run cargo doctor fallback")
    };

    assert!(
        output.status.success(),
        "doctor command failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("doctor output must be valid JSON")
}

fn check_status<'a>(report: &'a Value, code: &str) -> &'a str {
    report["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|entry| entry["code"].as_str() == Some(code))
        .and_then(|entry| entry["status"].as_str())
        .unwrap_or_else(|| panic!("missing doctor check {code}"))
}

fn check_message<'a>(report: &'a Value, code: &str) -> &'a str {
    report["checks"]
        .as_array()
        .expect("checks array")
        .iter()
        .find(|entry| entry["code"].as_str() == Some(code))
        .and_then(|entry| entry["message"].as_str())
        .unwrap_or_else(|| panic!("missing doctor check message {code}"))
}

#[test]
fn doctor_policy_activation_pass_path() {
    let report = run_doctor(
        &fixture_path("doctor_policy_activation_pass.json"),
        "doctor-policy-e2e-pass",
    );

    assert_ne!(report["overall_status"], "fail");
    assert_eq!(check_status(&report, "DR-POLICY-009"), "pass");
    assert_eq!(check_status(&report, "DR-POLICY-010"), "pass");
    assert_eq!(check_status(&report, "DR-POLICY-011"), "pass");

    assert_eq!(
        report["policy_activation"]["guardrail_certificate"]["dominant_verdict"],
        "allow"
    );
    assert_eq!(
        report["policy_activation"]["wording_validation"]["valid"],
        true
    );
    assert_eq!(
        report["policy_activation"]["top_ranked_candidate"],
        "balanced_patch"
    );
    assert_eq!(
        report["policy_activation"]["decision_outcome"]["chosen"],
        "balanced_patch"
    );
    assert_eq!(
        report["policy_activation"]["decision_outcome"]["reason"],
        "TopCandidateAccepted"
    );
}

#[test]
fn doctor_policy_activation_warn_path_surfaces_conformal_warning() {
    let report = run_doctor(
        &fixture_path("doctor_policy_activation_warn.json"),
        "doctor-policy-e2e-warn",
    );

    assert_eq!(report["overall_status"], "warn");
    assert_eq!(check_status(&report, "DR-POLICY-009"), "warn");
    assert_eq!(check_status(&report, "DR-POLICY-010"), "pass");
    assert_eq!(check_status(&report, "DR-POLICY-011"), "pass");

    assert_eq!(
        report["policy_activation"]["guardrail_certificate"]["dominant_verdict"],
        "warn"
    );
    assert_eq!(
        report["policy_activation"]["decision_outcome"]["reason"],
        "TopCandidateAccepted"
    );

    let findings = report["policy_activation"]["guardrail_certificate"]["findings"]
        .as_array()
        .expect("guardrail findings array");
    let conformal = findings
        .iter()
        .find(|finding| finding["budget_id"].as_str() == Some("conformal_risk"))
        .expect("conformal_risk finding");
    assert_eq!(conformal["verdict"], "warn");
}

#[test]
fn doctor_policy_activation_block_path_blocks_on_conformal_risk() {
    let report = run_doctor(
        &fixture_path("doctor_policy_activation_block.json"),
        "doctor-policy-e2e-block",
    );

    assert_eq!(report["overall_status"], "fail");
    assert_eq!(check_status(&report, "DR-POLICY-009"), "fail");
    assert_eq!(check_status(&report, "DR-POLICY-010"), "fail");
    assert_eq!(check_status(&report, "DR-POLICY-011"), "pass");

    assert_eq!(
        report["policy_activation"]["guardrail_certificate"]["dominant_verdict"],
        "block"
    );
    assert_eq!(
        report["policy_activation"]["decision_outcome"]["reason"],
        "AllCandidatesBlocked"
    );
    assert_eq!(
        report["policy_activation"]["decision_outcome"]["chosen"],
        Value::Null
    );

    let blocked_budgets =
        report["policy_activation"]["guardrail_certificate"]["blocking_budget_ids"]
            .as_array()
            .expect("blocking budget ids");
    assert!(
        blocked_budgets
            .iter()
            .any(|entry| entry.as_str() == Some("conformal_risk"))
    );
}

#[test]
fn doctor_policy_activation_invalid_input_fails_safely() {
    let report = run_doctor(
        &fixture_path("doctor_policy_activation_invalid.json"),
        "doctor-policy-e2e-invalid",
    );

    assert_eq!(report["overall_status"], "fail");
    assert_eq!(check_status(&report, "DR-POLICY-009"), "fail");
    assert_eq!(check_status(&report, "DR-POLICY-010"), "fail");
    assert_eq!(check_status(&report, "DR-POLICY-011"), "fail");
    assert!(
        check_message(&report, "DR-POLICY-009").contains("failed parsing policy activation input")
    );
    assert!(report.get("policy_activation").is_none());
}
