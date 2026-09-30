//! bd-reality-20260923-26n9r.14 (IBD-8): end-to-end proof that the copilot
//! `ActionRecommendationEngine` — previously compiled-by-default but reachable
//! from no CLI path — is now wired into a real product command,
//! `franken-node doctor expected-loss-actions`.
//!
//! Two invariants are enforced:
//!   1. REACHABILITY + well-formed output: a live `--json` run exits 0 and emits
//!      the versioned copilot envelope (schema_version, response.recommendations,
//!      response.served_at, response.system_degraded). This is the anti-"library
//!      island" proof the bead demands.
//!   2. MEASURABLE RANKING: given a schema-faithful doctor report (produced by
//!      the sibling `doctor workspace-pressure` command, then given controlled
//!      recommended_actions), the command ranks them highest value-of-information
//!      first, so the observed high-priority action outranks medium and low.
//!
//! The report fed to `--from-report` is emitted by the product itself, so this
//! test tracks the real DoctorOutput wire schema without hand-authoring it.

use std::process::Command;

fn franken_node_bin() -> &'static str {
    env!("CARGO_BIN_EXE_franken-node")
}

const ENVELOPE_SCHEMA: &str = "franken-node/doctor/expected-loss-actions/v1";

/// Run the binary and return (success, stdout, stderr).
fn run(args: &[&str]) -> (bool, String, String) {
    let output = Command::new(franken_node_bin())
        .args(args)
        .output()
        .expect("spawn franken-node");
    (
        output.status.success(),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[test]
fn live_expected_loss_actions_is_reachable_and_well_formed() {
    let (ok, stdout, stderr) = run(&["doctor", "expected-loss-actions", "--json", "--top-k", "3"]);
    assert!(ok, "live run must exit 0; stderr=\n{stderr}");
    let envelope: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("stdout not JSON: {e}\n{stdout}"));

    assert_eq!(envelope["schema_version"], ENVELOPE_SCHEMA);
    assert_eq!(envelope["source"], "live");

    let response = &envelope["response"];
    assert!(
        response["recommendation_id"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "recommendation_id must be a non-empty string"
    );
    assert!(
        response["served_at"]
            .as_str()
            .is_some_and(|s| !s.is_empty()),
        "served_at must be a non-empty RFC3339 string"
    );
    assert!(
        response["system_degraded"].is_boolean(),
        "system_degraded must be a bool"
    );
    let recs = response["recommendations"]
        .as_array()
        .expect("recommendations must be an array");
    assert!(recs.len() <= 3, "top-k must bound the count");
    // Any recommendation that exists must be VoI-ordered and carry a rationale.
    for pair in recs.windows(2) {
        let a = pair[0]["voi_score"].as_f64().expect("voi f64");
        let b = pair[1]["voi_score"].as_f64().expect("voi f64");
        assert!(a >= b, "live recommendations not VoI-descending");
    }
}

/// Emit a schema-faithful DoctorOutput JSON, override its findings with
/// controlled test values, and verify the ranking end-to-end.
#[test]
fn from_report_ranks_controlled_findings_by_expected_loss() {
    // 1. Produce a real, schema-faithful workspace-pressure report.
    let (ok, base_json, stderr) = run(&["doctor", "workspace-pressure", "--json"]);
    assert!(
        ok,
        "workspace-pressure --json must exit 0; stderr=\n{stderr}"
    );
    let mut report: serde_json::Value = serde_json::from_str(&base_json)
        .unwrap_or_else(|e| panic!("workspace-pressure stdout not JSON: {e}\n{base_json}"));

    // 2. Override findings with controlled, deterministic values. The injected
    //    actions are clearly test inputs; the surrounding schema stays as the
    //    product emitted it.
    report["status"] = serde_json::json!("degraded");
    report["recommended_actions"] = serde_json::json!([
        {
            "priority": "low",
            "action": "tidy caches",
            "explanation": "minor incremental cache cleanup",
            "command": null,
            "impact": "frees a small amount of space"
        },
        {
            "priority": "high",
            "action": "free disk",
            "explanation": "critical disk pressure on the build target",
            "command": "cargo clean",
            "impact": "reclaims the target directory"
        },
        {
            "priority": "medium",
            "action": "reduce builds",
            "explanation": "throttle concurrent build processes",
            "command": null,
            "impact": "lowers memory and disk contention"
        }
    ]);
    // Fixed observed pressures so the ranking is machine-independent.
    report["resources"]["memory_pressure"] = serde_json::json!(0.6);
    report["resources"]["active_builds"] = serde_json::json!(2);
    report["resources"]["coordination_healthy"] = serde_json::json!(true);
    report["resources"]["target_dir_bytes"] = serde_json::json!(1_000_000_000u64);
    report["resources"]["free_disk_bytes"] = serde_json::json!(1_000_000_000u64);

    // 3. Write the fixture and rank it through the wired copilot engine.
    let dir = tempfile::TempDir::new().expect("tempdir");
    let fixture = dir.path().join("report.json");
    std::fs::write(&fixture, serde_json::to_string_pretty(&report).unwrap())
        .expect("write fixture");

    let (ok, stdout, stderr) = run(&[
        "doctor",
        "expected-loss-actions",
        "--from-report",
        fixture.to_str().unwrap(),
        "--json",
        "--top-k",
        "5",
    ]);
    assert!(ok, "--from-report run must exit 0; stderr=\n{stderr}");

    let envelope: serde_json::Value =
        serde_json::from_str(&stdout).unwrap_or_else(|e| panic!("stdout not JSON: {e}\n{stdout}"));
    assert_eq!(envelope["schema_version"], ENVELOPE_SCHEMA);
    assert_eq!(envelope["source"], "report");
    assert_eq!(envelope["doctor_status"], "DEGRADED");

    let recs = envelope["response"]["recommendations"]
        .as_array()
        .expect("recommendations array");
    assert_eq!(recs.len(), 3, "all three controlled actions should rank");

    // Highest value-of-information first.
    for pair in recs.windows(2) {
        let a = pair[0]["voi_score"].as_f64().expect("voi f64");
        let b = pair[1]["voi_score"].as_f64().expect("voi f64");
        assert!(a >= b, "not VoI-descending: {recs:?}");
    }
    // The observed high-priority action outranks medium and low.
    assert_eq!(recs[0]["display_name"], "free disk");
    assert_eq!(recs[2]["display_name"], "tidy caches");
    // Rationale surfaces the VoI, and acting beats waiting.
    assert!(
        recs[0]["rationale"].as_str().unwrap().contains("VOI="),
        "rationale must surface VoI"
    );
    assert!(recs[0]["voi_score"].as_f64().unwrap() > 0.0);
    // Degraded status widens confidence and emits a warning.
    assert_eq!(
        envelope["response"]["system_degraded"],
        serde_json::json!(true)
    );
    assert!(envelope["response"]["degraded_warning"].is_object());
}

#[test]
fn from_report_human_output_is_readable() {
    let (ok, base_json, _) = run(&["doctor", "workspace-pressure", "--json"]);
    assert!(ok);
    let mut report: serde_json::Value = serde_json::from_str(&base_json).unwrap();
    report["status"] = serde_json::json!("warning");
    report["recommended_actions"] = serde_json::json!([
        {
            "priority": "high",
            "action": "free disk",
            "explanation": "critical disk pressure",
            "command": "cargo clean",
            "impact": "reclaims target"
        }
    ]);

    let dir = tempfile::TempDir::new().unwrap();
    let fixture = dir.path().join("report.json");
    std::fs::write(&fixture, serde_json::to_string(&report).unwrap()).unwrap();

    let (ok, stdout, stderr) = run(&[
        "doctor",
        "expected-loss-actions",
        "--from-report",
        fixture.to_str().unwrap(),
    ]);
    assert!(ok, "human run must exit 0; stderr=\n{stderr}");
    assert!(
        stdout.contains("Expected-loss action ranking"),
        "human output missing header:\n{stdout}"
    );
    assert!(
        stdout.contains("free disk"),
        "human output missing action:\n{stdout}"
    );
    assert!(
        stdout.contains("VoI"),
        "human output missing VoI score:\n{stdout}"
    );
}
