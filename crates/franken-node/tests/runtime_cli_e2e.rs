use assert_cmd::Command;
use chrono::{TimeZone, Utc};
use frankenengine_node::runtime::nversion_oracle::{RuntimeEntry, RuntimeOracle};
use frankenengine_node::runtime::resource_governor::{
    ObservedValidationProcess, ResourceGovernorDecisionKind, ResourceGovernorObservation,
    ResourceGovernorRequest, ResourceGovernorSnapshotInput, ResourceGovernorThresholds,
    SnapshotProcessInput, evaluate_resource_governor, reason_codes,
};
use insta::assert_snapshot;
use serde_json::{Value, json};
use std::{fs, path::Path};
use tempfile::TempDir;

#[path = "cli_golden_helpers.rs"]
mod cli_golden_helpers;

use cli_golden_helpers::with_scrubbed_snapshot_settings;

fn franken_node() -> Command {
    Command::cargo_bin("franken-node").expect("franken-node test binary")
}

fn oracle_runtime(id: &str) -> RuntimeEntry {
    RuntimeEntry {
        runtime_id: id.to_string(),
        runtime_name: id.to_string(),
        version: "1.0.0".to_string(),
        is_reference: false,
    }
}

fn stdout_text(mut command: Command) -> String {
    let output = command.assert().success().get_output().stdout.clone();
    String::from_utf8(output).expect("stdout should be utf8")
}

fn stdout_json(command: Command) -> Value {
    let stdout = stdout_text(command);
    serde_json::from_str(&stdout).expect("stdout should be json")
}

fn rg_ts(second: u32) -> chrono::DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 5, 5, 12, 0, second)
        .single()
        .expect("valid timestamp")
}

fn rg_process(command: &str) -> ObservedValidationProcess {
    ObservedValidationProcess::new(None, command).expect("validation process should classify")
}

fn rg_request(
    requested_proof_class: Option<&str>,
    source_only_allowed: bool,
) -> ResourceGovernorRequest {
    ResourceGovernorRequest {
        trace_id: "runtime-cli-e2e".to_string(),
        requested_proof_class: requested_proof_class.map(ToOwned::to_owned),
        source_only_allowed,
    }
}

fn relative_cli_path(path: &Path) -> String {
    let cwd = std::env::current_dir().expect("current dir");
    path.strip_prefix(&cwd)
        .unwrap_or(path)
        .to_str()
        .expect("utf8 path")
        .to_string()
}

#[test]
fn resource_governor_allows_empty_process_snapshot() {
    let observation = ResourceGovernorObservation::new(rg_ts(0), "fixture", Vec::new());
    let report = evaluate_resource_governor(
        rg_request(Some("cargo-check"), false),
        observation,
        ResourceGovernorThresholds::default(),
        rg_ts(1),
    );

    assert_eq!(report.decision.kind, ResourceGovernorDecisionKind::Allow);
    assert_eq!(report.decision.reason_code, reason_codes::ALLOW_IDLE);
    assert_eq!(
        report.observation.process_counts.total_validation_processes,
        0
    );
    assert_eq!(report.structured_log.trace_id, "runtime-cli-e2e");
}

#[test]
fn resource_governor_dedupes_matching_active_proof_class() {
    let mut observation = ResourceGovernorObservation::new(
        rg_ts(0),
        "fixture",
        vec![
            rg_process("cargo check"),
            rg_process("rustc --crate-name demo"),
        ],
    );
    observation.merge_hints(None, vec!["cargo-check".to_string()], None, None, None);

    let report = evaluate_resource_governor(
        rg_request(Some("cargo-check"), false),
        observation,
        ResourceGovernorThresholds::default(),
        rg_ts(1),
    );

    assert_eq!(
        report.decision.kind,
        ResourceGovernorDecisionKind::DedupeOnly
    );
    assert_eq!(
        report.decision.reason_code,
        reason_codes::DEDUPE_ACTIVE_PROOF_CLASS
    );
    assert_eq!(report.decision.recommended_backoff_ms, 0);
}

#[test]
fn resource_governor_uses_source_only_when_pressure_is_high_and_allowed() {
    let mut observation = ResourceGovernorObservation::new(
        rg_ts(0),
        "fixture",
        vec![
            rg_process("cargo test -p frankenengine-node"),
            rg_process("rustc crate-a"),
            rg_process("rustc crate-b"),
            rg_process("rch exec -- cargo test"),
            rg_process("validation broker worker"),
            rg_process("proof executor"),
        ],
    );
    observation.merge_hints(Some(9), Vec::new(), None, None, None);

    let report = evaluate_resource_governor(
        rg_request(Some("cargo-test"), true),
        observation,
        ResourceGovernorThresholds::default(),
        rg_ts(1),
    );

    assert_eq!(
        report.decision.kind,
        ResourceGovernorDecisionKind::SourceOnly
    );
    assert_eq!(
        report.decision.reason_code,
        reason_codes::SOURCE_ONLY_CONTENTION
    );
    assert!(report.decision.recommended_backoff_ms > 0);
}

#[test]
fn resource_governor_defers_stale_observation() {
    let observation = ResourceGovernorObservation::new(rg_ts(0), "fixture", Vec::new());
    let report = evaluate_resource_governor(
        rg_request(Some("cargo-check"), false),
        observation,
        ResourceGovernorThresholds::default(),
        rg_ts(0) + chrono::Duration::milliseconds(300_001),
    );

    assert_eq!(report.decision.kind, ResourceGovernorDecisionKind::Defer);
    assert_eq!(
        report.decision.reason_code,
        reason_codes::DEFER_STALE_OBSERVATION
    );
}

#[test]
fn resource_governor_snapshot_input_sorts_and_counts_hints() {
    let observation = ResourceGovernorObservation::from_snapshot(
        ResourceGovernorSnapshotInput {
            observed_at: Some(rg_ts(0)),
            source: Some("unit-fixture".to_string()),
            processes: vec![
                SnapshotProcessInput {
                    pid: Some(10),
                    command: "rustc crate-a".to_string(),
                    kind: None,
                },
                SnapshotProcessInput {
                    pid: Some(11),
                    command: "cargo check".to_string(),
                    kind: None,
                },
            ],
            rch_queue_depth: Some(2),
            active_proof_classes: vec![
                "cargo-test".to_string(),
                "cargo-check".to_string(),
                "cargo-test".to_string(),
            ],
            target_dir_usage_mb: Some(8192),
            memory_used_mb: Some(64000),
            cpu_load_permyriad: Some(7500),
            artifact_inventory: Vec::new(),
            ..ResourceGovernorSnapshotInput::default()
        },
        rg_ts(1),
    )
    .expect("valid snapshot");

    assert_eq!(observation.source, "unit-fixture");
    assert_eq!(observation.process_counts.cargo, 1);
    assert_eq!(observation.process_counts.rustc, 1);
    assert_eq!(
        observation.active_proof_classes,
        vec!["cargo-check".to_string(), "cargo-test".to_string()]
    );
}

#[test]
fn ops_resource_governor_cli_reads_snapshot_json() {
    let dir = TempDir::new_in(".").expect("temp dir");
    let snapshot_path = dir.path().join("resource-governor-snapshot.json");
    let snapshot_arg = relative_cli_path(&snapshot_path);
    fs::write(
        &snapshot_path,
        json!({
            "source": "e2e-fixture",
            "processes": [
                {"pid": 31, "command": "cargo check -p frankenengine-node"},
                {"pid": 32, "command": "rustc --crate-name frankenengine_node"}
            ],
            "rch_queue_depth": 2,
            "active_proof_classes": ["cargo-check"]
        })
        .to_string(),
    )
    .expect("write snapshot");

    let mut command = franken_node();
    command.args([
        "ops",
        "resource-governor",
        "--process-snapshot",
        snapshot_arg.as_str(),
        "--requested-proof-class",
        "cargo-check",
        "--trace-id",
        "runtime-cli-e2e",
        "--json",
    ]);

    let payload = stdout_json(command);
    assert_eq!(
        payload["schema_version"],
        "franken-node/resource-governor/report/v1"
    );
    assert_eq!(payload["command"], "ops resource-governor");
    assert_eq!(payload["trace_id"], "runtime-cli-e2e");
    assert_eq!(payload["observation"]["source"], "e2e-fixture");
    assert_eq!(
        payload["observation"]["process_counts"]["total_validation_processes"],
        2
    );
    assert_eq!(payload["decision"]["kind"], "dedupe_only");
    assert_eq!(
        payload["decision"]["reason_code"],
        reason_codes::DEDUPE_ACTIVE_PROOF_CLASS
    );
}

#[test]
fn ops_resource_governor_cli_human_output_names_decision_and_backoff() {
    let dir = TempDir::new_in(".").expect("temp dir");
    let snapshot_path = dir.path().join("resource-governor-snapshot.json");
    let snapshot_arg = relative_cli_path(&snapshot_path);
    fs::write(
        &snapshot_path,
        json!({
            "source": "human-fixture",
            "processes": [
                {"pid": 41, "command": "cargo test"},
                {"pid": 42, "command": "rustc crate-a"},
                {"pid": 43, "command": "rustc crate-b"},
                {"pid": 44, "command": "rch exec -- cargo test"},
                {"pid": 45, "command": "validation proof"},
                {"pid": 46, "command": "proof runner"}
            ]
        })
        .to_string(),
    )
    .expect("write snapshot");

    let mut command = franken_node();
    command.args([
        "ops",
        "resource-governor",
        "--process-snapshot",
        snapshot_arg.as_str(),
        "--requested-proof-class",
        "cargo-test",
        "--trace-id",
        "runtime-cli-human",
    ]);

    let stdout = stdout_text(command);
    assert!(stdout.contains("ops resource-governor: decision=defer"));
    assert!(stdout.contains("reason_code=RG_DEFER_CONTENTION"));
    assert!(stdout.contains("recommended_backoff_ms=180000"));
}

#[test]
fn runtime_lane_status_reports_default_policy() {
    let mut command = franken_node();
    command.args(["runtime", "lane", "status", "--json"]);

    let payload = stdout_json(command);

    assert_eq!(payload["schema_version"], "ls-v1.0");
    assert_eq!(payload["command"], "runtime.lane.status");
    assert!(payload["policy"]["lane_configs"]["control_critical"].is_object());
    assert_eq!(
        payload["policy"]["mapping_rules"]["epoch_transition"],
        "ControlCritical"
    );
    assert!(payload["telemetry"]["counters"].as_array().unwrap().len() >= 4);
}

#[test]
fn runtime_lane_assign_routes_task_class() {
    let mut command = franken_node();
    command.args([
        "runtime",
        "lane",
        "assign",
        "epoch_transition",
        "--timestamp-ms",
        "1700000000000",
        "--trace-id",
        "runtime-cli-e2e",
        "--json",
    ]);

    let payload = stdout_json(command);

    assert_eq!(payload["schema_version"], "ls-v1.0");
    assert_eq!(payload["command"], "runtime.lane.assign");
    assert_eq!(payload["assignment"]["task_class"], "epoch_transition");
    assert_eq!(payload["assignment"]["lane"], "ControlCritical");
    assert_eq!(payload["assignment"]["trace_id"], "runtime-cli-e2e");
}

#[test]
fn runtime_epoch_reports_mismatch_delta() {
    let mut command = franken_node();
    command.args([
        "runtime",
        "epoch",
        "--local-epoch",
        "7",
        "--peer-epoch",
        "9",
        "--json",
    ]);

    let stdout = stdout_text(command);
    let payload: Value = serde_json::from_str(&stdout).expect("stdout should be json");

    assert_eq!(payload["schema_version"], "runtime-epoch-v1");
    assert_eq!(payload["command"], "runtime.epoch");
    assert_eq!(payload["verdict"], "mismatch");
    assert_eq!(payload["epoch_delta"], 2);

    with_scrubbed_snapshot_settings("runtime_cli", || {
        assert_snapshot!("runtime_epoch_mismatch_json", stdout.trim_end());
    });
}

#[test]
fn runtime_oracle_quorum_uses_integer_ceiling() {
    let mut strict_oracle = RuntimeOracle::new("runtime-quorum-67", 67);
    strict_oracle
        .register_runtime(oracle_runtime("runtime-a"))
        .expect("register runtime a");
    strict_oracle
        .register_runtime(oracle_runtime("runtime-b"))
        .expect("register runtime b");
    strict_oracle
        .register_runtime(oracle_runtime("runtime-c"))
        .expect("register runtime c");

    strict_oracle
        .vote("check", "runtime-a", b"same".to_vec())
        .expect("vote a");
    strict_oracle
        .vote("check", "runtime-b", b"same".to_vec())
        .expect("vote b");
    let strict_result = strict_oracle.tally_votes("check").expect("tally strict");
    assert_eq!(strict_result.quorum_threshold, 3);
    assert!(!strict_result.quorum_reached);

    let mut majority_oracle = RuntimeOracle::new("runtime-quorum-66", 66);
    majority_oracle
        .register_runtime(oracle_runtime("runtime-a"))
        .expect("register runtime a");
    majority_oracle
        .register_runtime(oracle_runtime("runtime-b"))
        .expect("register runtime b");
    majority_oracle
        .register_runtime(oracle_runtime("runtime-c"))
        .expect("register runtime c");
    majority_oracle
        .vote("check", "runtime-a", b"same".to_vec())
        .expect("vote a");
    majority_oracle
        .vote("check", "runtime-b", b"same".to_vec())
        .expect("vote b");
    let majority_result = majority_oracle
        .tally_votes("check")
        .expect("tally majority");
    assert_eq!(majority_result.quorum_threshold, 2);
    assert!(majority_result.quorum_reached);
}

// ── K-9 (EngineIdentity) oracle self-comparison guard (gauntlet bd-rjc2m.K9 / H-002) ──
// Placed in this WIRED integration target because the crate's inline `#[cfg(test)]` tests do
// not run ([lib] test = false). These exercise the public register_runtime / executor_fingerprint
// guards that prevent one executor faking byte-identical "agreement" with itself.

fn k9_entry(id: &str, name: &str, version: &str, is_ref: bool) -> RuntimeEntry {
    RuntimeEntry {
        runtime_id: id.to_string(),
        runtime_name: name.to_string(),
        version: version.to_string(),
        is_reference: is_ref,
    }
}

#[test]
fn k9_register_rejects_same_executor_under_two_ids() {
    use frankenengine_node::runtime::nversion_oracle::error_codes;
    let mut oracle = RuntimeOracle::new("k9-collision", 100);
    oracle
        .register_runtime(k9_entry("node", "node", "20.0", true))
        .expect("first registration ok");
    // Same (name, version) under a DIFFERENT runtime_id == same executor -> must be rejected.
    let err = oracle
        .register_runtime(k9_entry("node-copy", "node", "20.0", true))
        .expect_err("same executor under a second id must be rejected (K-9)");
    assert_eq!(err.code, error_codes::ERR_NVO_FINGERPRINT_COLLISION);
    assert_eq!(oracle.runtime_count(), 1, "collision must not be registered");
}

#[test]
fn k9_register_allows_genuinely_distinct_runtimes() {
    let mut oracle = RuntimeOracle::new("k9-distinct", 100);
    oracle
        .register_runtime(k9_entry("node", "node", "20.0", true))
        .expect("node");
    oracle
        .register_runtime(k9_entry("bun", "bun", "1.3", true))
        .expect("bun");
    oracle
        .register_runtime(k9_entry("franken", "franken-node", "0.1", false))
        .expect("franken");
    assert_eq!(oracle.runtime_count(), 3);
}

#[test]
fn k9_duplicate_id_precedence_and_fingerprint_helpers() {
    use frankenengine_node::runtime::nversion_oracle::error_codes;
    let mut oracle = RuntimeOracle::new("k9-dup", 100);
    oracle
        .register_runtime(k9_entry("node", "node", "20.0", true))
        .expect("first");
    // Same id, different name -> duplicate-id check fires first (not the fingerprint check).
    let err = oracle
        .register_runtime(k9_entry("node", "other", "99", false))
        .expect_err("duplicate id");
    assert_eq!(err.code, error_codes::ERR_NVO_DUPLICATE_RUNTIME);
    // executor_fingerprint: equal for same (name,version); distinct otherwise; length-prefixed.
    let a = k9_entry("a", "node", "20.0", true);
    let b = k9_entry("b", "node", "20.0", false);
    let c = k9_entry("c", "bun", "1.3", true);
    assert_eq!(a.executor_fingerprint(), b.executor_fingerprint());
    assert_ne!(a.executor_fingerprint(), c.executor_fingerprint());
    assert_ne!(
        k9_entry("x", "ab", "c", true).executor_fingerprint(),
        k9_entry("y", "a", "bc", true).executor_fingerprint()
    );
}
