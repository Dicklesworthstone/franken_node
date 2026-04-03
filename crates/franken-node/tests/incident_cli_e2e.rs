use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use frankenengine_node::tools::replay_bundle::{
    EventType, INCIDENT_EVIDENCE_SCHEMA, IncidentEvidenceEvent, IncidentEvidenceMetadata,
    IncidentEvidencePackage, IncidentSeverity, read_bundle_from_path,
};
use serde_json::json;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn resolve_binary_path() -> PathBuf {
    if let Some(exe) = std::env::var_os("CARGO_BIN_EXE_franken-node") {
        return PathBuf::from(exe);
    }
    repo_root().join("target/debug/franken-node")
}

fn run_cli_in_workspace(workspace: &Path, args: &[&str]) -> Output {
    let binary_path = resolve_binary_path();
    assert!(
        binary_path.is_file(),
        "franken-node binary not found at {}",
        binary_path.display()
    );
    Command::new(&binary_path)
        .current_dir(workspace)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed running `{}`: {err}", args.join(" ")))
}

fn config_only_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(
        dir.path().join("franken_node.toml"),
        "profile = \"balanced\"\n",
    )
    .expect("write config");
    dir
}

fn write_fixture_incident_evidence(path: &Path, incident_id: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create evidence dir");
    }
    let package = IncidentEvidencePackage {
        schema_version: INCIDENT_EVIDENCE_SCHEMA.to_string(),
        incident_id: incident_id.to_string(),
        collected_at: "2026-02-20T10:05:00.000000Z".to_string(),
        trace_id: "trace-incident-e2e".to_string(),
        severity: IncidentSeverity::High,
        incident_type: "security".to_string(),
        detector: "incident-cli-e2e".to_string(),
        policy_version: "1.2.3".to_string(),
        initial_state_snapshot: json!({"epoch": 7_u64, "mode": "strict"}),
        events: vec![
            IncidentEvidenceEvent {
                event_id: "evt-001".to_string(),
                timestamp: "2026-02-20T10:00:00.000100Z".to_string(),
                event_type: EventType::ExternalSignal,
                payload: json!({"signal":"anomaly","severity":"high"}),
                provenance_ref: "refs/logs/event-001.json".to_string(),
                parent_event_id: None,
                state_snapshot: None,
                policy_version: None,
            },
            IncidentEvidenceEvent {
                event_id: "evt-002".to_string(),
                timestamp: "2026-02-20T10:00:00.000200Z".to_string(),
                event_type: EventType::PolicyEval,
                payload: json!({"decision":"quarantine","confidence":91_u64}),
                provenance_ref: "refs/logs/event-002.json".to_string(),
                parent_event_id: Some("evt-001".to_string()),
                state_snapshot: None,
                policy_version: None,
            },
            IncidentEvidenceEvent {
                event_id: "evt-003".to_string(),
                timestamp: "2026-02-20T10:00:00.000300Z".to_string(),
                event_type: EventType::OperatorAction,
                payload: json!({"action":"seal","result":"accepted"}),
                provenance_ref: "refs/logs/event-003.json".to_string(),
                parent_event_id: Some("evt-002".to_string()),
                state_snapshot: None,
                policy_version: None,
            },
        ],
        evidence_refs: vec![
            "refs/logs/event-001.json".to_string(),
            "refs/logs/event-002.json".to_string(),
            "refs/logs/event-003.json".to_string(),
        ],
        metadata: IncidentEvidenceMetadata {
            title: "Fixture incident evidence".to_string(),
            affected_components: vec!["auth-svc".to_string()],
            tags: vec!["fixture".to_string(), "test".to_string()],
        },
    };
    fs::write(
        path,
        serde_json::to_string_pretty(&package).expect("serialize evidence package"),
    )
    .expect("write evidence package");
}

#[test]
fn incident_bundle_accepts_explicit_evidence_path_and_writes_bundle() {
    let workspace = config_only_workspace();
    let evidence_path = workspace
        .path()
        .join("fixtures/incidents/INC-E2E-001/evidence.v1.json");
    write_fixture_incident_evidence(&evidence_path, "INC-E2E-001");
    let evidence_arg = evidence_path.to_string_lossy().to_string();

    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident",
            "bundle",
            "--id",
            "INC-E2E-001",
            "--evidence-path",
            &evidence_arg,
            "--verify",
        ],
    );
    assert!(
        output.status.success(),
        "incident bundle failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("incident bundle written:"));
    assert!(stderr.contains("evidence="));

    let output_path = workspace.path().join("INC-E2E-001.fnbundle");
    assert!(output_path.is_file());

    let bundle = read_bundle_from_path(&output_path).expect("read bundle");
    assert_eq!(bundle.incident_id, "INC-E2E-001");
    assert_eq!(
        bundle.initial_state_snapshot,
        json!({"epoch": 7_u64, "mode": "strict"})
    );
    assert_eq!(bundle.policy_version, "1.2.3");
    assert_eq!(bundle.timeline.len(), 3);
}

#[test]
fn incident_bundle_fails_closed_when_authoritative_evidence_is_missing() {
    let workspace = config_only_workspace();

    let output = run_cli_in_workspace(
        workspace.path(),
        &["incident", "bundle", "--id", "INC-E2E-MISSING-001"],
    );
    assert!(
        !output.status.success(),
        "incident bundle should fail when evidence is missing"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed reading authoritative incident evidence"));
    assert!(
        !workspace
            .path()
            .join("INC-E2E-MISSING-001.fnbundle")
            .exists()
    );
}
