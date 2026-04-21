use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Instant;

use frankenengine_node::tools::replay_bundle::{
    EventType, INCIDENT_EVIDENCE_SCHEMA, IncidentEvidenceEvent, IncidentEvidenceMetadata,
    IncidentEvidencePackage, IncidentSeverity, ReplayBundle, read_bundle_from_path,
    validate_bundle_integrity,
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

fn write_receipt_signing_key(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create key dir");
    }
    fs::write(path, hex::encode([42_u8; 32])).expect("write receipt signing key");
}

fn configure_replay_bundle_signing_key(workspace: &Path) {
    fs::write(
        workspace.join("franken_node.toml"),
        "profile = \"balanced\"\n\n[security]\ndecision_receipt_signing_key_path = \"keys/receipt-signing.key\"\n",
    )
    .expect("write config with signing key");
    write_receipt_signing_key(&workspace.join("keys/receipt-signing.key"));
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

fn write_dense_fixture_incident_evidence(path: &Path, incident_id: &str, event_count: usize) {
    assert!(event_count > 0, "event_count must be non-zero");
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create evidence dir");
    }

    let mut events = Vec::with_capacity(event_count);
    let mut refs = Vec::with_capacity(event_count);
    for idx in 0..event_count {
        let event_id = format!("evt-{:03}", idx + 1);
        let reference = format!("refs/logs/{event_id}.json");
        let confidence = if idx % 2 == 0 { 50_u64 } else { 30_u64 };
        let event_type = match idx % 3 {
            0 => EventType::ExternalSignal,
            1 => EventType::PolicyEval,
            _ => EventType::OperatorAction,
        };
        events.push(IncidentEvidenceEvent {
            event_id: event_id.clone(),
            timestamp: format!("2026-02-20T10:00:{idx:02}.000000Z"),
            event_type,
            payload: json!({
                "signal": format!("incident-step-{idx}"),
                "confidence": confidence,
                "degraded_mode": true,
                "mode": "degraded",
            }),
            provenance_ref: reference.clone(),
            parent_event_id: idx
                .checked_sub(1)
                .map(|parent| format!("evt-{:03}", parent + 1)),
            state_snapshot: None,
            policy_version: None,
        });
        refs.push(reference);
    }

    let package = IncidentEvidencePackage {
        schema_version: INCIDENT_EVIDENCE_SCHEMA.to_string(),
        incident_id: incident_id.to_string(),
        collected_at: "2026-02-20T10:05:00.000000Z".to_string(),
        trace_id: "trace-incident-pipeline-e2e".to_string(),
        severity: IncidentSeverity::Critical,
        incident_type: "security".to_string(),
        detector: "incident-pipeline-e2e".to_string(),
        policy_version: "balanced".to_string(),
        initial_state_snapshot: json!({"epoch": 11_u64, "mode": "degraded"}),
        events,
        evidence_refs: refs,
        metadata: IncidentEvidenceMetadata {
            title: "Dense fixture incident evidence".to_string(),
            affected_components: vec!["auth-svc".to_string(), "edge-gateway".to_string()],
            tags: vec!["fixture".to_string(), "pipeline".to_string()],
        },
    };
    fs::write(
        path,
        serde_json::to_string_pretty(&package).expect("serialize evidence package"),
    )
    .expect("write evidence package");
}

fn replay_result_line(stderr: &str) -> &str {
    stderr
        .lines()
        .find(|line| line.starts_with("incident replay result: "))
        .unwrap_or_else(|| panic!("missing replay result line in stderr: {stderr}"))
}

fn parse_replay_result(stderr: &str) -> (bool, usize, String, String) {
    let line = replay_result_line(stderr);
    let payload = line
        .strip_prefix("incident replay result: ")
        .expect("replay result prefix");
    let mut matched = None;
    let mut event_count = None;
    let mut expected = None;
    let mut replayed = None;
    for part in payload.split_whitespace() {
        let Some((key, value)) = part.split_once('=') else {
            continue;
        };
        match key {
            "matched" => matched = Some(value == "true"),
            "event_count" => event_count = Some(value.parse::<usize>().expect("event_count")),
            "expected" => expected = Some(value.to_string()),
            "replayed" => replayed = Some(value.to_string()),
            _ => {}
        }
    }
    (
        matched.expect("matched"),
        event_count.expect("event_count"),
        expected.expect("expected"),
        replayed.expect("replayed"),
    )
}

fn parse_counterfactual_output(stderr: &str) -> serde_json::Value {
    let line = stderr
        .lines()
        .find(|line| line.starts_with("counterfactual output: "))
        .unwrap_or_else(|| panic!("missing counterfactual output line in stderr: {stderr}"));
    let canonical = line
        .strip_prefix("counterfactual output: ")
        .expect("counterfactual prefix");
    serde_json::from_str(canonical).expect("parse counterfactual output json")
}

fn corrupt_bundle_integrity_hash(path: &Path) -> (String, String) {
    let contents = fs::read_to_string(path).expect("read bundle");
    let marker = "\"integrity_hash\":\"";
    let start = contents
        .find(marker)
        .map(|idx| idx + marker.len())
        .expect("integrity hash marker");
    let end = start
        + contents[start..]
            .find('"')
            .expect("integrity hash terminator");
    let original_hash = contents[start..end].to_string();

    let mut bytes = contents.into_bytes();
    bytes[start] = match bytes[start] {
        b'0' => b'1',
        b'1' => b'0',
        _ => b'0',
    };
    fs::write(path, &bytes).expect("write corrupted bundle");

    let updated = String::from_utf8(bytes).expect("utf8 bundle");
    let corrupted_hash = updated[start..end].to_string();
    (original_hash, corrupted_hash)
}

#[test]
fn incident_bundle_accepts_explicit_evidence_path_and_writes_bundle() {
    let workspace = config_only_workspace();
    configure_replay_bundle_signing_key(workspace.path());
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
    let signature = bundle.signature.expect("signed replay bundle");
    assert_eq!(signature.algorithm, "ed25519");
    assert_eq!(signature.key_source, "config");
    assert_eq!(signature.signing_identity, "incident-control-plane");
    assert_eq!(signature.trust_scope, "incident_replay_bundle");
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

#[test]
fn incident_bundle_receipt_export_fails_when_signing_key_missing() {
    let workspace = config_only_workspace();
    let evidence_path = workspace
        .path()
        .join("fixtures/incidents/INC-E2E-NOSIGN-001/evidence.v1.json");
    write_dense_fixture_incident_evidence(&evidence_path, "INC-E2E-NOSIGN-001", 3);
    let evidence_arg = evidence_path.to_string_lossy().to_string();
    let receipt_out = workspace.path().join("receipts/bundle-receipt.json");

    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident",
            "bundle",
            "--id",
            "INC-E2E-NOSIGN-001",
            "--evidence-path",
            &evidence_arg,
            "--receipt-out",
            receipt_out.to_str().expect("utf8 receipt path"),
        ],
    );
    assert!(
        !output.status.success(),
        "expected receipt export without a key to fail"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("receipt export requested but no signing key was configured"));
    assert!(stderr.contains(
        "fix_command=mkdir -p .franken-node/keys && openssl rand -hex 32 > .franken-node/keys/receipt-signing.key"
    ));
    assert!(
        !receipt_out.exists(),
        "receipt export should not be written on failure"
    );
    assert!(
        !workspace
            .path()
            .join("INC-E2E-NOSIGN-001.fnbundle")
            .exists(),
        "bundle should not be written when receipt export fails"
    );
}

#[test]
fn incident_replay_counterfactual_pipeline_is_deterministic_and_fail_closed() {
    let workspace = config_only_workspace();
    configure_replay_bundle_signing_key(workspace.path());
    let evidence_path = workspace
        .path()
        .join("fixtures/incidents/INC-E2E-PIPE-001/evidence.v1.json");
    write_dense_fixture_incident_evidence(&evidence_path, "INC-E2E-PIPE-001", 10);
    let evidence_arg = evidence_path.to_string_lossy().to_string();

    let bundle_output = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident",
            "bundle",
            "--id",
            "INC-E2E-PIPE-001",
            "--evidence-path",
            &evidence_arg,
            "--verify",
        ],
    );
    assert!(
        bundle_output.status.success(),
        "incident bundle failed: {}",
        String::from_utf8_lossy(&bundle_output.stderr)
    );
    let bundle_stderr = String::from_utf8_lossy(&bundle_output.stderr);
    assert!(bundle_stderr.contains("bundle integrity: valid"));
    assert!(bundle_stderr.contains("incident bundle written:"));

    let bundle_path = workspace.path().join("INC-E2E-PIPE-001.fnbundle");
    let bundle = read_bundle_from_path(&bundle_path).expect("read bundle");
    assert_eq!(bundle.timeline.len(), 10);
    assert_eq!(
        bundle.initial_state_snapshot,
        json!({"epoch": 11_u64, "mode": "degraded"})
    );

    let mut replay_hashes = Vec::new();
    let replay_started = Instant::now();
    for _ in 0..3 {
        let replay_output = run_cli_in_workspace(
            workspace.path(),
            &[
                "incident",
                "replay",
                "--bundle",
                "INC-E2E-PIPE-001.fnbundle",
            ],
        );
        assert!(
            replay_output.status.success(),
            "incident replay failed: {}",
            String::from_utf8_lossy(&replay_output.stderr)
        );
        let replay_stderr = String::from_utf8_lossy(&replay_output.stderr);
        let (matched, event_count, expected, replayed) = parse_replay_result(&replay_stderr);
        assert!(matched, "replay should match: {replay_stderr}");
        assert_eq!(event_count, 10);
        assert_eq!(expected, replayed);
        replay_hashes.push((expected, replayed));
    }
    assert!(
        replay_started.elapsed().as_secs_f64() < 5.0,
        "three sequential replays of a 10-event bundle should finish well under 5 seconds"
    );
    assert!(
        replay_hashes.windows(2).all(|pair| pair[0] == pair[1]),
        "replay hashes must be stable across repeated runs: {replay_hashes:?}"
    );

    let counterfactual_output = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident",
            "counterfactual",
            "--bundle",
            "INC-E2E-PIPE-001.fnbundle",
            "--policy",
            "strict",
        ],
    );
    assert!(
        counterfactual_output.status.success(),
        "counterfactual failed: {}",
        String::from_utf8_lossy(&counterfactual_output.stderr)
    );
    let counterfactual_stderr = String::from_utf8_lossy(&counterfactual_output.stderr);
    assert!(counterfactual_stderr.contains("counterfactual summary:"));
    let counterfactual_json = parse_counterfactual_output(&counterfactual_stderr);
    assert_eq!(counterfactual_json["mode"], "single");
    assert_eq!(
        counterfactual_json["summary_statistics"]["total_decisions"],
        json!(10)
    );
    assert!(
        counterfactual_json["summary_statistics"]["changed_decisions"]
            .as_u64()
            .expect("changed decisions")
            > 0,
        "strict counterfactual should produce decision deltas: {counterfactual_json}"
    );

    let corrupted_path = workspace.path().join("INC-E2E-PIPE-001-corrupt.fnbundle");
    fs::copy(&bundle_path, &corrupted_path).expect("copy bundle for corruption");
    let (original_hash, corrupted_hash) = corrupt_bundle_integrity_hash(&corrupted_path);
    assert_ne!(
        original_hash, corrupted_hash,
        "single-byte corruption must change the hash"
    );

    let corrupted_bundle: ReplayBundle =
        serde_json::from_str(&fs::read_to_string(&corrupted_path).expect("corrupted bundle text"))
            .expect("parse corrupted bundle");
    assert!(
        !validate_bundle_integrity(&corrupted_bundle).expect("validate corrupted bundle"),
        "corrupted bundle should fail integrity validation"
    );

    let corrupted_output = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident",
            "replay",
            "--bundle",
            "INC-E2E-PIPE-001-corrupt.fnbundle",
        ],
    );
    assert!(
        !corrupted_output.status.success(),
        "corrupted bundle replay should fail closed"
    );
    let corrupted_stderr = String::from_utf8_lossy(&corrupted_output.stderr);
    assert!(corrupted_stderr.contains("bundle integrity mismatch"));
}
