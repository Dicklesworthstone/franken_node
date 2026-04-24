use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::Instant;

use frankenengine_node::tools::replay_bundle::{
    EventType, INCIDENT_EVIDENCE_SCHEMA, IncidentEvidenceEvent, IncidentEvidenceMetadata,
    IncidentEvidencePackage, IncidentSeverity, ReplayBundle,
    read_bundle_from_path_with_trusted_key, validate_bundle_integrity,
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

    // Generate real ed25519 signing key for decision receipts
    // Note: Using fixed seed for test determinism, not cryptographically random
    let test_seed = [0x42_u8; 32]; // Deterministic test seed
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&test_seed);

    // Write hex-encoded seed bytes as expected by the signing key loader
    fs::write(path, hex::encode(signing_key.to_bytes())).expect("write receipt signing key");
}

fn write_replay_trust_anchor(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create key dir");
    }
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x42_u8; 32]);
    fs::write(path, hex::encode(signing_key.verifying_key().to_bytes()))
        .expect("write replay trust anchor");
}

fn replay_bundle_trusted_key_id() -> String {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42_u8; 32]);
    frankenengine_node::supply_chain::artifact_signing::KeyId::from_verifying_key(
        &signing_key.verifying_key(),
    )
    .to_string()
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

fn replay_result_contract_json(stderr: &str) -> serde_json::Value {
    let (matched, event_count, expected, replayed) = parse_replay_result(stderr);
    json!({
        "schema_version": "franken-node/incident-replay-result-golden/v1",
        "matched": matched,
        "event_count": event_count,
        "expected_sequence_hash": expected,
        "replayed_sequence_hash": replayed,
    })
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

fn assert_incident_json_golden(name: &str, value: &serde_json::Value) {
    let golden_path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/golden/incident")
        .join(format!("{name}.golden"));
    let actual = serde_json::to_string_pretty(value).expect("serialize incident golden");

    if std::env::var_os("UPDATE_GOLDENS").is_some() {
        if let Some(parent) = golden_path.parent() {
            fs::create_dir_all(parent).expect("create incident golden dir");
        }
        fs::write(&golden_path, format!("{actual}\n")).expect("write incident golden");
        eprintln!("[GOLDEN] Updated: {}", golden_path.display());
        return;
    }

    let expected = fs::read_to_string(&golden_path)
        .unwrap_or_else(|err| panic!("read golden {}: {err}", golden_path.display()));
    if expected.trim_end() != actual {
        let actual_path = golden_path.with_extension("actual");
        fs::write(&actual_path, format!("{actual}\n")).expect("write actual incident golden");
        panic!(
            "golden mismatch for {}; wrote actual to {}",
            golden_path.display(),
            actual_path.display()
        );
    }
}

fn incident_bundle_contract_json(bundle: &ReplayBundle) -> serde_json::Value {
    let signature = bundle.signature.as_ref().expect("signed replay bundle");
    json!({
        "schema_version": "franken-node/incident-replay-bundle-golden/v1",
        "bundle_id": bundle.bundle_id.to_string(),
        "incident_id": &bundle.incident_id,
        "created_at": &bundle.created_at,
        "policy_version": &bundle.policy_version,
        "initial_state_snapshot": &bundle.initial_state_snapshot,
        "manifest": &bundle.manifest,
        "integrity_hash": &bundle.integrity_hash,
        "signature": {
            "algorithm": &signature.algorithm,
            "public_key_hex": &signature.public_key_hex,
            "key_id": &signature.key_id,
            "key_source": &signature.key_source,
            "signing_identity": &signature.signing_identity,
            "trust_scope": &signature.trust_scope,
            "signed_payload_sha256": &signature.signed_payload_sha256,
            "signature_hex": &signature.signature_hex,
        },
        "timeline": bundle.timeline.iter().map(|event| {
            json!({
                "sequence_number": event.sequence_number,
                "timestamp": &event.timestamp,
                "event_type": &event.event_type,
                "payload": &event.payload,
                "causal_parent": event.causal_parent,
            })
        }).collect::<Vec<_>>(),
        "chunks": bundle.chunks.iter().map(|chunk| {
            json!({
                "bundle_id": chunk.bundle_id.to_string(),
                "chunk_index": chunk.chunk_index,
                "total_chunks": chunk.total_chunks,
                "event_count": chunk.event_count,
                "first_sequence_number": chunk.first_sequence_number,
                "last_sequence_number": chunk.last_sequence_number,
                "compressed_size_bytes": chunk.compressed_size_bytes,
                "chunk_hash": &chunk.chunk_hash,
                "event_sequence_numbers": chunk
                    .events
                    .iter()
                    .map(|event| event.sequence_number)
                    .collect::<Vec<_>>(),
            })
        }).collect::<Vec<_>>(),
    })
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

    let trusted_key_id = replay_bundle_trusted_key_id();
    let bundle = read_bundle_from_path_with_trusted_key(&output_path, Some(&trusted_key_id))
        .expect("read bundle");
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
    let trust_anchor_path = workspace.path().join("keys/replay-trust-anchor.pub");
    write_replay_trust_anchor(&trust_anchor_path);
    let trust_anchor_arg = trust_anchor_path.to_string_lossy().to_string();
    let trusted_key_id = replay_bundle_trusted_key_id();
    let bundle = read_bundle_from_path_with_trusted_key(&bundle_path, Some(&trusted_key_id))
        .expect("read bundle");
    assert_eq!(bundle.timeline.len(), 10);
    assert_eq!(
        bundle.initial_state_snapshot,
        json!({"epoch": 11_u64, "mode": "degraded"})
    );
    assert_incident_json_golden(
        "replay_bundle_contract",
        &incident_bundle_contract_json(&bundle),
    );

    let mut replay_hashes = Vec::new();
    let mut replay_contract = None;
    let replay_started = Instant::now();
    for _ in 0..3 {
        let replay_output = run_cli_in_workspace(
            workspace.path(),
            &[
                "incident",
                "replay",
                "--bundle",
                "INC-E2E-PIPE-001.fnbundle",
                "--trusted-public-key",
                &trust_anchor_arg,
            ],
        );
        assert!(
            replay_output.status.success(),
            "incident replay failed: {}",
            String::from_utf8_lossy(&replay_output.stderr)
        );
        let replay_stderr = String::from_utf8_lossy(&replay_output.stderr);
        if replay_contract.is_none() {
            replay_contract = Some(replay_result_contract_json(&replay_stderr));
        }
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
    assert_incident_json_golden(
        "replay_result_contract",
        replay_contract.as_ref().expect("replay contract"),
    );

    let counterfactual_output = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident",
            "counterfactual",
            "--bundle",
            "INC-E2E-PIPE-001.fnbundle",
            "--trusted-public-key",
            &trust_anchor_arg,
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
    assert_incident_json_golden("counterfactual_strict_contract", &counterfactual_json);

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
            "--trusted-public-key",
            &trust_anchor_arg,
        ],
    );
    assert!(
        !corrupted_output.status.success(),
        "corrupted bundle replay should fail closed"
    );
    let corrupted_stderr = String::from_utf8_lossy(&corrupted_output.stderr);
    assert!(corrupted_stderr.contains("bundle integrity mismatch"));
}

// Boundary testing for malformed evidence packages (bd-1wdtq)

#[test]
fn incident_bundle_rejects_empty_events_array() {
    let workspace = config_only_workspace();
    configure_replay_bundle_signing_key(workspace.path());
    let evidence_path = workspace
        .path()
        .join("fixtures/incidents/INC-EMPTY-EVENTS/evidence.v1.json");

    // Write malformed evidence with empty events array
    write_malformed_evidence_empty_events(&evidence_path, "INC-EMPTY-EVENTS");
    let evidence_arg = evidence_path.to_string_lossy().to_string();

    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident",
            "bundle",
            "--id",
            "INC-EMPTY-EVENTS",
            "--evidence-path",
            &evidence_arg,
        ],
    );

    // Should fail closed with specific error
    assert!(
        !output.status.success(),
        "bundle creation should fail with empty events array"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("evidence package validation failed"));
    assert!(stderr.contains("events array cannot be empty"));

    // Bundle file should not be created
    assert!(
        !workspace.path().join("INC-EMPTY-EVENTS.fnbundle").exists(),
        "no bundle file should be created on validation failure"
    );
}

#[test]
fn incident_bundle_rejects_mismatched_incident_id() {
    let workspace = config_only_workspace();
    configure_replay_bundle_signing_key(workspace.path());
    let evidence_path = workspace
        .path()
        .join("fixtures/incidents/INC-MISMATCH/evidence.v1.json");

    // Write evidence with different incident_id than what CLI expects
    write_fixture_incident_evidence(&evidence_path, "INC-DIFFERENT-ID");
    let evidence_arg = evidence_path.to_string_lossy().to_string();

    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident",
            "bundle",
            "--id",
            "INC-MISMATCH", // CLI expects this ID
            "--evidence-path",
            &evidence_arg, // But evidence contains INC-DIFFERENT-ID
        ],
    );

    // Should fail closed with specific error
    assert!(
        !output.status.success(),
        "bundle creation should fail with mismatched incident ID"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("incident ID mismatch"));
    assert!(stderr.contains("expected: INC-MISMATCH"));
    assert!(stderr.contains("found in evidence: INC-DIFFERENT-ID"));

    // Bundle file should not be created
    assert!(
        !workspace.path().join("INC-MISMATCH.fnbundle").exists(),
        "no bundle file should be created on ID validation failure"
    );
}

#[test]
fn incident_bundle_rejects_duplicate_event_ids() {
    let workspace = config_only_workspace();
    configure_replay_bundle_signing_key(workspace.path());
    let evidence_path = workspace
        .path()
        .join("fixtures/incidents/INC-DUP-EVENT/evidence.v1.json");

    // Write malformed evidence with duplicate event_id
    write_malformed_evidence_duplicate_event_id(&evidence_path, "INC-DUP-EVENT");
    let evidence_arg = evidence_path.to_string_lossy().to_string();

    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident",
            "bundle",
            "--id",
            "INC-DUP-EVENT",
            "--evidence-path",
            &evidence_arg,
        ],
    );

    // Should fail closed with specific error
    assert!(
        !output.status.success(),
        "bundle creation should fail with duplicate event IDs"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("duplicate event ID detected"));
    assert!(stderr.contains("evt-duplicate"));

    // Bundle file should not be created
    assert!(
        !workspace.path().join("INC-DUP-EVENT.fnbundle").exists(),
        "no bundle file should be created on duplicate event validation failure"
    );
}

#[test]
fn incident_bundle_rejects_invalid_parent_event_references() {
    let workspace = config_only_workspace();
    configure_replay_bundle_signing_key(workspace.path());
    let evidence_path = workspace
        .path()
        .join("fixtures/incidents/INC-INVALID-REF/evidence.v1.json");

    // Write malformed evidence with invalid parent_event_id reference
    write_malformed_evidence_invalid_parent_ref(&evidence_path, "INC-INVALID-REF");
    let evidence_arg = evidence_path.to_string_lossy().to_string();

    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident",
            "bundle",
            "--id",
            "INC-INVALID-REF",
            "--evidence-path",
            &evidence_arg,
        ],
    );

    // Should fail closed with specific error
    assert!(
        !output.status.success(),
        "bundle creation should fail with invalid parent event reference"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid parent event reference"));
    assert!(stderr.contains("evt-nonexistent"));

    // Bundle file should not be created
    assert!(
        !workspace.path().join("INC-INVALID-REF.fnbundle").exists(),
        "no bundle file should be created on reference validation failure"
    );
}

#[test]
fn incident_bundle_rejects_invalid_provenance_refs() {
    let workspace = config_only_workspace();
    configure_replay_bundle_signing_key(workspace.path());
    let evidence_path = workspace
        .path()
        .join("fixtures/incidents/INC-BAD-PROV/evidence.v1.json");

    // Write malformed evidence with invalid/malicious provenance_ref
    write_malformed_evidence_invalid_provenance(&evidence_path, "INC-BAD-PROV");
    let evidence_arg = evidence_path.to_string_lossy().to_string();

    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident",
            "bundle",
            "--id",
            "INC-BAD-PROV",
            "--evidence-path",
            &evidence_arg,
        ],
    );

    // Should fail closed with specific error
    assert!(
        !output.status.success(),
        "bundle creation should fail with invalid provenance reference"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid provenance reference"));
    assert!(stderr.contains("path traversal"));

    // Bundle file should not be created
    assert!(
        !workspace.path().join("INC-BAD-PROV.fnbundle").exists(),
        "no bundle file should be created on provenance validation failure"
    );
}

// Helper functions for malformed evidence generation

fn boundary_metadata(tag: &str) -> IncidentEvidenceMetadata {
    IncidentEvidenceMetadata {
        title: "Boundary incident evidence".to_string(),
        affected_components: vec!["boundary-detector".to_string()],
        tags: vec![
            "automated".to_string(),
            "test-pipeline".to_string(),
            tag.to_string(),
        ],
    }
}

fn evidence_refs(refs: &[&str]) -> Vec<String> {
    refs.iter()
        .map(|reference| (*reference).to_string())
        .collect()
}

fn write_malformed_evidence_empty_events(path: &Path, incident_id: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create evidence dir");
    }
    let package = IncidentEvidencePackage {
        schema_version: INCIDENT_EVIDENCE_SCHEMA.to_string(),
        incident_id: incident_id.to_string(),
        collected_at: "2026-02-20T10:05:00.000000Z".to_string(),
        trace_id: "trace-incident-boundary".to_string(),
        severity: IncidentSeverity::High,
        incident_type: "security".to_string(),
        detector: "boundary-test".to_string(),
        policy_version: "1.2.3".to_string(),
        initial_state_snapshot: json!({"epoch": 7_u64, "mode": "strict"}),
        events: vec![], // EMPTY EVENTS ARRAY
        evidence_refs: Vec::new(),
        metadata: boundary_metadata("empty-events"),
    };

    let json_str = serde_json::to_string_pretty(&package).expect("serialize empty events package");
    fs::write(path, json_str).expect("write malformed evidence file");
}

fn write_malformed_evidence_duplicate_event_id(path: &Path, incident_id: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create evidence dir");
    }
    let package = IncidentEvidencePackage {
        schema_version: INCIDENT_EVIDENCE_SCHEMA.to_string(),
        incident_id: incident_id.to_string(),
        collected_at: "2026-02-20T10:05:00.000000Z".to_string(),
        trace_id: "trace-incident-boundary".to_string(),
        severity: IncidentSeverity::High,
        incident_type: "security".to_string(),
        detector: "boundary-test".to_string(),
        policy_version: "1.2.3".to_string(),
        initial_state_snapshot: json!({"epoch": 7_u64, "mode": "strict"}),
        events: vec![
            IncidentEvidenceEvent {
                event_id: "evt-duplicate".to_string(), // DUPLICATE ID
                timestamp: "2026-02-20T10:00:00.000100Z".to_string(),
                event_type: EventType::ExternalSignal,
                payload: json!({"signal":"anomaly1","severity":"high"}),
                provenance_ref: "refs/logs/event-001.json".to_string(),
                parent_event_id: None,
                state_snapshot: None,
                policy_version: None,
            },
            IncidentEvidenceEvent {
                event_id: "evt-duplicate".to_string(), // SAME ID AGAIN
                timestamp: "2026-02-20T10:00:30.000200Z".to_string(),
                event_type: EventType::PolicyEval,
                payload: json!({"signal":"anomaly2","severity":"high"}),
                provenance_ref: "refs/logs/event-002.json".to_string(),
                parent_event_id: Some("evt-duplicate".to_string()),
                state_snapshot: None,
                policy_version: None,
            },
        ],
        evidence_refs: evidence_refs(&["refs/logs/event-001.json", "refs/logs/event-002.json"]),
        metadata: boundary_metadata("duplicate-event-id"),
    };

    let json_str = serde_json::to_string_pretty(&package).expect("serialize duplicate ID package");
    fs::write(path, json_str).expect("write malformed evidence file");
}

fn write_malformed_evidence_invalid_parent_ref(path: &Path, incident_id: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create evidence dir");
    }
    let package = IncidentEvidencePackage {
        schema_version: INCIDENT_EVIDENCE_SCHEMA.to_string(),
        incident_id: incident_id.to_string(),
        collected_at: "2026-02-20T10:05:00.000000Z".to_string(),
        trace_id: "trace-incident-boundary".to_string(),
        severity: IncidentSeverity::High,
        incident_type: "security".to_string(),
        detector: "boundary-test".to_string(),
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
                timestamp: "2026-02-20T10:00:30.000200Z".to_string(),
                event_type: EventType::PolicyEval,
                payload: json!({"policy":"strict-security"}),
                provenance_ref: "refs/logs/event-002.json".to_string(),
                parent_event_id: Some("evt-nonexistent".to_string()), // INVALID REFERENCE
                state_snapshot: None,
                policy_version: None,
            },
        ],
        evidence_refs: evidence_refs(&["refs/logs/event-001.json", "refs/logs/event-002.json"]),
        metadata: boundary_metadata("invalid-parent-ref"),
    };

    let json_str =
        serde_json::to_string_pretty(&package).expect("serialize invalid parent ref package");
    fs::write(path, json_str).expect("write malformed evidence file");
}

fn write_malformed_evidence_invalid_provenance(path: &Path, incident_id: &str) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create evidence dir");
    }
    let package = IncidentEvidencePackage {
        schema_version: INCIDENT_EVIDENCE_SCHEMA.to_string(),
        incident_id: incident_id.to_string(),
        collected_at: "2026-02-20T10:05:00.000000Z".to_string(),
        trace_id: "trace-incident-boundary".to_string(),
        severity: IncidentSeverity::High,
        incident_type: "security".to_string(),
        detector: "boundary-test".to_string(),
        policy_version: "1.2.3".to_string(),
        initial_state_snapshot: json!({"epoch": 7_u64, "mode": "strict"}),
        events: vec![IncidentEvidenceEvent {
            event_id: "evt-001".to_string(),
            timestamp: "2026-02-20T10:00:00.000100Z".to_string(),
            event_type: EventType::ExternalSignal,
            payload: json!({"signal":"anomaly","severity":"high"}),
            provenance_ref: "../../../etc/passwd".to_string(), // PATH TRAVERSAL ATTACK
            parent_event_id: None,
            state_snapshot: None,
            policy_version: None,
        }],
        evidence_refs: evidence_refs(&["../../../etc/passwd"]),
        metadata: boundary_metadata("invalid-provenance"),
    };

    let json_str =
        serde_json::to_string_pretty(&package).expect("serialize invalid provenance package");
    fs::write(path, json_str).expect("write malformed evidence file");
}
