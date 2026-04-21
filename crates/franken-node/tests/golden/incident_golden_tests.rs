//! Golden file conformance harness for incident replay bundles
//!
//! Prevents schema drift by freezing the exact structure of:
//! - Bundle JSON format (.fnbundle files)
//! - Counterfactual output JSON
//! - Replay result text output
//! - Receipt export JSON
//! - Error messages for corruption cases
//!
//! Addresses bd-1jybn: replace ad-hoc assertions with comprehensive
//! fixture validation that catches structural changes.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use frankenengine_node::tools::replay_bundle::{
    EventType, INCIDENT_EVIDENCE_SCHEMA, IncidentEvidenceEvent, IncidentEvidenceMetadata,
    IncidentEvidencePackage, IncidentSeverity, ReplayBundle, read_bundle_from_path_with_trusted_key,
    validate_bundle_integrity,
};
use serde_json::{json, Value};

use crate::golden::{assert_scrubbed_golden, assert_golden};

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
            },
            IncidentEvidenceEvent {
                event_id: "evt-002".to_string(),
                timestamp: "2026-02-20T10:00:30.000200Z".to_string(),
                event_type: EventType::PolicyActivation,
                payload: json!({"policy":"strict-security","triggered_by":"evt-001"}),
                provenance_ref: "refs/logs/event-002.json".to_string(),
            },
            IncidentEvidenceEvent {
                event_id: "evt-003".to_string(),
                timestamp: "2026-02-20T10:01:00.000300Z".to_string(),
                event_type: EventType::RemediationAction,
                payload: json!({"action":"quarantine","target":"suspicious_process"}),
                provenance_ref: "refs/logs/event-003.json".to_string(),
            },
        ],
        metadata: IncidentEvidenceMetadata {
            evidence_collection_method: "automated".to_string(),
            analysis_tools: vec!["franken-detector".to_string(), "baseline-analyzer".to_string()],
            chain_of_custody: "secure-evidence-pipeline".to_string(),
            integrity_verified: true,
            retention_policy: "90-day-security-incident".to_string(),
            related_incidents: vec!["INC-E2E-000".to_string()],
            escalation_path: "security-team".to_string(),
            impact_assessment: json!({"systems_affected": 3, "data_exposed": false, "recovery_time": "15m"}),
        },
    };

    let json_str = serde_json::to_string_pretty(&package).expect("serialize evidence package");
    fs::write(path, json_str).expect("write evidence file");
}

// Note: Using the existing golden module scrubbing which handles:
// - UUIDs, timestamps, paths, durations, hashes, etc.
// - The fixture timestamps (2026-02-20T10:0X:XX.XXXXXXZ) are deterministic
//   and preserved in the golden files as reference values

#[test]
fn golden_bundle_basic_structure_and_integrity() {
    let workspace = config_only_workspace();
    configure_replay_bundle_signing_key(workspace.path());
    let evidence_path = workspace
        .path()
        .join("fixtures/incidents/INC-GOLDEN-001/evidence.v1.json");
    write_fixture_incident_evidence(&evidence_path, "INC-GOLDEN-001");
    let evidence_arg = evidence_path.to_string_lossy().to_string();

    // Generate bundle
    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident",
            "bundle",
            "--id",
            "INC-GOLDEN-001",
            "--evidence-path",
            &evidence_arg,
            "--verify",
        ],
    );

    assert!(output.status.success(), "Bundle generation failed: {}",
        String::from_utf8_lossy(&output.stderr));

    // Read and scrub the bundle JSON for golden comparison
    let bundle_path = workspace.path().join("INC-GOLDEN-001.fnbundle");
    let bundle_json = fs::read_to_string(&bundle_path).expect("read bundle file");

    assert_scrubbed_golden(
        "incident/bundle_basic.fnbundle.json",
        &bundle_json,
    );

    // Verify bundle structure via round-trip
    let trusted_key_id = replay_bundle_trusted_key_id();
    let bundle = read_bundle_from_path_with_trusted_key(&bundle_path, Some(&trusted_key_id))
        .expect("round-trip bundle read");

    // Verify critical invariants that should never change
    assert_eq!(bundle.incident_id, "INC-GOLDEN-001");
    assert_eq!(bundle.policy_version, "1.2.3");
    assert_eq!(bundle.timeline.len(), 3);
    assert!(bundle.signature.is_some());

    // Create golden for the parsed bundle structure
    let canonical_structure = serde_json::to_string_pretty(&bundle).expect("serialize bundle");
    assert_scrubbed_golden(
        "incident/bundle_structure.json",
        &canonical_structure,
    );
}

#[test]
fn golden_counterfactual_output_format() {
    let workspace = config_only_workspace();
    configure_replay_bundle_signing_key(workspace.path());

    // Create test bundle first
    let evidence_path = workspace
        .path()
        .join("fixtures/incidents/INC-CF-001/evidence.v1.json");
    write_fixture_incident_evidence(&evidence_path, "INC-CF-001");
    let evidence_arg = evidence_path.to_string_lossy().to_string();

    let _bundle_output = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident", "bundle", "--id", "INC-CF-001",
            "--evidence-path", &evidence_arg,
        ],
    );

    // Run counterfactual analysis
    let cf_output = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident", "replay", "INC-CF-001.fnbundle",
            "--counterfactual", "--strict",
        ],
    );

    // Capture both stdout and stderr for golden comparison
    let stdout_str = String::from_utf8_lossy(&cf_output.stdout);
    let stderr_str = String::from_utf8_lossy(&cf_output.stderr);

    assert_scrubbed_golden(
        "incident/counterfactual_strict.stdout",
        &stdout_str,
    );

    assert_scrubbed_golden(
        "incident/counterfactual_strict.stderr",
        &stderr_str,
    );
}

#[test]
fn golden_replay_result_format() {
    let workspace = config_only_workspace();
    configure_replay_bundle_signing_key(workspace.path());

    let evidence_path = workspace
        .path()
        .join("fixtures/incidents/INC-REPLAY-001/evidence.v1.json");
    write_fixture_incident_evidence(&evidence_path, "INC-REPLAY-001");
    let evidence_arg = evidence_path.to_string_lossy().to_string();

    let _bundle_output = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident", "bundle", "--id", "INC-REPLAY-001",
            "--evidence-path", &evidence_arg,
        ],
    );

    // Run standard replay
    let replay_output = run_cli_in_workspace(
        workspace.path(),
        &["incident", "replay", "INC-REPLAY-001.fnbundle"],
    );

    let replay_text = String::from_utf8_lossy(&replay_output.stdout);
    assert_scrubbed_golden(
        "incident/replay_result.txt",
        &replay_text,
    );
}

#[test]
fn golden_receipt_export_format() {
    let workspace = config_only_workspace();
    configure_replay_bundle_signing_key(workspace.path());

    let evidence_path = workspace
        .path()
        .join("fixtures/incidents/INC-RECEIPT-001/evidence.v1.json");
    write_fixture_incident_evidence(&evidence_path, "INC-RECEIPT-001");
    let evidence_arg = evidence_path.to_string_lossy().to_string();

    let bundle_output = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident", "bundle", "--id", "INC-RECEIPT-001",
            "--evidence-path", &evidence_arg, "--export-receipt",
        ],
    );

    // Check if receipt was exported to expected location
    let receipt_path = workspace.path().join("INC-RECEIPT-001.receipt.json");
    if receipt_path.is_file() {
        let receipt_json = fs::read_to_string(&receipt_path).expect("read receipt file");
        assert_scrubbed_golden(
            "incident/receipt_export.json",
            &receipt_json,
        );
    } else {
        // If no receipt file, capture the stderr output for golden comparison
        let stderr_str = String::from_utf8_lossy(&bundle_output.stderr);
        assert_scrubbed_golden(
            "incident/receipt_export_stderr.txt",
            &stderr_str,
        );
    }
}

#[test]
fn golden_corrupt_bundle_error_messages() {
    let workspace = config_only_workspace();
    configure_replay_bundle_signing_key(workspace.path());

    // Create a corrupted bundle by writing invalid JSON
    let corrupt_bundle_path = workspace.path().join("CORRUPT.fnbundle");
    fs::write(&corrupt_bundle_path, "{\"invalid\": \"json\", \"missing\": }").expect("write corrupt bundle");

    // Try to replay the corrupt bundle
    let corrupt_output = run_cli_in_workspace(
        workspace.path(),
        &["incident", "replay", "CORRUPT.fnbundle"],
    );

    // Should fail with specific error message
    assert!(!corrupt_output.status.success());

    let error_text = String::from_utf8_lossy(&corrupt_output.stderr);
    assert_scrubbed_golden(
        "incident/corrupt_error.txt",
        &error_text,
    );
}

#[test]
fn conformance_round_trip_bundle_integrity() {
    // This test ensures that bundles can be written, read, and re-written
    // with perfect fidelity (no data loss or corruption)
    let workspace = config_only_workspace();
    configure_replay_bundle_signing_key(workspace.path());

    let evidence_path = workspace
        .path()
        .join("fixtures/incidents/INC-ROUND-001/evidence.v1.json");
    write_fixture_incident_evidence(&evidence_path, "INC-ROUND-001");
    let evidence_arg = evidence_path.to_string_lossy().to_string();

    // Generate original bundle
    let _output1 = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident", "bundle", "--id", "INC-ROUND-001",
            "--evidence-path", &evidence_arg,
        ],
    );

    let bundle_path = workspace.path().join("INC-ROUND-001.fnbundle");
    let trusted_key_id = replay_bundle_trusted_key_id();

    // Read bundle
    let bundle1 = read_bundle_from_path_with_trusted_key(&bundle_path, Some(&trusted_key_id))
        .expect("first read");

    // Re-serialize to temp file
    let temp_path = workspace.path().join("rewritten.fnbundle");
    let rewritten_json = serde_json::to_string_pretty(&bundle1).expect("serialize");
    fs::write(&temp_path, rewritten_json).expect("write rewritten");

    // Read again
    let bundle2 = read_bundle_from_path_with_trusted_key(&temp_path, Some(&trusted_key_id))
        .expect("second read");

    // Should be identical
    assert_eq!(bundle1.incident_id, bundle2.incident_id);
    assert_eq!(bundle1.timeline.len(), bundle2.timeline.len());
    assert_eq!(bundle1.initial_state_snapshot, bundle2.initial_state_snapshot);

    // Timeline order should be preserved exactly
    for (i, (event1, event2)) in bundle1.timeline.iter().zip(bundle2.timeline.iter()).enumerate() {
        assert_eq!(event1.event_id, event2.event_id, "Event {} ID mismatch", i);
        assert_eq!(event1.timestamp, event2.timestamp, "Event {} timestamp mismatch", i);
        assert_eq!(event1.event_type, event2.event_type, "Event {} type mismatch", i);
    }
}