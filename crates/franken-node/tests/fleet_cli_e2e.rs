use std::path::PathBuf;
use std::process::{Child, Command, Output, Stdio};
use std::time::{Duration, Instant};

use chrono::{TimeDelta, Utc};
#[cfg(feature = "asupersync-transport")]
use frankenengine_node::control_plane::fleet_transport::{
    AsupersyncFleetNetwork, AsupersyncFleetTransport, wait_until_fleet_converged_or_timeout,
};
use frankenengine_node::control_plane::fleet_transport::{
    FileFleetTransport, FleetAction, FleetActionRecord, FleetTargetKind, FleetTransport,
    NodeHealth, NodeStatus, canonical_fleet_convergence_receipt_payload,
    fleet_convergence_receipt_verdict,
};
use frankenengine_node::supply_chain::trust_card::{
    ReputationTrend, RiskAssessment, RiskLevel, TrustCardMutation, TrustCardRegistry,
};
use insta::{assert_json_snapshot, assert_snapshot};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

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

fn run_cli(args: &[&str]) -> Output {
    let fleet_state = tempdir().expect("tempdir");
    run_cli_with_fleet_state(args, &fleet_state.path().join("fleet-state"))
}

fn run_cli_with_fleet_state(args: &[&str], fleet_state_dir: &std::path::Path) -> Output {
    run_cli_in_dir_with_fleet_state(&repo_root(), args, fleet_state_dir)
}

fn run_cli_in_dir_with_fleet_state(
    current_dir: &std::path::Path,
    args: &[&str],
    fleet_state_dir: &std::path::Path,
) -> Output {
    run_cli_in_dir_with_fleet_state_and_env(current_dir, args, fleet_state_dir, &[])
}

fn run_cli_in_dir_with_fleet_state_and_env(
    current_dir: &std::path::Path,
    args: &[&str],
    fleet_state_dir: &std::path::Path,
    extra_env: &[(&str, &str)],
) -> Output {
    let binary_path = resolve_binary_path();
    assert!(
        binary_path.is_file(),
        "franken-node binary not found at {}",
        binary_path.display()
    );
    Command::new(&binary_path)
        .current_dir(current_dir)
        .args(args)
        .env("FRANKEN_NODE_FLEET_STATE_DIR", fleet_state_dir)
        .env_remove("FRANKEN_NODE_PROFILE")
        .env_remove("FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH")
        .envs(extra_env.iter().copied())
        .output()
        .unwrap_or_else(|err| panic!("failed running `{}`: {err}", args.join(" ")))
}

fn spawn_cli_in_dir_with_fleet_state(
    current_dir: &std::path::Path,
    args: &[&str],
    fleet_state_dir: &std::path::Path,
) -> Child {
    let binary_path = resolve_binary_path();
    assert!(
        binary_path.is_file(),
        "franken-node binary not found at {}",
        binary_path.display()
    );
    Command::new(&binary_path)
        .current_dir(current_dir)
        .args(args)
        .env("FRANKEN_NODE_FLEET_STATE_DIR", fleet_state_dir)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|err| panic!("failed spawning `{}`: {err}", args.join(" ")))
}

fn seed_transport(fleet_state_dir: &std::path::Path) -> FileFleetTransport {
    let mut transport = FileFleetTransport::new(fleet_state_dir);
    transport.initialize().expect("initialize fleet transport");
    transport
}

fn write_test_signing_key(
    root: &std::path::Path,
    file_name: &str,
    seed_byte: u8,
) -> (PathBuf, ed25519_dalek::SigningKey) {
    let path = root.join(file_name);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("signing key parent");
    }
    let seed = [seed_byte; 32];
    std::fs::write(&path, hex::encode(seed)).expect("write signing key seed");
    (path, ed25519_dalek::SigningKey::from_bytes(&seed))
}

fn write_fixture_registry_to(root: &std::path::Path) {
    let registry = frankenengine_node::supply_chain::trust_card::fixture_registry(1_000)
        .expect("fixture registry");
    let registry_path = root.join(".franken-node/state/trust-card-registry.v1.json");
    registry
        .persist_authoritative_state(&registry_path)
        .expect("persist trust registry");
}

fn write_profile_routing_config(root: &std::path::Path) {
    std::fs::write(
        root.join("franken_node.toml"),
        r#"
profile = "balanced"

[profiles.strict.fleet]
node_id = "strict-profile-node"
poll_interval_seconds = 3
convergence_timeout_seconds = 11

[profiles.balanced.fleet]
node_id = "balanced-profile-node"
poll_interval_seconds = 5
convergence_timeout_seconds = 22

[profiles."legacy-risky".fleet]
node_id = "legacy-profile-node"
poll_interval_seconds = 7
convergence_timeout_seconds = 33
"#,
    )
    .expect("write profile routing config");
}

fn seed_fleet_quarantine(
    transport: &mut FileFleetTransport,
    zone_id: &str,
    incident_id: &str,
    quarantine_version: u64,
) {
    transport
        .publish_action(&FleetActionRecord {
            action_id: format!("fleet-op-{incident_id}"),
            emitted_at: Utc::now(),
            action: FleetAction::Quarantine {
                zone_id: zone_id.to_string(),
                incident_id: incident_id.to_string(),
                target_id: format!("sha256:{incident_id}"),
                target_kind: FleetTargetKind::Artifact,
                reason: "e2e contract quarantine".to_string(),
                quarantine_version,
            },
        })
        .expect("publish quarantine");
}

fn assert_convergence_receipt_signature_round_trips(
    receipt: &serde_json::Value,
    expected_fleet_key: &ed25519_dalek::SigningKey,
) {
    let signature = &receipt["signature"];
    assert_eq!(signature["algorithm"], "ed25519");
    assert_eq!(signature["key_source"], "env");
    assert_eq!(signature["signing_identity"], "fleet-control-plane");
    assert_eq!(signature["trust_scope"], "fleet_convergence");
    assert_ne!(signature["key_source"], "local");
    assert_eq!(
        signature["public_key_hex"],
        hex::encode(expected_fleet_key.verifying_key().to_bytes())
    );
    assert_eq!(
        signature["key_id"],
        frankenengine_node::supply_chain::artifact_signing::KeyId::from_verifying_key(
            &expected_fleet_key.verifying_key()
        )
        .to_string()
    );

    let mut signed_payload = receipt.clone();
    signed_payload
        .as_object_mut()
        .expect("convergence receipt object")
        .remove("signature")
        .expect("signature field");
    let canonical_payload = canonical_fleet_convergence_receipt_payload(&signed_payload)
        .expect("canonical convergence receipt payload");

    let mut hasher = Sha256::new();
    hasher.update(b"fleet_convergence_receipt_payload_v1:");
    hasher.update((canonical_payload.len() as u64).to_le_bytes());
    hasher.update(&canonical_payload);
    assert_eq!(
        signature["signed_payload_sha256"]
            .as_str()
            .expect("signed payload hash"),
        hex::encode(hasher.finalize())
    );

    let public_key_bytes: [u8; 32] = hex::decode(
        signature["public_key_hex"]
            .as_str()
            .expect("public key hex"),
    )
    .expect("decode public key")
    .try_into()
    .expect("public key length");
    let signature_bytes = hex::decode(signature["signature_hex"].as_str().expect("signature hex"))
        .expect("decode signature");
    let verifying_key =
        ed25519_dalek::VerifyingKey::from_bytes(&public_key_bytes).expect("verifying key");

    frankenengine_verifier_sdk::bundle::verify_ed25519_signature(
        &verifying_key,
        &canonical_payload,
        &signature_bytes,
    )
    .expect("verifier SDK should accept convergence receipt signature");
}

fn canonicalize_fleet_reconcile_snapshot(
    mut payload: serde_json::Value,
    fleet_state_dir: &std::path::Path,
) -> serde_json::Value {
    let fleet_state_prefix = format!("{}/", fleet_state_dir.display());
    let repo_root_prefix = format!("{}/", repo_root().display());

    fn scrub(value: &mut serde_json::Value, fleet_state_prefix: &str, repo_root_prefix: &str) {
        match value {
            serde_json::Value::Array(items) => {
                for item in items {
                    scrub(item, fleet_state_prefix, repo_root_prefix);
                }
            }
            serde_json::Value::Object(map) => {
                for (key, nested) in map {
                    match key.as_str() {
                        "operation_id" => {
                            *nested = serde_json::Value::String("[operation-id]".to_string());
                        }
                        "receipt_id" => {
                            *nested = serde_json::Value::String("[receipt-id]".to_string());
                        }
                        "signature_hex" => {
                            *nested = serde_json::Value::String("[signature-hex]".to_string());
                        }
                        "signed_payload_sha256" => {
                            *nested =
                                serde_json::Value::String("[signed-payload-sha256]".to_string());
                        }
                        "payload_hash" => {
                            *nested = serde_json::Value::String("[payload-hash]".to_string());
                        }
                        "elapsed_ms" => {
                            *nested = serde_json::Value::from(0);
                        }
                        "action_id" => {
                            if let Some(action_id) = nested.as_str() {
                                if action_id.starts_with("fleet-op-release-")
                                    || action_id.starts_with("fleet-op-reconcile-republish-")
                                {
                                    *nested = serde_json::Value::String("[action-id]".to_string());
                                }
                            }
                        }
                        "timestamp" | "signed_at" | "emitted_at" | "recorded_at" | "issued_at"
                        | "completed_at" | "last_seen" | "as_of" | "poll_timestamp" => {
                            *nested = serde_json::Value::String(format!("[{key}]"));
                        }
                        "state_dir" => {
                            if let Some(path) = nested.as_str() {
                                *nested = serde_json::Value::String(
                                    path.strip_prefix(fleet_state_prefix)
                                        .map(|suffix| format!("[fleet-state]/{suffix}"))
                                        .unwrap_or_else(|| "[fleet-state]".to_string()),
                                );
                            }
                        }
                        _ => scrub(nested, fleet_state_prefix, repo_root_prefix),
                    }
                }
            }
            serde_json::Value::String(text) => {
                if let Some(path) = text.strip_prefix(fleet_state_prefix) {
                    *value = serde_json::Value::String(format!("[fleet-state]/{path}"));
                } else if let Some(path) = text.strip_prefix(repo_root_prefix) {
                    *value = serde_json::Value::String(format!("[repo-root]/{path}"));
                }
            }
            _ => {}
        }
    }

    scrub(&mut payload, &fleet_state_prefix, &repo_root_prefix);
    payload
}

fn canonicalize_fleet_human_snapshot(stdout: &str) -> String {
    stdout
        .lines()
        .map(|line| {
            if line.starts_with("fleet action: type=release operation_id=fleet-op-release-") {
                "fleet action: type=release operation_id=[operation-id]".to_string()
            } else if line.starts_with("  receipt_id=rcpt-fleet-op-release-") {
                let suffix = line
                    .split_once(" issuer=")
                    .map(|(_, suffix)| suffix)
                    .unwrap_or("cli-fleet-operator zone=[zone]");
                format!("  receipt_id=[receipt-id] issuer={suffix}")
            } else if line.starts_with("  convergence_receipt_elapsed_ms=") {
                let timed_out = line
                    .split_once(" timed_out=")
                    .map(|(_, suffix)| suffix)
                    .unwrap_or("false");
                format!("  convergence_receipt_elapsed_ms=[elapsed-ms] timed_out={timed_out}")
            } else {
                line.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn json_stdout(output: &Output, label: &str) -> serde_json::Value {
    match serde_json::from_slice(&output.stdout) {
        Ok(value) => value,
        Err(err) => {
            let message = format!(
                "{label} stdout must be JSON: {err}\n{}",
                String::from_utf8_lossy(&output.stdout)
            );
            Err::<serde_json::Value, _>(err).expect(&message)
        }
    }
}

fn jsonl_stdout(output: &Output, label: &str) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines = stdout
        .lines()
        .enumerate()
        .map(|(index, line)| match serde_json::from_str(line) {
            Ok(value) => value,
            Err(err) => {
                let message = format!("{label} line {index} must be JSON: {err}\n{line}");
                Err::<serde_json::Value, _>(err).expect(&message)
            }
        })
        .collect::<Vec<serde_json::Value>>();
    serde_json::Value::Array(lines)
}

#[test]
fn fleet_status_reports_zone_state() {
    let output = run_cli(&["fleet", "status", "--zone", "zone-1", "--verbose"]);
    assert!(
        output.status.success(),
        "fleet status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("fleet status: zone=zone-1"));
    assert!(stdout.contains("activated=true"));
    assert!(stdout.contains("pending_convergences=0"));
    assert!(stdout.contains("healthy_nodes=0/0"));
}

#[test]
fn fleet_reconcile_executes_and_reports_operation() {
    let fleet_state = tempdir().expect("tempdir");
    let fleet_state_dir = fleet_state.path().join("fleet-state");
    let (signing_key_path, _) = write_test_signing_key(fleet_state.path(), "keys/fleet.key", 11);
    let signing_key_path = signing_key_path.display().to_string();

    let output = run_cli_in_dir_with_fleet_state_and_env(
        &repo_root(),
        &["fleet", "reconcile"],
        &fleet_state_dir,
        &[(
            "FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH",
            signing_key_path.as_str(),
        )],
    );
    assert!(
        output.status.success(),
        "fleet reconcile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("fleet action: type=reconcile"));
    assert!(stdout.contains("success=true"));
    assert!(stdout.contains("event_code=FLEET-005"));
}

#[test]
fn fleet_reconcile_rejects_local_state_dir_self_attestation_key() {
    let fleet_state = tempdir().expect("tempdir");
    let fleet_state_dir = fleet_state.path().join("fleet-state");
    seed_transport(&fleet_state_dir);
    write_test_signing_key(&fleet_state_dir, "fleet-signing.ed25519", 12);

    let output = run_cli_in_dir_with_fleet_state(
        &repo_root(),
        &["fleet", "reconcile", "--json"],
        &fleet_state_dir,
    );

    assert!(
        !output.status.success(),
        "fleet reconcile should reject local self-attestation key"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("configured fleet-level signing key")
            && stderr.contains("self-attestation is not trusted"),
        "unexpected stderr: {stderr}",
    );
}

#[test]
fn fleet_release_nonexistent_incident_reports_error() {
    let output = run_cli(&["fleet", "release", "--incident", "inc-demo-123"]);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("incident `inc-demo-123` not found") || !output.status.success(),
        "fleet release should fail for nonexistent incident, stderr: {stderr}",
    );
}

#[test]
fn fleet_status_uses_transport_shared_state_counts() {
    let fleet_state = tempdir().expect("tempdir");
    let fleet_state_dir = fleet_state.path().join("fleet-state");
    let mut transport = seed_transport(&fleet_state_dir);
    let now = Utc::now();

    transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-quarantine-status".to_string(),
            emitted_at: now,
            action: FleetAction::Quarantine {
                zone_id: "zone-1".to_string(),
                incident_id: "inc-status-1".to_string(),
                target_id: "sha256:status".to_string(),
                target_kind: FleetTargetKind::Artifact,
                reason: "status verification".to_string(),
                quarantine_version: 4,
            },
        })
        .expect("publish quarantine");
    transport
        .upsert_node_status(&NodeStatus {
            zone_id: "zone-1".to_string(),
            node_id: "node-fresh".to_string(),
            last_seen: now,
            quarantine_version: 4,
            health: NodeHealth::Healthy,
        })
        .expect("write fresh node");
    transport
        .upsert_node_status(&NodeStatus {
            zone_id: "zone-1".to_string(),
            node_id: "node-stale".to_string(),
            last_seen: now - TimeDelta::seconds(600),
            quarantine_version: 1,
            health: NodeHealth::Degraded,
        })
        .expect("write stale node");

    let output = run_cli_with_fleet_state(
        &["fleet", "status", "--zone", "zone-1", "--json"],
        &fleet_state_dir,
    );
    assert!(
        output.status.success(),
        "fleet status --json failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fleet status json");
    assert_eq!(payload["status"]["zone_id"], "zone-1");
    assert_eq!(payload["status"]["active_quarantines"], 1);
    assert_eq!(payload["status"]["healthy_nodes"], 1);
    assert_eq!(payload["status"]["total_nodes"], 2);
    assert_eq!(
        payload["status"]["pending_convergences"][0]["progress_pct"],
        50
    );
    assert_eq!(
        payload["status"]["pending_convergences"][0]["phase"],
        "TimedOut"
    );
}

#[test]
fn fleet_release_publishes_release_action_to_transport() {
    let fleet_state = tempdir().expect("tempdir");
    let fleet_state_dir = fleet_state.path().join("fleet-state");
    let (signing_key_path, signing_key) =
        write_test_signing_key(fleet_state.path(), "keys/fleet.key", 23);
    let signing_key_path = signing_key_path.display().to_string();
    let mut transport = seed_transport(&fleet_state_dir);
    let now = Utc::now();

    transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-quarantine-release".to_string(),
            emitted_at: now,
            action: FleetAction::Quarantine {
                zone_id: "zone-1".to_string(),
                incident_id: "inc-release-1".to_string(),
                target_id: "sha256:release".to_string(),
                target_kind: FleetTargetKind::Artifact,
                reason: "release verification".to_string(),
                quarantine_version: 7,
            },
        })
        .expect("publish quarantine");

    let output = run_cli_in_dir_with_fleet_state_and_env(
        &repo_root(),
        &["fleet", "release", "--incident", "inc-release-1", "--json"],
        &fleet_state_dir,
        &[(
            "FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH",
            signing_key_path.as_str(),
        )],
    );
    assert!(
        output.status.success(),
        "fleet release failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fleet release json");
    assert_eq!(payload["action"]["action_type"], "release");
    assert_eq!(payload["action"]["event_code"], "FLEET-004");
    assert_eq!(payload["action"]["convergence"]["phase"], "Converged");
    assert_eq!(payload["convergence_receipt"]["event_code"], "FLEET-004");
    assert_convergence_receipt_signature_round_trips(&payload["convergence_receipt"], &signing_key);

    let actions = transport.list_actions().expect("list actions");
    assert!(matches!(
        &actions.last().expect("release action").action,
        FleetAction::Release {
            zone_id,
            incident_id,
            reason: Some(reason),
        } if zone_id == "zone-1"
            && incident_id == "inc-release-1"
            && reason == "manual release via fleet CLI"
    ));
}

#[test]
fn fleet_release_fails_on_convergence_timeout() {
    let fleet_state = tempdir().expect("tempdir");
    let fleet_state_dir = fleet_state.path().join("fleet-state");
    let (signing_key_path, _) = write_test_signing_key(fleet_state.path(), "keys/fleet.key", 24);
    let signing_key_path = signing_key_path.display().to_string();
    let mut transport = seed_transport(&fleet_state_dir);
    let now = Utc::now();

    transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-quarantine-release-timeout".to_string(),
            emitted_at: now,
            action: FleetAction::Quarantine {
                zone_id: "zone-release-timeout".to_string(),
                incident_id: "inc-release-timeout".to_string(),
                target_id: "sha256:release-timeout".to_string(),
                target_kind: FleetTargetKind::Artifact,
                reason: "release timeout verification".to_string(),
                quarantine_version: 8,
            },
        })
        .expect("publish quarantine");
    transport
        .upsert_node_status(&NodeStatus {
            zone_id: "zone-release-timeout".to_string(),
            node_id: "node-before-release".to_string(),
            last_seen: now - TimeDelta::seconds(60),
            quarantine_version: 8,
            health: NodeHealth::Healthy,
        })
        .expect("write pre-release node heartbeat");

    let output = run_cli_in_dir_with_fleet_state_and_env(
        &repo_root(),
        &[
            "fleet",
            "release",
            "--incident",
            "inc-release-timeout",
            "--json",
        ],
        &fleet_state_dir,
        &[
            ("FRANKEN_NODE_FLEET_CONVERGENCE_TIMEOUT_SECONDS", "1"),
            (
                "FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH",
                signing_key_path.as_str(),
            ),
        ],
    );

    assert!(
        !output.status.success(),
        "fleet release should fail closed on convergence timeout"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("fleet release convergence timed out"),
        "unexpected stderr: {stderr}"
    );
    assert!(
        output.stdout.is_empty(),
        "timeout path must not emit a success receipt"
    );
}

#[test]
fn fleet_reconcile_republishes_pending_quarantines_for_stale_nodes() {
    let fleet_state = tempdir().expect("tempdir");
    let fleet_state_dir = fleet_state.path().join("fleet-state");
    let (signing_key_path, signing_key) =
        write_test_signing_key(fleet_state.path(), "keys/fleet.key", 21);
    let signing_key_path = signing_key_path.display().to_string();
    let mut transport = seed_transport(&fleet_state_dir);
    let now = Utc::now();

    transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-quarantine-reconcile".to_string(),
            emitted_at: now,
            action: FleetAction::Quarantine {
                zone_id: "zone-1".to_string(),
                incident_id: "inc-reconcile-1".to_string(),
                target_id: "sha256:reconcile".to_string(),
                target_kind: FleetTargetKind::Artifact,
                reason: "reconcile verification".to_string(),
                quarantine_version: 5,
            },
        })
        .expect("publish quarantine");
    transport
        .upsert_node_status(&NodeStatus {
            zone_id: "zone-1".to_string(),
            node_id: "node-stale".to_string(),
            last_seen: now - TimeDelta::seconds(600),
            quarantine_version: 2,
            health: NodeHealth::Degraded,
        })
        .expect("write stale node");

    let output = run_cli_in_dir_with_fleet_state_and_env(
        &repo_root(),
        &["fleet", "reconcile", "--json"],
        &fleet_state_dir,
        &[
            ("FRANKEN_NODE_FLEET_CONVERGENCE_TIMEOUT_SECONDS", "1"),
            (
                "FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH",
                signing_key_path.as_str(),
            ),
        ],
    );
    assert!(
        output.status.success(),
        "fleet reconcile --json failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fleet reconcile json");
    assert_eq!(payload["action"]["action_type"], "reconcile");
    assert_eq!(payload["action"]["event_code"], "FLEET-005");
    assert_eq!(payload["convergence_receipt"]["timed_out"], true);
    assert_eq!(payload["convergence_receipt"]["verdict"], "non_converged");
    assert_eq!(payload["convergence_receipt"]["timeout_ms"], 1_000);
    assert!(
        payload["convergence_receipt"]["elapsed_ms"]
            .as_u64()
            .expect("elapsed_ms")
            >= 1_000
    );
    assert_convergence_receipt_signature_round_trips(&payload["convergence_receipt"], &signing_key);

    let actions = transport.list_actions().expect("list actions");
    assert_eq!(actions.len(), 2);
    assert!(matches!(
        &actions.last().expect("republished action").action,
        FleetAction::Quarantine {
            zone_id,
            incident_id,
            target_id,
            target_kind: FleetTargetKind::Artifact,
            reason,
            quarantine_version,
        } if zone_id == "zone-1"
            && incident_id == "inc-reconcile-1"
            && target_id == "sha256:reconcile"
            && reason == "reconcile verification"
            && *quarantine_version == 5
    ));
}

#[test]
fn fleet_reconcile_waits_for_delayed_node_convergence_receipt() {
    let fleet_state = tempdir().expect("tempdir");
    let fleet_state_dir = fleet_state.path().join("fleet-state");
    let (signing_key_path, signing_key) =
        write_test_signing_key(fleet_state.path(), "keys/fleet.key", 22);
    let signing_key_path = signing_key_path.display().to_string();
    let mut transport = seed_transport(&fleet_state_dir);
    let now = Utc::now();
    let delay = Duration::from_millis(350);

    transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-quarantine-delayed-reconcile".to_string(),
            emitted_at: now,
            action: FleetAction::Quarantine {
                zone_id: "zone-delayed".to_string(),
                incident_id: "inc-delayed-reconcile".to_string(),
                target_id: "sha256:delayed-reconcile".to_string(),
                target_kind: FleetTargetKind::Artifact,
                reason: "delayed reconcile verification".to_string(),
                quarantine_version: 9,
            },
        })
        .expect("publish quarantine");
    transport
        .upsert_node_status(&NodeStatus {
            zone_id: "zone-delayed".to_string(),
            node_id: "node-converged".to_string(),
            last_seen: now,
            quarantine_version: 9,
            health: NodeHealth::Healthy,
        })
        .expect("write converged node");
    transport
        .upsert_node_status(&NodeStatus {
            zone_id: "zone-delayed".to_string(),
            node_id: "node-delayed".to_string(),
            last_seen: now - TimeDelta::seconds(600),
            quarantine_version: 1,
            health: NodeHealth::Degraded,
        })
        .expect("write delayed stale node");

    let updater_state_dir = fleet_state_dir.clone();
    let updater = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut delayed_transport = FileFleetTransport::new(&updater_state_dir);
            delayed_transport
                .initialize()
                .expect("initialize delayed updater transport");
            let actions = delayed_transport.list_actions().expect("list actions");
            if actions.iter().any(|record| {
                record
                    .action_id
                    .starts_with("fleet-op-reconcile-republish-")
                    && matches!(
                        &record.action,
                        FleetAction::Quarantine {
                            incident_id,
                            zone_id,
                            ..
                        } if incident_id == "inc-delayed-reconcile" && zone_id == "zone-delayed"
                    )
            }) {
                std::thread::sleep(delay);
                delayed_transport
                    .upsert_node_status(&NodeStatus {
                        zone_id: "zone-delayed".to_string(),
                        node_id: "node-delayed".to_string(),
                        last_seen: Utc::now(),
                        quarantine_version: 9,
                        health: NodeHealth::Healthy,
                    })
                    .expect("write delayed node convergence");
                return;
            }

            assert!(
                Instant::now() < deadline,
                "fleet reconcile never republished delayed quarantine"
            );
            std::thread::sleep(Duration::from_millis(25));
        }
    });

    let output = run_cli_in_dir_with_fleet_state_and_env(
        &repo_root(),
        &["fleet", "reconcile", "--json"],
        &fleet_state_dir,
        &[
            ("FRANKEN_NODE_FLEET_CONVERGENCE_TIMEOUT_SECONDS", "3"),
            (
                "FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH",
                signing_key_path.as_str(),
            ),
        ],
    );
    updater
        .join()
        .expect("delayed convergence updater should finish");
    assert!(
        output.status.success(),
        "fleet reconcile --json failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fleet reconcile json");
    assert_eq!(payload["action"]["action_type"], "reconcile");
    assert_eq!(payload["action"]["event_code"], "FLEET-005");
    assert_eq!(payload["convergence_receipt"]["timed_out"], false);
    assert_eq!(payload["convergence_receipt"]["verdict"], "converged");
    assert_eq!(
        payload["convergence_receipt"]["convergence"]["phase"],
        "Converged"
    );
    assert!(
        payload["convergence_receipt"]["elapsed_ms"]
            .as_u64()
            .expect("elapsed_ms")
            >= u64::try_from(delay.as_millis()).expect("delay fits u64")
    );
    assert_convergence_receipt_signature_round_trips(&payload["convergence_receipt"], &signing_key);
}

#[test]
fn fleet_reconcile_receipt_default_timeout_overrun_is_non_converged() {
    assert_eq!(
        fleet_convergence_receipt_verdict(false, 120_001, 120, true),
        "non_converged"
    );
}

#[cfg(feature = "asupersync-transport")]
#[test]
fn asupersync_fleet_transport_converges_simulated_two_node_mode() {
    let network = AsupersyncFleetNetwork::new();
    let mut coordinator = AsupersyncFleetTransport::for_testing("coordinator", network.clone());
    let mut node_a = AsupersyncFleetTransport::for_testing("node-a", network.clone());
    let mut node_b = AsupersyncFleetTransport::for_testing("node-b", network.clone());

    coordinator.initialize().expect("initialize coordinator");
    node_a.initialize().expect("initialize node-a");
    node_b.initialize().expect("initialize node-b");

    coordinator
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-asupersync-quarantine".to_string(),
            emitted_at: Utc::now(),
            action: FleetAction::Quarantine {
                zone_id: "zone-asupersync".to_string(),
                incident_id: "inc-asupersync".to_string(),
                target_id: "sha256:asupersync".to_string(),
                target_kind: FleetTargetKind::Artifact,
                reason: "simulated asupersync two-node convergence".to_string(),
                quarantine_version: 7,
            },
        })
        .expect("publish asupersync quarantine");

    node_a
        .upsert_node_status(&NodeStatus {
            zone_id: "zone-asupersync".to_string(),
            node_id: "node-a".to_string(),
            last_seen: Utc::now(),
            quarantine_version: 7,
            health: NodeHealth::Healthy,
        })
        .expect("node-a status");
    node_b
        .upsert_node_status(&NodeStatus {
            zone_id: "zone-asupersync".to_string(),
            node_id: "node-b".to_string(),
            last_seen: Utc::now(),
            quarantine_version: 7,
            health: NodeHealth::Healthy,
        })
        .expect("node-b status");

    let outcome = wait_until_fleet_converged_or_timeout(Duration::from_secs(1), || {
        let state = coordinator.read_shared_state()?;
        let converged_nodes = state
            .nodes
            .iter()
            .filter(|node| {
                node.zone_id == "zone-asupersync"
                    && node.quarantine_version == 7
                    && node.health == NodeHealth::Healthy
            })
            .count();
        Ok(converged_nodes == 2)
    })
    .expect("wait for asupersync convergence");

    assert!(!outcome.timed_out, "asupersync transport should converge");
    assert_eq!(
        coordinator.read_shared_state().expect("state").nodes.len(),
        2
    );
    assert!(
        network
            .control_events()
            .expect("control events")
            .iter()
            .any(|event| event.operation == "publish_action"),
        "asupersync control-lane should record publish operation"
    );
}

#[test]
fn fleet_status_json_includes_full_shared_state() {
    let output = run_cli(&["fleet", "status", "--json"]);
    assert!(
        output.status.success(),
        "fleet status --json failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fleet status json");
    assert_eq!(payload["status"]["zone_id"], "all");
    assert_eq!(
        payload["state"]["schema_version"],
        "franken-node/fleet-transport-state/v1"
    );
    assert!(payload["state"]["actions"].is_array());
    assert!(payload["state"]["nodes"].is_array());
}

#[test]
fn fleet_agent_runs_poll_cycles_and_exits_on_max_cycles() {
    let fleet_state = tempdir().expect("tempdir");
    let fleet_state_dir = fleet_state.path().join("fleet-state");
    seed_transport(&fleet_state_dir);

    let output = run_cli_with_fleet_state(
        &[
            "fleet",
            "agent",
            "--node-id",
            "agent-node-1",
            "--zone",
            "zone-1",
            "--poll-interval-secs",
            "1",
            "--max-cycles",
            "2",
            "--json",
        ],
        &fleet_state_dir,
    );
    assert!(
        output.status.success(),
        "fleet agent failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(
        lines.len(),
        2,
        "expected 2 JSON poll results for max_cycles=2"
    );

    let poll1: serde_json::Value = serde_json::from_str(lines[0]).expect("poll result 1 json");
    assert_eq!(poll1["cycle"], 1);
    assert_eq!(poll1["node_id"], "agent-node-1");
    assert_eq!(poll1["zone_id"], "zone-1");
    assert_eq!(poll1["node_health"], "healthy");

    let poll2: serde_json::Value = serde_json::from_str(lines[1]).expect("poll result 2 json");
    assert_eq!(poll2["cycle"], 2);
}

#[test]
fn fleet_agent_processes_quarantine_actions_and_updates_heartbeat() {
    let fleet_state = tempdir().expect("tempdir");
    let fleet_state_dir = fleet_state.path().join("fleet-state");
    let mut transport = seed_transport(&fleet_state_dir);
    let now = Utc::now();

    transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-quarantine-agent".to_string(),
            emitted_at: now,
            action: FleetAction::Quarantine {
                zone_id: "zone-agent".to_string(),
                incident_id: "inc-agent-1".to_string(),
                target_id: "sha256:agent-test".to_string(),
                target_kind: FleetTargetKind::Artifact,
                reason: "agent test quarantine".to_string(),
                quarantine_version: 10,
            },
        })
        .expect("publish quarantine");

    let output = run_cli_with_fleet_state(
        &[
            "fleet",
            "agent",
            "--node-id",
            "agent-node-2",
            "--zone",
            "zone-agent",
            "--poll-interval-secs",
            "1",
            "--max-cycles",
            "1",
            "--json",
        ],
        &fleet_state_dir,
    );
    assert!(
        output.status.success(),
        "fleet agent failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let poll: serde_json::Value = serde_json::from_str(stdout.trim()).expect("poll result json");
    assert_eq!(poll["actions_processed"], 1);
    assert_eq!(poll["quarantine_version"], 10);
    assert_eq!(poll["last_action_id"], "fleet-op-quarantine-agent");

    // Verify heartbeat was written
    let nodes = transport.list_node_statuses().expect("list nodes");
    let agent_node = nodes
        .iter()
        .find(|n| n.node_id == "agent-node-2")
        .expect("agent node status");
    assert_eq!(agent_node.zone_id, "zone-agent");
    assert_eq!(agent_node.quarantine_version, 10);
    assert_eq!(agent_node.health, NodeHealth::Healthy);
}

#[test]
fn fleet_agent_once_processes_pending_actions_and_exits() {
    let fleet_state = tempdir().expect("tempdir");
    let fleet_state_dir = fleet_state.path().join("fleet-state");
    seed_transport(&fleet_state_dir);

    let output = run_cli_with_fleet_state(
        &[
            "fleet",
            "agent",
            "--node-id",
            "agent-node-once",
            "--zone",
            "zone-1",
            "--once",
            "--json",
        ],
        &fleet_state_dir,
    );
    assert!(
        output.status.success(),
        "fleet agent --once failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 1, "expected exactly one poll result");
    let poll: serde_json::Value = serde_json::from_str(lines[0]).expect("poll result");
    assert_eq!(poll["cycle"], 1);
    assert_eq!(poll["node_id"], "agent-node-once");
}

#[test]
fn fleet_agent_applies_quarantine_actions_to_local_registry() {
    let project = tempdir().expect("tempdir");
    let fleet_state_dir = project.path().join("fleet-state");
    let mut transport = seed_transport(&fleet_state_dir);
    std::fs::write(
        project.path().join("franken_node.toml"),
        "profile = \"balanced\"\n",
    )
    .expect("write config");
    std::fs::create_dir_all(project.path().join(".franken-node/state")).expect("state dir");
    write_fixture_registry_to(project.path());

    transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-quarantine-local".to_string(),
            emitted_at: Utc::now(),
            action: FleetAction::Quarantine {
                zone_id: "zone-local".to_string(),
                incident_id: "inc-local-1".to_string(),
                target_id: "npm:@acme/auth-guard".to_string(),
                target_kind: FleetTargetKind::Extension,
                reason: "local quarantine".to_string(),
                quarantine_version: 7,
            },
        })
        .expect("publish quarantine");

    let output = run_cli_in_dir_with_fleet_state(
        project.path(),
        &[
            "fleet",
            "agent",
            "--node-id",
            "agent-local-1",
            "--zone",
            "zone-local",
            "--once",
            "--json",
        ],
        &fleet_state_dir,
    );
    assert!(
        output.status.success(),
        "fleet agent failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let registry_path = project
        .path()
        .join(".franken-node/state/trust-card-registry.v1.json");
    let mut registry =
        TrustCardRegistry::load_authoritative_state(&registry_path, 60, 2_000).expect("load");
    let card = registry
        .read(
            "npm:@acme/auth-guard",
            2_000,
            "trace-test-fleet-agent-quarantine",
        )
        .expect("read")
        .expect("trust card");
    assert!(card.active_quarantine, "card should be quarantined");
}

#[test]
fn fleet_agent_release_actions_clear_local_quarantine_state() {
    let project = tempdir().expect("tempdir");
    let fleet_state_dir = project.path().join("fleet-state");
    let mut transport = seed_transport(&fleet_state_dir);
    std::fs::write(
        project.path().join("franken_node.toml"),
        "profile = \"balanced\"\n",
    )
    .expect("write config");
    std::fs::create_dir_all(project.path().join(".franken-node/state")).expect("state dir");
    write_fixture_registry_to(project.path());

    let registry_path = project
        .path()
        .join(".franken-node/state/trust-card-registry.v1.json");
    let mut registry =
        TrustCardRegistry::load_authoritative_state(&registry_path, 60, 2_000).expect("load");
    registry
        .update(
            "npm:@acme/auth-guard",
            TrustCardMutation {
                certification_level: None,
                revocation_status: None,
                active_quarantine: Some(true),
                reputation_score_basis_points: None,
                reputation_trend: Some(ReputationTrend::Declining),
                user_facing_risk_assessment: Some(RiskAssessment {
                    level: RiskLevel::High,
                    summary: "quarantined before fleet release".to_string(),
                }),
                last_verified_timestamp: Some("2026-04-10T00:00:00Z".to_string()),
                evidence_refs: None,
            },
            2_001,
            "trace-test-fleet-pre-release",
        )
        .expect("quarantine card");
    registry
        .persist_authoritative_state(&registry_path)
        .expect("persist registry");

    let emitted_at = Utc::now();
    transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-quarantine-release-source".to_string(),
            emitted_at,
            action: FleetAction::Quarantine {
                zone_id: "zone-release".to_string(),
                incident_id: "inc-release-1".to_string(),
                target_id: "npm:@acme/auth-guard".to_string(),
                target_kind: FleetTargetKind::Extension,
                reason: "source quarantine".to_string(),
                quarantine_version: 11,
            },
        })
        .expect("publish quarantine");
    transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-release-local".to_string(),
            emitted_at,
            action: FleetAction::Release {
                zone_id: "zone-release".to_string(),
                incident_id: "inc-release-1".to_string(),
                reason: Some("operator cleared incident".to_string()),
            },
        })
        .expect("publish release");

    let output = run_cli_in_dir_with_fleet_state(
        project.path(),
        &[
            "fleet",
            "agent",
            "--node-id",
            "agent-release-1",
            "--zone",
            "zone-release",
            "--once",
            "--json",
        ],
        &fleet_state_dir,
    );
    assert!(
        output.status.success(),
        "fleet agent failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut registry =
        TrustCardRegistry::load_authoritative_state(&registry_path, 60, 2_100).expect("reload");
    let card = registry
        .read(
            "npm:@acme/auth-guard",
            2_100,
            "trace-test-fleet-agent-release",
        )
        .expect("read")
        .expect("trust card");
    assert!(
        !card.active_quarantine,
        "release action should clear quarantine"
    );
}

#[test]
fn fleet_agent_release_actions_clear_global_quarantine_state() {
    let project = tempdir().expect("tempdir");
    let fleet_state_dir = project.path().join("fleet-state");
    let mut transport = seed_transport(&fleet_state_dir);
    std::fs::write(
        project.path().join("franken_node.toml"),
        "profile = \"balanced\"\n",
    )
    .expect("write config");
    std::fs::create_dir_all(project.path().join(".franken-node/state")).expect("state dir");
    write_fixture_registry_to(project.path());

    let registry_path = project
        .path()
        .join(".franken-node/state/trust-card-registry.v1.json");
    let mut registry =
        TrustCardRegistry::load_authoritative_state(&registry_path, 60, 2_000).expect("load");
    registry
        .update(
            "npm:@acme/auth-guard",
            TrustCardMutation {
                certification_level: None,
                revocation_status: None,
                active_quarantine: Some(true),
                reputation_score_basis_points: None,
                reputation_trend: Some(ReputationTrend::Declining),
                user_facing_risk_assessment: Some(RiskAssessment {
                    level: RiskLevel::High,
                    summary: "quarantined before global fleet release".to_string(),
                }),
                last_verified_timestamp: Some("2026-04-10T00:00:00Z".to_string()),
                evidence_refs: None,
            },
            2_001,
            "trace-test-fleet-pre-global-release",
        )
        .expect("quarantine card");
    registry
        .persist_authoritative_state(&registry_path)
        .expect("persist registry");

    let emitted_at = Utc::now();
    transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-quarantine-global-release-source".to_string(),
            emitted_at,
            action: FleetAction::Quarantine {
                zone_id: "all".to_string(),
                incident_id: "inc-global-release-1".to_string(),
                target_id: "npm:@acme/auth-guard".to_string(),
                target_kind: FleetTargetKind::Extension,
                reason: "global source quarantine".to_string(),
                quarantine_version: 13,
            },
        })
        .expect("publish global quarantine");
    transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-release-global".to_string(),
            emitted_at,
            action: FleetAction::Release {
                zone_id: "all".to_string(),
                incident_id: "inc-global-release-1".to_string(),
                reason: Some("operator cleared global incident".to_string()),
            },
        })
        .expect("publish global release");

    let output = run_cli_in_dir_with_fleet_state(
        project.path(),
        &[
            "fleet",
            "agent",
            "--node-id",
            "agent-global-release-1",
            "--zone",
            "zone-global",
            "--once",
            "--json",
        ],
        &fleet_state_dir,
    );
    assert!(
        output.status.success(),
        "fleet agent failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let mut registry =
        TrustCardRegistry::load_authoritative_state(&registry_path, 60, 2_100).expect("reload");
    let card = registry
        .read(
            "npm:@acme/auth-guard",
            2_100,
            "trace-test-fleet-agent-global-release",
        )
        .expect("read")
        .expect("trust card");
    assert!(
        !card.active_quarantine,
        "global release should clear quarantine for zone-local agents"
    );
}

#[test]
fn fleet_agent_release_preserves_quarantine_when_another_incident_is_still_active() {
    let project = tempdir().expect("tempdir");
    let fleet_state_dir = project.path().join("fleet-state");
    let mut transport = seed_transport(&fleet_state_dir);
    std::fs::write(
        project.path().join("franken_node.toml"),
        "profile = \"balanced\"\n",
    )
    .expect("write config");
    std::fs::create_dir_all(project.path().join(".franken-node/state")).expect("state dir");
    write_fixture_registry_to(project.path());

    let emitted_at = Utc::now();
    transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-quarantine-overlap-1".to_string(),
            emitted_at,
            action: FleetAction::Quarantine {
                zone_id: "zone-overlap".to_string(),
                incident_id: "inc-overlap-1".to_string(),
                target_id: "npm:@acme/auth-guard".to_string(),
                target_kind: FleetTargetKind::Extension,
                reason: "first quarantine".to_string(),
                quarantine_version: 20,
            },
        })
        .expect("publish first quarantine");
    transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-quarantine-overlap-2".to_string(),
            emitted_at: emitted_at + TimeDelta::seconds(1),
            action: FleetAction::Quarantine {
                zone_id: "zone-overlap".to_string(),
                incident_id: "inc-overlap-2".to_string(),
                target_id: "npm:@acme/auth-guard".to_string(),
                target_kind: FleetTargetKind::Extension,
                reason: "second quarantine".to_string(),
                quarantine_version: 21,
            },
        })
        .expect("publish second quarantine");
    transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-release-overlap-1".to_string(),
            emitted_at: emitted_at + TimeDelta::seconds(2),
            action: FleetAction::Release {
                zone_id: "zone-overlap".to_string(),
                incident_id: "inc-overlap-1".to_string(),
                reason: Some("operator cleared first incident".to_string()),
            },
        })
        .expect("publish release");

    let output = run_cli_in_dir_with_fleet_state(
        project.path(),
        &[
            "fleet",
            "agent",
            "--node-id",
            "agent-overlap-1",
            "--zone",
            "zone-overlap",
            "--once",
            "--json",
        ],
        &fleet_state_dir,
    );
    assert!(
        output.status.success(),
        "fleet agent failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let registry_path = project
        .path()
        .join(".franken-node/state/trust-card-registry.v1.json");
    let mut registry =
        TrustCardRegistry::load_authoritative_state(&registry_path, 60, 2_100).expect("reload");
    let card = registry
        .read(
            "npm:@acme/auth-guard",
            2_100,
            "trace-test-fleet-agent-overlap-release",
        )
        .expect("read")
        .expect("trust card");
    assert!(
        card.active_quarantine,
        "release should not clear quarantine while another active incident still targets the extension"
    );
}

#[test]
fn fleet_agent_release_actions_clear_local_quarantine_state_across_poll_cycles() {
    let project = tempdir().expect("tempdir");
    let fleet_state_dir = project.path().join("fleet-state");
    let mut transport = seed_transport(&fleet_state_dir);
    std::fs::write(
        project.path().join("franken_node.toml"),
        "profile = \"balanced\"\n",
    )
    .expect("write config");
    std::fs::create_dir_all(project.path().join(".franken-node/state")).expect("state dir");
    write_fixture_registry_to(project.path());

    transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-quarantine-cross-cycle".to_string(),
            emitted_at: Utc::now(),
            action: FleetAction::Quarantine {
                zone_id: "zone-release-cross-cycle".to_string(),
                incident_id: "inc-release-cross-cycle".to_string(),
                target_id: "npm:@acme/auth-guard".to_string(),
                target_kind: FleetTargetKind::Extension,
                reason: "cross-cycle source quarantine".to_string(),
                quarantine_version: 12,
            },
        })
        .expect("publish quarantine");

    let project_root = project.path().to_path_buf();
    let release_fleet_state_dir = fleet_state_dir.clone();
    let release_publisher = std::thread::spawn(move || {
        let registry_path = project_root.join(".franken-node/state/trust-card-registry.v1.json");
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut registry =
                TrustCardRegistry::load_authoritative_state(&registry_path, 60, 3_000)
                    .expect("load registry");
            let card = registry
                .read(
                    "npm:@acme/auth-guard",
                    3_000,
                    "trace-test-fleet-agent-release-cross-cycle",
                )
                .expect("read")
                .expect("trust card");
            if card.active_quarantine {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "fleet agent never applied quarantine before release publish"
            );
            std::thread::sleep(Duration::from_millis(50));
        }

        let mut release_transport = FileFleetTransport::new(&release_fleet_state_dir);
        release_transport
            .initialize()
            .expect("initialize release transport");
        release_transport
            .publish_action(&FleetActionRecord {
                action_id: "fleet-op-release-cross-cycle".to_string(),
                emitted_at: Utc::now(),
                action: FleetAction::Release {
                    zone_id: "zone-release-cross-cycle".to_string(),
                    incident_id: "inc-release-cross-cycle".to_string(),
                    reason: Some("operator cleared incident after first poll".to_string()),
                },
            })
            .expect("publish release");
    });

    let output = run_cli_in_dir_with_fleet_state(
        project.path(),
        &[
            "fleet",
            "agent",
            "--node-id",
            "agent-release-cross-cycle",
            "--zone",
            "zone-release-cross-cycle",
            "--poll-interval-secs",
            "1",
            "--max-cycles",
            "2",
            "--json",
        ],
        &fleet_state_dir,
    );
    release_publisher
        .join()
        .expect("cross-cycle release publisher should succeed");
    assert!(
        output.status.success(),
        "fleet agent failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let registry_path = project
        .path()
        .join(".franken-node/state/trust-card-registry.v1.json");
    let mut registry =
        TrustCardRegistry::load_authoritative_state(&registry_path, 60, 3_100).expect("reload");
    let card = registry
        .read(
            "npm:@acme/auth-guard",
            3_100,
            "trace-test-fleet-agent-release-cross-cycle-final",
        )
        .expect("read")
        .expect("trust card");
    assert!(
        !card.active_quarantine,
        "release from a later poll cycle should clear quarantine"
    );
}

#[test]
fn fleet_agent_processes_later_actions_with_lower_lexicographic_ids() {
    let fleet_state = tempdir().expect("tempdir");
    let fleet_state_dir = fleet_state.path().join("fleet-state");
    let mut transport = seed_transport(&fleet_state_dir);
    transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-zz-first".to_string(),
            emitted_at: Utc::now(),
            action: FleetAction::PolicyUpdate {
                zone_id: "zone-ordering".to_string(),
                policy_version: "policy-v1".to_string(),
                changed_fields: vec!["risk_threshold".to_string()],
            },
        })
        .expect("publish first policy update");

    let publisher_state_dir = fleet_state_dir.clone();
    let publisher = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let mut transport = FileFleetTransport::new(&publisher_state_dir);
            transport
                .initialize()
                .expect("initialize ordering transport");
            let nodes = transport.list_node_statuses().expect("list node statuses");
            if nodes
                .iter()
                .any(|node| node.zone_id == "zone-ordering" && node.node_id == "agent-ordering-1")
            {
                transport
                    .publish_action(&FleetActionRecord {
                        action_id: "fleet-op-aa-second".to_string(),
                        emitted_at: Utc::now(),
                        action: FleetAction::PolicyUpdate {
                            zone_id: "zone-ordering".to_string(),
                            policy_version: "policy-v2".to_string(),
                            changed_fields: vec!["policy_mode".to_string()],
                        },
                    })
                    .expect("publish second policy update");
                return;
            }
            assert!(
                Instant::now() < deadline,
                "fleet agent never completed first poll before second publish"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    let output = run_cli_with_fleet_state(
        &[
            "fleet",
            "agent",
            "--node-id",
            "agent-ordering-1",
            "--zone",
            "zone-ordering",
            "--poll-interval-secs",
            "1",
            "--max-cycles",
            "2",
            "--json",
        ],
        &fleet_state_dir,
    );
    publisher
        .join()
        .expect("ordering publisher thread should succeed");
    assert!(
        output.status.success(),
        "fleet agent failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines: Vec<&str> = stdout.lines().collect();
    assert_eq!(lines.len(), 2, "expected two poll cycles");

    let first: serde_json::Value = serde_json::from_str(lines[0]).expect("first poll result");
    assert_eq!(first["actions_processed"], 1);
    assert_eq!(first["last_action_id"], "fleet-op-zz-first");

    let second: serde_json::Value = serde_json::from_str(lines[1]).expect("second poll result");
    assert_eq!(second["actions_processed"], 1);
    assert_eq!(second["last_action_id"], "fleet-op-aa-second");
    assert_eq!(second["node_health"], "healthy");
}

#[test]
fn fleet_agent_uses_config_defaults_for_node_id_and_poll_interval() {
    let project = tempdir().expect("tempdir");
    let fleet_state_dir = project.path().join("fleet-state");
    seed_transport(&fleet_state_dir);
    std::fs::write(
        project.path().join("franken_node.toml"),
        "profile = \"balanced\"\n\n[fleet]\nnode_id = \"config-node-1\"\npoll_interval_seconds = 9\n",
    )
    .expect("write config");

    let output = run_cli_in_dir_with_fleet_state(
        project.path(),
        &[
            "fleet",
            "agent",
            "--zone",
            "zone-config",
            "--once",
            "--json",
        ],
        &fleet_state_dir,
    );
    assert!(
        output.status.success(),
        "fleet agent failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let poll: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fleet agent json output");
    assert_eq!(poll["node_id"], "config-node-1");
    assert_eq!(poll["configured_poll_interval_secs"], 9);
}

#[cfg(unix)]
#[test]
fn fleet_agent_handles_sigterm_gracefully() {
    let project = tempdir().expect("tempdir");
    let fleet_state_dir = project.path().join("fleet-state");
    seed_transport(&fleet_state_dir);
    std::fs::write(
        project.path().join("franken_node.toml"),
        "profile = \"balanced\"\n",
    )
    .expect("write config");

    let mut child = spawn_cli_in_dir_with_fleet_state(
        project.path(),
        &[
            "fleet",
            "agent",
            "--node-id",
            "agent-signal-1",
            "--zone",
            "zone-signal",
            "--poll-interval-secs",
            "30",
        ],
        &fleet_state_dir,
    );
    let readiness_deadline = Instant::now() + Duration::from_secs(5);
    let agent_status = loop {
        let mut readiness_transport = FileFleetTransport::new(&fleet_state_dir);
        readiness_transport
            .initialize()
            .expect("initialize readiness transport");
        if let Some(status) = readiness_transport
            .list_node_statuses()
            .expect("list readiness node statuses")
            .into_iter()
            .find(|status| status.node_id == "agent-signal-1" && status.zone_id == "zone-signal")
        {
            break status;
        }
        let early_exit = child.try_wait().expect("poll child status");
        assert!(
            early_exit.is_none(),
            "fleet agent exited before readiness marker: {early_exit:?}"
        );
        assert!(
            Instant::now() < readiness_deadline,
            "fleet agent did not write readiness heartbeat before SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(25));
    };
    assert_eq!(agent_status.health, NodeHealth::Healthy);
    let signal_status = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("send sigterm");
    assert!(signal_status.success(), "kill -TERM should succeed");

    let started = Instant::now();
    let output = child.wait_with_output().expect("wait for child");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "agent should exit quickly after SIGTERM"
    );
    assert!(
        output.status.success(),
        "fleet agent should exit successfully after SIGTERM: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("shutdown requested"),
        "expected graceful shutdown log, got: {stderr}"
    );
}

#[test]
fn fleet_agent_rejects_invalid_node_id() {
    let fleet_state = tempdir().expect("tempdir");
    let fleet_state_dir = fleet_state.path().join("fleet-state");
    seed_transport(&fleet_state_dir);

    let output = run_cli_with_fleet_state(
        &[
            "fleet",
            "agent",
            "--node-id",
            "",
            "--zone",
            "zone-1",
            "--poll-interval-secs",
            "1",
            "--max-cycles",
            "1",
        ],
        &fleet_state_dir,
    );
    assert!(
        !output.status.success(),
        "fleet agent should fail with empty node_id"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid node_id"),
        "expected invalid node_id error, got: {stderr}"
    );
}

#[test]
fn fleet_agent_routes_balanced_profile_from_config_file() {
    let project = tempdir().expect("tempdir");
    let fleet_state_dir = project.path().join("fleet-state");
    seed_transport(&fleet_state_dir);
    write_profile_routing_config(project.path());

    let output = run_cli_in_dir_with_fleet_state(
        project.path(),
        &[
            "fleet",
            "agent",
            "--zone",
            "zone-profile",
            "--once",
            "--json",
        ],
        &fleet_state_dir,
    );
    assert!(
        output.status.success(),
        "fleet agent failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fleet agent json output");
    assert_eq!(payload["node_id"], "balanced-profile-node");
    assert_eq!(payload["zone_id"], "zone-profile");
    assert_eq!(payload["configured_poll_interval_secs"], 5);
}

#[test]
fn fleet_agent_routes_strict_profile_from_env_override() {
    let project = tempdir().expect("tempdir");
    let fleet_state_dir = project.path().join("fleet-state");
    seed_transport(&fleet_state_dir);
    write_profile_routing_config(project.path());

    let output = run_cli_in_dir_with_fleet_state_and_env(
        project.path(),
        &[
            "fleet",
            "agent",
            "--zone",
            "zone-profile",
            "--once",
            "--json",
        ],
        &fleet_state_dir,
        &[("FRANKEN_NODE_PROFILE", "strict")],
    );
    assert!(
        output.status.success(),
        "fleet agent failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fleet agent json output");
    assert_eq!(payload["node_id"], "strict-profile-node");
    assert_eq!(payload["zone_id"], "zone-profile");
    assert_eq!(payload["configured_poll_interval_secs"], 3);
}

#[test]
fn fleet_agent_routes_legacy_risky_profile_from_env_override() {
    let project = tempdir().expect("tempdir");
    let fleet_state_dir = project.path().join("fleet-state");
    seed_transport(&fleet_state_dir);
    write_profile_routing_config(project.path());

    let output = run_cli_in_dir_with_fleet_state_and_env(
        project.path(),
        &[
            "fleet",
            "agent",
            "--zone",
            "zone-profile",
            "--once",
            "--json",
        ],
        &fleet_state_dir,
        &[("FRANKEN_NODE_PROFILE", "legacy-risky")],
    );
    assert!(
        output.status.success(),
        "fleet agent failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fleet agent json output");
    assert_eq!(payload["node_id"], "legacy-profile-node");
    assert_eq!(payload["zone_id"], "zone-profile");
    assert_eq!(payload["configured_poll_interval_secs"], 7);
}

#[test]
fn fleet_status_json_output_shape_is_stable() {
    let fleet_state = tempdir().expect("tempdir");
    let fleet_state_dir = fleet_state.path().join("fleet-state");
    let mut transport = seed_transport(&fleet_state_dir);
    seed_fleet_quarantine(&mut transport, "zone-json", "inc-json-shape", 2);

    let output = run_cli_with_fleet_state(
        &["fleet", "status", "--zone", "zone-json", "--json"],
        &fleet_state_dir,
    );
    assert!(
        output.status.success(),
        "fleet status --json failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fleet status json");
    assert!(payload["status"].is_object());
    assert!(payload["state"].is_object());
    assert!(payload["state_dir"].is_string());
    assert!(payload["stale_nodes"].is_array());
    assert!(payload["active_incidents"].is_array());
    assert!(payload["convergence_timeout_seconds"].is_u64());
    assert_eq!(payload["status"]["zone_id"], "zone-json");
    assert_eq!(payload["status"]["active_quarantines"], 1);
}

#[test]
fn fleet_status_human_output_shape_is_stable() {
    let output = run_cli(&["fleet", "status", "--zone", "zone-human", "--verbose"]);
    assert!(
        output.status.success(),
        "fleet status failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines = stdout.lines().collect::<Vec<_>>();
    assert_eq!(lines[0], "fleet status: zone=zone-human");
    assert_eq!(lines[1], "  activated=true");
    assert_eq!(lines[2], "  quarantines=0 revocations=0");
    assert_eq!(lines[3], "  healthy_nodes=0/0");
    assert_eq!(lines[4], "  pending_convergences=0");
}

#[test]
fn fleet_release_human_output_shape_is_stable() {
    let fleet_state = tempdir().expect("tempdir");
    let fleet_state_dir = fleet_state.path().join("fleet-state");
    let (signing_key_path, _) = write_test_signing_key(fleet_state.path(), "keys/fleet.key", 32);
    let signing_key_path = signing_key_path.display().to_string();
    let mut transport = seed_transport(&fleet_state_dir);
    seed_fleet_quarantine(&mut transport, "zone-release-human", "inc-release-human", 4);

    let output = run_cli_in_dir_with_fleet_state_and_env(
        &repo_root(),
        &["fleet", "release", "--incident", "inc-release-human"],
        &fleet_state_dir,
        &[(
            "FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH",
            signing_key_path.as_str(),
        )],
    );
    assert!(
        output.status.success(),
        "fleet release failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let lines = stdout.lines().collect::<Vec<_>>();
    assert!(lines[0].starts_with("fleet action: type=release operation_id=fleet-op-release-"));
    assert_eq!(lines[1], "  success=true");
    assert_eq!(lines[2], "  event_code=FLEET-004");
    assert!(lines[3].starts_with("  receipt_id=rcpt-fleet-op-release-"));
    assert!(lines[3].contains(" issuer=cli-fleet-operator zone=zone-release-human"));
    assert_eq!(
        lines[4],
        "  convergence=0/0 (100%) phase=Converged eta_seconds=Some(0)"
    );
    assert!(lines[5].starts_with("  convergence_receipt_elapsed_ms="));
    assert!(lines[5].ends_with(" timed_out=false"));

    assert_snapshot!(
        "fleet_release_human",
        canonicalize_fleet_human_snapshot(&stdout)
    );
}

#[test]
fn fleet_reconcile_json_output_shape_is_stable() {
    let fleet_state = tempdir().expect("tempdir");
    let fleet_state_dir = fleet_state.path().join("fleet-state");
    let (signing_key_path, signing_key) =
        write_test_signing_key(fleet_state.path(), "keys/fleet.key", 31);
    let signing_key_path = signing_key_path.display().to_string();

    let output = run_cli_in_dir_with_fleet_state_and_env(
        &repo_root(),
        &["fleet", "reconcile", "--json"],
        &fleet_state_dir,
        &[(
            "FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH",
            signing_key_path.as_str(),
        )],
    );
    assert!(
        output.status.success(),
        "fleet reconcile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fleet reconcile json");
    assert_eq!(payload["action"]["action_type"], "reconcile");
    assert_eq!(payload["action"]["success"], true);
    assert_eq!(payload["action"]["event_code"], "FLEET-005");
    assert!(
        payload["action"]["operation_id"]
            .as_str()
            .expect("operation id")
            .starts_with("fleet-op-reconcile-")
    );
    assert_eq!(payload["action"]["receipt"]["issuer"], "cli-fleet-operator");
    assert_convergence_receipt_signature_round_trips(&payload["convergence_receipt"], &signing_key);
    assert_eq!(payload["status"]["zone_id"], "all");
    assert!(payload["state"]["actions"].is_array());
}

#[test]
fn fleet_reconcile_json_matches_snapshot() {
    let fleet_state = tempdir().expect("tempdir");
    let fleet_state_dir = fleet_state.path().join("fleet-state");
    let (signing_key_path, signing_key) =
        write_test_signing_key(fleet_state.path(), "keys/fleet.key", 31);
    let signing_key_path = signing_key_path.display().to_string();

    let output = run_cli_in_dir_with_fleet_state_and_env(
        &repo_root(),
        &["fleet", "reconcile", "--json"],
        &fleet_state_dir,
        &[(
            "FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH",
            signing_key_path.as_str(),
        )],
    );
    assert!(
        output.status.success(),
        "fleet reconcile failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("fleet reconcile json");
    assert_convergence_receipt_signature_round_trips(&payload["convergence_receipt"], &signing_key);
    assert_json_snapshot!(
        "fleet_reconcile_json",
        canonicalize_fleet_reconcile_snapshot(payload, &fleet_state_dir)
    );
}

#[test]
fn fleet_cli_json_output_matrix_matches_snapshots() {
    let status_state = tempdir().expect("status tempdir");
    let status_state_dir = status_state.path().join("fleet-state");
    let mut status_transport = seed_transport(&status_state_dir);
    let now = Utc::now();
    status_transport
        .publish_action(&FleetActionRecord {
            action_id: "fleet-op-quarantine-golden-status".to_string(),
            emitted_at: now,
            action: FleetAction::Quarantine {
                zone_id: "zone-golden-status".to_string(),
                incident_id: "inc-golden-status".to_string(),
                target_id: "sha256:golden-status".to_string(),
                target_kind: FleetTargetKind::Artifact,
                reason: "golden status quarantine".to_string(),
                quarantine_version: 3,
            },
        })
        .expect("publish status quarantine");
    status_transport
        .upsert_node_status(&NodeStatus {
            zone_id: "zone-golden-status".to_string(),
            node_id: "node-golden-fresh".to_string(),
            last_seen: now,
            quarantine_version: 3,
            health: NodeHealth::Healthy,
        })
        .expect("write fresh status node");
    status_transport
        .upsert_node_status(&NodeStatus {
            zone_id: "zone-golden-status".to_string(),
            node_id: "node-golden-stale".to_string(),
            last_seen: now - TimeDelta::seconds(600),
            quarantine_version: 1,
            health: NodeHealth::Degraded,
        })
        .expect("write stale status node");

    let status_zone_output = run_cli_with_fleet_state(
        &["fleet", "status", "--zone", "zone-golden-status", "--json"],
        &status_state_dir,
    );
    assert!(
        status_zone_output.status.success(),
        "fleet status zone failed: {}",
        String::from_utf8_lossy(&status_zone_output.stderr)
    );
    let status_all_output =
        run_cli_with_fleet_state(&["fleet", "status", "--json"], &status_state_dir);
    assert!(
        status_all_output.status.success(),
        "fleet status all failed: {}",
        String::from_utf8_lossy(&status_all_output.stderr)
    );

    let release_state = tempdir().expect("release tempdir");
    let release_state_dir = release_state.path().join("fleet-state");
    let (release_signing_key_path, release_signing_key) =
        write_test_signing_key(release_state.path(), "keys/fleet.key", 41);
    let release_signing_key_path = release_signing_key_path.display().to_string();
    let mut release_transport = seed_transport(&release_state_dir);
    seed_fleet_quarantine(
        &mut release_transport,
        "zone-golden-release",
        "inc-golden-release",
        5,
    );
    let release_output = run_cli_in_dir_with_fleet_state_and_env(
        &repo_root(),
        &[
            "fleet",
            "release",
            "--incident",
            "inc-golden-release",
            "--json",
        ],
        &release_state_dir,
        &[(
            "FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH",
            release_signing_key_path.as_str(),
        )],
    );
    assert!(
        release_output.status.success(),
        "fleet release json failed: {}",
        String::from_utf8_lossy(&release_output.stderr)
    );
    let release_json = json_stdout(&release_output, "fleet release");
    assert_convergence_receipt_signature_round_trips(
        &release_json["convergence_receipt"],
        &release_signing_key,
    );

    let timeout_state = tempdir().expect("timeout tempdir");
    let timeout_state_dir = timeout_state.path().join("fleet-state");
    let (timeout_signing_key_path, timeout_signing_key) =
        write_test_signing_key(timeout_state.path(), "keys/fleet.key", 42);
    let timeout_signing_key_path = timeout_signing_key_path.display().to_string();
    let mut timeout_transport = seed_transport(&timeout_state_dir);
    seed_fleet_quarantine(
        &mut timeout_transport,
        "zone-golden-timeout",
        "inc-golden-timeout",
        6,
    );
    timeout_transport
        .upsert_node_status(&NodeStatus {
            zone_id: "zone-golden-timeout".to_string(),
            node_id: "node-golden-timeout".to_string(),
            last_seen: Utc::now() - TimeDelta::seconds(600),
            quarantine_version: 1,
            health: NodeHealth::Degraded,
        })
        .expect("write timeout node");
    let timeout_output = run_cli_in_dir_with_fleet_state_and_env(
        &repo_root(),
        &["fleet", "reconcile", "--json"],
        &timeout_state_dir,
        &[
            ("FRANKEN_NODE_FLEET_CONVERGENCE_TIMEOUT_SECONDS", "1"),
            (
                "FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH",
                timeout_signing_key_path.as_str(),
            ),
        ],
    );
    assert!(
        timeout_output.status.success(),
        "fleet reconcile timeout json failed: {}",
        String::from_utf8_lossy(&timeout_output.stderr)
    );
    let timeout_json = json_stdout(&timeout_output, "fleet reconcile timeout");
    assert_convergence_receipt_signature_round_trips(
        &timeout_json["convergence_receipt"],
        &timeout_signing_key,
    );

    let agent_state = tempdir().expect("agent tempdir");
    let agent_state_dir = agent_state.path().join("fleet-state");
    seed_transport(&agent_state_dir);
    let agent_output = run_cli_with_fleet_state(
        &[
            "fleet",
            "agent",
            "--node-id",
            "agent-golden-once",
            "--zone",
            "zone-golden-agent",
            "--once",
            "--json",
        ],
        &agent_state_dir,
    );
    assert!(
        agent_output.status.success(),
        "fleet agent once json failed: {}",
        String::from_utf8_lossy(&agent_output.stderr)
    );

    let matrix = serde_json::json!({
        "status_zone": canonicalize_fleet_reconcile_snapshot(
            json_stdout(&status_zone_output, "fleet status zone"),
            &status_state_dir,
        ),
        "status_all": canonicalize_fleet_reconcile_snapshot(
            json_stdout(&status_all_output, "fleet status all"),
            &status_state_dir,
        ),
        "release": canonicalize_fleet_reconcile_snapshot(release_json, &release_state_dir),
        "reconcile_timeout": canonicalize_fleet_reconcile_snapshot(timeout_json, &timeout_state_dir),
        "agent_once": canonicalize_fleet_reconcile_snapshot(
            jsonl_stdout(&agent_output, "fleet agent once"),
            &agent_state_dir,
        ),
    });

    assert_json_snapshot!("fleet_cli_json_output_matrix", matrix);
}

#[test]
fn fleet_release_missing_incident_argument_exits_with_clap_code() {
    let output = run_cli(&["fleet", "release"]);

    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("--incident"),
        "missing incident error should mention --incident, got: {stderr}"
    );
}

#[test]
fn fleet_invalid_profile_env_exits_with_config_error_code() {
    let project = tempdir().expect("tempdir");
    let fleet_state_dir = project.path().join("fleet-state");
    seed_transport(&fleet_state_dir);
    write_profile_routing_config(project.path());

    let output = run_cli_in_dir_with_fleet_state_and_env(
        project.path(),
        &["fleet", "status", "--json"],
        &fleet_state_dir,
        &[("FRANKEN_NODE_PROFILE", "experimental")],
    );

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("FRANKEN_NODE_PROFILE=`experimental`"),
        "invalid profile error should name env value, got: {stderr}"
    );
    assert!(
        stderr.contains("expected strict, balanced, or legacy-risky"),
        "invalid profile error should include valid profile set, got: {stderr}"
    );
}

#[test]
fn fleet_agent_invalid_node_id_exits_with_application_error_code() {
    let output = run_cli(&[
        "fleet",
        "agent",
        "--node-id",
        "",
        "--zone",
        "zone-1",
        "--poll-interval-secs",
        "1",
        "--max-cycles",
        "1",
    ]);

    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid node_id"),
        "expected invalid node_id error, got: {stderr}"
    );
}
