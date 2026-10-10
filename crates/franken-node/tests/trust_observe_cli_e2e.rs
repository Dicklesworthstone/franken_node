//! Real CLI, Ed25519 collector signatures, and the durable trust-card store.
//! Counts below are explicit test measurements, not runtime-collected evidence.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::SigningKey;
use frankenengine_node::supply_chain::behavioral_observation::{
    BehavioralObservation, SignedBehavioralObservation,
};
use frankenengine_node::supply_chain::trust_card::fixture_registry;
use frankenengine_node::supply_chain::trust_card_registry_store::{
    TrustCardRegistryStore, registry_snapshot_path,
};
use serde_json::Value;

const EXTENSION: &str = "npm:@acme/auth-guard";

fn run(root: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_franken-node"))
        .current_dir(root)
        .args(args)
        .output()
        .expect("execute trust CLI")
}

fn json(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "JSON report: {error}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        )
    })
}

fn workspace() -> (tempfile::TempDir, SigningKey, u64) {
    let root = tempfile::tempdir().expect("trust observation workspace");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("test clock")
        .as_secs();
    let registry_key = base64::engine::general_purpose::STANDARD
        .encode(b"franken-node-trust-card-registry-key-v1");
    std::fs::write(
        root.path().join("franken_node.toml"),
        format!(
            "profile = \"balanced\"\n[trust]\nregistry_signing_key = \"{registry_key}\"\n\
             [security]\nauthorized_api_keys = [\"observation-cli-test\"]\n"
        ),
    )
    .expect("explicit fixture signing config");
    fixture_registry(now)
        .expect("fixture registry")
        .persist_authoritative_state(&registry_snapshot_path(root.path()))
        .expect("seed actual durable store");
    let collector = SigningKey::from_bytes(&[91; 32]);
    std::fs::write(
        root.path().join("collector.pub"),
        hex::encode(collector.verifying_key().to_bytes()),
    )
    .expect("pin test collector");
    (root, collector, now)
}

fn observation(now: u64, sequence: u64, previous: Option<String>) -> BehavioralObservation {
    BehavioralObservation {
        extension_id: EXTENSION.to_string(),
        package_version: "1.4.2".to_string(),
        artifact_hash: format!("sha256:deadbeef{}", "a".repeat(56)),
        workload_id: "auth-validation-fixture-v1".to_string(),
        measurement_scope: "isolated_package".to_string(),
        sequence,
        observed_at_epoch_secs: now - 120 + sequence,
        window_duration_ms: 1_000,
        workload_iterations: 100,
        previous_observation_id: previous,
        observed_capabilities: BTreeMap::from([
            ("fs.read".to_string(), 100),
            ("net.egress".to_string(), 10),
        ]),
        declared_capabilities: BTreeMap::from([
            ("fs.read".to_string(), 100),
            ("net.egress".to_string(), 10),
        ]),
    }
}

fn submit(root: &Path, signed: &SignedBehavioralObservation) -> Output {
    std::fs::write(
        root.join("observation.json"),
        serde_json::to_vec(signed).expect("signed observation JSON"),
    )
    .expect("write signed observation");
    run(
        root,
        &[
            "trust",
            "observe",
            "observation.json",
            "--collector-key",
            "collector.pub",
            "--json",
        ],
    )
}

fn durable_state(root: &Path) -> Option<(String, Option<String>)> {
    TrustCardRegistryStore::open(&registry_snapshot_path(root))
        .expect("open registry store")
        .load_state()
        .expect("read registry state")
}

#[test]
fn trust_observe_commits_verified_evidence_and_retries_without_card_churn() {
    let (root, collector, now) = workspace();
    let signed = SignedBehavioralObservation::sign(observation(now, 0, None), &collector)
        .expect("sign collector measurement");
    let output = submit(root.path(), &signed);
    let accepted = json(&output);
    assert!(output.status.success(), "{accepted}");
    assert_eq!(accepted["status"], "accepted");
    assert_eq!(accepted["extension_id"], EXTENSION);
    assert_eq!(accepted["package_version"], "1.4.2");
    assert_eq!(accepted["sample_count"], 1);
    assert_eq!(accepted["observation_id"], signed.observation_id().unwrap());

    let committed = durable_state(root.path());
    let output = submit(root.path(), &signed);
    let duplicate = json(&output);
    assert!(output.status.success(), "{duplicate}");
    assert_eq!(duplicate["status"], "duplicate");
    assert_eq!(duplicate["card_hash"], accepted["card_hash"]);
    assert_eq!(duplicate["card_version"], accepted["card_version"]);
    assert_eq!(durable_state(root.path()), committed);

    let output = run(root.path(), &["trust", "card", EXTENSION, "--json"]);
    let card = json(&output);
    assert!(output.status.success(), "{card}");
    assert_eq!(card["card_hash"], accepted["card_hash"]);
    assert!(
        card["derivation_evidence"].to_string().contains(
            accepted["evidence_ref"]
                .as_str()
                .expect("evidence identity")
        ),
        "admitted collector evidence must reach the signed trust card: {card}"
    );
}

#[test]
fn trust_observe_rejects_untrusted_signer_and_broken_chain_without_mutation() {
    let (root, collector, now) = workspace();
    let before = durable_state(root.path());
    let untrusted = SigningKey::from_bytes(&[92; 32]);
    let signed = SignedBehavioralObservation::sign(observation(now, 0, None), &untrusted)
        .expect("sign with another collector");
    let output = submit(root.path(), &signed);
    let error = json(&output);
    assert!(!output.status.success());
    assert_eq!(error["schema_version"], "franken-node/trust-error-cli/v1");
    assert_eq!(error["command"], "trust.observe");
    assert_eq!(error["ok"], false);
    assert_eq!(durable_state(root.path()), before);

    let signed = SignedBehavioralObservation::sign(observation(now, 1, None), &collector)
        .expect("sign measurement starting after the required first sequence");
    let output = submit(root.path(), &signed);
    assert!(!output.status.success(), "{}", json(&output));
    assert_eq!(durable_state(root.path()), before);
}

#[test]
fn trust_observe_routes_real_detector_findings_into_persistent_card_risk() {
    let (root, collector, now) = workspace();
    let mut previous = None;
    let mut last = Value::Null;
    for sequence in 0..8 {
        let mut sample = observation(now, sequence, previous);
        if sequence >= 4 {
            sample
                .observed_capabilities
                .insert("net.egress".to_string(), 1_000);
        }
        let signed = SignedBehavioralObservation::sign(sample, &collector)
            .expect("sign ordered test measurements");
        previous = Some(signed.observation_id().unwrap());
        let output = submit(root.path(), &signed);
        last = json(&output);
        assert!(output.status.success(), "sequence {sequence}: {last}");
    }
    assert_eq!(last["sample_count"], 8);
    assert!(
        !last["hints"]
            .as_array()
            .expect("detector findings")
            .is_empty(),
        "{last}"
    );
    let output = run(root.path(), &["trust", "card", EXTENSION, "--json"]);
    let card = json(&output);
    assert!(output.status.success(), "{card}");
    assert!(
        !card["camouflage_hints"]
            .as_array()
            .expect("persisted hints")
            .is_empty()
    );
    assert_eq!(card["card_hash"], last["card_hash"]);
    assert_ne!(card["user_facing_risk_assessment"]["level"], "low");
    assert_eq!(
        card["active_quarantine"], false,
        "a heuristic must not silently quarantine"
    );
}
