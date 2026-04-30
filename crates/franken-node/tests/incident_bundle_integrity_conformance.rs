use chrono::{Duration, SecondsFormat, Utc};
use frankenengine_node::supply_chain::artifact_signing::KeyId;
use frankenengine_node::tools::replay_bundle::{
    EventType, INCIDENT_EVIDENCE_SCHEMA, IncidentEvidenceEvent, IncidentEvidenceMetadata,
    IncidentEvidencePackage, IncidentSeverity, ReplayBundle, ReplayBundleError,
    ReplayBundleSigningMaterial, generate_replay_bundle_from_evidence,
    read_bundle_from_path_with_trusted_key, read_incident_evidence_package, sign_replay_bundle,
    to_canonical_json, validate_bundle_integrity, verify_replay_bundle_signature,
    write_bundle_to_path_with_trusted_key,
};
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const INCIDENT_BUNDLE_INTEGRITY_VECTORS: &[&str] = &[
    "valid_bundle_round_trip",
    "authoritative_input_byte_identical",
    "tampered_signature_rejection",
    "missing_evidence_ref_rejection",
    "future_dated_promotion_input_rejection",
];

fn resolve_binary_path() -> PathBuf {
    if let Some(exe) = std::env::var_os("CARGO_BIN_EXE_franken-node") {
        return PathBuf::from(exe);
    }

    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .join("target/debug/franken-node")
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

fn fixture_signing_key() -> ed25519_dalek::SigningKey {
    ed25519_dalek::SigningKey::from_bytes(&[0x42_u8; 32])
}

fn fixture_trusted_key_id() -> String {
    let signing_key = fixture_signing_key();
    KeyId::from_verifying_key(&signing_key.verifying_key()).to_string()
}

fn sign_bundle(bundle: &mut ReplayBundle) {
    let signing_key = fixture_signing_key();
    let signing_material = ReplayBundleSigningMaterial {
        signing_key: &signing_key,
        key_source: "env",
        signing_identity: "incident-bundle-conformance",
    };
    sign_replay_bundle(bundle, &signing_material).expect("sign replay bundle");
}

fn write_receipt_signing_key(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create key dir");
    }

    let signing_key = fixture_signing_key();
    fs::write(path, hex::encode(signing_key.to_bytes())).expect("write receipt signing key");
}

fn write_replay_trust_anchor(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create trust anchor dir");
    }

    let signing_key = fixture_signing_key();
    fs::write(path, hex::encode(signing_key.verifying_key().to_bytes()))
        .expect("write replay trust anchor");
}

fn configured_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(
        dir.path().join("franken_node.toml"),
        "profile = \"balanced\"\n\n[security]\ndecision_receipt_signing_key_path = \"keys/receipt-signing.key\"\n",
    )
    .expect("write config");
    write_receipt_signing_key(&dir.path().join("keys/receipt-signing.key"));
    write_replay_trust_anchor(&dir.path().join("keys/replay-trust-anchor.pub"));
    dir
}

fn fixture_evidence_package(incident_id: &str) -> IncidentEvidencePackage {
    IncidentEvidencePackage {
        schema_version: INCIDENT_EVIDENCE_SCHEMA.to_string(),
        incident_id: incident_id.to_string(),
        collected_at: "2026-02-20T10:05:00.000000Z".to_string(),
        trace_id: format!("trace-{incident_id}"),
        severity: IncidentSeverity::High,
        incident_type: "security".to_string(),
        detector: "incident-bundle-integrity-conformance".to_string(),
        policy_version: "1.2.3".to_string(),
        initial_state_snapshot: json!({"epoch": 7_u64, "mode": "strict"}),
        events: vec![
            IncidentEvidenceEvent {
                event_id: "evt-001".to_string(),
                timestamp: "2026-02-20T10:00:00.000100Z".to_string(),
                event_type: EventType::ExternalSignal,
                payload: json!({"signal": "anomaly", "severity": "high"}),
                provenance_ref: "refs/logs/event-001.json".to_string(),
                parent_event_id: None,
                state_snapshot: None,
                policy_version: None,
            },
            IncidentEvidenceEvent {
                event_id: "evt-002".to_string(),
                timestamp: "2026-02-20T10:00:00.000200Z".to_string(),
                event_type: EventType::PolicyEval,
                payload: json!({"decision": "quarantine", "confidence": 91_u64}),
                provenance_ref: "refs/logs/event-002.json".to_string(),
                parent_event_id: Some("evt-001".to_string()),
                state_snapshot: None,
                policy_version: None,
            },
            IncidentEvidenceEvent {
                event_id: "evt-003".to_string(),
                timestamp: "2026-02-20T10:00:00.000300Z".to_string(),
                event_type: EventType::OperatorAction,
                payload: json!({"action": "seal", "result": "accepted"}),
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
            title: "Incident bundle integrity conformance fixture".to_string(),
            affected_components: vec!["auth-svc".to_string()],
            tags: vec!["incident".to_string(), "conformance".to_string()],
        },
    }
}

fn future_dated_evidence_package(incident_id: &str) -> IncidentEvidencePackage {
    let mut package = fixture_evidence_package(incident_id);
    let base = Utc::now() + Duration::hours(2);
    package.collected_at =
        (base + Duration::minutes(5)).to_rfc3339_opts(SecondsFormat::Micros, true);
    for (idx, event) in package.events.iter_mut().enumerate() {
        let offset = i64::try_from(idx.saturating_add(1)).expect("event offset fits i64");
        event.timestamp = (base + Duration::microseconds(offset * 100))
            .to_rfc3339_opts(SecondsFormat::Micros, true);
    }
    package
}

fn write_evidence_package(path: &Path, package: &IncidentEvidencePackage) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create evidence dir");
    }
    fs::write(
        path,
        serde_json::to_string_pretty(package).expect("serialize evidence package"),
    )
    .expect("write evidence package");
}

#[test]
fn incident_bundle_integrity_conformance_vectors_cover_required_contract() {
    assert_eq!(INCIDENT_BUNDLE_INTEGRITY_VECTORS.len(), 5);
    assert!(INCIDENT_BUNDLE_INTEGRITY_VECTORS.contains(&"valid_bundle_round_trip"));
    assert!(INCIDENT_BUNDLE_INTEGRITY_VECTORS.contains(&"authoritative_input_byte_identical"));
    assert!(INCIDENT_BUNDLE_INTEGRITY_VECTORS.contains(&"tampered_signature_rejection"));
    assert!(INCIDENT_BUNDLE_INTEGRITY_VECTORS.contains(&"missing_evidence_ref_rejection"));
    assert!(INCIDENT_BUNDLE_INTEGRITY_VECTORS.contains(&"future_dated_promotion_input_rejection"));
}

#[test]
fn incident_bundle_integrity_conformance_valid_bundle_round_trip() {
    let dir = tempfile::tempdir().expect("tempdir");
    let evidence_path = dir.path().join("fixtures/evidence.v1.json");
    let mut package = fixture_evidence_package("INC-CONF-ROUNDTRIP-001");
    package
        .evidence_refs
        .push("refs/trust/trust-card.json".to_string());
    write_evidence_package(&evidence_path, &package);

    let loaded_package = read_incident_evidence_package(&evidence_path, Some(&package.incident_id))
        .expect("parse evidence package");
    let mut bundle =
        generate_replay_bundle_from_evidence(&loaded_package).expect("generate bundle");
    assert!(validate_bundle_integrity(&bundle).expect("validate bundle"));

    sign_bundle(&mut bundle);
    let trusted_key_id = fixture_trusted_key_id();
    let bundle_path = dir.path().join("incident_bundle.fnbundle");
    write_bundle_to_path_with_trusted_key(&bundle, &bundle_path, &trusted_key_id)
        .expect("write bundle");

    let loaded_bundle = read_bundle_from_path_with_trusted_key(&bundle_path, Some(&trusted_key_id))
        .expect("read bundle");
    verify_replay_bundle_signature(&loaded_bundle, Some(&trusted_key_id))
        .expect("verify signature");
    assert!(validate_bundle_integrity(&loaded_bundle).expect("validate loaded bundle"));
    assert_eq!(loaded_bundle.evidence_refs, loaded_package.evidence_refs);
    assert_eq!(
        loaded_bundle.trust_artifact_refs,
        vec!["refs/trust/trust-card.json".to_string()]
    );
}

#[test]
fn incident_bundle_integrity_conformance_authoritative_input_is_byte_identical() {
    let package = fixture_evidence_package("INC-CONF-BYTE-IDENTICAL-001");

    let first_bundle = generate_replay_bundle_from_evidence(&package)
        .expect("first authoritative evidence package should generate bundle");
    let second_bundle = generate_replay_bundle_from_evidence(&package)
        .expect("second authoritative evidence package should generate bundle");

    assert!(validate_bundle_integrity(&first_bundle).expect("first bundle integrity"));
    assert!(validate_bundle_integrity(&second_bundle).expect("second bundle integrity"));

    let first_wire = to_canonical_json(&first_bundle).expect("first canonical replay bundle");
    let second_wire = to_canonical_json(&second_bundle).expect("second canonical replay bundle");

    assert_eq!(
        first_wire, second_wire,
        "bd-2fqyv.4.1 requires identical authoritative evidence-package input to yield byte-identical replay bundles"
    );
    assert_eq!(first_bundle.bundle_id, second_bundle.bundle_id);
    assert_eq!(first_bundle.integrity_hash, second_bundle.integrity_hash);
    assert_eq!(first_bundle.evidence_refs, package.evidence_refs);
    assert_eq!(second_bundle.evidence_refs, package.evidence_refs);
}

#[test]
fn incident_bundle_integrity_conformance_rejects_tampered_signature_chain() {
    let package = fixture_evidence_package("INC-CONF-TAMPER-001");
    let mut bundle = generate_replay_bundle_from_evidence(&package).expect("generate bundle");
    sign_bundle(&mut bundle);
    assert!(validate_bundle_integrity(&bundle).expect("validate signed bundle"));
    bundle.signature.as_mut().expect("signature").signature_hex = "00".repeat(64);

    let dir = tempfile::tempdir().expect("tempdir");
    let bundle_path = dir.path().join("tampered_signature.fnbundle");
    fs::write(
        &bundle_path,
        serde_json::to_string_pretty(&bundle).expect("serialize bundle"),
    )
    .expect("write bundle");

    let trusted_key_id = fixture_trusted_key_id();
    let err = read_bundle_from_path_with_trusted_key(&bundle_path, Some(&trusted_key_id))
        .expect_err("tampered signature must fail closed");
    assert!(matches!(err, ReplayBundleError::SignatureInvalid));
}

#[test]
fn incident_bundle_integrity_conformance_rejects_missing_evidence_ref() {
    let dir = tempfile::tempdir().expect("tempdir");
    let evidence_path = dir.path().join("fixtures/missing-evidence-ref.v1.json");
    let mut package = fixture_evidence_package("INC-CONF-MISSING-REF-001");
    package.events[1].provenance_ref = "refs/logs/missing.json".to_string();
    write_evidence_package(&evidence_path, &package);

    let err = read_incident_evidence_package(&evidence_path, Some(&package.incident_id))
        .expect_err("missing evidence ref must fail closed");
    assert!(matches!(
        err,
        ReplayBundleError::EvidenceUnknownProvenanceRef {
            ref event_id,
            ref provenance_ref,
        } if event_id == "evt-002" && provenance_ref == "refs/logs/missing.json"
    ));
}

#[test]
fn incident_bundle_integrity_conformance_rejects_future_dated_promotion_input() {
    let workspace = configured_workspace();
    let future_bundle_path = workspace.path().join("INC-CONF-FUTURE-001.fnbundle");
    let future_package = future_dated_evidence_package("INC-CONF-FUTURE-001");
    let mut future_bundle =
        generate_replay_bundle_from_evidence(&future_package).expect("generate future bundle");
    sign_bundle(&mut future_bundle);
    fs::write(
        &future_bundle_path,
        serde_json::to_string_pretty(&future_bundle).expect("serialize future bundle"),
    )
    .expect("write future bundle");

    let trust_anchor_arg = workspace
        .path()
        .join("keys/replay-trust-anchor.pub")
        .to_string_lossy()
        .to_string();
    let promotion_key_arg = workspace
        .path()
        .join("keys/receipt-signing.key")
        .to_string_lossy()
        .to_string();

    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident",
            "counterfactual",
            "--bundle",
            "INC-CONF-FUTURE-001.fnbundle",
            "--trusted-public-key",
            &trust_anchor_arg,
            "--policy",
            "strict",
            "--json",
            "--promote",
            "--promotion-signing-key",
            &promotion_key_arg,
            "--operator-id",
            "incident-bundle-conformance",
        ],
    );

    assert!(
        !output.status.success(),
        "future-dated promotion input must fail closed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("replay bundle timestamp") && stderr.contains("in the future"),
        "unexpected stderr: {stderr}"
    );
}
