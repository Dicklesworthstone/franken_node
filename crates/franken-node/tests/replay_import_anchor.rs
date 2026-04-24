use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use frankenengine_node::tools::replay_bundle::{
    EventType, RawEvent, ReplayBundleSigningMaterial, generate_replay_bundle, sign_replay_bundle,
    write_bundle_to_path_with_trusted_key,
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

fn key_id(signing_key: &ed25519_dalek::SigningKey) -> String {
    frankenengine_node::supply_chain::artifact_signing::KeyId::from_verifying_key(
        &signing_key.verifying_key(),
    )
    .to_string()
}

fn write_public_key(path: &Path, signing_key: &ed25519_dalek::SigningKey) {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create key dir");
    }
    std::fs::write(path, hex::encode(signing_key.verifying_key().to_bytes()))
        .expect("write public key");
}

fn write_signed_bundle(path: &Path, signing_key: &ed25519_dalek::SigningKey) {
    let events = vec![
        RawEvent::new(
            "2026-02-20T12:00:00.000001Z",
            EventType::ExternalSignal,
            json!({"incident_id": "INC-ANCHOR-001", "signal": "anomaly"}),
        )
        .with_state_snapshot(json!({"epoch": 7_u64, "mode": "strict"}))
        .with_policy_version("1.0.0"),
        RawEvent::new(
            "2026-02-20T12:00:00.000500Z",
            EventType::PolicyEval,
            json!({"decision": "quarantine", "confidence": 95_u64}),
        )
        .with_causal_parent(0),
    ];
    let mut bundle = generate_replay_bundle("INC-ANCHOR-001", &events).expect("bundle");
    let signing_material = ReplayBundleSigningMaterial {
        signing_key,
        key_source: "test",
        signing_identity: "replay-import-anchor-test",
    };
    sign_replay_bundle(&mut bundle, &signing_material).expect("sign bundle");
    write_bundle_to_path_with_trusted_key(&bundle, path, &key_id(signing_key))
        .expect("write bundle");
}

#[test]
fn replay_import_rejects_bundle_signed_by_untrusted_embedded_anchor() {
    let workspace = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        workspace.path().join("franken_node.toml"),
        "profile = \"balanced\"\n",
    )
    .expect("write config");

    let trusted_signing_key = ed25519_dalek::SigningKey::from_bytes(&[0x11_u8; 32]);
    let wrong_anchor_key = ed25519_dalek::SigningKey::from_bytes(&[0x22_u8; 32]);
    let bundle_path = workspace.path().join("INC-ANCHOR-001.fnbundle");
    let wrong_anchor_path = workspace.path().join("keys/wrong-anchor.pub");
    write_signed_bundle(&bundle_path, &trusted_signing_key);
    write_public_key(&wrong_anchor_path, &wrong_anchor_key);

    let bundle_arg = bundle_path.to_string_lossy().to_string();
    let wrong_anchor_arg = wrong_anchor_path.to_string_lossy().to_string();
    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "incident",
            "replay",
            "--bundle",
            &bundle_arg,
            "--trusted-public-key",
            &wrong_anchor_arg,
        ],
    );

    assert!(
        !output.status.success(),
        "replay import must reject a bundle whose embedded signing anchor is not in the current trust set"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not trusted key id `configured replay trust set`"),
        "unexpected stderr: {stderr}"
    );
}
