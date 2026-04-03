use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use frankenengine_node::supply_chain::trust_card::fixture_registry;
use serde_json::Value;

const FIXTURE_RECEIPT_KEY_ID: &str = "72416df9f1dcd9b3";

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
    run_cli_in_workspace_with_env(workspace, args, &[])
}

fn run_cli_in_workspace_with_env(workspace: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let binary_path = resolve_binary_path();
    assert!(
        binary_path.is_file(),
        "franken-node binary not found at {}",
        binary_path.display()
    );
    let mut command = Command::new(&binary_path);
    command.current_dir(workspace).args(args);
    for (key, value) in env {
        command.env(key, value);
    }
    command
        .output()
        .unwrap_or_else(|err| panic!("failed running `{}`: {err}", args.join(" ")))
}

fn seeded_fixture_trust_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(
        dir.path().join("franken_node.toml"),
        "profile = \"balanced\"\n",
    )
    .expect("write config");

    let registry = fixture_registry(1_000).expect("fixture registry");
    let path = dir
        .path()
        .join(".franken-node/state/trust-card-registry.v1.json");
    registry
        .persist_authoritative_state(&path)
        .expect("persist trust registry");
    fs::write(
        dir.path()
            .join(".franken-node/state/trust-card-registry.fixture-source.json"),
        concat!(
            "{\n",
            "  \"source_helper\": \"fixture_registry\",\n",
            "  \"purpose\": \"trust-cli-e2e deterministic fixture seed\",\n",
            "  \"authoritative_state_path\": \".franken-node/state/trust-card-registry.v1.json\"\n",
            "}\n"
        ),
    )
    .expect("write fixture metadata");
    dir
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

fn parse_json_stdout(output: &Output, context: &str) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    serde_json::from_str(&stdout)
        .unwrap_or_else(|err| panic!("{context} should emit valid JSON: {err}\nstdout:\n{stdout}"))
}

fn write_receipt_signing_key(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create key dir");
    }
    fs::write(path, hex::encode([42_u8; 32])).expect("write receipt signing key");
}

#[test]
fn trust_card_displays_known_extension_details() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(workspace.path(), &["trust", "card", "npm:@acme/auth-guard"]);
    assert!(
        output.status.success(),
        "trust card failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("extension: npm:@acme/auth-guard@1.4.2"));
    assert!(stdout.contains("publisher: Acme Security"));
    assert!(stdout.contains("risk: Low"));
}

#[test]
fn trust_list_filters_critical_revoked_cards() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &["trust", "list", "--risk", "critical", "--revoked", "true"],
    );
    assert!(
        output.status.success(),
        "trust list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("npm:@beta/telemetry-bridge"));
    assert!(stdout.contains("revoked:publisher key compromised"));
    assert!(!stdout.contains("npm:@acme/auth-guard"));
}

#[test]
fn trust_list_filters_low_active_cards() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &["trust", "list", "--risk", "low", "--revoked", "false"],
    );
    assert!(
        output.status.success(),
        "trust list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("npm:@acme/auth-guard"));
    assert!(stdout.contains("active"));
    assert!(!stdout.contains("npm:@beta/telemetry-bridge"));
}

#[test]
fn trust_list_rejects_unknown_risk_value() {
    let output = run_cli_in_workspace(
        repo_root().as_path(),
        &["trust", "list", "--risk", "severe"],
    );
    assert!(
        !output.status.success(),
        "expected failure for unknown risk, got status {}",
        output.status
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid --risk `severe`"));
}

#[test]
fn trust_revoke_marks_target_as_revoked() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &["trust", "revoke", "npm:@acme/auth-guard"],
    );
    assert!(
        output.status.success(),
        "trust revoke failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("extension: npm:@acme/auth-guard@1.4.2"));
    assert!(stdout.contains("revocation: revoked (manual revoke via franken-node trust revoke)"));
    assert!(stdout.contains("quarantine: true"));

    let persisted =
        run_cli_in_workspace(workspace.path(), &["trust", "card", "npm:@acme/auth-guard"]);
    assert!(
        persisted.status.success(),
        "persisted trust card read failed: {}",
        String::from_utf8_lossy(&persisted.stderr)
    );
    let persisted_stdout = String::from_utf8_lossy(&persisted.stdout);
    assert!(
        persisted_stdout
            .contains("revocation: revoked (manual revoke via franken-node trust revoke)")
    );
    assert!(persisted_stdout.contains("quarantine: true"));
}

#[test]
fn trust_revoke_fails_for_unknown_extension() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &["trust", "revoke", "npm:@does-not/exist"],
    );
    assert!(
        !output.status.success(),
        "trust revoke should fail for unknown extension"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("trust card not found"));
}

#[test]
fn trust_quarantine_supports_sha256_artifact_scope() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &["trust", "quarantine", "--artifact", "sha256:deadbeef"],
    );
    assert!(
        output.status.success(),
        "trust quarantine failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("quarantine applied: artifact=sha256:deadbeef"));
    assert!(stdout.contains("affected_cards=2"));
    assert!(stdout.contains("npm:@acme/auth-guard"));
    assert!(stdout.contains("npm:@beta/telemetry-bridge"));
}

#[test]
fn trust_revoke_receipt_export_fails_before_mutation_when_key_missing() {
    let workspace = seeded_fixture_trust_workspace();
    let receipt_out = workspace.path().join("artifacts/revoke-receipts.json");
    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "trust",
            "revoke",
            "npm:@acme/auth-guard",
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
    assert!(
        !receipt_out.exists(),
        "receipt export should not be written on failure"
    );

    let persisted =
        run_cli_in_workspace(workspace.path(), &["trust", "card", "npm:@acme/auth-guard"]);
    assert!(
        persisted.status.success(),
        "persisted read should still succeed"
    );
    let persisted_stdout = String::from_utf8_lossy(&persisted.stdout);
    assert!(!persisted_stdout.contains("manual revoke via franken-node trust revoke"));
}

#[test]
fn trust_revoke_receipt_export_succeeds_with_cli_signing_key() {
    let workspace = seeded_fixture_trust_workspace();
    let key_path = workspace.path().join("keys/receipt-signing.key");
    write_receipt_signing_key(&key_path);
    let receipt_out = workspace.path().join("artifacts/revoke-receipts.json");
    let receipt_summary_out = workspace.path().join("artifacts/revoke-receipts.md");

    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "trust",
            "revoke",
            "npm:@acme/auth-guard",
            "--receipt-signing-key",
            key_path.to_str().expect("utf8 key path"),
            "--receipt-out",
            receipt_out.to_str().expect("utf8 receipt path"),
            "--receipt-summary-out",
            receipt_summary_out.to_str().expect("utf8 summary path"),
        ],
    );
    assert!(
        output.status.success(),
        "trust revoke with explicit signing key failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("signing_source=cli"));
    assert!(stderr.contains(FIXTURE_RECEIPT_KEY_ID));

    let exported = fs::read_to_string(&receipt_out).expect("read receipt export");
    let payload: Value = serde_json::from_str(&exported).expect("receipt export json");
    let receipts = payload.as_array().expect("receipt export array");
    assert_eq!(receipts.len(), 1);
    assert_eq!(receipts[0]["action_name"], "revocation");
    assert_eq!(receipts[0]["signer_key_id"], FIXTURE_RECEIPT_KEY_ID);

    let summary = fs::read_to_string(&receipt_summary_out).expect("read summary export");
    assert!(summary.contains("Signed Decision Receipts"));
    assert!(summary.contains("Key ID"));
}

#[test]
fn trust_quarantine_receipt_export_uses_env_signing_key() {
    let workspace = seeded_fixture_trust_workspace();
    let key_path = workspace.path().join("keys/receipt-signing.key");
    write_receipt_signing_key(&key_path);
    let receipt_out = workspace.path().join("artifacts/quarantine-receipts.json");

    let output = run_cli_in_workspace_with_env(
        workspace.path(),
        &[
            "trust",
            "quarantine",
            "--artifact",
            "sha256:deadbeef",
            "--receipt-out",
            receipt_out.to_str().expect("utf8 receipt path"),
        ],
        &[(
            "FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH",
            key_path.to_str().expect("utf8 key path"),
        )],
    );
    assert!(
        output.status.success(),
        "trust quarantine with env signing key failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("signing_source=env"));

    let exported = fs::read_to_string(&receipt_out).expect("read receipt export");
    let payload: Value = serde_json::from_str(&exported).expect("receipt export json");
    let receipts = payload.as_array().expect("receipt export array");
    assert_eq!(receipts[0]["action_name"], "quarantine");
    assert_eq!(receipts[0]["signer_key_id"], FIXTURE_RECEIPT_KEY_ID);
}

#[test]
fn trust_quarantine_receipt_export_uses_config_signing_key() {
    let workspace = seeded_fixture_trust_workspace();
    fs::write(
        workspace.path().join("franken_node.toml"),
        "profile = \"balanced\"\n\n[security]\ndecision_receipt_signing_key_path = \"keys/receipt-signing.key\"\n",
    )
    .expect("rewrite config");
    let key_path = workspace.path().join("keys/receipt-signing.key");
    write_receipt_signing_key(&key_path);
    let receipt_out = workspace.path().join("artifacts/quarantine-receipts.json");

    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "trust",
            "quarantine",
            "--artifact",
            "sha256:deadbeef",
            "--receipt-out",
            receipt_out.to_str().expect("utf8 receipt path"),
        ],
    );
    assert!(
        output.status.success(),
        "trust quarantine with config signing key failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("signing_source=config"));

    let exported = fs::read_to_string(&receipt_out).expect("read receipt export");
    let payload: Value = serde_json::from_str(&exported).expect("receipt export json");
    let receipts = payload.as_array().expect("receipt export array");
    assert_eq!(receipts[0]["signer_key_id"], FIXTURE_RECEIPT_KEY_ID);
}

#[test]
fn trust_sync_reports_summary_counts() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(workspace.path(), &["trust", "sync", "--force"]);
    assert!(
        output.status.success(),
        "trust sync failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("trust sync completed: force=true"));
    assert!(stdout.contains("cards=2"));
    assert!(stdout.contains("revoked=1"));
    assert!(stdout.contains("quarantined=1"));
}

#[test]
fn trust_card_export_requires_json_flag() {
    let output = run_cli_in_workspace(
        repo_root().as_path(),
        &["trust-card", "export", "npm:@acme/auth-guard"],
    );
    assert!(
        !output.status.success(),
        "trust-card export without --json should fail"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("`trust-card export` requires `--json`"));
}

#[test]
fn trust_card_export_emits_known_card_json() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &["trust-card", "export", "npm:@acme/auth-guard", "--json"],
    );
    assert!(
        output.status.success(),
        "trust-card export failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = parse_json_stdout(&output, "trust-card export");
    assert_eq!(payload["extension"]["extension_id"], "npm:@acme/auth-guard");
    assert_eq!(payload["extension"]["version"], "1.4.2");
    assert_eq!(payload["publisher"]["display_name"], "Acme Security");
    assert_eq!(payload["user_facing_risk_assessment"]["level"], "low");
}

#[test]
fn trust_card_list_filters_by_publisher() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &["trust-card", "list", "--publisher", "pub-acme"],
    );
    assert!(
        output.status.success(),
        "trust-card list failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("extension | publisher | cert | reputation | status"));
    assert!(stdout.contains("npm:@acme/auth-guard | pub-acme | Gold | 920bp (Improving) | active"));
    assert!(!stdout.contains("npm:@beta/telemetry-bridge"));
}

#[test]
fn trust_card_list_rejects_zero_page() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(workspace.path(), &["trust-card", "list", "--page", "0"]);
    assert!(
        !output.status.success(),
        "trust-card list with page 0 should fail"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid pagination: page=0, per_page=20"));
}

#[test]
fn trust_card_compare_reports_expected_differences() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "trust-card",
            "compare",
            "npm:@acme/auth-guard",
            "npm:@beta/telemetry-bridge",
        ],
    );
    assert!(
        output.status.success(),
        "trust-card compare failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("compare npm:@acme/auth-guard vs npm:@beta/telemetry-bridge:"));
    assert!(stdout.contains("- certification_level: gold -> bronze"));
    assert!(stdout.contains("- extension_version: 1.4.2 -> 0.9.1"));
    assert!(stdout.contains("- active_quarantine: false -> true"));
}

#[test]
fn trust_card_diff_reports_version_history_changes() {
    let workspace = seeded_fixture_trust_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &["trust-card", "diff", "npm:@beta/telemetry-bridge", "1", "2"],
    );
    assert!(
        output.status.success(),
        "trust-card diff failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("compare npm:@beta/telemetry-bridge@1 vs npm:@beta/telemetry-bridge@2:")
    );
    assert!(stdout.contains("- certification_level: silver -> bronze"));
    assert!(stdout.contains("- reputation_score_basis_points: 680 -> 410"));
    assert!(stdout.contains("- revocation_status: active -> revoked"));
}

#[test]
fn trust_commands_fail_closed_without_authoritative_registry_state() {
    let workspace = config_only_workspace();
    let output = run_cli_in_workspace(workspace.path(), &["trust", "card", "npm:@acme/auth-guard"]);
    assert!(
        !output.status.success(),
        "trust card should fail when authoritative registry state is missing"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("authoritative trust-card registry not initialized"));
}
