use insta::assert_json_snapshot;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use frankenengine_node::supply_chain::artifact_signing::{build_and_sign_manifest, sign_artifact};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

fn fixture_artifact_signing_key(label: &[u8]) -> ed25519_dalek::SigningKey {
    let mut hasher = Sha256::new();
    hasher.update(b"verify_release_cli_e2e_artifact_key_v1:");
    hasher.update(u64::try_from(label.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(label);
    let seed: [u8; 32] = hasher.finalize().into();
    ed25519_dalek::SigningKey::from_bytes(&seed)
}

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
    run_cli_in_dir(repo_root().as_path(), args)
}

fn run_cli_in_dir(current_dir: &Path, args: &[&str]) -> Output {
    run_cli_in_dir_with_env(current_dir, args, &[])
}

fn run_cli_in_dir_with_env(current_dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let binary_path = resolve_binary_path();
    assert!(
        binary_path.is_file(),
        "franken-node binary not found at {}",
        binary_path.display()
    );
    let mut command = Command::new(&binary_path);
    command.current_dir(current_dir).args(args);
    for (key, value) in env {
        command.env(key, value);
    }
    command
        .output()
        .unwrap_or_else(|err| panic!("failed running `{}`: {err}", args.join(" ")))
}

fn ensure_parent_dir(path: &Path) {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)
            .unwrap_or_else(|err| panic!("failed creating {}: {err}", parent.display()));
    }
}

fn write_text_fixture(path: &Path, contents: &str) {
    ensure_parent_dir(path);
    std::fs::write(path, contents)
        .unwrap_or_else(|err| panic!("failed writing {}: {err}", path.display()));
}

fn read_json_fixture(path: &Path) -> serde_json::Value {
    let raw = std::fs::read_to_string(path)
        .unwrap_or_else(|err| panic!("failed reading {}: {err}", path.display()));
    serde_json::from_str(&raw)
        .unwrap_or_else(|err| panic!("invalid JSON in {}: {err}", path.display()))
}

fn write_json_fixture(path: &Path, value: &serde_json::Value) {
    write_text_fixture(
        path,
        &serde_json::to_string_pretty(value).expect("serialize JSON fixture"),
    );
}

fn write_valid_corpus_manifest(path: &Path) {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let manifest = serde_json::json!({
        "schema_version": "corpus-v1.0",
        "bead_id": "bd-p9cuk-test-corpus",
        "timestamp": timestamp,
        "fixtures": [
            {
                "fixture_id": "fixture-core-001",
                "api_surface": "fs.readFile",
                "band": "core",
                "expected_behavior": "utf8 read matches Node semantics",
                "node_version": "22.0.0",
                "deterministic": true,
                "spec_section": "fs"
            },
            {
                "fixture_id": "fixture-high-value-001",
                "api_surface": "process.env",
                "band": "high_value",
                "expected_behavior": "environment lookup preserves missing values",
                "node_version": "22.0.0",
                "deterministic": true,
                "spec_section": "process"
            },
            {
                "fixture_id": "fixture-edge-001",
                "api_surface": "path.join",
                "band": "edge",
                "expected_behavior": "path normalization handles empty components",
                "node_version": "22.0.0",
                "deterministic": true,
                "spec_section": "path"
            },
            {
                "fixture_id": "fixture-unsafe-001",
                "api_surface": "child_process.spawn",
                "band": "unsafe",
                "expected_behavior": "unsafe process launch is policy-gated",
                "node_version": "22.0.0",
                "deterministic": true,
                "spec_section": "child_process"
            }
        ],
        "summary": {
            "total_fixtures": 4,
            "by_band": {
                "core": 1,
                "high_value": 1,
                "edge": 1,
                "unsafe": 1
            }
        }
    });
    write_text_fixture(
        path,
        &serde_json::to_string_pretty(&manifest).expect("serialize corpus manifest"),
    );
}

const COMPAT_REPORT_API_FAMILIES: &[&str] = &[
    "buffer",
    "child_process",
    "cluster",
    "crypto",
    "events",
    "fs",
    "http",
    "net",
    "os",
    "path",
    "querystring",
    "stream",
    "timers",
    "tls",
    "url",
    "zlib",
];
const COMPAT_REPORT_BANDS: &[&str] = &["core", "high-value", "edge"];
const COMPAT_REPORT_RISK_BANDS: &[&str] = &["critical", "high", "medium", "low"];

fn valid_compatibility_report() -> serde_json::Value {
    let timestamp = chrono::Utc::now().to_rfc3339();
    let mut per_test_results = Vec::new();
    for index in 0..512usize {
        per_test_results.push(serde_json::json!({
            "test_id": format!("compat-case-{index:04}"),
            "api_family": COMPAT_REPORT_API_FAMILIES[index % COMPAT_REPORT_API_FAMILIES.len()],
            "band": COMPAT_REPORT_BANDS[index % COMPAT_REPORT_BANDS.len()],
            "risk_band": COMPAT_REPORT_RISK_BANDS[index % COMPAT_REPORT_RISK_BANDS.len()],
            "status": "pass",
        }));
    }

    serde_json::json!({
        "corpus": {
            "corpus_version": "compat-corpus-e2e-v1",
            "franken_node_version": "0.1.0-test",
            "lockstep_oracle_version": "lockstep-e2e-v1",
            "result_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "generated_at_utc": timestamp,
        },
        "totals": {
            "total_test_cases": per_test_results.len(),
            "passed_test_cases": per_test_results.len(),
            "failed_test_cases": 0,
            "errored_test_cases": 0,
            "skipped_test_cases": 0,
            "overall_pass_rate_pct": 100.0,
        },
        "thresholds": {
            "overall_pass_rate_min_pct": 95.0,
            "per_family_pass_rate_min_pct": 80.0,
            "band_pass_rate_min_pct": {
                "core": 95.0,
                "high-value": 95.0,
                "edge": 95.0,
            },
        },
        "previous_release": {
            "overall_pass_rate_pct": 99.0,
        },
        "ci_gate": {
            "threshold_met": true,
            "release_blocked": false,
            "regression_detected": false,
        },
        "failing_tests_tracking": [],
        "reproducibility": {
            "deterministic_seed": "verify-corpus-e2e-seed",
            "same_inputs_same_digest": true,
            "external_repro_command": "franken-node verify corpus compatibility-report.json --kind compatibility-report --json",
        },
        "per_test_results": per_test_results,
    })
}

fn write_valid_compatibility_report(path: &Path) {
    write_json_fixture(path, &valid_compatibility_report());
}

fn write_authoritative_migration_record(
    project_root: &Path,
    migration_id: &str,
    record: serde_json::Value,
) {
    let state_dir = project_root.join(".franken-node/state/migrations");
    std::fs::create_dir_all(&state_dir).expect("create migration state dir");
    std::fs::write(
        state_dir.join(format!("{migration_id}.json")),
        record.to_string(),
    )
    .expect("write migration record");
}

fn write_signed_release_fixture(release_dir: &Path, artifacts: &[(&str, &[u8])]) {
    let signing_key = fixture_artifact_signing_key(b"current");
    let manifest = build_and_sign_manifest(artifacts, &signing_key);

    for (name, bytes) in artifacts {
        let artifact_path = release_dir.join(name);
        ensure_parent_dir(&artifact_path);
        std::fs::write(&artifact_path, bytes)
            .unwrap_or_else(|err| panic!("failed writing {}: {err}", artifact_path.display()));

        let signature = sign_artifact(&signing_key, bytes);
        let signature_path = release_dir.join(format!("{name}.sig"));
        ensure_parent_dir(&signature_path);
        std::fs::write(&signature_path, hex::encode(signature))
            .unwrap_or_else(|err| panic!("failed writing {}: {err}", signature_path.display()));
    }

    let manifest_path = release_dir.join("SHA256SUMS");
    std::fs::write(&manifest_path, manifest.canonical_bytes())
        .unwrap_or_else(|err| panic!("failed writing {}: {err}", manifest_path.display()));

    let manifest_signature_path = release_dir.join("SHA256SUMS.sig");
    std::fs::write(&manifest_signature_path, hex::encode(manifest.signature)).unwrap_or_else(
        |err| {
            panic!(
                "failed writing {}: {err}",
                manifest_signature_path.display()
            )
        },
    );
}

fn write_release_key_dir(key_dir: &Path) {
    std::fs::create_dir_all(key_dir).expect("key dir");

    let wrong_key = fixture_artifact_signing_key(b"rotated");
    std::fs::write(
        key_dir.join("00-rotated.pub"),
        hex::encode(wrong_key.verifying_key().as_bytes()),
    )
    .expect("write rotated key");
    let correct_key = fixture_artifact_signing_key(b"current");
    std::fs::write(
        key_dir.join("10-current.pub"),
        hex::encode(correct_key.verifying_key().as_bytes()),
    )
    .expect("write current key");
    std::fs::write(key_dir.join("README.txt"), "non-key metadata").expect("write non-key file");
}

fn parse_json_stdout(output: &Output) -> serde_json::Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.trim().is_empty(),
        "expected JSON on stdout, got empty output; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_str(stdout.trim())
        .unwrap_or_else(|err| panic!("invalid JSON output: {err}\nstdout:\n{stdout}"))
}

fn run_cli_with_string_args(args: &[String]) -> Output {
    let borrowed_args = args.iter().map(String::as_str).collect::<Vec<_>>();
    run_cli(&borrowed_args)
}

fn run_verify_corpus(corpus_path: &Path, kind: Option<&str>) -> Output {
    let mut args = vec![
        "verify".to_string(),
        "corpus".to_string(),
        corpus_path.to_string_lossy().to_string(),
    ];
    if let Some(kind) = kind {
        args.push("--kind".to_string());
        args.push(kind.to_string());
    }
    args.push("--json".to_string());
    run_cli_with_string_args(&args)
}

fn assert_verify_corpus_failed_invariant(
    corpus_path: &Path,
    kind: Option<&str>,
    invariant_id: &str,
) -> serde_json::Value {
    let output = run_verify_corpus(corpus_path, kind);
    assert!(
        !output.status.success(),
        "verify corpus should fail for invariant {invariant_id}; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["command"], "verify corpus");
    assert_eq!(payload["verdict"], "FAIL");
    assert_eq!(payload["exit_code"], 1);
    assert!(
        payload["details"]["failed_invariants"]
            .as_array()
            .expect("failed invariants array")
            .iter()
            .any(|invariant| invariant["invariant_id"] == invariant_id),
        "missing failed invariant {invariant_id}: {payload:#?}"
    );
    assert!(
        payload["details"]["events"]
            .as_array()
            .expect("events array")
            .iter()
            .any(|event| event["event"] == "corpus_invariant_failed"
                && event["invariant_id"] == invariant_id),
        "missing structured failure event for {invariant_id}: {payload:#?}"
    );
    payload
}

fn path_scrubbers(paths: &[(&Path, &str)]) -> Vec<(String, String)> {
    let mut scrubbers = paths
        .iter()
        .map(|(path, replacement)| (path.display().to_string(), (*replacement).to_string()))
        .collect::<Vec<_>>();
    scrubbers.sort_by_key(|right| std::cmp::Reverse(right.0.len()));
    scrubbers
}

fn scrub_paths_in_text(text: &str, scrubbers: &[(String, String)]) -> String {
    let mut scrubbed = text.to_string();
    for (path, replacement) in scrubbers {
        scrubbed = scrubbed.replace(path, replacement);
    }
    scrubbed
}

fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn scrub_paths_in_json(value: &mut serde_json::Value, scrubbers: &[(String, String)]) {
    match value {
        serde_json::Value::Array(items) => {
            for item in items {
                scrub_paths_in_json(item, scrubbers);
            }
        }
        serde_json::Value::Object(map) => {
            for (key, nested) in map {
                if key == "trace_id" && nested.as_str().is_some() {
                    *nested = serde_json::Value::String("[trace-id]".to_string());
                    continue;
                }
                if key == "timestamp" && nested.as_str().is_some() {
                    *nested = serde_json::Value::String("[timestamp]".to_string());
                    continue;
                }
                if key == "sha256"
                    && let Some(hash) = nested.as_str()
                    && is_sha256_hex(hash)
                {
                    *nested = serde_json::Value::String("[sha256]".to_string());
                    continue;
                }
                scrub_paths_in_json(nested, scrubbers);
            }
        }
        serde_json::Value::String(text) => {
            *text = scrub_paths_in_text(text, scrubbers);
        }
        _ => {}
    }
}

fn compact_verify_corpus_snapshot(value: &mut serde_json::Value) {
    if value.get("command").and_then(serde_json::Value::as_str) != Some("verify corpus") {
        return;
    }
    let Some(details) = value
        .get_mut("details")
        .and_then(serde_json::Value::as_object_mut)
    else {
        return;
    };
    if details.contains_key("matched_artifacts") {
        details.insert(
            "matched_artifacts".to_string(),
            serde_json::Value::String("[validation-reports]".to_string()),
        );
    }
    if details.contains_key("events") {
        details.insert(
            "events".to_string(),
            serde_json::Value::String("[event-stream]".to_string()),
        );
    }
}

fn verify_json_matrix_case(
    name: &str,
    args: Vec<String>,
    scrubbed_paths: &[(&Path, &str)],
) -> serde_json::Value {
    let output = run_cli_with_string_args(&args);
    let mut stdout_json = parse_json_stdout(&output);
    compact_verify_corpus_snapshot(&mut stdout_json);
    let repo_root = repo_root();
    let mut scrubbers = path_scrubbers(&[(&repo_root, "[repo]")]);
    scrubbers.extend(path_scrubbers(scrubbed_paths));
    scrubbers.sort_by_key(|right| std::cmp::Reverse(right.0.len()));
    scrub_paths_in_json(&mut stdout_json, &scrubbers);

    let args = args
        .iter()
        .map(|arg| scrub_paths_in_text(arg, &scrubbers))
        .collect::<Vec<_>>();
    let stderr = String::from_utf8_lossy(&output.stderr);

    serde_json::json!({
        "name": name,
        "args": args,
        "exit_code": output.status.code().unwrap_or(-1),
        "success": output.status.success(),
        "stdout_json": stdout_json,
        "stderr": scrub_paths_in_text(stderr.trim(), &scrubbers),
    })
}

fn canonicalize_verify_release_snapshot(
    mut payload: serde_json::Value,
    release_dir: &Path,
    key_dir: &Path,
) -> serde_json::Value {
    let release_exact = release_dir.display().to_string();
    let release_prefix = format!("{}/", release_dir.display());
    let key_exact = key_dir.display().to_string();
    let key_prefix = format!("{}/", key_dir.display());

    fn scrub(
        value: &mut serde_json::Value,
        release_exact: &str,
        release_prefix: &str,
        key_exact: &str,
        key_prefix: &str,
    ) {
        match value {
            serde_json::Value::Array(items) => {
                for item in items {
                    scrub(item, release_exact, release_prefix, key_exact, key_prefix);
                }
            }
            serde_json::Value::Object(map) => {
                for nested in map.values_mut() {
                    scrub(nested, release_exact, release_prefix, key_exact, key_prefix);
                }
            }
            serde_json::Value::String(text) => {
                if text == release_exact {
                    *value = serde_json::Value::String("[release]".to_string());
                } else if let Some(path) = text.strip_prefix(release_prefix) {
                    *value = serde_json::Value::String(format!("[release]/{path}"));
                } else if text == key_exact {
                    *value = serde_json::Value::String("[keys]".to_string());
                } else if let Some(path) = text.strip_prefix(key_prefix) {
                    *value = serde_json::Value::String(format!("[keys]/{path}"));
                }
            }
            _ => {}
        }
    }

    scrub(
        &mut payload,
        &release_exact,
        &release_prefix,
        &key_exact,
        &key_prefix,
    );
    payload
}

#[test]
fn verify_module_passes_for_known_surface_module() {
    let output = run_cli(&["verify", "module", "runtime", "--json"]);
    assert!(
        output.status.success(),
        "verify module should pass for known module; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["command"], "verify module");
    assert_eq!(payload["verdict"], "PASS");
    assert_eq!(payload["status"], "pass");
    assert_eq!(payload["exit_code"], 0);
    assert_eq!(payload["contract_version"], "3.0.0");
    assert_eq!(payload["details"]["module_id"], "runtime");
    assert_eq!(payload["details"]["exists"], true);
    assert_eq!(payload["details"]["deps_satisfied"], true);
}

#[test]
fn verify_module_fails_for_unknown_module() {
    let output = run_cli(&["verify", "module", "definitely-not-a-real-module", "--json"]);
    assert!(
        !output.status.success(),
        "verify module should fail for unknown module"
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["command"], "verify module");
    assert_eq!(payload["verdict"], "FAIL");
    assert_eq!(payload["status"], "fail");
    assert_eq!(payload["exit_code"], 1);
}

#[test]
fn verify_module_rejects_unsupported_compat_version() {
    let output = run_cli(&[
        "verify",
        "module",
        "runtime",
        "--compat-version",
        "1",
        "--json",
    ]);
    assert!(
        !output.status.success(),
        "verify module should reject unsupported compat version"
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["command"], "verify module");
    assert_eq!(payload["compat_version"], 1);
    assert_eq!(payload["verdict"], "ERROR");
    assert_eq!(payload["status"], "error");
    assert_eq!(payload["exit_code"], 2);
    assert!(
        payload["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("unsupported --compat-version=1")
    );
}

#[test]
fn verify_migration_source_present_without_state_is_unproven() {
    let output = run_cli(&["verify", "migration", "rewrite", "--json"]);
    assert!(
        !output.status.success(),
        "verify migration source-only lane should not be authoritative; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["command"], "verify migration");
    assert_eq!(payload["verdict"], "UNPROVEN");
    assert_eq!(payload["status"], "unproven");
    assert_eq!(payload["exit_code"], 1);
    assert_eq!(payload["details"]["status"], "source_present");
    assert_eq!(payload["details"]["authority"], "diagnostic_only");
    assert_eq!(
        payload["details"]["invariant_failures"][0]["invariant_id"],
        "MIGRATION_EVIDENCE_RECORD_MISSING"
    );
}

#[test]
fn verify_migration_fails_for_unknown_target() {
    let output = run_cli(&["verify", "migration", "definitely-not-a-lane", "--json"]);
    assert!(
        !output.status.success(),
        "verify migration should fail for unknown lane"
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["command"], "verify migration");
    assert_eq!(payload["verdict"], "FAIL");
    assert_eq!(payload["status"], "fail");
    assert_eq!(payload["exit_code"], 1);
    assert!(
        payload["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("unknown migration target")
    );
}

#[test]
fn verify_compatibility_accepts_known_profile_targets() {
    let output = run_cli(&["verify", "compatibility", "strict", "--json"]);
    assert!(
        output.status.success(),
        "verify compatibility strict should pass; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = parse_json_stdout(&output);
    assert_eq!(payload["command"], "verify compatibility");
    assert_eq!(payload["verdict"], "PASS");
    assert_eq!(payload["exit_code"], 0);
    assert_eq!(payload["details"]["target_kind"], "profile");
}

#[test]
fn verify_compatibility_accepts_previous_major_compat_version() {
    let output = run_cli(&[
        "verify",
        "compatibility",
        "strict",
        "--compat-version",
        "2",
        "--json",
    ]);
    assert!(
        output.status.success(),
        "verify compatibility should accept previous major compat version; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["command"], "verify compatibility");
    assert_eq!(payload["compat_version"], 2);
    assert_eq!(payload["verdict"], "PASS");
    assert_eq!(payload["status"], "pass");
    assert_eq!(payload["exit_code"], 0);
}

#[test]
fn verify_migration_reads_state_record_and_checks_post_conditions() {
    let temp = TempDir::new().expect("temp dir");
    let artifact_path = temp.path().join("dist/server.js");
    let validation_path = temp.path().join("evidence/rewrite-validation.json");
    write_text_fixture(&artifact_path, "console.log('ok');");
    write_text_fixture(&validation_path, "{\"validated\":true}\n");
    write_authoritative_migration_record(
        temp.path(),
        "rewrite",
        serde_json::json!({
            "schema_version": "franken-node/migration-evidence/v1",
            "migration_id": "rewrite",
            "project_root": temp.path().display().to_string(),
            "status": "applied",
            "post_conditions_met": true,
            "validation_record_path": "evidence/rewrite-validation.json",
            "post_conditions": [
                "dist/server.js",
                {
                    "path": "dist/server.js",
                    "exists": true,
                    "contains": "console.log"
                }
            ]
        }),
    );

    let output = run_cli_in_dir(temp.path(), &["verify", "migration", "rewrite", "--json"]);
    assert!(
        output.status.success(),
        "verify migration should pass for applied migration record; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["verdict"], "PASS");
    assert_eq!(payload["details"]["status"], "applied");
    assert_eq!(payload["details"]["authority"], "authoritative");
    assert_eq!(payload["details"]["post_conditions_met"], true);
    assert_eq!(
        payload["details"]["invariant_failures"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert!(
        payload["details"]["record_path"]
            .as_str()
            .unwrap_or_default()
            .contains(".franken-node/state/migrations/rewrite.json")
    );
}

#[test]
fn verify_migration_fails_when_post_condition_is_missing() {
    let temp = TempDir::new().expect("temp dir");
    write_text_fixture(
        &temp.path().join("evidence/rewrite-validation.json"),
        "{\"validated\":false}\n",
    );
    write_authoritative_migration_record(
        temp.path(),
        "rewrite",
        serde_json::json!({
            "schema_version": "franken-node/migration-evidence/v1",
            "migration_id": "rewrite",
            "project_root": temp.path().display().to_string(),
            "status": "applied",
            "post_conditions_met": true,
            "validation_record_path": "evidence/rewrite-validation.json",
            "post_conditions": [
                "dist/missing.js"
            ]
        }),
    );

    let output = run_cli_in_dir(temp.path(), &["verify", "migration", "rewrite", "--json"]);
    assert!(
        !output.status.success(),
        "verify migration should fail when a post-condition is missing"
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["verdict"], "FAIL");
    assert_eq!(payload["details"]["status"], "applied");
    assert_eq!(payload["details"]["post_conditions_met"], false);
    assert_eq!(
        payload["details"]["invariant_failures"][0]["invariant_id"],
        "MIGRATION_EVIDENCE_POST_CONDITIONS_FAILED"
    );
    assert!(
        payload["details"]["diff_summary"]
            .as_str()
            .unwrap_or_default()
            .contains("dist/missing.js")
    );
}

#[test]
fn verify_migration_fails_when_record_schema_is_missing() {
    let temp = TempDir::new().expect("temp dir");
    write_text_fixture(
        &temp.path().join("evidence/rewrite-validation.json"),
        "{\"validated\":true}\n",
    );
    write_authoritative_migration_record(
        temp.path(),
        "rewrite",
        serde_json::json!({
            "migration_id": "rewrite",
            "project_root": temp.path().display().to_string(),
            "status": "applied",
            "post_conditions_met": true,
            "validation_record_path": "evidence/rewrite-validation.json"
        }),
    );

    let output = run_cli_in_dir(temp.path(), &["verify", "migration", "rewrite", "--json"]);
    assert!(
        !output.status.success(),
        "verify migration should fail when schema_version is missing"
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["verdict"], "FAIL");
    assert_eq!(
        payload["details"]["invariant_failures"][0]["invariant_id"],
        "MIGRATION_EVIDENCE_SCHEMA_MISSING"
    );
    assert!(
        payload["details"]["missing_fields"]
            .as_array()
            .unwrap()
            .contains(&serde_json::Value::String("schema_version".to_string()))
    );
}

#[test]
fn verify_migration_fails_when_record_scope_mismatches_project_root() {
    let temp = TempDir::new().expect("temp dir");
    let other_root = TempDir::new().expect("other root");
    write_text_fixture(
        &temp.path().join("evidence/rewrite-validation.json"),
        "{\"validated\":true}\n",
    );
    write_authoritative_migration_record(
        temp.path(),
        "rewrite",
        serde_json::json!({
            "schema_version": "franken-node/migration-evidence/v1",
            "migration_id": "rewrite",
            "project_root": other_root.path().display().to_string(),
            "status": "applied",
            "post_conditions_met": true,
            "validation_record_path": "evidence/rewrite-validation.json"
        }),
    );

    let output = run_cli_in_dir(temp.path(), &["verify", "migration", "rewrite", "--json"]);
    assert!(
        !output.status.success(),
        "verify migration should fail when project_root is from another workspace"
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["verdict"], "FAIL");
    assert_eq!(
        payload["details"]["invariant_failures"][0]["invariant_id"],
        "MIGRATION_EVIDENCE_PROJECT_ROOT_MISMATCH"
    );
}

#[test]
fn verify_migration_fails_when_record_id_mismatches_request() {
    let temp = TempDir::new().expect("temp dir");
    write_text_fixture(
        &temp.path().join("evidence/rewrite-validation.json"),
        "{\"validated\":true}\n",
    );
    write_authoritative_migration_record(
        temp.path(),
        "rewrite",
        serde_json::json!({
            "schema_version": "franken-node/migration-evidence/v1",
            "migration_id": "audit",
            "project_root": temp.path().display().to_string(),
            "status": "applied",
            "post_conditions_met": true,
            "validation_record_path": "evidence/rewrite-validation.json"
        }),
    );

    let output = run_cli_in_dir(temp.path(), &["verify", "migration", "rewrite", "--json"]);
    assert!(
        !output.status.success(),
        "verify migration should fail when record id does not match requested id"
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["verdict"], "FAIL");
    assert_eq!(
        payload["details"]["invariant_failures"][0]["invariant_id"],
        "MIGRATION_EVIDENCE_ID_MISMATCH"
    );
}

#[test]
fn verify_compatibility_accepts_current_binary_runtime() {
    let output = run_cli(&["verify", "compatibility", "franken-node", "--json"]);
    assert!(
        output.status.success(),
        "verify compatibility should pass for the current franken-node binary; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["verdict"], "PASS");
    assert_eq!(payload["details"]["target_kind"], "runtime");
    assert_eq!(payload["details"]["runtime"], "franken-node");
    assert_eq!(payload["details"]["installed"], true);
}

#[test]
fn verify_compatibility_fails_when_runtime_is_missing_from_path() {
    let output = run_cli_in_dir_with_env(
        repo_root().as_path(),
        &["verify", "compatibility", "node", "--json"],
        &[("PATH", "")],
    );
    assert!(
        !output.status.success(),
        "verify compatibility should fail when node is missing from PATH"
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["verdict"], "FAIL");
    assert_eq!(payload["details"]["runtime"], "node");
    assert_eq!(payload["details"]["installed"], false);
}

#[test]
fn verify_corpus_accepts_existing_artifact_path() {
    let temp = TempDir::new().expect("temp dir");
    let corpus_file = temp.path().join("sample-corpus.json");
    write_valid_corpus_manifest(&corpus_file);

    let output = run_cli(&[
        "verify",
        "corpus",
        corpus_file
            .to_str()
            .expect("corpus fixture path must be valid UTF-8"),
        "--json",
    ]);
    assert!(
        output.status.success(),
        "verify corpus should pass for existing artifact path; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = parse_json_stdout(&output);
    assert_eq!(payload["command"], "verify corpus");
    assert_eq!(payload["verdict"], "PASS");
    assert_eq!(payload["exit_code"], 0);
    assert_eq!(payload["details"]["requested_kind"], "auto");
    assert_eq!(payload["details"]["matched_count"], 1);
    assert_eq!(
        payload["details"]["matched_artifacts"][0]["validation_kind"],
        "corpus-manifest"
    );
    assert_eq!(
        payload["details"]["failed_invariants"],
        serde_json::json!([])
    );
    assert!(
        payload["details"]["events"]
            .as_array()
            .expect("events array")
            .iter()
            .any(|event| event["event"] == "corpus_validation_completed"
                && event["passed"] == serde_json::Value::Bool(true)),
        "verify corpus should emit completion event with pass=true: {payload:#?}"
    );
}

#[test]
fn verify_corpus_rejects_existing_but_unsupported_json() {
    let temp = TempDir::new().expect("temp dir");
    let corpus_file = temp.path().join("sample-corpus.json");
    std::fs::write(&corpus_file, b"{\"events\":[]}\n").expect("write corpus fixture");

    let output = run_cli(&[
        "verify",
        "corpus",
        corpus_file
            .to_str()
            .expect("corpus fixture path must be valid UTF-8"),
        "--json",
    ]);
    assert!(
        !output.status.success(),
        "verify corpus should fail existing unsupported JSON instead of passing on path existence"
    );
    let payload = parse_json_stdout(&output);
    assert_eq!(payload["command"], "verify corpus");
    assert_eq!(payload["verdict"], "FAIL");
    assert_eq!(payload["exit_code"], 1);
    assert!(
        payload["details"]["failed_invariants"]
            .as_array()
            .expect("failed invariants array")
            .iter()
            .any(|invariant| invariant["invariant_id"] == "VCORPUS-KIND-SUPPORTED"),
        "unsupported corpus JSON should report the failed semantic invariant: {payload:#?}"
    );
}

#[test]
fn verify_corpus_accepts_compatibility_report_path() {
    let report_path = repo_root().join("artifacts/13/compatibility_corpus_results.json");
    let output = run_verify_corpus(&report_path, Some("compatibility-report"));
    assert!(
        output.status.success(),
        "verify corpus should pass for the compatibility report; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["command"], "verify corpus");
    assert_eq!(payload["verdict"], "PASS");
    assert_eq!(
        payload["details"]["selected_validation_kind"],
        "compatibility-report"
    );
    assert_eq!(payload["details"]["case_count"], serde_json::json!(560));
    assert!(
        payload["details"]["events"]
            .as_array()
            .expect("events array")
            .iter()
            .any(|event| event["event"] == "coverage_summary_emitted"
                && event["validation_kind"] == "compatibility-report"),
        "compatibility report should emit a coverage event: {payload:#?}"
    );
}

#[test]
fn verify_corpus_rejects_duplicate_manifest_fixture_ids_from_generated_fixture() {
    let temp = TempDir::new().expect("temp dir");
    let corpus_file = temp.path().join("duplicate-corpus.json");
    write_valid_corpus_manifest(&corpus_file);
    let mut manifest = read_json_fixture(&corpus_file);
    let duplicate_id = manifest["fixtures"][0]["fixture_id"].clone();
    manifest["fixtures"][1]["fixture_id"] = duplicate_id;
    write_json_fixture(&corpus_file, &manifest);

    assert_verify_corpus_failed_invariant(
        &corpus_file,
        Some("corpus-manifest"),
        "VCORPUS-MANIFEST-UNIQUE-IDS",
    );
}

#[test]
fn verify_corpus_rejects_undersized_generated_manifest() {
    let temp = TempDir::new().expect("temp dir");
    let corpus_file = temp.path().join("undersized-corpus.json");
    write_valid_corpus_manifest(&corpus_file);
    let mut manifest = read_json_fixture(&corpus_file);
    manifest["fixtures"]
        .as_array_mut()
        .expect("fixtures array")
        .truncate(3);
    manifest["summary"]["total_fixtures"] = serde_json::json!(3);
    manifest["summary"]["by_band"]
        .as_object_mut()
        .expect("by_band object")
        .remove("unsafe");
    write_json_fixture(&corpus_file, &manifest);

    assert_verify_corpus_failed_invariant(
        &corpus_file,
        Some("corpus-manifest"),
        "VCORPUS-MANIFEST-MIN-CASES",
    );
}

#[test]
fn verify_corpus_rejects_stale_manifest() {
    let temp = TempDir::new().expect("temp dir");
    let corpus_file = temp.path().join("stale-corpus.json");
    write_valid_corpus_manifest(&corpus_file);
    let mut manifest = read_json_fixture(&corpus_file);
    manifest["timestamp"] =
        serde_json::json!((chrono::Utc::now() - chrono::Duration::days(181)).to_rfc3339());
    write_json_fixture(&corpus_file, &manifest);

    let payload = assert_verify_corpus_failed_invariant(
        &corpus_file,
        Some("corpus-manifest"),
        "VCORPUS-MANIFEST-FRESHNESS",
    );
    assert!(
        payload["details"]["events"]
            .as_array()
            .expect("events array")
            .iter()
            .any(|event| event["event"] == "stale_evidence_detected"
                && event["invariant_id"] == "VCORPUS-MANIFEST-FRESHNESS"),
        "stale manifests should emit stale evidence event: {payload:#?}"
    );
}

#[test]
fn verify_corpus_rejects_report_missing_required_api_family() {
    let temp = TempDir::new().expect("temp dir");
    let report_file = temp.path().join("compat-report-missing-family.json");
    let mut report =
        read_json_fixture(&repo_root().join("artifacts/13/compatibility_corpus_results.json"));
    for row in report["per_test_results"]
        .as_array_mut()
        .expect("per_test_results array")
    {
        if row["api_family"] == "zlib" {
            row["api_family"] = serde_json::json!("fs");
        }
    }
    write_json_fixture(&report_file, &report);

    assert_verify_corpus_failed_invariant(
        &report_file,
        Some("compatibility-report"),
        "VCORPUS-REPORT-FAMILY-COVERAGE",
    );
}

#[test]
fn verify_corpus_rejects_artifact_report_invalid_risk_band() {
    let temp = TempDir::new().expect("temp dir");
    let report_file = temp.path().join("compat-report-invalid-risk.json");
    let mut report =
        read_json_fixture(&repo_root().join("artifacts/13/compatibility_corpus_results.json"));
    report["per_test_results"][0]["risk_band"] = serde_json::json!("catastrophic");
    write_json_fixture(&report_file, &report);

    assert_verify_corpus_failed_invariant(
        &report_file,
        Some("compatibility-report"),
        "VCORPUS-REPORT-ROW-SHAPE",
    );
}

#[test]
fn verify_corpus_rejects_report_threshold_regression() {
    let temp = TempDir::new().expect("temp dir");
    let report_file = temp.path().join("compat-report-regression.json");
    let mut report =
        read_json_fixture(&repo_root().join("artifacts/13/compatibility_corpus_results.json"));
    report["previous_release"]["overall_pass_rate_pct"] = serde_json::json!(99.99);
    write_json_fixture(&report_file, &report);

    assert_verify_corpus_failed_invariant(
        &report_file,
        Some("compatibility-report"),
        "VCORPUS-REPORT-NO-REGRESSION",
    );
}

#[test]
fn verify_corpus_rejects_unsupported_compat_version_before_path_checks() {
    let output = run_cli(&[
        "verify",
        "corpus",
        "missing-corpus.json",
        "--compat-version",
        "1",
        "--json",
    ]);
    assert!(
        !output.status.success(),
        "verify corpus should reject unsupported compat version before searching for artifacts"
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["command"], "verify corpus");
    assert_eq!(payload["compat_version"], 1);
    assert_eq!(payload["verdict"], "ERROR");
    assert_eq!(payload["status"], "error");
    assert_eq!(payload["exit_code"], 2);
    assert!(
        payload["reason"]
            .as_str()
            .unwrap_or_default()
            .contains("unsupported --compat-version=1")
    );
}

#[test]
fn verify_corpus_accepts_compatibility_report_kind() {
    let temp = TempDir::new().expect("temp dir");
    let report_file = temp.path().join("compatibility-report.json");
    write_valid_compatibility_report(&report_file);

    let output = run_verify_corpus(&report_file, Some("compatibility-report"));
    assert!(
        output.status.success(),
        "verify corpus should pass for a complete compatibility report; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["command"], "verify corpus");
    assert_eq!(payload["verdict"], "PASS");
    assert_eq!(payload["details"]["requested_kind"], "compatibility-report");
    assert_eq!(
        payload["details"]["selected_validation_kind"],
        "compatibility-report"
    );
    assert_eq!(payload["details"]["case_count"], 512);
    assert!(
        payload["details"]["events"]
            .as_array()
            .expect("events array")
            .iter()
            .any(|event| event["event"] == "coverage_summary_emitted"
                && event["validation_kind"] == "compatibility-report"),
        "compatibility-report validation should emit coverage summary: {payload:#?}"
    );
}

#[test]
fn verify_corpus_rejects_duplicate_manifest_fixture_ids() {
    let temp = TempDir::new().expect("temp dir");
    let corpus_file = temp.path().join("duplicate-fixtures.json");
    write_valid_corpus_manifest(&corpus_file);
    let mut manifest = read_json_fixture(&corpus_file);
    manifest["fixtures"][1]["fixture_id"] = manifest["fixtures"][0]["fixture_id"].clone();
    write_json_fixture(&corpus_file, &manifest);

    assert_verify_corpus_failed_invariant(
        &corpus_file,
        Some("corpus-manifest"),
        "VCORPUS-MANIFEST-UNIQUE-IDS",
    );
}

#[test]
fn verify_corpus_rejects_undersized_manifest() {
    let temp = TempDir::new().expect("temp dir");
    let corpus_file = temp.path().join("undersized-corpus.json");
    write_valid_corpus_manifest(&corpus_file);
    let mut manifest = read_json_fixture(&corpus_file);
    manifest["fixtures"]
        .as_array_mut()
        .expect("fixtures array")
        .pop();
    manifest["summary"]["total_fixtures"] = serde_json::json!(3);
    manifest["summary"]["by_band"]["unsafe"] = serde_json::json!(0);
    write_json_fixture(&corpus_file, &manifest);

    assert_verify_corpus_failed_invariant(
        &corpus_file,
        Some("corpus-manifest"),
        "VCORPUS-MANIFEST-MIN-CASES",
    );
}

#[test]
fn verify_corpus_rejects_stale_manifest_evidence() {
    let temp = TempDir::new().expect("temp dir");
    let corpus_file = temp.path().join("stale-corpus.json");
    write_valid_corpus_manifest(&corpus_file);
    let mut manifest = read_json_fixture(&corpus_file);
    manifest["timestamp"] = serde_json::json!("2020-01-01T00:00:00Z");
    write_json_fixture(&corpus_file, &manifest);

    let payload = assert_verify_corpus_failed_invariant(
        &corpus_file,
        Some("corpus-manifest"),
        "VCORPUS-MANIFEST-FRESHNESS",
    );
    assert!(
        payload["details"]["events"]
            .as_array()
            .expect("events array")
            .iter()
            .any(|event| event["event"] == "stale_evidence_detected"
                && event["invariant_id"] == "VCORPUS-MANIFEST-FRESHNESS"),
        "stale corpus evidence should emit stale_evidence_detected: {payload:#?}"
    );
}

#[test]
fn verify_corpus_rejects_missing_required_report_family() {
    let temp = TempDir::new().expect("temp dir");
    let report_file = temp.path().join("missing-family-report.json");
    let mut report = valid_compatibility_report();
    for row in report["per_test_results"]
        .as_array_mut()
        .expect("per-test results")
    {
        if row["api_family"] == "zlib" {
            row["api_family"] = serde_json::json!("fs");
        }
    }
    write_json_fixture(&report_file, &report);

    assert_verify_corpus_failed_invariant(
        &report_file,
        Some("compatibility-report"),
        "VCORPUS-REPORT-FAMILY-COVERAGE",
    );
}

#[test]
fn verify_corpus_rejects_invalid_report_risk_band() {
    let temp = TempDir::new().expect("temp dir");
    let report_file = temp.path().join("invalid-risk-report.json");
    let mut report = valid_compatibility_report();
    report["per_test_results"][0]["risk_band"] = serde_json::json!("severe");
    write_json_fixture(&report_file, &report);

    assert_verify_corpus_failed_invariant(
        &report_file,
        Some("compatibility-report"),
        "VCORPUS-REPORT-ROW-SHAPE",
    );
}

#[test]
fn verify_corpus_rejects_threshold_regression() {
    let temp = TempDir::new().expect("temp dir");
    let report_file = temp.path().join("regressed-report.json");
    let mut report = valid_compatibility_report();
    report["per_test_results"][0]["status"] = serde_json::json!("fail");
    report["totals"]["passed_test_cases"] = serde_json::json!(511);
    report["totals"]["failed_test_cases"] = serde_json::json!(1);
    report["totals"]["overall_pass_rate_pct"] = serde_json::json!(99.8);
    report["previous_release"]["overall_pass_rate_pct"] = serde_json::json!(100.0);
    report["failing_tests_tracking"] = serde_json::json!([
        {
            "test_id": "compat-case-0000",
            "investigation_bead_id": "bd-p9cuk-regression",
            "investigation_status": "open"
        }
    ]);
    write_json_fixture(&report_file, &report);

    assert_verify_corpus_failed_invariant(
        &report_file,
        Some("compatibility-report"),
        "VCORPUS-REPORT-NO-REGRESSION",
    );
}

#[test]
fn verify_json_outputs_match_golden_matrix() {
    let corpus_temp = TempDir::new().expect("corpus temp dir");
    let corpus_file = corpus_temp.path().join("sample-corpus.json");
    write_valid_corpus_manifest(&corpus_file);

    let release_temp = TempDir::new().expect("release temp dir");
    let release_dir = release_temp.path().join("release");
    let key_dir = release_temp.path().join("keys");
    std::fs::create_dir_all(&release_dir).expect("release dir");
    let release_artifacts = [(
        "franken-node-linux-x64.tar.xz",
        b"artifact-linux-x64" as &[u8],
    )];
    write_signed_release_fixture(&release_dir, &release_artifacts);
    write_release_key_dir(&key_dir);
    std::fs::write(release_dir.join("rogue-extra.bin"), b"rogue payload")
        .expect("write rogue artifact");

    let corpus_arg = corpus_file.to_string_lossy().to_string();
    let release_arg = release_dir.to_string_lossy().to_string();
    let key_dir_arg = key_dir.to_string_lossy().to_string();

    let matrix = vec![
        verify_json_matrix_case(
            "module_pass",
            vec!["verify", "module", "config", "--json"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            &[],
        ),
        verify_json_matrix_case(
            "module_unknown",
            vec!["verify", "module", "definitely-not-a-real-module", "--json"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            &[],
        ),
        verify_json_matrix_case(
            "module_compat_error",
            vec![
                "verify",
                "module",
                "runtime",
                "--compat-version",
                "1",
                "--json",
            ]
            .into_iter()
            .map(str::to_string)
            .collect(),
            &[],
        ),
        verify_json_matrix_case(
            "migration_source_unproven",
            vec!["verify", "migration", "rewrite", "--json"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            &[],
        ),
        verify_json_matrix_case(
            "migration_unknown",
            vec!["verify", "migration", "definitely-not-a-lane", "--json"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            &[],
        ),
        verify_json_matrix_case(
            "compat_profile_pass",
            vec!["verify", "compatibility", "strict", "--json"]
                .into_iter()
                .map(str::to_string)
                .collect(),
            &[],
        ),
        verify_json_matrix_case(
            "corpus_pass",
            vec![
                "verify".to_string(),
                "corpus".to_string(),
                corpus_arg,
                "--json".to_string(),
            ],
            &[(&corpus_file, "[corpus]")],
        ),
        verify_json_matrix_case(
            "release_extra_artifact_fail",
            vec![
                "verify".to_string(),
                "release".to_string(),
                release_arg,
                "--key-dir".to_string(),
                key_dir_arg,
                "--json".to_string(),
            ],
            &[(&release_dir, "[release]"), (&key_dir, "[keys]")],
        ),
    ];

    assert_json_snapshot!("verify_json_output_matrix", matrix);
}

#[test]
fn verify_release_succeeds_with_hex_encoded_signatures_and_key_dir() {
    let temp = TempDir::new().expect("temp dir");
    let release_dir = temp.path().join("release");
    let key_dir = temp.path().join("keys");
    std::fs::create_dir_all(&release_dir).expect("release dir");

    let artifacts = [
        (
            "franken-node-linux-x64.tar.xz",
            b"artifact-linux-x64" as &[u8],
        ),
        (
            "franken-node-darwin-arm64.tar.xz",
            b"artifact-darwin-arm64" as &[u8],
        ),
    ];
    write_signed_release_fixture(&release_dir, &artifacts);
    write_release_key_dir(&key_dir);

    let release_arg = release_dir.to_string_lossy().to_string();
    let key_dir_arg = key_dir.to_string_lossy().to_string();
    let output = run_cli(&[
        "verify",
        "release",
        &release_arg,
        "--key-dir",
        &key_dir_arg,
        "--json",
    ]);
    assert!(
        output.status.success(),
        "verify release failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(
        payload["manifest_signature_ok"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(payload["overall_pass"], serde_json::Value::Bool(true));
    let results = payload["results"].as_array().expect("results array");
    assert_eq!(results.len(), artifacts.len());
    assert!(
        results
            .iter()
            .all(|row| row["passed"] == serde_json::Value::Bool(true))
    );
}

#[test]
fn verify_release_success_json_matches_snapshot() {
    let temp = TempDir::new().expect("temp dir");
    let release_dir = temp.path().join("release");
    let key_dir = temp.path().join("keys");
    std::fs::create_dir_all(&release_dir).expect("release dir");

    let artifacts = [
        (
            "franken-node-linux-x64.tar.xz",
            b"artifact-linux-x64" as &[u8],
        ),
        (
            "franken-node-darwin-arm64.tar.xz",
            b"artifact-darwin-arm64" as &[u8],
        ),
    ];
    write_signed_release_fixture(&release_dir, &artifacts);
    write_release_key_dir(&key_dir);

    let release_arg = release_dir.to_string_lossy().to_string();
    let key_dir_arg = key_dir.to_string_lossy().to_string();
    let output = run_cli(&[
        "verify",
        "release",
        &release_arg,
        "--key-dir",
        &key_dir_arg,
        "--json",
    ]);
    assert!(
        output.status.success(),
        "verify release failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = parse_json_stdout(&output);
    assert_json_snapshot!(
        "verify_release_success_json",
        canonicalize_verify_release_snapshot(payload, &release_dir, &key_dir)
    );
}

#[test]
fn verify_release_fails_when_unlisted_artifact_exists() {
    let temp = TempDir::new().expect("temp dir");
    let release_dir = temp.path().join("release");
    let key_dir = temp.path().join("keys");
    std::fs::create_dir_all(&release_dir).expect("release dir");

    let artifacts = [(
        "franken-node-linux-x64.tar.xz",
        b"artifact-linux-x64" as &[u8],
    )];
    write_signed_release_fixture(&release_dir, &artifacts);
    write_release_key_dir(&key_dir);
    std::fs::write(release_dir.join("rogue-extra.bin"), b"rogue payload")
        .expect("write rogue artifact");

    let release_arg = release_dir.to_string_lossy().to_string();
    let key_dir_arg = key_dir.to_string_lossy().to_string();
    let output = run_cli(&[
        "verify",
        "release",
        &release_arg,
        "--key-dir",
        &key_dir_arg,
        "--json",
    ]);
    assert!(
        !output.status.success(),
        "expected verify release failure for unlisted artifact"
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(
        payload["manifest_signature_ok"],
        serde_json::Value::Bool(true)
    );
    assert_eq!(payload["overall_pass"], serde_json::Value::Bool(false));

    let results = payload["results"].as_array().expect("results array");
    let rogue_entry = results
        .iter()
        .find(|row| {
            row["artifact_name"] == serde_json::Value::String("rogue-extra.bin".to_string())
        })
        .expect("rogue artifact result entry");
    assert_eq!(rogue_entry["passed"], serde_json::Value::Bool(false));
    assert!(
        rogue_entry["failure_reason"]
            .as_str()
            .unwrap_or_default()
            .contains("not listed")
    );
    assert_json_snapshot!(
        "verify_release_unlisted_artifact_json",
        canonicalize_verify_release_snapshot(payload, &release_dir, &key_dir)
    );
}

#[test]
fn release_manifest_inserted_invalid_line_fails_closed() {
    let temp = TempDir::new().expect("temp dir");
    let release_dir = temp.path().join("release");
    let key_dir = temp.path().join("keys");
    std::fs::create_dir_all(&release_dir).expect("release dir");

    let artifacts = [(
        "franken-node-linux-x64.tar.xz",
        b"artifact-linux-x64" as &[u8],
    )];
    write_signed_release_fixture(&release_dir, &artifacts);
    write_release_key_dir(&key_dir);

    let manifest_path = release_dir.join("SHA256SUMS");
    let mut manifest = std::fs::read_to_string(&manifest_path).expect("manifest");
    manifest.push_str("not covered by the manifest signature\n");
    std::fs::write(&manifest_path, manifest).expect("tamper manifest");

    let release_arg = release_dir.to_string_lossy().to_string();
    let key_dir_arg = key_dir.to_string_lossy().to_string();
    let output = run_cli(&[
        "verify",
        "release",
        &release_arg,
        "--key-dir",
        &key_dir_arg,
        "--json",
    ]);

    assert!(
        !output.status.success(),
        "expected inserted manifest line to fail closed"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("manifest"));
    assert!(stderr.contains("not canonical"));
}

#[test]
fn release_manifest_modified_field_invalidates_signature() {
    let temp = TempDir::new().expect("temp dir");
    let release_dir = temp.path().join("release");
    let key_dir = temp.path().join("keys");
    std::fs::create_dir_all(&release_dir).expect("release dir");

    let artifacts = [(
        "franken-node-linux-x64.tar.xz",
        b"artifact-linux-x64" as &[u8],
    )];
    write_signed_release_fixture(&release_dir, &artifacts);
    write_release_key_dir(&key_dir);

    let manifest_path = release_dir.join("SHA256SUMS");
    let manifest = std::fs::read_to_string(&manifest_path).expect("manifest");
    let mut fields = manifest.trim_end().split("  ").collect::<Vec<_>>();
    assert_eq!(fields.len(), 3);
    fields[2] = "999";
    std::fs::write(&manifest_path, format!("{}\n", fields.join("  "))).expect("tamper manifest");

    let release_arg = release_dir.to_string_lossy().to_string();
    let key_dir_arg = key_dir.to_string_lossy().to_string();
    let output = run_cli(&[
        "verify",
        "release",
        &release_arg,
        "--key-dir",
        &key_dir_arg,
        "--json",
    ]);

    assert!(
        !output.status.success(),
        "expected modified manifest field to invalidate signature"
    );
    let payload = parse_json_stdout(&output);
    assert_eq!(
        payload["manifest_signature_ok"],
        serde_json::Value::Bool(false)
    );
    assert_eq!(payload["overall_pass"], serde_json::Value::Bool(false));
}

#[test]
fn verify_release_fails_without_key_dir() {
    let temp = TempDir::new().expect("temp dir");
    let release_dir = temp.path().join("release");
    std::fs::create_dir_all(&release_dir).expect("release dir");

    let artifacts = [(
        "franken-node-linux-x64.tar.xz",
        b"artifact-linux-x64" as &[u8],
    )];
    write_signed_release_fixture(&release_dir, &artifacts);

    let release_arg = release_dir.to_string_lossy().to_string();
    let output = run_cli(&["verify", "release", &release_arg, "--json"]);
    assert!(
        !output.status.success(),
        "expected verify release failure without an explicit key directory"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--key-dir"));
}

#[test]
fn verify_release_fails_with_invalid_key_directory() {
    let temp = TempDir::new().expect("temp dir");
    let release_dir = temp.path().join("release");
    let key_dir = temp.path().join("keys");
    std::fs::create_dir_all(&release_dir).expect("release dir");
    std::fs::create_dir_all(&key_dir).expect("key dir");

    let artifacts = [(
        "franken-node-linux-x64.tar.xz",
        b"artifact-linux-x64" as &[u8],
    )];
    write_signed_release_fixture(&release_dir, &artifacts);
    std::fs::write(key_dir.join("README.txt"), "this is not an Ed25519 key")
        .expect("write invalid key file");

    let release_arg = release_dir.to_string_lossy().to_string();
    let key_dir_arg = key_dir.to_string_lossy().to_string();
    let output = run_cli(&[
        "verify",
        "release",
        &release_arg,
        "--key-dir",
        &key_dir_arg,
        "--json",
    ]);
    assert!(
        !output.status.success(),
        "expected verify release failure with invalid key directory"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("no usable Ed25519 public keys found"));
}
