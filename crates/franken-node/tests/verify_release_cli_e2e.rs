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

fn path_scrubbers(paths: &[(&Path, &str)]) -> Vec<(String, String)> {
    let mut scrubbers = paths
        .iter()
        .map(|(path, replacement)| (path.display().to_string(), (*replacement).to_string()))
        .collect::<Vec<_>>();
    scrubbers.sort_by(|left, right| right.0.len().cmp(&left.0.len()));
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

fn verify_json_matrix_case(
    name: &str,
    args: Vec<String>,
    scrubbed_paths: &[(&Path, &str)],
) -> serde_json::Value {
    let output = run_cli_with_string_args(&args);
    let mut stdout_json = parse_json_stdout(&output);
    let repo_root = repo_root();
    let mut scrubbers = path_scrubbers(&[(&repo_root, "[repo]")]);
    scrubbers.extend(path_scrubbers(scrubbed_paths));
    scrubbers.sort_by(|left, right| right.0.len().cmp(&left.0.len()));
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
fn verify_migration_passes_for_known_verify_lane() {
    let output = run_cli(&["verify", "migration", "rewrite", "--json"]);
    assert!(
        output.status.success(),
        "verify migration should pass for known lane; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["command"], "verify migration");
    assert_eq!(payload["verdict"], "PASS");
    assert_eq!(payload["status"], "pass");
    assert_eq!(payload["exit_code"], 0);
    assert_eq!(payload["details"]["status"], "source_present");
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
    let state_dir = temp.path().join(".franken-node/state/migrations");
    std::fs::create_dir_all(&state_dir).expect("create migration state dir");
    let artifact_path = temp.path().join("dist/server.js");
    ensure_parent_dir(&artifact_path);
    std::fs::write(&artifact_path, "console.log('ok');").expect("write migration artifact");
    std::fs::write(
        state_dir.join("rewrite.json"),
        serde_json::json!({
            "migration_id": "rewrite",
            "status": "applied",
            "post_conditions": [
                "dist/server.js",
                {
                    "path": "dist/server.js",
                    "exists": true,
                    "contains": "console.log"
                }
            ]
        })
        .to_string(),
    )
    .expect("write migration record");

    let output = run_cli_in_dir(temp.path(), &["verify", "migration", "rewrite", "--json"]);
    assert!(
        output.status.success(),
        "verify migration should pass for applied migration record; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["verdict"], "PASS");
    assert_eq!(payload["details"]["status"], "applied");
    assert_eq!(payload["details"]["post_conditions_met"], true);
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
    let state_dir = temp.path().join(".franken-node/state/migrations");
    std::fs::create_dir_all(&state_dir).expect("create migration state dir");
    std::fs::write(
        state_dir.join("rewrite.json"),
        serde_json::json!({
            "migration_id": "rewrite",
            "status": "applied",
            "post_conditions": [
                "dist/missing.js"
            ]
        })
        .to_string(),
    )
    .expect("write migration record");

    let output = run_cli_in_dir(temp.path(), &["verify", "migration", "rewrite", "--json"]);
    assert!(
        !output.status.success(),
        "verify migration should fail when a post-condition is missing"
    );

    let payload = parse_json_stdout(&output);
    assert_eq!(payload["verdict"], "FAIL");
    assert_eq!(payload["details"]["status"], "applied");
    assert_eq!(payload["details"]["post_conditions_met"], false);
    assert!(
        payload["details"]["diff_summary"]
            .as_str()
            .unwrap_or_default()
            .contains("dist/missing.js")
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
        output.status.success(),
        "verify corpus should pass for existing artifact path; stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = parse_json_stdout(&output);
    assert_eq!(payload["command"], "verify corpus");
    assert_eq!(payload["verdict"], "PASS");
    assert_eq!(payload["exit_code"], 0);
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
fn verify_json_outputs_match_golden_matrix() {
    let corpus_temp = TempDir::new().expect("corpus temp dir");
    let corpus_file = corpus_temp.path().join("sample-corpus.json");
    std::fs::write(&corpus_file, b"{\"events\":[]}\n").expect("write corpus fixture");

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
            "migration_pass",
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
