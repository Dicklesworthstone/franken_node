use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use frankenengine_node::supply_chain::artifact_signing::KeyId;

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

fn registry_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(dir.path().join("plugin.fnext"), b"dummy extension payload").expect("write package");
    dir
}

fn write_signing_key(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create key dir");
    }
    fs::write(path, hex::encode([42_u8; 32])).expect("write signing key");
}

fn registry_state_root(workspace: &Path) -> PathBuf {
    workspace.join(".franken-node/state/registry")
}

fn registry_artifacts_root(workspace: &Path) -> PathBuf {
    registry_state_root(workspace).join("artifacts")
}

fn registry_archive_root(workspace: &Path) -> PathBuf {
    registry_state_root(workspace).join("archive")
}

fn collect_named_paths(root: &Path, file_name: &str, output: &mut Vec<PathBuf>) {
    if !root.is_dir() {
        return;
    }

    for entry in fs::read_dir(root).expect("read dir") {
        let entry = entry.expect("dir entry");
        let path = entry.path();
        let file_type = entry.file_type().expect("file type");
        if file_type.is_dir() {
            collect_named_paths(&path, file_name, output);
        } else if file_type.is_file() && entry.file_name() == std::ffi::OsStr::new(file_name) {
            output.push(path);
        }
    }
}

fn collect_manifest_paths(root: &Path) -> Vec<PathBuf> {
    let mut manifests = Vec::new();
    collect_named_paths(root, "artifact.manifest.json", &mut manifests);
    manifests.sort();
    manifests
}

fn publish_field(stdout: &str, field: &str) -> String {
    let prefix = format!("{field}=");
    stdout
        .split_whitespace()
        .find_map(|token| token.strip_prefix(&prefix))
        .unwrap_or_else(|| panic!("missing `{field}` in publish output: {stdout}"))
        .to_string()
}

fn tamper_manifest_signature(manifest_path: &Path) {
    let raw = fs::read_to_string(manifest_path).expect("read manifest");
    let mut manifest: serde_json::Value = serde_json::from_str(&raw).expect("parse manifest");
    manifest["manifest_bytes_b64"] = serde_json::Value::String("dGFtcGVyZWQ=".to_string());
    fs::write(
        manifest_path,
        serde_json::to_vec_pretty(&manifest).expect("serialize manifest"),
    )
    .expect("write tampered manifest");
}

#[test]
fn registry_publish_requires_explicit_signing_key() {
    let workspace = registry_workspace();
    let output = run_cli_in_workspace(workspace.path(), &["registry", "publish", "plugin.fnext"]);
    assert!(
        !output.status.success(),
        "registry publish should fail when signing key is omitted"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--signing-key"));
    assert!(stderr.contains("registry publish requires --signing-key"));
    assert!(stderr.contains("fix_command=mkdir -p .franken-node/keys && openssl rand -hex 32 > .franken-node/keys/publisher.ed25519 && franken-node registry publish plugin.fnext --signing-key .franken-node/keys/publisher.ed25519"));
}

#[test]
fn registry_publish_succeeds_with_operator_managed_signing_key() {
    let workspace = registry_workspace();
    let signing_key_path = workspace.path().join("keys/publisher.ed25519");
    write_signing_key(&signing_key_path);
    let signing_key_arg = signing_key_path.to_string_lossy().to_string();
    let expected_key_id = KeyId::from_verifying_key(
        &ed25519_dalek::SigningKey::from_bytes(&[42_u8; 32]).verifying_key(),
    )
    .to_string();

    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "registry",
            "publish",
            "plugin.fnext",
            "--signing-key",
            &signing_key_arg,
        ],
    );
    assert!(
        output.status.success(),
        "registry publish failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("registry publish: extension_id="));
    assert!(stdout.contains(&format!("publisher_key_id={expected_key_id}")));
    assert!(stdout.contains("signing_key_source=cli"));
    assert!(stdout.contains(&format!("signing_key_path={signing_key_arg}")));
    assert!(stdout.contains("artifact_path=.franken-node/state/registry/artifacts/"));
    assert!(stdout.contains("manifest_path=.franken-node/state/registry/artifacts/"));
    assert!(stdout.contains("integrity=verified"));
}

#[test]
fn registry_publish_rejects_invalid_signing_key_material() {
    let workspace = registry_workspace();
    let signing_key_path = workspace.path().join("keys/invalid.ed25519");
    fs::create_dir_all(signing_key_path.parent().expect("key parent")).expect("create key dir");
    fs::write(&signing_key_path, "not-a-valid-key").expect("write invalid key");
    let signing_key_arg = signing_key_path.to_string_lossy().to_string();

    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "registry",
            "publish",
            "plugin.fnext",
            "--signing-key",
            &signing_key_arg,
        ],
    );
    assert!(
        !output.status.success(),
        "registry publish should fail on invalid signing key material"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed decoding Ed25519 registry publish signing key"));
}

#[test]
fn registry_publish_persists_artifact_and_search_reports_integrity() {
    let workspace = registry_workspace();
    let signing_key_path = workspace.path().join("keys/publisher.ed25519");
    write_signing_key(&signing_key_path);
    let signing_key_arg = signing_key_path.to_string_lossy().to_string();

    let publish_output = run_cli_in_workspace(
        workspace.path(),
        &[
            "registry",
            "publish",
            "plugin.fnext",
            "--signing-key",
            &signing_key_arg,
        ],
    );
    assert!(
        publish_output.status.success(),
        "registry publish failed: {}",
        String::from_utf8_lossy(&publish_output.stderr)
    );

    let publish_stdout = String::from_utf8_lossy(&publish_output.stdout);
    let extension_id = publish_field(&publish_stdout, "extension_id");
    let artifact_path = workspace
        .path()
        .join(publish_field(&publish_stdout, "artifact_path"));
    let manifest_path = workspace
        .path()
        .join(publish_field(&publish_stdout, "manifest_path"));
    assert!(
        artifact_path.starts_with(registry_artifacts_root(workspace.path())),
        "artifact path not stored under registry artifacts root: {}",
        artifact_path.display()
    );
    assert!(artifact_path.is_file(), "missing stored artifact");
    assert!(manifest_path.is_file(), "missing manifest");

    let manifests = collect_manifest_paths(&registry_artifacts_root(workspace.path()));
    assert_eq!(manifests.len(), 1, "expected one active manifest");
    assert_eq!(manifests[0], manifest_path);

    let manifest_raw = fs::read_to_string(&manifest_path).expect("read manifest");
    let manifest: serde_json::Value = serde_json::from_str(&manifest_raw).expect("parse manifest");
    let expected_hash = {
        use sha2::Digest;
        format!(
            "sha256:{:x}",
            sha2::Sha256::digest(fs::read(&artifact_path).expect("read stored artifact"))
        )
    };
    assert_eq!(
        manifest["artifact_sha256"],
        serde_json::Value::String(expected_hash)
    );

    let verify_output =
        run_cli_in_workspace(workspace.path(), &["registry", "verify", &extension_id]);
    assert!(
        verify_output.status.success(),
        "registry verify failed: {}",
        String::from_utf8_lossy(&verify_output.stderr)
    );
    let verify_stdout = String::from_utf8_lossy(&verify_output.stdout);
    assert!(verify_stdout.contains("integrity=verified"));
    assert!(verify_stdout.contains("manifest_path=.franken-node/state/registry/artifacts/"));

    let search_output = run_cli_in_workspace(workspace.path(), &["registry", "search", "plugin"]);
    assert!(
        search_output.status.success(),
        "registry search failed: {}",
        String::from_utf8_lossy(&search_output.stderr)
    );
    let search_stdout = String::from_utf8_lossy(&search_output.stdout);
    assert!(search_stdout.contains(&extension_id));
    assert!(search_stdout.contains(".franken-node/state/registry/artifacts/"));
    assert!(search_stdout.contains("verified"));
}

#[test]
fn registry_verify_detects_corrupted_local_artifact() {
    let workspace = registry_workspace();
    let signing_key_path = workspace.path().join("keys/publisher.ed25519");
    write_signing_key(&signing_key_path);
    let signing_key_arg = signing_key_path.to_string_lossy().to_string();

    let publish_output = run_cli_in_workspace(
        workspace.path(),
        &[
            "registry",
            "publish",
            "plugin.fnext",
            "--signing-key",
            &signing_key_arg,
        ],
    );
    assert!(
        publish_output.status.success(),
        "registry publish failed: {}",
        String::from_utf8_lossy(&publish_output.stderr)
    );
    let publish_stdout = String::from_utf8_lossy(&publish_output.stdout);
    let extension_id = publish_field(&publish_stdout, "extension_id");
    let artifact_path = workspace
        .path()
        .join(publish_field(&publish_stdout, "artifact_path"));

    fs::write(&artifact_path, b"tampered artifact payload").expect("tamper artifact");

    let verify_output =
        run_cli_in_workspace(workspace.path(), &["registry", "verify", &extension_id]);
    assert!(
        !verify_output.status.success(),
        "registry verify should fail after tampering"
    );
    let stderr = String::from_utf8_lossy(&verify_output.stderr);
    assert!(
        stderr.contains("hash-mismatch"),
        "expected hash-mismatch in stderr, got: {stderr}"
    );
}

#[test]
fn registry_search_reports_hash_mismatch_for_corrupted_local_artifact() {
    let workspace = registry_workspace();
    let signing_key_path = workspace.path().join("keys/publisher.ed25519");
    write_signing_key(&signing_key_path);
    let signing_key_arg = signing_key_path.to_string_lossy().to_string();

    let publish_output = run_cli_in_workspace(
        workspace.path(),
        &[
            "registry",
            "publish",
            "plugin.fnext",
            "--signing-key",
            &signing_key_arg,
        ],
    );
    assert!(
        publish_output.status.success(),
        "registry publish failed: {}",
        String::from_utf8_lossy(&publish_output.stderr)
    );
    let publish_stdout = String::from_utf8_lossy(&publish_output.stdout);
    let extension_id = publish_field(&publish_stdout, "extension_id");
    let artifact_path = workspace
        .path()
        .join(publish_field(&publish_stdout, "artifact_path"));

    fs::write(&artifact_path, b"tampered artifact payload").expect("tamper artifact");

    let search_output = run_cli_in_workspace(workspace.path(), &["registry", "search", "plugin"]);
    assert!(
        search_output.status.success(),
        "registry search failed: {}",
        String::from_utf8_lossy(&search_output.stderr)
    );
    let search_stdout = String::from_utf8_lossy(&search_output.stdout);
    assert!(search_stdout.contains(&extension_id));
    assert!(search_stdout.contains(".franken-node/state/registry/artifacts/"));
    assert!(search_stdout.contains("hash-mismatch"));
}

#[test]
fn registry_search_reports_invalid_signature_for_tampered_manifest() {
    let workspace = registry_workspace();
    let signing_key_path = workspace.path().join("keys/publisher.ed25519");
    write_signing_key(&signing_key_path);
    let signing_key_arg = signing_key_path.to_string_lossy().to_string();

    let publish_output = run_cli_in_workspace(
        workspace.path(),
        &[
            "registry",
            "publish",
            "plugin.fnext",
            "--signing-key",
            &signing_key_arg,
        ],
    );
    assert!(
        publish_output.status.success(),
        "registry publish failed: {}",
        String::from_utf8_lossy(&publish_output.stderr)
    );
    let publish_stdout = String::from_utf8_lossy(&publish_output.stdout);
    let extension_id = publish_field(&publish_stdout, "extension_id");
    let manifest_path = workspace
        .path()
        .join(publish_field(&publish_stdout, "manifest_path"));

    tamper_manifest_signature(&manifest_path);

    let search_output = run_cli_in_workspace(workspace.path(), &["registry", "search", "plugin"]);
    assert!(
        search_output.status.success(),
        "registry search failed: {}",
        String::from_utf8_lossy(&search_output.stderr)
    );
    let search_stdout = String::from_utf8_lossy(&search_output.stdout);
    assert!(search_stdout.contains(&extension_id));
    assert!(search_stdout.contains(".franken-node/state/registry/artifacts/"));
    assert!(search_stdout.contains("invalid-signature"));
}

#[test]
fn registry_verify_detects_tampered_manifest_signature() {
    let workspace = registry_workspace();
    let signing_key_path = workspace.path().join("keys/publisher.ed25519");
    write_signing_key(&signing_key_path);
    let signing_key_arg = signing_key_path.to_string_lossy().to_string();

    let publish_output = run_cli_in_workspace(
        workspace.path(),
        &[
            "registry",
            "publish",
            "plugin.fnext",
            "--signing-key",
            &signing_key_arg,
        ],
    );
    assert!(
        publish_output.status.success(),
        "registry publish failed: {}",
        String::from_utf8_lossy(&publish_output.stderr)
    );
    let publish_stdout = String::from_utf8_lossy(&publish_output.stdout);
    let extension_id = publish_field(&publish_stdout, "extension_id");
    let manifest_path = workspace
        .path()
        .join(publish_field(&publish_stdout, "manifest_path"));

    tamper_manifest_signature(&manifest_path);

    let verify_output =
        run_cli_in_workspace(workspace.path(), &["registry", "verify", &extension_id]);
    assert!(
        !verify_output.status.success(),
        "registry verify should fail after manifest tampering"
    );
    let stderr = String::from_utf8_lossy(&verify_output.stderr);
    assert!(
        stderr.contains("invalid-signature"),
        "expected invalid-signature in stderr, got: {stderr}"
    );
    assert!(
        stderr.contains(".franken-node/state/registry/artifacts/"),
        "expected artifact and manifest paths in stderr, got: {stderr}"
    );
}

#[test]
fn registry_gc_archives_older_lineage_entries() {
    let workspace = registry_workspace();
    let signing_key_path = workspace.path().join("keys/publisher.ed25519");
    write_signing_key(&signing_key_path);
    let signing_key_arg = signing_key_path.to_string_lossy().to_string();

    let mut published_extension_ids = Vec::new();
    for payload in [
        b"first artifact payload".as_slice(),
        b"second artifact payload".as_slice(),
    ] {
        fs::write(workspace.path().join("plugin.fnext"), payload).expect("rewrite package");
        let publish_output = run_cli_in_workspace(
            workspace.path(),
            &[
                "registry",
                "publish",
                "plugin.fnext",
                "--signing-key",
                &signing_key_arg,
            ],
        );
        assert!(
            publish_output.status.success(),
            "registry publish failed: {}",
            String::from_utf8_lossy(&publish_output.stderr)
        );
        let publish_stdout = String::from_utf8_lossy(&publish_output.stdout);
        published_extension_ids.push(publish_field(&publish_stdout, "extension_id"));
    }

    let active_before = collect_manifest_paths(&registry_artifacts_root(workspace.path()));
    assert_eq!(
        active_before.len(),
        2,
        "expected two active manifests before gc"
    );

    let gc_output = run_cli_in_workspace(workspace.path(), &["registry", "gc", "--keep", "1"]);
    assert!(
        gc_output.status.success(),
        "registry gc failed: {}",
        String::from_utf8_lossy(&gc_output.stderr)
    );
    let gc_stdout = String::from_utf8_lossy(&gc_output.stdout);
    assert!(gc_stdout.contains("archived=1"));

    let active_after = collect_manifest_paths(&registry_artifacts_root(workspace.path()));
    let archived_after = collect_manifest_paths(&registry_archive_root(workspace.path()));
    assert_eq!(
        active_after.len(),
        1,
        "expected one active manifest after gc"
    );
    assert_eq!(
        archived_after.len(),
        1,
        "expected one archived manifest after gc"
    );

    let archived_verify = run_cli_in_workspace(
        workspace.path(),
        &["registry", "verify", &published_extension_ids[0]],
    );
    assert!(
        archived_verify.status.success(),
        "registry verify should succeed for archived artifacts: {}",
        String::from_utf8_lossy(&archived_verify.stderr)
    );
    let archived_stdout = String::from_utf8_lossy(&archived_verify.stdout);
    assert!(archived_stdout.contains("archived=true"));
    assert!(archived_stdout.contains(".franken-node/state/registry/archive/"));
}
