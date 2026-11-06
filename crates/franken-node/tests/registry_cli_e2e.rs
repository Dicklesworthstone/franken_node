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
    if let Some(exe) = option_env!("CARGO_BIN_EXE_franken-node") {
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

fn run_git_in_workspace(workspace: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(workspace)
        .args(args)
        .status()
        .unwrap_or_else(|err| panic!("failed running `git {}`: {err}", args.join(" ")));
    assert!(status.success(), "git command failed: {}", args.join(" "));
}

fn registry_workspace() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    fs::write(dir.path().join("plugin.fnext"), b"dummy extension payload").expect("write package");
    run_git_in_workspace(dir.path(), &["init", "-b", "main"]);
    run_git_in_workspace(
        dir.path(),
        &["config", "user.email", "registry@example.com"],
    );
    run_git_in_workspace(dir.path(), &["config", "user.name", "Registry Test"]);
    run_git_in_workspace(
        dir.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://example.com/acme/plugin.git",
        ],
    );
    run_git_in_workspace(dir.path(), &["add", "plugin.fnext"]);
    run_git_in_workspace(dir.path(), &["commit", "-m", "initial"]);
    dir
}

fn write_signing_key(path: &Path) {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create key dir");
    }
    fs::write(path, hex::encode([42_u8; 32])).expect("write signing key");
}

/// Mutations that intentionally represent another legitimate publication must
/// sign both the exact registration bytes and their provenance binding. Merely
/// re-signing the source manifest is no longer a valid positive control.
fn resign_published_provenance(manifest: &mut serde_json::Value, key: &ed25519_dalek::SigningKey) {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use frankenengine_node::supply_chain::{artifact_signing, provenance, registry_artifact};
    let manifest_bytes = STANDARD
        .decode(manifest["manifest_bytes_b64"].as_str().unwrap())
        .unwrap();
    let mut attestation: provenance::ProvenanceAttestation =
        serde_json::from_value(manifest["extension"]["provenance"].clone()).unwrap();
    let payload = registry_artifact::registry_publish_provenance_signature_payload(
        &manifest_bytes,
        &attestation,
    )
    .unwrap();
    attestation.custom_claims.insert(
        "operator_provenance_signature".into(),
        hex::encode(artifact_signing::sign_bytes(key, &payload)),
    );
    let keys = attestation
        .links
        .iter()
        .map(|link| (link.signer_id.clone(), key.clone()))
        .collect();
    provenance::sign_links_in_place(&mut attestation, &keys).unwrap();
    manifest["extension"]["provenance"] = serde_json::to_value(attestation).unwrap();
}

fn publisher_runtime_authority() -> serde_json::Value {
    serde_json::json!({
        "schema_version": "franken-node/artifact-runtime-authority/v1",
        "policy_revision": "publisher-policy-7",
        "allowed_capabilities": [
            "builtin", "console", "fs_read", "heap_allocate", "module_load", "timer", "vm_dispatch"
        ],
        "allow_process_shape": false,
        "max_instructions": 2_000_000,
        "max_registers": 1_024,
        "max_call_depth": 32,
        "max_heap_objects": 4_096,
        "max_total_memory_bytes": 33_554_432,
        "max_console_entries": 16,
        "max_parse_source_bytes": 65_536,
        "max_parse_tokens": 16_384,
        "max_parse_recursion_depth": 128
    })
}

#[test]
fn registry_publish_runtime_authority_rejects_invalid_policy_before_persistence() {
    let workspace = registry_workspace();
    let signing_key = workspace.path().join("publisher.ed25519");
    write_signing_key(&signing_key);
    let policy_path = workspace.path().join("runtime-authority.json");
    let mut unknown_field = publisher_runtime_authority();
    unknown_field["unrecognized_permission"] = serde_json::json!(true);
    let mut missing_field = publisher_runtime_authority();
    missing_field
        .as_object_mut()
        .unwrap()
        .remove("max_instructions");
    let mut zero_budget = publisher_runtime_authority();
    zero_budget["max_instructions"] = serde_json::json!(0);
    let mut missing_ambient = publisher_runtime_authority();
    missing_ambient["allowed_capabilities"] = serde_json::json!(["module_load"]);
    let cases = [
        serde_json::to_vec(&unknown_field).unwrap(),
        serde_json::to_vec(&missing_field).unwrap(),
        serde_json::to_vec(&zero_budget).unwrap(),
        serde_json::to_vec(&missing_ambient).unwrap(),
        vec![b' '; (64 << 10) + 1],
    ];
    for (case, bytes) in cases.iter().enumerate() {
        fs::write(&policy_path, bytes).unwrap();
        let output = run_cli_in_workspace(
            workspace.path(),
            &[
                "registry",
                "publish",
                "plugin.fnext",
                "--version",
                "1.2.3",
                "--signing-key",
                signing_key.to_str().unwrap(),
                "--runtime-authority",
                policy_path.to_str().unwrap(),
                "--json",
            ],
        );
        assert!(
            !output.status.success(),
            "invalid authority case {case} was published"
        );
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
                panic!(
                    "case {case}: {error}; stdout={} stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                )
            });
        assert_eq!(
            report["schema_version"],
            "franken-node/registry-publish-error/v1"
        );
        assert!(collect_manifest_paths(&registry_artifacts_root(workspace.path())).is_empty());
    }
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

fn publish_signed_artifact(workspace: &Path) -> (String, PathBuf, PathBuf) {
    let signing_key_path = workspace.join("keys/publisher.ed25519");
    write_signing_key(&signing_key_path);
    let output = run_cli_in_workspace(
        workspace,
        &[
            "registry",
            "publish",
            "plugin.fnext",
            "--version",
            "1.0.0",
            "--signing-key",
            signing_key_path.to_str().expect("signing key path"),
            "--json",
        ],
    );
    assert!(
        output.status.success(),
        "registry publish failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).expect("publish report");
    assert_eq!(report["integrity"], "verified");
    (
        report["extension_id"]
            .as_str()
            .expect("extension id")
            .to_string(),
        workspace.join(report["artifact_path"].as_str().expect("artifact path")),
        workspace.join(report["manifest_path"].as_str().expect("manifest path")),
    )
}

#[cfg(all(feature = "engine", unix))]
fn source_fixture_command(workspace: &Path, state_home: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(resolve_binary_path());
    command
        .current_dir(workspace)
        .env("XDG_STATE_HOME", state_home)
        .env("XDG_CONFIG_HOME", state_home.join("config"))
        .env("PUBLISHER_TEST_VALUE", "VISIBLE_FROM_OPERATOR")
        .env_remove("FRANKEN_NODE_PROFILE")
        .env_remove("FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH")
        .args(args);
    command
}

#[cfg(all(feature = "engine", unix))]
fn run_source_fixture_cli(workspace: &Path, state_home: &Path, args: &[&str]) -> Output {
    source_fixture_command(workspace, state_home, args)
        .output()
        .expect("launch native publisher-approved source fixture")
}

#[cfg(all(feature = "engine", unix))]
struct PublishedSourceFixture {
    registry: tempfile::TempDir,
    project: tempfile::TempDir,
    state_home: tempfile::TempDir,
    entrypoint: String,
    public_key: PathBuf,
    manifest: PathBuf,
    artifact: PathBuf,
    graph_hash: String,
}

#[cfg(all(feature = "engine", unix))]
impl PublishedSourceFixture {
    fn new(esm: bool) -> Self {
        let (source, dependency) = if esm {
            (
                "import value from './side.mjs'; console.log('PUBLISHER_APPROVED_WORKLOAD', value);\n",
                "export default 42;\n",
            )
        } else {
            (
                "const value = require('./side.cjs'); console.log('PUBLISHER_APPROVED_WORKLOAD', value);\n",
                "module.exports = 42;\n",
            )
        };
        Self::with_modules(
            if esm { "app.mjs" } else { "app.cjs" },
            &[
                (if esm { "app.mjs" } else { "app.cjs" }, source),
                (if esm { "side.mjs" } else { "side.cjs" }, dependency),
            ],
        )
    }

    fn with_modules(entrypoint: &str, modules: &[(&str, &str)]) -> Self {
        Self::with_modules_and_authority(entrypoint, modules, None)
    }

    fn with_modules_and_authority(
        entrypoint: &str,
        modules: &[(&str, &str)],
        authority: Option<&serde_json::Value>,
    ) -> Self {
        let registry = registry_workspace();
        let project = tempfile::tempdir().unwrap();
        // Runtime evidence belongs outside the guest authority. Retain a
        // separate private state home instead of touching operator state.
        let state_home = tempfile::tempdir().unwrap();
        let entrypoint = entrypoint.to_owned();
        for (path, source) in modules {
            let path = project.path().join(path);
            fs::create_dir_all(path.parent().unwrap()).unwrap();
            fs::write(path, source).unwrap();
        }
        fs::write(
            project.path().join("package.json"),
            "{\"name\":\"publisher-capsule-test\",\"version\":\"1.0.0\"}\n",
        )
        .unwrap();
        let initialized = run_source_fixture_cli(
            project.path(),
            state_home.path(),
            &["init", "--profile", "balanced", "--out-dir", ".", "--json"],
        );
        assert!(
            initialized.status.success(),
            "init: {}\n{}",
            String::from_utf8_lossy(&initialized.stdout),
            String::from_utf8_lossy(&initialized.stderr)
        );
        let capture = run_cli_in_workspace(
            registry.path(),
            &[
                "verify",
                "source-graph",
                project.path().to_str().unwrap(),
                &entrypoint,
                "--write-source-capsule",
                "application.capsule",
                "--json",
            ],
        );
        assert!(
            capture.status.success(),
            "capture: {}\n{}",
            String::from_utf8_lossy(&capture.stdout),
            String::from_utf8_lossy(&capture.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&capture.stdout).unwrap();
        let graph_hash = report["input_hash"].as_str().unwrap().to_owned();
        assert_eq!(report["execution_performed"], false);
        assert_eq!(report["capsule_path"], "application.capsule");
        assert_eq!(report["capsule_closure_verified"], true);
        let signing_key_path = registry.path().join("publisher.ed25519");
        write_signing_key(&signing_key_path);
        let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
        let public_key = registry.path().join("publisher.pub");
        fs::write(&public_key, hex::encode(key.verifying_key().as_bytes())).unwrap();
        let authority_path = registry.path().join("runtime-authority.json");
        let mut publish_args = vec![
            "registry",
            "publish",
            "application.capsule",
            "--version",
            "1.2.3",
            "--signing-key",
            signing_key_path.to_str().unwrap(),
            "--json",
        ];
        if let Some(authority) = authority {
            fs::write(&authority_path, serde_json::to_vec(authority).unwrap()).unwrap();
            publish_args.extend(["--runtime-authority", authority_path.to_str().unwrap()]);
        }
        let publish = run_cli_in_workspace(registry.path(), &publish_args);
        assert!(
            publish.status.success(),
            "publish: {}\n{}",
            String::from_utf8_lossy(&publish.stdout),
            String::from_utf8_lossy(&publish.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&publish.stdout).unwrap();
        assert_eq!(report["integrity"], "verified");
        if let Some(authority) = authority {
            assert_eq!(&report["runtime_authority"], authority);
        } else {
            assert!(report.get("runtime_authority").is_none());
        }
        let manifest = registry
            .path()
            .join(report["manifest_path"].as_str().unwrap());
        let artifact = registry
            .path()
            .join(report["artifact_path"].as_str().unwrap());
        Self {
            registry,
            project,
            state_home,
            entrypoint,
            public_key,
            manifest,
            artifact,
            graph_hash,
        }
    }

    fn run(&self, extra: &[&str]) -> Output {
        self.run_with_policy("balanced", extra)
    }

    fn run_with_policy(&self, policy: &str, extra: &[&str]) -> Output {
        let mut args = vec![
            "run",
            &self.entrypoint,
            "--config",
            "franken_node.toml",
            "--policy",
            policy,
            "--runtime",
            "franken-engine",
            "--frozen-modules",
            "--registry-artifact",
            self.manifest.to_str().unwrap(),
            "--publisher-public-key",
            self.public_key.to_str().unwrap(),
            "--json",
        ];
        args.extend_from_slice(extra);
        run_source_fixture_cli(self.project.path(), self.state_home.path(), &args)
    }

    fn assert_denied(&self, extra: &[&str], expected: &str) {
        let output = self.run(extra);
        let diagnostics = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !output.status.success(),
            "unexpected admission: {diagnostics}"
        );
        assert!(
            diagnostics.contains(expected),
            "expected {expected}: {diagnostics}"
        );
        assert!(
            !diagnostics.contains("PUBLISHER_APPROVED_WORKLOAD"),
            "guest executed before refusal: {diagnostics}"
        );
    }
}

#[test]
fn trust_execution_revocation_rejects_ambiguous_and_partial_targets_before_mutation() {
    let workspace = tempfile::tempdir().unwrap();
    for args in [
        vec![
            "trust",
            "revoke",
            "--artifact-sha256",
            "sha256:deadbeef",
            "--json",
        ],
        vec![
            "trust",
            "revoke",
            "npm:plugin",
            "--artifact-sha256",
            "bad",
            "--json",
        ],
        vec![
            "trust",
            "revoke",
            "--publisher-public-key",
            "publisher.pub",
            "--artifact-sha256",
            "bad",
            "--json",
        ],
    ] {
        let output = run_cli_in_workspace(workspace.path(), &args);
        assert!(!output.status.success());
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)
            .expect("invalid revocation target must preserve structured CLI errors");
        assert_eq!(report["schema_version"], "franken-node/trust-error-cli/v1");
        assert_eq!(report["command"], "trust.revoke");
        assert!(
            !workspace.path().join(".franken-node").exists(),
            "invalid target must be rejected before creating or mutating trust state"
        );
    }
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn registry_source_capsule_obeys_exact_publisher_and_artifact_revocations_without_dependencies() {
    use frankenengine_node::supply_chain::registry_artifact::artifact_sha256;

    for publisher_target in [true, false] {
        for signed_authority in [false, true] {
            let authority = publisher_runtime_authority();
            let fixture = PublishedSourceFixture::with_modules_and_authority(
                "app.cjs",
                &[("app.cjs", "console.log('PUBLISHER_APPROVED_WORKLOAD');\n")],
                signed_authority.then_some(&authority),
            );
            let digest = artifact_sha256(&fs::read(&fixture.artifact).unwrap());
            let unrelated_key = fixture.registry.path().join("unrelated.pub");
            let key = ed25519_dalek::SigningKey::from_bytes(&[43; 32]);
            fs::write(&unrelated_key, hex::encode(key.verifying_key().as_bytes())).unwrap();
            let unrelated_digest = format!("sha256:{}", "fe".repeat(32));
            let (flag, unrelated, matching) = if publisher_target {
                (
                    "--publisher-public-key",
                    unrelated_key.to_str().unwrap(),
                    fixture.public_key.to_str().unwrap(),
                )
            } else {
                (
                    "--artifact-sha256",
                    unrelated_digest.as_str(),
                    digest.as_str(),
                )
            };
            let unrelated = run_source_fixture_cli(
                fixture.project.path(),
                fixture.state_home.path(),
                &["trust", "revoke", flag, unrelated, "--json"],
            );
            assert!(
                unrelated.status.success(),
                "{}",
                String::from_utf8_lossy(&unrelated.stderr)
            );
            let admitted = fixture.run(&[]);
            assert!(
                admitted.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&admitted.stdout),
                String::from_utf8_lossy(&admitted.stderr)
            );
            let report: serde_json::Value = serde_json::from_slice(&admitted.stdout).unwrap();
            assert_eq!(
                report["dispatch"]["captured_output"]["stdout"],
                "PUBLISHER_APPROVED_WORKLOAD\n"
            );

            let revoke_args = ["trust", "revoke", flag, matching, "--json"];
            let revoked = run_source_fixture_cli(
                fixture.project.path(),
                fixture.state_home.path(),
                &revoke_args,
            );
            assert!(
                revoked.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&revoked.stdout),
                String::from_utf8_lossy(&revoked.stderr)
            );
            let record: serde_json::Value = serde_json::from_slice(&revoked.stdout).unwrap();
            assert_eq!(
                record["schema_version"],
                "franken-node/trust-execution-revocation-cli/v1"
            );
            assert_eq!(record["scope"], "project_registry");
            assert_eq!(record["revoked"], true);
            let repeated = run_source_fixture_cli(
                fixture.project.path(),
                fixture.state_home.path(),
                &revoke_args,
            );
            assert!(repeated.status.success());
            let repeated: serde_json::Value = serde_json::from_slice(&repeated.stdout).unwrap();
            assert_eq!(
                repeated["revocation"], record["revocation"],
                "repeat revocation retains the original record"
            );

            for policy in ["strict", "balanced", "legacy-risky"] {
                let denied = fixture.run_with_policy(policy, &[]);
                let diagnostic = format!(
                    "{}\n{}",
                    String::from_utf8_lossy(&denied.stdout),
                    String::from_utf8_lossy(&denied.stderr)
                );
                assert!(
                    !denied.status.success(),
                    "revocation bypassed in {policy}: {diagnostic}"
                );
                assert!(
                    diagnostic.contains("revoked"),
                    "must deny the exact authority in {policy}: {diagnostic}"
                );
                assert!(
                    !diagnostic.contains("PUBLISHER_APPROVED_WORKLOAD"),
                    "revoked guest executed: {diagnostic}"
                );
            }
        }
    }
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn registry_revocation_stops_a_running_native_guest_and_retains_its_effect_observation() {
    use frankenengine_node::supply_chain::registry_artifact::artifact_sha256;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    struct ReapChild(std::process::Child);
    impl Drop for ReapChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    for publisher_target in [true, false] {
        let mut authority = publisher_runtime_authority();
        authority["allowed_capabilities"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!("fs_write"));
        authority["max_instructions"] = serde_json::json!(1_000_000_000_000_u64);
        let fixture = PublishedSourceFixture::with_modules_and_authority(
            "app.cjs",
            &[(
                "app.cjs",
                "require('fs').writeFileSync('guest.started', 'actual-native-effect'); while (true) {}\n",
            )],
            // Exercise both source-only and authority-bearing approvals. The
            // local legacy profile grants the test's single filesystem write;
            // it must never waive a publisher or artifact revocation.
            (!publisher_target).then_some(&authority),
        );
        let config_path = fixture.project.path().join("franken_node.toml");
        let mut config: frankenengine_node::config::Config =
            toml::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        config.runtime.max_instructions = Some(1_000_000_000_000);
        fs::write(config_path, config.to_toml().unwrap()).unwrap();
        let stdout_path = fixture.registry.path().join("running-guest.stdout");
        let stderr_path = fixture.registry.path().join("running-guest.stderr");
        let mut command = source_fixture_command(
            fixture.project.path(),
            fixture.state_home.path(),
            &[
                "run",
                "app.cjs",
                "--config",
                "franken_node.toml",
                "--policy",
                "legacy-risky",
                "--runtime",
                "franken-engine",
                "--frozen-modules",
                "--registry-artifact",
                fixture.manifest.to_str().unwrap(),
                "--publisher-public-key",
                fixture.public_key.to_str().unwrap(),
                "--json",
            ],
        );
        command
            .env("FRANKEN_ENGINE_TIMEOUT_SECS", "25")
            .stdout(Stdio::from(fs::File::create(&stdout_path).unwrap()))
            .stderr(Stdio::from(fs::File::create(&stderr_path).unwrap()));
        let mut child = ReapChild(command.spawn().expect("start actual native guest"));
        let startup_deadline = Instant::now() + Duration::from_secs(10);
        let marker = fixture.project.path().join("guest.started");
        let started = loop {
            if fs::read(&marker).is_ok_and(|bytes| bytes == b"actual-native-effect") {
                break true;
            }
            if child.0.try_wait().unwrap().is_some() || Instant::now() >= startup_deadline {
                break false;
            }
            std::thread::sleep(Duration::from_millis(10));
        };
        let digest = artifact_sha256(&fs::read(&fixture.artifact).unwrap());
        let (flag, target) = if publisher_target {
            (
                "--publisher-public-key",
                fixture.public_key.to_str().unwrap(),
            )
        } else {
            ("--artifact-sha256", digest.as_str())
        };
        let revocation = started.then(|| {
            run_source_fixture_cli(
                fixture.project.path(),
                fixture.state_home.path(),
                &["trust", "revoke", flag, target, "--json"],
            )
        });
        // This is a hang guard, not a measured propagation SLO. The actual
        // assertion below requires an execution-trust trigger, never timeout.
        let deadline = Instant::now() + Duration::from_secs(30);
        let status = loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                break status;
            }
            assert!(
                Instant::now() < deadline,
                "native supervisor failed to terminate"
            );
            std::thread::sleep(Duration::from_millis(10));
        };
        let stdout = fs::read(&stdout_path).unwrap();
        let stderr = fs::read(&stderr_path).unwrap();
        let diagnostic = format!(
            "{}\n{}",
            String::from_utf8_lossy(&stdout),
            String::from_utf8_lossy(&stderr)
        );
        assert!(
            started,
            "a real guest effect must precede revocation: {diagnostic}"
        );
        let revocation = revocation.unwrap();
        assert!(
            revocation.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&revocation.stdout),
            String::from_utf8_lossy(&revocation.stderr)
        );
        assert!(
            !status.success(),
            "revoked native guest returned success: {diagnostic}"
        );
        let report: serde_json::Value =
            serde_json::from_slice(&stdout).expect("interruption report");
        assert_eq!(
            report["schema_version"],
            "franken-node/native-effect-interruption-evidence/v1"
        );
        assert_eq!(
            report["control_trigger"]["kind"], "execution_trust",
            "{diagnostic}"
        );
        assert!(
            report["control_trigger"]["detail"]
                .as_str()
                .unwrap()
                .contains("revoked")
        );
        assert_eq!(report["replay_certified"], false);
        assert!(
            report["entries"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["effect_kind"] == "fs_write")
        );
        assert_eq!(
            fs::read(&marker).unwrap(),
            b"actual-native-effect",
            "revocation does not undo a completed write"
        );

        let inventory = run_source_fixture_cli(
            fixture.project.path(),
            fixture.state_home.path(),
            &["fleet", "sessions", "--json"],
        );
        assert!(inventory.status.success());
        let inventory: serde_json::Value = serde_json::from_slice(&inventory.stdout).unwrap();
        assert_eq!(inventory["quiescence_certified"], false);
        let retained = inventory["records"]
            .as_array()
            .unwrap()
            .iter()
            .find(|record| record["admission"]["session_nonce"] == report["session_nonce"])
            .expect("revoked session remains in the durable inventory");
        assert_eq!(retained["outcome"]["kind"], "interrupted");
        assert_eq!(retained["outcome"]["process"], "worker_reaped");
        assert_eq!(retained["outcome"]["effects"]["kind"], "interrupted");
        assert_eq!(
            retained["outcome"]["effects"]["evidence"]["control_trigger"],
            report["control_trigger"]
        );
    }
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn registry_source_capsule_admits_native_cjs_and_esm() {
    use frankenengine_node::ops::engine_dispatcher::RunDispatchReport;
    use frankenengine_node::tools::replay_bundle::parse_verified_run_ledger_record;
    for (esm, native_terminals) in [(false, false), (true, false), (false, true), (true, true)] {
        let (fixture, expected_output) = match (esm, native_terminals) {
            (false, true) => (PublishedSourceFixture::with_modules("app.cjs", &[
                ("app.cjs", "const path = require('node:path'); const value = require('./side.cjs'); console.log('PUBLISHER_APPROVED_WORKLOAD', path.join('value', String(value))); try { require('./optional.cjs'); } catch (error) { console.log('OPTIONAL', error.code); }\n"),
                ("side.cjs", "module.exports = 42;\n"),
            ]), "PUBLISHER_APPROVED_WORKLOAD value/42\nOPTIONAL MODULE_NOT_FOUND\n"),
            (true, true) => (PublishedSourceFixture::with_modules("app.mjs", &[
                ("app.mjs", "import {join} from 'node:path'; import value from './side.mjs'; console.log('PUBLISHER_APPROVED_WORKLOAD', join('value', String(value))); import('./optional.mjs').catch(error => console.log('OPTIONAL', error.code));\n"),
                ("side.mjs", "export default 42;\n"),
            ]), "PUBLISHER_APPROVED_WORKLOAD value/42\nOPTIONAL ERR_MODULE_NOT_FOUND\n"),
            _ => (PublishedSourceFixture::new(esm), "PUBLISHER_APPROVED_WORKLOAD 42\n"),
        };
        let output = fixture.run(&["--frozen-module-graph-hash", &fixture.graph_hash]);
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let dispatch: RunDispatchReport =
            serde_json::from_value(report["dispatch"].clone()).unwrap();
        assert_eq!(dispatch.captured_output.stdout, expected_output);
        let graph = dispatch.engine_decision.unwrap().frozen_modules.unwrap();
        let graph_value = serde_json::to_value(&graph).unwrap();
        assert_eq!(graph.graph_input_hash, fixture.graph_hash);
        assert_eq!(report["receipt"]["native_module_graph"], graph_value);
        let publisher = graph
            .publisher_artifact
            .expect("worker retained authenticated publisher identity");
        assert_eq!(publisher.version, "1.2.3");
        assert_eq!(publisher.name, "application");
        assert_eq!(
            publisher.publisher_key_id,
            KeyId::from_verifying_key(
                &ed25519_dalek::SigningKey::from_bytes(&[42; 32]).verifying_key()
            )
            .to_string()
        );
        assert_eq!(
            publisher.artifact_sha256,
            frankenengine_node::supply_chain::registry_artifact::artifact_sha256(
                &fs::read(&fixture.artifact).unwrap()
            )
        );
        let manifest: frankenengine_node::supply_chain::registry_artifact::LocalRegistryArtifactManifest =
            serde_json::from_slice(&fs::read(&fixture.manifest).unwrap()).unwrap();
        let provenance = frankenengine_node::supply_chain::provenance::canonical_attestation_json(
            &manifest.extension.provenance,
        )
        .unwrap();
        let provenance_hash =
            frankenengine_node::supply_chain::registry_artifact::artifact_sha256(
                provenance.as_bytes(),
            );
        assert_eq!(
            publisher.publisher_provenance_sha256.as_deref(),
            Some(provenance_hash.as_str())
        );

        // Authenticate the persisted product record with the independent run
        // public key created by init. A live dispatch JSON field alone cannot
        // establish durable publisher/source continuity.
        let receipt_path = fixture
            .project
            .path()
            .join(report["receipt_path"].as_str().unwrap());
        let receipt: serde_json::Value =
            serde_json::from_slice(&fs::read(receipt_path).unwrap()).unwrap();
        assert_eq!(receipt, report["receipt"]);
        let day = chrono::DateTime::parse_from_rfc3339(receipt["end_time_utc"].as_str().unwrap())
            .unwrap()
            .format("%Y-%m-%d")
            .to_string();
        let record_path = fixture
            .project
            .path()
            .join(".franken-node/state/run-ledgers")
            .join(day)
            .join(format!("{}.json", receipt["receipt_id"].as_str().unwrap()));
        let record_bytes = fs::read(record_path).expect("actual signed native run record");
        let public = fs::read_to_string(
            fixture
                .project
                .path()
                .join(".franken-node/keys/receipt-signing.pub"),
        )
        .unwrap();
        let key: [u8; 32] = hex::decode(public.trim()).unwrap().try_into().unwrap();
        let key = ed25519_dalek::VerifyingKey::from_bytes(&key).unwrap();
        let record = parse_verified_run_ledger_record(&record_bytes, &receipt, &key)
            .expect("actual receipt authority authenticates the retained graph and publisher");
        assert_eq!(
            record["receipt_snapshot"]["native_module_graph"],
            graph_value
        );
        for (pointer, replacement) in [
            (
                "/receipt_snapshot/native_module_graph/graph_input_hash",
                format!("sha256:{}", "0".repeat(64)),
            ),
            (
                "/receipt_snapshot/native_module_graph/publisher_artifact/publisher_key_id",
                "substituted-publisher-key".into(),
            ),
            (
                "/receipt_snapshot/native_module_graph/publisher_artifact/publisher_provenance_sha256",
                format!("sha256:{}", "ab".repeat(32)),
            ),
        ] {
            let mut substituted = record.clone();
            *substituted.pointer_mut(pointer).unwrap() = serde_json::json!(replacement);
            assert!(
                parse_verified_run_ledger_record(
                    &serde_json::to_vec(&substituted).unwrap(),
                    &substituted["receipt_snapshot"],
                    &key
                )
                .is_err(),
                "even a matching edited receipt cannot authorize a changed source/publisher in the signed record"
            );
        }
        if native_terminals {
            // The negative filesystem observation is part of the publisher's
            // commitment too. A newly installed optional module cannot borrow
            // the old signature, even when the entry source stays unchanged.
            fs::write(
                fixture.project.path().join(if esm { "optional.mjs" } else { "optional.cjs" }),
                "console.log('UNAPPROVED_OPTIONAL_MODULE');\n",
            ).unwrap();
            fixture.assert_denied(&[], "ERR_MODULE_REGISTRY_PIN_MISMATCH");
        }
    }
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn registry_runtime_authority_executes_signed_modules_under_narrowed_limits() {
    use frankenengine_node::ops::engine_dispatcher::RunDispatchReport;
    use frankenengine_node::tools::replay_bundle::parse_verified_run_ledger_record;
    let authority = publisher_runtime_authority();
    for esm in [false, true] {
        let modules = if esm {
            [
                (
                    "app.mjs",
                    "import value from './side.mjs'; console.log('PUBLISHER_APPROVED_WORKLOAD', value);\n",
                ),
                ("side.mjs", "export default 42;\n"),
            ]
        } else {
            [
                (
                    "app.cjs",
                    "console.log('PUBLISHER_APPROVED_WORKLOAD', require('./side.cjs'));\n",
                ),
                ("side.cjs", "module.exports = 42;\n"),
            ]
        };
        let fixture = PublishedSourceFixture::with_modules_and_authority(
            modules[0].0,
            &modules,
            Some(&authority),
        );
        let output = fixture.run(&[]);
        assert!(
            output.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        let dispatch: RunDispatchReport =
            serde_json::from_value(report["dispatch"].clone()).unwrap();
        assert_eq!(
            dispatch.captured_output.stdout,
            "PUBLISHER_APPROVED_WORKLOAD 42\n"
        );
        let settings = dispatch.invocation_settings.unwrap();
        assert!(!settings.process_shape_read_allowed);
        assert_eq!(settings.parser_budget.max_source_bytes, 65_536);
        assert_eq!(settings.parser_budget.max_token_count, 16_384);
        assert_eq!(settings.parser_budget.max_recursion_depth, 128);
        for lane in [
            settings.execution_limits.deterministic,
            settings.execution_limits.throughput,
        ] {
            assert_eq!(lane.max_instructions, 2_000_000);
            assert!(lane.max_registers.unwrap() <= 1_024);
            assert!(lane.max_call_depth.unwrap() <= 32);
            assert!(lane.max_heap_objects <= 4_096);
            assert!(lane.max_total_memory_bytes <= 33_554_432);
            assert!(lane.max_console_entries <= 16);
        }
        assert_eq!(
            report["receipt"]["native_module_graph"]["publisher_artifact"]["runtime_authority"],
            authority
        );

        let receipt = &report["receipt"];
        let day = chrono::DateTime::parse_from_rfc3339(receipt["end_time_utc"].as_str().unwrap())
            .unwrap()
            .format("%Y-%m-%d")
            .to_string();
        let record_path = fixture
            .project
            .path()
            .join(".franken-node/state/run-ledgers")
            .join(day)
            .join(format!("{}.json", receipt["receipt_id"].as_str().unwrap()));
        let public = fs::read_to_string(
            fixture
                .project
                .path()
                .join(".franken-node/keys/receipt-signing.pub"),
        )
        .unwrap();
        let key: [u8; 32] = hex::decode(public.trim()).unwrap().try_into().unwrap();
        let key = ed25519_dalek::VerifyingKey::from_bytes(&key).unwrap();
        let record =
            parse_verified_run_ledger_record(&fs::read(record_path).unwrap(), receipt, &key)
                .expect("run authority authenticates actual publisher ceilings");
        for change in ["max_instructions", "policy_revision"] {
            let mut forged = record.clone();
            forged["receipt_snapshot"]["native_module_graph"]["publisher_artifact"]["runtime_authority"]
                [change] = if change == "max_instructions" {
                serde_json::json!(u64::MAX)
            } else {
                serde_json::json!("substituted-policy")
            };
            assert!(
                parse_verified_run_ledger_record(
                    &serde_json::to_vec(&forged).unwrap(),
                    &forged["receipt_snapshot"],
                    &key
                )
                .is_err(),
                "changed {change} must invalidate the signed run record"
            );
        }

        // The same signed ceiling cannot relax a stricter local operator limit.
        let config_path = fixture.project.path().join("franken_node.toml");
        let mut config: frankenengine_node::config::Config =
            toml::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        config.runtime.max_instructions = Some(100_000);
        config.runtime.max_console_entries = Some(2);
        fs::write(config_path, config.to_toml().unwrap()).unwrap();
        let narrower = fixture.run(&[]);
        assert!(
            narrower.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&narrower.stdout),
            String::from_utf8_lossy(&narrower.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&narrower.stdout).unwrap();
        let dispatch: RunDispatchReport =
            serde_json::from_value(report["dispatch"].clone()).unwrap();
        let settings = dispatch.invocation_settings.unwrap();
        for lane in [
            settings.execution_limits.deterministic,
            settings.execution_limits.throughput,
        ] {
            assert_eq!(lane.max_instructions, 100_000);
            assert_eq!(lane.max_console_entries, 2);
        }
    }
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn registry_runtime_authority_enforces_output_instruction_and_dependency_parser_limits() {
    for (field, limit, entry, dependency, expected) in [
        (
            "max_console_entries",
            2,
            "require('./side.cjs'); console.log('PUBLISHER_APPROVED_WORKLOAD');\n".to_owned(),
            "console.log('one'); console.log('two'); console.log('three');\n".to_owned(),
            "console output budget exceeded",
        ),
        (
            "max_instructions",
            100,
            "require('./side.cjs'); console.log('PUBLISHER_APPROVED_WORKLOAD');\n".to_owned(),
            "let i = 0; while (i < 10000) { i = i + 1; } module.exports = i;\n".to_owned(),
            "budget",
        ),
        (
            "max_parse_source_bytes",
            256,
            "require('./side.cjs'); console.log('PUBLISHER_APPROVED_WORKLOAD');\n".to_owned(),
            format!("{}\nmodule.exports = 42;\n", ";".repeat(512)),
            "configured parser source-byte budget",
        ),
    ] {
        let mut authority = publisher_runtime_authority();
        authority[field] = serde_json::json!(limit);
        let fixture = PublishedSourceFixture::with_modules_and_authority(
            "app.cjs",
            &[("app.cjs", &entry), ("side.cjs", &dependency)],
            Some(&authority),
        );
        let output = fixture.run(&[]);
        let diagnostics = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success(), "{field}: {diagnostics}");
        assert!(diagnostics.contains(expected), "{field}: {diagnostics}");
        // Prefix effects can occur before a runtime ceiling; the success marker cannot.
        assert!(
            !diagnostics.contains("PUBLISHER_APPROVED_WORKLOAD"),
            "{field}: {diagnostics}"
        );
    }
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn registry_runtime_authority_denies_filesystem_effect_in_loaded_module() {
    let mut authority = publisher_runtime_authority();
    authority["allowed_capabilities"]
        .as_array_mut()
        .unwrap()
        .retain(|value| value != "fs_read");
    let fixture = PublishedSourceFixture::with_modules_and_authority(
        "app.cjs",
        &[
            (
                "app.cjs",
                "require('./side.cjs'); console.log('PUBLISHER_APPROVED_WORKLOAD');\n",
            ),
            (
                "side.cjs",
                "require('node:fs').readFileSync('data.txt', 'utf8');\n",
            ),
        ],
        Some(&authority),
    );
    fs::write(
        fixture.project.path().join("data.txt"),
        "PUBLIC_FIXTURE_DATA",
    )
    .unwrap();
    let output = fixture.run(&[]);
    let diagnostics = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!output.status.success(), "{diagnostics}");
    assert!(diagnostics.contains("fs_read"), "{diagnostics}");
    assert!(
        !diagnostics.contains("PUBLISHER_APPROVED_WORKLOAD"),
        "{diagnostics}"
    );
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn registry_runtime_authority_controls_environment_reads_in_loaded_modules() {
    for permitted in [true, false] {
        let mut authority = publisher_runtime_authority();
        if permitted {
            let capabilities = authority["allowed_capabilities"].as_array_mut().unwrap();
            capabilities.push(serde_json::json!("env_read"));
            capabilities.sort_by(|a, b| a.as_str().cmp(&b.as_str()));
        }
        let fixture = PublishedSourceFixture::with_modules_and_authority(
            "app.cjs",
            &[
                (
                    "app.cjs",
                    "require('./side.cjs'); console.log('PUBLISHER_APPROVED_WORKLOAD');\n",
                ),
                (
                    "side.cjs",
                    "void process.env.PUBLISHER_TEST_VALUE; console.log('ENV_READ_COMPLETED');\n",
                ),
            ],
            Some(&authority),
        );
        // The operator grants this single public fixture name in both runs.
        // Only the publisher's signed ceiling differs.
        let config_path = fixture.project.path().join("franken_node.toml");
        let mut config: frankenengine_node::config::Config =
            toml::from_str(&fs::read_to_string(&config_path).unwrap()).unwrap();
        config
            .runtime
            .environment_allowlist
            .insert("PUBLISHER_TEST_VALUE".into());
        fs::write(config_path, config.to_toml().unwrap()).unwrap();
        let output = fixture.run(&["--capture-replay"]);
        let diagnostics = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(output.status.success(), permitted, "{diagnostics}");
        if permitted {
            let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(
                report["dispatch"]["captured_output"]["stdout"],
                "ENV_READ_COMPLETED\nPUBLISHER_APPROVED_WORKLOAD\n"
            );
            let captured: serde_json::Value = serde_json::from_str(
                report["dispatch"]["native_replay"]["payload_json"]
                    .as_str()
                    .unwrap(),
            )
            .unwrap();
            assert!(
                captured["package"]["capabilities"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|capability| capability == "env_read")
            );
            let transcript = serde_json::to_string(&captured["host_effect_transcript"]).unwrap();
            assert!(transcript.contains("PUBLISHER_TEST_VALUE"), "{transcript}");
            assert!(transcript.contains("VISIBLE_FROM_OPERATOR"), "{transcript}");
        } else {
            assert!(diagnostics.contains("env_read"), "{diagnostics}");
            assert!(!diagnostics.contains("ENV_READ_COMPLETED"), "{diagnostics}");
            assert!(
                !diagnostics.contains("PUBLISHER_APPROVED_WORKLOAD"),
                "{diagnostics}"
            );
        }
    }
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn registry_runtime_authority_cannot_be_expanded_or_stripped_without_resigning() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let authority = publisher_runtime_authority();
    let fixture = PublishedSourceFixture::with_modules_and_authority(
        "app.cjs",
        &[("app.cjs", "console.log('PUBLISHER_APPROVED_WORKLOAD');\n")],
        Some(&authority),
    );
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.manifest).unwrap()).unwrap();
    let signed_bytes = STANDARD
        .decode(original["manifest_bytes_b64"].as_str().unwrap())
        .unwrap();
    let signed: serde_json::Value = serde_json::from_slice(&signed_bytes).unwrap();
    assert_eq!(
        signed["schema_version"],
        "franken-node/extension-registration-manifest/v2"
    );
    for mutation in ["budget", "capability", "revision", "strip", "downgrade"] {
        let mut changed = signed.clone();
        match mutation {
            "budget" => {
                changed["runtime_authority"]["max_instructions"] = serde_json::json!(u64::MAX)
            }
            "capability" => changed["runtime_authority"]["allowed_capabilities"]
                .as_array_mut()
                .unwrap()
                .push(serde_json::json!("fs_write")),
            "revision" => {
                changed["runtime_authority"]["policy_revision"] = serde_json::json!("substituted")
            }
            "strip" => {
                changed.as_object_mut().unwrap().remove("runtime_authority");
            }
            "downgrade" => {
                changed["schema_version"] =
                    serde_json::json!("franken-node/extension-registration-manifest/v1")
            }
            _ => unreachable!(),
        }
        let mut envelope = original.clone();
        envelope["manifest_bytes_b64"] =
            serde_json::json!(STANDARD.encode(serde_json::to_vec(&changed).unwrap()));
        fs::write(&fixture.manifest, serde_json::to_vec(&envelope).unwrap()).unwrap();
        fixture.assert_denied(&[], "manifest signature verification failed");
    }
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn registry_source_capsule_authenticates_provenance_before_guest_execution() {
    let authority = publisher_runtime_authority();
    let fixture = PublishedSourceFixture::with_modules_and_authority(
        "app.cjs",
        &[
            (
                "app.cjs",
                "const value = require('./side.cjs'); console.log('PUBLISHER_APPROVED_WORKLOAD', value);\n",
            ),
            ("side.cjs", "module.exports = 42;\n"),
        ],
        Some(&authority),
    );
    let valid = fixture.run(&[]);
    assert!(
        valid.status.success(),
        "positive signed publication: {}\n{}",
        String::from_utf8_lossy(&valid.stdout),
        String::from_utf8_lossy(&valid.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&valid.stdout).unwrap();
    assert_eq!(
        report["dispatch"]["captured_output"]["stdout"],
        "PUBLISHER_APPROVED_WORKLOAD 42\n"
    );
    assert!(
        report["receipt"]["native_module_graph"]["publisher_artifact"]
            ["publisher_provenance_sha256"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:") && hash.len() == 71)
    );
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.manifest).unwrap()).unwrap();
    for (pointer, replacement) in [
        (
            "/extension/provenance/source_repository_url",
            serde_json::json!("https://example.com/substituted/repository"),
        ),
        (
            "/extension/provenance/builder_identity",
            serde_json::json!("a-different-publisher"),
        ),
        (
            "/extension/provenance/output_hash",
            serde_json::json!(format!("sha256:{}", "00".repeat(32))),
        ),
        (
            "/extension/provenance/reproducibility_hash",
            serde_json::json!(format!("sha256:{}", "00".repeat(32))),
        ),
        (
            "/extension/provenance/custom_claims/operator_key_id",
            serde_json::json!("another-publisher-key"),
        ),
        (
            "/extension/provenance/custom_claims/operator_signature_scope",
            serde_json::json!("another-signature-purpose"),
        ),
        (
            "/extension/provenance/custom_claims/operator_provenance_signature",
            serde_json::json!("00".repeat(64)),
        ),
        (
            "/extension/provenance/links/0/signature",
            serde_json::json!("00".repeat(64)),
        ),
    ] {
        let mut tampered = original.clone();
        *tampered.pointer_mut(pointer).unwrap() = replacement;
        fs::write(&fixture.manifest, serde_json::to_vec(&tampered).unwrap()).unwrap();
        fixture.assert_denied(&[], "provenance");
    }

    let mut stripped = original.clone();
    let claims = stripped["extension"]["provenance"]["custom_claims"]
        .as_object_mut()
        .unwrap();
    for name in [
        "operator_key_id",
        "operator_signature_scope",
        "operator_provenance_signature",
    ] {
        claims.remove(name);
    }
    fs::write(&fixture.manifest, serde_json::to_vec(&stripped).unwrap()).unwrap();
    fixture.assert_denied(&[], "provenance");

    // Authentic signatures cannot waive an expired or explicitly revoked
    // attestation link. These failures must reach the existing chain policy.
    let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    for expired in [false, true] {
        let mut refused = original.clone();
        if expired {
            refused["extension"]["provenance"]["build_timestamp_epoch"] = serde_json::json!(1);
            for link in refused["extension"]["provenance"]["links"]
                .as_array_mut()
                .unwrap()
            {
                link["issued_at_epoch"] = serde_json::json!(1);
                link["expires_at_epoch"] = serde_json::json!(2);
            }
        } else {
            refused["extension"]["provenance"]["links"][0]["revoked"] = serde_json::json!(true);
        }
        resign_published_provenance(&mut refused, &key);
        fs::write(&fixture.manifest, serde_json::to_vec(&refused).unwrap()).unwrap();
        fixture.assert_denied(&[], "provenance");
    }
    fs::write(&fixture.manifest, serde_json::to_vec(&original).unwrap()).unwrap();
    let restored = fixture.run(&[]);
    assert!(
        restored.status.success(),
        "restored authentic publication: {}\n{}",
        String::from_utf8_lossy(&restored.stdout),
        String::from_utf8_lossy(&restored.stderr)
    );
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn registry_source_capsule_requires_signed_run_record_persistence() {
    let fixture = PublishedSourceFixture::new(false);
    let signing_key = fixture
        .project
        .path()
        .join(".franken-node/keys/receipt-signing.key");
    fs::rename(&signing_key, signing_key.with_extension("retained-key")).unwrap();
    for invalid_key in [None, Some("not an Ed25519 signing key")] {
        if let Some(contents) = invalid_key {
            fs::write(&signing_key, contents).unwrap();
        }
        let output = fixture.run(&[]);
        let diagnostics = format!(
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(
            !output.status.success(),
            "publisher-approved run must not succeed without its signed record: {diagnostics}"
        );
        assert!(
            diagnostics.contains("failed persisting publisher-approved native run record"),
            "a missing or malformed receipt authority must be a persistence failure: {diagnostics}"
        );
        // This is a post-execution persistence requirement. Do not describe it
        // as a pre-execution refusal or assert that guest effects were undone.
    }
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn registry_source_capsule_rejects_live_source_key_and_policy_substitutions() {
    let fixture = PublishedSourceFixture::new(false);
    let dependency = fixture.project.path().join("side.cjs");
    fs::write(&dependency, "module.exports = 9001;\n").unwrap();
    fixture.assert_denied(&[], "ERR_MODULE_REGISTRY_PIN_MISMATCH");
    fs::write(&dependency, "module.exports = 42;\n").unwrap();
    let entry = fixture.project.path().join(&fixture.entrypoint);
    let original_entry = fs::read(&entry).unwrap();
    fs::write(&entry, "console.log('UNSIGNED_ENTRY_EXECUTED');\n").unwrap();
    let refused = fixture.run(&[]);
    assert!(!refused.status.success());
    assert!(!String::from_utf8_lossy(&refused.stdout).contains("UNSIGNED_ENTRY_EXECUTED"));
    fs::write(&entry, original_entry).unwrap();
    fixture.assert_denied(
        &[
            "--frozen-module-graph-hash",
            &format!("sha256:{}", "0".repeat(64)),
        ],
        "explicit frozen module graph pin conflicts",
    );
    fixture.assert_denied(
        &["--conditions", "development"],
        "run conditions do not match",
    );
    fixture.assert_denied(
        &["--frozen-module-symlinks"],
        "run symlink policy does not match",
    );
    fs::write(
        &fixture.public_key,
        hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[13; 32])
                .verifying_key()
                .as_bytes(),
        ),
    )
    .unwrap();
    fixture.assert_denied(&[], "independently supplied public key");
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn registry_source_capsule_binds_signed_bytes_and_parent_admission() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    use frankenengine_node::supply_chain::{
        artifact_signing,
        registry_artifact::{PublisherSourceGraphApproval, artifact_sha256},
    };
    let fixture = PublishedSourceFixture::new(false);
    let publisher = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let approved =
        PublisherSourceGraphApproval::load(&fixture.manifest, &publisher.verifying_key()).unwrap();
    approved.revalidate().unwrap();
    let original_manifest = fs::read(&fixture.manifest).unwrap();
    let original_artifact = fs::read(&fixture.artifact).unwrap();
    fs::write(&fixture.artifact, b"not the signed capsule").unwrap();
    fixture.assert_denied(&[], "artifact hash mismatch");
    fs::write(&fixture.artifact, &original_artifact).unwrap();

    // Replace the package with a complete, valid capsule and recompute every
    // editable storage hash. The original signed version still rejects it.
    fs::write(
        fixture.project.path().join("side.cjs"),
        "module.exports = 9001;\n",
    )
    .unwrap();
    let replacement = run_cli_in_workspace(
        fixture.registry.path(),
        &[
            "verify",
            "source-graph",
            fixture.project.path().to_str().unwrap(),
            &fixture.entrypoint,
            "--write-source-capsule",
            "replacement.capsule",
            "--json",
        ],
    );
    assert!(replacement.status.success());
    let replacement = fs::read(fixture.registry.path().join("replacement.capsule")).unwrap();
    let replacement_hash = artifact_sha256(&replacement);
    let mut envelope: serde_json::Value = serde_json::from_slice(&original_manifest).unwrap();
    envelope["artifact_sha256"] = serde_json::json!(replacement_hash);
    envelope["artifact_size_bytes"] = serde_json::json!(replacement.len());
    envelope["extension"]["versions"][0]["content_hash"] =
        serde_json::json!(replacement_hash.strip_prefix("sha256:").unwrap());
    fs::write(&fixture.artifact, &replacement).unwrap();
    fs::write(&fixture.manifest, serde_json::to_vec(&envelope).unwrap()).unwrap();
    fixture.assert_denied(
        &[],
        "stored artifact version lineage does not match signed initial_version",
    );

    // An attacker can supply a self-consistent embedded key and real signature;
    // that signature still has no authority under the caller's separate anchor.
    let signed_bytes = STANDARD
        .decode(envelope["manifest_bytes_b64"].as_str().unwrap())
        .unwrap();
    let mut signed: serde_json::Value = serde_json::from_slice(&signed_bytes).unwrap();
    signed["initial_version"] = envelope["extension"]["versions"][0].clone();
    let signed_bytes = serde_json::to_vec(&signed).unwrap();
    envelope["manifest_bytes_b64"] = serde_json::json!(STANDARD.encode(&signed_bytes));
    let attacker = ed25519_dalek::SigningKey::from_bytes(&[13; 32]);
    envelope["publisher_public_key_hex"] =
        serde_json::json!(hex::encode(attacker.verifying_key().as_bytes()));
    envelope["extension"]["signature"]["key_id"] =
        serde_json::json!(KeyId::from_verifying_key(&attacker.verifying_key()).to_string());
    envelope["extension"]["signature"]["signature_bytes"] =
        serde_json::json!(artifact_signing::sign_bytes(&attacker, &signed_bytes));
    fs::write(&fixture.manifest, serde_json::to_vec(&envelope).unwrap()).unwrap();
    fixture.assert_denied(&[], "independently supplied public key");

    // Even another valid approval by the original publisher must not replace
    // the exact artifact retained between parent admission and worker launch.
    envelope["publisher_public_key_hex"] =
        serde_json::json!(hex::encode(publisher.verifying_key().as_bytes()));
    envelope["extension"]["signature"]["key_id"] =
        serde_json::json!(KeyId::from_verifying_key(&publisher.verifying_key()).to_string());
    envelope["extension"]["signature"]["signature_bytes"] =
        serde_json::json!(artifact_signing::sign_bytes(&publisher, &signed_bytes));
    for field in ["input_hash", "output_hash", "reproducibility_hash"] {
        envelope["extension"]["provenance"][field] = serde_json::json!(replacement_hash);
    }
    for link in envelope["extension"]["provenance"]["links"]
        .as_array_mut()
        .unwrap()
    {
        link["signed_payload_hash"] = serde_json::json!(replacement_hash);
    }
    resign_published_provenance(&mut envelope, &publisher);
    fs::write(&fixture.manifest, serde_json::to_vec(&envelope).unwrap()).unwrap();
    PublisherSourceGraphApproval::load(&fixture.manifest, &publisher.verifying_key()).unwrap();
    assert!(
        approved
            .revalidate()
            .unwrap_err()
            .to_string()
            .contains("changed after publisher admission")
    );
}

#[test]
#[cfg(all(feature = "engine", unix))]
fn registry_source_capsule_refuses_symlinks_path_escape_and_oversized_files() {
    use frankenengine_node::supply_chain::registry_artifact::{
        MAX_ARTIFACT_BYTES, PublisherSourceGraphApproval,
    };
    use std::os::unix::fs::symlink;
    let fixture = PublishedSourceFixture::new(false);
    let publisher = ed25519_dalek::SigningKey::from_bytes(&[42; 32]).verifying_key();
    let alias = fixture.registry.path().join("manifest-alias.json");
    symlink(&fixture.manifest, &alias).unwrap();
    assert!(PublisherSourceGraphApproval::load(&alias, &publisher).is_err());
    let parent_alias = fixture.registry.path().join("directory-alias");
    symlink(fixture.manifest.parent().unwrap(), &parent_alias).unwrap();
    assert!(
        PublisherSourceGraphApproval::load(
            &parent_alias.join(fixture.manifest.file_name().unwrap()),
            &publisher
        )
        .is_err()
    );
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&fixture.manifest).unwrap()).unwrap();
    envelope["artifact_file_name"] = serde_json::json!("../../application.capsule");
    fs::write(&fixture.manifest, serde_json::to_vec(&envelope).unwrap()).unwrap();
    fixture.assert_denied(&[], "artifact file name is unsafe");
    let huge = fixture.registry.path().join("oversized-manifest.json");
    std::fs::File::create(&huge)
        .unwrap()
        .set_len(MAX_ARTIFACT_BYTES + 1)
        .unwrap();
    assert!(
        PublisherSourceGraphApproval::load(&huge, &publisher)
            .unwrap_err()
            .to_string()
            .contains("byte bound")
    );
}

fn assert_registry_verify_integrity(
    workspace: &Path,
    extension_id: &str,
    expected: &str,
    case: &str,
) -> serde_json::Value {
    let output = run_cli_in_workspace(workspace, &["registry", "verify", extension_id, "--json"]);
    assert_eq!(
        output.status.success(),
        expected == "verified",
        "{case}: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{case}: invalid verification JSON: {error}"));
    assert_eq!(report["integrity"], expected, "{case}: {report}");
    report
}

#[test]
fn registry_publish_requires_explicit_signing_key() {
    let workspace = registry_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &["registry", "publish", "plugin.fnext", "--version", "1.0.0"],
    );
    assert!(
        !output.status.success(),
        "registry publish should fail when signing key is omitted"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("--signing-key"));
    assert!(stderr.contains("registry publish requires --signing-key"));
    assert!(stderr.contains("fix_command=mkdir -p .franken-node/keys && openssl rand -hex 32 > .franken-node/keys/publisher.ed25519 && franken-node registry publish plugin.fnext --version 1.0.0 --signing-key .franken-node/keys/publisher.ed25519"));

    let json_output = run_cli_in_workspace(
        workspace.path(),
        &[
            "registry",
            "publish",
            "plugin.fnext",
            "--version",
            "1.0.0",
            "--json",
        ],
    );
    assert!(
        !json_output.status.success(),
        "registry publish --json should fail when signing key is omitted"
    );
    let payload: serde_json::Value = serde_json::from_slice(&json_output.stdout)
        .expect("registry publish --json missing-key stdout must be JSON");
    assert_eq!(
        payload["schema_version"],
        "franken-node/registry-publish-error/v1"
    );
    assert_eq!(payload["command"], "registry.publish");
    assert_eq!(payload["ok"], false);
    let error = payload["error"]
        .as_str()
        .expect("error field must be a string");
    assert!(
        error.contains("registry publish requires --signing-key"),
        "JSON error must keep the actionable message: {error}"
    );
    assert!(
        error.contains("fix_command="),
        "JSON error must keep the fix_command: {error}"
    );
    let json_stderr = String::from_utf8_lossy(&json_output.stderr);
    assert!(
        !json_stderr.contains("Error: registry publish requires --signing-key"),
        "--json must not append a second human Error line after the JSON report: {json_stderr}"
    );
}

#[test]
fn registry_publish_json_fails_closed_when_package_path_missing() {
    let workspace = registry_workspace();
    let output = run_cli_in_workspace(workspace.path(), &["registry", "publish", "--json"]);
    assert!(
        !output.status.success(),
        "registry publish --json should fail when the package path is omitted"
    );
    let payload: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("registry publish --json missing package path stdout must be JSON");
    assert_eq!(
        payload["schema_version"],
        "franken-node/registry-publish-error/v1"
    );
    assert_eq!(payload["command"], "registry.publish");
    assert_eq!(payload["ok"], false);
    let error = payload["error"]
        .as_str()
        .expect("error field must be a string");
    assert!(
        error.contains("package path"),
        "missing package path --json must name the handler requirement: {error}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("error: the following required arguments were not provided")
            && !stderr.contains("Error: `registry publish` requires a package path"),
        "--json must not append a human clap/Error line after the JSON report: {stderr}"
    );
}

#[test]
fn registry_publish_json_fails_closed_when_version_missing() {
    let workspace = registry_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &["registry", "publish", "plugin.fnext", "--json"],
    );
    assert!(
        !output.status.success(),
        "registry publish --json should fail when --version is omitted"
    );
    let payload: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("registry publish --json missing --version stdout must be JSON");
    assert_eq!(
        payload["schema_version"],
        "franken-node/registry-publish-error/v1"
    );
    assert_eq!(payload["command"], "registry.publish");
    assert_eq!(payload["ok"], false);
    let error = payload["error"]
        .as_str()
        .expect("error field must be a string");
    assert!(
        error.contains("--version"),
        "missing --version --json must name the handler requirement: {error}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("error: the following required arguments were not provided")
            && !stderr.contains("Error: `registry publish` requires --version"),
        "--json must not append a human clap/Error line after the JSON report: {stderr}"
    );
}

#[test]
fn registry_publish_missing_package_json_emits_error_report() {
    let workspace = registry_workspace();
    let signing_key_path = workspace.path().join("keys/publisher.ed25519");
    write_signing_key(&signing_key_path);
    let signing_key_arg = signing_key_path.to_string_lossy().to_string();
    let output = run_cli_in_workspace(
        workspace.path(),
        &[
            "registry",
            "publish",
            "missing.fnext",
            "--version",
            "1.0.0",
            "--signing-key",
            &signing_key_arg,
            "--json",
        ],
    );
    assert!(
        !output.status.success(),
        "registry publish --json should fail when the package is missing"
    );
    let payload: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("registry publish --json missing-package stdout must be JSON");
    assert_eq!(
        payload["schema_version"],
        "franken-node/registry-publish-error/v1"
    );
    assert_eq!(payload["command"], "registry.publish");
    assert_eq!(payload["ok"], false);
    let error = payload["error"]
        .as_str()
        .expect("error field must be a string");
    assert!(
        error.contains("registry publish target does not exist"),
        "JSON error must name the missing package: {error}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Error: registry publish target does not exist"),
        "--json must not append a second human Error line after the JSON report: {stderr}"
    );
}

#[test]
fn registry_search_json_fails_closed_when_query_missing() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let output = run_cli_in_workspace(workspace.path(), &["registry", "search", "--json"]);
    assert!(
        !output.status.success(),
        "registry search --json should fail when the query is omitted"
    );
    let payload: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("registry search --json missing query must be JSON, not a clap usage dump");
    assert_eq!(
        payload["schema_version"],
        "franken-node/registry-error-cli/v1"
    );
    assert_eq!(payload["command"], "registry.search");
    assert_eq!(payload["ok"], false);
    let error = payload["error"]
        .as_str()
        .expect("error field must be a string");
    assert!(
        error.contains("query"),
        "missing query --json must name the handler requirement: {error}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("error: the following required arguments were not provided")
            && !stderr.contains("Error: `registry search` requires a query"),
        "--json must not append a human clap/Error line after the JSON report: {stderr}"
    );
}

#[test]
fn registry_verify_json_fails_closed_when_extension_id_missing() {
    let workspace = tempfile::tempdir().expect("tempdir");
    let output = run_cli_in_workspace(workspace.path(), &["registry", "verify", "--json"]);
    assert!(
        !output.status.success(),
        "registry verify --json should fail when the extension id is omitted"
    );
    let payload: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("registry verify --json missing id must be JSON, not a clap usage dump");
    assert_eq!(
        payload["schema_version"],
        "franken-node/registry-error-cli/v1"
    );
    assert_eq!(payload["command"], "registry.verify");
    assert_eq!(payload["ok"], false);
    let error = payload["error"]
        .as_str()
        .expect("error field must be a string");
    assert!(
        error.contains("extension id"),
        "missing id --json must name the handler requirement: {error}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("error: the following required arguments were not provided")
            && !stderr.contains("Error: `registry verify` requires an extension id"),
        "--json must not append a human clap/Error line after the JSON report: {stderr}"
    );
}

#[test]
fn registry_verify_missing_extension_json_emits_error_report() {
    let workspace = registry_workspace();
    let output = run_cli_in_workspace(
        workspace.path(),
        &["registry", "verify", "npm:@missing/package", "--json"],
    );
    assert!(
        !output.status.success(),
        "registry verify --json should fail when the extension is missing"
    );
    let payload: serde_json::Value = serde_json::from_slice(&output.stdout)
        .expect("registry verify --json missing-extension stdout must be JSON");
    assert_eq!(
        payload["schema_version"],
        "franken-node/registry-error-cli/v1"
    );
    assert_eq!(payload["command"], "registry.verify");
    assert_eq!(payload["ok"], false);
    let error = payload["error"]
        .as_str()
        .expect("error field must be a string");
    assert!(
        error.contains("registry artifact not found for extension_id=npm:@missing/package"),
        "JSON error must name the missing extension: {error}"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stderr.contains("Error: registry artifact not found"),
        "--json must not append a second human Error line after the JSON report: {stderr}"
    );
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
            "--version",
            "1.0.0",
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
            "--version",
            "1.0.0",
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
            "--version",
            "1.0.0",
            "--signing-key",
            &signing_key_arg,
            "--json",
        ],
    );
    assert!(
        publish_output.status.success(),
        "registry publish --json failed: {}",
        String::from_utf8_lossy(&publish_output.stderr)
    );
    let publish_payload: serde_json::Value = serde_json::from_slice(&publish_output.stdout)
        .expect("registry publish --json should emit valid JSON");
    assert_eq!(
        publish_payload["schema_version"],
        "franken-node/registry-publish-cli/v1"
    );
    assert_eq!(publish_payload["command"], "registry.publish");
    assert_eq!(publish_payload["integrity"], "verified");
    let publish_json_stdout = String::from_utf8_lossy(&publish_output.stdout);
    assert!(
        !publish_json_stdout.contains("registry publish:"),
        "json mode must not emit the human one-liner:\n{publish_json_stdout}"
    );

    let extension_id = publish_payload["extension_id"]
        .as_str()
        .expect("publish JSON extension_id")
        .to_string();
    let artifact_path = workspace.path().join(
        publish_payload["artifact_path"]
            .as_str()
            .expect("publish JSON artifact_path"),
    );
    let manifest_path = workspace.path().join(
        publish_payload["manifest_path"]
            .as_str()
            .expect("publish JSON manifest_path"),
    );
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
            "sha256:{}",
            hex::encode(sha2::Sha256::digest(
                fs::read(&artifact_path).expect("read stored artifact")
            ))
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

    let verify_json = run_cli_in_workspace(
        workspace.path(),
        &["registry", "verify", &extension_id, "--json"],
    );
    assert!(
        verify_json.status.success(),
        "registry verify --json failed: {}",
        String::from_utf8_lossy(&verify_json.stderr)
    );
    let verify_payload: serde_json::Value = serde_json::from_slice(&verify_json.stdout)
        .expect("registry verify --json should emit valid JSON");
    assert_eq!(
        verify_payload["schema_version"],
        "franken-node/registry-verify-cli/v1"
    );
    assert_eq!(verify_payload["command"], "registry.verify");
    assert_eq!(verify_payload["extension_id"], extension_id);
    assert_eq!(verify_payload["integrity"], "verified");
    let verify_json_stdout = String::from_utf8_lossy(&verify_json.stdout);
    assert!(
        !verify_json_stdout.contains("registry verify:"),
        "json mode must not emit the human one-liner:\n{verify_json_stdout}"
    );

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

    let json_output = run_cli_in_workspace(
        workspace.path(),
        &["registry", "search", "plugin", "--json"],
    );
    assert!(
        json_output.status.success(),
        "registry search --json failed: {}",
        String::from_utf8_lossy(&json_output.stderr)
    );
    let payload: serde_json::Value = serde_json::from_slice(&json_output.stdout)
        .expect("registry search --json should emit valid JSON");
    assert_eq!(
        payload["schema_version"],
        "franken-node/registry-search-cli/v1"
    );
    assert_eq!(payload["command"], "registry.search");
    assert_eq!(payload["query"], "plugin");
    assert_eq!(payload["matched"], 1);
    assert_eq!(payload["rows"][0]["extension_id"], extension_id);
    assert_eq!(payload["rows"][0]["integrity_status"], "verified");
    let json_stdout = String::from_utf8_lossy(&json_output.stdout);
    assert!(
        !json_stdout.contains("registry search: query="),
        "json mode must not emit the human table:\n{json_stdout}"
    );
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
            "--version",
            "1.0.0",
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

    let verify_json = run_cli_in_workspace(
        workspace.path(),
        &["registry", "verify", &extension_id, "--json"],
    );
    assert!(
        !verify_json.status.success(),
        "registry verify --json should fail after tampering"
    );
    let verify_payload: serde_json::Value = serde_json::from_slice(&verify_json.stdout)
        .expect("registry verify --json failure should emit JSON");
    assert_eq!(
        verify_payload["schema_version"],
        "franken-node/registry-verify-cli/v1"
    );
    assert_eq!(verify_payload["command"], "registry.verify");
    assert_eq!(verify_payload["extension_id"], extension_id);
    assert_eq!(verify_payload["integrity"], "hash-mismatch");
}

#[test]
fn registry_verify_rejects_replacement_artifact_with_recomputed_storage_hashes() {
    use sha2::Digest;

    let workspace = registry_workspace();
    let (extension_id, artifact_path, manifest_path) = publish_signed_artifact(workspace.path());
    assert_registry_verify_integrity(workspace.path(), &extension_id, "verified", "original");
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    let mut tampered = original.clone();
    let replacement = b"attacker-controlled replacement package";
    let digest = hex::encode(sha2::Sha256::digest(replacement));
    fs::write(&artifact_path, replacement).expect("replace stored artifact");
    tampered["artifact_sha256"] = serde_json::json!(format!("sha256:{digest}"));
    tampered["artifact_size_bytes"] = serde_json::json!(replacement.len());
    tampered["extension"]["versions"][0]["content_hash"] = serde_json::json!(digest);
    // No signing key is used for the attack. The original signed statement is
    // intact while every unsigned package hash agrees with the replacement.
    assert_eq!(
        tampered["manifest_bytes_b64"],
        original["manifest_bytes_b64"]
    );
    assert_eq!(
        tampered["extension"]["signature"],
        original["extension"]["signature"]
    );
    fs::write(
        &manifest_path,
        serde_json::to_vec(&tampered).expect("encode forged wrapper"),
    )
    .expect("write forged wrapper");

    let report = assert_registry_verify_integrity(
        workspace.path(),
        &extension_id,
        "invalid-metadata",
        "recomputed storage hashes",
    );
    assert!(
        report["detail"]
            .as_str()
            .expect("detail")
            .contains("initial_version")
    );
    let human = run_cli_in_workspace(workspace.path(), &["registry", "verify", &extension_id]);
    assert!(!human.status.success());
    assert!(String::from_utf8_lossy(&human.stderr).contains("invalid-metadata"));

    let search = run_cli_in_workspace(
        workspace.path(),
        &["registry", "search", "plugin", "--json"],
    );
    assert!(
        search.status.success(),
        "search must still report corrupt entries"
    );
    let search: serde_json::Value = serde_json::from_slice(&search.stdout).expect("search report");
    let row = search["rows"]
        .as_array()
        .expect("rows")
        .iter()
        .find(|row| row["extension_id"] == extension_id)
        .expect("published row");
    assert_eq!(row["integrity_status"], "invalid-metadata");
}

#[test]
fn registry_verify_rejects_substituted_publisher_provenance() {
    let workspace = registry_workspace();
    let (extension_id, _, manifest_path) = publish_signed_artifact(workspace.path());
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).unwrap()).unwrap();
    let mut substituted = original.clone();
    substituted["extension"]["provenance"]["source_repository_url"] =
        serde_json::json!("https://example.com/unapproved/source");
    fs::write(&manifest_path, serde_json::to_vec(&substituted).unwrap()).unwrap();
    let report = assert_registry_verify_integrity(
        workspace.path(),
        &extension_id,
        "invalid-signature",
        "provenance substitution",
    );
    assert!(report.to_string().contains("provenance"), "{report}");
    fs::write(&manifest_path, serde_json::to_vec(&original).unwrap()).unwrap();
    assert_registry_verify_integrity(
        workspace.path(),
        &extension_id,
        "verified",
        "authentic provenance restored",
    );
}

#[test]
fn registry_verify_binds_signed_identity_version_and_size() {
    let workspace = registry_workspace();
    let (extension_id, _, manifest_path) = publish_signed_artifact(workspace.path());
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    let mut appended_versions = original["extension"]["versions"].clone();
    let mut unsigned_version = original["extension"]["versions"][0].clone();
    unsigned_version["version"] = serde_json::json!("2.0.0");
    unsigned_version["parent_version"] = serde_json::json!("1.0.0");
    appended_versions
        .as_array_mut()
        .expect("versions")
        .push(unsigned_version);
    let cases = [
        (
            "/extension/name",
            serde_json::json!("substituted-package"),
            "invalid-metadata",
        ),
        (
            "/extension/publisher_id",
            serde_json::json!("another-publisher"),
            "invalid-metadata",
        ),
        (
            "/extension/tags",
            serde_json::json!(["trusted"]),
            "invalid-metadata",
        ),
        (
            "/extension/versions/0/version",
            serde_json::json!("2.0.0"),
            "invalid-metadata",
        ),
        (
            "/extension/versions/0/parent_version",
            serde_json::json!("0.9.0"),
            "invalid-metadata",
        ),
        (
            "/extension/versions/0/registered_at",
            serde_json::json!("2020-01-01T00:00:00Z"),
            "invalid-metadata",
        ),
        (
            "/extension/versions/0/compatible_with",
            serde_json::json!(["anything"]),
            "invalid-metadata",
        ),
        ("/extension/versions", appended_versions, "invalid-metadata"),
        (
            "/artifact_size_bytes",
            serde_json::json!(0),
            "invalid-metadata",
        ),
        (
            "/extension/signature/algorithm",
            serde_json::json!("sha256"),
            "invalid-signature",
        ),
    ];
    for (field, replacement, expected) in cases {
        let mut tampered = original.clone();
        *tampered.pointer_mut(field).expect("existing field") = replacement;
        fs::write(
            &manifest_path,
            serde_json::to_vec(&tampered).expect("encode manifest"),
        )
        .expect("write mutated manifest");
        assert_registry_verify_integrity(workspace.path(), &extension_id, expected, field);
    }
    fs::write(
        &manifest_path,
        serde_json::to_vec(&original).expect("encode original"),
    )
    .expect("restore fixture manifest");
    assert_registry_verify_integrity(
        workspace.path(),
        &extension_id,
        "verified",
        "original restored",
    );
}

#[test]
fn registry_verify_checks_signed_statement_schema_without_requiring_json_layout() {
    use base64::Engine as _;
    use ed25519_dalek::Signer as _;

    let workspace = registry_workspace();
    let (extension_id, _, manifest_path) = publish_signed_artifact(workspace.path());
    let original: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("read manifest"))
            .expect("parse manifest");
    let signed_bytes = base64::engine::general_purpose::STANDARD
        .decode(
            original["manifest_bytes_b64"]
                .as_str()
                .expect("signed bytes"),
        )
        .expect("decode statement");
    let statement: serde_json::Value = serde_json::from_slice(&signed_bytes).expect("statement");
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&[42_u8; 32]);
    let mut wrong_schema = statement.clone();
    wrong_schema["schema_version"] = serde_json::json!("unrelated-signed-statement/v1");
    let mut unknown_field = statement.clone();
    unknown_field["unsigned_authority"] = serde_json::json!("all");
    let mut missing_field = statement.clone();
    missing_field
        .as_object_mut()
        .expect("object")
        .remove("name");
    let valid = serde_json::to_string(&statement).expect("encode statement");
    let duplicate_field = format!(
        "{{\"name\":\"substituted\",{}",
        valid.strip_prefix('{').expect("object")
    );
    let cases = [
        (
            "equivalent pretty JSON",
            serde_json::to_vec_pretty(&statement).expect("pretty statement"),
            "verified",
        ),
        (
            "wrong schema",
            serde_json::to_vec(&wrong_schema).expect("wrong schema"),
            "invalid-metadata",
        ),
        (
            "unknown field",
            serde_json::to_vec(&unknown_field).expect("unknown field"),
            "invalid-metadata",
        ),
        (
            "missing field",
            serde_json::to_vec(&missing_field).expect("missing field"),
            "invalid-metadata",
        ),
        (
            "duplicate field",
            duplicate_field.into_bytes(),
            "invalid-metadata",
        ),
    ];
    for (case, bytes, expected) in cases {
        // Sign with the same real test publisher so malformed statements reach
        // semantic validation; rejection must not depend on a broken signature.
        let signature = signing_key.sign(&bytes);
        let mut manifest = original.clone();
        manifest["manifest_bytes_b64"] =
            serde_json::json!(base64::engine::general_purpose::STANDARD.encode(&bytes));
        manifest["extension"]["signature"]["signature_bytes"] =
            serde_json::json!(signature.to_bytes().to_vec());
        resign_published_provenance(&mut manifest, &signing_key);
        fs::write(
            &manifest_path,
            serde_json::to_vec(&manifest).expect("encode wrapper"),
        )
        .expect("write wrapper");
        assert_registry_verify_integrity(workspace.path(), &extension_id, expected, case);
    }
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
            "--version",
            "1.0.0",
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
            "--version",
            "1.0.0",
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
            "--version",
            "1.0.0",
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

    let verify_json = run_cli_in_workspace(
        workspace.path(),
        &["registry", "verify", &extension_id, "--json"],
    );
    assert!(
        !verify_json.status.success(),
        "registry verify --json should fail after manifest tampering"
    );
    let payload: serde_json::Value = serde_json::from_slice(&verify_json.stdout)
        .expect("registry verify --json failure stdout must be JSON");
    assert_eq!(
        payload["schema_version"],
        "franken-node/registry-verify-cli/v1"
    );
    assert_eq!(payload["command"], "registry.verify");
    assert_eq!(payload["integrity"], "invalid-signature");
    let json_stderr = String::from_utf8_lossy(&verify_json.stderr);
    assert!(
        !json_stderr.contains("Error: registry verify failed"),
        "--json must not append a second human Error line after the JSON report: {json_stderr}"
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
                "--version",
                "1.0.0",
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

    let gc_json = run_cli_in_workspace(
        workspace.path(),
        &["registry", "gc", "--keep", "1", "--json"],
    );
    assert!(
        gc_json.status.success(),
        "registry gc --json failed: {}",
        String::from_utf8_lossy(&gc_json.stderr)
    );
    let gc_payload: serde_json::Value =
        serde_json::from_slice(&gc_json.stdout).expect("registry gc --json should emit valid JSON");
    assert_eq!(
        gc_payload["schema_version"],
        "franken-node/registry-gc-cli/v1"
    );
    assert_eq!(gc_payload["command"], "registry.gc");
    assert_eq!(gc_payload["keep"], 1);
    assert_eq!(gc_payload["archived"], 0);
    let gc_json_stdout = String::from_utf8_lossy(&gc_json.stdout);
    assert!(
        !gc_json_stdout.contains("registry gc:"),
        "json mode must not emit the human one-liner:\n{gc_json_stdout}"
    );

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
