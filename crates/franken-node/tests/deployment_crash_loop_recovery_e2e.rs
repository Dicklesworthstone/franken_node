//! Crash-loop recovery to an authenticated known-good release, end to end
//! (bd-reality-20260923-26n9r.22; drill companion .23).
//!
//! Two publisher-approved releases of one application are admitted into a
//! deployment. The newer one panics the native engine on every start (the
//! `test-support` fault injection inside the engine worker's caught panic
//! boundary, so every crash passes the real validated panic path: envelope,
//! nonce, durable crash record, threshold and safe mode). After the third
//! validated panic the supervisor's crash-loop observation drives the signed
//! policy: the activation pointer moves to the release that previously ran
//! healthy, that release actually runs, and the failed release stays
//! contained and inspectable. Missing, corrupted and tampered state never
//! switches anything.

#![cfg(all(feature = "engine", feature = "test-support", unix))]

#[path = "deployment_support/dependency_admission.rs"]
mod dependency_admission;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use frankenengine_node::runtime::deployment::ReleaseRecord;
use serde_json::Value;

const PANIC_MARKER: &str = "__FRANKEN_NODE_TEST_SUPPORT_NATIVE_ENGINE_PANIC__";
const PANIC_AFTER_HOST_EFFECT_MARKER: &str =
    "__FRANKEN_NODE_TEST_SUPPORT_NATIVE_ENGINE_PANIC_AFTER_HOST_EFFECT__";

fn binary() -> &'static str {
    env!("CARGO_BIN_EXE_franken-node")
}

fn git(dir: &Path, args: &[&str]) {
    let status = Command::new("git")
        .current_dir(dir)
        .args(args)
        .status()
        .expect("git");
    assert!(status.success(), "git {}", args.join(" "));
}

struct Drill {
    /// Deployment root: the operator project holding the deployment state.
    root: tempfile::TempDir,
    /// Publisher workspace: signing key and registry state, outside the root.
    registry: tempfile::TempDir,
    /// Private runtime-evidence state home shared by every run.
    state_home: tempfile::TempDir,
    public_key: PathBuf,
}

impl Drill {
    fn new() -> Self {
        let root = tempfile::tempdir().expect("root");
        let registry = tempfile::tempdir().expect("registry");
        let state_home = tempfile::tempdir().expect("state home");
        fs::write(registry.path().join("README"), "publisher workspace\n").expect("readme");
        git(registry.path(), &["init", "-q", "-b", "main"]);
        git(
            registry.path(),
            &["config", "user.email", "publisher@example.com"],
        );
        git(registry.path(), &["config", "user.name", "Publisher"]);
        git(
            registry.path(),
            &[
                "remote",
                "add",
                "origin",
                "https://example.com/acme/app.git",
            ],
        );
        git(registry.path(), &["add", "README"]);
        git(registry.path(), &["commit", "-q", "-m", "initial"]);
        fs::write(
            registry.path().join("publisher.ed25519"),
            hex::encode([42_u8; 32]),
        )
        .expect("publisher key");
        let public_key = registry.path().join("publisher.pub");
        fs::write(
            &public_key,
            hex::encode(
                ed25519_dalek::SigningKey::from_bytes(&[42_u8; 32])
                    .verifying_key()
                    .as_bytes(),
            ),
        )
        .expect("publisher public key");
        let drill = Self {
            root,
            registry,
            state_home,
            public_key,
        };
        drill.init_project(drill.root.path());
        drill
    }

    fn command(&self, cwd: &Path, args: &[&str]) -> Command {
        self.command_with_binary(Path::new(binary()), cwd, args)
    }

    fn command_with_binary(&self, executable: &Path, cwd: &Path, args: &[&str]) -> Command {
        let mut command = Command::new(executable);
        command
            .current_dir(cwd)
            .env("XDG_STATE_HOME", self.state_home.path())
            .env("XDG_CONFIG_HOME", self.state_home.path().join("config"))
            .env_remove("FRANKEN_NODE_PROFILE")
            .env_remove("FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH")
            .env_remove("FRANKEN_NODE_TEST_DEPLOYMENT_STOP_AFTER")
            .args(args);
        command
    }

    fn cli(&self, cwd: &Path, args: &[&str]) -> Output {
        self.command(cwd, args)
            .output()
            .unwrap_or_else(|error| panic!("`{}`: {error}", args.join(" ")))
    }

    fn ok(&self, cwd: &Path, args: &[&str]) -> Value {
        let output = self.cli(cwd, args);
        assert!(
            output.status.success(),
            "`{}` failed:\n{}\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "`{}` must emit JSON ({error}): {}",
                args.join(" "),
                String::from_utf8_lossy(&output.stdout)
            )
        })
    }

    /// `init` mints the project's receipt signing key: the deployment root
    /// signs its deployment records with it, a release its run records.
    fn init_project(&self, dir: &Path) {
        let init = self.cli(
            dir,
            &["init", "--profile", "balanced", "--out-dir", ".", "--json"],
        );
        assert!(
            init.status.success(),
            "init: {}",
            String::from_utf8_lossy(&init.stderr)
        );
        assert!(dir.join(".franken-node/keys/receipt-signing.key").is_file());
    }

    /// Build, init, capture and publish one release; returns its directory
    /// and the publisher-signed manifest.
    fn publish_release(&self, version: &str, source: &str) -> (PathBuf, PathBuf) {
        let dir = self.root.path().join("releases").join(version);
        self.publish_release_at(version, source, &dir)
    }

    fn publish_release_at(&self, version: &str, source: &str, dir: &Path) -> (PathBuf, PathBuf) {
        self.publish_release_with_config(version, source, dir, None)
    }

    fn publish_release_with_config(
        &self,
        version: &str,
        source: &str,
        dir: &Path,
        config: Option<&str>,
    ) -> (PathBuf, PathBuf) {
        fs::create_dir_all(dir).expect("release dir");
        fs::write(dir.join("app.js"), source).expect("app source");
        fs::write(
            dir.join("package.json"),
            format!("{{\"name\":\"deployed-app\",\"version\":\"{version}\"}}\n"),
        )
        .expect("package.json");
        if let Some(config) = config {
            // Bootstrap the registry and receipt key under this exact policy;
            // replacing a generated registry key afterward would invalidate it.
            fs::write(dir.join("release-policy.toml"), config)
                .expect("explicit release bootstrap configuration");
            self.ok(
                dir,
                &[
                    "init",
                    "--config",
                    "release-policy.toml",
                    "--out-dir",
                    ".",
                    "--json",
                ],
            );
            assert!(dir.join(".franken-node/keys/receipt-signing.key").is_file());
        } else {
            self.init_project(dir);
        }
        let (_, manifest) = self.publish_source_graph(version, dir, &[]);
        (dir.to_path_buf(), manifest)
    }

    fn publish_source_graph(
        &self,
        version: &str,
        dir: &Path,
        options: &[&str],
    ) -> (Value, PathBuf) {
        let capsule = format!("app-{version}.capsule");
        let mut arguments = vec![
            "verify",
            "source-graph",
            dir.to_str().expect("utf-8"),
            "app.js",
            "--write-source-capsule",
            &capsule,
            "--json",
        ];
        arguments.extend_from_slice(options);
        let graph = self.ok(self.registry.path(), &arguments);
        let published = self.ok(
            self.registry.path(),
            &[
                "registry",
                "publish",
                &capsule,
                "--version",
                version,
                "--signing-key",
                "publisher.ed25519",
                "--json",
            ],
        );
        let manifest = self
            .registry
            .path()
            .join(published["manifest_path"].as_str().expect("manifest path"));
        (graph, manifest)
    }

    /// A real npm workspace link and nested CJS/ESM export selection. The
    /// publisher approves the same options the release's profile selects;
    /// unselected branches throw if defaults accidentally replace that policy.
    fn publish_workspace_release(&self, version: &str, esm: bool) -> (PathBuf, PathBuf) {
        use std::os::unix::fs::symlink;

        let dir = self.root.path().join("releases").join(version);
        let package = dir.join("packages/shared");
        fs::create_dir_all(&package).unwrap();
        fs::create_dir_all(dir.join("node_modules")).unwrap();
        fs::write(
            dir.join("package.json"),
            serde_json::to_vec(&serde_json::json!({
                "name": "deployed-app", "version": version, "private": true,
                "type": if esm { "module" } else { "commonjs" },
                "workspaces": ["packages/*"], "dependencies": {"shared": "workspace:*"},
            }))
            .unwrap(),
        )
        .unwrap();
        fs::write(
            package.join("package.json"),
            r#"{"name":"shared","version":"1.0.0","exports":{"deployment":{"import":"./selected.mjs","require":"./selected.cjs"},"import":"./default.mjs","require":"./default.cjs"}}"#,
        )
        .unwrap();
        for (name, source) in [
            ("selected.cjs", "module.exports = require('./value.cjs');\n"),
            ("value.cjs", "module.exports = 'WORKSPACE_SELECTED_CJS';\n"),
            (
                "selected.mjs",
                "import value from './value.mjs'; export default value;\n",
            ),
            ("value.mjs", "export default 'WORKSPACE_SELECTED_ESM';\n"),
            ("default.cjs", "throw Error('UNAPPROVED_DEFAULT_BRANCH');\n"),
            ("default.mjs", "throw Error('UNAPPROVED_DEFAULT_BRANCH');\n"),
        ] {
            fs::write(package.join(name), source).unwrap();
        }
        symlink("../packages/shared", dir.join("node_modules/shared")).unwrap();
        fs::write(
            dir.join("app.js"),
            if esm {
                "import value from 'shared'; console.log(value);\n"
            } else {
                "console.log(require('shared'));\n"
            },
        )
        .unwrap();
        self.init_project(&dir);
        let (graph, manifest) = self.publish_source_graph(
            version,
            &dir,
            &["--allow-contained-symlinks", "--conditions", "deployment"],
        );
        assert_eq!(graph["fully_resolved"], true, "{graph}");
        set_release_runtime(&dir, "frozen_modules", toml::Value::Boolean(true));
        set_release_runtime(&dir, "frozen_module_symlinks", toml::Value::Boolean(true));
        set_release_runtime(
            &dir,
            "module_conditions",
            toml::Value::Array(vec![toml::Value::String("deployment".into())]),
        );
        set_release_runtime(
            &dir,
            "frozen_module_graph_hash",
            toml::Value::String(graph["input_hash"].as_str().unwrap().to_string()),
        );
        (dir, manifest)
    }

    fn install(&self, version: &str, source: &str) -> PathBuf {
        let (dir, manifest) = self.publish_release(version, source);
        self.install_published(version, &dir, &manifest);
        dir
    }

    fn install_published(&self, version: &str, dir: &Path, manifest: &Path) {
        let installed = self.ok(
            self.root.path(),
            &[
                "deploy",
                "install",
                "app",
                "--release-dir",
                dir.to_str().expect("utf-8"),
                "--entrypoint",
                "app.js",
                "--registry-artifact",
                manifest.to_str().expect("utf-8"),
                "--publisher-public-key",
                self.public_key.to_str().expect("utf-8"),
                "--json",
            ],
        );
        assert_eq!(installed["release"]["release_id"], version, "{installed}");
        assert_eq!(installed["created"], true);
    }

    fn activate(&self, version: &str) {
        self.ok(
            self.root.path(),
            &[
                "deploy",
                "activate",
                "app",
                "--release",
                version,
                "--operator-id",
                "ops-1",
                "--json",
            ],
        );
    }

    fn policy(&self, on_crash_loop: &str, restart: &str) {
        self.ok(
            self.root.path(),
            &[
                "deploy",
                "policy",
                "app",
                "--on-crash-loop",
                on_crash_loop,
                "--restart",
                restart,
                "--operator-id",
                "ops-1",
                "--json",
            ],
        );
    }

    /// `deploy run app --json`: (exit code, report).
    fn run(&self) -> (Option<i32>, Value) {
        let output = self.cli(self.root.path(), &["deploy", "run", "app", "--json"]);
        let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "deploy run must emit JSON ({error}):\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        (output.status.code(), report)
    }

    fn status(&self) -> Value {
        self.ok(self.root.path(), &["deploy", "status", "app", "--json"])
    }

    #[cfg(target_os = "linux")]
    fn fleet_ok(&self, project: &Path, fleet_state: &Path, args: &[&str]) -> Value {
        let output = self
            .command(project, args)
            .env("FRANKEN_NODE_FLEET_STATE_DIR", fleet_state)
            .env("FRANKEN_NODE_FLEET_CONVERGENCE_TIMEOUT_SECONDS", "2")
            .output()
            .expect("deployment fleet command");
        assert!(
            output.status.success(),
            "{} failed: {}\n{}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).expect("deployment fleet JSON")
    }

    #[cfg(target_os = "linux")]
    fn fleet_poll(&self, project: &Path, fleet_state: &Path, node: &str) -> Value {
        self.fleet_ok(
            project,
            fleet_state,
            &[
                "fleet",
                "agent",
                "--node-id",
                node,
                "--zone",
                "east",
                "--fallback-file-transport",
                "--once",
                "--json",
            ],
        )
    }

    #[cfg(target_os = "linux")]
    fn publish_fleet_policy(
        &self,
        project: &Path,
        fleet_state: &Path,
        policy_name: &str,
        policy: &Value,
    ) -> Value {
        let input = self.state_home.path().join(format!("{policy_name}.json"));
        fs::write(&input, serde_json::to_vec(policy).expect("policy JSON"))
            .expect("fleet policy input");
        let publication = self.fleet_ok(
            project,
            fleet_state,
            &[
                "fleet",
                "policy",
                "publish",
                "--zone",
                "east",
                "--revision",
                "1",
                "--file",
                input.to_str().expect("policy path"),
                "--json",
            ],
        );
        assert_eq!(publication["published"], true, "{publication}");
        assert_eq!(publication["activated"], false, "{publication}");
        publication
    }

    #[cfg(target_os = "linux")]
    fn sessions(&self, project: &Path) -> Value {
        self.ok(
            self.root.path(),
            &[
                "fleet",
                "sessions",
                "--project",
                project.to_str().expect("project path"),
                "--json",
            ],
        )
    }

    fn admitted_release(&self, version: &str) -> ReleaseRecord {
        let record: Value = serde_json::from_slice(
            &fs::read(self.root.path().join(format!(
                ".franken-node/state/deployments/app/releases/{version}.json"
            )))
            .expect("signed release record"),
        )
        .expect("release record JSON");
        serde_json::from_value(record["payload"].clone()).expect("admitted release")
    }

    /// Exercise the child admission boundary after the supervisor has already
    /// chosen a signed release. Tests can replace inputs deterministically
    /// between these two phases without weakening or mocking native dispatch.
    fn admitted_child(&self, release: &ReleaseRecord, manifest: &Path) -> Output {
        self.cli(
            &release.release_dir,
            &[
                "run",
                &release.entrypoint,
                "--config",
                "franken_node.toml",
                "--runtime",
                "franken-engine",
                "--frozen-modules",
                "--json",
                "--registry-artifact",
                manifest.to_str().expect("manifest path"),
                "--publisher-public-key",
                self.public_key.to_str().expect("public key path"),
                "--admitted-config-sha256",
                &release.config_sha256,
                "--admitted-approval-sha256",
                &release.approval.admission_sha256().expect("approval pin"),
            ],
        )
    }

    fn state_path(&self, relative: &str) -> PathBuf {
        self.root
            .path()
            .join(".franken-node/state/deployments/app")
            .join(relative)
    }

    /// Terminate the actual CLI after the selected record has been fsynced.
    /// This hook is compiled only into test-support builds. The next command
    /// is a fresh process which must recover from the retained signed bytes.
    fn interrupt(&self, args: &[&str], stage: &str) {
        let output = self
            .command(self.root.path(), args)
            .env("FRANKEN_NODE_TEST_DEPLOYMENT_STOP_AFTER", stage)
            .output()
            .expect("interrupted deployment command");
        assert_eq!(
            output.status.code(),
            Some(86),
            "expected durable interruption after {stage}:\n{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn interrupt_activation(&self, stage: &str) {
        self.interrupt(
            &[
                "deploy",
                "activate",
                "app",
                "--release",
                "1.0.0",
                "--operator-id",
                "ops-1",
                "--json",
            ],
            stage,
        );
    }

    fn reconcile(&self) -> Value {
        self.ok(
            self.root.path(),
            &[
                "deploy",
                "reconcile",
                "app",
                "--operator-id",
                "ops-recovery",
                "--json",
            ],
        )
    }

    fn failed_reconcile(&self) -> Value {
        let output = self.cli(
            self.root.path(),
            &[
                "deploy",
                "reconcile",
                "app",
                "--operator-id",
                "ops-recovery",
                "--json",
            ],
        );
        assert!(!output.status.success(), "reconcile unexpectedly succeeded");
        let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "failed reconcile must emit JSON ({error}):\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        assert_eq!(report["ok"], false, "{report}");
        report
    }

    fn supersede(&self, version: &str, pending_digest: &str) -> Value {
        self.ok(self.root.path(), &supersede_args(version, pending_digest))
    }

    fn failed_supersede(&self, version: &str, pending_digest: &str) -> Value {
        let output = self.cli(self.root.path(), &supersede_args(version, pending_digest));
        assert!(!output.status.success(), "supersede unexpectedly succeeded");
        let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "failed supersede must emit JSON ({error}):\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        assert_eq!(report["ok"], false, "{report}");
        report
    }

    fn artifact_digest(&self, version: &str) -> String {
        self.status()["releases"]
            .as_array()
            .expect("releases")
            .iter()
            .find(|release| release["release_id"] == version)
            .and_then(|release| release["artifact"]["artifact_sha256"].as_str())
            .expect("artifact digest")
            .to_string()
    }

    /// Crash the active (panicking) release until the supervisor's validated
    /// crash-loop threshold (three panics in 60 s) is reached.
    fn crash_until_loop(&self) -> (Option<i32>, Value) {
        self.prime_crash_loop();
        self.run()
    }

    fn prime_crash_loop(&self) {
        for attempt in 1..=2 {
            let (code, report) = self.run();
            assert_eq!(report["phase"], "crashed", "attempt {attempt}: {report}");
            assert_ne!(code, Some(0));
            assert_eq!(report["run"]["outcome"], "native_engine_panic", "{report}");
            assert_eq!(report["run"]["crash_loop"]["crashes_in_window"], attempt);
            assert_eq!(
                report["observation_authentication"]["verified"], true,
                "{report}"
            );
            assert_eq!(
                report["observation_authentication"]["observation"]["session_nonce"],
                report["run"]["session_nonce"],
            );
            assert!(report.get("recovery").is_none(), "{report}");
        }
    }
}

const HEALTHY_V1: &str = "console.log('RELEASE_ONE_HEALTHY');\n";

fn set_release_runtime(dir: &Path, field: &str, value: toml::Value) {
    let path = dir.join("franken_node.toml");
    let mut document: toml::Value = toml::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    let mut section = &mut document;
    // Exercise effective profile configuration, not just the root document's
    // runtime table. Existing registry and receipt authority stay unchanged.
    for name in ["profiles", "balanced", "runtime"] {
        section = section
            .as_table_mut()
            .unwrap()
            .entry(name.to_string())
            .or_insert_with(|| toml::Value::Table(toml::Table::new()));
    }
    section
        .as_table_mut()
        .unwrap()
        .insert(field.to_string(), value);
    fs::write(path, toml::to_string_pretty(&document).unwrap()).unwrap();
}

fn crashing_v2() -> String {
    format!("// {PANIC_MARKER}\nconsole.log('RELEASE_TWO_NEVER_PRINTS');\n")
}

fn supersede_args<'a>(version: &'a str, pending_digest: &'a str) -> [&'a str; 12] {
    [
        "deploy",
        "supersede",
        "app",
        "--expected-pending-digest",
        pending_digest,
        "--release",
        version,
        "--operator-id",
        "ops-recovery",
        "--reason",
        "replace an unavailable activation target",
        "--json",
    ]
}

fn guest_stdout(run: &Value) -> &str {
    run["dispatch"]["captured_output"]["stdout"]
        .as_str()
        .unwrap_or_default()
}

fn assert_workspace_run(run: &Value, admitted: &ReleaseRecord, expected: &str) {
    assert_eq!(guest_stdout(run), expected, "{run}");
    let graph = &run["dispatch"]["engine_decision"]["frozen_modules"];
    assert_eq!(graph["contained_symlinks"], true, "{graph}");
    assert_eq!(
        graph["graph_input_hash"],
        admitted.approval.graph_input_hash()
    );
    assert_eq!(
        graph["publisher_artifact"],
        serde_json::to_value(admitted.approval.identity()).unwrap(),
    );
    assert!(!run.to_string().contains("UNAPPROVED_DEFAULT_BRANCH"));
}

#[test]
fn workspace_deployment_runs_its_signed_branch_and_recovers_to_it_after_a_crash_loop() {
    let drill = Drill::new();
    let (release, manifest) = drill.publish_workspace_release("1.0.0", false);
    drill.install_published("1.0.0", &release, &manifest);
    let admitted = drill.admitted_release("1.0.0");
    drill.activate("1.0.0");
    let (code, healthy) = drill.run();
    assert_eq!(code, Some(0), "{healthy}");
    assert_eq!(healthy["phase"], "healthy", "{healthy}");
    assert_workspace_run(&healthy["run"], &admitted, "WORKSPACE_SELECTED_CJS\n");

    let failed = drill.install("2.0.0", &crashing_v2());
    drill.policy("rollback", "automatic");
    drill.activate("2.0.0");
    let (code, recovered) = drill.crash_until_loop();
    assert_eq!(code, Some(0), "{recovered}");
    assert_eq!(recovered["phase"], "resumed_healthy", "{recovered}");
    assert_eq!(recovered["recovery"]["selected_release_id"], "1.0.0");
    assert_eq!(
        recovered["recovery"]["candidate_refusals"],
        serde_json::json!([]),
    );
    assert_workspace_run(
        &recovered["resumed"]["run"],
        &admitted,
        "WORKSPACE_SELECTED_CJS\n",
    );
    assert_eq!(drill.status()["active"]["release_id"], "1.0.0");
    assert!(failed.join("app.js").is_file());
    let failed_state: Value = serde_json::from_slice(
        &fs::read(failed.join(".franken-node/safe-mode/state.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(failed_state["active"], true);
}

#[test]
fn workspace_deployment_reconciles_and_executes_the_profile_selected_esm_branch() {
    let drill = Drill::new();
    let (release, manifest) = drill.publish_workspace_release("1.0.0", true);
    drill.install_published("1.0.0", &release, &manifest);
    let admitted = drill.admitted_release("1.0.0");
    drill.interrupt_activation("intent");
    let reconciled = drill.reconcile();
    assert_eq!(reconciled["reconciled"], true, "{reconciled}");
    assert!(reconciled.get("run").is_none());
    assert_eq!(drill.status()["releases"][0]["healthy_runs"], 0);

    // The supervisor's ambient options must not replace the signed release
    // policy or leak to the child, including during a resumed activation.
    let output = drill
        .command(drill.root.path(), &["deploy", "run", "app", "--json"])
        .env("FRANKEN_NODE_RUNTIME_FROZEN_MODULE_SYMLINKS", "false")
        .env(
            "FRANKEN_NODE_RUNTIME_MODULE_CONDITIONS",
            r#"["unapproved"]"#,
        )
        .env("FRANKEN_NODE_PROFILE", "strict")
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout),
    );
    let healthy: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(healthy["phase"], "healthy", "{healthy}");
    assert_workspace_run(&healthy["run"], &admitted, "WORKSPACE_SELECTED_ESM\n");
}

#[test]
fn workspace_deployment_refuses_unapproved_options_before_admission() {
    let drill = Drill::new();
    let (release, manifest) = drill.publish_workspace_release("1.0.0", false);
    let config = release.join("franken_node.toml");
    let original = fs::read(&config).unwrap();
    for (field, value, expected) in [
        (
            "module_conditions",
            toml::Value::Array(vec![toml::Value::String("different".into())]),
            "run conditions do not match",
        ),
        (
            "frozen_module_symlinks",
            toml::Value::Boolean(false),
            "run symlink policy does not match",
        ),
        (
            "frozen_module_graph_hash",
            toml::Value::String(format!("sha256:{}", "0".repeat(64))),
            "explicit frozen module graph pin conflicts",
        ),
    ] {
        fs::write(&config, &original).unwrap();
        set_release_runtime(&release, field, value);
        let output = drill.cli(
            drill.root.path(),
            &[
                "deploy",
                "install",
                "app",
                "--release-dir",
                release.to_str().unwrap(),
                "--entrypoint",
                "app.js",
                "--registry-artifact",
                manifest.to_str().unwrap(),
                "--publisher-public-key",
                drill.public_key.to_str().unwrap(),
                "--json",
            ],
        );
        assert!(
            !output.status.success(),
            "{field} must require publisher approval",
        );
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            report["error"].as_str().unwrap().contains(expected),
            "{field}: {report}",
        );
        assert!(!drill.state_path("releases/1.0.0.json").exists());
        assert!(!drill.state_path("active.json").exists());
    }
    fs::write(config, original).unwrap();
    drill.install_published("1.0.0", &release, &manifest);
}

#[test]
fn workspace_deployment_keeps_config_source_and_link_retargeting_bound_after_admission() {
    use std::os::unix::fs::symlink;

    let drill = Drill::new();
    let (release, manifest) = drill.publish_workspace_release("1.0.0", false);
    drill.install_published("1.0.0", &release, &manifest);
    drill.activate("1.0.0");
    let admitted = drill.admitted_release("1.0.0");
    let active = fs::read(drill.state_path("active.json")).unwrap();
    let config = release.join("franken_node.toml");
    let original_config = fs::read(&config).unwrap();
    set_release_runtime(
        &release,
        "module_conditions",
        toml::Value::Array(vec![toml::Value::String("different".into())]),
    );
    let (code, blocked) = drill.run();
    assert_ne!(code, Some(0), "{blocked}");
    assert!(
        blocked["error"]
            .as_str()
            .unwrap()
            .contains("release config")
    );
    assert!(blocked.get("run").is_none());
    let child = drill.admitted_child(&admitted, &manifest);
    assert!(!child.status.success());
    let child: Value = serde_json::from_slice(&child.stdout).unwrap();
    assert!(
        child["error"]
            .as_str()
            .unwrap()
            .contains("release config changed after admission"),
    );
    fs::write(config, original_config).unwrap();

    let selected = release.join("packages/shared/value.cjs");
    let original_source = fs::read(&selected).unwrap();
    fs::write(
        &selected,
        "module.exports = 'WORKSPACE_SELECTED_CJS'; // changed bytes\n",
    )
    .unwrap();
    let (code, blocked) = drill.run();
    assert_ne!(code, Some(0), "{blocked}");
    assert!(
        blocked["error"]
            .as_str()
            .unwrap()
            .contains("source graph changed"),
    );
    assert!(blocked.get("run").is_none());
    fs::write(selected, original_source).unwrap();

    // Keep the replacement outside packages/* so restoring the original link
    // does not leave a second workspace declaration with the same package name.
    let replacement = release.join("replacement-shared");
    fs::create_dir_all(&replacement).unwrap();
    for name in ["package.json", "selected.cjs", "value.cjs"] {
        fs::copy(
            release.join("packages/shared").join(name),
            replacement.join(name),
        )
        .unwrap();
    }
    let link = release.join("node_modules/shared");
    let retained = release.join("original-workspace-link");
    fs::rename(&link, &retained).unwrap();
    symlink("../replacement-shared", &link).unwrap();
    let (code, blocked) = drill.run();
    assert_ne!(code, Some(0), "{blocked}");
    assert!(
        blocked["error"]
            .as_str()
            .unwrap()
            .contains("source graph changed"),
    );
    assert!(blocked.get("run").is_none());
    fs::rename(&link, release.join("changed-workspace-link")).unwrap();
    fs::rename(retained, link).unwrap();
    assert_eq!(fs::read(drill.state_path("active.json")).unwrap(), active);

    let (code, healthy) = drill.run();
    assert_eq!(code, Some(0), "{healthy}");
    assert_workspace_run(&healthy["run"], &admitted, "WORKSPACE_SELECTED_CJS\n");
}

#[cfg(target_os = "linux")]
#[test]
fn deployment_admission_binds_executable_bytes_even_with_the_same_version() {
    use std::io::Write as _;

    let drill = Drill::new();
    drill.install("1.0.0", HEALTHY_V1);
    drill.activate("1.0.0");
    let admitted = drill.admitted_release("1.0.0");
    let (_, digest) = admitted
        .engine_compatibility
        .rsplit_once("/sha256:")
        .expect("admission includes the executable commitment");
    assert_eq!(digest.len(), 64);
    assert!(digest.bytes().all(|byte| byte.is_ascii_hexdigit()));

    let binaries = tempfile::tempdir().expect("copied executable directory");
    let copied = binaries.path().join("franken-node-copy");
    fs::copy(binary(), &copied).expect("copy exact executable");
    let args = ["deploy", "run", "app", "--json"];
    let allowed = drill
        .command_with_binary(&copied, drill.root.path(), &args)
        .output()
        .expect("run the byte-identical copy");
    assert!(
        allowed.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed.stdout)
    );
    let allowed: Value = serde_json::from_slice(&allowed.stdout).expect("deployment report");
    assert_eq!(allowed["phase"], "healthy");
    assert_eq!(guest_stdout(&allowed["run"]), "RELEASE_ONE_HEALTHY\n");
    let before = drill.status();

    // An ELF trailer changes the binary commitment without changing its
    // executable instructions, package version, or compiled Git revision.
    // No source, release, signature or policy fixture is altered.
    {
        let mut executable = fs::OpenOptions::new()
            .append(true)
            .open(&copied)
            .expect("open completed executable copy");
        executable
            .write_all(b"\nfranken-node-different-build-regression\n")
            .expect("change executable identity");
        executable.sync_all().expect("persist changed executable");
    }
    let original_version = drill.cli(drill.root.path(), &["--version"]);
    let changed_version = drill
        .command_with_binary(&copied, drill.root.path(), &["--version"])
        .output()
        .expect("changed executable still runs");
    assert!(original_version.status.success());
    assert!(changed_version.status.success());
    assert_eq!(changed_version.stdout, original_version.stdout);

    for arguments in [
        vec!["deploy", "run", "app", "--json"],
        vec![
            "deploy",
            "activate",
            "app",
            "--release",
            "1.0.0",
            "--operator-id",
            "ops-other-build",
            "--json",
        ],
    ] {
        let refused = drill
            .command_with_binary(&copied, drill.root.path(), &arguments)
            .output()
            .expect("different-build deployment request");
        assert!(!refused.status.success());
        let refused: Value = serde_json::from_slice(&refused.stdout).expect("refusal report");
        assert!(
            refused["error"].as_str().is_some_and(|error| {
                error.contains("release was admitted under") && error.contains("sha256:")
            }),
            "{refused}"
        );
        assert!(!refused.to_string().contains("RELEASE_ONE_HEALTHY"));
        assert_eq!(
            drill.status(),
            before,
            "refusal must not rewrite deployment state"
        );
    }

    drill.interrupt_activation("intent");
    let pending = drill.status();
    assert!(!pending["pending_activation"].is_null());
    let refused = drill
        .command_with_binary(
            &copied,
            drill.root.path(),
            &[
                "deploy",
                "reconcile",
                "app",
                "--operator-id",
                "ops-other-build",
                "--json",
            ],
        )
        .output()
        .expect("different-build pending reconciliation");
    assert!(!refused.status.success());
    let refused: Value = serde_json::from_slice(&refused.stdout).expect("reconciliation refusal");
    assert!(
        refused["error"]
            .as_str()
            .is_some_and(|error| error.contains("release was admitted under")),
        "{refused}"
    );
    assert_eq!(
        drill.status(),
        pending,
        "signed pending intent must remain unchanged"
    );
    assert_eq!(drill.reconcile()["reconciled"], true);
    assert_eq!(drill.run().1["phase"], "healthy");
}

#[test]
fn historical_revision_only_deployment_is_readable_but_cannot_run() {
    use frankenengine_node::runtime::deployment::{
        ActivationReason, DeploymentAuthority, DeploymentStore,
    };

    let drill = Drill::new();
    drill.install("1.0.0", HEALTHY_V1);
    let mut historical = drill.admitted_release("1.0.0");
    historical.release_id = "legacy".to_string();
    historical.engine_compatibility = historical
        .engine_compatibility
        .rsplit_once("/sha256:")
        .expect("current admission contains an executable commitment")
        .0
        .to_string();

    // Construct a genuinely signed historical record with the deployment's
    // own authority. Rejecting an invalid signature would miss this regression.
    let key_hex = fs::read_to_string(
        drill
            .root
            .path()
            .join(".franken-node/keys/receipt-signing.key"),
    )
    .expect("deployment authority");
    let secret: [u8; 32] = hex::decode(key_hex.trim())
        .expect("hex signing key")
        .try_into()
        .expect("32-byte signing key");
    let authority = DeploymentAuthority::new(ed25519_dalek::SigningKey::from_bytes(&secret));
    let store = DeploymentStore::open(drill.root.path(), "app").expect("deployment store");
    {
        let lock = store.lock().expect("deployment lock");
        store
            .install_release(&lock, &authority, historical.clone())
            .expect("retain authenticated legacy admission");
        store
            .activate(
                &lock,
                &authority,
                "legacy",
                ActivationReason::Operator,
                Some("historical-operator"),
                None,
                historical.installed_at_epoch_secs,
            )
            .expect("historical activation");
    }

    let before = drill.status();
    assert_eq!(before["active"]["release_id"], "legacy");
    let (code, refused) = drill.run();
    assert_ne!(code, Some(0));
    assert!(
        refused["error"]
            .as_str()
            .is_some_and(|error| error.contains("release was admitted under")),
        "{refused}"
    );
    assert!(!refused.to_string().contains("RELEASE_ONE_HEALTHY"));
    assert_eq!(
        drill.status(),
        before,
        "historical signatures are not upgraded"
    );
}

#[test]
fn admitted_child_binds_config_bytes_before_any_guest_execution() {
    let drill = Drill::new();
    let directory = drill.install("1.0.0", HEALTHY_V1);
    let admitted = drill.admitted_release("1.0.0");
    let allowed = drill.admitted_child(&admitted, &admitted.registry_manifest);
    assert!(
        allowed.status.success(),
        "{}",
        String::from_utf8_lossy(&allowed.stdout)
    );
    let report: Value = serde_json::from_slice(&allowed.stdout).unwrap();
    assert_eq!(guest_stdout(&report), "RELEASE_ONE_HEALTHY\n");

    // Substitute after supervisor admission, before child load. Even a parse
    // failure must be classified as a commitment mismatch, not consumed as
    // new runtime configuration.
    fs::write(
        directory.join("franken_node.toml"),
        "not an admitted TOML policy",
    )
    .unwrap();
    let refused = drill.admitted_child(&admitted, &admitted.registry_manifest);
    assert!(!refused.status.success());
    let report: Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert!(
        report["error"]
            .as_str()
            .unwrap()
            .contains("release config changed after admission")
    );
    assert_eq!(guest_stdout(&report), "");
    assert!(!report.to_string().contains("RELEASE_ONE_HEALTHY"));
}

#[test]
fn admitted_child_rejects_another_valid_publishers_approval() {
    let drill = Drill::new();
    drill.install("1.0.0", HEALTHY_V1);
    drill.install("2.0.0", HEALTHY_V1);
    let admitted = drill.admitted_release("1.0.0");
    let substituted = drill.admitted_release("2.0.0");
    // Independently establish that the replacement has a real valid signature
    // from the same publisher; rejection must be the exact admission binding.
    substituted.approval.revalidate().unwrap();
    let refused = drill.admitted_child(&admitted, &substituted.registry_manifest);
    assert!(!refused.status.success());
    let report: Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert!(
        report["error"]
            .as_str()
            .unwrap()
            .contains("publisher approval changed after deployment admission")
    );
    assert!(!report.to_string().contains("RELEASE_ONE_HEALTHY"));
}

#[test]
fn supervised_release_uses_admitted_policy_without_supervisor_environment_overrides() {
    let drill = Drill::new();
    drill.install("1.0.0", HEALTHY_V1);
    drill.activate("1.0.0");
    let output = Command::new(binary())
        .current_dir(drill.root.path())
        .env("XDG_STATE_HOME", drill.state_home.path())
        .env("XDG_CONFIG_HOME", drill.state_home.path().join("config"))
        .env("FRANKEN_NODE_PROFILE", "strict")
        .env("FRANKEN_NODE_RUNTIME_MAX_INSTRUCTIONS", "1")
        .env(
            "FRANKEN_ENGINE_BIN",
            "/nonexistent/deployment-engine-override",
        )
        .env("FRANKEN_ENGINE_TIMEOUT_SECS", "0")
        .args(["deploy", "run", "app", "--json"])
        .output()
        .expect("supervised deployment");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["phase"], "healthy");
    assert_eq!(guest_stdout(&report["run"]), "RELEASE_ONE_HEALTHY\n");
}

#[test]
#[cfg(target_os = "linux")]
fn effect_free_native_panic_retains_a_terminal_authenticated_observation() {
    let drill = Drill::new();
    let release = drill.install("2.0.0", &crashing_v2());
    let output = drill.cli(&release, &["run", "app.js", "--json"]);
    assert!(!output.status.success());
    let panic: Value = serde_json::from_slice(&output.stdout).expect("native panic report");
    assert_eq!(panic["outcome"], "native_engine_panic", "{panic}");
    assert_eq!(panic["cleanup_successful"], true, "{panic}");
    let inventory = drill.sessions(&release);
    let records = inventory["records"]
        .as_array()
        .expect("retained native sessions");
    assert_eq!(records.len(), 1, "{inventory}");
    assert_eq!(
        records[0]["admission"]["session_nonce"],
        panic["session_nonce"]
    );
    assert_eq!(records[0]["outcome"]["kind"], "panicked");
    assert_eq!(records[0]["outcome"]["process"], "worker_reaped");
    assert_eq!(
        records[0]["outcome"]["effects"]["kind"],
        "no_admitted_host_effects"
    );
    assert_eq!(inventory["terminal_sessions"], 1);
    assert_eq!(inventory["unknown_effect_sessions"], 0);
    assert_eq!(inventory["quiescence_certified"], false);
}

#[test]
fn crash_loop_rolls_back_to_the_healthy_release_and_resumes_it() {
    let drill = Drill::new();
    drill.install("1.0.0", HEALTHY_V1);
    let v2_dir = drill.install("2.0.0", &crashing_v2());
    drill.policy("rollback", "automatic");

    // Readiness: 1.0.0 runs healthy under the deployment first.
    drill.activate("1.0.0");
    let (code, healthy) = drill.run();
    assert_eq!(code, Some(0), "{healthy}");
    assert_eq!(healthy["phase"], "healthy");
    assert_eq!(healthy["observation_authentication"]["verified"], true);
    assert!(guest_stdout(&healthy["run"]).contains("RELEASE_ONE_HEALTHY"));

    // The bad release crash-loops; the third validated panic recovers.
    drill.activate("2.0.0");
    let (code, recovered) = drill.crash_until_loop();
    assert_eq!(recovered["phase"], "resumed_healthy", "{recovered}");
    assert_eq!(code, Some(0), "{recovered}");
    assert_eq!(recovered["observation_authentication"]["verified"], true);
    assert_eq!(
        recovered["observation_authentication"]["observation"]["no_admitted_host_effects"],
        true,
    );
    assert_eq!(
        recovered["resumed"]["observation_authentication"]["verified"],
        true
    );
    let recovery = &recovered["recovery"];
    assert_eq!(recovery["outcome"], "rolled_back", "{recovery}");
    assert_eq!(recovery["failed_release_id"], "2.0.0");
    assert_eq!(recovery["selected_release_id"], "1.0.0");
    assert_eq!(recovery["crash"]["crashes_in_window"], 3);
    assert_eq!(recovery["crash"]["threshold"], 3);
    assert_eq!(recovery["candidate_refusals"], serde_json::json!([]));
    // The retained prior artifact actually runs.
    assert_eq!(recovered["resumed"]["release_id"], "1.0.0");
    assert!(guest_stdout(&recovered["resumed"]["run"]).contains("RELEASE_ONE_HEALTHY"));
    assert!(!recovered.to_string().contains("RELEASE_TWO_NEVER_PRINTS"));

    // Signed state: the pointer moved by recovery; history is retained.
    let status = drill.status();
    assert_eq!(status["active"]["release_id"], "1.0.0", "{status}");
    assert_eq!(status["active"]["reason"], "crash_loop_rollback");
    assert_eq!(status["active"]["recovery_sequence"], 1);
    let chain: Vec<_> = status["activations"]
        .as_array()
        .expect("activations")
        .iter()
        .map(|activation| activation["release_id"].as_str().expect("id").to_string())
        .collect();
    assert_eq!(chain, ["1.0.0", "2.0.0", "1.0.0"]);
    let releases = status["releases"].as_array().expect("releases");
    let failed = releases
        .iter()
        .find(|release| release["release_id"] == "2.0.0")
        .expect("failed release retained");
    assert_eq!(failed["crash_looped"], true);
    let good = releases
        .iter()
        .find(|release| release["release_id"] == "1.0.0")
        .expect("good release");
    assert_eq!(good["healthy_runs"], 2);

    // The failed work stays contained and inspectable: its source and its
    // crash-loop safe mode remain, and a direct run of it is still refused.
    assert!(v2_dir.join("app.js").is_file());
    let safe_mode: Value = serde_json::from_slice(
        &fs::read(v2_dir.join(".franken-node/safe-mode/state.json")).expect("v2 safe mode"),
    )
    .expect("safe mode json");
    assert_eq!(safe_mode["active"], true, "{safe_mode}");
    let direct = drill.cli(&v2_dir, &["run", "app.js", "--json"]);
    assert!(!direct.status.success());
    assert!(
        String::from_utf8_lossy(&direct.stdout).contains("active safe mode"),
        "{}",
        String::from_utf8_lossy(&direct.stdout)
    );

    // The next supervised run is the known-good release, healthy again.
    let (code, next) = drill.run();
    assert_eq!(code, Some(0), "{next}");
    assert_eq!(next["release_id"], "1.0.0");
    assert_eq!(next["phase"], "healthy");
}

#[test]
fn forged_unsigned_crash_counter_cannot_authorize_a_deployment_rollback() {
    let drill = Drill::new();
    drill.install("1.0.0", HEALTHY_V1);
    let failed = drill.install("2.0.0", &crashing_v2());
    drill.policy("rollback", "automatic");
    drill.activate("1.0.0");
    assert_eq!(drill.run().1["phase"], "healthy");
    drill.activate("2.0.0");

    let (code, first) = drill.run();
    assert_ne!(code, Some(0));
    assert_eq!(first["phase"], "crashed", "{first}");
    assert_eq!(first["observation_authentication"]["verified"], true);
    let state_path = failed.join(".franken-node/safe-mode/state.json");
    let mut state: Value = serde_json::from_slice(&fs::read(&state_path).unwrap()).unwrap();
    let crashes = state["native_crashes"]
        .as_array_mut()
        .expect("local crash history");
    assert_eq!(crashes.len(), 1);
    let mut forged = crashes[0].clone();
    forged["session_nonce"] = serde_json::json!(uuid::Uuid::from_u128(12_345).to_string());
    crashes.push(forged);
    fs::write(&state_path, serde_json::to_vec_pretty(&state).unwrap()).unwrap();

    let (code, second) = drill.run();
    assert_ne!(code, Some(0));
    assert_eq!(
        second["run"]["crash_loop"]["crashes_in_window"], 3,
        "{second}"
    );
    assert_eq!(second["run"]["crash_loop"]["safe_mode_active"], true);
    assert_eq!(second["observation_authentication"]["verified"], true);
    assert_eq!(second["phase"], "crashed", "{second}");
    assert!(second.get("recovery").is_none());
    assert!(second.get("resumed").is_none());
    let status = drill.status();
    assert_eq!(status["active"]["release_id"], "2.0.0");
    assert!(status["recoveries"].as_array().unwrap().is_empty());
    assert!(failed.join("app.js").is_file());
}

#[test]
fn authenticated_panic_after_real_host_effect_stays_contained_without_restart() {
    let drill = Drill::new();
    drill.install("1.0.0", HEALTHY_V1);
    let source = format!(
        "require('fs').writeFileSync('before-panic', 'admitted effect');\n// {PANIC_AFTER_HOST_EFFECT_MARKER}\n"
    );
    let directory = drill.root.path().join("releases/2.0.0");
    let (failed, manifest) = drill.publish_release_with_config(
        "2.0.0",
        &source,
        &directory,
        Some("profile = \"legacy-risky\"\n"),
    );
    drill.install_published("2.0.0", &failed, &manifest);
    drill.policy("rollback", "automatic");
    drill.activate("1.0.0");
    assert_eq!(drill.run().1["phase"], "healthy");
    drill.activate("2.0.0");

    let (code, report) = drill.crash_until_loop();
    assert_ne!(code, Some(0));
    assert_eq!(
        report["phase"], "contained_effects_indeterminate",
        "{report}"
    );
    assert_eq!(report["observation_authentication"]["verified"], true);
    assert_eq!(
        report["observation_authentication"]["observation"]["no_admitted_host_effects"],
        false,
    );
    assert_eq!(
        report["recovery"]["outcome"],
        "contained_effects_indeterminate"
    );
    assert!(report["recovery"]["selected_release_id"].is_null());
    assert!(report["recovery"]["activation_sequence"].is_null());
    assert!(report.get("resumed").is_none());
    assert_eq!(
        fs::read_to_string(failed.join("before-panic")).unwrap(),
        "admitted effect"
    );
    assert_eq!(fs::read_to_string(failed.join("app.js")).unwrap(), source);

    let inventory = drill.sessions(&failed);
    assert_eq!(inventory["unknown_effect_sessions"], 3, "{inventory}");
    let records = inventory["records"].as_array().unwrap();
    assert_eq!(records.len(), 3);
    assert!(records.iter().all(|record| {
        record["outcome"]["kind"] == "panicked" && record["outcome"]["effects"]["kind"] == "unknown"
    }));
    let status = drill.status();
    assert_eq!(status["active"]["release_id"], "2.0.0");
    assert_eq!(status["activations"].as_array().unwrap().len(), 2);
    assert_eq!(status["recoveries"].as_array().unwrap().len(), 1);
    let good = status["releases"]
        .as_array()
        .unwrap()
        .iter()
        .find(|release| release["release_id"] == "1.0.0")
        .unwrap();
    assert_eq!(good["healthy_runs"], 1);
}

#[test]
fn operator_restart_policy_switches_the_pointer_but_starts_nothing() {
    let drill = Drill::new();
    drill.install("1.0.0", HEALTHY_V1);
    drill.install("2.0.0", &crashing_v2());
    drill.policy("rollback", "operator");
    drill.activate("1.0.0");
    assert_eq!(drill.run().1["phase"], "healthy");
    drill.activate("2.0.0");
    let (code, report) = drill.crash_until_loop();
    assert_eq!(report["phase"], "rolled_back", "{report}");
    assert_ne!(code, Some(0));
    assert!(report.get("resumed").is_none(), "{report}");
    assert_eq!(drill.status()["active"]["release_id"], "1.0.0");
}

#[test]
fn no_corrupted_or_unproven_release_is_ever_selected() {
    let drill = Drill::new();
    let v1_dir = drill.install("1.0.0", HEALTHY_V1);
    drill.install("2.0.0", &crashing_v2());
    drill.policy("rollback", "automatic");
    drill.activate("1.0.0");
    assert_eq!(drill.run().1["phase"], "healthy");
    // The known-good candidate's bytes change after it was proven healthy.
    fs::write(
        v1_dir.join("app.js"),
        "console.log('SWAPPED_AFTER_ADMISSION');\n",
    )
    .expect("tamper v1");
    drill.activate("2.0.0");
    let (code, report) = drill.crash_until_loop();
    assert_ne!(code, Some(0));
    assert_eq!(report["phase"], "contained_no_known_good", "{report}");
    let refusals = report["recovery"]["candidate_refusals"]
        .as_array()
        .expect("refusals");
    assert_eq!(refusals.len(), 1, "{report}");
    assert_eq!(refusals[0]["release_id"], "1.0.0");
    assert!(
        refusals[0]["reason"]
            .as_str()
            .is_some_and(|reason| reason.contains("source graph changed after admission")),
        "{report}"
    );
    assert!(!report.to_string().contains("SWAPPED_AFTER_ADMISSION"));
    // Nothing switched: the pointer still names the failed release.
    assert_eq!(drill.status()["active"]["release_id"], "2.0.0");
}

#[test]
fn contain_policy_and_missing_readiness_stay_contained() {
    let drill = Drill::new();
    drill.install("1.0.0", HEALTHY_V1);
    drill.install("2.0.0", &crashing_v2());
    // Default policy: contain. 1.0.0 was never activated or proven healthy.
    drill.activate("2.0.0");
    let (code, report) = drill.crash_until_loop();
    assert_ne!(code, Some(0));
    assert_eq!(report["phase"], "contained", "{report}");
    assert_eq!(report["recovery"]["outcome"], "contained");
    assert_eq!(drill.status()["active"]["release_id"], "2.0.0");
}

#[test]
fn tampered_pointer_and_drifted_release_refuse_to_run() {
    let drill = Drill::new();
    let v1_dir = drill.install("1.0.0", HEALTHY_V1);
    drill.activate("1.0.0");
    // A release whose config drifted after admission is not started.
    let config = v1_dir.join("franken_node.toml");
    let original = fs::read_to_string(&config).expect("config");
    fs::write(&config, format!("{original}\n# drift\n")).expect("drift config");
    let (code, report) = drill.run();
    assert_ne!(code, Some(0));
    assert_eq!(report["ok"], false, "{report}");
    assert!(
        report["error"]
            .as_str()
            .is_some_and(|error| error.contains("release config changed after admission")),
        "{report}"
    );
    fs::write(&config, original).expect("restore config");
    assert_eq!(drill.run().1["phase"], "healthy");

    // An edited activation pointer fails its signature: nothing runs.
    let pointer = drill
        .root
        .path()
        .join(".franken-node/state/deployments/app/active.json");
    let edited = fs::read_to_string(&pointer)
        .expect("pointer")
        .replace("\"sequence\": 1", "\"sequence\": 7");
    fs::write(&pointer, edited).expect("edit pointer");
    let (code, report) = drill.run();
    assert_ne!(code, Some(0));
    assert!(
        report["error"]
            .as_str()
            .is_some_and(|error| error.contains("signature")),
        "{report}"
    );
}

#[test]
fn a_revoked_known_good_release_is_refused_before_any_switch() {
    let drill = Drill::new();
    let v1_dir = drill.install("1.0.0", HEALTHY_V1);
    drill.install("2.0.0", &crashing_v2());
    drill.policy("rollback", "automatic");
    drill.activate("1.0.0");
    assert_eq!(drill.run().1["phase"], "healthy");
    // After proving healthy, 1.0.0's exact artifact is revoked in its own
    // authenticated trust registry.
    let status = drill.status();
    let artifact = status["releases"]
        .as_array()
        .expect("releases")
        .iter()
        .find(|release| release["release_id"] == "1.0.0")
        .and_then(|release| release["artifact"]["artifact_sha256"].as_str())
        .expect("artifact digest")
        .to_string();
    drill.ok(
        &v1_dir,
        &["trust", "revoke", "--artifact-sha256", &artifact, "--json"],
    );
    drill.activate("2.0.0");
    let (code, report) = drill.crash_until_loop();
    assert_ne!(code, Some(0));
    assert_eq!(report["phase"], "contained_no_known_good", "{report}");
    let refusals = report["recovery"]["candidate_refusals"]
        .as_array()
        .expect("refusals");
    assert_eq!(refusals.len(), 1, "{report}");
    assert_eq!(refusals[0]["release_id"], "1.0.0");
    let reason = refusals[0]["reason"].as_str().unwrap_or_default();
    assert!(
        reason.contains("trust admission") && reason.contains("revoked"),
        "{report}"
    );
    assert!(report.get("resumed").is_none(), "{report}");
    assert_eq!(drill.status()["active"]["release_id"], "2.0.0");
}

#[test]
fn reconcile_completes_interrupted_activation_without_starting_a_guest() {
    for stage in ["intent", "history"] {
        let drill = Drill::new();
        drill.install("1.0.0", HEALTHY_V1);
        drill.interrupt_activation(stage);

        let intent = drill.state_path("transactions/0000000001.json");
        let signed_intent = fs::read(&intent).expect("durable signed activation intent");
        assert!(!drill.state_path("active.json").exists(), "stage {stage}");
        let pending = drill.status();
        assert!(pending["active"].is_null(), "{pending}");
        assert!(pending["activations"].as_array().unwrap().is_empty());
        assert_eq!(
            pending["pending_activation"]["activation"]["release_id"],
            "1.0.0"
        );
        assert_eq!(pending["pending_activation"]["activation"]["sequence"], 1);
        assert!(pending["pending_activation"]["planned_recovery"].is_null());
        assert!(pending["recoveries"].as_array().unwrap().is_empty());
        assert!(
            !drill.state_path("active.json").exists(),
            "status is read-only"
        );
        assert_eq!(fs::read(&intent).unwrap(), signed_intent);
        let (code, blocked) = drill.run();
        assert_ne!(code, Some(0), "stage {stage}: {blocked}");
        assert_eq!(blocked["ok"], false, "{blocked}");
        assert!(blocked.get("run").is_none(), "{blocked}");

        // A different command cannot silently supersede the interrupted
        // transition. Its original signed authorization remains intact.
        let duplicate = drill.cli(
            drill.root.path(),
            &[
                "deploy",
                "activate",
                "app",
                "--release",
                "1.0.0",
                "--operator-id",
                "ops-other",
                "--json",
            ],
        );
        assert!(!duplicate.status.success(), "stage {stage}");
        assert_eq!(fs::read(&intent).expect("retained intent"), signed_intent);

        let reconciled = drill.reconcile();
        assert_eq!(reconciled["command"], "deploy.reconcile", "{reconciled}");
        assert_eq!(
            reconciled["reconciled"], true,
            "stage {stage}: {reconciled}"
        );
        assert_eq!(reconciled["activation"]["release_id"], "1.0.0");
        assert_eq!(reconciled["activation"]["sequence"], 1);
        assert!(reconciled.get("run").is_none());
        let status = drill.status();
        assert_eq!(status["active"]["release_id"], "1.0.0", "{status}");
        assert_eq!(status["releases"][0]["healthy_runs"], 0, "{status}");
        assert!(status["pending_activation"].is_null());
        assert_eq!(status["activations"].as_array().expect("history").len(), 1);
        assert_eq!(fs::read(&intent).expect("retained intent"), signed_intent);

        let repeated = drill.reconcile();
        assert_eq!(repeated["reconciled"], false, "{repeated}");
        assert!(repeated["activation"].is_null(), "{repeated}");
        assert_eq!(drill.status()["releases"][0]["healthy_runs"], 0);

        // An explicit subsequent run executes the admitted source, proving
        // reconciliation restored a useful deployment rather than a report.
        let (code, healthy) = drill.run();
        assert_eq!(code, Some(0), "stage {stage}: {healthy}");
        assert_eq!(healthy["phase"], "healthy", "{healthy}");
        assert_eq!(guest_stdout(&healthy["run"]), "RELEASE_ONE_HEALTHY\n");
    }
}

#[test]
fn reconcile_completes_interrupted_crash_recovery_without_automatic_restart() {
    for stage in ["intent", "history", "recovery"] {
        let drill = Drill::new();
        drill.install("1.0.0", HEALTHY_V1);
        let failed_dir = drill.install("2.0.0", &crashing_v2());
        drill.policy("rollback", "automatic");
        drill.activate("1.0.0");
        let (code, healthy) = drill.run();
        assert_eq!(code, Some(0), "{healthy}");
        assert_eq!(healthy["phase"], "healthy", "{healthy}");
        drill.activate("2.0.0");
        let previous_pointer = fs::read(drill.state_path("active.json")).expect("v2 pointer");
        drill.prime_crash_loop();
        drill.interrupt(&["deploy", "run", "app", "--json"], stage);

        let intent_path = drill.state_path("transactions/0000000003.json");
        let intent = fs::read(&intent_path).expect("signed rollback intent");
        let pending = drill.status();
        assert_eq!(pending["active"]["release_id"], "2.0.0", "{pending}");
        assert_eq!(pending["activations"].as_array().unwrap().len(), 2);
        assert!(pending["recoveries"].as_array().unwrap().is_empty());
        let planned = &pending["pending_activation"];
        assert_eq!(planned["activation"]["sequence"], 3);
        assert_eq!(planned["activation"]["release_id"], "1.0.0");
        assert_eq!(planned["planned_recovery"]["outcome"], "rolled_back");
        assert_eq!(planned["planned_recovery"]["failed_release_id"], "2.0.0");
        assert_eq!(fs::read(&intent_path).unwrap(), intent);
        assert_eq!(
            fs::read(drill.state_path("active.json")).expect("retained v2 pointer"),
            previous_pointer,
            "pointer must be committed after every signed record: stage {stage}"
        );
        let (code, blocked) = drill.run();
        assert_ne!(code, Some(0), "stage {stage}: {blocked}");
        assert!(blocked.get("run").is_none(), "{blocked}");

        let reconciled = drill.reconcile();
        assert_eq!(
            reconciled["reconciled"], true,
            "stage {stage}: {reconciled}"
        );
        assert_eq!(reconciled["activation"]["release_id"], "1.0.0");
        assert_eq!(reconciled["activation"]["reason"], "crash_loop_rollback");
        assert_eq!(reconciled["activation"]["sequence"], 3);
        assert_eq!(reconciled["activation"]["recovery_sequence"], 1);
        assert!(reconciled.get("run").is_none());
        assert!(reconciled.get("resumed").is_none());
        assert_eq!(
            fs::read(&intent_path).expect("retained rollback intent"),
            intent
        );

        let status = drill.status();
        assert_eq!(status["active"]["release_id"], "1.0.0", "{status}");
        assert!(status["pending_activation"].is_null());
        assert_eq!(
            status["activations"].as_array().expect("activations").len(),
            3
        );
        assert_eq!(
            status["recoveries"].as_array().expect("recoveries").len(),
            1
        );
        assert_eq!(status["recoveries"][0]["outcome"], "rolled_back");
        let good = status["releases"]
            .as_array()
            .expect("releases")
            .iter()
            .find(|release| release["release_id"] == "1.0.0")
            .expect("known-good release");
        assert_eq!(
            good["healthy_runs"], 1,
            "reconcile must not launch: {status}"
        );
        let failed_safe_mode: Value = serde_json::from_slice(
            &fs::read(failed_dir.join(".franken-node/safe-mode/state.json"))
                .expect("retained failed release containment"),
        )
        .expect("safe mode JSON");
        assert_eq!(failed_safe_mode["active"], true);
        assert!(failed_dir.join("app.js").is_file());

        let completed_recovery = fs::read(drill.state_path("recoveries/0000000001.json"))
            .expect("signed recovery outcome");
        assert_eq!(drill.reconcile()["reconciled"], false);
        assert_eq!(
            fs::read(drill.state_path("recoveries/0000000001.json"))
                .expect("unchanged recovery outcome"),
            completed_recovery
        );
        let (code, resumed) = drill.run();
        assert_eq!(code, Some(0), "stage {stage}: {resumed}");
        assert_eq!(resumed["phase"], "healthy", "{resumed}");
        assert_eq!(guest_stdout(&resumed["run"]), "RELEASE_ONE_HEALTHY\n");
    }
}

#[test]
fn reconcile_rechecks_target_source_before_completing_interrupted_activation() {
    let drill = Drill::new();
    let release = drill.install("1.0.0", HEALTHY_V1);
    drill.interrupt_activation("history");
    let intent_path = drill.state_path("transactions/0000000001.json");
    let intent = fs::read(&intent_path).expect("signed activation intent");
    let history_path = drill.state_path("activations/0000000001.json");
    let history = fs::read(&history_path).expect("signed activation record");
    fs::write(
        release.join("app.js"),
        "console.log('UNAPPROVED_REPLACEMENT');\n",
    )
    .expect("substitute source after interruption");

    let refused = drill.failed_reconcile();
    assert!(
        refused["error"]
            .as_str()
            .is_some_and(|error| error.contains("source graph changed after admission")),
        "{refused}"
    );
    assert!(!drill.state_path("active.json").exists());
    assert_eq!(fs::read(&intent_path).expect("retained intent"), intent);
    assert_eq!(fs::read(&history_path).expect("retained history"), history);
    let pending = drill.status();
    assert!(pending["active"].is_null(), "{pending}");
    assert_eq!(
        pending["pending_activation"]["activation"]["release_id"],
        "1.0.0"
    );
    assert!(pending["activations"].as_array().unwrap().is_empty());
    assert!(pending["recoveries"].as_array().unwrap().is_empty());

    // The refusal neither consumes nor rewrites authorization. Restoring
    // the exact approved source permits a fresh independently checked retry.
    fs::write(release.join("app.js"), HEALTHY_V1).expect("restore approved source");
    assert_eq!(drill.reconcile()["reconciled"], true);
    let (code, healthy) = drill.run();
    assert_eq!(code, Some(0), "{healthy}");
    assert_eq!(guest_stdout(&healthy["run"]), "RELEASE_ONE_HEALTHY\n");
}

#[test]
fn reconcile_refuses_a_target_revoked_after_the_signed_intent() {
    let drill = Drill::new();
    let release = drill.install("1.0.0", HEALTHY_V1);
    let artifact = drill.artifact_digest("1.0.0");
    drill.interrupt_activation("history");
    let intent_path = drill.state_path("transactions/0000000001.json");
    let intent = fs::read(&intent_path).expect("signed activation intent");
    drill.ok(
        &release,
        &["trust", "revoke", "--artifact-sha256", &artifact, "--json"],
    );

    let refused = drill.failed_reconcile();
    let reason = refused["error"].as_str().expect("refusal reason");
    assert!(
        reason.contains("trust admission") && reason.contains("revoked"),
        "{refused}"
    );
    assert!(!drill.state_path("active.json").exists());
    assert_eq!(fs::read(&intent_path).expect("retained intent"), intent);
    let (code, blocked) = drill.run();
    assert_ne!(code, Some(0), "{blocked}");
    assert!(blocked.get("run").is_none(), "{blocked}");
}

#[test]
fn reconcile_refuses_forged_or_missing_authorization_without_guessing() {
    let drill = Drill::new();
    drill.install("1.0.0", HEALTHY_V1);
    drill.interrupt_activation("history");
    let intent_path = drill.state_path("transactions/0000000001.json");
    let original = fs::read(&intent_path).expect("signed activation intent");
    let mut forged: Value = serde_json::from_slice(&original).expect("intent JSON");
    forged["signature_hex"] = Value::String("0".repeat(128));
    fs::write(
        &intent_path,
        serde_json::to_vec_pretty(&forged).expect("forged JSON"),
    )
    .expect("replace signature");
    let refused = drill.failed_reconcile();
    assert!(
        refused["error"]
            .as_str()
            .is_some_and(|error| error.contains("signature")),
        "{refused}"
    );
    assert!(!drill.state_path("active.json").exists());

    fs::write(&intent_path, &original).expect("restore authentic intent");
    let retained = drill.root.path().join("retained-activation-intent.json");
    fs::rename(&intent_path, &retained).expect("preserve intent outside transaction history");
    let missing = drill.failed_reconcile();
    assert!(
        missing["error"]
            .as_str()
            .is_some_and(|error| !error.is_empty())
    );
    assert!(!drill.state_path("active.json").exists());
    fs::rename(&retained, &intent_path).expect("restore retained authorization");
    assert_eq!(drill.reconcile()["reconciled"], true);
    assert_eq!(fs::read(&intent_path).expect("retained intent"), original);
}

#[test]
fn deployment_root_safe_mode_blocks_a_release_outside_that_directory() {
    let drill = Drill::new();
    let external = tempfile::tempdir().expect("external release directory");
    let (release, manifest) = drill.publish_release_at("1.0.0", HEALTHY_V1, external.path());
    assert!(!release.starts_with(drill.root.path()));
    drill.install_published("1.0.0", &release, &manifest);
    drill.activate("1.0.0");
    let (code, healthy) = drill.run();
    assert_eq!(code, Some(0), "{healthy}");
    assert_eq!(guest_stdout(&healthy["run"]), "RELEASE_ONE_HEALTHY\n");
    drill.ok(
        drill.root.path(),
        &[
            "safe-mode",
            "enter",
            "--reason",
            "explicit-flag",
            "--operator-id",
            "ops-1",
            "--trust-state-hash",
            "operator:test-state",
            "--json",
        ],
    );

    let (code, blocked) = drill.run();
    assert_ne!(code, Some(0), "{blocked}");
    assert_eq!(blocked["ok"], false, "{blocked}");
    assert!(
        blocked["error"]
            .as_str()
            .is_some_and(|error| error.contains("safe mode")),
        "{blocked}"
    );
    assert!(blocked.get("run").is_none(), "{blocked}");
    assert_eq!(drill.status()["releases"][0]["healthy_runs"], 1);
}

#[test]
#[cfg(target_os = "linux")]
fn deployment_operator_and_release_fleet_holds_each_fence_their_own_admission_scope() {
    let drill = Drill::new();
    let external = tempfile::tempdir().expect("external release directory");
    let (release, manifest) = drill.publish_release_at("1.0.0", HEALTHY_V1, external.path());
    assert!(!release.starts_with(drill.root.path()));
    drill.install_published("1.0.0", &release, &manifest);
    drill.activate("1.0.0");
    let (code, healthy) = drill.run();
    assert_eq!(code, Some(0), "{healthy}");
    assert_eq!(guest_stdout(&healthy["run"]), "RELEASE_ONE_HEALTHY\n");

    let operator_sessions = drill.sessions(drill.root.path());
    let release_sessions = drill.sessions(&release);
    assert_eq!(operator_sessions["records"].as_array().unwrap().len(), 1);
    assert_eq!(operator_sessions["records"], release_sessions["records"]);
    let admission = &operator_sessions["records"][0]["admission"];
    assert_eq!(
        admission["project_root"],
        release.canonicalize().unwrap().to_str().unwrap()
    );
    assert!(
        admission["control_scopes"]
            .as_array()
            .unwrap()
            .iter()
            .any(|scope| scope["project_root"]
                == drill.root.path().canonicalize().unwrap().to_str().unwrap()),
        "the signed admission must retain the operator root without replacing the release identity: {admission}"
    );
    assert_eq!(operator_sessions["quiescence_certified"], false);
    let operator_fleet = drill.state_home.path().join("operator-fleet");
    let release_fleet = drill.state_home.path().join("release-fleet");
    let hold = |project: &Path, fleet: &Path, id: &str| {
        drill.fleet_ok(
            project,
            fleet,
            &[
                "fleet",
                "hold",
                "--zone",
                "east",
                "--id",
                id,
                "--reason",
                "independent deployment maintenance owner",
                "--json",
            ],
        )
    };
    hold(drill.root.path(), &operator_fleet, "operator-owner");
    let held = drill.fleet_poll(drill.root.path(), &operator_fleet, "operator-node");
    assert_eq!(held["node_health"], "maintenance", "{held}");
    assert_eq!(held["native_session_drain"]["admitted_sessions"], 1);
    assert_eq!(held["native_session_drain"]["terminal_sessions"], 1);
    assert_eq!(held["native_session_drain"]["fence_held"], true);
    let (code, refused) = drill.run();
    assert_ne!(code, Some(0), "{refused}");
    assert!(
        refused
            .to_string()
            .contains("native-session admission is fenced"),
        "{refused}"
    );
    assert_eq!(drill.status()["releases"][0]["healthy_runs"], 1);

    // The operator alias belongs to this supervised invocation. It must not
    // silently attach itself to an independently admitted standalone run.
    let standalone = drill.ok(
        &release,
        &[
            "run",
            "app.js",
            "--runtime",
            "franken-engine",
            "--frozen-modules",
            "--registry-artifact",
            manifest.to_str().unwrap(),
            "--publisher-public-key",
            drill.public_key.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(guest_stdout(&standalone), "RELEASE_ONE_HEALTHY\n");
    assert_eq!(
        drill.sessions(drill.root.path())["records"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert_eq!(
        drill.sessions(&release)["records"]
            .as_array()
            .unwrap()
            .len(),
        2
    );

    hold(&release, &release_fleet, "release-owner");
    let held = drill.fleet_poll(&release, &release_fleet, "release-node");
    assert_eq!(held["native_session_drain"]["admitted_sessions"], 2);
    assert_eq!(held["native_session_drain"]["fence_held"], true);
    drill.fleet_ok(
        drill.root.path(),
        &operator_fleet,
        &["fleet", "resume", "--hold", "operator-owner", "--json"],
    );
    let resumed = drill.fleet_poll(drill.root.path(), &operator_fleet, "operator-node");
    assert_eq!(resumed["node_health"], "healthy", "{resumed}");
    assert_eq!(resumed["native_session_drain"]["fence_held"], false);
    let (code, still_refused) = drill.run();
    assert_ne!(code, Some(0), "{still_refused}");
    assert!(
        still_refused
            .to_string()
            .contains("native-session admission is fenced"),
        "{still_refused}"
    );
    assert_eq!(drill.status()["releases"][0]["healthy_runs"], 1);

    drill.fleet_ok(
        &release,
        &release_fleet,
        &["fleet", "resume", "--hold", "release-owner", "--json"],
    );
    let resumed = drill.fleet_poll(&release, &release_fleet, "release-node");
    assert_eq!(resumed["node_health"], "healthy", "{resumed}");
    assert_eq!(resumed["native_session_drain"]["fence_held"], false);
    let (code, resumed) = drill.run();
    assert_eq!(code, Some(0), "{resumed}");
    assert_eq!(guest_stdout(&resumed["run"]), "RELEASE_ONE_HEALTHY\n");
    assert_eq!(drill.status()["releases"][0]["healthy_runs"], 2);
    assert_eq!(
        drill.sessions(drill.root.path())["records"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(
        drill.sessions(&release)["records"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
}

#[test]
#[cfg(target_os = "linux")]
fn deployment_operator_fleet_policy_rejects_a_weaker_external_release_profile() {
    let drill = Drill::new();
    let external = tempfile::tempdir().expect("external release directory");
    let (release, manifest) = drill.publish_release_with_config(
        "1.0.0",
        HEALTHY_V1,
        external.path(),
        Some("profile = \"legacy-risky\"\n"),
    );
    drill.install_published("1.0.0", &release, &manifest);
    drill.activate("1.0.0");
    let (code, baseline) = drill.run();
    assert_eq!(code, Some(0), "{baseline}");
    let operator_fleet = drill.state_home.path().join("operator-fleet");
    drill.publish_fleet_policy(
        drill.root.path(),
        &operator_fleet,
        "operator-profile-policy",
        &serde_json::json!({"minimum_profile": "balanced"}),
    );
    let applied = drill.fleet_poll(drill.root.path(), &operator_fleet, "operator-node");
    assert_eq!(applied["node_health"], "healthy", "{applied}");

    let (code, refused) = drill.run();
    assert_ne!(code, Some(0), "{refused}");
    assert!(
        refused
            .to_string()
            .contains("activated fleet policy requires profile `balanced`"),
        "{refused}"
    );
    assert_eq!(drill.status()["releases"][0]["healthy_runs"], 1);
    let standalone = drill.ok(
        &release,
        &[
            "run",
            "app.js",
            "--runtime",
            "franken-engine",
            "--frozen-modules",
            "--registry-artifact",
            manifest.to_str().unwrap(),
            "--publisher-public-key",
            drill.public_key.to_str().unwrap(),
            "--json",
        ],
    );
    assert_eq!(guest_stdout(&standalone), "RELEASE_ONE_HEALTHY\n");
}

#[test]
#[cfg(target_os = "linux")]
fn deployment_intersects_operator_and_release_fleet_budgets_in_worker_and_receipt() {
    let drill = Drill::new();
    let external = tempfile::tempdir().expect("external release directory");
    let (release, manifest) = drill.publish_release_at("1.0.0", HEALTHY_V1, external.path());
    drill.install_published("1.0.0", &release, &manifest);
    drill.activate("1.0.0");
    for (project, name, policy) in [
        (
            drill.root.path(),
            "operator",
            serde_json::json!({
                "max_instructions": 100_000,
                "max_parse_source_bytes": 4096,
                "max_parse_tokens": 128,
            }),
        ),
        (
            release.as_path(),
            "release",
            serde_json::json!({
                "max_instructions": 400_000,
                "max_parse_source_bytes": 2048,
                "max_parse_tokens": 256,
            }),
        ),
    ] {
        let fleet_state = drill.state_home.path().join(format!("{name}-fleet"));
        drill.publish_fleet_policy(project, &fleet_state, name, &policy);
        let applied = drill.fleet_poll(project, &fleet_state, name);
        assert_eq!(applied["node_health"], "healthy", "{applied}");
    }
    let (code, completed) = drill.run();
    assert_eq!(code, Some(0), "{completed}");
    let run = &completed["run"];
    assert_eq!(guest_stdout(run), "RELEASE_ONE_HEALTHY\n");
    let decision = &run["dispatch"]["engine_decision"];
    for lane in ["deterministic", "throughput"] {
        assert_eq!(
            decision["execution_limits"][lane]["max_instructions"], 100_000,
            "operator instruction ceiling: {decision}"
        );
    }
    assert_eq!(decision["parser_budget"]["max_source_bytes"], 2048);
    assert_eq!(decision["parser_budget"]["max_token_count"], 128);
    assert_eq!(run["receipt"]["parser_budget"], decision["parser_budget"]);
    assert_eq!(
        run["receipt"]["execution_limits"],
        decision["execution_limits"]
    );

    let standalone = drill.ok(
        &release,
        &[
            "run",
            "app.js",
            "--runtime",
            "franken-engine",
            "--frozen-modules",
            "--registry-artifact",
            manifest.to_str().unwrap(),
            "--publisher-public-key",
            drill.public_key.to_str().unwrap(),
            "--json",
        ],
    );
    let decision = &standalone["dispatch"]["engine_decision"];
    for lane in ["deterministic", "throughput"] {
        assert_eq!(
            decision["execution_limits"][lane]["max_instructions"],
            400_000
        );
    }
    assert_eq!(decision["parser_budget"]["max_source_bytes"], 2048);
    assert_eq!(decision["parser_budget"]["max_token_count"], 256);
}

#[test]
#[cfg(target_os = "linux")]
fn nested_deployment_retains_both_fleet_policies_and_refuses_unretained_ancestors() {
    let drill = Drill::new();
    let (release, manifest) = drill.publish_release("1.0.0", HEALTHY_V1);
    assert!(release.starts_with(drill.root.path()));
    drill.install_published("1.0.0", &release, &manifest);
    drill.activate("1.0.0");
    let admitted = drill.admitted_release("1.0.0");
    for (project, name, policy) in [
        (
            drill.root.path(),
            "operator",
            serde_json::json!({
                "max_instructions": 100_000,
                "max_parse_source_bytes": 4096,
                "max_parse_tokens": 128,
            }),
        ),
        (
            release.as_path(),
            "release",
            serde_json::json!({
                "max_instructions": 400_000,
                "max_parse_source_bytes": 2048,
                "max_parse_tokens": 256,
            }),
        ),
    ] {
        let fleet_state = drill.state_home.path().join(format!("{name}-fleet"));
        drill.publish_fleet_policy(project, &fleet_state, name, &policy);
        let applied = drill.fleet_poll(project, &fleet_state, name);
        assert_eq!(applied["node_health"], "healthy", "{applied}");
    }

    let (code, completed) = drill.run();
    assert_eq!(code, Some(0), "{completed}");
    let run = &completed["run"];
    assert_eq!(guest_stdout(run), "RELEASE_ONE_HEALTHY\n");
    let decision = &run["dispatch"]["engine_decision"];
    assert_eq!(
        decision["frozen_modules"]["graph_input_hash"],
        admitted.approval.graph_input_hash()
    );
    assert_eq!(
        decision["frozen_modules"]["publisher_artifact"],
        serde_json::to_value(admitted.approval.identity()).unwrap()
    );
    for lane in ["deterministic", "throughput"] {
        assert_eq!(
            decision["execution_limits"][lane]["max_instructions"],
            100_000
        );
    }
    assert_eq!(decision["parser_budget"]["max_source_bytes"], 2048);
    assert_eq!(decision["parser_budget"]["max_token_count"], 128);
    assert_eq!(run["receipt"]["parser_budget"], decision["parser_budget"]);
    assert_eq!(
        run["receipt"]["execution_limits"],
        decision["execution_limits"]
    );

    let operator_sessions = drill.sessions(drill.root.path());
    assert_eq!(operator_sessions["records"].as_array().unwrap().len(), 1);
    assert_eq!(
        operator_sessions["records"],
        drill.sessions(&release)["records"]
    );
    let admission = &operator_sessions["records"][0]["admission"];
    assert_eq!(
        admission["project_root"],
        release.canonicalize().unwrap().to_str().unwrap()
    );
    assert_eq!(
        admission["entrypoint"],
        release
            .join("app.js")
            .canonicalize()
            .unwrap()
            .to_str()
            .unwrap()
    );
    let scopes = admission["control_scopes"].as_array().unwrap();
    assert_eq!(scopes.len(), 1);
    assert_eq!(
        scopes[0]["project_root"],
        drill.root.path().canonicalize().unwrap().to_str().unwrap()
    );

    // An ordinary nested invocation has no retained operator owner. It must
    // still refuse to choose a narrower source root beneath fleet enrollment.
    let standalone = drill.cli(
        &release,
        &[
            "run",
            "app.js",
            "--runtime",
            "franken-engine",
            "--frozen-modules",
            "--registry-artifact",
            manifest.to_str().unwrap(),
            "--publisher-public-key",
            drill.public_key.to_str().unwrap(),
            "--json",
        ],
    );
    assert!(!standalone.status.success());
    let refused: Value = serde_json::from_slice(&standalone.stdout).expect("nested refusal JSON");
    assert!(
        refused.to_string().contains("inside fleet-managed project"),
        "{refused}"
    );

    // Retaining the exact operator is not permission to ignore a different
    // enrolled project between that operator and the signed release.
    let intermediate = release.parent().expect("intermediate releases directory");
    assert_ne!(intermediate, drill.root.path());
    let intermediate_fleet = drill.state_home.path().join("intermediate-fleet");
    drill.publish_fleet_policy(
        intermediate,
        &intermediate_fleet,
        "intermediate-policy",
        &serde_json::json!({"max_instructions": 50_000}),
    );
    let applied = drill.fleet_poll(intermediate, &intermediate_fleet, "intermediate-node");
    assert_eq!(applied["node_health"], "healthy", "{applied}");
    let (code, refused) = drill.run();
    assert_ne!(code, Some(0), "{refused}");
    assert!(
        refused.to_string().contains("inside fleet-managed project"),
        "{refused}"
    );
    assert!(
        refused.to_string().contains(intermediate.to_str().unwrap()),
        "the refusal must identify the unretained ancestor: {refused}"
    );
    assert_eq!(drill.status()["releases"][0]["healthy_runs"], 1);
    assert_eq!(
        drill.sessions(drill.root.path())["records"],
        operator_sessions["records"],
        "both refusals must happen before admitting another native worker"
    );
}

#[test]
fn supersede_replaces_a_revoked_pending_target_without_rewriting_its_evidence() {
    for stage in ["intent", "history"] {
        let drill = Drill::new();
        let rejected = drill.install("1.0.0", HEALTHY_V1);
        drill.install("2.0.0", "console.log('REPLACEMENT_HEALTHY');\n");
        let rejected_artifact = drill.artifact_digest("1.0.0");
        drill.interrupt_activation(stage);
        let intent_path = drill.state_path("transactions/0000000001.json");
        let original_intent = fs::read(&intent_path).expect("retained original intent");
        let original_history = fs::read(drill.state_path("activations/0000000001.json")).ok();
        let pending = drill.status();
        let digest = pending["pending_activation"]["transaction_digest"]
            .as_str()
            .expect("authenticated pending digest")
            .to_string();
        drill.ok(
            &rejected,
            &[
                "trust",
                "revoke",
                "--artifact-sha256",
                &rejected_artifact,
                "--json",
            ],
        );
        let refused = drill.failed_reconcile();
        assert!(
            refused["error"]
                .as_str()
                .is_some_and(|error| error.contains("revoked")),
            "{refused}"
        );
        let wrong_digest = format!("sha256:{}", "0".repeat(64));
        drill.failed_supersede("2.0.0", &wrong_digest);
        assert!(!drill.state_path("transactions/0000000002.json").exists());
        assert_eq!(
            fs::read(&intent_path).expect("unchanged intent"),
            original_intent
        );

        let replaced = drill.supersede("2.0.0", &digest);
        assert_eq!(replaced["command"], "deploy.supersede", "{replaced}");
        assert_eq!(replaced["workload_started"], false, "{replaced}");
        assert_eq!(replaced["already_committed"], false, "{replaced}");
        assert_eq!(replaced["superseded_transaction_digest"], digest);
        assert_eq!(replaced["activation"]["release_id"], "2.0.0");
        assert_eq!(replaced["activation"]["sequence"], 2);
        assert!(replaced.get("run").is_none());
        let status = drill.status();
        assert_eq!(status["active"]["release_id"], "2.0.0", "{status}");
        assert!(status["pending_activation"].is_null());
        assert_eq!(
            status["activations"]
                .as_array()
                .expect("committed history")
                .len(),
            1
        );
        assert_eq!(status["activations"][0]["sequence"], 2);
        assert!(
            status["recoveries"]
                .as_array()
                .expect("recoveries")
                .is_empty()
        );
        let superseded = status["superseded_activations"]
            .as_array()
            .expect("superseded attempts");
        assert_eq!(superseded.len(), 1, "{status}");
        assert_eq!(superseded[0]["activation"]["release_id"], "1.0.0");
        assert_eq!(superseded[0]["transaction_digest"], digest);
        assert_eq!(superseded[0]["superseded_by_sequence"], 2);
        assert!(superseded[0]["planned_recovery"].is_null());
        assert!(
            status["releases"]
                .as_array()
                .unwrap()
                .iter()
                .all(|release| release["healthy_runs"] == 0)
        );
        assert_eq!(
            fs::read(&intent_path).expect("retained original intent"),
            original_intent
        );
        if let Some(history) = original_history {
            assert_eq!(
                fs::read(drill.state_path("activations/0000000001.json")).unwrap(),
                history
            );
        }

        // An exact retry observes the already committed replacement. A later
        // operator activation makes that original compare-and-swap stale.
        let pointer = fs::read(drill.state_path("active.json")).expect("replacement pointer");
        let repeated = drill.supersede("2.0.0", &digest);
        assert_eq!(repeated["already_committed"], true, "{repeated}");
        assert_eq!(fs::read(drill.state_path("active.json")).unwrap(), pointer);
        assert!(!drill.state_path("transactions/0000000003.json").exists());
        let (code, healthy) = drill.run();
        assert_eq!(code, Some(0), "stage {stage}: {healthy}");
        assert_eq!(guest_stdout(&healthy["run"]), "REPLACEMENT_HEALTHY\n");
        drill.activate("2.0.0");
        let advanced_pointer =
            fs::read(drill.state_path("active.json")).expect("new operator choice");
        drill.failed_supersede("2.0.0", &digest);
        assert_eq!(
            fs::read(drill.state_path("active.json")).unwrap(),
            advanced_pointer
        );
        assert!(!drill.state_path("transactions/0000000004.json").exists());

        // The signed supersession authority must remain available even after
        // an ordinary activation advances the pointer beyond the replacement.
        let authority_path = drill.state_path("transactions/0000000002.json");
        let retained_authority = drill
            .root
            .path()
            .join("retained-supersession-authority.json");
        fs::rename(&authority_path, &retained_authority).expect("retain authority outside journal");
        let unavailable = drill.cli(drill.root.path(), &["deploy", "status", "app", "--json"]);
        assert!(
            !unavailable.status.success(),
            "missing supersession must not turn canceled attempts into committed history"
        );
        let (code, blocked) = drill.run();
        assert_ne!(code, Some(0), "{blocked}");
        assert!(blocked.get("run").is_none(), "{blocked}");
        assert_eq!(
            fs::read(drill.state_path("active.json")).unwrap(),
            advanced_pointer
        );
        fs::rename(&retained_authority, &authority_path).expect("restore authentic supersession");
        assert_eq!(drill.status()["active"]["sequence"], 3);
    }
}

#[test]
fn supersede_rechecks_replacement_source_and_revocation_before_writing_authority() {
    let drill = Drill::new();
    drill.install("1.0.0", HEALTHY_V1);
    let candidate_source = "console.log('CANDIDATE_TWO');\n";
    let candidate = drill.install("2.0.0", candidate_source);
    drill.install("3.0.0", "console.log('ADMITTED_REPLACEMENT');\n");
    let candidate_artifact = drill.artifact_digest("2.0.0");
    drill.interrupt_activation("history");
    let intent_path = drill.state_path("transactions/0000000001.json");
    let history_path = drill.state_path("activations/0000000001.json");
    let original_intent = fs::read(&intent_path).expect("original intent");
    let original_history = fs::read(&history_path).expect("original history");
    let digest = drill.status()["pending_activation"]["transaction_digest"]
        .as_str()
        .expect("pending digest")
        .to_string();
    fs::write(
        candidate.join("app.js"),
        "console.log('UNAPPROVED_SOURCE');\n",
    )
    .expect("substitute candidate source");
    let source_refusal = drill.failed_supersede("2.0.0", &digest);
    assert!(
        source_refusal["error"]
            .as_str()
            .is_some_and(|error| error.contains("source graph changed after admission")),
        "{source_refusal}"
    );
    assert!(!drill.state_path("transactions/0000000002.json").exists());
    assert!(!drill.state_path("active.json").exists());

    fs::write(candidate.join("app.js"), candidate_source).expect("restore admitted source");
    drill.ok(
        &candidate,
        &[
            "trust",
            "revoke",
            "--artifact-sha256",
            &candidate_artifact,
            "--json",
        ],
    );
    let trust_refusal = drill.failed_supersede("2.0.0", &digest);
    assert!(
        trust_refusal["error"]
            .as_str()
            .is_some_and(|error| error.contains("revoked")),
        "{trust_refusal}"
    );
    assert!(!drill.state_path("transactions/0000000002.json").exists());
    assert!(!drill.state_path("active.json").exists());
    assert_eq!(fs::read(&intent_path).unwrap(), original_intent);
    assert_eq!(fs::read(&history_path).unwrap(), original_history);
    assert_eq!(
        drill.status()["pending_activation"]["transaction_digest"],
        digest
    );

    let replaced = drill.supersede("3.0.0", &digest);
    assert_eq!(replaced["activation"]["release_id"], "3.0.0");
    assert_eq!(replaced["activation"]["sequence"], 2);
    let (code, healthy) = drill.run();
    assert_eq!(code, Some(0), "{healthy}");
    assert_eq!(guest_stdout(&healthy["run"]), "ADMITTED_REPLACEMENT\n");
}

#[test]
fn interrupted_repeated_supersessions_never_reauthorize_abandoned_targets() {
    for second_stage in ["superseded_history", "history"] {
        let drill = Drill::new();
        let original = drill.install("1.0.0", HEALTHY_V1);
        let intermediate = drill.install("2.0.0", "console.log('INTERMEDIATE_NEVER_RUNS');\n");
        drill.install("3.0.0", "console.log('FINAL_REPLACEMENT');\n");
        let original_artifact = drill.artifact_digest("1.0.0");
        let intermediate_artifact = drill.artifact_digest("2.0.0");
        drill.interrupt_activation("intent");
        let original_intent =
            fs::read(drill.state_path("transactions/0000000001.json")).expect("original intent");
        let first_digest = drill.status()["pending_activation"]["transaction_digest"]
            .as_str()
            .expect("original digest")
            .to_string();
        drill.ok(
            &original,
            &[
                "trust",
                "revoke",
                "--artifact-sha256",
                &original_artifact,
                "--json",
            ],
        );
        drill.interrupt(&supersede_args("2.0.0", &first_digest), "intent");
        assert!(!drill.state_path("active.json").exists());
        assert!(!drill.state_path("activations/0000000001.json").exists());
        let intermediate_intent = fs::read(drill.state_path("transactions/0000000002.json"))
            .expect("successor intent durable before canceled history");
        let pending = drill.status();
        assert_eq!(
            pending["pending_activation"]["activation"]["release_id"], "2.0.0",
            "{pending}"
        );
        assert_eq!(
            pending["superseded_activations"].as_array().unwrap().len(),
            1
        );
        assert!(pending["activations"].as_array().unwrap().is_empty());
        let second_digest = pending["pending_activation"]["transaction_digest"]
            .as_str()
            .expect("latest pending digest")
            .to_string();
        drill.failed_supersede("3.0.0", &first_digest);
        assert!(!drill.state_path("transactions/0000000003.json").exists());
        drill.ok(
            &intermediate,
            &[
                "trust",
                "revoke",
                "--artifact-sha256",
                &intermediate_artifact,
                "--json",
            ],
        );
        let refused = drill.failed_reconcile();
        assert!(
            refused["error"]
                .as_str()
                .is_some_and(|error| error.contains("revoked")),
            "{refused}"
        );
        drill.interrupt(&supersede_args("3.0.0", &second_digest), second_stage);

        // A fresh process reads a partially materialized supersession chain.
        // Neither abandoned release ever becomes an execution authority.
        let pending = drill.status();
        assert!(pending["active"].is_null(), "{pending}");
        assert!(pending["activations"].as_array().unwrap().is_empty());
        assert_eq!(pending["pending_activation"]["activation"]["sequence"], 3);
        assert_eq!(
            pending["pending_activation"]["activation"]["release_id"],
            "3.0.0"
        );
        assert_eq!(
            pending["superseded_activations"].as_array().unwrap().len(),
            2
        );
        assert_eq!(
            pending["superseded_activations"][0]["superseded_by_sequence"],
            2
        );
        assert_eq!(
            pending["superseded_activations"][1]["superseded_by_sequence"],
            3
        );
        let (code, blocked) = drill.run();
        assert_ne!(code, Some(0), "{blocked}");
        assert!(blocked.get("run").is_none(), "{blocked}");
        assert!(!drill.state_path("active.json").exists());
        assert_eq!(
            fs::read(drill.state_path("transactions/0000000001.json")).unwrap(),
            original_intent
        );
        assert_eq!(
            fs::read(drill.state_path("transactions/0000000002.json")).unwrap(),
            intermediate_intent
        );

        let reconciled = drill.reconcile();
        assert_eq!(
            reconciled["activation"]["release_id"], "3.0.0",
            "{reconciled}"
        );
        assert_eq!(reconciled["workload_started"], false);
        let status = drill.status();
        assert_eq!(status["activations"].as_array().unwrap().len(), 1);
        assert_eq!(status["activations"][0]["sequence"], 3);
        assert!(status["pending_activation"].is_null());
        assert_eq!(
            status["superseded_activations"].as_array().unwrap().len(),
            2
        );
        let (code, healthy) = drill.run();
        assert_eq!(code, Some(0), "stage {second_stage}: {healthy}");
        assert_eq!(guest_stdout(&healthy["run"]), "FINAL_REPLACEMENT\n");
    }
}

#[test]
fn supersede_archives_interrupted_rollback_without_claiming_a_committed_recovery() {
    for original_stage in ["intent", "history", "recovery"] {
        let drill = Drill::new();
        let rejected = drill.install("1.0.0", HEALTHY_V1);
        let failed = drill.install("2.0.0", &crashing_v2());
        drill.install("3.0.0", "console.log('OPERATOR_RECOVERY');\n");
        let rejected_artifact = drill.artifact_digest("1.0.0");
        drill.policy("rollback", "automatic");
        drill.activate("1.0.0");
        let (code, healthy) = drill.run();
        assert_eq!(code, Some(0), "{healthy}");
        drill.activate("2.0.0");
        drill.prime_crash_loop();
        drill.interrupt(&["deploy", "run", "app", "--json"], original_stage);
        let pointer = fs::read(drill.state_path("active.json")).expect("failed release pointer");
        let intent =
            fs::read(drill.state_path("transactions/0000000003.json")).expect("rollback intent");
        let history = fs::read(drill.state_path("activations/0000000003.json")).ok();
        let recovery = fs::read(drill.state_path("recoveries/0000000001.json")).ok();
        let failed_health =
            fs::read(drill.state_path("health/2.0.0.json")).expect("retained crash evidence");
        let failed_safe_mode = fs::read(failed.join(".franken-node/safe-mode/state.json"))
            .expect("failed release containment");
        let pending = drill.status();
        let digest = pending["pending_activation"]["transaction_digest"]
            .as_str()
            .expect("pending rollback digest")
            .to_string();
        let planned_recovery = pending["pending_activation"]["planned_recovery"].clone();
        drill.policy("contain", "operator");
        drill.ok(
            &rejected,
            &[
                "trust",
                "revoke",
                "--artifact-sha256",
                &rejected_artifact,
                "--json",
            ],
        );
        let refused = drill.failed_reconcile();
        assert!(
            refused["error"]
                .as_str()
                .is_some_and(|error| error.contains("policy changed")),
            "{refused}"
        );

        drill.interrupt(&supersede_args("3.0.0", &digest), "superseded_recovery");
        let interrupted = drill.status();
        assert_eq!(
            interrupted["active"]["release_id"], "2.0.0",
            "{interrupted}"
        );
        assert_eq!(
            interrupted["pending_activation"]["activation"]["release_id"],
            "3.0.0"
        );
        assert_eq!(
            interrupted["pending_activation"]["activation"]["sequence"],
            4
        );
        assert!(interrupted["recoveries"].as_array().unwrap().is_empty());
        assert_eq!(
            interrupted["superseded_activations"][0]["planned_recovery"],
            planned_recovery
        );
        assert_eq!(fs::read(drill.state_path("active.json")).unwrap(), pointer);
        assert_eq!(
            fs::read(drill.state_path("transactions/0000000003.json")).unwrap(),
            intent
        );
        if let Some(history) = history {
            assert_eq!(
                fs::read(drill.state_path("activations/0000000003.json")).unwrap(),
                history
            );
        }
        if let Some(recovery) = recovery {
            assert_eq!(
                fs::read(drill.state_path("recoveries/0000000001.json")).unwrap(),
                recovery
            );
        }
        let archived_recovery = fs::read(drill.state_path("recoveries/0000000001.json"))
            .expect("archived recovery reservation");

        // Retrying the exact operator request resumes its own signed intent;
        // the superseded rollback's changed policy is never reinstated.
        let replaced = drill.supersede("3.0.0", &digest);
        assert_eq!(replaced["workload_started"], false, "{replaced}");
        assert_eq!(replaced["activation"]["reason"], "operator");
        assert!(replaced["activation"]["recovery_sequence"].is_null());
        let status = drill.status();
        assert_eq!(status["active"]["release_id"], "3.0.0", "{status}");
        assert_eq!(status["activations"].as_array().unwrap().len(), 3);
        assert_eq!(status["activations"][2]["sequence"], 4);
        assert!(status["recoveries"].as_array().unwrap().is_empty());
        assert_eq!(
            status["superseded_activations"][0]["planned_recovery"],
            planned_recovery
        );
        assert_eq!(
            fs::read(drill.state_path("recoveries/0000000001.json")).unwrap(),
            archived_recovery
        );
        assert_eq!(
            fs::read(drill.state_path("health/2.0.0.json")).unwrap(),
            failed_health
        );
        assert_eq!(
            fs::read(failed.join(".franken-node/safe-mode/state.json")).unwrap(),
            failed_safe_mode
        );
        let replacement = status["releases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|release| release["release_id"] == "3.0.0")
            .expect("replacement");
        assert_eq!(
            replacement["healthy_runs"], 0,
            "supersede must not restart: {status}"
        );
        let (code, resumed) = drill.run();
        assert_eq!(code, Some(0), "stage {original_stage}: {resumed}");
        assert_eq!(guest_stdout(&resumed["run"]), "OPERATOR_RECOVERY\n");
    }
}

#[cfg(target_os = "linux")]
mod external_release_live_control {
    use super::*;
    use std::collections::BTreeMap;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::process::{Child, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    fn process_start_time(pid: u32) -> Option<String> {
        fs::read_to_string(format!("/proc/{pid}/stat"))
            .ok()?
            .rsplit_once(") ")?
            .1
            .split_whitespace()
            .nth(19)
            .map(str::to_string)
    }

    /// Retain the identities of this test's deployment child and native worker.
    /// The successful path proves they have exited before this guard drops;
    /// a failed assertion cannot leave the blocked native workload behind.
    struct DeploymentProcess {
        child: Child,
        descendants: BTreeMap<u32, String>,
    }

    impl DeploymentProcess {
        fn remember_descendants(&mut self) {
            // Once Child has reaped its process, its PID could be reused.
            // Never inventory a different process after that point.
            if !matches!(self.child.try_wait(), Ok(None)) {
                return;
            }
            let mut parents = vec![self.child.id()];
            while let Some(parent) = parents.pop() {
                let Ok(children) =
                    fs::read_to_string(format!("/proc/{parent}/task/{parent}/children"))
                else {
                    continue;
                };
                for child in children.split_whitespace() {
                    if let Ok(pid) = child.parse::<u32>()
                        && let Some(start) = process_start_time(pid)
                        && self.descendants.insert(pid, start).is_none()
                    {
                        parents.push(pid);
                    }
                }
            }
        }
    }

    impl Drop for DeploymentProcess {
        fn drop(&mut self) {
            self.remember_descendants();
            if let Some(kill) = ["/bin/kill", "/usr/bin/kill"]
                .into_iter()
                .find(|path| Path::new(path).is_file())
            {
                for (pid, start) in self.descendants.iter().rev() {
                    if process_start_time(*pid).as_deref() == Some(start.as_str()) {
                        let _ = Command::new(kill)
                            .args(["-KILL", "--", &pid.to_string()])
                            .stdin(Stdio::null())
                            .stdout(Stdio::null())
                            .stderr(Stdio::null())
                            .status();
                    }
                }
            }
            if self.child.try_wait().ok().flatten().is_none() {
                let _ = self.child.kill();
                let _ = self.child.wait();
            }
        }
    }

    #[test]
    fn deployment_operator_safe_mode_interrupts_an_external_release_during_real_io() {
        const ADMISSION_DEADLINE: Duration = Duration::from_secs(30);
        const CONTROL_DEADLINE: Duration = Duration::from_secs(15);
        let drill = Drill::new();
        let external = tempfile::tempdir().expect("external release");
        let listener = TcpListener::bind("127.0.0.1:0").expect("real HTTP sink");
        listener.set_nonblocking(true).expect("bounded accept");
        let address = listener.local_addr().expect("HTTP sink address");
        let source = format!(
            "require('fs').writeFileSync('entered.marker', 'entered');\n\
             require('http').get('http://{address}/', (res) => {{\n\
               require('fs').writeFileSync('after.marker', res.body);\n\
             }});\n"
        );
        let config = format!(
            "profile = \"legacy-risky\"\n\
             [[security.network_policy.allowlist]]\n\
             host = \"127.0.0.1\"\n\
             port = {}\n\
             reason = \"real deployment containment regression sink\"\n",
            address.port()
        );
        let (release, manifest) =
            drill.publish_release_with_config("1.0.0", &source, external.path(), Some(&config));
        assert!(!release.starts_with(drill.root.path()));
        drill.install_published("1.0.0", &release, &manifest);
        drill.activate("1.0.0");
        drill.policy("rollback", "automatic");
        let active = fs::read(drill.state_path("active.json")).expect("admitted activation");
        let release_safe_mode_path = release.join(".franken-node/safe-mode/state.json");
        let release_safe_mode_before = fs::read(&release_safe_mode_path).ok();

        let (admitted_tx, admitted_rx) = mpsc::sync_channel(1);
        let (release_tx, release_rx) = mpsc::sync_channel(1);
        let server = std::thread::spawn(move || -> std::io::Result<()> {
            let started = Instant::now();
            let (mut stream, _) = loop {
                match listener.accept() {
                    Ok(connection) => break connection,
                    Err(error)
                        if error.kind() == std::io::ErrorKind::WouldBlock
                            && started.elapsed() < ADMISSION_DEADLINE =>
                    {
                        if matches!(release_rx.try_recv(), Err(mpsc::TryRecvError::Disconnected)) {
                            return Ok(());
                        }
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => return Err(error),
                }
            };
            stream.set_nonblocking(false)?;
            stream.set_read_timeout(Some(ADMISSION_DEADLINE))?;
            stream.set_write_timeout(Some(Duration::from_secs(2)))?;
            let mut request = Vec::new();
            stream.read_to_end(&mut request)?;
            if admitted_tx.send(request).is_err() {
                return Ok(());
            }
            if release_rx.recv_timeout(Duration::from_secs(45)).is_err() {
                return Ok(());
            }
            stream.write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ntoo-late",
            )?;
            stream.flush()
        });
        let child = drill
            .command(drill.root.path(), &["deploy", "run", "app", "--json"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("real deployed native workload");
        let mut deployment = DeploymentProcess {
            child,
            descendants: BTreeMap::new(),
        };
        let request = admitted_rx
            .recv_timeout(ADMISSION_DEADLINE)
            .expect("admitted native HTTP effect reached the sink");
        assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
        assert!(release.join("entered.marker").is_file());
        deployment.remember_descendants();
        assert!(
            deployment.descendants.len() >= 2,
            "deployment must own its run child and native worker"
        );

        drill.ok(
            drill.root.path(),
            &[
                "safe-mode",
                "enter",
                "--reason",
                "explicit-flag",
                "--operator-id",
                "live-deployment-operator",
                "--trust-state-hash",
                "operator:external-release-control",
                "--json",
            ],
        );
        let stopped_at = Instant::now();
        let status = loop {
            match deployment
                .child
                .try_wait()
                .expect("poll deployment supervisor")
            {
                Some(status) => break status,
                None => {
                    assert!(
                        stopped_at.elapsed() < CONTROL_DEADLINE,
                        "operator safe mode did not stop the external native session"
                    );
                    std::thread::sleep(Duration::from_millis(10));
                }
            }
        };
        let mut stdout = String::new();
        deployment
            .child
            .stdout
            .take()
            .expect("deployment stdout")
            .read_to_string(&mut stdout)
            .expect("deployment report");
        let mut stderr = String::new();
        deployment
            .child
            .stderr
            .take()
            .expect("deployment stderr")
            .read_to_string(&mut stderr)
            .expect("deployment diagnostics");
        assert!(
            deployment.descendants.iter().all(|(pid, start)| {
                process_start_time(*pid).as_deref() != Some(start.as_str())
            }),
            "the run child and native worker must be reaped before deployment completion"
        );
        assert!(!release.join("after.marker").exists());
        release_tx.send(()).expect("release the late HTTP response");
        // Whether the peer accepts the late bytes says nothing about a guest
        // callback; containment is proved by process exit and the absent file.
        let _ = server.join().expect("join HTTP sink");
        assert!(
            !status.success(),
            "live containment unexpectedly succeeded: {stdout}; {stderr}"
        );
        assert!(
            !release.join("after.marker").exists(),
            "late effect revived the guest"
        );
        let report: Value = serde_json::from_str(&stdout).unwrap_or_else(|error| {
            panic!("invalid deployment report: {error}; {stdout}; {stderr}")
        });
        assert_eq!(report["phase"], "failed", "{report}");
        assert_eq!(report["ok"], false);
        assert!(report.get("recovery").is_none());
        assert!(report.get("resumed").is_none());
        let evidence = &report["run"];
        assert_eq!(
            evidence["schema_version"],
            "franken-node/native-effect-interruption-evidence/v1"
        );
        assert_eq!(evidence["terminal_state"], "control_indeterminate");
        assert_eq!(evidence["control_trigger"]["kind"], "safe_mode");
        let detail = evidence["control_trigger"]["detail"]
            .as_str()
            .expect("operator containment cause");
        assert!(
            detail.contains("operator safe-mode scope") && detail.contains("active safe mode"),
            "{detail}"
        );
        assert_eq!(evidence["journal_complete"], true);
        assert_eq!(evidence["replay_certified"], false);
        assert_eq!(evidence["interrupted_effect_count"], 1);
        assert!(
            evidence["entries"].as_array().unwrap().iter().any(|entry| {
                entry["effect_kind"] == "network_request"
                    && entry["state"] == "interrupted_indeterminate"
                    && entry.get("policy_outcome").is_none()
                    && entry.get("allowed").is_none()
                    && entry.get("denied").is_none()
            }),
            "interrupted network effect must remain indeterminate: {evidence}"
        );
        let receipt_path = release.join(
            evidence["receipt_path"]
                .as_str()
                .expect("durable receipt path"),
        );
        let persisted: Value =
            serde_json::from_slice(&fs::read(receipt_path).expect("durable interruption receipt"))
                .unwrap();
        assert_eq!(persisted, evidence["receipt"]);
        assert_eq!(fs::read(drill.state_path("active.json")).unwrap(), active);
        let status = drill.status();
        assert_eq!(status["active"]["release_id"], "1.0.0");
        assert_eq!(status["releases"][0]["healthy_runs"], 0);
        assert_eq!(status["releases"][0]["crash_looped"], false);
        assert!(status["recoveries"].as_array().unwrap().is_empty());
        let operator_state: Value = serde_json::from_slice(
            &fs::read(drill.root.path().join(".franken-node/safe-mode/state.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(operator_state["active"], true);
        assert!(
            operator_state["native_crashes"]
                .as_array()
                .is_none_or(Vec::is_empty)
        );
        assert_eq!(
            fs::read(&release_safe_mode_path).ok(),
            release_safe_mode_before,
            "operator containment must not be misclassified as a release crash"
        );
    }

    /// Hold a real approved external release inside an admitted HTTP effect.
    /// The operator command can then change deployment authority while both
    /// the run child and native worker still exist.
    struct BlockedActivationRun {
        process: DeploymentProcess,
        stdout: Option<std::thread::JoinHandle<std::io::Result<Vec<u8>>>>,
        stderr: Option<std::thread::JoinHandle<std::io::Result<Vec<u8>>>>,
        release: tempfile::TempDir,
        replacement: PathBuf,
        release_response: mpsc::SyncSender<()>,
        server: Option<std::thread::JoinHandle<std::io::Result<()>>>,
        safe_mode_before: Option<Vec<u8>>,
    }

    fn drain_deployment_output(
        mut pipe: impl Read + Send + 'static,
    ) -> std::thread::JoinHandle<std::io::Result<Vec<u8>>> {
        std::thread::spawn(move || {
            let mut bytes = Vec::new();
            pipe.read_to_end(&mut bytes)?;
            Ok(bytes)
        })
    }

    impl BlockedActivationRun {
        fn start(drill: &Drill, retire_on_activation: bool) -> Self {
            const ADMISSION_DEADLINE: Duration = Duration::from_secs(30);
            let release = tempfile::tempdir().expect("external retiring release");
            let listener = TcpListener::bind("127.0.0.1:0").expect("activation HTTP sink");
            listener.set_nonblocking(true).expect("bounded accept");
            let address = listener.local_addr().expect("activation sink address");
            let source = format!(
                "require('fs').writeFileSync('entered.marker', 'entered');\n\
                 require('http').get('http://{address}/', (res) => {{\n\
                   require('fs').writeFileSync('after.marker', res.body);\n\
                   console.log('OLD_RELEASE_CALLBACK');\n\
                 }});\n"
            );
            let config = format!(
                "profile = \"legacy-risky\"\n\
                 [[security.network_policy.allowlist]]\n\
                 host = \"127.0.0.1\"\n\
                 port = {}\n\
                 reason = \"real activation retirement regression sink\"\n",
                address.port()
            );
            let (old, manifest) =
                drill.publish_release_with_config("1.0.0", &source, release.path(), Some(&config));
            assert!(!old.starts_with(drill.root.path()));
            drill.install_published("1.0.0", &old, &manifest);
            let replacement = drill.root.path().join("releases/2.0.0");
            let (_, manifest) = drill.publish_release_with_config(
                "2.0.0",
                "require('fs').writeFileSync('replacement.marker', 'started');\n\
                 console.log('REPLACEMENT_RUNNING');\n",
                &replacement,
                Some("profile = \"legacy-risky\"\n"),
            );
            drill.install_published("2.0.0", &replacement, &manifest);
            drill.activate("1.0.0");
            drill.policy("rollback", "automatic");
            let safe_mode_before = fs::read(old.join(".franken-node/safe-mode/state.json")).ok();

            let (admitted_tx, admitted_rx) = mpsc::sync_channel(1);
            let (release_response, release_rx) = mpsc::sync_channel(1);
            let server = std::thread::spawn(move || -> std::io::Result<()> {
                let started = Instant::now();
                let (mut stream, _) = loop {
                    match listener.accept() {
                        Ok(connection) => break connection,
                        Err(error)
                            if error.kind() == std::io::ErrorKind::WouldBlock
                                && started.elapsed() < ADMISSION_DEADLINE =>
                        {
                            if matches!(
                                release_rx.try_recv(),
                                Err(mpsc::TryRecvError::Disconnected)
                            ) {
                                return Ok(());
                            }
                            std::thread::sleep(Duration::from_millis(5));
                        }
                        Err(error) => return Err(error),
                    }
                };
                stream.set_nonblocking(false)?;
                stream.set_read_timeout(Some(ADMISSION_DEADLINE))?;
                stream.set_write_timeout(Some(Duration::from_secs(2)))?;
                let mut request = Vec::new();
                stream.read_to_end(&mut request)?;
                if admitted_tx.send(request).is_err() {
                    return Ok(());
                }
                if release_rx.recv_timeout(Duration::from_secs(45)).is_err() {
                    return Ok(());
                }
                stream.write_all(
                    b"HTTP/1.1 200 OK\r\nContent-Length: 8\r\nConnection: close\r\n\r\ntoo-late",
                )?;
                stream.flush()
            });
            let mut args = vec!["deploy", "run", "app", "--json"];
            if retire_on_activation {
                args.push("--retire-on-activation");
            }
            let mut child = drill
                .command(drill.root.path(), &args)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()
                .expect("real activation-observed native workload");
            // Drain while the supervisor runs: a large retained interruption
            // report must not fill its pipe and prevent the exit we observe.
            let stdout = drain_deployment_output(child.stdout.take().expect("deployment stdout"));
            let stderr = drain_deployment_output(child.stderr.take().expect("deployment stderr"));
            let mut process = DeploymentProcess {
                child,
                descendants: BTreeMap::new(),
            };
            let request = admitted_rx
                .recv_timeout(ADMISSION_DEADLINE)
                .expect("admitted HTTP effect before changing activation");
            assert!(request.starts_with(b"GET / HTTP/1.1\r\n"));
            assert!(old.join("entered.marker").is_file());
            assert!(!old.join("after.marker").exists());
            process.remember_descendants();
            assert!(
                process.descendants.len() >= 2,
                "the supervisor must own a run child and native worker"
            );
            Self {
                process,
                stdout: Some(stdout),
                stderr: Some(stderr),
                release,
                replacement,
                release_response,
                server: Some(server),
                safe_mode_before,
            }
        }

        fn finish(&mut self) -> (Option<i32>, Value) {
            let stopped_at = Instant::now();
            let status = loop {
                match self.process.child.try_wait().expect("poll deployment") {
                    Some(status) => break status,
                    None => {
                        assert!(
                            stopped_at.elapsed() < Duration::from_secs(15),
                            "deployment did not finish within its live-control deadline"
                        );
                        std::thread::sleep(Duration::from_millis(10));
                    }
                }
            };
            assert!(
                self.process.descendants.iter().all(|(pid, start)| {
                    process_start_time(*pid).as_deref() != Some(start.as_str())
                }),
                "the run child and native worker must be reaped before completion"
            );
            let stdout = self
                .stdout
                .take()
                .expect("deployment stdout reader")
                .join()
                .expect("join deployment stdout reader")
                .expect("deployment report");
            let stderr = self
                .stderr
                .take()
                .expect("deployment stderr reader")
                .join()
                .expect("join deployment stderr reader")
                .expect("deployment diagnostics");
            let report = serde_json::from_slice(&stdout).unwrap_or_else(|error| {
                panic!(
                    "invalid deployment report: {error}; {}; {}",
                    String::from_utf8_lossy(&stdout),
                    String::from_utf8_lossy(&stderr)
                )
            });
            (status.code(), report)
        }

        fn release_http_response(&mut self) -> std::io::Result<()> {
            self.release_response
                .send(())
                .expect("release HTTP response");
            self.server
                .take()
                .expect("retained HTTP sink")
                .join()
                .expect("join HTTP sink")
        }

        fn assert_retired(&mut self) -> Value {
            let (code, report) = self.finish();
            assert_ne!(code, Some(0), "{report}");
            assert_eq!(report["ok"], false);
            assert_eq!(report["phase"], "activation_interrupted", "{report}");
            assert_eq!(report["retire_on_activation"], true);
            assert_eq!(report["release_id"], "1.0.0");
            assert_eq!(report["activation_sequence"], 1);
            assert!(report.get("recovery").is_none(), "{report}");
            assert!(report.get("resumed").is_none(), "{report}");
            let evidence = &report["run"];
            assert_eq!(
                evidence["schema_version"],
                "franken-node/native-effect-interruption-evidence/v1"
            );
            assert_eq!(evidence["terminal_state"], "control_indeterminate");
            assert_eq!(
                evidence["control_trigger"]["kind"],
                "activation_interrupted"
            );
            assert_eq!(evidence["journal_complete"], true);
            assert_eq!(evidence["replay_certified"], false);
            assert_eq!(evidence["interrupted_effect_count"], 1);
            assert!(
                evidence["entries"].as_array().unwrap().iter().any(|entry| {
                    entry["effect_kind"] == "network_request"
                        && entry["state"] == "interrupted_indeterminate"
                        && entry.get("policy_outcome").is_none()
                        && entry.get("allowed").is_none()
                        && entry.get("denied").is_none()
                }),
                "the admitted network effect must remain indeterminate: {evidence}"
            );
            let receipt_path = self.release.path().join(
                evidence["receipt_path"]
                    .as_str()
                    .expect("durable activation interruption receipt"),
            );
            let persisted: Value =
                serde_json::from_slice(&fs::read(receipt_path).expect("retained receipt"))
                    .expect("receipt JSON");
            assert_eq!(persisted, evidence["receipt"]);
            assert!(!self.release.path().join("after.marker").exists());
            // A closed socket can refuse these bytes. Either outcome is fine:
            // the stopped guest must never regain its callback.
            let _ = self.release_http_response();
            assert!(
                !self.release.path().join("after.marker").exists(),
                "late HTTP completion revived a retired guest"
            );
            assert!(
                !self.replacement.join("replacement.marker").exists(),
                "retirement must not automatically follow a new activation"
            );
            assert_eq!(
                fs::read(
                    self.release
                        .path()
                        .join(".franken-node/safe-mode/state.json")
                )
                .ok(),
                self.safe_mode_before,
                "activation retirement is not a native crash"
            );
            report
        }
    }

    fn assert_no_health_or_recovery(drill: &Drill) {
        let status = drill.status();
        assert!(status["recoveries"].as_array().unwrap().is_empty());
        for release in status["releases"].as_array().unwrap() {
            assert_eq!(release["healthy_runs"], 0, "{status}");
            assert_eq!(release["crash_looped"], false, "{status}");
        }
    }

    fn run_replacement_explicitly(drill: &Drill, blocked: &BlockedActivationRun, sequence: u64) {
        let report = drill.ok(
            drill.root.path(),
            &["deploy", "run", "app", "--retire-on-activation", "--json"],
        );
        assert_eq!(report["phase"], "healthy", "{report}");
        assert_eq!(report["release_id"], "2.0.0");
        assert_eq!(report["activation_sequence"], sequence);
        assert_eq!(report["retire_on_activation"], true);
        assert_eq!(guest_stdout(&report["run"]), "REPLACEMENT_RUNNING\n");
        assert!(blocked.replacement.join("replacement.marker").is_file());
    }

    #[test]
    fn deployment_operator_fleet_hold_stops_external_io_and_retains_unknown_effects() {
        let drill = Drill::new();
        let mut blocked = BlockedActivationRun::start(&drill, false);
        let operator_before = drill.sessions(drill.root.path());
        let release_before = drill.sessions(blocked.release.path());
        assert_eq!(operator_before["records"].as_array().unwrap().len(), 1);
        assert_eq!(operator_before["records"], release_before["records"]);
        assert_eq!(operator_before["pending_sessions"], 1);
        assert_eq!(operator_before["quiescence_certified"], false);
        let nonce = operator_before["records"][0]["admission"]["session_nonce"]
            .as_str()
            .expect("retained native session nonce")
            .to_owned();
        let operator_fleet = drill.state_home.path().join("operator-fleet");
        drill.fleet_ok(
            drill.root.path(),
            &operator_fleet,
            &[
                "fleet",
                "hold",
                "--zone",
                "east",
                "--id",
                "live-deployment-owner",
                "--reason",
                "contain the admitted external deployment",
                "--json",
            ],
        );
        let first_poll = drill.fleet_poll(drill.root.path(), &operator_fleet, "operator-node");
        let first_drain = &first_poll["native_session_drain"];
        assert_eq!(first_drain["admitted_sessions"], 1, "{first_poll}");
        assert_eq!(first_drain["fence_held"], true, "{first_poll}");
        assert_eq!(
            first_drain["pending_sessions"].as_u64().unwrap()
                + first_drain["indeterminate_sessions"].as_u64().unwrap(),
            1,
            "an admitted external HTTP effect must not disappear from the operator drain: {first_poll}"
        );

        let (code, stopped) = blocked.finish();
        assert_ne!(code, Some(0), "{stopped}");
        assert_eq!(stopped["phase"], "failed", "{stopped}");
        assert_eq!(stopped["ok"], false);
        assert!(stopped.get("recovery").is_none());
        assert!(stopped.get("resumed").is_none());
        let evidence = &stopped["run"];
        assert_eq!(
            evidence["schema_version"],
            "franken-node/native-effect-interruption-evidence/v1"
        );
        assert_eq!(evidence["control_trigger"]["kind"], "fleet_drain");
        assert_eq!(evidence["terminal_state"], "control_indeterminate");
        assert_eq!(evidence["journal_complete"], true);
        assert_eq!(evidence["replay_certified"], false);
        assert_eq!(evidence["interrupted_effect_count"], 1);
        assert!(
            evidence["entries"].as_array().unwrap().iter().any(|entry| {
                entry["effect_kind"] == "network_request"
                    && entry["state"] == "interrupted_indeterminate"
                    && entry.get("policy_outcome").is_none()
                    && entry.get("allowed").is_none()
                    && entry.get("denied").is_none()
            }),
            "the outstanding network request is not certified as rolled back: {evidence}"
        );
        let receipt_path = blocked.release.path().join(
            evidence["receipt_path"]
                .as_str()
                .expect("durable interruption receipt"),
        );
        let persisted: Value =
            serde_json::from_slice(&fs::read(receipt_path).expect("retained receipt"))
                .expect("receipt JSON");
        assert_eq!(persisted, evidence["receipt"]);
        assert!(!blocked.release.path().join("after.marker").exists());
        let _ = blocked.release_http_response();
        assert!(
            !blocked.release.path().join("after.marker").exists(),
            "late HTTP completion must not revive the held deployment"
        );

        // A fresh process reconstructs the same population from the signed
        // admission. Reaping the worker does not resolve its external effect.
        let operator_after = drill.sessions(drill.root.path());
        let release_after = drill.sessions(blocked.release.path());
        assert_eq!(operator_after["records"], release_after["records"]);
        assert_eq!(operator_after["records"].as_array().unwrap().len(), 1);
        assert_eq!(
            operator_after["records"][0]["admission"]["session_nonce"],
            nonce
        );
        assert_eq!(operator_after["pending_sessions"], 0);
        assert_eq!(operator_after["terminal_sessions"], 1);
        assert_eq!(operator_after["unknown_effect_sessions"], 1);
        assert_eq!(operator_after["quiescence_certified"], false);
        let retained = drill.fleet_poll(drill.root.path(), &operator_fleet, "operator-node");
        let drain = &retained["native_session_drain"];
        assert_eq!(retained["node_health"], "degraded", "{retained}");
        assert_eq!(
            drain["session_set_sha256"],
            first_drain["session_set_sha256"]
        );
        assert_eq!(drain["admitted_sessions"], 1);
        assert_eq!(drain["terminal_sessions"], 0);
        assert_eq!(drain["pending_sessions"], 0);
        assert_eq!(drain["indeterminate_sessions"], 1);
        assert_eq!(drain["fence_held"], true);

        // Releasing the maintenance owner cannot erase the unresolved effect
        // or evade it by activating a different release/entrypoint.
        drill.fleet_ok(
            drill.root.path(),
            &operator_fleet,
            &[
                "fleet",
                "resume",
                "--hold",
                "live-deployment-owner",
                "--json",
            ],
        );
        let resumed = drill.fleet_poll(drill.root.path(), &operator_fleet, "operator-node");
        assert_eq!(
            resumed["native_session_drain"]["session_set_sha256"],
            drain["session_set_sha256"]
        );
        assert_eq!(resumed["native_session_drain"]["indeterminate_sessions"], 1);
        assert_eq!(resumed["native_session_drain"]["fence_held"], true);
        drill.activate("2.0.0");
        let (code, refused) = drill.run();
        assert_ne!(code, Some(0), "{refused}");
        assert!(
            refused
                .to_string()
                .contains("native-session admission is fenced"),
            "{refused}"
        );
        assert!(!blocked.replacement.join("replacement.marker").exists());
        assert_no_health_or_recovery(&drill);
        assert_eq!(
            fs::read(
                blocked
                    .release
                    .path()
                    .join(".franken-node/safe-mode/state.json")
            )
            .ok(),
            blocked.safe_mode_before,
            "fleet containment is not a native crash"
        );
    }

    #[test]
    fn deployment_operator_policy_tightening_interrupts_already_admitted_external_io() {
        use frankenengine_node::control_plane::fleet_transport::{
            FleetActionRecord, activate_fleet_policy_snapshot,
        };

        let drill = Drill::new();
        let mut blocked = BlockedActivationRun::start(&drill, false);
        let operator_fleet = drill.state_home.path().join("operator-fleet");
        let publication = drill.publish_fleet_policy(
            drill.root.path(),
            &operator_fleet,
            "operator-network-policy",
            &serde_json::json!({"block_private_network": true}),
        );
        let action: FleetActionRecord =
            serde_json::from_value(publication["action"].clone()).expect("published policy action");
        // Use the agent's canonical activation API with the real publication.
        // A fleet-agent poll also establishes an admission fence, which would
        // obscure whether the independent operator policy observer works.
        activate_fleet_policy_snapshot(drill.root.path(), &[action], "east")
            .expect("activate operator restriction")
            .expect("active operator policy");
        let (code, stopped) = blocked.finish();
        assert_ne!(code, Some(0), "{stopped}");
        assert_eq!(stopped["phase"], "failed", "{stopped}");
        assert!(stopped.get("recovery").is_none());
        assert!(stopped.get("resumed").is_none());
        let evidence = &stopped["run"];
        assert_eq!(evidence["control_trigger"]["kind"], "fleet_policy_changed");
        assert_eq!(evidence["terminal_state"], "control_indeterminate");
        assert_eq!(evidence["interrupted_effect_count"], 1);
        assert_eq!(evidence["replay_certified"], false);
        assert!(!blocked.release.path().join("after.marker").exists());
        let _ = blocked.release_http_response();
        assert!(!blocked.release.path().join("after.marker").exists());
        assert_no_health_or_recovery(&drill);
        let operator_sessions = drill.sessions(drill.root.path());
        assert_eq!(operator_sessions["unknown_effect_sessions"], 1);
        assert_eq!(
            operator_sessions["records"],
            drill.sessions(blocked.release.path())["records"]
        );
    }

    #[test]
    fn deployment_retire_on_activation_stops_old_io_for_new_and_same_release_activations() {
        for next in ["2.0.0", "1.0.0"] {
            let drill = Drill::new();
            let mut blocked = BlockedActivationRun::start(&drill, true);
            let initial = fs::read(drill.state_path("active.json")).unwrap();
            drill.activate(next);
            blocked.assert_retired();
            let status = drill.status();
            assert_eq!(status["active"]["release_id"], next);
            assert_eq!(status["active"]["sequence"], 2);
            assert_ne!(fs::read(drill.state_path("active.json")).unwrap(), initial);
            assert_no_health_or_recovery(&drill);
            // Re-activating the same release also retires its old invocation.
            // Only a subsequent explicit operator action starts another guest.
            let sequence = if next == "1.0.0" {
                drill.activate("2.0.0");
                3
            } else {
                2
            };
            run_replacement_explicitly(&drill, &blocked, sequence);
        }
    }

    #[test]
    fn deployment_retire_on_activation_observes_unfinished_durable_intent_without_following_it() {
        let drill = Drill::new();
        let mut blocked = BlockedActivationRun::start(&drill, true);
        let original = fs::read(drill.state_path("active.json")).unwrap();
        drill.interrupt(
            &[
                "deploy",
                "activate",
                "app",
                "--release",
                "2.0.0",
                "--operator-id",
                "interrupted-rollout",
                "--json",
            ],
            "intent",
        );
        assert_eq!(fs::read(drill.state_path("active.json")).unwrap(), original);
        let pending = drill.status();
        assert_eq!(pending["active"]["release_id"], "1.0.0");
        assert_eq!(
            pending["pending_activation"]["activation"]["release_id"],
            "2.0.0"
        );
        assert_eq!(pending["pending_activation"]["activation"]["sequence"], 2);
        blocked.assert_retired();
        assert_eq!(
            drill.status()["pending_activation"],
            pending["pending_activation"],
            "retirement must not complete an unfinished operator activation"
        );
        assert_no_health_or_recovery(&drill);
        let reconciled = drill.reconcile();
        assert_eq!(reconciled["activation"]["sequence"], 2);
        assert!(!blocked.replacement.join("replacement.marker").exists());
        run_replacement_explicitly(&drill, &blocked, 2);
    }

    #[test]
    fn deployment_retire_on_activation_fails_closed_when_pointer_is_lost_corrupt_or_replaced() {
        let foreign = Drill::new();
        foreign.install("1.0.0", HEALTHY_V1);
        foreign.activate("1.0.0");
        let foreign_pointer = fs::read(foreign.state_path("active.json")).unwrap();
        for mutation in ["missing", "malformed", "foreign"] {
            let drill = Drill::new();
            let mut blocked = BlockedActivationRun::start(&drill, true);
            let pointer = drill.state_path("active.json");
            let original = fs::read(&pointer).unwrap();
            match mutation {
                "missing" => fs::rename(
                    &pointer,
                    drill.root.path().join("retained-original-active.json"),
                )
                .expect("retain missing pointer evidence"),
                "malformed" => {
                    fs::write(&pointer, b"{not an activation\n").expect("malformed pointer")
                }
                "foreign" => {
                    let original_record: Value = serde_json::from_slice(&original).unwrap();
                    let foreign_record: Value = serde_json::from_slice(&foreign_pointer).unwrap();
                    assert_ne!(
                        original_record["signer_public_key_hex"],
                        foreign_record["signer_public_key_hex"],
                        "replacement fixture must use another deployment authority"
                    );
                    fs::write(&pointer, &foreign_pointer)
                        .expect("foreign signed activation pointer");
                }
                _ => unreachable!(),
            }
            blocked.assert_retired();
            // A missing pointer can remain inspectable as a pending durable
            // intent. Inspection must never invent a current replacement.
            let inspected = drill.cli(drill.root.path(), &["deploy", "status", "app", "--json"]);
            if inspected.status.success() {
                let status: Value = serde_json::from_slice(&inspected.stdout).unwrap();
                assert!(status["active"].is_null(), "mutation {mutation}: {status}");
            }
            fs::write(&pointer, original).expect("restore retained authenticated pointer");
            assert_no_health_or_recovery(&drill);
            drill.activate("2.0.0");
            run_replacement_explicitly(&drill, &blocked, 2);
        }
    }

    #[test]
    fn deployment_without_retirement_finishes_the_admitted_release_after_activation_changes() {
        let drill = Drill::new();
        let mut blocked = BlockedActivationRun::start(&drill, false);
        drill.activate("2.0.0");
        let changed_at = Instant::now();
        while changed_at.elapsed() < Duration::from_secs(1) {
            assert!(
                blocked.process.child.try_wait().unwrap().is_none(),
                "default deployment run must continue its admitted invocation"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
        blocked
            .release_http_response()
            .expect("complete original HTTP effect");
        let (code, report) = blocked.finish();
        assert_eq!(code, Some(0), "{report}");
        assert_eq!(report["phase"], "healthy");
        assert_eq!(report["retire_on_activation"], false);
        assert_eq!(report["release_id"], "1.0.0");
        assert_eq!(report["activation_sequence"], 1);
        assert_eq!(guest_stdout(&report["run"]), "OLD_RELEASE_CALLBACK\n");
        assert_eq!(
            fs::read_to_string(blocked.release.path().join("after.marker")).unwrap(),
            "too-late"
        );
        assert!(!blocked.replacement.join("replacement.marker").exists());
        let status = drill.status();
        assert_eq!(status["active"]["release_id"], "2.0.0");
        assert!(status["recoveries"].as_array().unwrap().is_empty());
        let old = status["releases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|release| release["release_id"] == "1.0.0")
            .unwrap();
        assert_eq!(old["healthy_runs"], 1);
        assert_eq!(old["crash_looped"], false);
        run_replacement_explicitly(&drill, &blocked, 2);
    }

    #[test]
    fn deployment_retirement_uses_a_fresh_admission_for_an_authorized_crash_loop_restart() {
        let drill = Drill::new();
        drill.install("1.0.0", HEALTHY_V1);
        drill.install("2.0.0", &crashing_v2());
        drill.policy("rollback", "automatic");
        drill.activate("1.0.0");
        let healthy = drill.ok(
            drill.root.path(),
            &["deploy", "run", "app", "--retire-on-activation", "--json"],
        );
        assert_eq!(healthy["phase"], "healthy");
        assert_eq!(healthy["activation_sequence"], 1);
        drill.activate("2.0.0");
        drill.prime_crash_loop();

        // The original invocation really crashed. The signed recovery policy
        // grants one new start, whose restriction must name activation 3.
        let resumed = drill.ok(
            drill.root.path(),
            &["deploy", "run", "app", "--retire-on-activation", "--json"],
        );
        assert_eq!(resumed["phase"], "resumed_healthy", "{resumed}");
        assert_eq!(resumed["retire_on_activation"], true);
        assert_eq!(resumed["activation_sequence"], 2);
        assert_eq!(resumed["run"]["outcome"], "native_engine_panic");
        assert_eq!(resumed["recovery"]["outcome"], "rolled_back");
        assert_eq!(resumed["recovery"]["activation_sequence"], 3);
        assert_eq!(resumed["resumed"]["release_id"], "1.0.0");
        assert_eq!(resumed["resumed"]["activation_sequence"], 3);
        assert_eq!(
            guest_stdout(&resumed["resumed"]["run"]),
            "RELEASE_ONE_HEALTHY\n"
        );
        let status = drill.status();
        assert_eq!(status["active"]["sequence"], 3);
        assert_eq!(status["active"]["release_id"], "1.0.0");
        let good = status["releases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|release| release["release_id"] == "1.0.0")
            .unwrap();
        assert_eq!(good["healthy_runs"], 2);
    }

    #[test]
    fn admitted_child_rejects_a_stale_activation_before_any_guest_execution() {
        use frankenengine_node::runtime::deployment::{DeploymentAuthority, DeploymentStore};
        use sha2::{Digest, Sha256};

        let drill = Drill::new();
        let directory = drill.root.path().join("releases/1.0.0");
        let (_, manifest) = drill.publish_release_with_config(
            "1.0.0",
            "require('fs').writeFileSync('stale-guest.marker', 'must not run');\n",
            &directory,
            Some("profile = \"legacy-risky\"\n"),
        );
        drill.install_published("1.0.0", &directory, &manifest);
        drill.install("2.0.0", HEALTHY_V1);
        drill.activate("1.0.0");
        let admitted = drill.admitted_release("1.0.0");
        let key_hex = fs::read_to_string(
            drill
                .root
                .path()
                .join(".franken-node/keys/receipt-signing.key"),
        )
        .expect("deployment authority");
        let secret: [u8; 32] = hex::decode(key_hex.trim())
            .expect("hex signing key")
            .try_into()
            .expect("32-byte signing key");
        let authority = DeploymentAuthority::new(ed25519_dalek::SigningKey::from_bytes(&secret));
        let store = DeploymentStore::open(drill.root.path(), "app").expect("deployment store");
        let restriction = {
            let lock = store.lock().expect("deployment lock");
            let active = store
                .active(&authority)
                .expect("verified activation")
                .unwrap();
            store
                .capture_activation_restriction(&lock, &authority, &active)
                .expect("capture actual activation restriction")
        };
        restriction.enforce().expect("initial restriction holds");
        let pins = serde_json::to_value(&restriction).expect("restriction JSON");
        assert_eq!(
            pins["schema_version"],
            "franken-node/deployment-activation-restriction/v1"
        );
        assert_eq!(
            pins["store_root"],
            fs::canonicalize(drill.state_path(""))
                .unwrap()
                .to_str()
                .unwrap()
        );
        assert_eq!(pins["deployment"], "app");
        assert_eq!(pins["activation_sequence"], 1);
        assert_eq!(pins["release_id"], "1.0.0");
        assert_eq!(pins["signer_public_key_hex"], authority.public_key_hex());
        assert_eq!(
            pins["pointer_sha256"],
            format!(
                "sha256:{}",
                hex::encode(Sha256::digest(
                    fs::read(drill.state_path("active.json")).unwrap()
                ))
            )
        );
        let serialized = serde_json::to_string(&restriction).expect("exact child restriction");
        drill.activate("2.0.0");
        let before = drill.status();
        assert_eq!(before["active"]["sequence"], 2);
        assert_eq!(
            before["active"]["previous_activation_digest"],
            pins["activation_digest"]
        );
        assert!(
            restriction.enforce().is_err(),
            "the retained admission is now stale"
        );
        let approval_pin = admitted.approval.admission_sha256().expect("approval pin");
        let output = drill.cli(
            &directory,
            &[
                "run",
                "app.js",
                "--config",
                "franken_node.toml",
                "--runtime",
                "franken-engine",
                "--frozen-modules",
                "--json",
                "--registry-artifact",
                manifest.to_str().unwrap(),
                "--publisher-public-key",
                drill.public_key.to_str().unwrap(),
                "--admitted-config-sha256",
                &admitted.config_sha256,
                "--admitted-approval-sha256",
                &approval_pin,
                "--admitted-deployment-activation",
                &serialized,
            ],
        );
        assert!(
            !output.status.success(),
            "stale activation admitted a child"
        );
        let refused: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
            panic!(
                "stale admission must emit typed JSON: {error}; {}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            )
        });
        assert_eq!(refused["outcome"], "activation_interrupted", "{refused}");
        assert_eq!(refused["admission_only"], true);
        assert_eq!(refused["ok"], false);
        assert!(!directory.join("stale-guest.marker").exists());
        assert_eq!(
            drill.status(),
            before,
            "denied admission must not record health or recovery"
        );
    }
}
