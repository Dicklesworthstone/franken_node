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

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use frankenengine_node::runtime::deployment::ReleaseRecord;
use serde_json::Value;

const PANIC_MARKER: &str = "__FRANKEN_NODE_TEST_SUPPORT_NATIVE_ENGINE_PANIC__";

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
        let mut command = Command::new(binary());
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
        let capsule = format!("app-{version}.capsule");
        self.ok(
            self.registry.path(),
            &[
                "verify",
                "source-graph",
                dir.to_str().expect("utf-8"),
                "app.js",
                "--write-source-capsule",
                &capsule,
                "--json",
            ],
        );
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
        (dir.to_path_buf(), manifest)
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
            assert!(report.get("recovery").is_none(), "{report}");
        }
    }
}

const HEALTHY_V1: &str = "console.log('RELEASE_ONE_HEALTHY');\n";

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
    assert!(guest_stdout(&healthy["run"]).contains("RELEASE_ONE_HEALTHY"));

    // The bad release crash-loops; the third validated panic recovers.
    drill.activate("2.0.0");
    let (code, recovered) = drill.crash_until_loop();
    assert_eq!(recovered["phase"], "resumed_healthy", "{recovered}");
    assert_eq!(code, Some(0), "{recovered}");
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
}
