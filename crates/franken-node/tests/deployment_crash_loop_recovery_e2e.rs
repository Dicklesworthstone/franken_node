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
        fs::create_dir_all(dir).expect("release dir");
        fs::write(dir.join("app.js"), source).expect("app source");
        fs::write(
            dir.join("package.json"),
            format!("{{\"name\":\"deployed-app\",\"version\":\"{version}\"}}\n"),
        )
        .expect("package.json");
        self.init_project(dir);
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

fn guest_stdout(run: &Value) -> &str {
    run["dispatch"]["captured_output"]["stdout"]
        .as_str()
        .unwrap_or_default()
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
