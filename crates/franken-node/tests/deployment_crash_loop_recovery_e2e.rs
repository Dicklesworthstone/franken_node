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

    fn cli(&self, cwd: &Path, args: &[&str]) -> Output {
        Command::new(binary())
            .current_dir(cwd)
            .env("XDG_STATE_HOME", self.state_home.path())
            .env("XDG_CONFIG_HOME", self.state_home.path().join("config"))
            .env_remove("FRANKEN_NODE_PROFILE")
            .env_remove("FRANKEN_NODE_SECURITY_DECISION_RECEIPT_SIGNING_KEY_PATH")
            .args(args)
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
        fs::create_dir_all(&dir).expect("release dir");
        fs::write(dir.join("app.js"), source).expect("app source");
        fs::write(
            dir.join("package.json"),
            format!("{{\"name\":\"deployed-app\",\"version\":\"{version}\"}}\n"),
        )
        .expect("package.json");
        self.init_project(&dir);
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
        (dir, manifest)
    }

    fn install(&self, version: &str, source: &str) -> PathBuf {
        let (dir, manifest) = self.publish_release(version, source);
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
        dir
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

    /// Crash the active (panicking) release until the supervisor's validated
    /// crash-loop threshold (three panics in 60 s) is reached.
    fn crash_until_loop(&self) -> (Option<i32>, Value) {
        for attempt in 1..=2 {
            let (code, report) = self.run();
            assert_eq!(report["phase"], "crashed", "attempt {attempt}: {report}");
            assert_ne!(code, Some(0));
            assert_eq!(report["run"]["outcome"], "native_engine_panic", "{report}");
            assert_eq!(report["run"]["crash_loop"]["crashes_in_window"], attempt);
            assert!(report.get("recovery").is_none(), "{report}");
        }
        self.run()
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
