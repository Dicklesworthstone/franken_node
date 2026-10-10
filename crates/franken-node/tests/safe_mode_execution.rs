//! Persisted operator safe mode is an execution interlock, including inherited
//! directory scopes. These checks use actual controller serialization and CLI
//! processes; native success after recovery is exercised with the engine feature.

use frankenengine_node::runtime::safe_mode::{
    ExitVerification, MAX_SAFE_MODE_STATE_BYTES, OperationFlags, SafeModeController,
    SafeModeEntryReason, enforce_run_safe_mode, read_persisted_safe_mode,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn entry(scope: &Path) -> PathBuf {
    fs::create_dir_all(scope).unwrap();
    let path = scope.join("app.js");
    fs::write(&path, "console.log('SAFE_MODE_GUEST_RAN');\n").unwrap();
    path
}

fn state_path(scope: &Path) -> PathBuf {
    let directory = scope.join(".franken-node/safe-mode");
    fs::create_dir_all(&directory).unwrap();
    directory.join("state.json")
}

fn active_controller() -> SafeModeController {
    let mut controller = SafeModeController::with_default_config();
    controller.set_flags(OperationFlags::safe_mode_only());
    controller.enter_safe_mode(
        SafeModeEntryReason::ExplicitFlag,
        "2026-10-10T00:00:00Z",
        "operator:test-state",
        Vec::new(),
    );
    controller
}

fn persist(scope: &Path, controller: &SafeModeController) {
    fs::write(state_path(scope), serde_json::to_vec(controller).unwrap()).unwrap();
}

fn exit_checks() -> ExitVerification {
    ExitVerification {
        trust_state_consistent: true,
        no_unresolved_incidents: true,
        evidence_ledger_intact: true,
        operator_confirmed: true,
    }
}

#[test]
fn missing_state_and_explicitly_recovered_state_allow_execution() {
    let directory = tempfile::tempdir().unwrap();
    let app = entry(directory.path());
    enforce_run_safe_mode(&app).unwrap();

    let mut controller = active_controller();
    persist(directory.path(), &controller);
    assert!(enforce_run_safe_mode(&app).is_err());
    controller
        .exit_safe_mode(&exit_checks(), "operator", "2026-10-10T00:01:00Z")
        .unwrap();
    // A legitimate exit retains the old flags. Only active state is binding.
    assert_eq!(serde_json::to_value(&controller).unwrap()["flags"]["safe_mode"], true);
    persist(directory.path(), &controller);
    enforce_run_safe_mode(&app).unwrap();
}

#[test]
fn inactive_child_cannot_override_active_ancestor() {
    let directory = tempfile::tempdir().unwrap();
    let child = directory.path().join("nested");
    let app = entry(&child);
    persist(directory.path(), &active_controller());
    persist(&child, &SafeModeController::with_default_config());

    let error = enforce_run_safe_mode(&app.canonicalize().unwrap()).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("run blocked by active safe mode"), "{message}");
    assert!(
        message.contains(state_path(directory.path()).to_str().unwrap()),
        "refusal must identify the controlling parent: {message}"
    );
}

#[test]
fn nested_scope_blocks_its_entrypoint_but_not_a_sibling() {
    let directory = tempfile::tempdir().unwrap();
    let left = directory.path().join("left");
    let blocked = entry(&left);
    let allowed = entry(&directory.path().join("right"));
    persist(&left, &active_controller());

    assert!(enforce_run_safe_mode(&blocked).is_err());
    enforce_run_safe_mode(&allowed).unwrap();
}

#[test]
fn active_state_with_empty_restriction_set_still_blocks() {
    let directory = tempfile::tempdir().unwrap();
    let app = entry(directory.path());
    let mut value = serde_json::to_value(active_controller()).unwrap();
    value["restricted_capabilities"] = serde_json::json!([]);
    fs::write(state_path(directory.path()), serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(enforce_run_safe_mode(&app).is_err());
}

#[test]
fn malformed_and_oversized_state_fail_closed() {
    let directory = tempfile::tempdir().unwrap();
    let app = entry(directory.path());
    let path = state_path(directory.path());
    fs::write(&path, b"{").unwrap();
    let error = enforce_run_safe_mode(&app).unwrap_err();
    assert!(error.to_string().contains("invalid safe-mode state"));

    let file = fs::File::create(&path).unwrap();
    file.set_len(MAX_SAFE_MODE_STATE_BYTES + 1).unwrap();
    let error = enforce_run_safe_mode(&app).unwrap_err();
    let message = error.to_string();
    assert!(message.contains("Safe-mode state file too large"));
    assert!(message.contains(&(MAX_SAFE_MODE_STATE_BYTES + 1).to_string()));
    assert!(message.contains(&MAX_SAFE_MODE_STATE_BYTES.to_string()));
}

#[test]
fn non_regular_state_is_not_treated_as_inactive() {
    let directory = tempfile::tempdir().unwrap();
    let app = entry(directory.path());
    let path = state_path(directory.path());
    fs::create_dir(&path).unwrap();
    assert!(read_persisted_safe_mode(&path).is_err());
    assert!(enforce_run_safe_mode(&app).is_err());
}

#[cfg(unix)]
#[test]
fn dangling_symlink_and_socket_state_are_refused() {
    use std::os::unix::fs::symlink;
    use std::os::unix::net::UnixListener;

    let directory = tempfile::tempdir().unwrap();
    let linked = directory.path().join("linked");
    let linked_app = entry(&linked);
    symlink("missing-controller.json", state_path(&linked)).unwrap();
    assert!(enforce_run_safe_mode(&linked_app).is_err());

    let socket = directory.path().join("socket");
    let socket_app = entry(&socket);
    let _listener = UnixListener::bind(state_path(&socket)).unwrap();
    assert!(enforce_run_safe_mode(&socket_app).is_err());
}

#[cfg(feature = "engine")]
#[test]
fn public_dispatcher_cannot_bypass_operator_safe_mode() {
    use frankenengine_node::config::{Config, PreferredRuntime, Profile};
    use frankenengine_node::ops::engine_dispatcher::{EngineDispatcher, RunProjectPaths};

    let directory = tempfile::tempdir().unwrap();
    let app = entry(directory.path());
    persist(directory.path(), &active_controller());
    let current = std::env::current_dir().unwrap();
    let paths = RunProjectPaths::resolve(&app, &current).unwrap();
    let error = EngineDispatcher::new(None, PreferredRuntime::FrankenEngine)
        .with_project_paths(paths)
        .dispatch_run(&app, &Config::for_profile(Profile::Balanced), "balanced", &[], 0)
        .unwrap_err();
    assert!(error.to_string().contains("run blocked by active safe mode"));
}

fn cli(directory: &Path, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_franken-node"))
        .current_dir(directory)
        .env_remove("FRANKEN_NODE_RUNTIME_ALLOW_PROCESS_SHAPE")
        .args(arguments)
        .output()
        .expect("run actual CLI")
}

fn initialized_project() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    entry(directory.path());
    let output = cli(
        directory.path(),
        &["init", "--profile", "balanced", "--out-dir", "."],
    );
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    directory
}

fn enter_from_cli(directory: &Path) {
    let output = cli(
        directory,
        &[
            "safe-mode", "enter", "--reason", "explicit-flag",
            "--operator-id", "operator", "--trust-state-hash", "operator:test-state",
            "--json",
        ],
    );
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
}

#[test]
fn cli_safe_mode_blocks_every_profile_before_guest_output() {
    let directory = initialized_project();
    enter_from_cli(directory.path());
    for profile in ["strict", "balanced", "legacy-risky"] {
        let output = cli(
            directory.path(),
            &["run", "app.js", "--policy", profile, "--json"],
        );
        assert!(!output.status.success());
        let value: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
        assert_eq!(value["schema_version"], "franken-node/run-error-cli/v1");
        assert!(value.to_string().contains("run blocked by active safe mode"));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("SAFE_MODE_GUEST_RAN"));
    }
}

#[cfg(feature = "engine")]
#[test]
fn cli_explicit_exit_restores_native_execution() {
    let directory = initialized_project();
    enter_from_cli(directory.path());
    let denied = cli(
        directory.path(),
        &["safe-mode", "exit", "--operator-id", "operator", "--confirm", "--json"],
    );
    assert!(!denied.status.success());
    assert!(enforce_run_safe_mode(&directory.path().join("app.js")).is_err());

    let recovered = cli(
        directory.path(),
        &[
            "safe-mode", "exit", "--operator-id", "operator", "--confirm",
            "--trust-state-consistent", "--no-unresolved-incidents",
            "--evidence-ledger-intact", "--json",
        ],
    );
    assert!(recovered.status.success(), "{}", String::from_utf8_lossy(&recovered.stderr));
    let output = cli(
        directory.path(),
        &["run", "app.js", "--policy", "balanced", "--runtime", "franken-engine", "--console-only"],
    );
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    assert!(String::from_utf8_lossy(&output.stdout).contains("SAFE_MODE_GUEST_RAN"));
}
