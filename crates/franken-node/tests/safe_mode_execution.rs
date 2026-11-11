//! Persisted operator safe mode is an execution interlock, including inherited
//! directory scopes. These checks use actual controller serialization and CLI
//! processes; native success after recovery is exercised with the engine feature.

use frankenengine_node::runtime::lockstep_harness::LockstepHarness;
use frankenengine_node::runtime::safe_mode::{
    AdmittedSafeModeProject, ContainmentGate, ContainmentScopeKind, ExitVerification,
    MAX_SAFE_MODE_STATE_BYTES, OperationFlags, SafeModeAction, SafeModeController,
    SafeModeEntryReason, enforce_project_safe_mode, enforce_run_safe_mode,
    read_persisted_safe_mode, record_native_crash, update_persisted_safe_mode,
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
    assert_eq!(
        serde_json::to_value(&controller).unwrap()["flags"]["safe_mode"],
        true
    );
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
    assert!(
        message.contains("run blocked by active safe mode"),
        "{message}"
    );
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
    fs::write(
        state_path(directory.path()),
        serde_json::to_vec(&value).unwrap(),
    )
    .unwrap();
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

    // RCH's inherited TMPDIR can exceed sockaddr_un's path limit before
    // this test reaches the non-regular-controller admission check.
    let directory = tempfile::Builder::new()
        .prefix("fn-sock-")
        .tempdir_in("/tmp")
        .unwrap();
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
        .dispatch_run(
            &app,
            &Config::for_profile(Profile::Balanced),
            "balanced",
            &[],
            0,
        )
        .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("run blocked by active safe mode")
    );
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
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    directory
}

fn enter_from_cli(directory: &Path) {
    let output = cli(
        directory,
        &[
            "safe-mode",
            "enter",
            "--reason",
            "explicit-flag",
            "--operator-id",
            "operator",
            "--trust-state-hash",
            "operator:test-state",
            "--json",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
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
        assert!(
            value
                .to_string()
                .contains("run blocked by active safe mode")
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("SAFE_MODE_GUEST_RAN"));
    }
}

#[test]
fn retained_project_scopes_recheck_original_ancestry_without_guest_files() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("nested/project");
    fs::create_dir_all(&project).unwrap();
    let admitted = AdmittedSafeModeProject::capture(&project).unwrap();
    assert_eq!(admitted.root(), project.canonicalize().unwrap().as_path());
    enforce_project_safe_mode(&project).unwrap();

    persist(&project, &SafeModeController::with_default_config());
    let mut parent = active_controller();
    persist(directory.path(), &parent);
    assert!(
        admitted
            .enforce()
            .unwrap_err()
            .to_string()
            .contains("active safe mode")
    );
    assert!(enforce_project_safe_mode(&project).is_err());
    parent
        .exit_safe_mode(&exit_checks(), "operator", "2026-10-10T00:01:00Z")
        .unwrap();
    persist(directory.path(), &parent);
    admitted.enforce().unwrap();

    fs::write(state_path(directory.path()), b"{").unwrap();
    assert!(
        admitted
            .enforce()
            .unwrap_err()
            .to_string()
            .contains("invalid safe-mode state")
    );
}

#[test]
fn lockstep_refuses_files_directories_and_corpora_before_starting_runtimes() {
    let directory = tempfile::tempdir().unwrap();
    let project = directory.path().join("nested");
    let app = entry(&project);
    let manifest = project.join("manifest.json");
    fs::write(&manifest, br#"{"cases":[{"id":"guest","file":"app.js"}]}"#).unwrap();
    persist(directory.path(), &active_controller());
    persist(&project, &SafeModeController::with_default_config());
    let before = fs::read(state_path(directory.path())).unwrap();
    let harness = LockstepHarness::new(vec![
        "/missing/reference-runtime".into(),
        "/missing/candidate-runtime".into(),
    ]);
    for input in [&app, &project, &manifest] {
        let error = harness.verify_lockstep(input, true).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("run blocked by active safe mode"),
            "{error:#}"
        );
    }
    assert_eq!(fs::read(state_path(directory.path())).unwrap(), before);
    assert!(!project.join("fixtures").exists());
}

#[test]
fn lockstep_refuses_malformed_control_state_before_runtime_resolution() {
    let directory = tempfile::tempdir().unwrap();
    let app = entry(directory.path());
    fs::write(state_path(directory.path()), b"{").unwrap();
    let harness = LockstepHarness::new(vec!["node".into(), "bun".into()]);
    let error = harness.verify_lockstep(&app, false).unwrap_err();
    assert!(
        error.to_string().contains("invalid safe-mode state"),
        "{error:#}"
    );
}

#[test]
fn cli_lockstep_obeys_the_same_operator_interlock_as_run() {
    let directory = initialized_project();
    enter_from_cli(directory.path());
    let output = cli(
        directory.path(),
        &[
            "verify",
            "lockstep",
            "app.js",
            "--runtimes",
            "node,bun",
            "--json",
        ],
    );
    assert!(!output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report["schema_version"],
        "franken-node/verify-lockstep-error-cli/v1"
    );
    assert!(
        report
            .to_string()
            .contains("run blocked by active safe mode"),
        "{report}"
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("SAFE_MODE_GUEST_RAN"));
}

#[cfg(unix)]
#[test]
fn lockstep_stops_reference_process_groups_when_safe_mode_activates() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Stdio;
    use std::time::{Duration, Instant};

    if Command::new("strace")
        .arg("-V")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .is_err()
    {
        eprintln!("skipping live lockstep containment test because strace is unavailable");
        return;
    }
    let directory = tempfile::tempdir().unwrap();
    let app = entry(directory.path());
    let control = state_path(directory.path());
    assert!(!control.exists());
    fs::write(
        directory.path().join("activate.json"),
        serde_json::to_vec(&active_controller()).unwrap(),
    )
    .unwrap();
    let mut runtimes = Vec::new();
    for name in ["reference.sh", "candidate.sh"] {
        let runtime = directory.path().join(name);
        fs::write(&runtime, "#!/bin/sh\nset -eu\nroot=$(dirname \"$1\")\nstate=\"$root/.franken-node/safe-mode/state.json\"\ncp \"$root/activate.json\" \"$state.$$.tmp\"\nmv \"$state.$$.tmp\" \"$state\"\nsleep 30\nprintf escaped > \"$root/late-guest-effect\"\n").unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        runtimes.push(runtime.to_str().unwrap().to_owned());
    }
    let started = Instant::now();
    let error = LockstepHarness::new(runtimes)
        .verify_lockstep(&app, false)
        .unwrap_err();
    assert!(format!("{error:#}").contains("safe mode"), "{error:#}");
    assert!(
        started.elapsed() < Duration::from_secs(15),
        "containment must not wait for the guest sleep"
    );
    assert!(!directory.path().join("late-guest-effect").exists());
    assert!(enforce_project_safe_mode(directory.path()).is_err());
}

#[cfg(feature = "engine")]
#[test]
fn cli_explicit_exit_restores_native_execution() {
    let directory = initialized_project();
    enter_from_cli(directory.path());
    let denied = cli(
        directory.path(),
        &[
            "safe-mode",
            "exit",
            "--operator-id",
            "operator",
            "--confirm",
            "--json",
        ],
    );
    assert!(!denied.status.success());
    assert!(enforce_run_safe_mode(&directory.path().join("app.js")).is_err());

    let recovered = cli(
        directory.path(),
        &[
            "safe-mode",
            "exit",
            "--operator-id",
            "operator",
            "--confirm",
            "--trust-state-consistent",
            "--no-unresolved-incidents",
            "--evidence-ledger-intact",
            "--json",
        ],
    );
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let output = cli(
        directory.path(),
        &[
            "run",
            "app.js",
            "--policy",
            "balanced",
            "--runtime",
            "franken-engine",
            "--console-only",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("SAFE_MODE_GUEST_RAN"));
}

fn current_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn persist_crash_observation(
    scope: &Path,
    app: &Path,
    nonce: &str,
    observed: u64,
) -> frankenengine_node::runtime::safe_mode::CrashLoopObservation {
    // This exercises the actual store API with observation metadata. The
    // engine's separate typed-error tests cover classification/authentication.
    record_native_crash(
        scope,
        app,
        nonce,
        observed,
        true,
        &scope
            .join("retained-captures")
            .join(format!("{nonce}.json")),
    )
    .unwrap()
}

#[test]
fn persisted_crash_threshold_activates_real_execution_admission() {
    let directory = tempfile::tempdir().unwrap();
    let scope = directory.path().canonicalize().unwrap();
    let app = entry(&scope);
    let observed = current_epoch_secs();
    for expected in 1..=3 {
        let result =
            persist_crash_observation(&scope, &app, &uuid::Uuid::now_v7().to_string(), observed);
        assert_eq!(result.crashes_in_window, expected);
        assert_eq!(result.safe_mode_active, expected == 3);
        let reloaded = read_persisted_safe_mode(&state_path(&scope))
            .unwrap()
            .unwrap();
        assert_eq!(reloaded.is_active(), expected == 3);
    }
    let error = enforce_run_safe_mode(&app).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("run blocked by active safe mode")
    );
    let controller = read_persisted_safe_mode(&state_path(&scope))
        .unwrap()
        .unwrap();
    assert_eq!(
        controller.entry_reason(),
        Some(&SafeModeEntryReason::CrashLoop {
            crash_count: 3,
            window_secs: 60,
        })
    );
}

#[test]
fn concurrent_crash_updates_retain_every_attempt_and_activate_once() {
    use std::sync::{Arc, Barrier};

    let directory = tempfile::tempdir().unwrap();
    let scope = directory.path().canonicalize().unwrap();
    let app = entry(&scope);
    let observed = current_epoch_secs();
    let barrier = Arc::new(Barrier::new(12));
    let workers: Vec<_> = (0..12)
        .map(|_| {
            let scope = scope.clone();
            let app = app.clone();
            let barrier = Arc::clone(&barrier);
            let nonce = uuid::Uuid::now_v7().to_string();
            std::thread::spawn(move || {
                barrier.wait();
                persist_crash_observation(&scope, &app, &nonce, observed)
            })
        })
        .collect();
    let results: Vec<_> = workers
        .into_iter()
        .map(|worker| worker.join().unwrap())
        .collect();
    assert_eq!(
        results
            .iter()
            .filter(|result| result.safe_mode_activated)
            .count(),
        1
    );
    assert_eq!(
        results.iter().map(|result| result.crashes_in_window).max(),
        Some(12)
    );
    let controller = read_persisted_safe_mode(&state_path(&scope))
        .unwrap()
        .unwrap();
    let persisted = serde_json::to_value(&controller).unwrap();
    assert_eq!(persisted["native_crashes"].as_array().unwrap().len(), 12);
    assert_eq!(
        controller
            .events()
            .iter()
            .filter(|event| event.code == "SMO-001")
            .count(),
        1
    );
    assert!(controller.is_active());
}

#[test]
fn cli_entry_and_recovery_preserve_crash_identity_and_denied_exit_audit() {
    let directory = initialized_project();
    let scope = directory.path().canonicalize().unwrap();
    let app = scope.join("app.js");
    let nonce = uuid::Uuid::now_v7().to_string();
    let observed = current_epoch_secs();
    persist_crash_observation(&scope, &app, &nonce, observed);

    enter_from_cli(&scope);
    let controller = read_persisted_safe_mode(&state_path(&scope))
        .unwrap()
        .unwrap();
    assert_eq!(
        serde_json::to_value(controller).unwrap()["native_crashes"]
            .as_array()
            .unwrap()
            .len(),
        1,
        "manual entry must not replace the existing controller or forget crash identities"
    );

    let denied = cli(
        &scope,
        &[
            "safe-mode",
            "exit",
            "--operator-id",
            "operator",
            "--confirm",
            "--json",
        ],
    );
    assert!(!denied.status.success());
    let denied_state = read_persisted_safe_mode(&state_path(&scope))
        .unwrap()
        .unwrap();
    assert!(denied_state.is_active());
    assert!(
        denied_state
            .audit_log()
            .iter()
            .any(|entry| { matches!(&entry.action, SafeModeAction::ExitDenied) })
    );

    let recovered = cli(
        &scope,
        &[
            "safe-mode",
            "exit",
            "--operator-id",
            "operator",
            "--confirm",
            "--trust-state-consistent",
            "--no-unresolved-incidents",
            "--evidence-ledger-intact",
            "--json",
        ],
    );
    assert!(
        recovered.status.success(),
        "{}",
        String::from_utf8_lossy(&recovered.stderr)
    );
    let retry = persist_crash_observation(&scope, &app, &nonce, observed);
    assert!(retry.duplicate);
    assert!(!retry.counted);
    assert_eq!(retry.crashes_in_window, 0);
    assert!(!retry.safe_mode_active);
    enforce_run_safe_mode(&app).unwrap();
    let new_attempt = persist_crash_observation(
        &scope,
        &app,
        &uuid::Uuid::now_v7().to_string(),
        current_epoch_secs(),
    );
    assert_eq!(new_attempt.crashes_in_window, 1);
    assert!(!new_attempt.safe_mode_active);
}

#[test]
fn failed_safe_mode_transaction_leaves_prior_restriction_and_bytes_intact() {
    let directory = tempfile::tempdir().unwrap();
    let app = entry(directory.path());
    persist(directory.path(), &active_controller());
    let path = state_path(directory.path());
    let original = fs::read(&path).unwrap();
    let result: anyhow::Result<()> = update_persisted_safe_mode(&path, false, |controller| {
        controller.exit_safe_mode(&exit_checks(), "operator", "2026-10-10T00:01:00Z")?;
        anyhow::bail!("abort before commit")
    });
    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("abort before commit")
    );
    assert_eq!(fs::read(&path).unwrap(), original);
    assert!(enforce_run_safe_mode(&app).is_err());
}

#[test]
fn crash_accounting_uses_retained_entrypoint_even_if_guest_renamed_it() {
    let directory = tempfile::tempdir().unwrap();
    let scope = directory.path().canonicalize().unwrap();
    let app = entry(&scope);
    fs::rename(&app, scope.join("renamed-by-guest.js")).unwrap();
    let result = persist_crash_observation(
        &scope,
        &app,
        &uuid::Uuid::now_v7().to_string(),
        current_epoch_secs(),
    );
    assert_eq!(result.entrypoint, app.to_str().unwrap());
    assert_eq!(result.crashes_in_window, 1);
    assert!(Path::new(&result.state_path).is_file());
}

#[cfg(unix)]
#[test]
fn symlinked_safe_mode_lock_is_refused_without_modifying_controller() {
    use std::os::unix::fs::symlink;

    let directory = tempfile::tempdir().unwrap();
    entry(directory.path());
    persist(directory.path(), &active_controller());
    let path = state_path(directory.path());
    let original = fs::read(&path).unwrap();
    let target = directory.path().join("unrelated-file");
    fs::write(&target, b"preserve me").unwrap();
    symlink(&target, path.with_extension("lock")).unwrap();
    let result = update_persisted_safe_mode(&path, false, |controller| {
        controller.set_unresolved_incidents(99);
        Ok(())
    });
    assert!(result.is_err());
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(fs::read(&target).unwrap(), b"preserve me");
}

#[cfg(feature = "engine")]
#[test]
fn repeated_real_guest_exceptions_do_not_enter_native_crash_safe_mode() {
    let directory = initialized_project();
    fs::write(
        directory.path().join("app.js"),
        "console.log('GUEST_EXCEPTION_REACHED'); throw new Error('ordinary application failure');",
    )
    .unwrap();
    for _ in 0..3 {
        let output = cli(
            directory.path(),
            &[
                "run",
                "app.js",
                "--policy",
                "balanced",
                "--runtime",
                "franken-engine",
                "--json",
            ],
        );
        assert!(!output.status.success());
        let report: serde_json::Value = serde_json::from_slice(&output.stdout)
            .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stdout)));
        assert!(
            report.to_string().contains("GUEST_EXCEPTION_REACHED"),
            "the guest must actually have run before throwing: {report}"
        );
        assert_ne!(report["outcome"], "native_engine_panic");
    }
    let state =
        read_persisted_safe_mode(&directory.path().join(".franken-node/safe-mode/state.json"))
            .unwrap();
    assert!(
        state.is_none(),
        "ordinary guest exceptions must not create crash state"
    );
}

#[test]
fn containment_gate_typestate_permit_enforces_and_rechecks_all_scopes() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("workspace/service");
    let release = project.join("releases/1.0.0");
    let app = entry(&release);

    let project_permit = ContainmentGate::acquire_project(&project).unwrap();
    assert_eq!(project_permit.scope_kind(), ContainmentScopeKind::Project);
    assert_eq!(
        project_permit.project_root(),
        project.canonicalize().unwrap().as_path()
    );
    project_permit.recheck().unwrap();

    let entry_permit = ContainmentGate::acquire_entrypoint(&release, &app).unwrap();
    assert_eq!(entry_permit.scope_kind(), ContainmentScopeKind::Entrypoint);
    entry_permit.recheck().unwrap();

    let deploy_permit = ContainmentGate::acquire_deploy_release(&release, &app, None).unwrap();
    assert_eq!(
        deploy_permit.scope_kind(),
        ContainmentScopeKind::DeployRelease
    );
    deploy_permit.recheck().unwrap();

    // Activating safe mode on an ancestor invalidates previously acquired permits on recheck
    // and blocks fresh permit issuance across all three containment scopes.
    let mut ancestor_controller = active_controller();
    persist(root.path(), &ancestor_controller);

    let recheck_denial = deploy_permit.recheck().unwrap_err();
    assert_eq!(
        recheck_denial.scope_kind,
        ContainmentScopeKind::DeployRelease
    );
    assert!(
        recheck_denial.reason.contains("active safe mode"),
        "{recheck_denial}"
    );
    assert!(project_permit.recheck().is_err());
    assert!(entry_permit.recheck().is_err());

    let deploy_denial = ContainmentGate::acquire_deploy_release(&release, &app, None).unwrap_err();
    assert_eq!(
        deploy_denial.scope_kind,
        ContainmentScopeKind::DeployRelease
    );
    assert!(
        deploy_denial.reason.contains("active safe mode"),
        "{deploy_denial}"
    );

    ancestor_controller
        .exit_safe_mode(&exit_checks(), "operator", "2026-10-10T00:05:00Z")
        .unwrap();
    persist(root.path(), &ancestor_controller);
    deploy_permit.recheck().unwrap();

    // Release-local malformed safe-mode state fails closed even when ancestor recovered.
    fs::write(state_path(&release), b"{").unwrap();
    let malformed_denial =
        ContainmentGate::acquire_deploy_release(&release, &app, None).unwrap_err();
    assert!(
        malformed_denial.reason.contains("invalid safe-mode state"),
        "{malformed_denial}"
    );
}

#[test]
fn deploy_install_and_activate_refuse_safe_mode_contained_release_and_project() {
    let root = tempfile::tempdir().unwrap();
    let registry = tempfile::tempdir().unwrap();
    let state_home = tempfile::tempdir().unwrap();

    let git = |dir: &Path, args: &[&str]| {
        let status = Command::new("git")
            .current_dir(dir)
            .args(args)
            .status()
            .expect("git");
        assert!(status.success(), "git {}", args.join(" "));
    };
    fs::write(registry.path().join("README"), "publisher workspace\n").unwrap();
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
    .unwrap();
    let public_key = registry.path().join("publisher.pub");
    fs::write(
        &public_key,
        hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[42_u8; 32])
                .verifying_key()
                .as_bytes(),
        ),
    )
    .unwrap();

    let run_cli = |cwd: &Path, args: &[&str]| -> Output {
        Command::new(env!("CARGO_BIN_EXE_franken-node"))
            .current_dir(cwd)
            .env("XDG_STATE_HOME", state_home.path())
            .env("XDG_CONFIG_HOME", state_home.path().join("config"))
            .env_remove("FRANKEN_NODE_PROFILE")
            .env_remove("FRANKEN_NODE_RUNTIME_ALLOW_PROCESS_SHAPE")
            .args(args)
            .output()
            .expect("run CLI")
    };

    let init_root = run_cli(
        root.path(),
        &["init", "--profile", "balanced", "--out-dir", ".", "--json"],
    );
    assert!(
        init_root.status.success(),
        "{}",
        String::from_utf8_lossy(&init_root.stderr)
    );

    let release_dir = root.path().join("releases/1.0.0");
    fs::create_dir_all(&release_dir).unwrap();
    fs::write(release_dir.join("app.js"), "console.log('DEPLOYED_V1');\n").unwrap();
    fs::write(
        release_dir.join("package.json"),
        "{\"name\":\"deployed-app\",\"version\":\"1.0.0\"}\n",
    )
    .unwrap();
    let init_rel = run_cli(
        &release_dir,
        &["init", "--profile", "balanced", "--out-dir", ".", "--json"],
    );
    assert!(
        init_rel.status.success(),
        "{}",
        String::from_utf8_lossy(&init_rel.stderr)
    );

    let sg = run_cli(
        registry.path(),
        &[
            "verify",
            "source-graph",
            release_dir.to_str().unwrap(),
            "app.js",
            "--write-source-capsule",
            "app-1.0.0.capsule",
            "--json",
        ],
    );
    assert!(
        sg.status.success(),
        "{}",
        String::from_utf8_lossy(&sg.stderr)
    );
    let pub_out = run_cli(
        registry.path(),
        &[
            "registry",
            "publish",
            "app-1.0.0.capsule",
            "--version",
            "1.0.0",
            "--signing-key",
            "publisher.ed25519",
            "--json",
        ],
    );
    assert!(
        pub_out.status.success(),
        "{}",
        String::from_utf8_lossy(&pub_out.stderr)
    );
    let published: serde_json::Value = serde_json::from_slice(&pub_out.stdout).unwrap();
    let manifest = registry
        .path()
        .join(published["manifest_path"].as_str().unwrap());

    // 1. Entering safe mode on the release directory blocks `deploy install`.
    enter_from_cli(&release_dir);
    let refused_install = run_cli(
        root.path(),
        &[
            "deploy",
            "install",
            "app",
            "--release-dir",
            release_dir.to_str().unwrap(),
            "--entrypoint",
            "app.js",
            "--registry-artifact",
            manifest.to_str().unwrap(),
            "--publisher-public-key",
            public_key.to_str().unwrap(),
            "--json",
        ],
    );
    assert!(!refused_install.status.success());
    let install_err: serde_json::Value = serde_json::from_slice(&refused_install.stdout).unwrap();
    assert_eq!(install_err["ok"], false, "{install_err}");
    assert!(
        install_err["error"]
            .as_str()
            .unwrap()
            .contains("safe-mode containment"),
        "{install_err}"
    );
    assert!(
        !root
            .path()
            .join(".franken-node/deployments/app/releases/1.0.0.json")
            .exists()
    );

    // Recover release safe mode so `deploy install` succeeds cleanly.
    let exit_rel = run_cli(
        &release_dir,
        &[
            "safe-mode",
            "exit",
            "--operator-id",
            "operator",
            "--confirm",
            "--trust-state-consistent",
            "--no-unresolved-incidents",
            "--evidence-ledger-intact",
            "--json",
        ],
    );
    assert!(
        exit_rel.status.success(),
        "{}",
        String::from_utf8_lossy(&exit_rel.stderr)
    );
    let ok_install = run_cli(
        root.path(),
        &[
            "deploy",
            "install",
            "app",
            "--release-dir",
            release_dir.to_str().unwrap(),
            "--entrypoint",
            "app.js",
            "--registry-artifact",
            manifest.to_str().unwrap(),
            "--publisher-public-key",
            public_key.to_str().unwrap(),
            "--json",
        ],
    );
    assert!(
        ok_install.status.success(),
        "{}",
        String::from_utf8_lossy(&ok_install.stderr)
    );

    // 2. Entering safe mode on the release directory after install blocks `deploy activate`
    // before `active.json` is written.
    enter_from_cli(&release_dir);
    let refused_activate = run_cli(
        root.path(),
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
    );
    assert!(!refused_activate.status.success());
    let activate_err: serde_json::Value = serde_json::from_slice(&refused_activate.stdout).unwrap();
    assert_eq!(activate_err["ok"], false, "{activate_err}");
    assert!(
        activate_err["error"]
            .as_str()
            .unwrap()
            .contains("safe-mode containment"),
        "{activate_err}"
    );
    assert!(
        !root
            .path()
            .join(".franken-node/deployments/app/active.json")
            .exists()
    );

    // 3. Even after release safe mode exits, active safe mode on the ancestor deployment root
    // also blocks `deploy activate`.
    let exit_rel_again = run_cli(
        &release_dir,
        &[
            "safe-mode",
            "exit",
            "--operator-id",
            "operator",
            "--confirm",
            "--trust-state-consistent",
            "--no-unresolved-incidents",
            "--evidence-ledger-intact",
            "--json",
        ],
    );
    assert!(exit_rel_again.status.success());
    enter_from_cli(root.path());
    let ancestor_refused = run_cli(
        root.path(),
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
    );
    assert!(!ancestor_refused.status.success());
    let ancestor_err: serde_json::Value = serde_json::from_slice(&ancestor_refused.stdout).unwrap();
    assert!(
        ancestor_err["error"]
            .as_str()
            .unwrap()
            .contains("safe-mode containment"),
        "{ancestor_err}"
    );
    assert!(
        !root
            .path()
            .join(".franken-node/deployments/app/active.json")
            .exists()
    );
}

#[test]
fn migrate_rollout_ed25519_transition_signatures_and_deployment_store_sync() {
    use frankenengine_node::migration::rollout::RolloutReport;
    use frankenengine_node::runtime::deployment::{
        DeploymentAuthority, DeploymentStore, HealthEvent,
    };
    use std::os::unix::fs::PermissionsExt;

    let outer = tempfile::tempdir().unwrap();
    let root = outer.path().join("project");
    fs::create_dir_all(&root).unwrap();
    let registry = tempfile::tempdir().unwrap();
    let state_home = tempfile::tempdir().unwrap();

    let git = |dir: &Path, args: &[&str]| {
        let out = Command::new("git")
            .current_dir(dir)
            .args(args)
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
    };
    git(registry.path(), &["init", "-q", "-b", "main"]);
    git(
        registry.path(),
        &["config", "user.email", "test@franken-node.invalid"],
    );
    git(registry.path(), &["config", "user.name", "Rollout Test"]);
    git(
        registry.path(),
        &[
            "remote",
            "add",
            "origin",
            "https://example.com/acme/rollout-app.git",
        ],
    );
    fs::write(
        registry.path().join("README"),
        "rollout deployment registry\n",
    )
    .unwrap();
    git(registry.path(), &["add", "README"]);
    git(registry.path(), &["commit", "-q", "-m", "initial"]);

    fs::write(
        registry.path().join("publisher.ed25519"),
        hex::encode([51_u8; 32]),
    )
    .unwrap();
    let publisher_pub = registry.path().join("publisher.pub");
    fs::write(
        &publisher_pub,
        hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[51_u8; 32])
                .verifying_key()
                .as_bytes(),
        ),
    )
    .unwrap();

    // Operator Ed25519 rollout keypair: public anchor inside project, 0o600 seed outside project.
    let rollout_sk = ed25519_dalek::SigningKey::from_bytes(&[77_u8; 32]);
    let rollout_vk = rollout_sk.verifying_key();
    let rollout_seed = outer.path().join("rollout-operator.seed");
    fs::write(&rollout_seed, rollout_sk.to_bytes()).unwrap();
    fs::set_permissions(&rollout_seed, fs::Permissions::from_mode(0o600)).unwrap();

    let run_cli = |cwd: &Path, args: &[&str]| -> Output {
        Command::new(env!("CARGO_BIN_EXE_franken-node"))
            .current_dir(cwd)
            .env("XDG_STATE_HOME", state_home.path())
            .env("XDG_CONFIG_HOME", state_home.path().join("config"))
            .env_remove("FRANKEN_NODE_PROFILE")
            .env_remove("FRANKEN_NODE_ROLLOUT_SIGNING_KEY")
            .args(args)
            .output()
            .expect("run CLI")
    };

    assert!(
        run_cli(
            &root,
            &["init", "--profile", "balanced", "--out-dir", ".", "--json"]
        )
        .status
        .success()
    );
    fs::create_dir_all(root.join(".franken-node/keys")).unwrap();
    fs::write(
        root.join(".franken-node/keys/migration-rollout.pub"),
        hex::encode(rollout_vk.to_bytes()),
    )
    .unwrap();

    let install_release = |ver: &str, banner: &str| {
        let rel_dir = root.join(format!("releases/{ver}"));
        fs::create_dir_all(&rel_dir).unwrap();
        fs::write(
            rel_dir.join("app.js"),
            format!("console.log('{banner}');\n"),
        )
        .unwrap();
        fs::write(
            rel_dir.join("package.json"),
            format!("{{\"name\":\"rollout-app\",\"version\":\"{ver}\"}}\n"),
        )
        .unwrap();
        assert!(
            run_cli(
                &rel_dir,
                &["init", "--profile", "balanced", "--out-dir", ".", "--json"]
            )
            .status
            .success()
        );
        let cap_name = format!("app-{ver}.capsule");
        assert!(
            run_cli(
                registry.path(),
                &[
                    "verify",
                    "source-graph",
                    rel_dir.to_str().unwrap(),
                    "app.js",
                    "--write-source-capsule",
                    &cap_name,
                    "--json",
                ],
            )
            .status
            .success()
        );
        let pub_out = run_cli(
            registry.path(),
            &[
                "registry",
                "publish",
                &cap_name,
                "--version",
                ver,
                "--signing-key",
                "publisher.ed25519",
                "--json",
            ],
        );
        assert!(
            pub_out.status.success(),
            "stdout={} stderr={}",
            String::from_utf8_lossy(&pub_out.stdout),
            String::from_utf8_lossy(&pub_out.stderr)
        );
        let published: serde_json::Value = serde_json::from_slice(&pub_out.stdout).unwrap();
        let manifest = registry
            .path()
            .join(published["manifest_path"].as_str().unwrap());
        let inst = run_cli(
            &root,
            &[
                "deploy",
                "install",
                "app",
                "--release-dir",
                rel_dir.to_str().unwrap(),
                "--entrypoint",
                "app.js",
                "--registry-artifact",
                manifest.to_str().unwrap(),
                "--publisher-public-key",
                publisher_pub.to_str().unwrap(),
                "--json",
            ],
        );
        assert!(
            inst.status.success(),
            "{}",
            String::from_utf8_lossy(&inst.stderr)
        );
    };

    install_release("1.0.0", "KNOWN_GOOD_V1");
    install_release("2.0.0", "CANDIDATE_V2");

    // Activate 1.0.0 and record one verified healthy run so 1.0.0 is an eligible known-good release.
    let act_v1 = run_cli(
        &root,
        &[
            "deploy",
            "activate",
            "app",
            "--release",
            "1.0.0",
            "--operator-id",
            "ops-init",
            "--json",
        ],
    );
    assert!(act_v1.status.success());
    {
        let key_hex =
            fs::read_to_string(root.join(".franken-node/keys/receipt-signing.key")).unwrap();
        let seed_bytes: [u8; 32] = hex::decode(key_hex.trim()).unwrap().try_into().unwrap();
        let authority =
            DeploymentAuthority::new(ed25519_dalek::SigningKey::from_bytes(&seed_bytes));
        let store = DeploymentStore::open(&root, "app").unwrap();
        let lock = store.lock().unwrap();
        store
            .record_health(
                &lock,
                &authority,
                "1.0.0",
                HealthEvent::HealthyRun {
                    receipt_id: "rcpt-v1-healthy-001".to_string(),
                    observed_at_epoch_secs: 1_700_000_000,
                },
            )
            .unwrap();
    }

    // Promote rollout to Default synchronized with DeploymentStore `app` -> release `2.0.0`.
    let promote_out = run_cli(
        outer.path(),
        &[
            "migrate",
            "rollout",
            root.to_str().unwrap(),
            "--migration-id",
            "mig-ed25519-sync",
            "--signing-key",
            rollout_seed.to_str().unwrap(),
            "--stage",
            "default",
            "--force",
            "--deployment",
            "app",
            "--release",
            "2.0.0",
            "--operator-id",
            "ops-rollout",
            "--json",
        ],
    );
    assert!(
        promote_out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&promote_out.stdout),
        String::from_utf8_lossy(&promote_out.stderr)
    );
    let promote_report: RolloutReport = serde_json::from_slice(&promote_out.stdout).unwrap();
    assert!(promote_report.ok);
    assert_eq!(promote_report.history.len(), 1);
    let promote_ev = &promote_report.history[0];
    assert_eq!(
        promote_ev
            .transition_ed25519_signature
            .as_deref()
            .map(str::len),
        Some(128)
    );
    promote_ev
        .verify_transition_signature("mig-ed25519-sync", &rollout_vk)
        .expect("Ed25519 transition signature verifies");

    // Mutating the reason invalidates the Ed25519 transition signature.
    let mut tampered_ev = promote_ev.clone();
    tampered_ev.reason.push_str(" (forged)");
    assert!(
        tampered_ev
            .verify_transition_signature("mig-ed25519-sync", &rollout_vk)
            .is_err()
    );

    let sync = promote_report
        .deployment_sync
        .as_ref()
        .expect("deployment_sync populated");
    assert_eq!(sync.deployment, "app");
    assert_eq!(sync.action, "activated");
    assert_eq!(sync.active_release_id, "2.0.0");

    // Rolling back `migrate rollout` signs `rollback_started` + `rollback` transitions AND
    // rolls DeploymentStore `app` back to known-good release `1.0.0`.
    let rb_out = run_cli(
        outer.path(),
        &[
            "migrate",
            "rollout",
            root.to_str().unwrap(),
            "--migration-id",
            "mig-ed25519-sync",
            "--action",
            "rollback",
            "--signing-key",
            rollout_seed.to_str().unwrap(),
            "--deployment",
            "app",
            "--operator-id",
            "ops-rollout",
            "--json",
        ],
    );
    assert!(
        rb_out.status.success(),
        "stdout={} stderr={}",
        String::from_utf8_lossy(&rb_out.stdout),
        String::from_utf8_lossy(&rb_out.stderr)
    );
    let rb_report: RolloutReport = serde_json::from_slice(&rb_out.stdout).unwrap();
    assert_eq!(rb_report.history.len(), 3);
    for ev in &rb_report.history {
        ev.verify_transition_signature("mig-ed25519-sync", &rollout_vk)
            .expect("every rollout transition event is Ed25519-signed");
    }
    let rb_sync = rb_report
        .deployment_sync
        .as_ref()
        .expect("rollback deployment_sync populated");
    assert_eq!(rb_sync.action, "rolled_back_to_known_good");
    assert_eq!(rb_sync.active_release_id, "1.0.0");
}
