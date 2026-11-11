use super::*;
use crate::runtime::safe_mode::{
    ExitVerification, OperationFlags, SafeModeController, SafeModeEntryReason,
};
use std::thread;

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(40)
}

fn put(root: &Path, path: &str, bytes: impl AsRef<[u8]>) {
    let path = root.join(path);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, bytes).unwrap();
}

pub(super) fn active_controller() -> SafeModeController {
    let mut controller = SafeModeController::with_default_config();
    controller.set_flags(OperationFlags::safe_mode_only());
    controller.enter_safe_mode(
        SafeModeEntryReason::ExplicitFlag,
        "2026-11-11T00:00:00Z",
        "trusted",
        Vec::new(),
    );
    controller
}

pub(super) fn persist(scope: &Path, controller: &SafeModeController) {
    put(
        scope,
        ".franken-node/safe-mode/state.json",
        serde_json::to_vec(controller).unwrap(),
    );
}

fn invocation(role: &str) -> Invocation {
    Invocation {
        executable: node_on_path().unwrap(),
        before: Vec::new(),
        after: vec![role.into()],
    }
}

fn measure(original: &Snapshot, candidate: &Snapshot) -> Result<SuiteReport> {
    execute_suite_pair(
        original,
        candidate,
        &invocation("reference"),
        &invocation("native"),
        deadline(),
        Duration::from_secs(15),
        false,
    )
}

fn product(original: &Snapshot, candidate: &Snapshot) -> Result<product_oracle::ProductReport> {
    // Three explicit Node roles test containment/orchestration, not runtime
    // independence or successful execution by Bun/Franken.
    let node = invocation("node");
    let bun = invocation("bun");
    let native = invocation("native");
    let identities = [
        node.identity(deadline()).unwrap(),
        bun.identity(deadline()).unwrap(),
        native.identity(deadline()).unwrap(),
    ];
    product_oracle::execute(
        original,
        candidate,
        [&node, &bun, &native],
        identities,
        deadline(),
        Duration::from_secs(15),
        false,
    )
}

fn error_text<T>(result: Result<T>) -> String {
    format!("{:#}", result.err().expect("containment must refuse"))
}

#[test]
fn safe_mode_admits_missing_state_and_legitimately_recovered_controller() {
    for recovered in [false, true] {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "case.test.cjs", "console.log(42);");
        if recovered {
            let mut controller = active_controller();
            controller
                .exit_safe_mode(
                    &ExitVerification {
                        trust_state_consistent: true,
                        no_unresolved_incidents: true,
                        evidence_ledger_intact: true,
                        operator_confirmed: true,
                    },
                    "operator",
                    "2026-11-11T00:01:00Z",
                )
                .unwrap();
            assert!(!controller.is_active() && controller.flags().safe_mode);
            persist(root.path(), &controller);
        }
        let snapshot = Snapshot::capture(root.path(), deadline()).unwrap();
        assert_eq!(measure(&snapshot, &snapshot).unwrap().verdict, "PASS");
        assert_eq!(product(&snapshot, &snapshot).unwrap().verdict, "PASS");
    }
}

#[test]
fn safe_mode_original_candidate_and_nested_scopes_refuse_before_any_role() {
    for selected in ["original", "candidate", "nested"] {
        let root = tempfile::tempdir().unwrap();
        let original = root.path().join("reference/project");
        let candidate = root.path().join("native/project");
        let marker = root.path().join("guest-ran");
        let source = format!(
            "require('fs').writeFileSync({}, 'ran');",
            serde_json::to_string(&marker).unwrap()
        );
        for project in [&original, &candidate] {
            put(project, "nested/case.test.cjs", &source);
        }
        let before = Snapshot::capture(&original, deadline()).unwrap();
        let after = Snapshot::capture(&candidate, deadline()).unwrap();
        let scope = match selected {
            "original" => original.parent().unwrap().to_path_buf(),
            "candidate" => candidate.parent().unwrap().to_path_buf(),
            _ => original.join("nested"),
        };
        persist(&scope, &active_controller());
        // Static capture and inventory inspection remain available.
        assert_eq!(
            Snapshot::capture(&original, deadline())
                .unwrap()
                .tests()
                .unwrap(),
            vec![PathBuf::from("nested/case.test.cjs")]
        );
        assert!(error_text(measure(&before, &after)).contains("safe"));
        assert!(error_text(product(&before, &after)).contains("safe"));
        assert!(
            !marker.exists(),
            "a role executed before all scopes were admitted"
        );
    }
}

#[test]
fn safe_mode_implicit_link_into_protected_scope_refuses_the_entire_inventory() {
    for malformed in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        let marker = root.path().join("guest-ran");
        let source = format!(
            "require('fs').appendFileSync({},'ran');",
            serde_json::to_string(&marker).unwrap()
        );
        put(&project, "protected/entry.js", &source);
        put(&project, "ordinary.test.js", &source);
        symlink("protected/entry.js", project.join("case.test.js")).unwrap();
        if malformed {
            put(
                &project,
                "protected/.franken-node/safe-mode/state.json",
                "{}",
            );
        } else {
            persist(&project.join("protected"), &active_controller());
        }
        let snapshot = Snapshot::capture(&project, deadline()).unwrap();
        let message = error_text(snapshot.tests());
        assert!(
            message.contains("regular captured file") && message.contains("case.test.js"),
            "{message}"
        );
        assert!(error_text(measure(&snapshot, &snapshot)).contains("regular captured file"));
        assert!(error_text(product(&snapshot, &snapshot)).contains("regular captured file"));
        assert!(
            !marker.exists(),
            "a linked or ordinary peer test ran after invalid selection"
        );
    }
}

#[test]
fn safe_mode_captured_active_and_malformed_state_is_not_lost_on_restore() {
    for malformed in [false, true] {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "nested/case.test.cjs", "console.log(42);");
        if malformed {
            put(
                root.path(),
                "nested/.franken-node/safe-mode/state.json",
                "{}",
            );
        } else {
            persist(&root.path().join("nested"), &active_controller());
        }
        let captured = Snapshot::capture(root.path(), deadline()).unwrap();
        let restored = Snapshot::from_entries(captured.entries.clone());
        assert!(restored.origin.is_none());
        assert_eq!(captured.digest, restored.digest);
        let message = error_text(ExecutionControl::admit(&[&restored]));
        assert!(message.contains("captured safe"), "{message}");
    }
}

#[test]
fn safe_mode_malformed_and_nonregular_live_state_fail_closed_before_dispatch() {
    for kind in ["malformed", "directory", "symlink"] {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        put(&project, "case.test.cjs", "console.log(42);");
        let snapshot = Snapshot::capture(&project, deadline()).unwrap();
        let state = root.path().join(".franken-node/safe-mode/state.json");
        fs::create_dir_all(state.parent().unwrap()).unwrap();
        match kind {
            "malformed" => fs::write(&state, b"not a controller").unwrap(),
            "directory" => fs::create_dir(&state).unwrap(),
            _ => {
                let target = root.path().join("other.json");
                fs::write(
                    &target,
                    serde_json::to_vec(&SafeModeController::with_default_config()).unwrap(),
                )
                .unwrap();
                symlink(target, &state).unwrap();
            }
        }
        assert!(measure(&snapshot, &snapshot).is_err(), "{kind}");
        assert!(product(&snapshot, &snapshot).is_err(), "{kind}");
    }
}

#[test]
fn safe_mode_source_alias_rebinding_is_rejected_before_admission() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    let replacement = root.path().join("replacement");
    put(&project, "case.test.cjs", "console.log(42);");
    put(&replacement, "case.test.cjs", "console.log(42);");
    let snapshot = Snapshot::capture(&project, deadline()).unwrap();
    fs::rename(&project, root.path().join("retained-original")).unwrap();
    symlink(&replacement, &project).unwrap();
    assert!(error_text(ExecutionControl::admit(&[&snapshot])).contains("became an alias"));
}

fn activate_after_ready(scope: &Path, ready: &Path, malformed: bool) -> u32 {
    let limit = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(raw) = fs::read_to_string(ready)
            && let Ok(pid) = raw.parse()
        {
            if malformed {
                put(scope, ".franken-node/safe-mode/state.json", "{invalid");
            } else {
                persist(scope, &active_controller());
            }
            return pid;
        }
        assert!(
            Instant::now() < limit,
            "guest never reached the supervised boundary"
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn safe_mode_late_change_stops_and_reaps_silent_reference_with_file_or_pipe_input() {
    for pipe in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let project = root.path().join("project");
        let ready = root.path().join("ready");
        let native = root.path().join("native-ran");
        put(
            &project,
            "case.test.cjs",
            format!(
                "const fs=require('fs');if(process.argv[2]==='native'){{fs.writeFileSync({},'ran')}}else{{fs.writeFileSync({},String(process.pid));setInterval(()=>{{}},1000)}}",
                serde_json::to_string(&native).unwrap(),
                serde_json::to_string(&ready).unwrap(),
            ),
        );
        if pipe {
            put(&project, "request.bin", vec![b'x'; 1024 * 1024]);
            put(
                &project,
                ".franken-node/migration-tests.json",
                serde_json::to_vec(&serde_json::json!({
                    "schema_version":"franken-node/migration-tests/v1", "tests":["case.test.cjs"],
                    "execution":{"case.test.cjs":{"stdin":"request.bin","stdin_mode":"pipe"}}
                }))
                .unwrap(),
            );
        }
        let snapshot = Snapshot::capture(&project, deadline()).unwrap();
        let (report, pid) = thread::scope(|threads| {
            let operator = threads.spawn(|| activate_after_ready(root.path(), &ready, pipe));
            let report = measure(&snapshot, &snapshot).unwrap();
            (report, operator.join().unwrap())
        });
        assert_eq!(report.verdict, "ERROR", "{report:#?}");
        assert!(
            report.cases[0]
                .errors
                .iter()
                .any(|error| error.contains("safe")),
            "{report:#?}"
        );
        assert!(report.cases[0].native.is_none() && !native.exists());
        assert!(
            !Path::new("/proc").join(pid.to_string()).exists(),
            "leader was not reaped"
        );
    }
}

#[test]
fn safe_mode_candidate_activation_during_bun_stops_product_without_native_dispatch() {
    let root = tempfile::tempdir().unwrap();
    let original = root.path().join("reference/project");
    let candidate = root.path().join("native/project");
    let ready = root.path().join("ready");
    let native = root.path().join("native-ran");
    let source = format!(
        "const fs=require('fs');if(process.argv[2]==='bun'){{fs.writeFileSync({},String(process.pid));setInterval(()=>{{}},1000)}}else if(process.argv[2]==='native'){{fs.writeFileSync({},'ran')}}else{{console.log(42)}}",
        serde_json::to_string(&ready).unwrap(),
        serde_json::to_string(&native).unwrap(),
    );
    for project in [&original, &candidate] {
        put(project, "case.test.cjs", &source);
    }
    let before = Snapshot::capture(&original, deadline()).unwrap();
    let after = Snapshot::capture(&candidate, deadline()).unwrap();
    let (report, pid) = thread::scope(|threads| {
        let operator =
            threads.spawn(|| activate_after_ready(candidate.parent().unwrap(), &ready, false));
        let report = product(&before, &after).unwrap();
        (report, operator.join().unwrap())
    });
    assert_eq!(report.verdict, "ERROR", "{report:#?}");
    assert!(report.cases[0].node.is_some() && report.cases[0].native.is_none());
    assert!(!native.exists());
    assert!(
        !Path::new("/proc").join(pid.to_string()).exists(),
        "Bun-role leader was not reaped"
    );
}
