//! Deployment eligibility must recheck dependency authority at every pointer
//! boundary, even when the publisher approval and healthy history remain valid.

use super::*;

fn scanned_workspace_release(drill: &Drill) -> (PathBuf, PathBuf) {
    let (directory, manifest) = drill.publish_workspace_release("1.0.0", false);
    drill.ok(&directory, &["trust", "scan", ".", "--json"]);
    (directory, manifest)
}

fn revoke_shared(drill: &Drill, directory: &Path) {
    let revoked = drill.ok(directory, &["trust", "revoke", "npm:shared", "--json"]);
    assert_eq!(
        revoked["extension"]["extension_id"], "npm:shared",
        "{revoked}"
    );
    assert_eq!(
        revoked["revocation_status"]["status"], "revoked",
        "{revoked}"
    );
}

fn assert_dependency_refusal(report: &Value) {
    assert_eq!(report["ok"], false, "{report}");
    let reason = report["error"].as_str().expect("typed refusal reason");
    assert!(
        reason.contains("trust admission")
            && reason.contains("npm:shared")
            && reason.contains("revoked"),
        "{report}"
    );
}

fn refused(output: Output) -> Value {
    assert!(
        !output.status.success(),
        "revoked dependency was admitted: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let report: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "dependency refusal must emit JSON ({error}): {}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    });
    assert_dependency_refusal(&report);
    report
}

#[test]
fn dependency_revocation_refuses_install_without_recording_the_release() {
    let drill = Drill::new();
    drill.install("0.9.0", HEALTHY_V1);
    let (directory, manifest) = scanned_workspace_release(&drill);
    revoke_shared(&drill, &directory);
    let before = drill.status();

    refused(drill.cli(
        drill.root.path(),
        &[
            "deploy",
            "install",
            "app",
            "--release-dir",
            directory.to_str().unwrap(),
            "--entrypoint",
            "app.js",
            "--registry-artifact",
            manifest.to_str().unwrap(),
            "--publisher-public-key",
            drill.public_key.to_str().unwrap(),
            "--json",
        ],
    ));

    assert_eq!(drill.status(), before, "refusal must not admit a release");
    assert!(!drill.state_path("active.json").exists());
}

#[test]
fn dependency_revocation_after_install_refuses_activation_before_pointer_change() {
    let drill = Drill::new();
    let (directory, manifest) = scanned_workspace_release(&drill);
    drill.install_published("1.0.0", &directory, &manifest);
    revoke_shared(&drill, &directory);
    let before = drill.status();

    refused(drill.cli(
        drill.root.path(),
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
    ));

    assert_eq!(drill.status(), before, "refusal must not record activation");
    assert!(!drill.state_path("active.json").exists());
}

#[test]
fn dependency_revocation_after_signed_intent_prevents_reconciliation() {
    let drill = Drill::new();
    let (directory, manifest) = scanned_workspace_release(&drill);
    drill.install_published("1.0.0", &directory, &manifest);
    drill.interrupt_activation("history");
    let intent_path = drill.state_path("transactions/0000000001.json");
    let history_path = drill.state_path("activations/0000000001.json");
    let intent = fs::read(&intent_path).unwrap();
    let history = fs::read(&history_path).unwrap();
    revoke_shared(&drill, &directory);
    let before = drill.status();

    assert_dependency_refusal(&drill.failed_reconcile());

    assert!(!drill.state_path("active.json").exists());
    assert_eq!(fs::read(&intent_path).unwrap(), intent);
    assert_eq!(fs::read(&history_path).unwrap(), history);
    assert_eq!(
        drill.status(),
        before,
        "refusal must retain pending authorization"
    );
}

#[test]
fn dependency_revocation_disqualifies_a_previously_healthy_rollback_candidate() {
    let drill = Drill::new();
    let (directory, manifest) = scanned_workspace_release(&drill);
    drill.install_published("1.0.0", &directory, &manifest);
    drill.install("2.0.0", &crashing_v2());
    drill.policy("rollback", "automatic");
    drill.activate("1.0.0");
    let (code, healthy) = drill.run();
    assert_eq!(code, Some(0), "{healthy}");
    assert_eq!(healthy["phase"], "healthy", "{healthy}");
    assert_eq!(guest_stdout(&healthy["run"]), "WORKSPACE_SELECTED_CJS\n");
    revoke_shared(&drill, &directory);

    drill.activate("2.0.0");
    let (code, report) = drill.crash_until_loop();

    assert_ne!(code, Some(0));
    assert_eq!(report["phase"], "contained_no_known_good", "{report}");
    let refusals = report["recovery"]["candidate_refusals"]
        .as_array()
        .expect("candidate refusals");
    assert_eq!(refusals.len(), 1, "{report}");
    assert_eq!(refusals[0]["release_id"], "1.0.0");
    let reason = refusals[0]["reason"].as_str().expect("dependency refusal");
    assert!(
        reason.contains("trust admission")
            && reason.contains("npm:shared")
            && reason.contains("revoked"),
        "{report}"
    );
    assert!(report.get("resumed").is_none(), "{report}");
    assert_eq!(drill.status()["active"]["release_id"], "2.0.0");
}

#[test]
fn safe_mode_on_release_disqualifies_a_previously_healthy_rollback_candidate() {
    let drill = Drill::new();
    let (directory, manifest) = scanned_workspace_release(&drill);
    drill.install_published("1.0.0", &directory, &manifest);
    drill.install("2.0.0", &crashing_v2());
    drill.policy("rollback", "automatic");
    drill.activate("1.0.0");
    let (code, healthy) = drill.run();
    assert_eq!(code, Some(0), "{healthy}");
    assert_eq!(healthy["phase"], "healthy", "{healthy}");

    drill.ok(
        &directory,
        &[
            "safe-mode",
            "enter",
            "--reason",
            "explicit-flag",
            "--operator-id",
            "ops-contain",
            "--trust-state-hash",
            "operator:contain-1.0.0",
            "--json",
        ],
    );

    drill.activate("2.0.0");
    let (code, report) = drill.crash_until_loop();

    assert_ne!(code, Some(0));
    assert_eq!(report["phase"], "contained_no_known_good", "{report}");
    let refusals = report["recovery"]["candidate_refusals"]
        .as_array()
        .expect("candidate refusals");
    assert_eq!(refusals.len(), 1, "{report}");
    assert_eq!(refusals[0]["release_id"], "1.0.0");
    let reason = refusals[0]["reason"].as_str().expect("safe-mode refusal");
    assert!(reason.contains("safe-mode containment"), "{report}");
    assert!(report.get("resumed").is_none(), "{report}");
    assert_eq!(drill.status()["active"]["release_id"], "2.0.0");
}
