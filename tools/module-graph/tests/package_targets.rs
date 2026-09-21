//! Executable contract and independent Node oracle for package-map selection.
#![cfg(unix)]

use serde_json::{Value, json};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn put(root: &Path, name: &str, source: &str) {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, source).unwrap();
}

fn output(mut command: Command) -> Output {
    let mut child = command.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() { return child.wait_with_output().unwrap(); }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let evidence = child.wait_with_output().unwrap();
            panic!("bounded resolver process timed out: {evidence:?}");
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn run(root: &Path, args: &[&str]) -> (i32, Value) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_franken-module-graph"));
    command.arg(root).args(args);
    let result = output(command);
    let report = serde_json::from_slice(&result.stdout).unwrap_or_else(|_| panic!("{result:?}"));
    (result.status.code().unwrap(), report)
}

fn selected(root: &Path, args: &[&str]) -> Value {
    let (code, report) = run(root, args);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["verdict"], "SELECTED");
    assert_eq!(report["scope"], "package-map-target-selection");
    assert_eq!(report["execution_performed"], false);
    assert_eq!(report["filesystem_verified"], false);
    report
}

fn node(root: &Path, request: &str, esm: bool, extra: &[&str]) -> Value {
    let mut command = Command::new("node");
    command.current_dir(root).env_remove("NODE_OPTIONS").env_remove("NODE_PATH");
    for condition in extra { command.arg(format!("--conditions={condition}")); }
    if esm {
        command.args(["--input-type=module", "-e", r#"
import {fileURLToPath} from 'node:url';
try { console.log(JSON.stringify({target:fileURLToPath(import.meta.resolve(process.argv[1]))})); }
catch (error) { console.log(JSON.stringify({code:error.code})); }
"#]);
    } else {
        command.args(["-e", r#"
try { console.log(JSON.stringify({target:require.resolve(process.argv[1])})); }
catch (error) { console.log(JSON.stringify({code:error.code})); }
"#]);
    }
    command.arg(request);
    let result = output(command);
    assert!(result.status.success(), "{result:?}");
    serde_json::from_slice(&result.stdout).unwrap()
}

fn package(root: &Path, manifest: &str) -> PathBuf {
    put(root, "package.json", "{}");
    let pkg = root.join("node_modules/map-package");
    put(&pkg, "package.json", manifest);
    for name in ["node.cjs", "default.cjs", "import.mjs", "require.cjs", "custom.cjs", "wide/a.js", "special/a.json", "exact.cjs"] {
        put(&pkg, name, "throw new Error('package resolver must not execute this module');");
    }
    pkg
}

#[test]
fn import_and_require_conditions_select_different_targets_without_loading_them() {
    let root = tempfile::tempdir().unwrap();
    let pkg = package(root.path(), r#"{"name":"map-package","exports":{"import":"./import.mjs","require":"./require.cjs"}}"#);
    for (esm, mode, target) in [(true,"import","import.mjs"), (false,"require","require.cjs")] {
        let report = selected(root.path(), &["--resolve-export", ".", "--package-manifest", "node_modules/map-package/package.json", "--condition", "node", "--condition", mode]);
        assert_eq!(report["selection"]["target"], format!("./{target}"));
        assert_eq!(node(root.path(), "map-package", esm, &[])["target"], pkg.join(target).to_str().unwrap());
    }
}

#[test]
fn native_selection_and_input_pin_preserve_order_that_the_legacy_graph_loses() {
    let root = tempfile::tempdir().unwrap();
    let mut old_pin = String::new();
    let mut old_graph = String::new();
    for (index, manifest, target) in [
        (0, r#"{"name":"map-package","exports":{"node":"./node.cjs","default":"./default.cjs"}}"#, "node.cjs"),
        (1, r#"{"name":"map-package","exports":{"default":"./default.cjs","node":"./node.cjs"}}"#, "default.cjs"),
    ] {
        let pkg = package(root.path(), manifest);
        let report = selected(&pkg, &["--resolve-export", "."]);
        assert_eq!(report["selection"]["target"], format!("./{target}"));
        assert_eq!(node(root.path(), "map-package", false, &[])["target"], pkg.join(target).to_str().unwrap());
        let (_, direct) = run(&pkg, &[]);
        if index == 0 {
            old_pin = report["input_hash"].as_str().unwrap().to_owned();
            old_graph = direct["canonical_hash"].as_str().unwrap().to_owned();
        } else {
            assert_ne!(report["input_hash"], old_pin);
            assert_eq!(direct["canonical_hash"], old_graph);
            for pin in [&old_pin, &old_graph] {
                let (code, mismatch) = run(&pkg, &["--resolve-export", ".", "--expected-hash", pin]);
                assert_eq!(code, 1);
                assert_eq!(mismatch["verdict"], "HASH_MISMATCH");
                assert!(mismatch["selection"].is_null());
            }
        }
    }
}

#[test]
fn exact_pattern_suffix_and_null_exclusion_agree_with_node() {
    let root = tempfile::tempdir().unwrap();
    let pkg = package(root.path(), r#"{"name":"map-package","exports":{"./*":"./wide/*.js","./*.json":"./special/*.json","./exact":"./exact.cjs","./private/*":null}}"#);
    for (request, target) in [("./a","wide/a.js"), ("./a.json","special/a.json"), ("./exact","exact.cjs")] {
        let report = selected(&pkg, &["--resolve-export", request]);
        assert_eq!(report["selection"]["target"], format!("./{target}"));
        assert_eq!(node(root.path(), &format!("map-package/{}", &request[2..]), false, &[])["target"], pkg.join(target).to_str().unwrap());
    }
    let (code, report) = run(&pkg, &["--resolve-export", "./private/secret"]);
    assert_eq!(code, 1);
    assert_eq!(report["error_code"], node(root.path(), "map-package/private/secret", false, &[])["code"]);
}

#[test]
fn array_fallback_and_nested_condition_failures_match_node() {
    let root = tempfile::tempdir().unwrap();
    for (exports, target, expected_error) in [
        (r#"["../bad",null,{"browser":"./custom.cjs"},"./node.cjs"]"#, Some("node.cjs"), None),
        (r#"{"node":{"browser":"./custom.cjs"},"default":"./default.cjs"}"#, Some("default.cjs"), None),
        (r#"{"node":null,"default":"./default.cjs"}"#, None, Some("ERR_PACKAGE_PATH_NOT_EXPORTED")),
        (r#"[null,"../bad"]"#, None, Some("ERR_INVALID_PACKAGE_TARGET")),
        (r#"[{"0":"./node.cjs"},"./default.cjs"]"#, None, Some("ERR_INVALID_PACKAGE_CONFIG")),
    ] {
        let pkg = package(root.path(), &format!(r#"{{"name":"map-package","exports":{exports}}}"#));
        let (code, report) = run(&pkg, &["--resolve-export", ".", "--condition", "node", "--condition", "require"]);
        let reference = node(root.path(), "map-package", false, &[]);
        if let Some(target) = target {
            assert_eq!(code, 0, "{report}");
            assert_eq!(report["selection"]["target"], format!("./{target}"));
            assert_eq!(reference["target"], pkg.join(target).to_str().unwrap());
        } else {
            assert_ne!(code, 0, "{report}");
            assert_eq!(report["error_code"], expected_error.unwrap());
            assert_eq!(report["error_code"], reference["code"]);
        }
    }
}

#[test]
fn custom_conditions_and_internal_imports_match_the_independent_resolver() {
    let root = tempfile::tempdir().unwrap();
    let pkg = package(root.path(), r##"{"name":"map-package","imports":{"#local":{"development":"./custom.cjs","default":"./default.cjs"},"#hidden":null}}"##);
    let report = selected(&pkg, &["--resolve-import", "#local", "--condition", "development"]);
    assert_eq!(report["selection"]["target"], "./custom.cjs");
    assert_eq!(node(&pkg, "#local", false, &["development"])["target"], pkg.join("custom.cjs").to_str().unwrap());
    let (_, blocked) = run(&pkg, &["--resolve-import", "#hidden"]);
    assert_eq!(blocked["error_code"], node(&pkg, "#hidden", false, &[])["code"]);
}

#[test]
fn external_imports_are_requests_not_fabricated_installed_paths() {
    let root = tempfile::tempdir().unwrap();
    let pkg = package(root.path(), r##"{"name":"map-package","imports":{"#dep":"other-package/sub"}}"##);
    put(root.path(), "node_modules/other-package/package.json", r#"{"exports":{"./sub":"./entry.cjs"}}"#);
    put(root.path(), "node_modules/other-package/entry.cjs", "throw new Error('never load');");
    let report = selected(&pkg, &["--resolve-import", "#dep"]);
    assert_eq!(report["selection"]["target_kind"], "external_package");
    assert_eq!(report["selection"]["target"], "other-package/sub");
    assert_eq!(node(&pkg, "#dep", false, &[])["target"], root.path().join("node_modules/other-package/entry.cjs").to_str().unwrap());
}

#[test]
fn missing_target_is_selected_without_existence_fallback() {
    let root = tempfile::tempdir().unwrap();
    let pkg = package(root.path(), r#"{"name":"map-package","exports":["./missing.cjs","./node.cjs"]}"#);
    let report = selected(&pkg, &["--resolve-export", "."]);
    assert_eq!(report["selection"]["target"], "./missing.cjs");
    assert_eq!(node(root.path(), "map-package", true, &[])["target"], pkg.join("missing.cjs").to_str().unwrap());
    assert_eq!(node(root.path(), "map-package", false, &[])["code"], "MODULE_NOT_FOUND");
    assert!(!pkg.join("missing.cjs").exists());
}

#[test]
fn traversal_and_ambiguous_json_fail_closed_without_target_execution() {
    let root = tempfile::tempdir().unwrap();
    for source in [r#"{"exports":"./%2e%2e/outside.cjs"}"#, r#"{"exports":{".":"./node.cjs","node":"./default.cjs"}}"#,
        r#"{"exports":"./node.cjs","exports":"./default.cjs"}"#] {
        let pkg = package(root.path(), source);
        let (code, report) = run(&pkg, &["--resolve-export", "."]);
        assert_eq!(code, 2, "{report}");
        assert!(report.get("selection").is_none_or(Value::is_null));
        assert_eq!(report["execution_performed"], false);
    }
    let pkg = package(root.path(), r#"{"exports":{"./*":"./src/*"}}"#);
    for request in ["./../outside", "./%2e%2e/outside", "./node_modules/x"] {
        let (code, report) = run(&pkg, &["--resolve-export", request]);
        assert_eq!(code, 2, "{report}");
        assert_eq!(report["error_code"], "ERR_INVALID_MODULE_SPECIFIER");
    }
}

#[test]
fn descriptor_relative_capture_rejects_links_fifos_and_escaping_names() {
    use std::os::unix::fs::symlink;
    let root = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    put(external.path(), "package.json", r#"{"exports":"./must-not-read.cjs"}"#);
    symlink(external.path(), root.path().join("linked")).unwrap();
    fs::create_dir(root.path().join("final-link")).unwrap();
    symlink(external.path().join("package.json"), root.path().join("final-link/package.json")).unwrap();
    fs::create_dir(root.path().join("fifo")).unwrap();
    assert!(Command::new("mkfifo").arg(root.path().join("fifo/package.json")).status().unwrap().success());
    for path in ["linked/package.json", "final-link/package.json", "fifo/package.json", "../package.json", "./package.json", "x//package.json", "/package.json", "other.json"] {
        let (code, report) = run(root.path(), &["--resolve-export", ".", "--package-manifest", path]);
        assert_eq!(code, 2, "{path}: {report}");
        assert!(!report.to_string().contains("must-not-read"));
        assert_eq!(report["scope"], "package-map-target-selection");
    }
}

#[test]
fn input_pin_relocation_absent_maps_and_exact_conditions_have_explicit_contracts() {
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    let source = r#"{"exports":{"node":"./node.cjs","default":"./default.cjs"}}"#;
    for root in [first.path(), second.path()] { put(root, "package.json", source); }
    let report = selected(first.path(), &["--resolve-export", "."]);
    let pin = report["input_hash"].as_str().unwrap();
    let repeated = selected(second.path(), &["--resolve-export", ".", "--expected-hash", pin]);
    assert_eq!(repeated["expected_hash_matched"], true);
    let default_only = selected(second.path(), &["--resolve-export", ".", "--condition", "default"]);
    assert_eq!(default_only["conditions"], json!(["default"]));
    assert_eq!(default_only["selection"]["target"], "./default.cjs");
    put(first.path(), "package.json", "{}");
    let (code, absent) = run(first.path(), &["--resolve-export", "."]);
    assert_eq!(code, 1);
    assert_eq!(absent["error_code"], "ERR_PACKAGE_MAP_ABSENT");
}

#[test]
fn conflicting_query_modes_and_orphaned_options_are_rejected_by_clap() {
    let root = tempfile::tempdir().unwrap();
    for args in [vec!["--resolve-export", ".", "--resolve-import", "#x"],
        vec!["--resolve-export", ".", "--transitive"],
        vec!["--resolve-export", ".", "--dependency", "x"],
        vec!["--resolve-import", "#x", "--impact", "node_modules/x"],
        vec!["--resolve-export", ".", "--require-resolved"],
        vec!["--resolve-export", ".", "--importer", "package.json"],
        vec!["--condition", "node"], vec!["--package-manifest", "package.json"]] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_franken-module-graph"));
        command.arg(root.path()).args(&args);
        let result = output(command);
        assert_eq!(result.status.code(), Some(2), "{args:?}: {result:?}");
        assert!(result.stdout.is_empty());
    }
}
