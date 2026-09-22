//! Entrypoint graph behavior through the production executable.
#![cfg(unix)]

use serde_json::Value;
use std::path::Path;
use std::process::Command;

fn put(root: &Path, path: &str, source: &str) {
    let path = root.join(path);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(path, source).unwrap();
}

fn run(root: &Path, entry: &str, flags: &[&str]) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_franken-module-graph"))
        .arg(root).args(["--capture-source-graph", entry]).args(flags).output().unwrap();
    let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|e|
        panic!("invalid JSON: {e}; stdout={}; stderr={}",
            String::from_utf8_lossy(&output.stdout), String::from_utf8_lossy(&output.stderr)));
    (output.status.code().unwrap(), report)
}

fn paths(report: &Value) -> Vec<&str> {
    report["source_graph"]["modules"].as_array().unwrap().iter()
        .map(|m| m["id"]["path"].as_str().unwrap()).collect()
}

// Only invoke public resolution APIs. Selected fixture sources deliberately
// throw, so neither this oracle nor the native scanner may load them.
fn assert_node_edges(root: &Path, report: &Value) {
    let script = r#"
import {createRequire} from 'node:module';
import {pathToFileURL,fileURLToPath} from 'node:url';
import path from 'node:path';
const [root,from,request,kind] = process.argv.slice(1);
const importer=pathToFileURL(path.join(root,from));
const selected=kind==='require' ? createRequire(importer).resolve(request)
    : fileURLToPath(import.meta.resolve(request,importer.href));
console.log(path.relative(root,selected));
"#;
    for edge in report["source_graph"]["edges"].as_array().unwrap() {
        if edge["state"] != "resolved" { continue; }
        let output = Command::new("node").env_remove("NODE_OPTIONS").env_remove("NODE_PATH")
            .args(["--experimental-import-meta-resolve", "--input-type=module", "-e", script])
            .arg(root).args([edge["importer"]["path"].as_str().unwrap(),
                edge["specifier"].as_str().unwrap(), edge["kind"].as_str().unwrap()])
            .output().unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert_eq!(String::from_utf8(output.stdout).unwrap().trim(),
            edge["target"]["path"].as_str().unwrap(), "{edge}");
    }
}

#[test]
fn complete_entrypoint_graph_follows_reexports_cycles_and_real_node_edges_without_execution() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "app.mjs", "import './lib/a.mjs'; export * from './lib/b.mjs'; throw Error('never execute');");
    put(root.path(), "lib/a.mjs", "import './shared.mjs';");
    put(root.path(), "lib/b.mjs", "export {value} from './shared.mjs';");
    put(root.path(), "lib/shared.mjs", "import '../app.mjs'; export const value=1;");
    let (code, report) = run(root.path(), "app.mjs", &[]);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["verdict"], "CAPTURED");
    assert_eq!(paths(&report), ["app.mjs", "lib/a.mjs", "lib/b.mjs", "lib/shared.mjs"]);
    assert_eq!(report["source_graph"]["edges"].as_array().unwrap().len(), 5);
    assert_eq!(report["source_graph"]["fully_resolved"], true);
    assert_eq!(report["runtime_completeness"], false);
    assert_eq!(report["execution_performed"], false);
    assert_eq!(report["release_certification"], false);
    assert_node_edges(root.path(), &report);
}

#[test]
fn mixed_package_graph_preserves_nested_instances_and_import_require_conditions() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "app.mjs", "import 'dual'; import './bridge.cjs';");
    put(root.path(), "bridge.cjs", "require('dual');");
    put(root.path(), "node_modules/dual/package.json", r#"{"exports":{"import":"./esm.mjs","require":"./cjs.cjs"}}"#);
    put(root.path(), "node_modules/dual/esm.mjs", "import 'dep'; throw Error('never execute');");
    put(root.path(), "node_modules/dual/cjs.cjs", "require('dep'); throw Error('never execute');");
    put(root.path(), "node_modules/dual/node_modules/dep/index.js", "throw Error('never execute');");
    put(root.path(), "node_modules/dep/index.js", "throw Error('wrong version');");
    let (code, report) = run(root.path(), "app.mjs", &[]);
    assert_eq!(code, 0, "{report}");
    assert_eq!(paths(&report).len(), 5);
    assert!(!paths(&report).contains(&"node_modules/dep/index.js"));
    assert_node_edges(root.path(), &report);
}

#[test]
fn incomplete_graph_keeps_good_edges_missing_dependencies_runtime_modules_and_computed_sites() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "app.mjs", "import './ok.mjs'; import 'node:fs'; import './absent.mjs'; import(name);");
    put(root.path(), "ok.mjs", "export const ok=1;");
    let (code, report) = run(root.path(), "app.mjs", &[]);
    assert_eq!(code, 1, "{report}");
    assert_eq!(report["verdict"], "INCOMPLETE");
    let states: Vec<_> = report["source_graph"]["edges"].as_array().unwrap().iter()
        .map(|e| e["state"].as_str().unwrap()).collect();
    assert_eq!(states, ["resolved", "runtime_required", "unresolved", "non_literal"]);
    assert_eq!(paths(&report), ["app.mjs", "ok.mjs"]);
    assert_eq!(report["source_graph"]["fully_resolved"], false);
}

#[test]
fn pin_checks_bind_transitive_source_and_suppress_graph_on_mismatch() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "app.mjs", "import './dependency.mjs';");
    put(root.path(), "dependency.mjs", "export const value=1;");
    let (code, report) = run(root.path(), "app.mjs", &[]);
    assert_eq!(code, 0);
    let hash = report["input_hash"].as_str().unwrap();
    let (code, pinned) = run(root.path(), "app.mjs", &["--expected-hash", hash]);
    assert_eq!(code, 0, "{pinned}");
    assert_eq!(pinned["expected_hash_matched"], true);
    put(root.path(), "dependency.mjs", "export const value=2;");
    let (code, changed) = run(root.path(), "app.mjs", &["--expected-hash", hash]);
    assert_eq!(code, 1, "{changed}");
    assert_eq!(changed["verdict"], "HASH_MISMATCH");
    assert!(changed["source_graph"].is_null());
}

#[test]
fn graph_capture_is_relocation_stable_and_custom_conditions_are_explicit() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    for root in [a.path(), b.path()] {
        put(root, "app.mjs", "import 'pkg';");
        put(root, "node_modules/pkg/package.json", r#"{"exports":{"custom":"./custom.mjs","default":"./default.mjs"}}"#);
        put(root, "node_modules/pkg/custom.mjs", "");
        put(root, "node_modules/pkg/default.mjs", "");
    }
    let (code, first) = run(a.path(), "app.mjs", &[]);
    assert_eq!(code, 0);
    assert_eq!(first, run(b.path(), "app.mjs", &[]).1);
    let (code, custom) = run(a.path(), "app.mjs", &["--condition", "custom"]);
    assert_eq!(code, 0, "{custom}");
    assert_ne!(first["input_hash"], custom["input_hash"]);
    assert!(paths(&custom).contains(&"node_modules/pkg/custom.mjs"));
}

#[test]
fn workspace_graph_uses_physical_context_only_after_explicit_link_admission() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "app.mjs", "import 'workspace';");
    put(root.path(), "packages/workspace/package.json", r#"{"exports":"./main.mjs"}"#);
    put(root.path(), "packages/workspace/main.mjs", "import './dep.mjs';");
    put(root.path(), "packages/workspace/dep.mjs", "export default 1;");
    std::fs::create_dir_all(root.path().join("node_modules")).unwrap();
    std::os::unix::fs::symlink("../packages/workspace", root.path().join("node_modules/workspace")).unwrap();
    let (code, rejected) = run(root.path(), "app.mjs", &[]);
    assert_eq!(code, 2, "{rejected}");
    assert!(rejected["source_graph"].is_null());
    let (code, captured) = run(root.path(), "app.mjs", &["--allow-contained-symlinks"]);
    assert_eq!(code, 0, "{captured}");
    assert!(paths(&captured).contains(&"packages/workspace/dep.mjs"));
    assert_node_edges(root.path(), &captured);
}

#[test]
fn syntax_and_loader_alias_diagnostics_prevent_a_complete_result() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "app.mjs", "import './broken.mjs'; import './alias.cjs';");
    put(root.path(), "broken.mjs", "export const = ;");
    put(root.path(), "alias.cjs", "const load=require; load('concealed');");
    let (code, report) = run(root.path(), "app.mjs", &[]);
    assert_eq!(code, 1, "{report}");
    let codes: Vec<_> = report["source_graph"]["diagnostics"].as_array().unwrap().iter()
        .map(|d| d["code"].as_str().unwrap()).collect();
    assert!(codes.contains(&"JAVASCRIPT_PARSE_ERROR"));
    assert!(codes.contains(&"INDIRECT_REQUIRE"));
}

#[test]
fn malformed_pins_and_ambiguous_query_modes_fail_before_execution() {
    let root = tempfile::tempdir().unwrap();
    let absent = root.path().join("absent");
    let (code, report) = run(&absent, "entry.mjs", &["--expected-hash", "bad"]);
    assert_eq!(code, 2, "{report}");
    assert!(report["error"].as_str().unwrap().contains("expected hash"));
    for flags in [vec!["--resolve-export", "."], vec!["--transitive"],
        vec!["--resolve-module", "./x", "--from", "app.mjs"],
        vec!["--resolution-mode", "require"], vec!["--require-resolved"], vec!["--from", "app.mjs"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_franken-module-graph"))
            .arg(&absent).args(["--capture-source-graph", "entry.mjs"]).args(&flags).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{flags:?}: {}", String::from_utf8_lossy(&output.stderr));
    }
}

#[test]
fn source_graph_handles_empty_entry_without_claiming_runtime_execution_or_leaking_code() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "app.mjs", "");
    let (code, report) = run(root.path(), "app.mjs", &[]);
    assert_eq!(code, 0);
    assert_eq!(paths(&report), ["app.mjs"]);
    assert!(report["source_graph"]["edges"].as_array().unwrap().is_empty());
    assert_eq!(report["source_graph"]["runtime_completeness"], false);
    put(root.path(), "app.mjs", "const private_literal='not_report_data';");
    let (_, report) = run(root.path(), "app.mjs", &[]);
    assert!(!serde_json::to_string(&report).unwrap().contains("not_report_data"));
}

#[test]
fn errors_and_module_limits_never_expose_a_partial_successful_graph() {
    let root = tempfile::tempdir().unwrap();
    let (code, report) = run(root.path(), "absent.mjs", &[]);
    assert_eq!(code, 1, "{report}");
    assert!(report["source_graph"].is_null());
    put(root.path(), "app.mjs", "import '../outside.mjs';");
    let (code, report) = run(root.path(), "app.mjs", &[]);
    assert_eq!(code, 2, "{report}");
    assert!(report["source_graph"].is_null());
    let imports = (0..256).map(|i| format!("import './m{i}.mjs';")).collect::<String>();
    put(root.path(), "app.mjs", &imports);
    for i in 0..256 { put(root.path(), &format!("m{i}.mjs"), ""); }
    let (code, report) = run(root.path(), "app.mjs", &[]);
    assert_eq!(code, 2, "{report}");
    assert_eq!(report["error_code"], "ERR_MODULE_GRAPH_LIMIT");
    assert!(report["source_graph"].is_null());
}
