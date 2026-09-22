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

// Independent erasure oracle: transform only fixture text through Node's public
// API, never evaluate the input or the resulting JavaScript.
fn node_strip(source: &str) -> Value {
    let script = r#"
const {stripTypeScriptTypes} = require('node:module');
try { console.log(JSON.stringify({source:stripTypeScriptTypes(process.argv[1])})); }
catch (e) { console.log(JSON.stringify({error:e.code})); }
"#;
    let output = Command::new("node").env_remove("NODE_OPTIONS").env_remove("NODE_PATH")
        .args(["--no-warnings", "-e", script, source]).output().unwrap();
    assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
    serde_json::from_slice(&output.stdout).unwrap()
}

fn runtime_edges(report: &Value, entry: &str) -> Vec<Value> {
    report["source_graph"]["edges"].as_array().unwrap().iter()
        .filter(|e| e["importer"]["path"] == entry && e["state"] != "type_only")
        .map(|e| serde_json::json!([e["kind"], e["specifier"], e["state"], e["target"]])).collect()
}

#[test]
fn typescript_runtime_edges_agree_with_independent_node_type_erasure() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "dep.mts", "export type T = string; export default 1;");
    put(root.path(), "dep.cjs", "throw Error('selected code must not run');");
    for source in [
        "import type {T} from '../outside'; import {type T} from './dep.mts'; export {type T} from './dep.mts';",
        "let p: typeof import('types') = import('./dep.mts'); const x = p as typeof import('more-types');",
        "(require as Loader)('./dep.cjs'); require!('./dep.cjs'); (module.require satisfies Loader)('./dep.cjs');",
        "import type X = require('types'); const value: number = 1;",
        "function load(x = require('./dep.cjs')): typeof import('types') { return x; }",
        "import type from './dep.mts'; import {type require, type Function} from './dep.mts';",
        "declare module 'virtual' { import X from '../outside'; } import './dep.mts';",
    ] {
        let stripped = node_strip(source);
        assert!(stripped["error"].is_null(), "{stripped}");
        put(root.path(), "app.ts", source);
        put(root.path(), "stripped.mjs", stripped["source"].as_str().unwrap());
        let (code, native) = run(root.path(), "app.ts", &[]);
        let (stripped_code, reference) = run(root.path(), "stripped.mjs", &[]);
        assert_eq!(code, 0, "{source}: {native}");
        assert_eq!(stripped_code, 0, "{reference}");
        assert_eq!(runtime_edges(&native, "app.ts"), runtime_edges(&reference, "stripped.mjs"));
        assert_eq!(native["source_graph"]["type_resolution_performed"], false);
        assert_node_edges(root.path(), &native);
    }
}

#[test]
fn type_only_files_are_not_opened_even_when_fifo_or_escaping_symlink() {
    let root = tempfile::tempdir().unwrap();
    rustix::fs::mkfifoat(rustix::fs::CWD, root.path().join("types.d.ts"),
        rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR).unwrap();
    std::os::unix::fs::symlink("../outside", root.path().join("escape.d.ts")).unwrap();
    put(root.path(), "app.ts", "import type {A} from './types.d.ts'; export type {B} from './escape.d.ts';");
    let (code, report) = run(root.path(), "app.ts", &[]);
    assert_eq!(code, 0, "{report}");
    assert_eq!(paths(&report), ["app.ts"]);
    assert!(report["source_graph"]["probes"].as_array().unwrap().iter()
        .all(|p| !["types.d.ts", "escape.d.ts"].contains(&p["path"].as_str().unwrap())));
    put(root.path(), "app.ts", "import './types.d.ts';");
    let (code, rejected) = run(root.path(), "app.ts", &[]);
    assert_eq!(code, 2, "{rejected}");
    assert!(rejected["source_graph"].is_null());
}

#[test]
fn typed_import_equals_selects_require_target_without_claiming_strip_only_execution() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "app.cts", "import dep = require('dual'); export = dep;");
    put(root.path(), "node_modules/dual/package.json", r#"{"exports":{"import":"./esm.mts","require":"./cjs.cts"}}"#);
    put(root.path(), "node_modules/dual/esm.mts", "export default 1;");
    put(root.path(), "node_modules/dual/cjs.cts", "const value: number = 1; module.exports=value;");
    let (code, report) = run(root.path(), "app.cts", &[]);
    assert_eq!(code, 1, "{report}");
    assert_eq!(report["verdict"], "INCOMPLETE");
    assert!(paths(&report).contains(&"node_modules/dual/cjs.cts"));
    assert!(!paths(&report).contains(&"node_modules/dual/esm.mts"));
    assert_eq!(node_strip("import dep = require('dual');")["error"], "ERR_UNSUPPORTED_TYPESCRIPT_SYNTAX");
    assert_node_edges(root.path(), &report);
}

#[test]
fn typescript_transforms_and_tsx_keep_explicit_edges_and_expose_missing_analysis() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "dependency.ts", "export default 1;");
    for (entry, source, diagnostic) in [
        ("app.ts", "enum E { A = 1 }; import './dependency.ts';", "TYPESCRIPT_TRANSFORM_REQUIRED"),
        ("app.ts", "class C { constructor(public value: number) {} } import './dependency.ts';", "TYPESCRIPT_TRANSFORM_REQUIRED"),
        ("app.tsx", "import X from './dependency.ts'; const view = <X/>;", "UNSUPPORTED_JAVASCRIPT_SURFACE"),
    ] {
        put(root.path(), entry, source);
        let (code, report) = run(root.path(), entry, &[]);
        assert_eq!(code, 1, "{report}");
        assert!(paths(&report).contains(&"dependency.ts"));
        assert!(report["source_graph"]["diagnostics"].as_array().unwrap().iter().any(|d| d["code"] == diagnostic));
        assert_eq!(report["runtime_completeness"], false);
        assert_eq!(report["execution_performed"], false);
    }
}

#[test]
fn typescript_graph_pins_bind_runtime_sources_and_erased_spelling_but_not_unread_types() {
    let root = tempfile::tempdir().unwrap();
    let source = "import type {T} from './types.d.ts'; import './dep.mts';";
    put(root.path(), "app.ts", source);
    put(root.path(), "types.d.ts", "export interface T {}");
    put(root.path(), "dep.mts", "export const n: number = 1;");
    let (code, initial) = run(root.path(), "app.ts", &[]);
    assert_eq!(code, 0, "{initial}");
    let hash = initial["input_hash"].as_str().unwrap();
    put(root.path(), "types.d.ts", "export interface T { changed: true }");
    let (code, same) = run(root.path(), "app.ts", &["--expected-hash", hash]);
    assert_eq!(code, 0, "{same}");
    put(root.path(), "dep.mts", "export const n: number = 2;");
    let (code, changed) = run(root.path(), "app.ts", &["--expected-hash", hash]);
    assert_eq!(code, 1, "{changed}");
    assert_eq!(changed["verdict"], "HASH_MISMATCH");
    assert!(changed["source_graph"].is_null());
    put(root.path(), "dep.mts", "export const n: number = 1;");
    put(root.path(), "app.ts", "import type {T} from './different.d.ts'; import './dep.mts';");
    assert_ne!(run(root.path(), "app.ts", &[]).1["input_hash"], initial["input_hash"]);
}

#[test]
fn typescript_workspace_graph_remains_contained_physical_and_relocation_stable() {
    let a = tempfile::tempdir().unwrap();
    let b = tempfile::tempdir().unwrap();
    for root in [a.path(), b.path()] {
        put(root, "app.mts", "import 'workspace';");
        put(root, "packages/workspace/package.json", r#"{"exports":"./main.ts"}"#);
        put(root, "packages/workspace/main.ts", "import type {T} from 'types'; import './dep.mts';");
        put(root, "packages/workspace/dep.mts", "export const n: number = 1;");
        std::fs::create_dir_all(root.join("node_modules")).unwrap();
        std::os::unix::fs::symlink("../packages/workspace", root.join("node_modules/workspace")).unwrap();
    }
    let flags = ["--allow-contained-symlinks"];
    let (code, report) = run(a.path(), "app.mts", &flags);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report, run(b.path(), "app.mts", &flags).1);
    assert_eq!(paths(&report), ["app.mts", "packages/workspace/dep.mts", "packages/workspace/main.ts"]);
    assert_eq!(run(a.path(), "app.mts", &[]).0, 2);
    assert_node_edges(a.path(), &report);
}

#[test]
fn runtime_declaration_import_is_incomplete_and_does_not_become_an_empty_implementation() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "app.ts", "import './types.d.ts';");
    put(root.path(), "types.d.ts", "export interface T {}");
    let (code, report) = run(root.path(), "app.ts", &[]);
    assert_eq!(code, 1, "{report}");
    assert!(paths(&report).contains(&"types.d.ts"));
    assert!(report["source_graph"]["diagnostics"].as_array().unwrap().iter()
        .any(|d| d["code"] == "DECLARATION_FILE_NOT_RUNTIME"));
    assert!(report["source_graph"]["modules"].as_array().unwrap().iter()
        .any(|m| m["source_language"] == "declaration" && m["analyzed"] == false));
}

#[test]
fn typed_graph_has_no_implicit_tsconfig_alias_or_emitted_extension_fallback() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "app.mts", "import './lib.js'; import './lib'; import '@src/lib';");
    put(root.path(), "lib.ts", "export default 1;");
    put(root.path(), "tsconfig.json", r#"{"compilerOptions":{"paths":{"@src/*":["./*"]}}}"#);
    let (code, report) = run(root.path(), "app.mts", &[]);
    assert_eq!(code, 1, "{report}");
    assert_eq!(paths(&report), ["app.mts"]);
    assert!(report["source_graph"]["edges"].as_array().unwrap().iter().all(|e| e["state"] == "unresolved"));
}

#[test]
fn typed_parse_failures_preserve_capture_without_asserting_dependency_completeness() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "app.ts", "const value: = 1;");
    let (code, report) = run(root.path(), "app.ts", &[]);
    assert_eq!(code, 1, "{report}");
    assert_eq!(report["source_graph"]["diagnostics"][0]["code"], "TYPESCRIPT_PARSE_ERROR");
    assert_eq!(report["source_graph"]["modules"][0]["source_language"], "typescript");
    assert_eq!(report["source_graph"]["modules"][0]["analyzed"], false);
    assert!(!report.to_string().contains("const value"));
}

#[test]
fn typed_computed_loads_and_asserted_loader_aliases_remain_incomplete() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "app.ts", "const load = require as Loader; load('hidden'); import(name as string);");
    let (code, report) = run(root.path(), "app.ts", &[]);
    assert_eq!(code, 1, "{report}");
    assert!(report["source_graph"]["edges"].as_array().unwrap().iter().any(|e| e["state"] == "non_literal"));
    assert!(report["source_graph"]["diagnostics"].as_array().unwrap().iter().any(|d| d["code"] == "INDIRECT_REQUIRE"));
}

fn capsule_pin(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    hash.update(b"franken-node/module-source-capsule/v1\0");
    hash.update((bytes.len() as u64).to_le_bytes());
    hash.update(bytes);
    format!("sha256:{}", hex::encode(hash.finalize()))
}

fn export_capsule(root: &Path, entry: &str, path: &Path, flags: &[&str]) -> (i32, Value) {
    let mut options = vec!["--write-source-capsule", path.to_str().unwrap()];
    options.extend_from_slice(flags);
    run(root, entry, &options)
}

fn replay_capsule(path: &Path, pin: &str, cwd: &Path) -> (i32, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_franken-module-graph"))
        .current_dir(cwd).args(["--replay-source-capsule", path.to_str().unwrap(), "--expected-hash", pin])
        .output().unwrap();
    let report = serde_json::from_slice(&output.stdout).unwrap_or_else(|e|
        panic!("invalid replay JSON: {e}; stderr={}", String::from_utf8_lossy(&output.stderr)));
    (output.status.code().unwrap(), report)
}

#[test]
fn durable_capsule_replays_without_the_original_checkout_or_source_evaluation() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    let unrelated = temp.path().join("unrelated");
    std::fs::create_dir(&unrelated).unwrap();
    put(&project, "app.mjs", "import './dep.mjs'; throw Error('private_source_capsule_marker');");
    put(&project, "dep.mjs", "export const x=1;");
    let path = temp.path().join("capture.fnsc");
    let (code, captured) = export_capsule(&project, "app.mjs", &path, &[]);
    assert_eq!(code, 0, "{captured}");
    let bytes = std::fs::read(&path).unwrap();
    let pin = captured["capsule_hash"].as_str().unwrap();
    assert_eq!(pin, capsule_pin(&bytes));
    assert_eq!(captured["capsule_bytes"], bytes.len());
    assert!(bytes.windows(b"private_source_capsule_marker".len()).any(|w| w == b"private_source_capsule_marker"));
    assert!(!captured.to_string().contains("private_source_capsule_marker"));
    std::fs::rename(&project, temp.path().join("original-not-at-recorded-path")).unwrap();
    let (code, replayed) = replay_capsule(&path, pin, &unrelated);
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["verdict"], "REPLAYED");
    assert_eq!(replayed["replay_verified"], true);
    assert_eq!(replayed["source_graph"], captured["source_graph"]);
    assert_eq!(replayed["input_hash"], captured["input_hash"]);
    for field in ["runtime_completeness", "execution_performed", "filesystem_verified", "release_certification"] {
        assert_eq!(replayed[field], false, "{field}");
    }
    assert!(!replayed.to_string().contains("private_source_capsule_marker"));
    assert_eq!(std::fs::read_dir(&unrelated).unwrap().count(), 0, "replay must not extract files");
}

#[test]
fn replayed_incomplete_analysis_cannot_be_upgraded_by_later_host_files() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    put(&project, "app.mjs", "import './missing.mjs'; import 'node:fs'; import(variable);");
    let path = temp.path().join("incomplete.fnsc");
    let (code, captured) = export_capsule(&project, "app.mjs", &path, &[]);
    assert_eq!(code, 1, "{captured}");
    assert!(path.is_file());
    put(&project, "missing.mjs", "export const nowExists=1;");
    let (code, replayed) = replay_capsule(&path, captured["capsule_hash"].as_str().unwrap(), &project);
    assert_eq!(code, 1, "{replayed}");
    assert_eq!(replayed["verdict"], "INCOMPLETE");
    assert_eq!(replayed["replay_verified"], true);
    assert_eq!(replayed["source_graph"], captured["source_graph"]);
    assert!(!paths(&replayed).contains(&"missing.mjs"));
}

#[test]
fn source_pin_mismatch_and_unsafe_capture_do_not_publish_capsules() {
    let temp = tempfile::tempdir().unwrap();
    put(temp.path(), "app.mjs", "export const x=1;");
    let path = temp.path().join("must-not-exist.fnsc");
    let pin = format!("sha256:{}", "0".repeat(64));
    let (code, report) = export_capsule(temp.path(), "app.mjs", &path, &["--expected-hash", &pin]);
    assert_eq!(code, 1, "{report}");
    assert_eq!(report["verdict"], "HASH_MISMATCH");
    assert!(report["source_graph"].is_null());
    assert!(!path.exists());
    put(temp.path(), "app.mjs", "import '../outside.mjs';");
    let (code, report) = export_capsule(temp.path(), "app.mjs", &path, &[]);
    assert_eq!(code, 2, "{report}");
    assert!(!path.exists());
}

#[test]
fn publication_never_overwrites_existing_files_symlinks_or_directories() {
    let temp = tempfile::tempdir().unwrap();
    put(temp.path(), "app.mjs", "export const x=1;");
    let sentinel = temp.path().join("sentinel.fnsc");
    std::fs::write(&sentinel, b"preserve prior evidence").unwrap();
    let alias = temp.path().join("alias.fnsc");
    std::os::unix::fs::symlink("sentinel.fnsc", &alias).unwrap();
    let directory = temp.path().join("directory.fnsc");
    std::fs::create_dir(&directory).unwrap();
    for path in [&sentinel, &alias, &directory] {
        let (code, report) = export_capsule(temp.path(), "app.mjs", path, &[]);
        assert_eq!(code, 2, "{report}");
        assert_eq!(report["verdict"], "ERROR");
        assert!(report["source_graph"].is_null());
        assert!(report["capsule_hash"].is_null());
    }
    assert_eq!(std::fs::read(&sentinel).unwrap(), b"preserve prior evidence");
    assert!(std::fs::symlink_metadata(&alias).unwrap().is_symlink());
    assert!(directory.is_dir());
}

#[test]
fn successful_publication_is_private_and_deterministic_across_relocation() {
    use std::os::unix::fs::PermissionsExt;
    let temp = tempfile::tempdir().unwrap();
    let a = temp.path().join("a"); let b = temp.path().join("b");
    let first = temp.path().join("first.fnsc"); let second = temp.path().join("second.fnsc");
    for root in [&a, &b] { put(root, "app.ts", "import type T from '../unread'; export const n:number=1;"); }
    let (a_code, a_report) = export_capsule(&a, "app.ts", &first, &[]);
    let (b_code, b_report) = export_capsule(&b, "app.ts", &second, &[]);
    assert_eq!((a_code, b_code), (0, 0), "{a_report} {b_report}");
    assert_eq!(std::fs::metadata(&first).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::read(&first).unwrap(), std::fs::read(&second).unwrap());
    assert_eq!(a_report["capsule_hash"], b_report["capsule_hash"]);
}

#[test]
fn replay_requires_capsule_identity_not_graph_identity_and_rejects_corruption() {
    let temp = tempfile::tempdir().unwrap();
    put(temp.path(), "app.mjs", "export const value=1;");
    let path = temp.path().join("capture.fnsc");
    let (_, captured) = export_capsule(temp.path(), "app.mjs", &path, &[]);
    let (code, report) = replay_capsule(&path, captured["input_hash"].as_str().unwrap(), temp.path());
    assert_eq!(code, 1, "{report}");
    assert_eq!(report["error_code"], "ERR_MODULE_CAPSULE_PIN_MISMATCH");
    assert!(report["source_graph"].is_null());
    let mut bytes = std::fs::read(&path).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    let corrupted = temp.path().join("corrupted.fnsc");
    std::fs::write(&corrupted, &bytes).unwrap();
    let (code, report) = replay_capsule(&corrupted, captured["capsule_hash"].as_str().unwrap(), temp.path());
    assert_eq!(code, 1, "{report}");
    assert_eq!(report["replay_verified"], false);
    let (code, report) = replay_capsule(&corrupted, &capsule_pin(&bytes), temp.path());
    assert_eq!(code, 2, "{report}");
    assert_eq!(report["error_code"], "ERR_MODULE_CAPSULE_INVALID");
    assert!(report["source_graph"].is_null());
}

#[test]
fn malformed_or_truncated_capsules_never_return_a_successful_graph() {
    let temp = tempfile::tempdir().unwrap();
    put(temp.path(), "app.mjs", "export const value=1;");
    let path = temp.path().join("capture.fnsc");
    export_capsule(temp.path(), "app.mjs", &path, &[]);
    let bytes = std::fs::read(&path).unwrap();
    for (index, invalid) in [b"not a capsule".as_slice(), &bytes[..10], &bytes[..bytes.len()-1]].iter().enumerate() {
        let path = temp.path().join(format!("malformed-{index}.fnsc"));
        std::fs::write(&path, invalid).unwrap();
        let (code, report) = replay_capsule(&path, &capsule_pin(invalid), temp.path());
        assert_eq!(code, 2, "{report}");
        assert_eq!(report["scope"], "captured-source-graph-replay");
        assert_eq!(report["replay_verified"], false);
        assert!(report["source_graph"].is_null());
    }
}

#[test]
fn replay_admission_refuses_fifo_symlink_directory_and_oversized_file_without_hanging() {
    use rustix::fs::{Mode, mkfifoat};
    use std::process::Stdio;
    use std::time::{Duration, Instant};
    let temp = tempfile::tempdir().unwrap();
    let directory = std::fs::File::open(temp.path()).unwrap();
    mkfifoat(&directory, "fifo.fnsc", Mode::RUSR | Mode::WUSR).unwrap();
    put(temp.path(), "regular.fnsc", "small");
    std::os::unix::fs::symlink("regular.fnsc", temp.path().join("link.fnsc")).unwrap();
    let oversized = temp.path().join("oversized.fnsc");
    std::fs::File::create(&oversized).unwrap().set_len(64 * 1024 * 1024).unwrap();
    let pin = format!("sha256:{}", "0".repeat(64));
    for path in [temp.path().join("fifo.fnsc"), temp.path().join("link.fnsc"), temp.path().to_owned(), oversized] {
        let mut child = Command::new(env!("CARGO_BIN_EXE_franken-module-graph"))
            .arg("--replay-source-capsule").arg(&path).args(["--expected-hash", &pin])
            .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        while child.try_wait().unwrap().is_none() {
            if Instant::now() >= deadline {
                child.kill().unwrap(); child.wait().unwrap();
                panic!("capsule admission blocked on {}", path.display());
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(report["source_graph"].is_null());
        assert_eq!(report["replay_verified"], false);
    }
}

#[test]
fn replay_cannot_accept_live_project_context_or_override_captured_options() {
    let pin = format!("sha256:{}", "0".repeat(64));
    for extra in [vec!["project"], vec!["--capture-source-graph", "app.mjs"], vec!["--condition", "custom"],
        vec!["--allow-contained-symlinks"], vec!["--resolve-export", "."], vec!["--transitive"],
        vec!["--write-source-capsule", "output"], vec!["--require-resolved"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_franken-module-graph"))
            .args(["--replay-source-capsule", "absent", "--expected-hash", &pin])
            .args(&extra).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{extra:?}");
        assert!(output.stdout.is_empty(), "rejected options must not start inspection");
    }
    for args in [vec!["--replay-source-capsule", "absent"], vec!["--write-source-capsule", "output"], vec![]] {
        let output = Command::new(env!("CARGO_BIN_EXE_franken-module-graph")).args(&args).output().unwrap();
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn pinned_export_and_replay_preserve_typed_workspace_links_after_metadata_changes() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("project");
    put(&project, "app.mts", "import type T from '../unread'; import 'workspace';");
    put(&project, "pkg/package.json", r#"{"exports":"./index.ts"}"#);
    put(&project, "pkg/index.ts", "import './value.mts'; export const n:number=1;");
    put(&project, "pkg/value.mts", "export const x=1;");
    std::fs::create_dir(project.join("node_modules")).unwrap();
    std::os::unix::fs::symlink("../pkg", project.join("node_modules/workspace")).unwrap();
    let (_, reviewed) = run(&project, "app.mts", &["--allow-contained-symlinks"]);
    let path = temp.path().join("workspace.fnsc");
    let (code, captured) = export_capsule(&project, "app.mts", &path,
        &["--allow-contained-symlinks", "--expected-hash", reviewed["input_hash"].as_str().unwrap()]);
    assert_eq!(code, 0, "{captured}");
    assert_eq!(captured["expected_hash_matched"], true);
    put(&project, "pkg/package.json", r#"{"exports":null}"#);
    put(&project, "pkg/value.mts", "import 'changed';");
    let (code, replayed) = replay_capsule(&path, captured["capsule_hash"].as_str().unwrap(), temp.path());
    assert_eq!(code, 0, "{replayed}");
    assert_eq!(replayed["source_graph"], reviewed["source_graph"]);
    assert_eq!(replayed["source_graph"]["type_resolution_performed"], false);
}

#[test]
fn failed_capsule_publication_never_returns_a_successful_capture_report() {
    let temp = tempfile::tempdir().unwrap();
    put(temp.path(), "app.mjs", "export const x=1;");
    let output = temp.path().join("nonexistent-parent/capture.fnsc");
    let (code, report) = export_capsule(temp.path(), "app.mjs", &output, &[]);
    assert_eq!(code, 2, "{report}");
    assert_eq!(report["verdict"], "ERROR");
    assert!(report["source_graph"].is_null());
    assert!(report["capsule_hash"].is_null());
    assert!(!output.exists());
}

#[test]
fn even_a_re_pinned_capsule_must_recompute_the_recorded_graph_hash() {
    let temp = tempfile::tempdir().unwrap();
    put(temp.path(), "app.mjs", "export const x=1;");
    let original = temp.path().join("original.fnsc");
    let (_, captured) = export_capsule(temp.path(), "app.mjs", &original, &[]);
    let mut bytes = std::fs::read(&original).unwrap();
    let graph_hash = captured["input_hash"].as_str().unwrap().as_bytes();
    let offset = bytes.windows(graph_hash.len()).position(|w| w == graph_hash).unwrap();
    let digit = &mut bytes[offset + graph_hash.len() - 1];
    *digit = if *digit == b'0' { b'1' } else { b'0' };
    let altered = temp.path().join("altered.fnsc");
    std::fs::write(&altered, &bytes).unwrap();
    let (code, report) = replay_capsule(&altered, &capsule_pin(&bytes), temp.path());
    assert_eq!(code, 2, "{report}");
    assert_eq!(report["error_code"], "ERR_MODULE_CAPSULE_REPLAY_MISMATCH");
    assert_eq!(report["replay_verified"], false);
    assert!(report["source_graph"].is_null());
}
