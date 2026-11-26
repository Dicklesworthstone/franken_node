//! bd-reality-20260923-26n9r.4: mock-free end-to-end qualification of multi-file
//! CommonJS, ESM (`"type": "module"` + `.mjs`), dual-package conditional `exports`,
//! JSON imports, installed `node_modules` walk-up, directory entry (`run ./dir`),
//! multi-dependency `package.json` preflight receipt bounding, and fail-closed
//! actionable `ERR_MODULE_REGISTRY_INCOMPLETE` diagnostics across `strict`,
//! `balanced`, and `legacy-risky` profiles.
//!
//! When `node` is present on `PATH`, each positive scenario is also compared
//! byte-for-byte against live `node` output; when absent, pinned golden output
//! keeps the suite deterministic and offline-safe.

use serde_json::Value;
use std::path::Path;
use std::process::Command;

const PROFILES: &[&str] = &["strict", "balanced", "legacy-risky"];

fn franken_node_bin() -> &'static str {
    env!("CARGO_BIN_EXE_franken-node")
}

fn live_node_available() -> bool {
    Command::new("node")
        .arg("--version")
        .output()
        .is_ok_and(|out| out.status.success())
}

fn run_live_node(cwd: &Path, entry: &str) -> Option<String> {
    if !live_node_available() {
        return None;
    }
    let output = Command::new("node")
        .arg(entry)
        .current_dir(cwd)
        .output()
        .expect("spawn node");
    assert!(
        output.status.success(),
        "reference node execution failed for {entry} in {}: stderr=\n{}",
        cwd.display(),
        String::from_utf8_lossy(&output.stderr)
    );
    Some(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn write_file(root: &Path, rel: &str, contents: &str) {
    let path = root.join(rel);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).expect("create fixture parent dir");
    }
    std::fs::write(path, contents).expect("write fixture file");
}

fn init_workspace(project_dir: &Path, state_home: &Path, profile: &str) {
    let init = Command::new(franken_node_bin())
        .args(["init", "--profile", profile, "--out-dir", "."])
        .current_dir(project_dir)
        .env("XDG_STATE_HOME", state_home)
        .output()
        .expect("spawn franken-node init");
    assert!(
        init.status.success(),
        "franken-node init --profile {profile} failed: stderr=\n{}",
        String::from_utf8_lossy(&init.stderr)
    );
}

fn run_franken_console(
    project_dir: &Path,
    state_home: &Path,
    profile: &str,
    entry: &str,
) -> std::process::Output {
    Command::new(franken_node_bin())
        .args([
            "run",
            entry,
            "--policy",
            profile,
            "--runtime",
            "franken-engine",
            "--engine-bin",
            franken_node_bin(),
            "--console-only",
        ])
        .current_dir(project_dir)
        .env("XDG_STATE_HOME", state_home)
        .output()
        .expect("spawn franken-node run")
}

fn assert_matches_golden_and_live_node(
    scenario: &str,
    setup: impl Fn(&Path),
    entry: &str,
    golden_stdout: &str,
) {
    // Capture live Node reference once on a pristine copy (without .franken-node).
    let ref_dir = tempfile::TempDir::new().expect("node ref tempdir");
    setup(ref_dir.path());
    if let Some(node_stdout) = run_live_node(ref_dir.path(), entry) {
        assert_eq!(
            node_stdout, golden_stdout,
            "{scenario}: golden drifted from live node output"
        );
    }

    for profile in PROFILES {
        let work = tempfile::TempDir::new().expect("profile tempdir");
        let project = work.path().join("project");
        let state_home = work.path().join("state");
        std::fs::create_dir_all(&project).expect("create project dir");
        std::fs::create_dir_all(&state_home).expect("create state dir");
        setup(&project);
        init_workspace(&project, &state_home, profile);

        let output = run_franken_console(&project, &state_home, profile, entry);
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "{scenario} [{profile}] failed with status {:?}\nstdout:\n{stdout}\nstderr:\n{stderr}",
            output.status.code()
        );
        assert_eq!(
            stdout, golden_stdout,
            "{scenario} [{profile}] stdout mismatch vs Node/golden\nstderr:\n{stderr}"
        );
    }
}

#[test]
fn multi_file_cjs_graph_and_builtins_match_node_across_profiles() {
    let golden = "5|dir-index|a1|7|a/b|9|6869|u:4|ok|string|string\n";
    assert_matches_golden_and_live_node(
        "multi_file_cjs_graph",
        |root| {
            write_file(root, "lib/math.js", "exports.add = (a, b) => a + b;\n");
            write_file(
                root,
                "sub/index.js",
                "module.exports = { tag: \"dir-index\" };\n",
            );
            write_file(
                root,
                "a.js",
                "exports.stage = \"a1\";\nconst b = require(\"./b\");\nexports.after = b.seen;\n",
            );
            write_file(
                root,
                "b.js",
                "const a = require(\"./a\");\nexports.seen = a.stage;\n",
            );
            write_file(root, "data.json", "{\"k\":7,\"arr\":[1,2]}\n");
            write_file(
                root,
                "app.cjs",
                r#"const math = require("./lib/math");
const sub = require("./sub");
const a = require("./a");
const data = require("./data.json");
const path = require("node:path");
const EventEmitter = require("node:events");
const { Buffer } = require("node:buffer");
const util = require("node:util");
const assert = require("node:assert");
const { StringDecoder } = require("node:string_decoder");
const ee = new EventEmitter();
let hit = 0;
ee.on("x", (v) => { hit = v; });
ee.emit("x", 9);
assert.strictEqual(math.add(2, 3), 5);
const dec = new StringDecoder("utf8");
console.log([
  math.add(2, 3),
  sub.tag,
  a.after,
  data.k,
  path.posix.join("a", "b"),
  hit,
  Buffer.from("hi").toString("hex"),
  util.format("%s:%d", "u", 4),
  dec.end(Buffer.from("ok")),
  typeof __dirname,
  typeof __filename,
].join("|"));
"#,
            );
        },
        "app.cjs",
        golden,
    );
}

#[test]
fn esm_type_module_reexport_cjs_interop_json_and_dynamic_import_match_node_across_profiles() {
    let golden = "12|cjs-interop|11|json-attr|42\n";
    assert_matches_golden_and_live_node(
        "esm_interop_json",
        |root| {
            write_file(
                root,
                "package.json",
                r#"{"name":"esm-app","version":"1.0.0","type":"module"}"#,
            );
            write_file(root, "math.js", "export const mul = (a, b) => a * b;\n");
            write_file(root, "reexp.js", "export * from \"./math.js\";\n");
            write_file(root, "lazy.js", "export const answer = 42;\n");
            write_file(
                root,
                "legacy.cjs",
                "module.exports = { origin: \"cjs-interop\", n: 11 };\n",
            );
            write_file(root, "cfg.json", r#"{"mode":"json-attr"}"#);
            write_file(
                root,
                "app.js",
                r#"import { mul } from "./reexp.js";
import legacy from "./legacy.cjs";
import cfg from "./cfg.json" with { type: "json" };
const lazy = await import("./lazy.js");
console.log([mul(3, 4), legacy.origin, legacy.n, cfg.mode, lazy.answer].join("|"));
"#,
            );
        },
        "app.js",
        golden,
    );
}

#[test]
fn dual_package_conditional_exports_and_node_modules_walkup_match_node_across_profiles() {
    let setup = |root: &Path| {
        write_file(
            root,
            "package.json",
            r#"{"name":"dual-consumer","version":"1.0.0"}"#,
        );
        write_file(
            root,
            "node_modules/@acme/dual/package.json",
            r#"{
  "name": "@acme/dual",
  "version": "1.0.0",
  "exports": {
    ".": { "import": "./esm.mjs", "require": "./cjs.cjs" },
    "./sub": "./sub.cjs"
  }
}"#,
        );
        write_file(
            root,
            "node_modules/@acme/dual/esm.mjs",
            "export const flavor = \"esm\";\n",
        );
        write_file(
            root,
            "node_modules/@acme/dual/cjs.cjs",
            "module.exports = { flavor: \"cjs\" };\n",
        );
        write_file(
            root,
            "node_modules/@acme/dual/sub.cjs",
            "module.exports = { sub: \"subpath\" };\n",
        );
        write_file(
            root,
            "node_modules/shared-util/package.json",
            r#"{"name":"shared-util","version":"1.0.0","main":"./lib/main.js"}"#,
        );
        write_file(
            root,
            "node_modules/shared-util/lib/main.js",
            "module.exports = { tag: \"walkup-ok\" };\n",
        );
        write_file(
            root,
            "packages/sub/entry.cjs",
            r#"const dual = require("@acme/dual");
const sub = require("@acme/dual/sub");
const shared = require("shared-util");
console.log([dual.flavor, sub.sub, shared.tag].join("|"));
"#,
        );
        write_file(
            root,
            "packages/sub/entry.mjs",
            r#"import { flavor } from "@acme/dual";
import shared from "shared-util";
console.log([flavor, shared.tag].join("|"));
"#,
        );
    };

    assert_matches_golden_and_live_node(
        "dual_package_cjs",
        setup,
        "packages/sub/entry.cjs",
        "cjs|subpath|walkup-ok\n",
    );
    assert_matches_golden_and_live_node(
        "dual_package_esm",
        setup,
        "packages/sub/entry.mjs",
        "esm|walkup-ok\n",
    );
}

#[test]
fn directory_entry_resolves_package_main_and_index_fallback_with_json_receipt() {
    let work = tempfile::TempDir::new().expect("dir entry tempdir");
    let main_app = work.path().join("my-app");
    let idx_app = work.path().join("idx-app");
    let state_home = work.path().join("state");
    std::fs::create_dir_all(&main_app).expect("mkdir main_app");
    std::fs::create_dir_all(&idx_app).expect("mkdir idx_app");
    std::fs::create_dir_all(&state_home).expect("mkdir state_home");

    write_file(
        &main_app,
        "package.json",
        r#"{"name":"my-app","version":"1.0.0","main":"./src/entry.js"}"#,
    );
    write_file(&main_app, "src/entry.js", "console.log(\"dir-main-ok\");\n");
    write_file(&idx_app, "index.js", "console.log(\"dir-index-ok\");\n");

    if let Some(node_main) = run_live_node(work.path(), "./my-app") {
        assert_eq!(node_main, "dir-main-ok\n");
    }
    if let Some(node_idx) = run_live_node(work.path(), "./idx-app") {
        assert_eq!(node_idx, "dir-index-ok\n");
    }

    init_workspace(&main_app, &state_home, "balanced");
    init_workspace(&idx_app, &state_home, "balanced");

    let console_out = Command::new(franken_node_bin())
        .args([
            "run",
            "./my-app",
            "--config",
            "./my-app/franken_node.toml",
            "--policy",
            "balanced",
            "--runtime",
            "franken-engine",
            "--engine-bin",
            franken_node_bin(),
            "--console-only",
        ])
        .current_dir(work.path())
        .env("XDG_STATE_HOME", &state_home)
        .output()
        .expect("spawn franken-node run ./my-app");
    assert!(
        console_out.status.success(),
        "run ./my-app failed: stderr=\n{}",
        String::from_utf8_lossy(&console_out.stderr)
    );
    assert_eq!(
        String::from_utf8_lossy(&console_out.stdout),
        "dir-main-ok\n"
    );

    let idx_out = run_franken_console(&idx_app, &state_home, "balanced", ".");
    assert!(
        idx_out.status.success(),
        "run . (index.js fallback) failed: stderr=\n{}",
        String::from_utf8_lossy(&idx_out.stderr)
    );
    assert_eq!(String::from_utf8_lossy(&idx_out.stdout), "dir-index-ok\n");

    let json_out = Command::new(franken_node_bin())
        .args([
            "run",
            ".",
            "--policy",
            "balanced",
            "--runtime",
            "franken-engine",
            "--engine-bin",
            franken_node_bin(),
            "--json",
        ])
        .current_dir(&main_app)
        .env("XDG_STATE_HOME", &state_home)
        .output()
        .expect("spawn franken-node run . --json");
    assert!(
        json_out.status.success(),
        "run . --json failed: stderr=\n{}",
        String::from_utf8_lossy(&json_out.stderr)
    );
    let envelope: Value =
        serde_json::from_slice(&json_out.stdout).expect("parse run --json envelope");
    assert_eq!(
        envelope["success"].as_bool(),
        Some(true),
        "expected success=true in run --json envelope: {envelope}"
    );
    assert_eq!(
        envelope["dispatch"]["runtime"].as_str(),
        Some("franken_engine"),
        "expected native franken_engine runtime: {envelope}"
    );
    assert!(
        envelope["receipt"]["receipt_id"]
            .as_str()
            .is_some_and(|id| !id.is_empty()),
        "expected non-empty receipt.receipt_id in run --json envelope: {envelope}"
    );
    let receipt_path = envelope["receipt_path"]
        .as_str()
        .expect("expected receipt_path string");
    assert!(
        Path::new(receipt_path).is_file(),
        "expected persisted receipt file at {receipt_path}"
    );
}

#[test]
fn multi_dep_package_json_with_large_preflight_warnings_runs_cleanly_under_balanced() {
    let work = tempfile::TempDir::new().expect("multi-dep tempdir");
    let project = work.path().join("project");
    let state_home = work.path().join("state");
    std::fs::create_dir_all(&project).expect("mkdir project");
    std::fs::create_dir_all(&state_home).expect("mkdir state_home");

    // 80 uncertified dependencies produce >4,096 bytes of preflight warnings;
    // run_preflight_rationale must bound receipt rationale cleanly rather than
    // failing on MAX_RECEIPT_TEXT_FIELD_BYTES.
    let mut deps = serde_json::Map::new();
    for idx in 0..80 {
        deps.insert(
            format!("synthetic-untrusted-package-{idx:03}"),
            Value::String("1.0.0".to_owned()),
        );
    }
    let pkg = serde_json::json!({
        "name": "multi-dep-app",
        "version": "1.0.0",
        "dependencies": deps,
    });
    write_file(&project, "package.json", &pkg.to_string());
    write_file(
        &project,
        "node_modules/local-helper/package.json",
        r#"{"name":"local-helper","version":"1.0.0","main":"./index.js"}"#,
    );
    write_file(
        &project,
        "node_modules/local-helper/index.js",
        "module.exports = (x) => x * 7;\n",
    );
    write_file(
        &project,
        "app.js",
        "const helper = require(\"local-helper\");\nconsole.log(\"multi-dep:\" + helper(6));\n",
    );

    init_workspace(&project, &state_home, "balanced");
    let output = run_franken_console(&project, &state_home, "balanced", "app.js");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "multi-dep project must not crash on preflight rationale overflow\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert_eq!(stdout, "multi-dep:42\n");
}

#[test]
fn frozen_module_admission_fails_closed_with_actionable_incomplete_diagnostics() {
    let cases = [
        (
            "dynamic_function_codegen",
            "const fn = Function('return 1');\nconsole.log(fn());\n",
            "DYNAMIC_CODE_OR_LOADER at app.js:1",
        ),
        (
            "unsupported_native_builtin",
            "const proc = require('node:process');\nconsole.log(typeof proc);\n",
            "unsupported native builtin 'node:process' requested by app.js:1",
        ),
    ];

    for (name, source, expected_fragment) in cases {
        let work = tempfile::TempDir::new().expect("fail-closed tempdir");
        let project = work.path().join("project");
        let state_home = work.path().join("state");
        std::fs::create_dir_all(&project).expect("mkdir project");
        std::fs::create_dir_all(&state_home).expect("mkdir state_home");

        write_file(&project, "app.js", source);
        init_workspace(&project, &state_home, "balanced");

        let output = run_franken_console(&project, &state_home, "balanced", "app.js");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "{name}: must fail closed under frozen module admission"
        );
        assert!(
            stderr.contains("ERR_MODULE_REGISTRY_INCOMPLETE"),
            "{name}: expected ERR_MODULE_REGISTRY_INCOMPLETE in stderr:\n{stderr}"
        );
        assert!(
            stderr.contains(expected_fragment),
            "{name}: expected actionable detail {:?} in stderr:\n{stderr}",
            expected_fragment
        );
    }
}
