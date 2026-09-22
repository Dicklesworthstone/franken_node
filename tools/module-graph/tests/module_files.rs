//! Importer-to-file differential tests: only Node's public resolvers execute.
//! Selected source files deliberately throw; no package source may be loaded.
#![cfg(unix)]
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;
use std::process::{Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

fn put(root: &Path, name: &str, bytes: &[u8]) {
    let file = root.join(name);
    fs::create_dir_all(file.parent().unwrap()).unwrap();
    fs::write(file, bytes).unwrap();
}
fn source(root: &Path, name: &str) { put(root, name, b"throw new Error('SOURCE_MUST_NEVER_EXECUTE_OR_BE_PRINTED');"); }
fn fixture() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "package.json", br#"{"name":"application","type":"commonjs"}"#);
    source(root.path(), "app.js");
    root
}
fn bounded(mut command: Command) -> Output {
    let mut child = command.stdout(Stdio::piped()).stderr(Stdio::piped()).spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if child.try_wait().unwrap().is_some() { return child.wait_with_output().unwrap(); }
        if Instant::now() >= deadline {
            let _ = child.kill();
            panic!("bounded resolution timed out: {:?}", child.wait_with_output().unwrap());
        }
        thread::sleep(Duration::from_millis(5));
    }
}
fn run(root: &Path, from: &str, request: &str, mode: &str, extra: &[&str]) -> (i32, Value) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_franken-module-graph"));
    command.arg(root).args(["--resolve-module", request, "--from", from, "--resolution-mode", mode]).args(extra);
    let output = bounded(command);
    let result: Value = serde_json::from_slice(&output.stdout).unwrap_or_else(|_| panic!("{output:?}"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("SOURCE_MUST_NEVER"));
    assert_eq!(result["scope"], "project-contained-module-resolution");
    assert_eq!(result["execution_performed"], false);
    assert_eq!(result["release_certification"], false);
    (output.status.code().unwrap(), result)
}
fn selected(root: &Path, from: &str, request: &str, mode: &str) -> Value {
    let (code, report) = run(root, from, request, mode, &[]);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["verdict"], "RESOLVED");
    assert_eq!(report["filesystem_verified"], true);
    report
}
fn node(root: &Path, from: &str, request: &str, mode: &str) -> Value {
    let mut command = Command::new("node");
    command.current_dir(root).env_remove("NODE_OPTIONS").env_remove("NODE_PATH");
    if mode == "import" {
        command.args(["--experimental-import-meta-resolve", "--input-type=module", "-e", r#"
import {pathToFileURL,fileURLToPath} from 'node:url';
try { const u=new URL(import.meta.resolve(process.argv[2],pathToFileURL(process.argv[1])));
console.log(JSON.stringify({path:fileURLToPath(u),suffix:u.search+u.hash})); }
catch(e) { console.log(JSON.stringify({code:e.code})); }
"#]);
    } else {
        command.args(["-e", r#"
try { console.log(JSON.stringify({path:require('module').createRequire(process.argv[1]).resolve(process.argv[2]),suffix:''})); }
catch(e) { console.log(JSON.stringify({code:e.code})); }
"#]);
    }
    command.arg(root.join(from)).arg(request);
    let output = bounded(command);
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).unwrap()
}
fn same_as_node(root: &Path, from: &str, request: &str, mode: &str) -> Value {
    let report = selected(root, from, request, mode);
    let reference = node(root, from, request, mode);
    assert_eq!(root.join(report["resolution"]["path"].as_str().unwrap()).to_str().unwrap(), reference["path"], "{report}");
    assert_eq!(report["resolution"]["url_suffix"], reference["suffix"]);
    report
}

#[test]
fn conditional_nearest_nested_scoped_and_alias_packages_resolve_actual_files() {
    let root = fixture();
    source(root.path(), "packages/api/app.js");
    for dir in ["node_modules/pkg", "packages/api/node_modules/pkg", "node_modules/@scope/alias"] {
        put(root.path(), &format!("{dir}/package.json"), br#"{"name":"actual-name","exports":{"import":"./esm.mjs","require":"./cjs.cjs"}}"#);
        source(root.path(), &format!("{dir}/esm.mjs")); source(root.path(), &format!("{dir}/cjs.cjs"));
    }
    for mode in ["import","require"] {
        for (from, req) in [("app.js","pkg"),("packages/api/app.js","pkg"),("packages/api/app.js","@scope/alias")] {
            let result = same_as_node(root.path(), from, req, mode);
            assert_eq!(result["resolution"]["mappings"].as_array().unwrap().len(), 1);
        }
    }
}

#[test]
fn main_extension_index_and_strict_esm_resolution_follow_distinct_rules() {
    let root = fixture();
    source(root.path(), "local.js"); source(root.path(), "folder.js"); source(root.path(), "folder/index.js");
    put(root.path(), "node_modules/legacy/package.json", br#"{"main":"lib"}"#);
    source(root.path(), "node_modules/legacy/lib/index.js");
    for req in ["./local", "./folder", "./folder/", "legacy", "./local.js"] { same_as_node(root.path(), "app.js", req, "require"); }
    for req in ["legacy", "./local.js"] { same_as_node(root.path(), "app.js", req, "import"); }
    for (req, error) in [("./local","ERR_MODULE_NOT_FOUND"),("./folder","ERR_UNSUPPORTED_DIR_IMPORT")] {
        let (code, report) = run(root.path(), "app.js", req, "import", &[]);
        assert_eq!(code, 1); assert_eq!(report["error_code"], error);
        // import.meta.resolve intentionally permits nonexistent files. This
        // command implements the existence check before any eventual loading.
    }
}

#[test]
fn self_and_internal_external_imports_resolve_without_losing_map_witnesses() {
    let root = fixture();
    put(root.path(), "package.json", br##"{"name":"application","exports":{"./feature":"./local.mjs"},"imports":{"#local":"./local.mjs","#external":"dependency/feature"}}"##);
    source(root.path(), "local.mjs");
    put(root.path(), "node_modules/dependency/package.json", br#"{"exports":{"./feature":"./result.cjs"}}"#);
    source(root.path(), "node_modules/dependency/result.cjs");
    for mode in ["import","require"] {
        for req in ["application/feature","#local","#external"] { same_as_node(root.path(), "app.js", req, mode); }
    }
    let report = selected(root.path(), "app.js", "#external", "require");
    assert_eq!(report["resolution"]["mappings"].as_array().unwrap().len(), 2);
}

#[test]
fn exports_encapsulation_blocks_legacy_paths_and_outer_package_fallback() {
    let root = fixture(); source(root.path(), "packages/api/app.js");
    put(root.path(), "packages/api/node_modules/pkg/package.json", br#"{"exports":{".":"./entry.cjs","./private":null},"main":"private.js"}"#);
    source(root.path(), "packages/api/node_modules/pkg/private.js");
    source(root.path(), "node_modules/pkg/private.js");
    for mode in ["import","require"] {
        let (code, report) = run(root.path(), "packages/api/app.js", "pkg/private", mode, &[]);
        assert_eq!(code, 1); assert_eq!(report["error_code"], "ERR_PACKAGE_PATH_NOT_EXPORTED");
        assert_eq!(node(root.path(), "packages/api/app.js", "pkg/private", mode)["code"], report["error_code"]);
    }
}

#[test]
fn package_maps_never_try_a_later_array_target_when_the_first_file_is_absent() {
    let root = fixture();
    put(root.path(), "node_modules/pkg/package.json", br#"{"exports":["./missing","./present.js"]}"#);
    source(root.path(), "node_modules/pkg/missing.js"); source(root.path(), "node_modules/pkg/present.js");
    let (code, report) = run(root.path(), "app.js", "pkg", "require", &[]);
    assert_eq!(code, 1); assert_eq!(report["error_code"], "MODULE_NOT_FOUND");
    assert_eq!(node(root.path(), "app.js", "pkg", "require")["code"], "MODULE_NOT_FOUND");
}

#[test]
fn wildcard_urls_and_literal_commonjs_names_are_not_conflated() {
    let root = fixture();
    put(root.path(), "node_modules/pkg/package.json", br#"{"exports":{"./*":"./files/*.mjs?context=one#part"}}"#);
    source(root.path(), "node_modules/pkg/files/a b.mjs");
    for mode in ["import","require"] { same_as_node(root.path(), "app.js", "pkg/a%20b", mode); }
    source(root.path(), "literal%20name.cjs"); same_as_node(root.path(), "app.js", "./literal%20name.cjs", "require");
    source(root.path(), "space name.mjs"); same_as_node(root.path(), "app.js", "./space%20name.mjs?query=2#hash", "import");
}

#[test]
fn pin_binds_source_bytes_negative_probes_and_context_not_just_manifest_metadata() {
    let root = fixture(); source(root.path(), "lib/index.js");
    let before = selected(root.path(), "app.js", "./lib", "require");
    let pin = before["input_hash"].as_str().unwrap();
    let (code, same) = run(root.path(), "app.js", "./lib", "require", &["--expected-hash",pin]);
    assert_eq!(code, 0); assert_eq!(same["expected_hash_matched"], true);
    source(root.path(), "lib.js");
    let (code, changed) = run(root.path(), "app.js", "./lib", "require", &["--expected-hash",pin]);
    assert_eq!(code, 1); assert_eq!(changed["verdict"], "HASH_MISMATCH"); assert!(changed["resolution"].is_null());
    let current = selected(root.path(), "app.js", "./lib", "require");
    put(root.path(), "lib.js", b"different source, unchanged manifest");
    let (code, changed) = run(root.path(), "app.js", "./lib", "require", &["--expected-hash",current["input_hash"].as_str().unwrap()]);
    assert_eq!(code, 1); assert_eq!(changed["verdict"], "HASH_MISMATCH");
    let (code, changed_context) = run(root.path(), "app.js", "./lib", "require", &["--condition","custom","--expected-hash",pin]);
    assert_eq!(code, 1); assert_eq!(changed_context["verdict"], "HASH_MISMATCH");
}

#[test]
fn relocation_and_unused_files_do_not_change_the_bounded_resolution_identity() {
    let first = fixture(); let second = fixture();
    for root in [first.path(),second.path()] { source(root,"selected.cjs"); }
    let a = selected(first.path(),"app.js","./selected.cjs","require");
    source(second.path(),"unrelated.cjs");
    let b = selected(second.path(),"app.js","./selected.cjs","require");
    assert_eq!(a["input_hash"],b["input_hash"]);
    assert_eq!(a["resolution"]["content_sha256"],hex::encode(Sha256::digest(fs::read(first.path().join("selected.cjs")).unwrap())));
}

#[test]
fn symlinked_packages_manifests_sources_and_fifos_fail_without_following_or_blocking() {
    let root = fixture(); source(root.path(),"real.cjs");
    symlink("real.cjs",root.path().join("linked.cjs")).unwrap();
    let (code,report) = run(root.path(),"app.js","./linked.cjs","require",&[]);
    assert_eq!(code,2); assert_eq!(report["error_code"],"ERR_UNSUPPORTED_MODULE_FILE");
    fs::create_dir_all(root.path().join("node_modules")).unwrap();
    symlink("..",root.path().join("node_modules/pkg")).unwrap();
    assert_eq!(run(root.path(),"app.js","pkg","import",&[]).0,2);
    let mut command = Command::new("mkfifo"); command.arg(root.path().join("request.cjs"));
    assert!(bounded(command).status.success());
    let (code,report) = run(root.path(),"app.js","./request.cjs","require",&[]);
    assert_eq!(code,2); assert_eq!(report["error_code"],"ERR_UNSUPPORTED_MODULE_FILE");
}

#[test]
fn ambient_search_roots_cannot_supply_an_absent_project_dependency() {
    let outer = tempfile::tempdir().unwrap();
    let root=outer.path().join("project"); fs::create_dir(&root).unwrap(); source(&root,"app.js");
    source(outer.path(),"node_modules/hidden/index.js");
    let mut command=Command::new(env!("CARGO_BIN_EXE_franken-module-graph"));
    command.arg(&root).args(["--resolve-module","hidden","--from","app.js","--resolution-mode","require"])
        .env("NODE_PATH",outer.path().join("node_modules"));
    let output=bounded(command); assert_eq!(output.status.code(),Some(1));
    let report:Value=serde_json::from_slice(&output.stdout).unwrap(); assert_eq!(report["error_code"],"MODULE_NOT_FOUND");
}

#[test]
fn builtin_requests_and_unmarked_javascript_require_runtime_decisions() {
    let root=fixture(); source(root.path(),"node_modules/fs/index.js");
    for req in ["fs","fs/promises","node:fs","node:not-a-real-module"] {
        let (code,report)=run(root.path(),"app.js",req,"import",&[]);
        assert_eq!(code,1); assert_eq!(report["verdict"],"RUNTIME_REQUIRED"); assert_eq!(report["filesystem_verified"],false);
    }
    put(root.path(),"package.json",b"{}"); source(root.path(),"unmarked.js");
    assert_eq!(selected(root.path(),"app.js","./unmarked.js","import")["resolution"]["format_hint"],"javascript_unspecified");
}

#[test]
fn ambiguous_modes_invalid_pins_and_noncanonical_importers_never_produce_resolution() {
    let root=fixture();
    for flags in [vec!["--resolve-module","./app.js"],vec!["--from","app.js"],
        vec!["--resolution-mode","require"],vec!["--resolve-module","./app.js","--from","app.js","--resolve-export","."],
        vec!["--resolve-module","./app.js","--from","app.js","--package-manifest","package.json"],
        vec!["--resolve-module","./app.js","--from","app.js","--require-resolved"]] {
        let mut cmd=Command::new(env!("CARGO_BIN_EXE_franken-module-graph"));cmd.arg(root.path()).args(flags);
        assert_eq!(bounded(cmd).status.code(),Some(2));
    }
    let (code,report)=run(root.path(),"./app.js","./app.js","import",&[]);
    assert_eq!(code,2); assert_eq!(report["error_code"],"ERR_INVALID_MODULE_SPECIFIER");
    let (code,report)=run(root.path(),"app.js","./app.js","import",&["--expected-hash","not-a-pin"]);
    assert_eq!(code,2); assert_eq!(report["verdict"],"ERROR");
}

fn link(root: &Path, name: &str, target: &str) {
    fs::create_dir_all(root.join(name).parent().unwrap()).unwrap();
    symlink(target, root.join(name)).unwrap();
}
fn linked_selection(root: &Path, from: &str, request: &str, mode: &str) -> Value {
    let (code, report) = run(root, from, request, mode, &["--allow-contained-symlinks"]);
    assert_eq!(code, 0, "{report}");
    assert_eq!(report["symlink_policy"], "contained");
    assert_eq!(report["resolution"]["symlink_policy"], "contained");
    assert_eq!(report["resolution"]["schema_version"], "franken-node/module-file-resolution/v2");
    // Ordinary loaded Node modules use their physical filename as context. A
    // synthetic createRequire(alias) is a different, explicitly lexical API.
    let physical_from = fs::canonicalize(root.join(from)).unwrap();
    let physical_from = physical_from.strip_prefix(fs::canonicalize(root).unwrap()).unwrap().to_str().unwrap();
    let reference = node(root, physical_from, request, mode);
    assert_eq!(root.join(report["resolution"]["path"].as_str().unwrap()).to_str().unwrap(), reference["path"], "{report}");
    assert_eq!(report["resolution"]["url_suffix"], reference["suffix"]);
    report
}

#[test]
fn workspace_package_links_are_opt_in_and_match_node_in_both_modes() {
    let root = fixture();
    put(root.path(), "packages/pkg/package.json", br#"{"name":"pkg","exports":{"import":"./main.mjs","require":"./main.cjs"}}"#);
    source(root.path(), "packages/pkg/main.mjs");
    source(root.path(), "packages/pkg/main.cjs");
    link(root.path(), "node_modules/pkg", "../packages/pkg");
    let (code, rejected) = run(root.path(), "app.js", "pkg", "import", &[]);
    assert_eq!(code, 2);
    assert_eq!(rejected["error_code"], "ERR_UNSUPPORTED_MODULE_FILE");
    assert_eq!(rejected["symlink_policy"], "reject");
    for mode in ["import", "require"] {
        let report = linked_selection(root.path(), "app.js", "pkg", mode);
        assert_eq!(report["resolution"]["resolved_importer"], "app.js");
        let probe = report["resolution"]["probes"].as_array().unwrap().iter().find(|p| p["path"] == "node_modules/pkg").unwrap();
        assert_eq!(probe["kind"], "symlink");
        assert_eq!(probe["link_target"], "../packages/pkg");
        assert_eq!(probe["sha256"], hex::encode(Sha256::digest(b"../packages/pkg")));
    }
}

#[test]
fn pnpm_linked_importers_select_physical_nested_versions_not_hoisted_names() {
    let root = fixture();
    source(root.path(), "node_modules/.pnpm/pkg@1/node_modules/pkg/app.cjs");
    for version in ["1", "2"] {
        let base = format!("node_modules/.pnpm/dep@{version}/node_modules/dep");
        put(root.path(), &format!("{base}/package.json"), br#"{"exports":"./index.cjs"}"#);
        source(root.path(), &format!("{base}/index.cjs"));
    }
    link(root.path(), "node_modules/pkg", ".pnpm/pkg@1/node_modules/pkg");
    link(root.path(), "node_modules/dep", ".pnpm/dep@2/node_modules/dep");
    link(root.path(), "node_modules/.pnpm/pkg@1/node_modules/dep", "../../dep@1/node_modules/dep");
    for mode in ["import", "require"] {
        let nested = linked_selection(root.path(), "node_modules/pkg/app.cjs", "dep", mode);
        assert_eq!(nested["resolution"]["path"], "node_modules/.pnpm/dep@1/node_modules/dep/index.cjs");
        assert_eq!(nested["resolution"]["resolved_importer"], "node_modules/.pnpm/pkg@1/node_modules/pkg/app.cjs");
        let root_report = linked_selection(root.path(), "app.js", "dep", mode);
        assert_eq!(root_report["resolution"]["path"], "node_modules/.pnpm/dep@2/node_modules/dep/index.cjs");
    }
}

#[test]
fn linked_self_internal_and_external_imports_keep_the_real_package_scope() {
    let root = fixture();
    put(root.path(), "packages/pkg/package.json", br##"{"name":"pkg","type":"module","exports":{"./self":"./local.js"},"imports":{"#local":"./local.js","#dep":"dep"}}"##);
    source(root.path(), "packages/pkg/app.js");
    source(root.path(), "packages/pkg/local.js");
    source(root.path(), "packages/pkg/node_modules/dep/index.cjs");
    put(root.path(), "packages/pkg/node_modules/dep/package.json", br#"{"exports":"./index.cjs"}"#);
    link(root.path(), "node_modules/pkg", "../packages/pkg");
    for mode in ["import", "require"] {
        for request in ["pkg/self", "#local"] {
            let report = linked_selection(root.path(), "node_modules/pkg/app.js", request, mode);
            assert_eq!(report["resolution"]["format_hint"], "module");
            assert_eq!(report["resolution"]["path"], "packages/pkg/local.js");
        }
        let report = linked_selection(root.path(), "node_modules/pkg/app.js", "#dep", mode);
        assert_eq!(report["resolution"]["path"], "packages/pkg/node_modules/dep/index.cjs");
    }
}

#[test]
fn linked_files_keep_physical_format_and_query_fragment_identity() {
    let root = fixture();
    source(root.path(), "real/value.mjs");
    link(root.path(), "alias.cjs", "real/value.mjs");
    let report = linked_selection(root.path(), "app.js", "./alias.cjs?one#two", "import");
    assert_eq!(report["resolution"]["format_hint"], "module");
    assert_eq!(report["resolution"]["url_suffix"], "?one#two");
    assert_eq!(linked_selection(root.path(), "app.js", "./alias.cjs", "require")["resolution"]["path"], "real/value.mjs");
}

#[test]
fn link_target_spelling_policy_and_retargeting_invalidate_reviewed_pins() {
    let root = fixture();
    source(root.path(), "value.mjs");
    let strict = selected(root.path(), "app.js", "./value.mjs", "import");
    let (code, policy_mismatch) = run(root.path(), "app.js", "./value.mjs", "import",
        &["--allow-contained-symlinks", "--expected-hash", strict["input_hash"].as_str().unwrap()]);
    assert_eq!(code, 1);
    assert_eq!(policy_mismatch["verdict"], "HASH_MISMATCH");
    assert!(policy_mismatch["resolution"].is_null());
    link(root.path(), "alias", "value.mjs");
    let first = linked_selection(root.path(), "app.js", "./alias", "import");
    let pin = first["input_hash"].as_str().unwrap();
    let (code, same) = run(root.path(), "app.js", "./alias", "import", &["--allow-contained-symlinks", "--expected-hash", pin]);
    assert_eq!(code, 0, "{same}");
    link(root.path(), "replacement", "./value.mjs");
    fs::rename(root.path().join("replacement"), root.path().join("alias")).unwrap();
    let (code, mismatch) = run(root.path(), "app.js", "./alias", "import", &["--allow-contained-symlinks", "--expected-hash", pin]);
    assert_eq!(code, 1);
    assert_eq!(mismatch["verdict"], "HASH_MISMATCH");
    assert_eq!(mismatch["filesystem_verified"], false);
    assert!(mismatch["resolution"].is_null());
}

#[test]
fn relative_linked_projects_keep_the_same_pin_after_relocation() {
    let first = fixture();
    let second = fixture();
    for root in [first.path(), second.path()] {
        source(root, "packages/pkg/index.cjs");
        put(root, "packages/pkg/package.json", br#"{"exports":"./index.cjs"}"#);
        link(root, "node_modules/pkg", "../packages/pkg");
    }
    let original = linked_selection(first.path(), "app.js", "pkg", "require");
    let moved = linked_selection(second.path(), "app.js", "pkg", "require");
    assert_eq!(original, moved);
}

#[test]
fn contained_links_never_allow_escape_cycles_fifo_or_reserved_state() {
    let root = fixture();
    for (name, target, expected) in [
        ("escape", "../outside.js", "ERR_MODULE_OUTSIDE_PROJECT"),
        ("absolute", "/etc/passwd", "ERR_INVALID_MODULE_SYMLINK"),
        ("reserved", ".git/HEAD", "ERR_INVALID_MODULE_SYMLINK"),
        ("cycle", "cycle", "ERR_MODULE_SYMLINK_LOOP"),
    ] {
        link(root.path(), name, target);
        let (code, report) = run(root.path(), "app.js", &format!("./{name}"), "import", &["--allow-contained-symlinks"]);
        assert_eq!(code, 2, "{report}");
        assert_eq!(report["error_code"], expected);
        assert_eq!(report["filesystem_verified"], false);
        assert!(report["resolution"].is_null());
    }
    let directory = fs::File::open(root.path()).unwrap();
    rustix::fs::mkfifoat(&directory, "fifo", rustix::fs::Mode::RUSR | rustix::fs::Mode::WUSR).unwrap();
    link(root.path(), "fifo-alias", "fifo");
    let (code, report) = run(root.path(), "app.js", "./fifo-alias", "import", &["--allow-contained-symlinks"]);
    assert_eq!(code, 2);
    assert_eq!(report["error_code"], "ERR_UNSUPPORTED_MODULE_FILE");
}

#[test]
fn linked_export_blocks_and_missing_selected_targets_never_fall_back() {
    let root = fixture();
    put(root.path(), "packages/pkg/package.json", br#"{"exports":{".":["./missing","./fallback.js"],"./blocked":null},"main":"fallback.js"}"#);
    source(root.path(), "packages/pkg/fallback.js");
    source(root.path(), "packages/pkg/missing.js");
    link(root.path(), "node_modules/pkg", "../packages/pkg");
    for mode in ["import", "require"] {
        for request in ["pkg", "pkg/blocked"] {
            let (code, report) = run(root.path(), "app.js", request, mode, &["--allow-contained-symlinks"]);
            assert_eq!(code, 1, "{report}");
            assert_eq!(report["verdict"], "UNRESOLVED");
            assert!(report["resolution"].is_null());
            let reference = node(root.path(), "app.js", request, mode);
            if mode == "import" && request == "pkg" {
                // import.meta.resolve returns even missing file URLs; our file
                // capture additionally requires existence, never a fallback.
                assert_eq!(report["error_code"], "ERR_MODULE_NOT_FOUND");
                assert!(reference["path"].as_str().unwrap().ends_with("/missing"));
            } else {
                assert_eq!(report["error_code"], reference["code"]);
            }
        }
    }
}

#[test]
fn link_policy_flag_is_rejected_outside_file_resolution() {
    for flags in [vec!["--allow-contained-symlinks"],
        vec!["--transitive", "--allow-contained-symlinks"],
        vec!["--resolve-export", ".", "--allow-contained-symlinks"]] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_franken-module-graph"));
        command.arg("/must-not-be-inspected").args(flags);
        let output = bounded(command);
        assert_eq!(output.status.code(), Some(2), "{output:?}");
        assert!(output.stdout.is_empty());
    }
}
