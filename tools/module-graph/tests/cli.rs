//! Execute the actual native graph command, including a Node resolver oracle.
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use tempfile::TempDir;

fn put(root: &Path, path: &str, value: Value) {
    let destination = root.join(path);
    fs::create_dir_all(destination.parent().unwrap()).unwrap();
    fs::write(destination, serde_json::to_vec(&value).unwrap()).unwrap();
}

fn fixture(packages: Value) -> TempDir {
    let temp = tempfile::tempdir().unwrap();
    put(temp.path(), "package.json", json!({"name":"root", "version":"1.0.0",
        "workspaces":["packages/*"], "dependencies":{"dep":"*"}}));
    put(temp.path(), "packages/a/package.json", json!({"name":"app-a", "dependencies":{"dep":"*"}}));
    put(temp.path(), "packages/b/package.json", json!({"name":"app-b", "dependencies":{"dep":"*"}}));
    put(temp.path(), "package-lock.json", json!({"lockfileVersion":3, "packages":packages}));
    temp
}

fn invoke(root: &Path, args: &[&str]) -> (Output, Value) {
    let output = Command::new(env!("CARGO_BIN_EXE_franken-module-graph"))
        .arg(root).args(args).output().unwrap();
    let value: Value = serde_json::from_slice(&output.stdout)
        .unwrap_or_else(|error| panic!("{error}: {}", String::from_utf8_lossy(&output.stderr)));
    (output, value)
}

fn selected(root: &Path, importer: &str, name: &str) -> Value {
    let (output, value) = invoke(root, &["--importer", importer, "--dependency", name]);
    assert!(output.status.success(), "{value}");
    assert_eq!(value["execution_performed"], false);
    assert_eq!(value["release_certification"], false);
    value
}

#[test]
fn nearest_importer_pin_wins_and_sibling_versions_are_not_global() {
    let root = fixture(json!({
        "node_modules/dep":{"version":"1.0.0"},
        "packages/a/node_modules/dep":{"version":"2.0.0"},
        "packages/b/node_modules/dep":{"version":"3.0.0"},
        "node_modules/unrelated/node_modules/dep":{"version":"99.0.0"}
    }));
    for (importer, path, version) in [
        ("package.json", "node_modules/dep", "1.0.0"),
        ("packages/a/package.json", "packages/a/node_modules/dep", "2.0.0"),
        ("packages/b/package.json", "packages/b/node_modules/dep", "3.0.0"),
    ] {
        let value = selected(root.path(), importer, "dep");
        assert_eq!(value["edges"][0]["lockfile_package_path"], path);
        assert_eq!(value["pins"][0]["version"], version);
    }
}

#[test]
fn hoisting_checks_every_parent_and_unresolved_is_not_a_pass_under_required_resolution() {
    let root = fixture(json!({"packages/node_modules/dep":{"version":"4.0.0"}}));
    let value = selected(root.path(), "packages/a/package.json", "dep");
    assert_eq!(value["edges"][0]["lockfile_package_path"], "packages/node_modules/dep");
    let (output, value) = invoke(root.path(), &["--dependency", "dep", "--require-resolved"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(value["verdict"], "UNRESOLVED");
    assert_eq!(value["unresolved_edges"], 1);
}

#[test]
fn scoped_installation_alias_keeps_actual_package_identity() {
    let root = fixture(json!({"node_modules/@alias/tool":{"name":"real-tool", "version":"7.1.0"}}));
    put(root.path(), "package.json", json!({"name":"root", "dependencies":{"@alias/tool":"npm:real-tool@7.1.0"}}));
    let value = selected(root.path(), "package.json", "@alias/tool");
    assert_eq!(value["edges"][0]["lockfile_package_path"], "node_modules/@alias/tool");
    assert_eq!(value["pins"][0]["package_name"], "real-tool");
}

#[test]
fn legacy_v1_retains_nested_installations_without_overwriting_hoisted_pin() {
    let root = fixture(json!({}));
    put(root.path(), "package-lock.json", json!({"lockfileVersion":1, "dependencies":{
        "dep":{"version":"1.0.0"},
        "parent":{"version":"3.0.0", "requires":{"dep":"2.0.0"},
            "dependencies":{"dep":{"version":"2.0.0", "integrity":"sha512-nested"}}}
    }}));
    let value = selected(root.path(), "package.json", "dep");
    assert_eq!(value["pins"][0]["version"], "1.0.0");
    let (output, value) = invoke(root.path(), &[]);
    assert!(output.status.success());
    let pins = value["graph"]["lockfile_pins"].as_array().unwrap();
    assert_eq!(pins.len(), 3);
    assert!(pins.iter().any(|pin| pin["package_path"] == "node_modules/parent/node_modules/dep"
        && pin["integrity"] == "sha512-nested"));
}

#[test]
fn modern_packages_are_authoritative_over_legacy_compatibility_records() {
    let root = fixture(json!({"node_modules/dep":{"version":"2.0.0"}}));
    put(root.path(), "package-lock.json", json!({"lockfileVersion":2,
        "packages":{"node_modules/dep":{"version":"2.0.0"}},
        "dependencies":{"dep":{"version":"old-value"}}}));
    assert_eq!(selected(root.path(), "package.json", "dep")["pins"][0]["version"], "2.0.0");
}

#[test]
fn ordinary_dependency_is_not_bound_to_a_workspace_just_by_name() {
    let root = fixture(json!({"node_modules/dep":{"version":"5.0.0"}}));
    put(root.path(), "packages/a/package.json", json!({"name":"dep", "version":"1.0.0"}));
    let value = selected(root.path(), "package.json", "dep");
    assert!(value["edges"][0]["target_package_id"].is_null());
    assert_eq!(value["pins"][0]["version"], "5.0.0");
}

#[test]
fn recorded_workspace_link_and_explicit_workspace_intent_bind_distinctly() {
    let root = fixture(json!({"node_modules/dep":{"resolved":"packages/a", "link":true}}));
    put(root.path(), "packages/a/package.json", json!({"name":"dep", "version":"1.0.0"}));
    let value = selected(root.path(), "package.json", "dep");
    assert_eq!(value["edges"][0]["target_package_id"], "npm:dep@1.0.0#packages/a");
    assert_eq!(value["edges"][0]["lockfile_package_path"], "node_modules/dep");
    put(root.path(), "package-lock.json", json!({"lockfileVersion":3,"packages":{}}));
    put(root.path(), "package.json", json!({"name":"root","workspaces":["packages/*"],"dependencies":{"dep":"workspace:*"}}));
    let value = selected(root.path(), "package.json", "dep");
    assert_eq!(value["edges"][0]["target_package_id"], "npm:dep@1.0.0#packages/a");
    assert!(value["edges"][0]["lockfile_package_path"].is_null());
}

#[test]
fn duplicate_workspace_names_and_unverifiable_links_fail_closed() {
    let root = fixture(json!({"node_modules/dep":{"resolved":"outside", "link":true}}));
    let (output, value) = invoke(root.path(), &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(value["error"].as_str().unwrap().contains("uncaptured workspace"));
    put(root.path(), "package-lock.json", json!({"packages":{}}));
    put(root.path(), "packages/a/package.json", json!({"name":"same"}));
    put(root.path(), "packages/b/package.json", json!({"name":"same"}));
    let (output, value) = invoke(root.path(), &[]);
    assert_eq!(output.status.code(), Some(2));
    assert!(value["error"].as_str().unwrap().contains("duplicate workspace"));
}

#[test]
fn malformed_lockfiles_never_fall_back_to_an_empty_success_graph() {
    let root = fixture(json!({}));
    for bad in [
        json!(null), json!([]), json!({"lockfileVersion":99}),
        json!({"lockfileVersion":"3", "packages":{}}),
        json!({"lockfileVersion":3,"dependencies":{"dep":{"version":"1"}}}),
        json!({"packages":[]}), json!({"packages":{"node_modules/dep":null}}),
        json!({"packages":{"node_modules/dep":{"version":1}}}),
        json!({"packages":{"../node_modules/dep":{"version":"1"}}}),
        json!({"packages":{"node_modules/dep/extra":{"version":"1"}}}),
        json!({"packages":{"node_modules/@scope":{"version":"1"}}}),
        json!({"packages":{"node_modules/dep":{"link":"true","resolved":"packages/a"}}}),
        json!({"dependencies":{"../escape":{"version":"1"}}}),
        json!({"dependencies":{"dep":{"requires":{"x":1}}}}),
    ] {
        put(root.path(), "package-lock.json", bad.clone());
        let (output, value) = invoke(root.path(), &[]);
        assert_eq!(output.status.code(), Some(2), "accepted {bad}: {value}");
        assert_eq!(value["verdict"], "ERROR");
    }
}

#[test]
fn graph_pin_detects_changed_dependency_identity_and_is_relocation_stable() {
    let root = fixture(json!({"node_modules/dep":{"version":"1.0.0", "integrity":"sha512-first"}}));
    let other = fixture(json!({"node_modules/dep":{"integrity":"sha512-first", "version":"1.0.0"}}));
    let (_, first) = invoke(root.path(), &[]);
    let (_, second) = invoke(other.path(), &[]);
    assert_eq!(first["canonical_hash"], second["canonical_hash"]);
    let pin = first["canonical_hash"].as_str().unwrap();
    assert!(invoke(root.path(), &["--expected-hash", pin]).0.status.success());
    put(root.path(), "package-lock.json", json!({"lockfileVersion":3,
        "packages":{"node_modules/dep":{"version":"1.0.0", "integrity":"sha512-changed"}}}));
    let (output, value) = invoke(root.path(), &["--expected-hash", pin]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(value["verdict"], "HASH_MISMATCH");
    assert_eq!(value["expected_hash_matched"], false);
}

#[test]
fn unsupported_importer_and_manifest_requirements_fail_before_resolution() {
    let root = fixture(json!({}));
    for args in [vec!["--dependency","missing"],
        vec!["--dependency","dep","--importer","./package.json"],
        vec!["--expected-hash","sha256:garbage"]] {
        assert_eq!(invoke(root.path(), &args).0.status.code(), Some(2));
    }
    for manifest in [json!([]), json!({"dependencies":[]}),
        json!({"dependencies":{"../dep":"1"}}), json!({"dependencies":{"dep":false}})] {
        put(root.path(), "package.json", manifest);
        assert_eq!(invoke(root.path(), &[]).0.status.code(), Some(2));
    }
}

#[test]
fn pin_lookup_agrees_with_real_node_for_nested_hoisted_scoped_and_alias_packages() {
    let root = fixture(json!({
        "node_modules/dep":{"version":"1.0.0"},
        "packages/a/node_modules/dep":{"version":"2.0.0"},
        "node_modules/@scope/tool":{"version":"3.0.0"},
        "node_modules/alias":{"name":"actual","version":"4.0.0"}
    }));
    for (path, name, version) in [
        ("node_modules/dep", "dep", "1.0.0"),
        ("packages/a/node_modules/dep", "dep", "2.0.0"),
        ("node_modules/@scope/tool", "@scope/tool", "3.0.0"),
        ("node_modules/alias", "actual", "4.0.0"),
    ] {
        put(root.path(), &format!("{path}/package.json"), json!({"name":name,"version":version,"main":"index.js"}));
        fs::write(root.path().join(path).join("index.js"), "throw new Error('must not execute package code');").unwrap();
    }
    put(root.path(), "package.json", json!({"name":"root","workspaces":["packages/*"],
        "dependencies":{"dep":"*","@scope/tool":"*","alias":"npm:actual@4.0.0"}}));
    for (importer, name) in [("package.json","dep"), ("packages/a/package.json","dep"),
        ("packages/b/package.json","dep"), ("package.json","@scope/tool"), ("package.json","alias")] {
        let value = selected(root.path(), importer, name);
        let output = Command::new("node").arg("-e").arg(
            "const {createRequire}=require('module'); const p=require('path'); const r=createRequire(p.resolve(process.argv[1])); process.stdout.write(p.relative(process.cwd(),p.dirname(r.resolve(process.argv[2]))).split(p.sep).join('/'));"
        ).arg(importer).arg(name).current_dir(root.path()).output().expect("Node oracle must be available");
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert_eq!(value["edges"][0]["lockfile_package_path"], String::from_utf8(output.stdout).unwrap());
    }
}
