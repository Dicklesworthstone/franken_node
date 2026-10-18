//! Real native CLI coverage of transitive queries, not a reimplemented graph.
use super::*;

#[cfg(target_os = "linux")]
#[test]
fn cli_bun_manifest_capture_bounds_include_root_before_parsing_more_workspaces() {
    let root = tempfile::tempdir().unwrap();
    put(root.path(), "package.json", json!({"workspaces":["packages/*"]}));
    // Each workspace is within the per-file bound. The root makes this total
    // exceed the aggregate bound; rejection must precede Bun lock projection.
    let prefix = "{\"padding\":\"";
    let suffix = "\"}";
    let manifest = format!("{prefix}{}{suffix}", "x".repeat(512 * 1024 - prefix.len() - suffix.len()));
    for index in 0..64 {
        let directory = root.path().join(format!("packages/p{index:02}"));
        fs::create_dir_all(&directory).unwrap();
        fs::write(directory.join("package.json"), &manifest).unwrap();
    }
    put(root.path(), "bun.lock", json!({}));
    let (output, value) = invoke(root.path(), &["--transitive"]);
    assert_eq!(output.status.code(), Some(2));
    assert!(value.to_string().contains("captured manifest bytes"), "{value}");
}

fn chain() -> TempDir {
    let root = fixture(json!({
        "node_modules/dep":{"version":"1", "dependencies":{"leaf":"*"}},
        "node_modules/leaf":{"version":"1"},
        "packages/a/node_modules/dep":{"version":"2", "dependencies":{"leaf":"*"}},
        "packages/a/node_modules/dep/node_modules/leaf":{"version":"2"}
    }));
    root
}

#[test]
fn cli_transitive_closure_and_installed_importer_preserve_nearest_versions() {
    let root = chain();
    let (output, value) = invoke(root.path(), &["--transitive", "--require-resolved"]);
    assert!(output.status.success(), "{value}");
    assert_eq!(value["scope"], "declared-dependency-topology");
    assert_eq!(value["closure"]["reachable"], json!([".","node_modules/dep","node_modules/leaf"]));
    assert_eq!(value["fully_resolved"], true);
    let (output, value) = invoke(root.path(), &["--transitive", "--importer", "packages/a/node_modules/dep/package.json"]);
    assert!(output.status.success(), "{value}");
    assert_eq!(value["closure"]["reachable"], json!([
        "packages/a/node_modules/dep", "packages/a/node_modules/dep/node_modules/leaf"]));
    assert_eq!(value["execution_performed"], false);
}

#[test]
fn cli_impact_distinguishes_same_name_nested_instances_and_explains_the_path() {
    let root = chain();
    let (output, value) = invoke(root.path(), &["--impact", "packages/a/node_modules/dep/node_modules/leaf", "--require-resolved"]);
    assert!(output.status.success(), "{value}");
    assert_eq!(value["impact"]["affected_manifests"], json!(["packages/a/package.json"]));
    assert_eq!(value["impact"]["toward_target"], json!([
        {"location":"packages/a","next":"packages/a/node_modules/dep"},
        {"location":"packages/a/node_modules/dep","next":"packages/a/node_modules/dep/node_modules/leaf"}
    ]));
    let (_, other) = invoke(root.path(), &["--impact", "node_modules/leaf"]);
    assert_eq!(other["impact"]["affected_manifests"], json!(["package.json","packages/b/package.json"]));
}

#[test]
fn cli_missing_optional_and_peer_requirements_are_visible_not_silently_complete() {
    let root = fixture(json!({"node_modules/dep":{
        "dependencies":{"needed":"*","optional":"old"}, "optionalDependencies":{"optional":"new"},
        "peerDependencies":{"host":"*"}, "peerDependenciesMeta":{"host":{"optional":true}}
    }}));
    let (output, value) = invoke(root.path(), &["--transitive", "--require-resolved"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(value["verdict"], "UNRESOLVED");
    assert_eq!(value["closure"]["unresolved_required_edges"], 1);
    assert_eq!(value["closure"]["unresolved_optional_edges"], 2);
    assert_eq!(value["closure"]["metadata_complete"], true);
    assert_eq!(value["fully_resolved"], false);
    let edges = value["topology"]["edges"].as_array().unwrap();
    let selected: Vec<_> = edges.iter().filter(|edge| edge["importer"] == "node_modules/dep"
        && edge["dependency_name"] == "optional").collect();
    assert_eq!(selected.len(), 1);
    assert_eq!(selected[0]["requested_range"], "new");
    assert_eq!(selected[0]["dependency_kind"], "optional");
    assert!(invoke(root.path(), &["--transitive"]).0.status.success());
}

#[test]
fn cli_global_unknown_branch_prevents_false_negative_impact_certainty() {
    let root = fixture(json!({"node_modules/dep":{"dependencies":{"unknown":"*"}},"node_modules/unused":{}}));
    let (output, value) = invoke(root.path(), &["--impact", "node_modules/unused", "--require-resolved"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(value["impact"]["affected_manifests"], json!([]));
    assert_eq!(value["impact"]["unresolved_edges"].as_array().unwrap().len(), 1);
    assert_eq!(value["fully_resolved"], false);
}

#[test]
fn cli_scope_specific_hash_binds_optional_metadata_and_refuses_a_direct_graph_pin() {
    let root = fixture(json!({"node_modules/dep":{"optionalDependencies":{"x":"1"}}}));
    let (_, direct) = invoke(root.path(), &[]);
    let (_, topology) = invoke(root.path(), &["--transitive"]);
    let old_direct = direct["canonical_hash"].as_str().unwrap();
    let pin = topology["canonical_hash"].as_str().unwrap();
    assert_ne!(old_direct, pin);
    assert!(invoke(root.path(), &["--transitive","--expected-hash",pin]).0.status.success());
    let (output, value) = invoke(root.path(), &["--transitive","--expected-hash",old_direct]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(value["verdict"], "HASH_MISMATCH");
    put(root.path(), "package-lock.json", json!({"lockfileVersion":3,"packages":{
        "node_modules/dep":{"optionalDependencies":{"x":"2"}}
    }}));
    assert_eq!(invoke(root.path(), &[]).1["canonical_hash"], old_direct);
    let (output, value) = invoke(root.path(), &["--transitive","--expected-hash",pin,"--require-resolved"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(value["verdict"], "HASH_MISMATCH");
    assert_eq!(value["expected_hash_matched"], false);
}

#[test]
fn cli_workspace_link_and_uncaptured_workspace_intent_are_not_equivalent() {
    let root = fixture(json!({"node_modules/dep":{"resolved":"packages/a","link":true},
        "packages/a/node_modules/leaf":{"version":"2"}, "node_modules/leaf":{"version":"1"}}));
    put(root.path(), "packages/a/package.json", json!({"name":"dep","dependencies":{"leaf":"*"}}));
    let (output, value) = invoke(root.path(), &["--transitive", "--require-resolved"]);
    assert!(output.status.success(), "{value}");
    assert_eq!(value["closure"]["reachable"], json!([".","node_modules/dep","packages/a","packages/a/node_modules/leaf"]));
    put(root.path(), "package-lock.json", json!({"packages":{"packages/a/node_modules/leaf":{"version":"2"}}}));
    put(root.path(), "package.json", json!({"workspaces":["packages/*"],"dependencies":{"dep":"workspace:*"}}));
    let (output, value) = invoke(root.path(), &["--transitive", "--require-resolved"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(value["closure"]["intent_only_edges"].as_array().unwrap().len(), 1);
    assert_eq!(value["fully_resolved"], false);
}

#[test]
fn cli_legacy_requires_do_not_invent_missing_kind_information() {
    let root = fixture(json!({}));
    put(root.path(), "package-lock.json", json!({"lockfileVersion":1,"dependencies":{
        "dep":{"requires":{"leaf":"*"},"dependencies":{"leaf":{"version":"1"}}}
    }}));
    let (output, value) = invoke(root.path(), &["--transitive", "--require-resolved"]);
    assert_eq!(output.status.code(), Some(1));
    assert_eq!(value["closure"]["unresolved_edges"], json!([]));
    assert_eq!(value["closure"]["metadata_complete"], false);
    assert_eq!(value["fully_resolved"], false);
}

#[test]
fn cli_ambiguous_query_flags_are_rejected_before_project_inspection() {
    for args in [vec!["--importer","package.json"], vec!["--transitive","--dependency","dep"],
        vec!["--impact","node_modules/dep","--dependency","dep"],
        vec!["--impact","node_modules/dep","--transitive"],
        vec!["--impact","node_modules/dep","--importer","package.json"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_franken-module-graph"))
            .arg("/not-a-project").args(args).output().unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stdout.is_empty());
        assert!(!output.stderr.is_empty());
    }
}

#[test]
fn cli_query_errors_keep_scope_and_never_normalize_unknown_locations() {
    let root = chain();
    for args in [vec!["--transitive","--importer","./package.json"],
        vec!["--transitive","--importer","missing/package.json"],
        vec!["--impact","./node_modules/dep"], vec!["--impact","missing"]] {
        let (output, value) = invoke(root.path(), &args);
        assert_eq!(output.status.code(), Some(2));
        assert_eq!(value["scope"], "declared-dependency-topology");
        assert_eq!(value["verdict"], "ERROR");
        assert_eq!(value["execution_performed"], false);
    }
}

#[test]
fn cli_transitive_pin_selections_match_real_node_without_executing_package_code() {
    let root = fixture(json!({
        "node_modules/dep":{"name":"real-parent","version":"1", "dependencies":{"@scope/leaf":"*"}},
        "node_modules/dep/node_modules/@scope/leaf":{"version":"2","dependencies":{"tail":"*"}},
        "node_modules/@scope/leaf":{"version":"1"}, "node_modules/tail":{"version":"3"}
    }));
    for (path, name) in [("node_modules/dep","real-parent"),
        ("node_modules/dep/node_modules/@scope/leaf","@scope/leaf"),
        ("node_modules/@scope/leaf","@scope/leaf"), ("node_modules/tail","tail")] {
        put(root.path(), &format!("{path}/package.json"), json!({"name":name,"main":"index.js"}));
        fs::write(root.path().join(path).join("index.js"), "throw new Error('metadata query executed code');").unwrap();
    }
    let (output, value) = invoke(root.path(), &["--transitive", "--require-resolved"]);
    assert!(output.status.success(), "{value}");
    for edge in value["topology"]["edges"].as_array().unwrap().iter().filter(|edge|
        edge["importer"].as_str().unwrap().starts_with("node_modules/")) {
        let source = format!("{}/package.json", edge["importer"].as_str().unwrap());
        let output = Command::new("node").arg("-e").arg(
            "const p=require('path');const r=require('module').createRequire(p.resolve(process.argv[1]));process.stdout.write(p.relative(process.cwd(),p.dirname(r.resolve(process.argv[2]))).split(p.sep).join('/'));"
        ).arg(source).arg(edge["dependency_name"].as_str().unwrap()).current_dir(root.path())
            .output().expect("real Node resolver required");
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        assert_eq!(edge["target"], String::from_utf8(output.stdout).unwrap());
    }
    assert_eq!(value["release_certification"], false);
}

#[test]
fn root_optional_override_and_optional_peer_flags_reach_the_existing_direct_api() {
    let root = fixture(json!({}));
    put(root.path(), "package.json", json!({"dependencies":{"dep":"old"},
        "optionalDependencies":{"dep":"new"},"peerDependencies":{"host":"*"},
        "peerDependenciesMeta":{"host":{"optional":true}}}));
    let value = selected(root.path(), "package.json", "dep");
    assert_eq!(value["edges"].as_array().unwrap().len(), 1);
    assert_eq!(value["edges"][0]["requested_range"], "new");
    assert_eq!(value["edges"][0]["dependency_kind"], "optional");
    assert_eq!(selected(root.path(), "package.json", "host")["edges"][0]["optional"], true);
}

#[cfg(target_os = "linux")]
#[test]
fn cli_bun_text_lock_versions_preserve_nested_pins_and_hashes() {
    for version in [1, 2] {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "package.json", json!({"dependencies":{"dep":"^1"}}));
        let mut lock = json!({"lockfileVersion":version,
            "workspaces":{"":{"dependencies":{"dep":"^1"}}},
            "packages":{
                "dep":["dep@1.2.3","",{"dependencies":{"leaf":"^2"}},"sha512-cGFyZW50"],
                "dep/leaf":["leaf@2.3.4","",{},"sha512-c2VsZWN0ZWQ="],
                "leaf":["leaf@9.0.0","",{},"sha512-dW5yZWFjaGVk"]
            }});
        let mut raw = lock.to_string();
        assert_eq!(raw.pop(), Some('}'));
        raw.push_str(",}");
        fs::write(root.path().join("bun.lock"), format!("\u{feff}// Bun text lock\n{raw}")).unwrap();
        let (output, topology) = invoke(root.path(), &["--transitive", "--require-resolved"]);
        assert!(output.status.success(), "{topology}");
        assert_eq!(topology["closure"]["reachable"], json!([
            ".", "node_modules/dep", "node_modules/dep/node_modules/leaf"]));
        let pin = topology["canonical_hash"].as_str().unwrap();
        let (output, direct) = invoke(root.path(), &[]);
        assert!(output.status.success(), "{direct}");
        let nested = direct["graph"]["lockfile_pins"].as_array().unwrap().iter()
            .find(|pin| pin["package_path"] == "node_modules/dep/node_modules/leaf").unwrap();
        assert_eq!(nested["version"], "2.3.4");
        assert_eq!(nested["integrity"], "sha512-c2VsZWN0ZWQ=");
        assert_eq!(nested["resolved"], Value::Null, "empty Bun placeholders are not artifact identity");
        assert!(invoke(root.path(), &["--transitive", "--expected-hash", pin]).0.status.success());
        lock["packages"]["dep/leaf"][0] = json!("leaf@2.4.0");
        put(root.path(), "bun.lock", lock);
        let (output, changed) = invoke(root.path(), &["--transitive", "--expected-hash", pin]);
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(changed["verdict"], "HASH_MISMATCH");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn cli_bun_catalogs_bind_aliases_and_workspace_private_dependencies() {
    let root = tempfile::tempdir().unwrap();
    let workspace = json!({"name":"app", "version":"1.0.0",
        "dependencies":{"private":"catalog:local", "alias":"catalog:"}});
    put(root.path(), "package.json", json!({"name":"root",
        "workspaces":{"packages":["packages/*"], "catalog":{"alias":"npm:@scope/real@^2"},
            "catalogs":{"local":{"private":"^1"}}},
        "dependencies":{"app":"workspace:*"}}));
    put(root.path(), "packages/app/package.json", workspace.clone());
    put(root.path(), "bun.lock", json!({"lockfileVersion":2,
        "catalog":{"alias":"npm:@scope/real@^2"}, "catalogs":{"local":{"private":"^1"}},
        "workspaces":{"":{"name":"root","dependencies":{"app":"workspace:*"}},
            "packages/app":workspace},
        "packages":{
            "app":["app@workspace:packages/app"],
            "app/private":["private@1.2.3","",{},""],
            "private":["private@9.0.0","",{},""],
            "alias":["@scope/real@2.4.0","",{"dependencies":{"leaf":"1"}},""],
            "leaf":["leaf@1.0.0","",{},""]
        }}));
    let (output, value) = invoke(root.path(), &["--transitive", "--require-resolved"]);
    assert!(output.status.success(), "{value}");
    assert_eq!(value["closure"]["reachable"], json!([
        ".", "node_modules/alias", "node_modules/app", "node_modules/leaf",
        "packages/app", "packages/app/node_modules/private"]));
    let alias = selected(root.path(), "packages/app/package.json", "alias");
    assert_eq!(alias["edges"][0]["requested_range"], "npm:@scope/real@^2");
    assert_eq!(alias["pins"][0]["package_name"], "@scope/real");
    let private = selected(root.path(), "packages/app/package.json", "private");
    assert_eq!(private["edges"][0]["requested_range"], "^1");
    assert_eq!(private["pins"][0]["package_path"], "packages/app/node_modules/private");
    assert_eq!(private["pins"][0]["version"], "1.2.3");

    // Metadata changed after the captured lock was installed. It must not
    // yield a successful graph that omits the new transitive requirement.
    let mut stale = workspace;
    stale["dependencies"]["hidden"] = json!("1");
    put(root.path(), "packages/app/package.json", stale);
    let (output, value) = invoke(root.path(), &["--transitive"]);
    assert_eq!(output.status.code(), Some(2));
    assert_eq!(value["verdict"], "ERROR");
    assert!(value["error"].as_str().unwrap().contains("workspace dependencies differ"));
}

#[cfg(target_os = "linux")]
#[test]
fn cli_bun_malformed_mixed_binary_and_oversized_locks_never_lose_their_graph() {
    for case in ["duplicate", "duplicate-manifest", "mixed", "binary", "oversized", "workspace-type", "catalog-mismatch"] {
        let root = tempfile::tempdir().unwrap();
        put(root.path(), "package.json", json!({}));
        let empty = json!({"lockfileVersion":2,"workspaces":{"":{}},"packages":{}});
        match case {
            "duplicate" => fs::write(root.path().join("bun.lock"),
                "{\"lockfileVersion\":2,\"workspaces\":{\"\":{}},\"packages\":{},\"packages\":{}}").unwrap(),
            "duplicate-manifest" => {
                fs::write(root.path().join("package.json"), "{\"dependencies\":{},\"dependencies\":{}}").unwrap();
                put(root.path(), "bun.lock", empty);
            }
            "mixed" => {
                put(root.path(), "bun.lock", empty);
                put(root.path(), "package-lock.json", json!({"lockfileVersion":3,"packages":{}}));
            }
            "binary" => fs::write(root.path().join("bun.lockb"), [0xff,0,1]).unwrap(),
            "oversized" => std::fs::File::create(root.path().join("bun.lock")).unwrap()
                .set_len(4 * 1024 * 1024 + 1).unwrap(),
            "workspace-type" => {
                put(root.path(), "package.json", json!({"workspaces":[42]}));
                put(root.path(), "bun.lock", empty);
            }
            "catalog-mismatch" => {
                put(root.path(), "package.json", json!({"catalog":{"alias":"npm:real@^1"},
                    "dependencies":{"alias":"catalog:"}}));
                put(root.path(), "bun.lock", json!({"lockfileVersion":2,
                    "catalog":{"alias":"npm:other@^1"},
                    "workspaces":{"":{"dependencies":{"alias":"catalog:"}}},
                    "packages":{"alias":["other@1.0.0","",{},""]}}));
            }
            _ => unreachable!(),
        }
        let (output, value) = invoke(root.path(), &["--transitive"]);
        assert_eq!(output.status.code(), Some(2), "{case}: {value}");
        assert_eq!(value["scope"], "declared-dependency-topology");
        assert_eq!(value["verdict"], "ERROR");
        assert_eq!(value["execution_performed"], false);
    }
}
