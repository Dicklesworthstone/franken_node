use frankenengine_node::supply_chain::module_resolution_graph::{
    MODULE_RESOLUTION_GRAPH_SCHEMA, ModuleResolutionGraphError,
    build_canonical_module_resolution_graph, canonical_module_resolution_graph_bytes,
    recompute_module_resolution_graph_hash,
};
use std::collections::BTreeSet;
use tempfile::tempdir;

#[test]
fn canonical_graph_captures_workspaces_lockfile_and_conditions() {
    let tmp = tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::create_dir_all(root.join("packages/app")).expect("app dir");
    std::fs::create_dir_all(root.join("packages/lib")).expect("lib dir");
    std::fs::write(
        root.join("package.json"),
        r##"{
            "name": "root-app",
            "version": "1.0.0",
            "workspaces": ["packages/*"],
            "dependencies": {"left-pad": "^1.3.0"},
            "devDependencies": {"@scope/tool": "~2.0.0"},
            "exports": {
                ".": {"import": "./esm/index.js", "require": "./cjs/index.cjs"},
                "./feature": {"node": {"import": "./esm/feature.js"}}
            },
            "imports": {"#internal": {"default": "./src/internal.js"}}
        }"##,
    )
    .expect("root package");
    std::fs::write(
        root.join("packages/app/package.json"),
        r#"{"name":"@acme/app","version":"0.1.0","dependencies":{"@acme/lib":"workspace:*"}}"#,
    )
    .expect("app package");
    std::fs::write(
        root.join("packages/lib/package.json"),
        r#"{"name":"@acme/lib","version":"0.1.0","peerDependencies":{"react":"^18.2.0"}}"#,
    )
    .expect("lib package");
    std::fs::write(
        root.join("package-lock.json"),
        r#"{
            "lockfileVersion": 3,
            "packages": {
                "": {"name": "root-app", "version": "1.0.0"},
                "node_modules/left-pad": {
                    "version": "1.3.0",
                    "resolved": "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                    "integrity": "sha512-left",
                    "dependencies": {"repeat-string": "^1.6.1"}
                },
                "node_modules/@scope/tool": {
                    "version": "2.0.1",
                    "integrity": "sha512-tool"
                },
                "node_modules/repeat-string": {"version": "1.6.1"}
            }
        }"#,
    )
    .expect("lockfile");

    let graph = build_canonical_module_resolution_graph(root).expect("graph");

    assert_eq!(graph.schema_version, MODULE_RESOLUTION_GRAPH_SCHEMA);
    assert_eq!(graph.project_root, ".");
    assert_eq!(graph.packages.len(), 3);
    assert_eq!(graph.lockfile_pins.len(), 3);
    assert!(graph.dependency_edges.iter().any(|edge| {
        edge.dependency_name == "@acme/lib"
            && edge
                .target_package_id
                .as_deref()
                .is_some_and(|id| id.contains("@acme/lib"))
    }));
    assert!(
        graph
            .dependency_edges
            .iter()
            .any(|edge| edge.dependency_name == "left-pad"
                && edge.lockfile_package_path.as_deref() == Some("node_modules/left-pad"))
    );

    let root_package = graph
        .packages
        .iter()
        .find(|package| package.name.as_deref() == Some("root-app"))
        .expect("root package node");
    let export_targets = root_package
        .exports
        .iter()
        .find(|entry| entry.specifier == ".")
        .expect("root export")
        .targets
        .iter()
        .map(|target| (target.condition.as_str(), target.target.as_str()))
        .collect::<BTreeSet<_>>();
    assert!(export_targets.contains(&("import", "./esm/index.js")));
    assert!(export_targets.contains(&("require", "./cjs/index.cjs")));

    let bytes = canonical_module_resolution_graph_bytes(&graph).expect("canonical bytes");
    let hash = recompute_module_resolution_graph_hash(&graph).expect("hash");
    assert_eq!(graph.canonical_hash, hash);
    assert!(
        String::from_utf8(bytes)
            .expect("json")
            .contains("\"dependency_edges\"")
    );
}

#[test]
fn graph_is_deterministic_for_repeated_builds() {
    let tmp = tempdir().expect("tempdir");
    let root = tmp.path();
    std::fs::write(
        root.join("package.json"),
        r#"{"name":"deterministic","version":"1.0.0","dependencies":{"b":"2","a":"1"}}"#,
    )
    .expect("package");

    let first = build_canonical_module_resolution_graph(root).expect("first");
    let second = build_canonical_module_resolution_graph(root).expect("second");

    assert_eq!(first, second);
    assert_eq!(
        canonical_module_resolution_graph_bytes(&first).expect("first bytes"),
        canonical_module_resolution_graph_bytes(&second).expect("second bytes")
    );
}

#[test]
fn missing_manifest_fails_closed() {
    let tmp = tempdir().expect("tempdir");
    let error = build_canonical_module_resolution_graph(tmp.path())
        .expect_err("missing manifest must fail");

    assert!(matches!(
        error,
        ModuleResolutionGraphError::MissingRootManifest { .. }
    ));
}

#[test]
fn unsupported_workspace_pattern_fails_closed() {
    let tmp = tempdir().expect("tempdir");
    std::fs::write(
        tmp.path().join("package.json"),
        r#"{"name":"bad-workspace","version":"1.0.0","workspaces":["../*"]}"#,
    )
    .expect("package");

    let error = build_canonical_module_resolution_graph(tmp.path())
        .expect_err("workspace escape must fail");

    assert!(matches!(
        error,
        ModuleResolutionGraphError::InvalidWorkspacePattern { .. }
    ));
}

#[cfg(target_os = "linux")]
mod bun_trust {
    use super::*;
    use frankenengine_node::supply_chain::module_resolution_graph::dependency_topology;
    use frankenengine_node::supply_chain::trust_card::CapturedDependencyTrust;
    use serde_json::{Value, json};
    use std::path::Path;

    fn put(root: &Path, path: &str, value: &Value) {
        let path = root.join(path);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    }

    fn simple_lock(version: u32) -> Value {
        json!({
            "lockfileVersion": version,
            "workspaces": {"": {"dependencies": {"parent": "^1"},
                "devDependencies": {"dev": "1"}}},
            "packages": {
                "parent": ["parent@1.2.3", "", {
                    "dependencies": {"alias": "npm:@scope/real@^2"},
                    "optionalDependencies": {"optional": "1"},
                    "peerDependencies": {"peer": "2"},
                    "optionalPeers": ["peer"]
                }, "sha512-cGFyZW50"],
                "parent/alias": ["@scope/real@2.3.4", "", {}, "sha512-c2VsZWN0ZWQ="],
                "alias": ["@scope/real@9.0.0", "", {}, "sha512-dW5yZWFjaGVk"],
                "dev": ["dev@1.0.0", "", {"dependencies": {"dev-child": "1"}}, ""],
                "dev-child": ["dev-child@1.0.0", "", {}, ""]
            }
        })
    }

    fn simple_project(version: u32) -> (tempfile::TempDir, Value) {
        let root = tempdir().unwrap();
        put(root.path(), "package.json", &json!({
            "dependencies": {"parent": "^1"}, "devDependencies": {"dev": "1"}
        }));
        let lock = simple_lock(version);
        put(root.path(), "bun.lock", &lock);
        (root, lock)
    }

    #[test]
    fn bun_text_lock_v1_v2_feed_transitive_runtime_trust_and_recheck_pins() {
        for version in [1, 2] {
            let (root, mut lock) = simple_project(version);
            // Bun's text format admits BOM, comments and trailing commas.
            let mut raw = serde_json::to_string_pretty(&lock).unwrap();
            assert_eq!(raw.pop(), Some('}'));
            raw.push_str(",\n}\n");
            std::fs::write(root.path().join("bun.lock"), format!("\u{feff}// Bun lock\n{raw}")).unwrap();

            let graph = build_canonical_module_resolution_graph(root.path()).unwrap();
            assert_eq!(graph.lockfile_pins.len(), 5);
            let topology = dependency_topology::build(root.path()).unwrap();
            let runtime = topology.trust_dependencies(".", false).unwrap();
            let selected = runtime.iter().find(|entry| entry.package_name == "@scope/real").unwrap();
            assert_eq!(selected.target.as_deref(), Some("node_modules/parent/node_modules/alias"));
            assert_eq!(selected.pinned_version.as_deref(), Some("2.3.4"));
            assert_eq!(selected.integrity.as_deref(), Some("sha512-c2VsZWN0ZWQ="));
            assert!(!runtime.iter().any(|entry| entry.package_name.starts_with("dev")));
            assert!(topology.trust_dependencies(".", true).unwrap().iter()
                .any(|entry| entry.package_name == "dev-child"));
            for optional in ["optional", "peer"] {
                assert!(runtime.iter().any(|entry| entry.package_name == optional && entry.target.is_none()));
                assert!(topology.edges().iter().any(|edge| edge.dependency_name == optional && edge.optional));
            }

            // The exact production trust type now includes a Bun-only
            // transitive artifact and refuses a changed pin before execution.
            let capture = CapturedDependencyTrust::from_topology(&topology).unwrap();
            capture.verify_project(root.path()).unwrap();
            assert_eq!(capture.packages["npm:@scope/real"][0].version.as_deref(), Some("2.3.4"));
            lock["packages"]["parent/alias"][0] = json!("@scope/real@2.4.0");
            put(root.path(), "bun.lock", &lock);
            assert!(capture.verify_project(root.path()).is_err());
            assert_eq!(runtime, topology.trust_dependencies(".", false).unwrap(),
                "an existing topology must retain its captured pins");
        }
    }

    fn workspace_project() -> (tempfile::TempDir, Value, Value) {
        let root = tempdir().unwrap();
        let manifest = json!({
            "name": "root",
            "workspaces": {"packages": ["packages/*"],
                "catalog": {"alias": "npm:@scope/real@^2"},
                "catalogs": {"local": {"private": "^1"}}},
            "dependencies": {"@demo/app": "workspace:*", "alias": "catalog:"}
        });
        let workspace = json!({"name": "@demo/app", "version": "1.0.0",
            "dependencies": {"private": "catalog:local", "alias": "catalog:"}});
        let lock = json!({
            "lockfileVersion": 2, "configVersion": 0,
            "catalog": {"alias": "npm:@scope/real@^2"},
            "catalogs": {"local": {"private": "^1"}},
            "workspaces": {"": {"name": "root",
                "dependencies": {"@demo/app": "workspace:*", "alias": "catalog:"}},
                "packages/app": workspace},
            "packages": {
                "@demo/app": ["@demo/app@workspace:packages/app"],
                "@demo/app/private": ["private@1.2.3", "", {}, "sha512-cHJpdmF0ZQ=="],
                "private": ["private@9.0.0", "", {}, "sha512-dW5yZWFjaGVk"],
                "alias": ["@scope/real@2.4.0", "", {"dependencies": {"leaf": "1"}}, "sha512-cmVhbA=="],
                "leaf": ["leaf@1.0.0", "", {}, ""]
            }
        });
        put(root.path(), "package.json", &manifest);
        put(root.path(), "packages/app/package.json", &workspace);
        put(root.path(), "bun.lock", &lock);
        (root, workspace, lock)
    }

    #[test]
    fn bun_workspace_catalogs_bind_aliases_and_resolve_from_physical_locations() {
        let (root, _, _) = workspace_project();
        let graph = build_canonical_module_resolution_graph(root.path()).unwrap();
        assert!(graph.dependency_edges.iter().any(|edge|
            edge.dependency_name == "alias" && edge.requested_range == "npm:@scope/real@^2"));
        let topology = dependency_topology::build(root.path()).unwrap();
        assert_eq!(topology.closure(".").unwrap().unresolved_required_edges, 0);
        let runtime = topology.trust_dependencies(".", false).unwrap();
        let private = runtime.iter().find(|entry| entry.package_name == "private").unwrap();
        assert_eq!(private.importer, "packages/app");
        assert_eq!(private.requested_range, "^1");
        assert_eq!(private.target.as_deref(), Some("packages/app/node_modules/private"));
        assert_eq!(private.pinned_version.as_deref(), Some("1.2.3"));
        let capture = CapturedDependencyTrust::from_topology(&topology).unwrap();
        assert!(capture.packages.contains_key("npm:@scope/real"));
        assert!(capture.packages.contains_key("npm:leaf"));
        assert!(!capture.packages.contains_key("npm:alias"));
        assert_eq!(capture.packages["npm:private"].len(), 1);
        capture.verify_project(root.path()).unwrap();
    }

    #[test]
    fn bun_stale_workspaces_and_catalogs_cannot_supply_trust_identity() {
        for change in ["workspace-version", "workspace-dependencies", "catalog", "workspace-selection"] {
            let (root, mut workspace, mut lock) = workspace_project();
            match change {
                "workspace-version" => {
                    workspace["version"] = json!("2.0.0");
                    put(root.path(), "packages/app/package.json", &workspace);
                }
                "workspace-dependencies" => {
                    workspace["dependencies"]["hidden"] = json!("1");
                    put(root.path(), "packages/app/package.json", &workspace);
                }
                "catalog" => {
                    lock["catalog"]["alias"] = json!("npm:other@^2");
                    put(root.path(), "bun.lock", &lock);
                }
                "workspace-selection" => {
                    put(root.path(), "packages/unrecorded/package.json", &json!({
                        "name": "unrecorded", "version": "1.0.0", "dependencies": {"hidden": "1"}
                    }));
                }
                _ => unreachable!(),
            }
            assert!(CapturedDependencyTrust::capture(root.path()).is_err(), "{change}");
        }
    }

    #[test]
    fn malformed_bun_and_mixed_lock_authorities_fail_closed() {
        for raw in [
            r#"{"lockfileVersion":2,"workspaces":{"":{}},"packages":{},"packages":{}}"#,
            r#"{"lockfileVersion":3,"workspaces":{"":{}},"packages":{}}"#,
            r#"{"lockfileVersion":2,"workspaces":{"":{}},"packages":{"parent":["parent@1.0.0"]}}"#,
            "/* unfinished",
        ] {
            let (root, _) = simple_project(2);
            std::fs::write(root.path().join("bun.lock"), raw).unwrap();
            assert!(build_canonical_module_resolution_graph(root.path()).is_err(), "{raw}");
        }
        for filename in ["package-lock.json", "npm-shrinkwrap.json"] {
            let (root, _) = simple_project(2);
            put(root.path(), filename, &json!({"lockfileVersion":3,"packages":{}}));
            let error = build_canonical_module_resolution_graph(root.path()).unwrap_err();
            assert!(error.to_string().contains("select one dependency authority"));
        }
    }

    #[test]
    fn bun_binary_oversized_and_linked_locks_are_not_manifest_only_inventory() {
        let binary = tempdir().unwrap();
        put(binary.path(), "package.json", &json!({"dependencies":{"parent":"1"}}));
        std::fs::write(binary.path().join("bun.lockb"), [0xff, 0x00, 0x01]).unwrap();
        let error = CapturedDependencyTrust::capture(binary.path()).unwrap_err();
        assert!(error.to_string().contains("binary bun.lockb"));

        let oversized = tempdir().unwrap();
        put(oversized.path(), "package.json", &json!({}));
        let lock = std::fs::File::create(oversized.path().join("bun.lock")).unwrap();
        lock.set_len(4 * 1024 * 1024 + 1).unwrap();
        assert!(CapturedDependencyTrust::capture(oversized.path()).unwrap_err()
            .to_string().contains("byte bound"));

        let linked = tempdir().unwrap();
        put(linked.path(), "package.json", &json!({}));
        std::os::unix::fs::symlink(oversized.path().join("bun.lock"), linked.path().join("bun.lock")).unwrap();
        assert!(CapturedDependencyTrust::capture(linked.path()).is_err());
    }

    #[test]
    fn npm_shrinkwrap_keeps_precedence_over_ignored_package_lock() {
        let root = tempdir().unwrap();
        put(root.path(), "package.json", &json!({"dependencies":{"parent":"1"}}));
        put(root.path(), "npm-shrinkwrap.json", &json!({"lockfileVersion":3,"packages":{
            "node_modules/parent":{"version":"1.2.3","dependencies":{"leaf":"2"}},
            "node_modules/leaf":{"version":"2.0.0"}
        }}));
        std::fs::write(root.path().join("package-lock.json"), "not selected JSON").unwrap();
        let capture = CapturedDependencyTrust::capture(root.path()).unwrap();
        assert_eq!(capture.packages["npm:leaf"][0].version.as_deref(), Some("2.0.0"));
    }
}
