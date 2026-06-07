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
