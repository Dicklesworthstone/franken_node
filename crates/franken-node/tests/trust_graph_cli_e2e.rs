//! `trust graph` end to end: the reputation graph is built from the project's
//! own verified trust-card registry (seeded by `trust scan`) and its npm
//! lockfile, a quarantine propagates through `depends_on` edges with a
//! recorded explanation, the quarantined card's version transition carries
//! its cause, and lockfile packages without a card are coverage gaps rather
//! than silently trusted nodes.

use std::path::Path;
use std::process::{Command, Output};

use serde_json::Value;

fn cli(workspace: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_franken-node"))
        .current_dir(workspace)
        .env_remove("FRANKEN_NODE_PROFILE")
        .env_remove("FRANKEN_NODE_OSV_QUERY_URL")
        .args(args)
        .output()
        .unwrap_or_else(|error| panic!("`{}`: {error}", args.join(" ")))
}

fn json_ok(workspace: &Path, args: &[&str]) -> Value {
    let output = cli(workspace, args);
    assert!(
        output.status.success(),
        "`{}` failed:\n{}\n{}",
        args.join(" "),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "`{}` must emit JSON ({error}): {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

/// `app` depends on `web-kit` and `lib-core`; `web-kit` itself depends on
/// `lib-core`, which depends on `tiny-helper` (in the lockfile only).
fn project() -> tempfile::TempDir {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name":"graph-app","version":"1.0.0","dependencies":{"web-kit":"^3.1.0","lib-core":"^2.0.0"}}"#,
    )
    .expect("package.json");
    std::fs::write(
        dir.path().join("package-lock.json"),
        r#"{
  "name": "graph-app",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "packages": {
    "": {"name": "graph-app", "version": "1.0.0",
         "dependencies": {"web-kit": "^3.1.0", "lib-core": "^2.0.0"}},
    "node_modules/web-kit": {"version": "3.1.4", "dependencies": {"lib-core": "^2.0.0"}},
    "node_modules/lib-core": {"version": "2.0.7", "dependencies": {"tiny-helper": "^1.0.0"}},
    "node_modules/tiny-helper": {"version": "1.0.2"}
  }
}"#,
    )
    .expect("package-lock.json");
    let init = cli(
        dir.path(),
        &["init", "--profile", "balanced", "--out-dir", "."],
    );
    assert!(
        init.status.success(),
        "init: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    json_ok(dir.path(), &["trust", "scan", ".", "--json"]);
    dir
}

fn node<'a>(graph: &'a Value, id: &str) -> &'a Value {
    graph["nodes"]
        .as_array()
        .expect("nodes")
        .iter()
        .find(|node| node["node_id"] == id)
        .unwrap_or_else(|| panic!("node {id} missing: {graph}"))
}

fn has_edge(graph: &Value, source: &str, target: &str, relation: &str) -> bool {
    graph["edges"]
        .as_array()
        .expect("edges")
        .iter()
        .any(|edge| {
            edge["source"] == source && edge["target"] == target && edge["relation"] == relation
        })
}

#[test]
fn quarantine_propagates_through_lockfile_edges_with_explanations_and_blast_radius() {
    let workspace = project();
    let before = json_ok(workspace.path(), &["trust", "graph", "--json"]);
    assert_eq!(before["schema_version"], "franken-node/trust-graph-cli/v1");
    assert_eq!(before["lockfile"], "package-lock.json");
    let graph = &before["graph"];
    assert_eq!(node(graph, "npm:web-kit")["kind"], "extension");
    assert_eq!(node(graph, "npm:lib-core")["kind"], "extension");
    assert!(
        has_edge(graph, "npm:web-kit", "npm:lib-core", "depends_on"),
        "{graph}"
    );
    // A lockfile package nobody scanned is a coverage gap, never trusted.
    let helper = node(graph, "npm:tiny-helper");
    assert_eq!(helper["kind"], "untracked_dependency", "{helper}");
    assert!(helper["effective_score"].is_null(), "{helper}");
    assert!(has_edge(
        graph,
        "npm:lib-core",
        "npm:tiny-helper",
        "depends_on"
    ));
    assert!(graph["summary"]["untracked_dependencies"].as_u64() >= Some(1));
    let web_kit_before = node(graph, "npm:web-kit")["effective_score"]
        .as_u64()
        .expect("score");

    json_ok(
        workspace.path(),
        &[
            "trust",
            "quarantine",
            "--artifact",
            "npm:lib-core",
            "--json",
        ],
    );
    let after = json_ok(workspace.path(), &["trust", "graph", "--json"]);
    let graph = &after["graph"];
    let lib_core = node(graph, "npm:lib-core");
    assert_eq!(lib_core["quarantined"], true, "{lib_core}");
    assert!(
        lib_core["explanation"]
            .as_array()
            .expect("explanation")
            .iter()
            .any(|reason| reason["rule"] == "R2_QUARANTINED"),
        "{lib_core}"
    );
    // The dependent's trust now rests on a quarantined dependency: lowered,
    // and the reason names the dependency.
    let web_kit = node(graph, "npm:web-kit");
    let web_kit_after = web_kit["effective_score"].as_u64().expect("score");
    assert!(
        web_kit_after < web_kit_before,
        "{web_kit_before} -> {web_kit}"
    );
    assert!(
        web_kit["explanation"]
            .as_array()
            .expect("explanation")
            .iter()
            .any(|reason| reason["rule"] == "R3_WEAK_DEPENDENCY"
                && reason["detail"]
                    .as_str()
                    .is_some_and(|detail| detail.contains("npm:lib-core"))),
        "{web_kit}"
    );
    assert!(graph["summary"]["quarantined"].as_u64() >= Some(1));
    assert!(graph["summary"]["degraded_by_propagation"].as_u64() >= Some(1));

    // Focus: what rests on lib-core, and why its card changed.
    let focus = json_ok(
        workspace.path(),
        &["trust", "graph", "--extension", "npm:lib-core", "--json"],
    );
    let radius = focus["focus"]["blast_radius"]
        .as_array()
        .expect("blast radius");
    assert!(
        radius
            .iter()
            .any(|entry| entry["extension_id"] == "npm:web-kit" && entry["depth"] == 1),
        "{focus}"
    );
    let transitions = focus["focus"]["transitions"]
        .as_array()
        .expect("transitions");
    assert!(
        !transitions.is_empty(),
        "the quarantine is a recorded transition: {focus}"
    );
    assert!(
        transitions
            .iter()
            .all(|transition| transition["extension_id"] == "npm:lib-core"),
        "{focus}"
    );

    // An unknown extension is an error, not an empty focus.
    let unknown = cli(
        workspace.path(),
        &[
            "trust",
            "graph",
            "--extension",
            "npm:no-such-package",
            "--json",
        ],
    );
    assert!(!unknown.status.success());
}
