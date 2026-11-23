//! `trust graph` end to end: the reputation graph is built from the project's
//! own verified trust-card registry (seeded by `trust scan`) and its npm
//! lockfile, a quarantine propagates through `depends_on` edges with a
//! recorded explanation, the quarantined card's version transition carries
//! its cause, and lockfile packages without a card are coverage gaps rather
//! than silently trusted nodes.

use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use ed25519_dalek::SigningKey;
use frankenengine_node::supply_chain::behavioral_observation::{
    BehavioralObservation, SignedBehavioralObservation,
};
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
/// `lib-core`, which depends on `tiny-helper`. `trust scan` seeds a card for
/// every package the lockfile resolves at scan time.
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
    for scanned in ["npm:web-kit", "npm:lib-core", "npm:tiny-helper"] {
        assert_eq!(node(graph, scanned)["kind"], "extension", "{scanned}");
    }
    assert!(
        has_edge(graph, "npm:web-kit", "npm:lib-core", "depends_on"),
        "{graph}"
    );
    assert!(has_edge(
        graph,
        "npm:lib-core",
        "npm:tiny-helper",
        "depends_on"
    ));
    assert_eq!(graph["summary"]["untracked_dependencies"], 0, "{graph}");

    // The lockfile gains a package after the last scan: a coverage gap,
    // never a trusted node.
    let lock_path = workspace.path().join("package-lock.json");
    let mut lock: Value =
        serde_json::from_slice(&std::fs::read(&lock_path).expect("lockfile")).expect("lock json");
    lock["packages"]["node_modules/lib-core"]["dependencies"]["late-helper"] =
        serde_json::json!("^0.1.0");
    lock["packages"]["node_modules/late-helper"] = serde_json::json!({"version": "0.1.3"});
    std::fs::write(
        &lock_path,
        serde_json::to_vec_pretty(&lock).expect("encode"),
    )
    .expect("write");
    let drifted = json_ok(workspace.path(), &["trust", "graph", "--json"]);
    let graph = &drifted["graph"];
    let late = node(graph, "npm:late-helper");
    assert_eq!(late["kind"], "untracked_dependency", "{late}");
    assert!(late["effective_score"].is_null(), "{late}");
    assert!(has_edge(
        graph,
        "npm:lib-core",
        "npm:late-helper",
        "depends_on"
    ));
    assert_eq!(graph["summary"]["untracked_dependencies"], 1, "{graph}");

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

    // Real topology is available, but a scan is not behavioral measurement.
    // Current surfaces must not manufacture interventions or economic history.
    let immunized = json_ok(
        workspace.path(),
        &["trust", "graph", "--immunize", "--json"],
    );
    let imm = &immunized["immunization"];
    assert!(
        imm.is_object(),
        "expected immunization payload: {immunized}"
    );
    assert_eq!(
        imm["schema_version"],
        "franken-node/trust-graph-immunization/v2"
    );
    assert_eq!(imm["topology_status"], "computed");
    assert_eq!(
        imm["topology_metrics"]["npm:lib-core"]["transitive_dependents"],
        1
    );
    assert_eq!(
        imm["topology_metrics"]["npm:lib-core"]["direct_dependencies"],
        2
    );
    assert_eq!(
        imm["topology_metrics"]["npm:lib-core"]["is_articulation_point"],
        true
    );
    assert!(imm["topology_metrics"]["npm:lib-core"]["betweenness_centrality"].as_f64() > Some(0.0));
    assert!(imm["topology_metrics"]["npm:late-helper"].is_object());
    assert_eq!(imm["barrier_enforcement_performed"], false);
    assert_eq!(imm["risk_estimates_calibrated"], false);
    assert_eq!(
        imm["economic_trajectory_status"],
        "unavailable_no_measured_maintainer_trajectory"
    );
    assert!(imm.get("complexity_gate_pass").is_none());
    assert!(imm.get("complexity_replay_deterministic").is_none());
    assert!(imm.get("bpet_trust_surfaces").is_none());
    assert_eq!(
        imm["risk_surfaces"]
            .as_array()
            .expect("risk_surfaces")
            .len(),
        3,
        "{imm}"
    );
    assert_eq!(
        imm["bpet_dgis_priorities"]
            .as_array()
            .expect("bpet_dgis_priorities")
            .len(),
        0,
        "{imm}"
    );
    assert!(imm["behavioral_streams"].as_array().unwrap().is_empty());
    assert!(
        imm["behavioral_coverage"]
            .as_array()
            .unwrap()
            .iter()
            .all(|coverage| {
                coverage["status"] == "no_current_artifact_observations"
                    && coverage["assessed_streams"] == 0
            })
    );
    for surface in imm["risk_surfaces"].as_array().unwrap() {
        assert!(
            surface["planned_update_deltas"]
                .as_array()
                .unwrap()
                .is_empty(),
            "{surface}"
        );
        assert!(
            surface["risk_ui"]["delta_heatmap"]
                .as_object()
                .unwrap()
                .is_empty(),
            "{surface}"
        );
    }
}

fn coverage<'a>(report: &'a Value, extension: &str) -> &'a Value {
    report["immunization"]["behavioral_coverage"]
        .as_array()
        .expect("behavioral coverage")
        .iter()
        .find(|entry| entry["extension_id"] == extension)
        .unwrap_or_else(|| panic!("coverage for {extension} missing: {report}"))
}

#[test]
fn immunization_uses_admitted_measurements_and_keeps_artifact_scope() {
    let workspace = project();
    let root = workspace.path();
    let lock_path = root.join("package-lock.json");
    let mut lock: Value = serde_json::from_slice(&std::fs::read(&lock_path).unwrap()).unwrap();
    let artifact_hash = format!("sha256:{}", hex::encode([0xa1_u8; 32]));
    lock["packages"]["node_modules/lib-core"]["integrity"] = serde_json::json!(format!(
        "sha256-{}",
        base64::engine::general_purpose::STANDARD.encode([0xa1_u8; 32])
    ));
    std::fs::write(&lock_path, serde_json::to_vec(&lock).unwrap()).unwrap();
    json_ok(root, &["trust", "scan", ".", "--refresh", "--json"]);
    let collector = SigningKey::from_bytes(&[97; 32]);
    std::fs::write(
        root.join("collector.pub"),
        hex::encode(collector.verifying_key().to_bytes()),
    )
    .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut previous = None;
    let mut last = Value::Null;

    // Explicit synthetic test measurements are admitted through the real
    // Ed25519 collector path, stored, then re-evaluated by a separate CLI read.
    for sequence in 0..8 {
        let signed = SignedBehavioralObservation::sign(
            BehavioralObservation {
                extension_id: "npm:lib-core".to_string(),
                package_version: "2.0.7".to_string(),
                artifact_hash: artifact_hash.clone(),
                workload_id: "lib-core-isolated-fixture-v1".to_string(),
                measurement_scope: "isolated_package".to_string(),
                sequence,
                observed_at_epoch_secs: now - 120 + sequence,
                window_duration_ms: 1_000,
                workload_iterations: 100,
                previous_observation_id: previous,
                observed_capabilities: BTreeMap::from([
                    ("fs.read".to_string(), 100),
                    (
                        "net.egress".to_string(),
                        if sequence >= 4 { 1_000 } else { 10 },
                    ),
                ]),
                declared_capabilities: BTreeMap::from([
                    ("fs.read".to_string(), 100),
                    ("net.egress".to_string(), 10),
                ]),
            },
            &collector,
        )
        .expect("sign ordered measurement");
        previous = Some(signed.observation_id().unwrap());
        std::fs::write(
            root.join("observation.json"),
            serde_json::to_vec(&signed).unwrap(),
        )
        .unwrap();
        last = json_ok(
            root,
            &[
                "trust",
                "observe",
                "observation.json",
                "--collector-key",
                "collector.pub",
                "--json",
            ],
        );
        if sequence == 0 {
            let insufficient = json_ok(root, &["trust", "graph", "--immunize", "--json"]);
            assert_eq!(
                coverage(&insufficient, "npm:lib-core")["status"],
                "insufficient_comparable_observations"
            );
            assert!(
                insufficient["immunization"]["bpet_dgis_priorities"]
                    .as_array()
                    .unwrap()
                    .is_empty()
            );
            assert!(
                insufficient["immunization"]["behavioral_streams"][0]["max_severity"].is_null()
            );
        }
    }

    let report = json_ok(root, &["trust", "graph", "--immunize", "--json"]);
    let imm = &report["immunization"];
    assert_eq!(coverage(&report, "npm:lib-core")["status"], "assessed");
    assert_eq!(coverage(&report, "npm:lib-core")["assessed_streams"], 1);
    assert_eq!(
        coverage(&report, "npm:web-kit")["status"],
        "no_current_artifact_observations"
    );
    let streams = imm["behavioral_streams"].as_array().unwrap();
    assert_eq!(streams.len(), 1);
    let stream = &streams[0];
    assert_eq!(stream["sample_count"], 8);
    assert_eq!(stream["current_artifact"], true);
    assert_eq!(stream["artifact_hash"], artifact_hash);
    assert_eq!(stream["last_observation_id"], last["observation_id"]);
    assert_eq!(stream["hints"], last["hints"]);
    assert!(!stream["hints"].as_array().unwrap().is_empty());
    let severity = last["hints"]
        .as_array()
        .unwrap()
        .iter()
        .map(|hint| hint["severity"].as_f64().unwrap())
        .fold(0.0_f64, f64::max);
    assert_eq!(stream["max_severity"].as_f64(), Some(severity));
    let priorities = imm["bpet_dgis_priorities"].as_array().unwrap();
    assert_eq!(priorities.len(), 1);
    assert_eq!(priorities[0]["stream_id"], stream["stream_id"]);
    assert_eq!(priorities[0]["observation_id"], last["observation_id"]);
    assert_eq!(priorities[0]["confidence_status"], "uncalibrated");
    assert_eq!(priorities[0]["priority"]["package_id"], "npm:lib-core");
    assert_eq!(
        priorities[0]["priority"]["expected_loss"]["confidence_basis_points"],
        0
    );

    // A new captured artifact must not inherit the old artifact's measurement
    // coverage, even though its authenticated history remains inspectable.
    lock["packages"]["node_modules/lib-core"]["version"] = serde_json::json!("2.0.8");
    lock["packages"]["node_modules/lib-core"]["integrity"] = serde_json::json!(format!(
        "sha256-{}",
        base64::engine::general_purpose::STANDARD.encode([0xb2_u8; 32])
    ));
    std::fs::write(&lock_path, serde_json::to_vec(&lock).unwrap()).unwrap();
    // Until the registry is refreshed, its latest card still authenticates
    // the old artifact. Its measurements remain inspectable but cannot rank
    // the different artifact now selected by the project's dependency capture.
    let stale = json_ok(root, &["trust", "graph", "--immunize", "--json"]);
    assert_eq!(
        node(&stale["graph"], "npm:lib-core")["artifact_coverage"]["status"],
        "mismatch"
    );
    assert_eq!(
        coverage(&stale, "npm:lib-core")["status"],
        "project_artifact_mismatch"
    );
    assert_eq!(
        stale["immunization"]["behavioral_streams"][0]["current_artifact"],
        false
    );
    assert_eq!(
        stale["immunization"]["behavioral_streams"][0]["sample_count"],
        8
    );
    assert!(
        stale["immunization"]["bpet_dgis_priorities"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert!(
        stale["immunization"]["planner_selected_nodes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|id| id != "npm:lib-core")
    );
    json_ok(root, &["trust", "scan", ".", "--refresh", "--json"]);
    let upgraded = json_ok(root, &["trust", "graph", "--immunize", "--json"]);
    assert_eq!(
        coverage(&upgraded, "npm:lib-core")["status"],
        "no_current_artifact_observations"
    );
    assert_eq!(
        coverage(&upgraded, "npm:lib-core")["other_artifact_streams"],
        1
    );
    assert_eq!(
        upgraded["immunization"]["behavioral_streams"][0]["current_artifact"],
        false
    );
    assert!(
        upgraded["immunization"]["bpet_dgis_priorities"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[test]
fn immunization_reports_missing_topology_and_rejects_unsupported_lockfile_shape() {
    let workspace = project();
    std::fs::rename(
        workspace.path().join("package-lock.json"),
        workspace.path().join("package-lock.saved"),
    )
    .unwrap();
    let report = json_ok(
        workspace.path(),
        &["trust", "graph", "--immunize", "--json"],
    );
    let imm = &report["immunization"];
    assert!(report["lockfile"].is_null());
    assert_eq!(imm["topology_status"], "unavailable");
    assert!(imm["topology_metrics"].is_null());
    assert!(
        imm["topology_unavailable_reason"]
            .as_str()
            .unwrap()
            .contains("lockfile")
    );
    assert_eq!(imm["planner_status"], "topology_unavailable");
    assert!(imm["planner_catalog"].is_null());
    assert!(imm["risk_surfaces"].as_array().unwrap().is_empty());
    assert_eq!(imm["behavioral_coverage"].as_array().unwrap().len(), 3);

    for unsupported_shape in ["{}", r#"{"lockfileVersion":1,"packages":false}"#] {
        std::fs::write(
            workspace.path().join("package-lock.json"),
            unsupported_shape,
        )
        .unwrap();
        let unsupported = cli(
            workspace.path(),
            &["trust", "graph", "--immunize", "--json"],
        );
        assert!(!unsupported.status.success());
        let diagnostic = format!(
            "{}{}",
            String::from_utf8_lossy(&unsupported.stdout),
            String::from_utf8_lossy(&unsupported.stderr)
        );
        assert!(
            diagnostic.contains("unsupported lockfile dependency shape"),
            "{diagnostic}"
        );
    }

    // npm v1 legitimately omits its dependency map, but it cannot certify
    // topology while the captured manifest still requires absent packages.
    std::fs::write(
        workspace.path().join("package-lock.json"),
        r#"{"lockfileVersion":1}"#,
    )
    .unwrap();
    let incomplete = json_ok(
        workspace.path(),
        &["trust", "graph", "--immunize", "--json"],
    );
    assert_eq!(incomplete["immunization"]["topology_status"], "unavailable");
    assert_eq!(
        incomplete["dependency_capture"]["coverage"]["unresolved_required_edges"],
        2
    );
    assert!(incomplete["immunization"]["topology_metrics"].is_null());
    assert!(incomplete["immunization"]["planner_catalog"].is_null());

    // The same valid empty v1 lock remains useful for a truly empty project.
    write_json(
        workspace.path(),
        "package.json",
        &serde_json::json!({"name": "empty-app", "version": "1.0.0"}),
    );
    let empty = json_ok(
        workspace.path(),
        &["trust", "graph", "--immunize", "--json"],
    );
    assert_eq!(empty["immunization"]["topology_status"], "computed");
    assert_eq!(
        empty["immunization"]["topology_metrics"]["npm:lib-core"]["transitive_dependents"],
        0
    );
}

#[test]
fn planner_budget_prioritizes_shared_dependency_before_alphabetical_leaves() {
    let workspace = project();
    let lock_path = workspace.path().join("package-lock.json");
    let manifest_path = workspace.path().join("package.json");
    let mut lock: Value = serde_json::from_slice(&std::fs::read(&lock_path).unwrap()).unwrap();
    let mut manifest: Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).unwrap()).unwrap();
    for index in 0..20 {
        let name = format!("a-leaf-{index:02}");
        manifest["dependencies"][&name] = serde_json::json!("1.0.0");
        lock["packages"][""]["dependencies"][&name] = serde_json::json!("1.0.0");
        lock["packages"][format!("node_modules/a-leaf-{index:02}")] = serde_json::json!({
            "version": "1.0.0", "dependencies": {"zz-core": "1.0.0"}
        });
    }
    lock["packages"]["node_modules/zz-core"] = serde_json::json!({"version": "1.0.0"});
    std::fs::write(&manifest_path, serde_json::to_vec(&manifest).unwrap()).unwrap();
    std::fs::write(&lock_path, serde_json::to_vec(&lock).unwrap()).unwrap();
    json_ok(
        workspace.path(),
        &["trust", "scan", ".", "--refresh", "--json"],
    );
    let report = json_ok(
        workspace.path(),
        &["trust", "graph", "--immunize", "--json"],
    );
    let imm = &report["immunization"];
    let selected = imm["planner_selected_nodes"].as_array().unwrap();
    assert_eq!(selected.len(), 18);
    assert_eq!(selected[0], "npm:zz-core", "{imm}");
    assert_eq!(imm["planner_omitted_nodes"], 6);
    assert_eq!(
        imm["topology_metrics"]["npm:zz-core"]["transitive_dependents"],
        20
    );
    assert_eq!(imm["risk_surfaces"].as_array().unwrap().len(), 24);
}

fn write_json(workspace: &Path, relative_path: &str, value: &Value) {
    let path = workspace.join(relative_path);
    std::fs::create_dir_all(path.parent().expect("fixture parent")).unwrap();
    std::fs::write(path, serde_json::to_vec_pretty(value).unwrap()).unwrap();
}

fn initialize_and_scan(workspace: &Path) {
    let init = cli(
        workspace,
        &["init", "--profile", "balanced", "--out-dir", "."],
    );
    assert!(
        init.status.success(),
        "init: {}",
        String::from_utf8_lossy(&init.stderr)
    );
    json_ok(workspace, &["trust", "scan", ".", "--json"]);
}

#[test]
fn graph_uses_shrinkwrap_authority_before_conflicting_package_lock() {
    let workspace = project();
    let root = workspace.path();
    let mut shrinkwrap: Value =
        serde_json::from_slice(&std::fs::read(root.join("package-lock.json")).unwrap()).unwrap();
    shrinkwrap["packages"]["node_modules/web-kit"]["dependencies"] =
        serde_json::json!({"tiny-helper": "^1.0.0"});
    shrinkwrap["packages"]["node_modules/lib-core"]["dependencies"] =
        serde_json::json!({"shrinkwrap-only": "^1.0.0"});
    shrinkwrap["packages"]["node_modules/shrinkwrap-only"] =
        serde_json::json!({"version": "1.0.3"});
    write_json(root, "npm-shrinkwrap.json", &shrinkwrap);

    let report = json_ok(root, &["trust", "graph", "--json"]);
    assert_eq!(report["lockfile"], "npm-shrinkwrap.json");
    let graph = &report["graph"];
    assert!(has_edge(
        graph,
        "npm:web-kit",
        "npm:tiny-helper",
        "depends_on"
    ));
    assert!(!has_edge(
        graph,
        "npm:web-kit",
        "npm:lib-core",
        "depends_on"
    ));
    assert!(has_edge(
        graph,
        "npm:lib-core",
        "npm:shrinkwrap-only",
        "depends_on"
    ));
    assert_eq!(
        node(graph, "npm:shrinkwrap-only")["kind"],
        "untracked_dependency"
    );
    assert_eq!(
        report["dependency_capture"]["lockfile_source"]["path"],
        "npm-shrinkwrap.json"
    );
    assert!(
        report["dependency_capture"]["topology_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:")),
        "{report}"
    );

    // npm ignores the losing lockfile entirely. Its invalid JSON must neither
    // break the selected graph nor replace the selected dependency authority.
    std::fs::write(root.join("package-lock.json"), "{").unwrap();
    let unchanged = json_ok(root, &["trust", "graph", "--json"]);
    assert_eq!(unchanged["lockfile"], "npm-shrinkwrap.json");
    assert_eq!(unchanged["graph"], report["graph"]);
    assert_eq!(
        unchanged["dependency_capture"],
        report["dependency_capture"]
    );
}

#[test]
fn aliases_preserve_actual_identity_transitive_edges_and_quarantine_blast_radius() {
    let manifest = serde_json::json!({
        "name": "alias-app",
        "version": "1.0.0",
        "dependencies": {"web-kit": "^3.1.0"}
    });
    for lock in [
        serde_json::json!({
            "lockfileVersion": 3,
            "packages": {
                "": manifest.clone(),
                "node_modules/web-kit": {
                    "version": "3.1.4",
                    "dependencies": {"renamed": "npm:@scope/actual@^2"}
                },
                "node_modules/renamed": {
                    "name": "@scope/actual", "version": "2.0.7",
                    "dependencies": {"leaf": "^1"}
                },
                "node_modules/leaf": {"version": "1.0.2"}
            }
        }),
        serde_json::json!({
            "lockfileVersion": 1,
            "dependencies": {
                "web-kit": {
                    "version": "3.1.4",
                    "requires": {"renamed": "npm:@scope/actual@^2"},
                    "dependencies": {
                        "renamed": {
                            "version": "npm:@scope/actual@2.0.7",
                            "requires": {"leaf": "^1"}
                        }
                    }
                },
                "leaf": {"version": "1.0.2"}
            }
        }),
    ] {
        let workspace = tempfile::tempdir().unwrap();
        let root = workspace.path();
        write_json(root, "package.json", &manifest);
        write_json(root, "package-lock.json", &lock);
        initialize_and_scan(root);

        let before = json_ok(root, &["trust", "graph", "--json"]);
        let graph = &before["graph"];
        assert_eq!(node(graph, "npm:@scope/actual")["kind"], "extension");
        assert!(has_edge(
            graph,
            "npm:web-kit",
            "npm:@scope/actual",
            "depends_on"
        ));
        assert!(has_edge(
            graph,
            "npm:@scope/actual",
            "npm:leaf",
            "depends_on"
        ));
        assert!(
            graph["nodes"]
                .as_array()
                .unwrap()
                .iter()
                .all(|entry| entry["node_id"] != "npm:renamed"),
            "an installation alias is not a second registry identity: {graph}"
        );
        let original_score = node(graph, "npm:web-kit")["effective_score"]
            .as_u64()
            .unwrap();

        json_ok(
            root,
            &[
                "trust",
                "quarantine",
                "--artifact",
                "npm:@scope/actual",
                "--json",
            ],
        );
        let after = json_ok(
            root,
            &[
                "trust",
                "graph",
                "--extension",
                "npm:@scope/actual",
                "--json",
            ],
        );
        assert_eq!(after["focus"]["node"]["quarantined"], true);
        assert!(
            node(&after["graph"], "npm:web-kit")["effective_score"]
                .as_u64()
                .is_some_and(|score| score < original_score),
            "alias containment must lower its real dependent's trust: {after}"
        );
        assert!(
            after["focus"]["blast_radius"]
                .as_array()
                .unwrap()
                .iter()
                .any(|entry| entry["extension_id"] == "npm:web-kit" && entry["depth"] == 1),
            "{after}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn bun_workspaces_aliases_peers_and_optional_dependencies_feed_the_same_graph() {
    let workspace = tempfile::tempdir().unwrap();
    let root = workspace.path();
    let manifest = serde_json::json!({
        "name": "bun-graph-app", "version": "1.0.0",
        "workspaces": ["packages/*"],
        "dependencies": {"app": "workspace:*"}
    });
    let member = serde_json::json!({
        "name": "app", "version": "1.0.0",
        "dependencies": {"renamed": "npm:@scope/actual@^2"},
        "peerDependencies": {"host": "^1"},
        "optionalDependencies": {"present": "^1", "not-installed": "^1"}
    });
    write_json(root, "package.json", &manifest);
    write_json(root, "packages/app/package.json", &member);
    write_json(
        root,
        "bun.lock",
        &serde_json::json!({
            "lockfileVersion": 1,
            "workspaces": {
                "": {"dependencies": {"app": "workspace:*"}},
                "packages/app": member
            },
            "packages": {
                "app": ["app@workspace:packages/app"],
                "renamed": ["@scope/actual@2.4.0", "", {"dependencies": {"leaf": "^1"}}, ""],
                "leaf": ["leaf@1.0.2", "", {}, ""],
                "host": ["host@1.0.0", "", {}, ""],
                "present": ["present@1.0.0", "", {}, ""]
            }
        }),
    );
    initialize_and_scan(root);

    let report = json_ok(root, &["trust", "graph", "--json"]);
    assert_eq!(report["lockfile"], "bun.lock");
    assert_eq!(
        report["dependency_capture"]["lockfile_source"]["path"],
        "bun.lock"
    );
    let graph = &report["graph"];
    for target in ["npm:@scope/actual", "npm:host", "npm:present"] {
        assert!(has_edge(graph, "npm:app", target, "depends_on"), "{report}");
    }
    assert!(has_edge(
        graph,
        "npm:@scope/actual",
        "npm:leaf",
        "depends_on"
    ));
    assert!(!has_edge(
        graph,
        "npm:app",
        "npm:not-installed",
        "depends_on"
    ));
    assert!(!has_edge(graph, "npm:app", "npm:app", "depends_on"));
    assert_eq!(
        report["dependency_capture"]["coverage"]["unresolved_optional_edges"],
        1
    );
    assert_eq!(
        report["dependency_capture"]["coverage"]["unresolved_required_edges"],
        0
    );
    assert!(
        report["dependency_capture"]["placements"]
            .as_array()
            .unwrap()
            .iter()
            .any(|placement| placement["location"] == "node_modules/renamed"
                && placement["package_name"] == "@scope/actual"
                && placement["version"] == "2.4.0"),
        "{report}"
    );
    assert!(
        graph["nodes"]
            .as_array()
            .unwrap()
            .iter()
            .all(|entry| entry["node_id"] != "npm:renamed"),
        "{report}"
    );
    let focus = json_ok(
        root,
        &["trust", "graph", "--extension", "npm:leaf", "--json"],
    );
    assert!(
        focus["focus"]["blast_radius"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entry| entry["extension_id"] == "npm:app" && entry["depth"] == 2),
        "{focus}"
    );
}

#[test]
fn selected_metadata_errors_cannot_downgrade_the_trust_graph_authority() {
    let workspace = project();
    let root = workspace.path();
    std::fs::write(root.join("npm-shrinkwrap.json"), "{").unwrap();
    let malformed = cli(root, &["trust", "graph", "--json"]);
    assert!(!malformed.status.success());
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&malformed.stdout),
        String::from_utf8_lossy(&malformed.stderr)
    );
    assert!(diagnostic.contains("npm-shrinkwrap.json"), "{diagnostic}");

    // Two different lockfile ecosystems cannot both be the authority for a
    // graph, even if the npm side alone is valid and previously scanned.
    std::fs::rename(
        root.join("npm-shrinkwrap.json"),
        root.join("npm-shrinkwrap.invalid"),
    )
    .unwrap();
    write_json(root, "bun.lock", &serde_json::json!({}));
    let ambiguous = cli(root, &["trust", "graph", "--json"]);
    assert!(!ambiguous.status.success());
    let diagnostic = format!(
        "{}{}",
        String::from_utf8_lossy(&ambiguous.stdout),
        String::from_utf8_lossy(&ambiguous.stderr)
    );
    assert!(diagnostic.contains("Bun and npm lockfiles"), "{diagnostic}");
}

fn fixture_integrity(byte: u8) -> String {
    format!(
        "sha256-{}",
        base64::engine::general_purpose::STANDARD.encode([byte; 32])
    )
}

fn project_with_artifact_pin() -> (tempfile::TempDir, Value) {
    let workspace = project();
    let root = workspace.path();
    let mut lock: Value =
        serde_json::from_slice(&std::fs::read(root.join("package-lock.json")).unwrap()).unwrap();
    lock["packages"]["node_modules/lib-core"]["integrity"] =
        serde_json::json!(fixture_integrity(0xa1));
    write_json(root, "package-lock.json", &lock);
    json_ok(root, &["trust", "scan", ".", "--refresh", "--json"]);
    (workspace, lock)
}

#[test]
fn changed_artifact_pins_do_not_inherit_a_current_trust_score() {
    let (workspace, lock) = project_with_artifact_pin();
    let root = workspace.path();
    let signed_card = json_ok(root, &["trust-card", "show", "npm:lib-core", "--json"]);
    assert!(
        signed_card["card_hash"]
            .as_str()
            .is_some_and(|hash| !hash.is_empty())
    );
    let original = json_ok(root, &["trust", "graph", "--json"]);
    let original_node = node(&original["graph"], "npm:lib-core");
    assert_eq!(original_node["artifact_coverage"]["status"], "matched");
    assert_eq!(original_node["artifact_coverage"]["placement_count"], 1);
    let original_score = original_node["effective_score"].as_u64().unwrap();
    assert_eq!(original["graph"]["summary"]["artifact_mismatches"], 0);
    // Missing hashes are incomplete inventory, not contradictory evidence.
    assert_eq!(
        node(&original["graph"], "npm:web-kit")["artifact_coverage"]["status"],
        "unverified"
    );

    for (field, changed) in [
        ("version", serde_json::json!("2.0.8")),
        ("integrity", serde_json::json!(fixture_integrity(0xb2))),
    ] {
        let mut changed_lock = lock.clone();
        changed_lock["packages"]["node_modules/lib-core"][field] = changed;
        write_json(root, "package-lock.json", &changed_lock);
        let report = json_ok(root, &["trust", "graph", "--json"]);
        let selected = node(&report["graph"], "npm:lib-core");
        assert_eq!(selected["kind"], "extension");
        assert_eq!(selected["artifact_coverage"]["status"], "mismatch");
        assert_eq!(selected["artifact_coverage"]["placement_count"], 1);
        assert!(
            selected["artifact_coverage"]["detail"]
                .as_str()
                .is_some_and(|detail| !detail.is_empty()),
            "{field}: {selected}"
        );
        assert!(selected["effective_score"].is_null(), "{field}: {selected}");
        assert_eq!(report["graph"]["summary"]["artifact_mismatches"], 1);

        // The weighted reputation API must not restore positive trust from
        // publisher, verifier or dependency edges for a different artifact.
        let reputation = json_ok(
            root,
            &[
                "trust-card", "reputation", "--extension", "npm:lib-core", "--json",
            ],
        );
        let scores = reputation["scores"].as_array().unwrap();
        assert_eq!(scores.len(), 1, "{reputation}");
        let score = &scores[0];
        assert_eq!(score["node_id"], "npm:lib-core");
        assert_eq!(score["artifact_coverage"]["status"], "mismatch");
        assert_eq!(score["base_score"].as_f64(), Some(0.0), "{reputation}");
        assert_eq!(score["composite_score"].as_f64(), Some(0.0), "{reputation}");
        assert_eq!(score["meets_threshold"], false);
        assert_eq!(score["edge_count"], 0);
        assert!(score["neighbors"].as_array().unwrap().is_empty());
        assert!(
            reputation["focused_subgraph"]["edges"]
                .as_array()
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            json_ok(root, &["trust-card", "show", "npm:lib-core", "--json"]),
            signed_card,
            "graph and reputation inspection must not rewrite the signed card"
        );
    }

    // Graph inspection never rewrites the authenticated card to bless a new
    // pin or permanently demote the historical artifact it actually describes.
    write_json(root, "package-lock.json", &lock);
    let restored = json_ok(root, &["trust", "graph", "--json"]);
    let restored_node = node(&restored["graph"], "npm:lib-core");
    assert_eq!(restored_node["artifact_coverage"]["status"], "matched");
    assert_eq!(restored_node["effective_score"].as_u64(), Some(original_score));
    assert_eq!(restored["graph"]["summary"]["artifact_mismatches"], 0);
    let reputation = json_ok(
        root,
        &[
            "trust-card", "reputation", "--extension", "npm:lib-core", "--json",
        ],
    );
    assert_eq!(reputation["scores"][0]["artifact_coverage"]["status"], "matched");
    assert!(
        reputation["scores"][0]["base_score"]
            .as_f64()
            .is_some_and(|score| score > 0.0),
        "{reputation}"
    );
    assert_eq!(
        json_ok(root, &["trust-card", "show", "npm:lib-core", "--json"]),
        signed_card
    );
}

#[test]
fn every_captured_placement_must_match_before_package_trust_is_propagated() {
    let (workspace, lock) = project_with_artifact_pin();
    let root = workspace.path();
    for (version, digest) in [("2.0.8", 0xa1), ("2.0.7", 0xb2), ("2.0.7", 0xa1)] {
        let mut nested = lock.clone();
        nested["packages"]["node_modules/web-kit/node_modules/lib-core"] = serde_json::json!({
            "version": version,
            "integrity": fixture_integrity(digest)
        });
        write_json(root, "package-lock.json", &nested);
        let report = json_ok(root, &["trust", "graph", "--json"]);
        let selected = node(&report["graph"], "npm:lib-core");
        let all_match = version == "2.0.7" && digest == 0xa1;
        assert_eq!(
            selected["artifact_coverage"]["status"],
            if all_match { "matched" } else { "mismatch" },
            "{report}"
        );
        assert_eq!(selected["artifact_coverage"]["placement_count"], 2);
        assert_eq!(selected["effective_score"].is_number(), all_match, "{report}");
        let placements = report["dependency_capture"]["placements"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|placement| placement["package_name"] == "lib-core")
            .collect::<Vec<_>>();
        assert_eq!(placements.len(), 2);
        assert!(placements.iter().any(|placement| {
            placement["location"] == "node_modules/lib-core"
                && placement["version"] == "2.0.7"
        }));
        assert!(placements.iter().any(|placement| {
            placement["location"] == "node_modules/web-kit/node_modules/lib-core"
                && placement["version"] == version
        }));
    }
}

#[test]
fn mismatched_artifacts_keep_known_quarantine_and_revocation_effective() {
    let (workspace, mut lock) = project_with_artifact_pin();
    let root = workspace.path();
    json_ok(
        root,
        &["trust", "quarantine", "--artifact", "npm:lib-core", "--json"],
    );
    lock["packages"]["node_modules/lib-core"]["version"] = serde_json::json!("2.0.8");
    write_json(root, "package-lock.json", &lock);
    let quarantined = json_ok(root, &["trust", "graph", "--json"]);
    let selected = node(&quarantined["graph"], "npm:lib-core");
    assert_eq!(selected["artifact_coverage"]["status"], "mismatch");
    assert_eq!(selected["quarantined"], true);
    assert!(
        selected["effective_score"]
            .as_u64()
            .is_some_and(|score| score <= 100),
        "{selected}"
    );
    assert!(
        node(&quarantined["graph"], "npm:web-kit")["effective_score"]
            .as_u64()
            .is_some_and(|score| score <= 300),
        "{quarantined}"
    );

    json_ok(root, &["trust", "revoke", "npm:lib-core", "--json"]);
    let revoked = json_ok(root, &["trust", "graph", "--json"]);
    let selected = node(&revoked["graph"], "npm:lib-core");
    assert_eq!(selected["artifact_coverage"]["status"], "mismatch");
    assert_eq!(selected["revoked"], true);
    assert_eq!(selected["effective_score"], 0);
    assert!(
        node(&revoked["graph"], "npm:web-kit")["effective_score"]
            .as_u64()
            .is_some_and(|score| score <= 200),
        "{revoked}"
    );
}
