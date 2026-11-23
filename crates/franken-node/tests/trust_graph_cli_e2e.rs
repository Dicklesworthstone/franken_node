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
        std::fs::write(workspace.path().join("package-lock.json"), unsupported_shape).unwrap();
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

    // npm v1 legitimately omits its dependency map for an empty project.
    std::fs::write(
        workspace.path().join("package-lock.json"),
        r#"{"lockfileVersion":1}"#,
    )
    .unwrap();
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
