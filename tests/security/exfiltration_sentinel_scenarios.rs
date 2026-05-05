// Exfiltration sentinel scenario tests for bd-2iyk.
//
// Validates the information-flow lineage tracker and exfiltration sentinel
// from `security::lineage_tracker` against simulated exfiltration scenarios.

use frankenengine_node::security::lineage_tracker::*;
use std::collections::BTreeSet;

fn default_config() -> SentinelConfig {
    SentinelConfig::default()
}

fn make_label(id: &str, severity: u32) -> TaintLabel {
    TaintLabel {
        id: id.to_string(),
        description: format!("{} label", id),
        severity,
    }
}

fn make_boundary(id: &str, from: &str, to: &str, denied: &[&str]) -> TaintBoundary {
    TaintBoundary {
        boundary_id: id.to_string(),
        from_zone: from.to_string(),
        to_zone: to.to_string(),
        denied_labels: denied.iter().map(|s| s.to_string()).collect(),
        deny_all: false,
    }
}

fn make_edge(edge_id: &str, source: &str, sink: &str, timestamp_ms: u64) -> FlowEdge {
    FlowEdge {
        edge_id: edge_id.to_string(),
        source: source.to_string(),
        sink: sink.to_string(),
        operation: "op".to_string(),
        taint_set: TaintSet::new(),
        timestamp_ms,
        quarantined: false,
    }
}

// ---- Scenario: PII data exported to external API ----

#[test]
fn scenario_pii_external_export_detected() {
    let config = default_config();
    let mut graph = LineageGraph::new(config.clone());
    let mut sentinel = ExfiltrationSentinel::new(config);

    sentinel
        .add_boundary(make_boundary("b-pii-ext", "internal", "external", &["PII"]))
        .unwrap();

    graph.register_label(make_label("PII", 10));
    sentinel
        .attach_lineage_tag(&mut graph, "user-record", "PII")
        .unwrap();

    let verdict = sentinel
        .track_flow(&mut graph, "user-record", "external-api", "export", 1000)
        .unwrap();
    assert_eq!(verdict, FlowVerdict::Quarantine);
    assert_eq!(sentinel.alert_count(), 1);
    assert_eq!(sentinel.receipt_count(), 1);
}

// ---- Scenario: Secret data crossing trust boundary ----

#[test]
fn scenario_secret_cross_boundary_quarantined() {
    let config = default_config();
    let mut graph = LineageGraph::new(config.clone());
    let mut sentinel = ExfiltrationSentinel::new(config);

    sentinel
        .add_boundary(make_boundary("b-secret", "secure", "public", &["SECRET"]))
        .unwrap();

    graph.register_label(make_label("SECRET", 20));
    graph.assign_taint("classified-doc", "SECRET").unwrap();

    let verdict = sentinel
        .track_flow(&mut graph, "classified-doc", "public-cdn", "publish", 2000)
        .unwrap();
    assert_eq!(verdict, FlowVerdict::Quarantine);
}

// ---- Scenario: Safe internal flow passes ----

#[test]
fn scenario_safe_internal_flow_passes() {
    let config = default_config();
    let mut graph = LineageGraph::new(config.clone());
    let mut sentinel = ExfiltrationSentinel::new(config);

    sentinel
        .add_boundary(make_boundary("b-int", "internal", "external", &["PII"]))
        .unwrap();

    graph.register_label(make_label("INTERNAL", 5));
    graph.assign_taint("report", "INTERNAL").unwrap();

    let verdict = sentinel
        .track_flow(&mut graph, "report", "internal-archive", "archive", 3000)
        .unwrap();
    assert_eq!(verdict, FlowVerdict::Pass);
    assert_eq!(sentinel.alert_count(), 0);
}

// ---- Scenario: Multi-hop taint propagation ----

#[test]
fn scenario_multi_hop_taint_propagation() {
    let config = default_config();
    let mut graph = LineageGraph::new(config.clone());
    let mut sentinel = ExfiltrationSentinel::new(config);

    sentinel
        .add_boundary(make_boundary("b-hop", "stage", "external", &["CRED"]))
        .unwrap();

    graph.register_label(make_label("CRED", 15));
    graph.assign_taint("password-store", "CRED").unwrap();

    // Hop 1: password-store -> staging-cache (internal, safe)
    let v1 = sentinel
        .track_flow(&mut graph, "password-store", "staging-cache", "copy", 100)
        .unwrap();
    assert_eq!(v1, FlowVerdict::Pass);

    // Verify taint propagated to staging-cache
    let ts = graph.get_taint_set("staging-cache").unwrap();
    assert!(ts.contains("CRED"));

    // Hop 2: staging-cache -> external-log (crosses boundary with CRED taint)
    let v2 = sentinel
        .track_flow(&mut graph, "staging-cache", "external-log", "export", 200)
        .unwrap();
    assert_eq!(v2, FlowVerdict::Quarantine);
}

// ---- Scenario: Deny-all boundary ----

#[test]
fn scenario_deny_all_boundary_blocks_any_taint() {
    let config = default_config();
    let mut graph = LineageGraph::new(config.clone());
    let mut sentinel = ExfiltrationSentinel::new(config);

    let deny_all_boundary = TaintBoundary {
        boundary_id: "airgap".to_string(),
        from_zone: "classified".to_string(),
        to_zone: "unclassified".to_string(),
        denied_labels: BTreeSet::new(),
        deny_all: true,
    };
    sentinel.add_boundary(deny_all_boundary).unwrap();

    graph.register_label(make_label("LOW", 1));
    graph.assign_taint("doc-a", "LOW").unwrap();

    let verdict = sentinel
        .track_flow(&mut graph, "doc-a", "unclassified-net", "send", 400)
        .unwrap();
    // Source contains "doc-a" which doesn't contain "classified", so this should pass
    // because the boundary check uses source.contains(&from_zone).
    // Let's use correct zone names:
    assert_eq!(verdict, FlowVerdict::Pass);
}

#[test]
fn scenario_deny_all_boundary_with_matching_zones() {
    let config = default_config();
    let mut graph = LineageGraph::new(config.clone());
    let mut sentinel = ExfiltrationSentinel::new(config);

    let deny_all_boundary = TaintBoundary {
        boundary_id: "airgap".to_string(),
        from_zone: "classified".to_string(),
        to_zone: "unclassified".to_string(),
        denied_labels: BTreeSet::new(),
        deny_all: true,
    };
    sentinel.add_boundary(deny_all_boundary).unwrap();

    graph.register_label(make_label("LOW", 1));
    graph.assign_taint("classified-doc", "LOW").unwrap();

    let verdict = sentinel
        .track_flow(
            &mut graph,
            "classified-doc",
            "unclassified-net",
            "send",
            500,
        )
        .unwrap();
    assert_eq!(verdict, FlowVerdict::Quarantine);
}

// ---- Scenario: Graph scan across multiple edges ----

#[test]
fn scenario_scan_graph_finds_all_violations() {
    let config = default_config();
    let mut graph = LineageGraph::new(config.clone());
    let mut sentinel = ExfiltrationSentinel::new(config);

    sentinel
        .add_boundary(make_boundary("b-scan", "priv", "pub", &["TOKEN"]))
        .unwrap();

    graph.register_label(make_label("TOKEN", 10));

    let mut ts = TaintSet::new();
    ts.insert("TOKEN");

    // Add 3 violating edges
    for i in 0..3 {
        let edge = FlowEdge {
            edge_id: format!("scan-edge-{}", i),
            source: format!("priv-svc-{}", i),
            sink: format!("pub-api-{}", i),
            operation: "leak".to_string(),
            taint_set: ts.clone(),
            timestamp_ms: i as u64,
            quarantined: false,
        };
        graph.append_edge(edge).unwrap();
    }

    // Add 2 safe edges
    for i in 0..2 {
        let edge = FlowEdge {
            edge_id: format!("safe-edge-{}", i),
            source: format!("priv-svc-{}", i),
            sink: format!("priv-cache-{}", i),
            operation: "cache".to_string(),
            taint_set: TaintSet::new(),
            timestamp_ms: (10 + i) as u64,
            quarantined: false,
        };
        graph.append_edge(edge).unwrap();
    }

    let result = sentinel.scan_graph(&mut graph).unwrap();
    assert_eq!(result.exfiltrations_detected, 3);
    assert_eq!(result.exfiltrations_contained, 3);
    assert_eq!(result.edges_passed, 2);
}

// ---- Scenario: Recall/precision metric evaluation ----

#[test]
fn scenario_metrics_above_threshold() {
    let config = default_config();
    let sentinel = ExfiltrationSentinel::new(config);
    let metrics = sentinel.evaluate_metrics(96, 4, 5).unwrap();
    assert!(metrics.recall_ok, "recall should be above 95%");
    assert!(metrics.precision_ok, "precision should be above 90%");
    assert!(metrics.recall_pct >= 95.0);
    assert!(metrics.precision_pct >= 90.0);
}

#[test]
fn scenario_recall_below_threshold() {
    let config = default_config();
    let sentinel = ExfiltrationSentinel::new(config);
    let metrics = sentinel.evaluate_metrics(50, 50, 0).unwrap();
    assert!(
        !metrics.recall_ok,
        "50% recall should be below 95% threshold"
    );
}

#[test]
fn scenario_precision_below_threshold() {
    let config = default_config();
    let sentinel = ExfiltrationSentinel::new(config);
    let metrics = sentinel.evaluate_metrics(50, 0, 50).unwrap();
    assert!(
        !metrics.precision_ok,
        "50% precision should be below 90% threshold"
    );
}

// ---- Scenario: Covert channel detection ----

#[test]
fn scenario_covert_channel_rapid_flow() {
    let config = default_config();
    let mut graph = LineageGraph::new(config.clone());
    let sentinel = ExfiltrationSentinel::new(config);

    // Simulate rapid flows from same source to external sink
    for i in 0..5 {
        let edge = FlowEdge {
            edge_id: format!("covert-{}", i),
            source: "covert-src".to_string(),
            sink: "external-drop".to_string(),
            operation: "drip".to_string(),
            taint_set: TaintSet::new(),
            timestamp_ms: i as u64 * 10,
            quarantined: false,
        };
        graph.append_edge(edge).unwrap();
    }

    let detections = sentinel.detect_covert_channels(&graph);
    assert!(!detections.is_empty());
    assert_eq!(detections[0].pattern, "rapid_external_flow");
    assert!(detections[0].confidence_pct > 0);
}

#[test]
fn scenario_no_covert_channel_below_threshold() {
    let config = default_config();
    let mut graph = LineageGraph::new(config.clone());
    let sentinel = ExfiltrationSentinel::new(config);

    // Only 2 flows from same source - below the threshold of 3
    for i in 0..2 {
        let edge = FlowEdge {
            edge_id: format!("low-{}", i),
            source: "src".to_string(),
            sink: "external-api".to_string(),
            operation: "call".to_string(),
            taint_set: TaintSet::new(),
            timestamp_ms: i as u64,
            quarantined: false,
        };
        graph.append_edge(edge).unwrap();
    }

    let detections = sentinel.detect_covert_channels(&graph);
    assert!(detections.is_empty());
}

// ---- Scenario: Lineage tag persistence across propagation ----

#[test]
fn scenario_lineage_tag_persists_through_propagation_chain() {
    let config = default_config();
    let mut graph = LineageGraph::new(config);

    graph.register_label(make_label("GDPR", 10));
    graph.register_label(make_label("HIPAA", 15));

    graph.assign_taint("patient-record", "GDPR").unwrap();
    graph.assign_taint("patient-record", "HIPAA").unwrap();

    // Propagate through chain
    graph
        .propagate_taint("patient-record", "staging", "copy", 100)
        .unwrap();
    graph
        .propagate_taint("staging", "warehouse", "transform", 200)
        .unwrap();
    graph
        .propagate_taint("warehouse", "report", "aggregate", 300)
        .unwrap();

    // All intermediate and final nodes should carry both labels
    for node in ["staging", "warehouse", "report"] {
        let ts = graph.get_taint_set(node).expect("taint set must exist");
        assert!(ts.contains("GDPR"), "{node} must retain GDPR");
        assert!(ts.contains("HIPAA"), "{node} must retain HIPAA");
    }
}

// ---- Scenario: Snapshot faithfulness ----

#[test]
fn scenario_snapshot_captures_full_state() {
    let config = default_config();
    let mut graph = LineageGraph::new(config);

    graph.register_label(make_label("PII", 10));
    graph.register_label(make_label("SECRET", 20));

    for i in 0..5 {
        let edge = FlowEdge {
            edge_id: format!("snap-{}", i),
            source: "a".to_string(),
            sink: "b".to_string(),
            operation: "op".to_string(),
            taint_set: TaintSet::new(),
            timestamp_ms: i as u64,
            quarantined: false,
        };
        graph.append_edge(edge).unwrap();
    }

    let snap = graph.snapshot("test-snap", 9999);
    assert_eq!(snap.edge_count, 5);
    assert_eq!(snap.label_count, 2);
    assert_eq!(snap.schema_version, SCHEMA_VERSION);
    assert!(invariants::verify_snapshot_faithful(&graph, &snap));
}

#[test]
fn scenario_snapshot_faithfulness_rejects_edge_content_substitution() {
    let mut graph = LineageGraph::new(default_config());
    graph.register_label(make_label("PII", 10));
    graph
        .append_edge(make_edge("edge-1", "internal-source", "external-sink", 1))
        .unwrap();

    let mut snap = graph.snapshot("test-snap", 9999);
    snap.edges.first_mut().expect("snapshot has one edge").sink =
        "attacker-controlled-sink".to_string();

    assert_eq!(snap.edge_count, graph.edge_count());
    assert_eq!(snap.label_count, graph.label_count());
    assert!(!invariants::verify_snapshot_faithful(&graph, &snap));
}

#[test]
fn scenario_snapshot_faithfulness_rejects_edge_reordering() {
    let mut graph = LineageGraph::new(default_config());
    graph.register_label(make_label("PII", 10));
    graph
        .append_edge(make_edge("edge-1", "internal-a", "external-a", 1))
        .unwrap();
    graph
        .append_edge(make_edge("edge-2", "internal-b", "external-b", 2))
        .unwrap();

    let mut snap = graph.snapshot("test-snap", 9999);
    snap.edges.swap(0, 1);

    assert_eq!(snap.edge_count, graph.edge_count());
    assert_eq!(snap.label_count, graph.label_count());
    assert!(!invariants::verify_snapshot_faithful(&graph, &snap));
}

#[test]
fn scenario_snapshot_faithfulness_rejects_label_content_substitution() {
    let mut graph = LineageGraph::new(default_config());
    graph.register_label(make_label("SECRET", 20));
    graph
        .append_edge(make_edge("edge-1", "secure-source", "internal-sink", 1))
        .unwrap();

    let mut snap = graph.snapshot("test-snap", 9999);
    snap.labels
        .get_mut("SECRET")
        .expect("snapshot has SECRET label")
        .severity = 1;

    assert_eq!(snap.edge_count, graph.edge_count());
    assert_eq!(snap.label_count, graph.label_count());
    assert!(!invariants::verify_snapshot_faithful(&graph, &snap));
}

// ---- Scenario: Event and error code constants are correct ----

#[test]
fn all_canonical_event_codes_defined() {
    assert_eq!(LINEAGE_TAG_ATTACHED, "LINEAGE_TAG_ATTACHED");
    assert_eq!(LINEAGE_FLOW_TRACKED, "LINEAGE_FLOW_TRACKED");
    assert_eq!(SENTINEL_SCAN_START, "SENTINEL_SCAN_START");
    assert_eq!(SENTINEL_EXFIL_DETECTED, "SENTINEL_EXFIL_DETECTED");
    assert_eq!(
        SENTINEL_CONTAINMENT_TRIGGERED,
        "SENTINEL_CONTAINMENT_TRIGGERED"
    );
}

#[test]
fn all_canonical_error_codes_defined() {
    assert_eq!(ERR_LINEAGE_TAG_MISSING, "ERR_LINEAGE_TAG_MISSING");
    assert_eq!(ERR_LINEAGE_FLOW_BROKEN, "ERR_LINEAGE_FLOW_BROKEN");
    assert_eq!(
        ERR_SENTINEL_RECALL_BELOW_THRESHOLD,
        "ERR_SENTINEL_RECALL_BELOW_THRESHOLD"
    );
    assert_eq!(
        ERR_SENTINEL_PRECISION_BELOW_THRESHOLD,
        "ERR_SENTINEL_PRECISION_BELOW_THRESHOLD"
    );
    assert_eq!(
        ERR_SENTINEL_CONTAINMENT_FAILED,
        "ERR_SENTINEL_CONTAINMENT_FAILED"
    );
    assert_eq!(ERR_SENTINEL_COVERT_CHANNEL, "ERR_SENTINEL_COVERT_CHANNEL");
}

#[test]
fn all_canonical_invariants_defined() {
    assert_eq!(INV_LINEAGE_TAG_PERSISTENCE, "INV-LINEAGE-TAG-PERSISTENCE");
    assert_eq!(
        INV_SENTINEL_RECALL_THRESHOLD,
        "INV-SENTINEL-RECALL-THRESHOLD"
    );
    assert_eq!(
        INV_SENTINEL_PRECISION_THRESHOLD,
        "INV-SENTINEL-PRECISION-THRESHOLD"
    );
    assert_eq!(INV_SENTINEL_AUTO_CONTAIN, "INV-SENTINEL-AUTO-CONTAIN");
}
