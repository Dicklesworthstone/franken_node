//! Manifest negotiation fail-closed conformance tests (bd-17mb).
//!
//! Verifies SemVer comparison is semantic, fail-closed behaviour on
//! version/feature/transport mismatches, and trace correlation.

use frankenengine_node::connector::manifest_negotiation::*;

fn host() -> HostCapabilities {
    HostCapabilities {
        min_version: SemVer::new(1, 0, 0),
        max_version: SemVer::new(2, 99, 99),
        available_features: vec!["auth".into(), "streaming".into(), "batch".into()],
        transport_caps: vec![TransportCap::Http1, TransportCap::Http2, TransportCap::Grpc],
    }
}

fn manifest(version: SemVer, features: Vec<&str>, transport: Vec<TransportCap>) -> ConnectorManifest {
    ConnectorManifest {
        connector_id: "conn-test".into(),
        version,
        required_features: features.into_iter().map(|s| s.to_string()).collect(),
        transport_caps: transport,
    }
}

#[test]
fn semver_is_semantic_not_lexical() {
    // "9.0.0" > "10.0.0" lexically, but 9 < 10 semantically
    assert!(check_version(
        &SemVer::new(9, 0, 0),
        &SemVer::new(1, 0, 0),
        &SemVer::new(10, 0, 0)
    ));
}

#[test]
fn major_version_mismatch_fails_closed() {
    let m = manifest(SemVer::new(5, 0, 0), vec![], vec![TransportCap::Http1]);
    let result = negotiate(&m, &host(), "t1", "ts");
    assert!(matches!(result.outcome, Outcome::Rejected { .. }));
    assert!(!result.version_ok);
}

#[test]
fn missing_feature_fails_closed() {
    let m = manifest(SemVer::new(1, 0, 0), vec!["teleport"], vec![TransportCap::Http1]);
    let result = negotiate(&m, &host(), "t2", "ts");
    assert!(matches!(result.outcome, Outcome::Rejected { .. }));
    assert!(!result.features_ok);
    assert_eq!(result.missing_features, vec!["teleport".to_string()]);
}

#[test]
fn missing_transport_fails_closed() {
    let m = manifest(SemVer::new(1, 0, 0), vec![], vec![TransportCap::Http3]);
    let result = negotiate(&m, &host(), "t3", "ts");
    assert!(matches!(result.outcome, Outcome::Rejected { .. }));
    assert!(!result.transport_ok);
}

#[test]
fn all_pass_accepted() {
    let m = manifest(SemVer::new(2, 1, 0), vec!["auth"], vec![TransportCap::Http2]);
    let result = negotiate(&m, &host(), "t4", "ts");
    assert_eq!(result.outcome, Outcome::Accepted);
}

#[test]
fn partial_match_still_rejected() {
    // Version OK, features OK, transport FAIL → rejected
    let m = manifest(SemVer::new(1, 0, 0), vec!["auth"], vec![TransportCap::Http3]);
    let result = negotiate(&m, &host(), "t5", "ts");
    assert!(matches!(result.outcome, Outcome::Rejected { .. }));
}

#[test]
fn trace_id_preserved() {
    let m = manifest(SemVer::new(1, 0, 0), vec![], vec![TransportCap::Http1]);
    let result = negotiate(&m, &host(), "trace-xyz", "ts");
    assert_eq!(result.trace_id, "trace-xyz");
}

#[test]
fn rejection_reason_contains_error_codes() {
    let m = manifest(SemVer::new(99, 0, 0), vec!["warp"], vec![TransportCap::Http3]);
    let result = negotiate(&m, &host(), "t6", "ts");
    if let Outcome::Rejected { reason } = &result.outcome {
        assert!(reason.contains("MANIFEST_VERSION_UNSUPPORTED"));
        assert!(reason.contains("MANIFEST_FEATURE_MISSING"));
        assert!(reason.contains("MANIFEST_TRANSPORT_MISMATCH"));
    } else {
        panic!("expected rejected");
    }
}

#[test]
fn boundary_version_min_accepted() {
    let m = manifest(SemVer::new(1, 0, 0), vec![], vec![TransportCap::Http1]);
    let result = negotiate(&m, &host(), "t7", "ts");
    assert_eq!(result.outcome, Outcome::Accepted);
}

#[test]
fn boundary_version_max_accepted() {
    let m = manifest(SemVer::new(2, 99, 99), vec![], vec![TransportCap::Http1]);
    let result = negotiate(&m, &host(), "t8", "ts");
    assert_eq!(result.outcome, Outcome::Accepted);
}
