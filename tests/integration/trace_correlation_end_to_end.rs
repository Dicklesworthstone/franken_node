//! Integration tests for bd-1gnb: Distributed trace correlation IDs.

use frankenengine_node::connector::trace_context::*;

fn tid() -> String {
    "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6".to_string()
}
fn sid(n: u8) -> String {
    format!("00000000000000{n:02x}")
}

#[test]
fn inv_trc_required() {
    let bad = TraceContext {
        trace_id: String::new(),
        span_id: sid(1),
        parent_span_id: None,
        timestamp: "ts".into(),
    };
    assert_eq!(bad.validate().unwrap_err().code(), "TRC_MISSING_TRACE_ID");
}

#[test]
fn inv_trc_propagated() {
    let root = TraceContext {
        trace_id: tid(),
        span_id: sid(1),
        parent_span_id: None,
        timestamp: "ts1".into(),
    };
    let child = root.child(&sid(2), "ts2");
    assert_eq!(child.trace_id, root.trace_id);
    assert_eq!(child.parent_span_id, Some(root.span_id.clone()));
}

#[test]
fn inv_trc_stitchable() {
    let mut store = TraceStore::new();
    let root = TraceContext {
        trace_id: tid(),
        span_id: sid(1),
        parent_span_id: None,
        timestamp: "ts1".into(),
    };
    store.record(&root).unwrap();
    let child = root.child(&sid(2), "ts2");
    store.record(&child).unwrap();
    let grandchild = child.child(&sid(3), "ts3");
    store.record(&grandchild).unwrap();

    let stitched = store.stitch(&tid());
    assert_eq!(stitched.len(), 3);
    assert_eq!(stitched[0].span_id, sid(1));
    assert_eq!(stitched[1].span_id, sid(2));
    assert_eq!(stitched[2].span_id, sid(3));
}

#[test]
fn inv_trc_conformance() {
    let good = TracedArtifact {
        artifact_id: "a1".into(),
        artifact_type: "invoke".into(),
        trace_context: Some(TraceContext {
            trace_id: tid(),
            span_id: sid(1),
            parent_span_id: None,
            timestamp: "ts".into(),
        }),
    };
    let bad = TracedArtifact {
        artifact_id: "a2".into(),
        artifact_type: "receipt".into(),
        trace_context: None,
    };
    let report = TraceStore::check_conformance(&[good, bad]);
    assert_eq!(report.verdict, "FAIL");
    assert_eq!(report.violations.len(), 1);
    assert_eq!(report.violations[0].artifact_id, "a2");
}
