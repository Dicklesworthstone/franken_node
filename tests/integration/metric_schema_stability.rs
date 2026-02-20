//! Integration tests for bd-1ugy: Stable telemetry namespace.

use frankenengine_node::connector::telemetry_namespace::*;

fn make_registry() -> SchemaRegistry {
    let mut r = SchemaRegistry::new();
    let metrics = vec![
        ("franken.protocol.messages_total", MetricType::Counter, vec!["peer_id"]),
        ("franken.capability.invocations_total", MetricType::Counter, vec!["cap_id"]),
        ("franken.egress.bytes_sent_total", MetricType::Counter, vec!["dest"]),
        ("franken.security.auth_failures_total", MetricType::Counter, vec!["method"]),
    ];
    for (name, mt, labels) in &metrics {
        r.register(&MetricRegistration {
            name: name.to_string(),
            metric_type: *mt,
            labels: labels.iter().map(|s| s.to_string()).collect(),
            version: 1,
        })
        .unwrap();
        r.freeze(name).unwrap();
    }
    r
}

#[test]
fn inv_tns_versioned() {
    let mut r = SchemaRegistry::new();
    let err = r
        .register(&MetricRegistration {
            name: "franken.protocol.foo".into(),
            metric_type: MetricType::Counter,
            labels: vec![],
            version: 0,
        })
        .unwrap_err();
    assert_eq!(err.code(), "TNS_VERSION_MISSING");
}

#[test]
fn inv_tns_frozen() {
    let mut r = make_registry();
    let err = r
        .register(&MetricRegistration {
            name: "franken.protocol.messages_total".into(),
            metric_type: MetricType::Gauge,
            labels: vec!["peer_id".into()],
            version: 2,
        })
        .unwrap_err();
    assert_eq!(err.code(), "TNS_FROZEN_CONFLICT");
}

#[test]
fn inv_tns_deprecated_still_queryable() {
    let mut r = make_registry();
    r.deprecate("franken.egress.bytes_sent_total", "replaced by v2", 2)
        .unwrap();
    let s = r.get("franken.egress.bytes_sent_total").unwrap();
    assert!(s.deprecated);
    assert_eq!(s.deprecation_reason.as_deref(), Some("replaced by v2"));
}

#[test]
fn inv_tns_namespace_enforced() {
    let mut r = SchemaRegistry::new();
    let err = r
        .register(&MetricRegistration {
            name: "custom.invalid.metric".into(),
            metric_type: MetricType::Counter,
            labels: vec![],
            version: 1,
        })
        .unwrap_err();
    assert_eq!(err.code(), "TNS_INVALID_NAMESPACE");
}
