//! Network guard conformance tests (bd-2m2b).
//!
//! Verifies default-deny, rule ordering, audit emission, and
//! protocol separation.

use frankenengine_node::security::network_guard::*;
use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, RemoteOperation, RemoteScope,
};

fn sample_policy() -> EgressPolicy {
    let mut policy = EgressPolicy::new("conn-1".into(), Action::Deny);
    policy.add_rule(EgressRule {
        host: "api.example.com".into(),
        port: Some(443),
        action: Action::Allow,
        protocol: Protocol::Http,
    });
    policy.add_rule(EgressRule {
        host: "*.trusted.com".into(),
        port: None,
        action: Action::Allow,
        protocol: Protocol::Http,
    });
    policy
}

fn egress_scope() -> RemoteScope {
    RemoteScope::new(
        vec![RemoteOperation::NetworkEgress],
        vec!["http://".to_string(), "tcp://".to_string()],
    )
}

fn gate_and_cap() -> (
    CapabilityGate,
    frankenengine_node::security::remote_cap::RemoteCap,
) {
    let provider = CapabilityProvider::new("conformance-secret");
    let (cap, _) = provider
        .issue(
            "network-guard-conformance",
            egress_scope(),
            1_700_000_000,
            3_600,
            true,
            false,
            "trace-conformance-cap",
        )
        .expect("issue cap");
    (CapabilityGate::new("conformance-secret"), cap)
}

#[test]
fn default_deny_applied() {
    let policy = EgressPolicy::new("conn-1".into(), Action::Deny);
    let (action, idx) = policy.evaluate("anything.com", 80, Protocol::Http);
    assert_eq!(action, Action::Deny);
    assert_eq!(idx, None);
}

#[test]
fn explicit_allow_overrides_default() {
    let policy = sample_policy();
    let (action, _) = policy.evaluate("api.example.com", 443, Protocol::Http);
    assert_eq!(action, Action::Allow);
}

#[test]
fn rules_evaluated_in_order() {
    let mut policy = EgressPolicy::new("conn-1".into(), Action::Deny);
    policy.add_rule(EgressRule {
        host: "*".into(),
        port: None,
        action: Action::Allow,
        protocol: Protocol::Http,
    });
    policy.add_rule(EgressRule {
        host: "evil.com".into(),
        port: None,
        action: Action::Deny,
        protocol: Protocol::Http,
    });
    let (action, idx) = policy.evaluate("evil.com", 80, Protocol::Http);
    assert_eq!(action, Action::Allow);
    assert_eq!(idx, Some(0));
}

#[test]
fn every_decision_emits_audit() {
    let mut guard = NetworkGuard::new(sample_policy());
    let (mut gate, cap) = gate_and_cap();
    let _ = guard.process_egress(
        "api.example.com",
        443,
        Protocol::Http,
        Some(&cap),
        &mut gate,
        "t1",
        "ts",
        1_700_000_001,
    );
    let _ = guard.process_egress(
        "unknown.com",
        80,
        Protocol::Http,
        Some(&cap),
        &mut gate,
        "t2",
        "ts",
        1_700_000_002,
    );
    assert_eq!(guard.audit_log.len(), 2);
}

#[test]
fn audit_captures_trace_id() {
    let mut guard = NetworkGuard::new(sample_policy());
    let (mut gate, cap) = gate_and_cap();
    let _ = guard.process_egress(
        "api.example.com",
        443,
        Protocol::Http,
        Some(&cap),
        &mut gate,
        "trace-xyz",
        "ts",
        1_700_000_003,
    );
    assert_eq!(guard.audit_log[0].trace_id, "trace-xyz");
}

#[test]
fn protocol_separation() {
    let policy = sample_policy(); // rules are HTTP only
    let (action, _) = policy.evaluate("api.example.com", 443, Protocol::Tcp);
    assert_eq!(action, Action::Deny); // TCP doesn't match HTTP rules
}

#[test]
fn wildcard_host_matching() {
    let policy = sample_policy();
    let (action, _) = policy.evaluate("sub.trusted.com", 443, Protocol::Http);
    assert_eq!(action, Action::Allow);
    let (action, _) = policy.evaluate("trusted.com", 443, Protocol::Http);
    assert_eq!(action, Action::Deny); // exact "trusted.com" doesn't match "*.trusted.com"
}
