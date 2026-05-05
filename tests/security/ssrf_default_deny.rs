//! SSRF default-deny conformance tests (bd-1nk5).
//!
//! Verifies that the default policy template blocks all private CIDRs,
//! cloud metadata, tailnet, and IPv6 loopback. Tests allowlist
//! exceptions with receipts and common SSRF attack patterns.

use frankenengine_node::security::network_guard::{Action, Protocol};
use frankenengine_node::security::ssrf_policy::*;
use std::net::{IpAddr, Ipv4Addr};

fn fresh_template() -> SsrfPolicyTemplate {
    SsrfPolicyTemplate::default_template("conn-test".into())
}

fn public_fixture_ip() -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))
}

// === Default deny for all private CIDRs ===

#[test]
fn denies_127_0_0_1() {
    let mut t = fresh_template();
    let result = t.check_ssrf("127.0.0.1", 80, Protocol::Http, "t1", "ts");
    assert!(result.is_err());
}

#[test]
fn denies_10_network() {
    let mut t = fresh_template();
    let result = t.check_ssrf("10.0.0.1", 443, Protocol::Http, "t2", "ts");
    assert!(result.is_err());
}

#[test]
fn denies_172_16_network() {
    let mut t = fresh_template();
    let result = t.check_ssrf("172.16.0.1", 443, Protocol::Http, "t3", "ts");
    assert!(result.is_err());
}

#[test]
fn denies_192_168_network() {
    let mut t = fresh_template();
    let result = t.check_ssrf("192.168.1.1", 443, Protocol::Http, "t4", "ts");
    assert!(result.is_err());
}

#[test]
fn denies_cloud_metadata() {
    let mut t = fresh_template();
    let result = t.check_ssrf("169.254.169.254", 80, Protocol::Http, "t5", "ts");
    assert!(result.is_err());
}

#[test]
fn denies_tailnet_range() {
    let mut t = fresh_template();
    let result = t.check_ssrf("100.100.100.100", 443, Protocol::Http, "t6", "ts");
    assert!(result.is_err());
}

#[test]
fn denies_ipv6_loopback() {
    let mut t = fresh_template();
    let result = t.check_ssrf("::1", 80, Protocol::Http, "t7", "ts");
    assert!(result.is_err());
}

// === Public IPs and resolved hostnames allowed ===

#[test]
fn allows_public_ip() {
    let mut t = fresh_template();
    let result = t.check_ssrf("8.8.8.8", 443, Protocol::Http, "t8", "ts");
    assert!(result.is_ok());
}

#[test]
fn denies_unresolved_hostname() {
    let mut t = fresh_template();
    let result = t.check_ssrf("api.example.com", 443, Protocol::Http, "t9", "ts");
    assert!(result.is_err());
}

#[test]
fn allows_resolved_public_hostname() {
    let mut t = fresh_template();
    let result = t.check_ssrf_resolved(
        "api.example.com",
        public_fixture_ip(),
        443,
        Protocol::Http,
        "t9-resolved",
        "ts",
    );
    assert!(result.is_ok());
}

// === Allowlist exceptions ===

#[test]
fn allowlist_overrides_deny() {
    let mut t = fresh_template();
    let receipt = t
        .add_allowlist("10.0.0.5", Some(8080), "health check", "t10", "ts")
        .unwrap();
    assert!(!receipt.receipt_id.is_empty());
    let result = t.check_ssrf("10.0.0.5", 8080, Protocol::Http, "t11", "ts");
    assert!(result.is_ok());
}

#[test]
fn allowlist_requires_reason() {
    let mut t = fresh_template();
    let result = t.add_allowlist("10.0.0.5", None, "", "t12", "ts");
    assert!(result.is_err());
}

#[test]
fn allowlist_receipt_has_trace_id() {
    let mut t = fresh_template();
    let receipt = t
        .add_allowlist("192.168.1.1", None, "dev db", "trace-abc", "ts")
        .unwrap();
    assert_eq!(receipt.trace_id, "trace-abc");
}

// === Audit emission ===

#[test]
fn every_check_emits_audit() {
    let mut t = fresh_template();
    let _ = t.check_ssrf("127.0.0.1", 80, Protocol::Http, "t13", "ts");
    let _ = t.check_ssrf("8.8.8.8", 443, Protocol::Http, "t14", "ts");
    assert_eq!(t.audit_log.len(), 2);
}

#[test]
fn audit_records_correct_action() {
    let mut t = fresh_template();
    let _ = t.check_ssrf("127.0.0.1", 80, Protocol::Http, "t15", "ts");
    assert_eq!(t.audit_log[0].action, Action::Deny);
    let _ = t.check_ssrf("8.8.8.8", 443, Protocol::Http, "t16", "ts");
    assert_eq!(t.audit_log[1].action, Action::Allow);
}

// === Egress policy conversion ===

#[test]
fn to_egress_policy_default_deny() {
    let t = fresh_template();
    let policy = t.to_egress_policy();
    assert_eq!(policy.default_action, Action::Deny);
}

#[test]
fn to_egress_policy_includes_allowlist() {
    let mut t = fresh_template();
    let _ = t.add_allowlist("10.0.0.5", Some(8080), "api", "t17", "ts");
    let policy = t.to_egress_policy();
    assert!(!policy.rules.is_empty());
}
