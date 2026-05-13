//! Security harness for bd-3b8m anti-amplification response bounds.

use frankenengine_node::connector::anti_amplification::{
    AmplificationAuditEntry, AmplificationPolicy, BoundCheckRequest, BoundCheckVerdict,
    BoundViolation, ResponseBound, check_response_bound, enforced_limit, run_adversarial_harness,
};

const TRACE_ID: &str = "trace-bd-3b8m-security";
const TIMESTAMP: &str = "2026-05-13T00:00:00Z";

fn policy() -> AmplificationPolicy {
    AmplificationPolicy {
        max_response_ratio: 10.0,
        unauth_max_bytes: 1_000,
        auth_max_bytes: 10_000,
        max_items_per_response: 50,
    }
}

fn bound(max_bytes: u64, max_items: u32) -> ResponseBound {
    ResponseBound {
        max_bytes,
        max_items,
    }
}

fn req(
    request_id: &str,
    peer_id: &str,
    authenticated: bool,
    request_bytes: u64,
    declared_bytes: u64,
    actual_response_bytes: u64,
    actual_items: u32,
) -> BoundCheckRequest {
    BoundCheckRequest {
        request_id: request_id.to_string(),
        peer_id: peer_id.to_string(),
        authenticated,
        request_bytes,
        declared_bound: bound(declared_bytes, 50),
        actual_response_bytes,
        actual_items,
    }
}

fn check(request: &BoundCheckRequest) -> (BoundCheckVerdict, AmplificationAuditEntry) {
    check_response_bound(request, &policy(), TRACE_ID, TIMESTAMP).expect("policy is valid")
}

#[test]
fn inv_aar_bounded_blocks_response_above_declared_bytes() {
    let exact = req("r-exact", "peer-auth", true, 512, 1_024, 1_024, 1);
    let over = req("r-over", "peer-auth", true, 512, 1_024, 1_025, 1);

    let (exact_verdict, _) = check(&exact);
    let (over_verdict, over_audit) = check(&over);

    assert!(exact_verdict.allowed);
    assert!(!over_verdict.allowed);
    assert_eq!(over_verdict.enforced_limit, 1_024);
    assert_eq!(over_audit.enforced_limit, 1_024);
    assert!(over_verdict.violations.iter().any(|violation| {
        matches!(
            violation,
            BoundViolation::ResponseTooLarge {
                actual: 1_025,
                limit: 1_024
            }
        )
    }));
}

#[test]
fn inv_aar_unauth_strict_uses_lower_peer_cap_than_authenticated() {
    let p = policy();
    let declared = bound(50_000, 50);
    let unauth_limit = enforced_limit(&p, &declared, false);
    let auth_limit = enforced_limit(&p, &declared, true);

    assert!(unauth_limit < auth_limit);
    assert_eq!(unauth_limit, 1_000);
    assert_eq!(auth_limit, 10_000);

    let unauth = req("r-unauth", "peer-guest", false, 1_000, 50_000, 1_001, 1);
    let auth = req("r-auth", "peer-auth", true, 1_000, 50_000, 1_001, 1);

    let (unauth_verdict, _) = check(&unauth);
    let (auth_verdict, _) = check(&auth);

    assert!(!unauth_verdict.allowed);
    assert!(auth_verdict.allowed);
    assert!(unauth_verdict.violations.iter().any(|violation| {
        matches!(
            violation,
            BoundViolation::UnauthLimit {
                actual: 1_001,
                limit: 1_000
            }
        )
    }));
}

#[test]
fn inv_aar_auditable_records_blocked_peer_trace_and_verdict() {
    let blocked = req("r-audit", "peer-audit", false, 500, 50_000, 1_001, 1);

    let (verdict, audit) = check(&blocked);

    assert!(!verdict.allowed);
    assert_eq!(verdict.request_id, "r-audit");
    assert_eq!(verdict.trace_id, TRACE_ID);
    assert_eq!(audit.request_id, "r-audit");
    assert_eq!(audit.peer_id, "peer-audit");
    assert_eq!(audit.timestamp, TIMESTAMP);
    assert_eq!(audit.verdict, "BLOCK");
}

#[test]
fn inv_aar_deterministic_harness_preserves_order_and_verdicts() {
    let requests = vec![
        req("r-ok", "peer-auth", true, 1_000, 5_000, 500, 1),
        req("r-ratio", "peer-auth", true, 100, 10_000, 1_001, 1),
        req("r-unauth", "peer-guest", false, 1_000, 50_000, 1_001, 1),
    ];

    let first =
        run_adversarial_harness(&requests, &policy(), TRACE_ID, TIMESTAMP).expect("valid policy");
    let second =
        run_adversarial_harness(&requests, &policy(), TRACE_ID, TIMESTAMP).expect("valid policy");

    assert_eq!(first.len(), second.len());
    for ((first_verdict, first_audit), (second_verdict, second_audit)) in
        first.iter().zip(second.iter())
    {
        assert_eq!(first_verdict.request_id, second_verdict.request_id);
        assert_eq!(first_verdict.allowed, second_verdict.allowed);
        assert_eq!(
            first_verdict.violations.len(),
            second_verdict.violations.len()
        );
        assert_eq!(first_verdict.enforced_limit, second_verdict.enforced_limit);
        assert_eq!(first_audit.verdict, second_audit.verdict);
        assert_eq!(first_audit.ratio, second_audit.ratio);
    }

    assert_eq!(first[0].0.request_id, "r-ok");
    assert!(first[0].0.allowed);
    assert_eq!(first[1].0.request_id, "r-ratio");
    assert!(!first[1].0.allowed);
    assert_eq!(first[2].0.request_id, "r-unauth");
    assert!(!first[2].0.allowed);
}

#[test]
fn adversarial_zero_byte_request_with_response_is_ratio_blocked() {
    let zero_request = req("r-zero", "peer-auth", true, 0, 5_000, 1, 0);

    let (verdict, audit) = check(&zero_request);

    assert!(!verdict.allowed);
    assert!(audit.ratio.is_infinite());
    assert!(verdict.violations.iter().any(|violation| {
        matches!(
            violation,
            BoundViolation::RatioExceeded {
                ratio,
                max_ratio: 10.0
            } if ratio.is_infinite()
        )
    }));
}

#[test]
fn adversarial_zero_declared_items_blocks_independently_of_bytes() {
    let mut zero_items = req("r-zero-items", "peer-auth", true, 1_000, 5_000, 100, 1);
    zero_items.declared_bound.max_items = 0;

    let (verdict, audit) = check(&zero_items);

    assert!(!verdict.allowed);
    assert_eq!(audit.actual_bytes, 100);
    assert_eq!(verdict.violations.len(), 1);
    assert!(verdict.violations.iter().any(|violation| {
        matches!(
            violation,
            BoundViolation::ItemsExceeded {
                actual: 1,
                limit: 0
            }
        )
    }));
}
