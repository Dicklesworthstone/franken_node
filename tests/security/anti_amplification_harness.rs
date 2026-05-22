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

fn fuzz_word(state: &mut u64) -> u64 {
    *state = state
        .wrapping_mul(6_364_136_223_846_793_005)
        .wrapping_add(1_442_695_040_888_963_407);
    *state
}

fn fuzz_u64(state: &mut u64, cap: u64) -> u64 {
    match fuzz_word(state) % 12 {
        0 => 0,
        1 => 1,
        2 => cap,
        3 => cap.saturating_sub(1),
        4 => cap.saturating_add(1),
        5 => u64::MAX,
        6 => u64::MAX - 1,
        7 => 10_000,
        _ => fuzz_word(state) % cap.saturating_add(1).max(1),
    }
}

fn fuzz_u32(state: &mut u64, cap: u32) -> u32 {
    match fuzz_word(state) % 8 {
        0 => 0,
        1 => 1,
        2 => cap,
        3 => cap.saturating_sub(1),
        4 => cap.saturating_add(1),
        5 => u32::MAX,
        _ => {
            let value = fuzz_word(state) % u64::from(cap.saturating_add(1).max(1));
            u32::try_from(value).expect("fuzz value is bounded by u32 cap")
        }
    }
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

#[test]
fn fuzz_generated_bounds_never_allow_limit_escape() {
    for seed in 0..512u64 {
        let mut state = seed ^ 0xA17A_D7E5_CAFE_BABE;
        let unauth_cap = fuzz_u64(&mut state, 2_048).max(1);
        let auth_cap = unauth_cap.saturating_add(fuzz_u64(&mut state, 65_536).max(1));
        let item_cap = fuzz_u32(&mut state, 128).max(1);
        let policy = AmplificationPolicy {
            max_response_ratio: match fuzz_word(&mut state) % 5 {
                0 => f64::MIN_POSITIVE,
                1 => 1.0,
                2 => 2.5,
                3 => 10.0,
                _ => 256.0,
            },
            unauth_max_bytes: unauth_cap,
            auth_max_bytes: auth_cap,
            max_items_per_response: item_cap,
        };
        let authenticated = (fuzz_word(&mut state) & 1) == 0;
        let declared_bytes = fuzz_u64(&mut state, auth_cap);
        let declared_items = fuzz_u32(&mut state, item_cap);
        let enforced = declared_bytes.min(if authenticated {
            policy.auth_max_bytes
        } else {
            policy.unauth_max_bytes
        });
        let request = BoundCheckRequest {
            request_id: format!("fuzz-{seed}"),
            peer_id: format!("peer-{}", seed % 17),
            authenticated,
            request_bytes: fuzz_u64(&mut state, 4_096),
            declared_bound: ResponseBound {
                max_bytes: declared_bytes,
                max_items: declared_items,
            },
            actual_response_bytes: fuzz_u64(&mut state, enforced.saturating_add(1)),
            actual_items: fuzz_u32(&mut state, declared_items.saturating_add(1)),
        };

        let (verdict, audit) = check_response_bound(&request, &policy, "trace-fuzz", "ts-fuzz")
            .expect("generated policy must be valid");

        assert_eq!(verdict.enforced_limit, enforced, "seed={seed}");
        assert_eq!(audit.enforced_limit, enforced, "seed={seed}");
        assert_eq!(
            verdict.allowed,
            verdict.violations.is_empty(),
            "seed={seed}"
        );
        assert_eq!(
            audit.verdict,
            if verdict.allowed { "ALLOW" } else { "BLOCK" },
            "seed={seed}"
        );

        if verdict.allowed {
            assert!(
                request.actual_response_bytes <= enforced,
                "seed={seed}: allowed response escaped enforced byte limit"
            );
            assert!(
                request.actual_items <= request.declared_bound.max_items.min(item_cap),
                "seed={seed}: allowed response escaped item limit"
            );
            if !request.authenticated {
                assert!(
                    request.actual_response_bytes <= policy.unauth_max_bytes,
                    "seed={seed}: unauthenticated response escaped unauth cap"
                );
            }
            assert!(
                audit.ratio <= policy.max_response_ratio,
                "seed={seed}: allowed response escaped ratio policy"
            );
        }

        for violation in &verdict.violations {
            match violation {
                BoundViolation::ResponseTooLarge { actual, limit } => {
                    assert_eq!(*actual, request.actual_response_bytes, "seed={seed}");
                    assert_eq!(*limit, enforced, "seed={seed}");
                    assert!(request.actual_response_bytes > enforced, "seed={seed}");
                }
                BoundViolation::RatioExceeded { ratio, max_ratio } => {
                    assert_eq!(*max_ratio, policy.max_response_ratio, "seed={seed}");
                    assert!(*ratio > *max_ratio, "seed={seed}");
                }
                BoundViolation::UnauthLimit { actual, limit } => {
                    assert!(!request.authenticated, "seed={seed}");
                    assert_eq!(*actual, request.actual_response_bytes, "seed={seed}");
                    assert_eq!(*limit, policy.unauth_max_bytes, "seed={seed}");
                    assert!(
                        request.actual_response_bytes > policy.unauth_max_bytes,
                        "seed={seed}"
                    );
                }
                BoundViolation::ItemsExceeded { actual, limit } => {
                    assert_eq!(*actual, request.actual_items, "seed={seed}");
                    assert_eq!(
                        *limit,
                        request.declared_bound.max_items.min(item_cap),
                        "seed={seed}"
                    );
                    assert!(
                        request.actual_items > request.declared_bound.max_items.min(item_cap),
                        "seed={seed}"
                    );
                }
            }
        }
    }
}
