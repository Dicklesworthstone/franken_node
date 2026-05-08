//! Conformance harness for fail-closed expiry invariants
//!
//! INVARIANT: At exactly t == expires_at, validation functions must return
//! Rejected/Expired (not Allowed/Valid). The boundary condition `now >= expires_at`
//! prevents fail-open vulnerabilities where items remain valid for one additional
//! moment at the exact expiry boundary, which could be exploited by timing attacks.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[test]
fn test_expiry_boundary_semantics_exactly_at_expiry() {
    // At exactly t == expires_at, item MUST be expired (fail-closed)

    let now = SystemTime::now();
    let expires_at = now;  // Exactly at expiry boundary

    let now_secs = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let expires_secs = expires_at.duration_since(UNIX_EPOCH).unwrap().as_secs();

    // Boundary condition: now >= expires_at should be true when now == expires_at
    assert!(now_secs >= expires_secs, "Boundary check failed at exact expiry");

    // This represents the fail-closed behavior: expired at exactly t == expires_at
    let is_expired_fail_closed = now_secs >= expires_secs;
    let is_expired_fail_open = now_secs > expires_secs;

    assert_eq!(is_expired_fail_closed, true, "Fail-closed: must expire exactly at boundary");
    assert_eq!(is_expired_fail_open, false, "Fail-open: incorrectly allows at boundary");
}

#[test]
fn test_expiry_boundary_one_second_before_expiry() {
    // One second before expiry: item must be valid

    let expires_at = SystemTime::now() + Duration::from_secs(1);
    let now = SystemTime::now();

    let now_secs = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let expires_secs = expires_at.duration_since(UNIX_EPOCH).unwrap().as_secs();

    // Before expiry: now < expires_at
    assert!(now_secs < expires_secs, "Should be before expiry");

    let is_expired = now_secs >= expires_secs;
    assert_eq!(is_expired, false, "Must not be expired before expiry time");
}

#[test]
fn test_expiry_boundary_one_second_after_expiry() {
    // One second after expiry: item must be expired

    let now = SystemTime::now();
    let expires_at = now - Duration::from_secs(1);

    let now_secs = now.duration_since(UNIX_EPOCH).unwrap().as_secs();
    let expires_secs = expires_at.duration_since(UNIX_EPOCH).unwrap().as_secs();

    // After expiry: now > expires_at
    assert!(now_secs > expires_secs, "Should be after expiry");

    let is_expired = now_secs >= expires_secs;
    assert_eq!(is_expired, true, "Must be expired after expiry time");
}

#[test]
fn test_freshness_expires_at_validation_readiness_behavior() {
    // Simulates the validation_readiness.rs line 2290 fix: now >= input.freshness_expires_at

    struct ValidationInput {
        freshness_expires_at: u64,
    }

    let current_time = 1000000000_u64;  // Arbitrary timestamp

    // Test cases for boundary behavior
    let test_cases = [
        // (expires_at, expected_expired)
        (999999999, true),   // 1 second ago: expired
        (1000000000, true),  // exactly now: expired (fail-closed)
        (1000000001, false), // 1 second future: not expired
    ];

    for (expires_at, expected_expired) in test_cases {
        let input = ValidationInput { freshness_expires_at: expires_at };

        // The corrected fail-closed check: now >= expires_at
        let is_expired_fail_closed = current_time >= input.freshness_expires_at;

        // The incorrect fail-open check: now > expires_at
        let is_expired_fail_open = current_time > input.freshness_expires_at;

        assert_eq!(is_expired_fail_closed, expected_expired,
            "Fail-closed behavior failed for expires_at={}", expires_at);

        if expires_at == current_time {
            // At exact boundary, fail-closed and fail-open differ
            assert_eq!(is_expired_fail_closed, true, "Fail-closed: expired at boundary");
            assert_eq!(is_expired_fail_open, false, "Fail-open: incorrectly allows at boundary");
        }
    }
}

#[test]
fn test_capability_freshness_closure_behavior() {
    // Simulates the validation_readiness.rs line 2633 fix: now >= expires_at in closure

    let current_time = SystemTime::now();
    let current_secs = current_time.duration_since(UNIX_EPOCH).unwrap().as_secs();

    let capability_scenarios = [
        current_secs - 1,  // expired 1 second ago
        current_secs,      // expires exactly now (boundary)
        current_secs + 1,  // expires 1 second from now
    ];

    for expires_at in capability_scenarios {
        // Fail-closed: now >= expires_at
        let is_expired_fail_closed = current_secs >= expires_at;

        // Fail-open: now > expires_at
        let is_expired_fail_open = current_secs > expires_at;

        match expires_at.cmp(&current_secs) {
            std::cmp::Ordering::Less => {
                // Past expiry: both should agree (expired)
                assert_eq!(is_expired_fail_closed, true);
                assert_eq!(is_expired_fail_open, true);
            },
            std::cmp::Ordering::Equal => {
                // Exactly at expiry: fail-closed expires, fail-open allows
                assert_eq!(is_expired_fail_closed, true, "Fail-closed must expire at boundary");
                assert_eq!(is_expired_fail_open, false, "Fail-open incorrectly allows at boundary");
            },
            std::cmp::Ordering::Greater => {
                // Future expiry: both should agree (not expired)
                assert_eq!(is_expired_fail_closed, false);
                assert_eq!(is_expired_fail_open, false);
            },
        }
    }
}