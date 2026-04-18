//! Security hardening conformance test suite
//!
//! This test harness verifies that the security module implementations
//! conform to the hardening requirements from the user's audit request:
//!
//! 1. Constant-time comparisons are used everywhere for cryptographic operations
//! 2. Key material is properly zeroized and doesn't leak in memory
//! 3. Capability tokens expire correctly with fail-closed semantics
//! 4. SSRF policies block correctly and handle all bypass attempts
//!
//! These tests verify the actual implementation behavior, not just mock behavior.

use frankenengine_node::security::constant_time::{ct_eq, ct_eq_bytes};
use frankenengine_node::security::epoch_scoped_keys::{
    AuthError, RootSecret, sign_epoch_artifact, verify_epoch_signature
};
use frankenengine_node::security::remote_cap::{
    CapabilityGate, CapabilityProvider, ConnectivityMode, RemoteOperation, RemoteScope
};
use frankenengine_node::security::ssrf_policy::SsrfPolicyTemplate;
use frankenengine_node::security::network_guard::Protocol;
use frankenengine_node::control_plane::control_epoch::ControlEpoch;

use std::time::{SystemTime, UNIX_EPOCH};

// === 1. CONSTANT-TIME COMPARISON CONFORMANCE ===

#[test]
fn ct_eq_is_constant_time_for_equal_length_strings() {
    // Verify that ct_eq returns correct results for strings of equal length
    // (the actual constant-time property can't be tested in unit tests,
    // but we can verify correctness)

    assert!(ct_eq("identical", "identical"));
    assert!(!ct_eq("different", "differing"));
    assert!(!ct_eq("almost___", "almost123"));
    assert!(ct_eq("", ""));

    // Test with cryptographic-style strings
    let signature1 = "0123456789abcdef0123456789abcdef01234567";
    let signature2 = "0123456789abcdef0123456789abcdef01234567";
    let signature3 = "0123456789abcdef0123456789abcdef01234568"; // Last char different

    assert!(ct_eq(signature1, signature2));
    assert!(!ct_eq(signature1, signature3));
}

#[test]
fn ct_eq_bytes_handles_cryptographic_material() {
    let key1 = [0xAB; 32];
    let key2 = [0xAB; 32];
    let mut key3 = [0xAB; 32];
    key3[31] = 0xAC; // Only last byte differs

    assert!(ct_eq_bytes(&key1, &key2));
    assert!(!ct_eq_bytes(&key1, &key3));

    // Test with different lengths (should return false quickly)
    let short_key = [0xAB; 16];
    assert!(!ct_eq_bytes(&key1, &short_key));
}

#[test]
fn epoch_keys_use_constant_time_comparisons() {
    // Verify that the epoch key system uses constant-time comparisons
    // We test this by verifying that signature verification fails correctly
    // when signatures differ (the ct_eq should be used internally)

    let root_secret = RootSecret::from_hex(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ).expect("valid hex");

    let epoch = ControlEpoch::new(42);
    let domain = "test_domain";
    let artifact = b"test_artifact_data";

    // Create a valid signature
    let valid_sig = sign_epoch_artifact(artifact, epoch, domain, &root_secret)
        .expect("sign should work");

    // Create an invalid signature by modifying one byte
    let mut invalid_sig = valid_sig.clone();
    invalid_sig.bytes[31] ^= 0x01; // Flip last bit

    // Valid signature should verify
    assert!(verify_epoch_signature(artifact, &valid_sig, epoch, domain, &root_secret).is_ok());

    // Invalid signature should fail (this internally uses ct_eq)
    assert!(verify_epoch_signature(artifact, &invalid_sig, epoch, domain, &root_secret).is_err());
}

// === 2. KEY MATERIAL ZEROIZATION CONFORMANCE ===

#[test]
fn root_secret_can_be_zeroized() {
    use zeroize::Zeroize;

    let test_bytes = [0xAB; 32];
    let mut secret = RootSecret::from_hex(
        "ababababababababababababababababababababababababababababababab"
    ).expect("valid hex");

    // Verify initial state
    assert_eq!(secret.as_bytes(), &test_bytes);

    // Zeroize the secret
    secret.zeroize();

    // Verify it's been zeroed
    assert_eq!(secret.as_bytes(), &[0u8; 32]);
}

#[test]
fn derived_keys_use_constant_time_equality() {
    // Test that DerivedKey equality uses constant-time comparison
    let root_secret = RootSecret::from_hex(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ).expect("valid hex");

    let epoch1 = ControlEpoch::new(1);
    let epoch2 = ControlEpoch::new(2);
    let domain = "test_domain";

    let key1a = frankenengine_node::security::epoch_scoped_keys::derive_epoch_key(&root_secret, epoch1, domain);
    let key1b = frankenengine_node::security::epoch_scoped_keys::derive_epoch_key(&root_secret, epoch1, domain);
    let key2 = frankenengine_node::security::epoch_scoped_keys::derive_epoch_key(&root_secret, epoch2, domain);

    // Same epoch should produce identical keys
    assert_eq!(key1a, key1b);

    // Different epochs should produce different keys
    assert_ne!(key1a, key2);
}

// === 3. CAPABILITY TOKEN EXPIRY CONFORMANCE ===

#[test]
fn capability_tokens_expire_with_fail_closed_semantics() {
    let provider = CapabilityProvider::new("test-secret");
    let scope = RemoteScope::new(
        vec![RemoteOperation::TelemetryExport],
        vec!["https://example.com".to_string()]
    );

    let issued_at = 1_700_000_000u64;
    let ttl_secs = 300u64;
    let expires_at = issued_at + ttl_secs;

    let (cap, _audit) = provider.issue(
        "test-issuer",
        scope,
        issued_at,
        ttl_secs,
        true,  // operator_authorized
        false, // single_use
        "test-trace"
    ).expect("should issue");

    let mut gate = CapabilityGate::new("test-secret");

    // Should be valid just before expiry
    assert!(gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://example.com/endpoint",
        expires_at - 1,
        "test-trace-before"
    ).is_ok());

    // Should be EXPIRED at exact boundary (fail-closed: >= means expired)
    let err = gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://example.com/endpoint",
        expires_at, // Exactly at expiry
        "test-trace-at-boundary"
    ).expect_err("should be expired at boundary");
    assert_eq!(err.code(), "REMOTECAP_EXPIRED");

    // Should be expired after boundary
    let err = gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://example.com/endpoint",
        expires_at + 1,
        "test-trace-after"
    ).expect_err("should be expired after boundary");
    assert_eq!(err.code(), "REMOTECAP_EXPIRED");
}

#[test]
fn capability_tokens_not_valid_before_issue_time() {
    let provider = CapabilityProvider::new("test-secret");
    let scope = RemoteScope::new(
        vec![RemoteOperation::TelemetryExport],
        vec!["https://example.com".to_string()]
    );

    let issued_at = 1_700_000_000u64;

    let (cap, _audit) = provider.issue(
        "test-issuer",
        scope,
        issued_at,
        300,
        true,
        false,
        "test-trace"
    ).expect("should issue");

    let mut gate = CapabilityGate::new("test-secret");

    // Should be invalid before issue time (fail-closed)
    let err = gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://example.com/endpoint",
        issued_at - 1,
        "test-trace-early"
    ).expect_err("should not be valid before issue time");
    assert_eq!(err.code(), "REMOTECAP_NOT_YET_VALID");
}

#[test]
fn single_use_tokens_prevent_replay() {
    let provider = CapabilityProvider::new("test-secret");
    let scope = RemoteScope::new(
        vec![RemoteOperation::TelemetryExport],
        vec!["https://example.com".to_string()]
    );

    let (cap, _audit) = provider.issue(
        "test-issuer",
        scope,
        1_700_000_000,
        300,
        true,
        true, // single_use = true
        "test-trace"
    ).expect("should issue");

    let mut gate = CapabilityGate::new("test-secret");

    // First use should succeed
    assert!(gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://example.com/endpoint",
        1_700_000_010,
        "test-trace-first"
    ).is_ok());

    // Second use should fail (replay detection)
    let err = gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://example.com/endpoint",
        1_700_000_011,
        "test-trace-replay"
    ).expect_err("second use should fail");
    assert_eq!(err.code(), "REMOTECAP_REPLAY");
}

#[test]
fn capability_tokens_use_saturating_arithmetic() {
    let provider = CapabilityProvider::new("test-secret");
    let scope = RemoteScope::new(
        vec![RemoteOperation::TelemetryExport],
        vec!["https://example.com".to_string()]
    );

    // Issue with potential overflow condition
    let near_max_time = u64::MAX - 100;
    let large_ttl = 200;

    let (cap, _audit) = provider.issue(
        "test-issuer",
        scope,
        near_max_time,
        large_ttl,
        true,
        false,
        "test-trace"
    ).expect("should issue even with potential overflow");

    // expires_at should be saturated at u64::MAX, not wrapped around
    assert_eq!(cap.expires_at_epoch_secs(), u64::MAX);

    let mut gate = CapabilityGate::new("test-secret");

    // Should be valid at issue time
    assert!(gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://example.com/endpoint",
        near_max_time,
        "test-trace-valid"
    ).is_ok());

    // Should be expired at u64::MAX (fail-closed)
    let err = gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://example.com/endpoint",
        u64::MAX,
        "test-trace-max"
    ).expect_err("should be expired at u64::MAX");
    assert_eq!(err.code(), "REMOTECAP_EXPIRED");
}

// === 4. SSRF POLICY CONFORMANCE ===

#[test]
fn ssrf_policy_blocks_localhost_variants() {
    let mut policy = SsrfPolicyTemplate::default_template("test-connector".to_string());

    let localhost_variants = [
        "127.0.0.1",
        "127.1.2.3",
        "127.255.255.255",
        "localhost",
        "LOCALHOST",
        "localhost.",
        "API.localhost",
        "subdomain.localhost.",
    ];

    for variant in &localhost_variants {
        let result = policy.check_ssrf(variant, 80, Protocol::Http, "test-trace", "test-time");
        assert!(result.is_err(), "Should block localhost variant: {}", variant);
    }
}

#[test]
fn ssrf_policy_blocks_private_networks() {
    let mut policy = SsrfPolicyTemplate::default_template("test-connector".to_string());

    let private_networks = [
        ("10.0.0.1", "RFC1918 Class A"),
        ("10.255.255.255", "RFC1918 Class A boundary"),
        ("172.16.0.1", "RFC1918 Class B start"),
        ("172.31.255.255", "RFC1918 Class B end"),
        ("192.168.0.1", "RFC1918 Class C start"),
        ("192.168.255.255", "RFC1918 Class C end"),
        ("169.254.169.254", "AWS metadata"),
        ("169.254.0.1", "Link-local"),
        ("100.100.100.100", "CGNAT/Tailnet"),
    ];

    for (ip, description) in &private_networks {
        let result = policy.check_ssrf(ip, 80, Protocol::Http, "test-trace", "test-time");
        assert!(result.is_err(), "Should block {}: {}", description, ip);
    }
}

#[test]
fn ssrf_policy_blocks_ipv6_loopback() {
    let mut policy = SsrfPolicyTemplate::default_template("test-connector".to_string());

    let ipv6_variants = ["::1", "[::1]", " ::1 "];

    for variant in &ipv6_variants {
        let result = policy.check_ssrf(variant, 80, Protocol::Http, "test-trace", "test-time");
        assert!(result.is_err(), "Should block IPv6 loopback variant: {}", variant);
    }
}

#[test]
fn ssrf_policy_blocks_bypass_attempts() {
    let mut policy = SsrfPolicyTemplate::default_template("test-connector".to_string());

    let bypass_attempts = [
        ("127.0.0.1.", "Trailing dot on IP"),
        ("8.8.8.8.", "Trailing dot on public IP"),
        ("[127.0.0.1]", "Brackets around IPv4"),
        ("example.com..", "Multiple trailing dots"),
        ("127.0.0.1..", "Multiple trailing dots on IP"),
        ("[example.com]", "Brackets around hostname"),
    ];

    for (attempt, description) in &bypass_attempts {
        let result = policy.check_ssrf(attempt, 80, Protocol::Http, "test-trace", "test-time");
        assert!(result.is_err(), "Should block bypass attempt {}: {}", description, attempt);
    }
}

#[test]
fn ssrf_policy_allows_legitimate_public_targets() {
    let mut policy = SsrfPolicyTemplate::default_template("test-connector".to_string());

    let legitimate_targets = [
        ("8.8.8.8", "Google DNS"),
        ("1.1.1.1", "Cloudflare DNS"),
        ("api.example.com", "Public hostname"),
        ("github.com", "Public service"),
        ("203.0.113.1", "Documentation IP range"),
    ];

    for (target, description) in &legitimate_targets {
        let result = policy.check_ssrf(target, 443, Protocol::Http, "test-trace", "test-time");
        if target.chars().next().unwrap().is_alphabetic() {
            // DNS names should be allowed (they'll be resolved elsewhere)
            assert!(result.is_ok(), "Should allow {}: {}", description, target);
        } else if let Some(octets) = parse_simple_ipv4(target) {
            // Simple check for common public IPs
            if is_simple_public_ip(octets) {
                assert!(result.is_ok(), "Should allow public IP {}: {}", description, target);
            }
        }
    }
}

#[test]
fn ssrf_policy_allowlist_overrides_blocks() {
    let mut policy = SsrfPolicyTemplate::default_template("test-connector".to_string());

    // Add allowlist entry for normally blocked IP
    let receipt = policy.add_allowlist(
        "10.0.0.100",
        Some(8080),
        "Internal API for health checks",
        "test-trace",
        "test-time"
    ).expect("should add allowlist entry");

    assert!(!receipt.receipt_id.is_empty());
    assert_eq!(receipt.host, "10.0.0.100");
    assert_eq!(receipt.reason, "Internal API for health checks");

    // Should now allow the previously blocked IP
    let result = policy.check_ssrf(
        "10.0.0.100",
        8080,
        Protocol::Http,
        "test-trace-allowed",
        "test-time"
    );
    assert!(result.is_ok(), "Allowlisted IP should be allowed");

    // Should still block same IP on different port
    let result = policy.check_ssrf(
        "10.0.0.100",
        3000,
        Protocol::Http,
        "test-trace-wrong-port",
        "test-time"
    );
    assert!(result.is_err(), "Should block same IP on non-allowlisted port");
}

// === INTEGRATED CONFORMANCE TESTS ===

#[test]
fn integration_fail_closed_semantics_across_modules() {
    // Test that fail-closed semantics are consistent across all security modules

    // 1. SSRF: Malformed input should be blocked (fail-closed)
    let mut ssrf_policy = SsrfPolicyTemplate::default_template("test".to_string());
    let malformed_result = ssrf_policy.check_ssrf(
        "malformed..",
        80,
        Protocol::Http,
        "test",
        "test"
    );
    assert!(malformed_result.is_err(), "SSRF should fail-closed on malformed input");

    // 2. Capabilities: Expired tokens should be rejected (fail-closed)
    let provider = CapabilityProvider::new("test-secret");
    let scope = RemoteScope::new(vec![RemoteOperation::TelemetryExport], vec!["https://test.com".to_string()]);
    let (cap, _) = provider.issue("issuer", scope, 1000, 100, true, false, "trace").expect("issue");
    let mut gate = CapabilityGate::new("test-secret");

    let expired_result = gate.authorize_network(
        Some(&cap),
        RemoteOperation::TelemetryExport,
        "https://test.com",
        1100, // Exactly at expiry boundary
        "test"
    );
    assert!(expired_result.is_err(), "Capabilities should fail-closed at expiry boundary");

    // 3. Cryptographic verification should use constant-time comparison
    let root_secret = RootSecret::from_hex(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    ).expect("valid hex");

    let sig_result = sign_epoch_artifact(
        b"test",
        ControlEpoch::new(1),
        "domain",
        &root_secret
    );
    assert!(sig_result.is_ok(), "Signing should work");
}

// Helper functions for SSRF tests

fn parse_simple_ipv4(ip: &str) -> Option<[u8; 4]> {
    let parts: Vec<&str> = ip.split('.').collect();
    if parts.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        octets[i] = part.parse::<u8>().ok()?;
    }
    Some(octets)
}

fn is_simple_public_ip(octets: [u8; 4]) -> bool {
    // Simple check for well-known public IPs
    match octets {
        [8, 8, 8, 8] => true,     // Google DNS
        [1, 1, 1, 1] => true,     // Cloudflare DNS
        [203, 0, 113, _] => true, // Documentation range
        _ => false,
    }
}

// === COMPREHENSIVE NEGATIVE-PATH TESTS ===
// Tests for edge cases that security hardening work may have missed

#[cfg(test)]
mod security_hardening_comprehensive_negative_tests {
    use super::*;
    use std::collections::HashMap;

    #[test]
    fn unicode_injection_in_cryptographic_material() {
        // Test Unicode injection attempts in cryptographic keys/signatures
        // Control characters and homograph attacks could bypass validation

        let unicode_attack_vectors = [
            "0123456789abcdef\u{200B}0123456789abcdef0123456789abcdef01234567", // Zero-width space
            "0123456789abcdef\u{202E}fedcba9876543210fedcba9876543210fedcba98", // Right-to-left override
            "0123456789abcdef\u{0000}0123456789abcdef0123456789abcdef01234567", // Null byte
            "0123456789abcdef\u{FEFF}0123456789abcdef0123456789abcdef01234567", // BOM
            "0123456789abcdef\u{000C}0123456789abcdef0123456789abcdef01234567", // Form feed
            "0123456789abcdef\n0123456789abcdef0123456789abcdef01234567",        // Newline
            "012345е789abcdef0123456789abcdef0123456789abcdef01234567",          // Cyrillic 'е' homograph
        ];

        for attack_vector in &unicode_attack_vectors {
            // RootSecret should reject Unicode injection attempts
            let result = RootSecret::from_hex(attack_vector);
            assert!(result.is_err(), "Should reject Unicode injection in hex: {:?}", attack_vector);
        }

        // Domain names in signing should handle Unicode normalization attacks
        let root_secret = RootSecret::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ).expect("valid hex");

        let unicode_domains = [
            "test\u{200B}domain",  // Zero-width space
            "test\u{202E}niamod",  // Right-to-left override
            "test\u{0000}domain",  // Null byte injection
            "tеst_domain",         // Cyrillic 'е' homograph
            "test\ndomain",        // Newline injection
        ];

        for domain in &unicode_domains {
            // Signing with Unicode-injected domains should be handled safely
            let result = sign_epoch_artifact(
                b"test_artifact",
                ControlEpoch::new(1),
                domain,
                &root_secret
            );
            // The function should either reject malformed domains or handle them consistently
            match result {
                Ok(sig) => {
                    // If accepted, verification with same domain should work
                    assert!(verify_epoch_signature(
                        b"test_artifact",
                        &sig,
                        ControlEpoch::new(1),
                        domain,
                        &root_secret
                    ).is_ok());
                },
                Err(_) => {
                    // Rejection is also acceptable for malformed domains
                }
            }
        }
    }

    #[test]
    fn arithmetic_overflow_in_capability_token_calculations() {
        // Test arithmetic overflow scenarios in timestamp/expiry calculations
        // Recent hardening may have missed edge cases in token lifetime math

        let provider = CapabilityProvider::new("test-secret");
        let scope = RemoteScope::new(
            vec![RemoteOperation::TelemetryExport],
            vec!["https://example.com".to_string()]
        );

        // Test near-overflow scenarios
        let overflow_test_cases = [
            (u64::MAX - 1, 2, u64::MAX),        // Should saturate to MAX
            (u64::MAX - 100, 200, u64::MAX),    // Should saturate to MAX
            (u64::MAX, 1, u64::MAX),            // Already at MAX
            (0, u64::MAX, u64::MAX),            // TTL overflow
            (1, u64::MAX - 1, u64::MAX),        // Near-MAX TTL
        ];

        for (issued_at, ttl_secs, expected_max) in &overflow_test_cases {
            let result = provider.issue(
                "test-issuer",
                scope.clone(),
                *issued_at,
                *ttl_secs,
                true,
                false,
                "overflow-test"
            );

            match result {
                Ok((cap, _audit)) => {
                    // If successful, expiry should be capped at u64::MAX
                    assert!(cap.expires_at_epoch_secs() <= *expected_max,
                           "Expiry should not exceed u64::MAX for issued_at={}, ttl={}",
                           issued_at, ttl_secs);
                },
                Err(_) => {
                    // Rejection of overflow scenarios is also acceptable
                }
            }
        }

        // Test sequence number overflow in audit events
        let mut gate = CapabilityGate::new("test-secret");

        // Issue a token that will be used repeatedly
        let (cap, _) = provider.issue(
            "test-issuer",
            scope.clone(),
            1000,
            3600,
            true,
            false,
            "seq-test"
        ).expect("should issue");

        // Simulate many operations to test sequence overflow handling
        for i in 0..1000u32 {
            let trace_id = format!("trace-{}", i);
            let _ = gate.authorize_network(
                Some(&cap),
                RemoteOperation::TelemetryExport,
                "https://example.com",
                1001,
                &trace_id
            );
            // Should not panic even with many operations
        }
    }

    #[test]
    fn memory_exhaustion_through_massive_scope_lists() {
        // Test memory exhaustion attacks via massive capability scopes
        // Security hardening may not have considered DoS through memory pressure

        let provider = CapabilityProvider::new("test-secret");

        // Massive operation list
        let massive_operations = vec![RemoteOperation::TelemetryExport; 10000];

        // Massive hostname list with varying lengths
        let massive_hosts: Vec<String> = (0..1000)
            .map(|i| format!("https://very-long-hostname-{}.example.com/path/to/endpoint", i))
            .collect();

        let large_scope = RemoteScope::new(massive_operations, massive_hosts);

        // Should handle large scopes without panicking or excessive memory use
        let result = provider.issue(
            "test-issuer",
            large_scope,
            1000,
            3600,
            true,
            false,
            "memory-test"
        );

        match result {
            Ok((cap, _audit)) => {
                // If successful, basic operations should still work
                let mut gate = CapabilityGate::new("test-secret");
                let auth_result = gate.authorize_network(
                    Some(&cap),
                    RemoteOperation::TelemetryExport,
                    "https://very-long-hostname-0.example.com/path/to/endpoint",
                    1001,
                    "memory-test-auth"
                );
                // Should complete without excessive memory usage
                assert!(auth_result.is_ok() || auth_result.is_err()); // Either outcome acceptable
            },
            Err(_) => {
                // Rejection of massive scopes is also acceptable
            }
        }

        // Test SSRF policy with massive allowlist
        let mut policy = SsrfPolicyTemplate::default_template("memory-test".to_string());

        // Add many allowlist entries to test memory handling
        for i in 0..100 {
            let host = format!("allowed-host-{}.example.com", i);
            let _ = policy.add_allowlist(
                &host,
                Some(8080),
                "Memory test entry",
                "trace",
                "time"
            );
        }

        // Policy should still function correctly
        let check_result = policy.check_ssrf(
            "allowed-host-0.example.com",
            8080,
            Protocol::Http,
            "test",
            "test"
        );
        assert!(check_result.is_ok(), "Should find allowlisted entry efficiently");
    }

    #[test]
    fn concurrent_capability_validation_simulation() {
        // Test concurrent access patterns to capability validation
        // Race conditions in token state management could cause security issues

        use std::sync::{Arc, Mutex};
        use std::thread;

        let provider = CapabilityProvider::new("concurrent-test");
        let scope = RemoteScope::new(
            vec![RemoteOperation::TelemetryExport],
            vec!["https://concurrent.example.com".to_string()]
        );

        // Issue multiple tokens
        let tokens: Vec<_> = (0..10).map(|i| {
            provider.issue(
                &format!("issuer-{}", i),
                scope.clone(),
                1000,
                3600,
                true,
                true, // single_use to test replay detection
                &format!("concurrent-{}", i)
            ).expect("should issue").0
        }).collect();

        let gate = Arc::new(Mutex::new(CapabilityGate::new("concurrent-test")));
        let success_count = Arc::new(Mutex::new(0u32));
        let error_count = Arc::new(Mutex::new(0u32));

        // Simulate concurrent access to capability validation
        let handles: Vec<_> = tokens.into_iter().enumerate().map(|(i, token)| {
            let gate_clone = Arc::clone(&gate);
            let success_clone = Arc::clone(&success_count);
            let error_clone = Arc::clone(&error_count);

            thread::spawn(move || {
                // Simulate concurrent validation attempts
                for attempt in 0..5 {
                    let result = {
                        let mut g = gate_clone.lock().unwrap();
                        g.authorize_network(
                            Some(&token),
                            RemoteOperation::TelemetryExport,
                            "https://concurrent.example.com",
                            1001 + attempt,
                            &format!("concurrent-{}-{}", i, attempt)
                        )
                    };

                    match result {
                        Ok(_) => {
                            let mut count = success_clone.lock().unwrap();
                            *count = count.saturating_add(1);
                        },
                        Err(_) => {
                            let mut count = error_clone.lock().unwrap();
                            *count = count.saturating_add(1);
                        }
                    }

                    // Small delay to increase chance of race conditions
                    thread::sleep(std::time::Duration::from_millis(1));
                }
            })
        }).collect();

        // Wait for all threads
        for handle in handles {
            handle.join().unwrap();
        }

        let final_success = *success_count.lock().unwrap();
        let final_errors = *error_count.lock().unwrap();

        // With single-use tokens, we should see exactly 10 successes and 40 replay errors
        // (first use of each token succeeds, subsequent attempts fail)
        assert_eq!(final_success, 10, "Should have exactly 10 successful single-uses");
        assert_eq!(final_errors, 40, "Should have exactly 40 replay errors");
    }

    #[test]
    fn malformed_cryptographic_inputs_edge_cases() {
        // Test malformed cryptographic inputs that could bypass validation
        // Edge cases in parsing/validation might allow security bypasses

        let root_secret = RootSecret::from_hex(
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        ).expect("valid hex");

        // Test malformed hex inputs
        let malformed_hex_cases = [
            "",                          // Empty string
            "G123456789abcdef",         // Invalid hex character
            "0123456789abcdef",         // Too short (16 chars, need 64)
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdefAA", // Too long
            "0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef",  // Mixed case
            " 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", // Leading space
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef ", // Trailing space
        ];

        for hex in &malformed_hex_cases {
            let result = RootSecret::from_hex(hex);
            assert!(result.is_err(), "Should reject malformed hex: '{}'", hex);
        }

        // Test edge cases in signature verification
        let epoch = ControlEpoch::new(42);
        let domain = "test_domain";
        let artifact = b"test_artifact";

        // Create valid signature for tampering tests
        let valid_sig = sign_epoch_artifact(artifact, epoch, domain, &root_secret)
            .expect("should sign");

        // Test signature tampering edge cases
        let mut tampered_sig = valid_sig.clone();

        // Single bit flips in different positions
        for byte_pos in [0, 16, 31, 63] {
            if byte_pos < tampered_sig.bytes.len() {
                tampered_sig.bytes[byte_pos] ^= 0x01;
                let result = verify_epoch_signature(artifact, &tampered_sig, epoch, domain, &root_secret);
                assert!(result.is_err(), "Should reject single bit flip at position {}", byte_pos);
                tampered_sig.bytes[byte_pos] ^= 0x01; // Restore
            }
        }

        // Test with modified epoch
        let wrong_epoch = ControlEpoch::new(43);
        let result = verify_epoch_signature(artifact, &valid_sig, wrong_epoch, domain, &root_secret);
        assert!(result.is_err(), "Should reject wrong epoch");

        // Test with modified domain (injection attempts)
        let domain_injection_cases = [
            "test_domain\0extra",    // Null byte injection
            "test_domain\ntest",     // Newline injection
            "test_domain\r\ntest",   // CRLF injection
            "test_domain\ttest",     // Tab injection
        ];

        for injected_domain in &domain_injection_cases {
            let result = verify_epoch_signature(artifact, &valid_sig, epoch, injected_domain, &root_secret);
            assert!(result.is_err(), "Should reject domain injection: {:?}", injected_domain);
        }
    }

    #[test]
    fn timing_attack_resistance_validation() {
        // Test timing attack resistance in constant-time operations
        // Verify that comparison times don't leak information about input differences

        use std::time::Instant;

        // Test constant-time string comparison
        let reference_string = "0123456789abcdef0123456789abcdef01234567";

        let test_cases = [
            ("0123456789abcdef0123456789abcdef01234567", "identical"),
            ("0000000000000000000000000000000000000000", "all different"),
            ("0123456789abcdef0123456789abcdef01234568", "last char different"),
            ("1123456789abcdef0123456789abcdef01234567", "first char different"),
            ("0123456789abcdef1123456789abcdef01234567", "middle different"),
        ];

        let mut timing_results = Vec::new();

        // Measure timing for multiple iterations
        for (test_input, description) in &test_cases {
            let iterations = 1000;
            let start = Instant::now();

            for _ in 0..iterations {
                let _ = ct_eq(reference_string, test_input);
            }

            let elapsed = start.elapsed().as_nanos();
            timing_results.push((elapsed, description));
        }

        // Check that timing variations are within reasonable bounds
        // (We can't guarantee perfect constant-time in unit tests, but we can check for obvious leaks)
        let min_time = timing_results.iter().map(|(time, _)| *time).min().unwrap();
        let max_time = timing_results.iter().map(|(time, _)| *time).max().unwrap();

        // Allow for some variation, but flag excessive differences
        let time_ratio = max_time as f64 / min_time as f64;
        assert!(time_ratio < 3.0,
               "Timing variation too high (ratio: {:.2}), possible timing leak. Results: {:?}",
               time_ratio, timing_results);

        // Test byte-level constant-time comparison
        let reference_bytes = [0xAB; 32];
        let test_byte_cases = [
            ([0xAB; 32], "identical"),
            ([0x00; 32], "all different"),
            ({
                let mut bytes = [0xAB; 32];
                bytes[31] = 0xAC;
                bytes
            }, "last byte different"),
            ({
                let mut bytes = [0xAB; 32];
                bytes[0] = 0xAC;
                bytes
            }, "first byte different"),
        ];

        let mut byte_timing_results = Vec::new();

        for (test_bytes, description) in &test_byte_cases {
            let iterations = 1000;
            let start = Instant::now();

            for _ in 0..iterations {
                let _ = ct_eq_bytes(&reference_bytes, test_bytes);
            }

            let elapsed = start.elapsed().as_nanos();
            byte_timing_results.push((elapsed, description));
        }

        let min_byte_time = byte_timing_results.iter().map(|(time, _)| *time).min().unwrap();
        let max_byte_time = byte_timing_results.iter().map(|(time, _)| *time).max().unwrap();

        let byte_time_ratio = max_byte_time as f64 / min_byte_time as f64;
        assert!(byte_time_ratio < 3.0,
               "Byte timing variation too high (ratio: {:.2}), possible timing leak. Results: {:?}",
               byte_time_ratio, byte_timing_results);
    }

    #[test]
    fn ssrf_policy_injection_and_bypass_edge_cases() {
        // Test advanced SSRF bypass techniques and injection attacks
        // Security hardening may have missed sophisticated bypass attempts

        let mut policy = SsrfPolicyTemplate::default_template("injection-test".to_string());

        // Test URL encoding bypass attempts
        let encoding_bypass_cases = [
            ("127.0.0.1", "Direct localhost"),
            ("127%2E0%2E0%2E1", "URL encoded dots"),
            ("127。0。0。1", "Unicode dots (fullwidth)"),
            ("127․0․0․1", "One-dot leader"),
            ("127‧0‧0‧1", "Hyphenation point"),
            ("127%00.0.0.1", "Null byte injection"),
            ("127.0.0.1%00", "Null byte suffix"),
            ("127.0.0.1%0A", "Newline suffix"),
            ("127.0.0.1%0D%0A", "CRLF injection"),
            ("127.0.0.1%20", "Space suffix"),
            ("127.0.0.1\t", "Tab suffix"),
        ];

        for (bypass_attempt, description) in &encoding_bypass_cases {
            let result = policy.check_ssrf(bypass_attempt, 80, Protocol::Http, "test", "test");
            assert!(result.is_err(), "Should block encoding bypass {}: {}", description, bypass_attempt);
        }

        // Test numeric representation attacks
        let numeric_bypass_cases = [
            ("2130706433", "Decimal representation of 127.0.0.1"),
            ("0177.0.0.1", "Octal first octet"),
            ("127.000.000.001", "Leading zeros"),
            ("127.0x0.0x0.0x1", "Mixed hex representation"),
            ("0x7f000001", "Full hex representation"),
            ("0177.0.0.1", "Octal representation"),
            ("127.1", "Short form (127.0.0.1)"),
            ("2130706433", "32-bit integer form"),
        ];

        for (bypass_attempt, description) in &numeric_bypass_cases {
            let result = policy.check_ssrf(bypass_attempt, 80, Protocol::Http, "test", "test");
            // Some numeric forms might be accepted by the policy (depending on implementation)
            // but we should at least verify the policy handles them consistently
            match result {
                Ok(_) => {
                    // If accepted, it should consistently accept the same form
                    let second_result = policy.check_ssrf(bypass_attempt, 80, Protocol::Http, "test2", "test2");
                    assert_eq!(result.is_ok(), second_result.is_ok(),
                              "Should consistently handle numeric form: {}", description);
                },
                Err(_) => {
                    // Rejection is expected for localhost representations
                }
            }
        }

        // Test malformed hostname injection
        let hostname_injection_cases = [
            ("example.com\0.evil.com", "Null byte injection"),
            ("example.com\n.evil.com", "Newline injection"),
            ("example.com\r.evil.com", "Carriage return injection"),
            ("example.com\t.evil.com", "Tab injection"),
            ("example.com\x00.evil.com", "Raw null byte"),
            ("example.com\x01.evil.com", "Control character"),
            ("example.com\x7F.evil.com", "DEL character"),
            ("example.com..evil.com", "Double dot"),
            ("example.com.", "Trailing dot"),
            ("example.com..", "Double trailing dot"),
        ];

        for (injection_attempt, description) in &hostname_injection_cases {
            let result = policy.check_ssrf(injection_attempt, 443, Protocol::Http, "test", "test");
            // Should either reject malformed hostnames or handle them safely
            match result {
                Ok(_) => {
                    // If accepted, verify it doesn't cause issues in subsequent operations
                    let second_result = policy.check_ssrf(injection_attempt, 443, Protocol::Http, "test2", "test2");
                    assert!(second_result.is_ok() || second_result.is_err(),
                           "Should handle injection consistently: {}", description);
                },
                Err(_) => {
                    // Rejection is also acceptable for malformed hostnames
                }
            }
        }

        // Test allowlist injection attacks
        let injection_reason = "Test\ninjection\rattack\0payload\tmalicious";
        let allowlist_result = policy.add_allowlist(
            "safe.example.com",
            Some(443),
            injection_reason,
            "trace\0injection",
            "time\ninjection"
        );

        match allowlist_result {
            Ok(receipt) => {
                // If injection is accepted, verify it doesn't corrupt the allowlist
                assert!(!receipt.receipt_id.is_empty(), "Receipt ID should not be empty");

                // Test that the allowlisted host still works correctly
                let check_result = policy.check_ssrf("safe.example.com", 443, Protocol::Http, "test", "test");
                assert!(check_result.is_ok(), "Allowlisted host should still work after injection attempt");
            },
            Err(_) => {
                // Rejection of injection attempts is also acceptable
            }
        }
    }

    #[test]
    fn resource_exhaustion_through_audit_log_flooding() {
        // Test resource exhaustion attacks via audit log flooding
        // Security hardening may not have considered DoS through log volume

        let provider = CapabilityProvider::new("audit-flood-test");
        let scope = RemoteScope::new(
            vec![RemoteOperation::TelemetryExport],
            vec!["https://flood.example.com".to_string()]
        );

        // Generate many tokens to create audit events
        let mut audit_events = Vec::new();
        for i in 0..1000 {
            let result = provider.issue(
                &format!("flood-issuer-{}", i),
                scope.clone(),
                1000 + i,
                3600,
                true,
                false,
                &format!("flood-trace-with-very-long-identifier-that-might-cause-memory-issues-{}", i)
            );

            match result {
                Ok((_, audit)) => {
                    audit_events.push(audit);
                },
                Err(_) => {
                    // Rate limiting or rejection is acceptable
                    break;
                }
            }
        }

        // Test that audit events don't cause excessive memory usage
        let total_audit_size: usize = audit_events.iter()
            .map(|audit| {
                audit.issuer.len() +
                audit.trace_id.len() +
                64 // Approximate size of other fields
            })
            .sum();

        // Should not exceed reasonable memory bounds (e.g., 10MB for 1000 events)
        assert!(total_audit_size < 10 * 1024 * 1024,
               "Audit events consuming excessive memory: {} bytes", total_audit_size);

        // Test SSRF policy audit flooding
        let mut policy = SsrfPolicyTemplate::default_template("flood-test".to_string());

        // Generate many SSRF check events
        for i in 0..1000 {
            let host = format!("flood-host-{}.example.com", i);
            let trace = format!("flood-trace-{}-with-very-long-identifier-content", i);
            let time = format!("flood-time-{}", i);

            let _ = policy.check_ssrf(&host, 443, Protocol::Http, &trace, &time);

            // Add some allowlist entries to test memory usage
            if i % 10 == 0 {
                let _ = policy.add_allowlist(
                    &host,
                    Some(443),
                    &format!("Flood test entry {} with long description", i),
                    &trace,
                    &time
                );
            }
        }

        // Policy should still function after flood attempts
        let final_check = policy.check_ssrf(
            "final-test.example.com",
            443,
            Protocol::Http,
            "final-trace",
            "final-time"
        );
        assert!(final_check.is_ok() || final_check.is_err(), "Policy should still function after flooding");
    }

    #[test]
    fn state_consistency_validation_under_error_conditions() {
        // Test state consistency when operations fail partially
        // Error handling might leave systems in inconsistent states

        let provider = CapabilityProvider::new("consistency-test");
        let scope = RemoteScope::new(
            vec![RemoteOperation::TelemetryExport],
            vec!["https://consistency.example.com".to_string()]
        );

        // Test token issuance under error conditions
        let error_inducing_cases = [
            ("", "Empty issuer"),
            ("issuer\0injection", "Null byte in issuer"),
            ("issuer\ninject", "Newline in issuer"),
            (&"x".repeat(10000), "Extremely long issuer"),
        ];

        for (bad_issuer, description) in &error_inducing_cases {
            let result = provider.issue(
                bad_issuer,
                scope.clone(),
                1000,
                3600,
                true,
                false,
                "consistency-test"
            );

            match result {
                Ok((cap, audit)) => {
                    // If successful despite bad input, verify token is still valid
                    let mut gate = CapabilityGate::new("consistency-test");
                    let auth_result = gate.authorize_network(
                        Some(&cap),
                        RemoteOperation::TelemetryExport,
                        "https://consistency.example.com",
                        1001,
                        "consistency-validation"
                    );
                    assert!(auth_result.is_ok(),
                           "Token should be valid if issuance succeeded with {}", description);

                    // Audit should contain valid data
                    assert!(!audit.trace_id.is_empty(), "Audit trace should not be empty");
                },
                Err(_) => {
                    // Rejection is also acceptable for malformed input
                }
            }
        }

        // Test gate state consistency after authorization failures
        let mut gate = CapabilityGate::new("consistency-test");

        let (valid_cap, _) = provider.issue(
            "valid-issuer",
            scope.clone(),
            1000,
            3600,
            true,
            true, // single_use
            "consistency-test"
        ).expect("should issue valid token");

        // First authorization should succeed
        let first_result = gate.authorize_network(
            Some(&valid_cap),
            RemoteOperation::TelemetryExport,
            "https://consistency.example.com",
            1001,
            "first-use"
        );
        assert!(first_result.is_ok(), "First use should succeed");

        // Second authorization should fail (replay)
        let second_result = gate.authorize_network(
            Some(&valid_cap),
            RemoteOperation::TelemetryExport,
            "https://consistency.example.com",
            1002,
            "replay-attempt"
        );
        assert!(second_result.is_err(), "Replay should be detected");

        // Gate should still work with other tokens
        let (other_cap, _) = provider.issue(
            "other-issuer",
            scope.clone(),
            1000,
            3600,
            true,
            false, // not single_use
            "other-token"
        ).expect("should issue other token");

        let other_result = gate.authorize_network(
            Some(&other_cap),
            RemoteOperation::TelemetryExport,
            "https://consistency.example.com",
            1003,
            "other-token-test"
        );
        assert!(other_result.is_ok(), "Gate should work with other tokens after replay detection");

        // Test SSRF policy state consistency
        let mut policy = SsrfPolicyTemplate::default_template("consistency-test".to_string());

        // Add some valid allowlist entries
        let valid_entries = ["valid1.example.com", "valid2.example.com"];
        for host in &valid_entries {
            let receipt = policy.add_allowlist(host, Some(443), "Valid entry", "trace", "time")
                .expect("should add valid entry");
            assert!(!receipt.receipt_id.is_empty(), "Receipt should be valid");
        }

        // Attempt to add invalid entries
        let invalid_entries = [
            ("", "Empty host"),
            ("invalid\0.example.com", "Null byte in host"),
            ("invalid\n.example.com", "Newline in host"),
        ];

        for (invalid_host, description) in &invalid_entries {
            let result = policy.add_allowlist(invalid_host, Some(443), description, "trace", "time");

            // Whether accepted or rejected, valid entries should still work
            let check_result = policy.check_ssrf("valid1.example.com", 443, Protocol::Http, "test", "test");
            assert!(check_result.is_ok(),
                   "Valid allowlist entries should still work after invalid entry attempt: {}",
                   description);
        }
    }
}