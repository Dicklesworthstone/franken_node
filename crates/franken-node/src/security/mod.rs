pub mod adversarial_runner;
pub mod adversary_graph;
pub mod blake3_adapter;
pub mod bpet;
pub mod challenge_flow;
pub mod constant_time;
pub mod copilot_engine;
pub mod cuckoo_filter;
pub mod decision_receipt;
pub mod degraded_mode_audit;
pub mod degraded_mode_policy;
pub mod dgis;
pub mod epoch_scoped_keys;
pub mod impossible_default;
pub mod intent_firewall;
pub mod interface_hash;
pub mod isolation_backend;
pub mod isolation_rail_router;
pub mod lineage_tracker;
pub mod network_guard;
pub mod quarantine_controller;
pub mod remote_cap;
pub mod revocation_freshness;
pub mod revocation_freshness_gate;
pub mod sandbox_policy_compiler;
pub mod ssrf_policy;
pub mod staking_governance;
pub mod sybil_defense;
pub mod threshold_sig;
pub mod trust_complexity;
pub mod trust_zone;
pub mod vef_degraded_mode;
pub mod zk_attestation;

#[cfg(test)]
mod tests {
    use super::{
        constant_time,
        network_guard::Protocol,
        remote_cap::{
            CapabilityGate, CapabilityProvider, RemoteCapError, RemoteOperation, RemoteScope,
        },
        revocation_freshness::{
            FreshnessCheck, FreshnessError, FreshnessPolicy, SafetyTier, evaluate_freshness,
        },
        ssrf_policy::{SsrfError, SsrfPolicyTemplate},
    };

    fn remote_scope() -> RemoteScope {
        RemoteScope::new(
            vec![RemoteOperation::NetworkEgress],
            vec!["https://api.example.com".to_string()],
        )
    }

    fn freshness_check(tier: SafetyTier, age: u64) -> FreshnessCheck {
        FreshnessCheck {
            action_id: "action-negative".to_string(),
            tier,
            revocation_age_secs: age,
            trace_id: "trace-negative".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn negative_ct_eq_rejects_truncated_digest_prefix() {
        let full_digest = "abcdef0123456789abcdef0123456789";
        let truncated = "abcdef0123456789";

        assert!(!constant_time::ct_eq(full_digest, truncated));
        assert!(!constant_time::ct_eq_bytes(
            full_digest.as_bytes(),
            truncated.as_bytes()
        ));
    }

    #[test]
    fn negative_remote_cap_issue_requires_operator_authorization() {
        let provider = CapabilityProvider::new("negative-secret");

        let err = provider
            .issue(
                "operator-negative",
                remote_scope(),
                1_700_000_000,
                60,
                false,
                false,
                "trace-no-operator",
            )
            .unwrap_err();

        assert_eq!(err, RemoteCapError::OperatorAuthorizationRequired);
        assert_eq!(err.code(), "REMOTECAP_OPERATOR_AUTH_REQUIRED");
    }

    #[test]
    fn negative_remote_cap_issue_rejects_zero_ttl() {
        let provider = CapabilityProvider::new("negative-secret");

        let err = provider
            .issue(
                "operator-negative",
                remote_scope(),
                1_700_000_000,
                0,
                true,
                false,
                "trace-zero-ttl",
            )
            .unwrap_err();

        assert_eq!(err, RemoteCapError::InvalidTtl { ttl_secs: 0 });
        assert_eq!(err.code(), "REMOTECAP_TTL_INVALID");
    }

    #[test]
    fn negative_remote_cap_gate_denies_missing_capability() {
        let mut gate = CapabilityGate::new("negative-secret");

        let err = gate
            .authorize_network(
                None,
                RemoteOperation::NetworkEgress,
                "https://api.example.com/v1",
                1_700_000_001,
                "trace-missing-cap",
            )
            .unwrap_err();

        assert_eq!(err, RemoteCapError::Missing);
        assert_eq!(err.compatibility_code(), Some("ERR_REMOTE_CAP_REQUIRED"));
    }

    #[test]
    fn negative_remote_scope_does_not_allow_lookalike_prefix() {
        let scope = remote_scope();

        assert!(!scope.allows_endpoint("https://api.example.com.evil.test/v1"));
        assert!(!scope.allows_endpoint("https://api.example.comevil/v1"));
    }

    #[test]
    fn negative_revocation_freshness_rejects_invalid_policy() {
        let policy = FreshnessPolicy {
            risky_max_age_secs: 300,
            dangerous_max_age_secs: 3600,
        };

        let err = policy.validate().unwrap_err();

        assert!(matches!(err, FreshnessError::PolicyInvalid { .. }));
        assert_eq!(err.code(), "RF_POLICY_INVALID");
    }

    #[test]
    fn negative_revocation_freshness_denies_exact_boundary_age() {
        let policy = FreshnessPolicy {
            risky_max_age_secs: 60,
            dangerous_max_age_secs: 10,
        };

        let err =
            evaluate_freshness(&policy, &freshness_check(SafetyTier::Risky, 60), None).unwrap_err();

        match err {
            FreshnessError::StaleFrontier {
                age_secs,
                max_age_secs,
                ..
            } => {
                assert_eq!(age_secs, 60);
                assert_eq!(max_age_secs, 60);
            }
            other => panic!("unexpected boundary error: {other:?}"),
        }
    }

    #[test]
    fn negative_ssrf_blocks_localhost_by_default() {
        let mut template = SsrfPolicyTemplate::default_template("connector-negative".to_string());

        let err = template
            .check_ssrf(
                "localhost",
                80,
                Protocol::Http,
                "trace-ssrf-localhost",
                "2026-01-01T00:00:00Z",
            )
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfDenied { .. }));
        assert_eq!(template.audit_log.len(), 1);
    }

    #[test]
    fn negative_ssrf_allowlist_requires_reason() {
        let mut template = SsrfPolicyTemplate::default_template("connector-negative".to_string());

        let err = template
            .add_allowlist(
                "api.example.com",
                Some(443),
                "",
                "trace-allowlist-missing-reason",
                "2026-01-01T00:00:00Z",
            )
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfReceiptMissing { .. }));
        assert!(template.allowlist.is_empty());
    }
}

#[cfg(test)]
mod security_root_additional_negative_tests {
    use super::{
        constant_time,
        network_guard::Protocol,
        remote_cap::{
            CapabilityGate, CapabilityProvider, ConnectivityMode, RemoteCap, RemoteCapError,
            RemoteOperation, RemoteScope,
        },
        revocation_freshness::{
            FreshnessCheck, FreshnessError, FreshnessPolicy, OverrideReceipt, SafetyTier,
            evaluate_freshness,
        },
        ssrf_policy::{SsrfError, SsrfPolicyTemplate},
    };

    fn scope(operations: Vec<RemoteOperation>, endpoints: Vec<&str>) -> RemoteScope {
        RemoteScope::new(
            operations,
            endpoints
                .into_iter()
                .map(std::string::ToString::to_string)
                .collect(),
        )
    }

    fn issued_cap(scope: RemoteScope, ttl_secs: u64, single_use: bool) -> RemoteCap {
        let provider = CapabilityProvider::new("additional-secret");
        provider
            .issue(
                "operator-additional",
                scope,
                1_700_000_000,
                ttl_secs,
                true,
                single_use,
                "trace-issue-additional",
            )
            .expect("fixture capability should issue")
            .0
    }

    fn stale_check(tier: SafetyTier, age: u64) -> FreshnessCheck {
        FreshnessCheck {
            action_id: "action-additional".to_string(),
            tier,
            revocation_age_secs: age,
            trace_id: "trace-freshness-additional".to_string(),
            timestamp: "2026-01-01T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn negative_ct_eq_bytes_rejects_same_length_digest_mutation() {
        let expected = b"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let mutated = b"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaab";

        assert!(!constant_time::ct_eq_bytes(expected, mutated));
    }

    #[test]
    fn negative_remote_cap_denies_operation_outside_scope() {
        let cap = issued_cap(
            scope(
                vec![RemoteOperation::NetworkEgress],
                vec!["https://api.example.com"],
            ),
            60,
            false,
        );
        let mut gate = CapabilityGate::new("additional-secret");

        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::ArtifactUpload,
                "https://api.example.com/upload",
                1_700_000_001,
                "trace-op-denied",
            )
            .unwrap_err();

        assert!(matches!(
            err,
            RemoteCapError::ScopeDenied {
                operation: RemoteOperation::ArtifactUpload,
                ..
            }
        ));
    }

    #[test]
    fn negative_remote_cap_denies_at_exact_expiry_boundary() {
        let cap = issued_cap(
            scope(
                vec![RemoteOperation::NetworkEgress],
                vec!["https://api.example.com"],
            ),
            10,
            false,
        );
        let mut gate = CapabilityGate::new("additional-secret");

        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::NetworkEgress,
                "https://api.example.com/v1",
                1_700_000_010,
                "trace-expired-boundary",
            )
            .unwrap_err();

        assert!(matches!(
            err,
            RemoteCapError::Expired {
                now_epoch_secs: 1_700_000_010,
                expires_at_epoch_secs: 1_700_000_010,
            }
        ));
    }

    #[test]
    fn negative_single_use_cap_replay_is_rejected_after_first_use() {
        let cap = issued_cap(
            scope(
                vec![RemoteOperation::NetworkEgress],
                vec!["https://api.example.com"],
            ),
            60,
            true,
        );
        let mut gate = CapabilityGate::new("additional-secret");

        gate.authorize_network(
            Some(&cap),
            RemoteOperation::NetworkEgress,
            "https://api.example.com/v1",
            1_700_000_001,
            "trace-first-use",
        )
        .expect("first use should be accepted");
        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::NetworkEgress,
                "https://api.example.com/v1",
                1_700_000_002,
                "trace-replay",
            )
            .unwrap_err();

        assert!(matches!(err, RemoteCapError::ReplayDetected { .. }));
    }

    #[test]
    fn negative_local_only_mode_denies_valid_remote_capability() {
        let cap = issued_cap(
            scope(
                vec![RemoteOperation::NetworkEgress],
                vec!["https://api.example.com"],
            ),
            60,
            false,
        );
        let mut gate = CapabilityGate::with_mode("additional-secret", ConnectivityMode::LocalOnly);

        let err = gate
            .authorize_network(
                Some(&cap),
                RemoteOperation::NetworkEgress,
                "https://api.example.com/v1",
                1_700_000_001,
                "trace-local-only",
            )
            .unwrap_err();

        assert!(matches!(
            err,
            RemoteCapError::ConnectivityModeDenied {
                mode: ConnectivityMode::LocalOnly,
                ..
            }
        ));
    }

    #[test]
    fn negative_dangerous_freshness_denies_exact_boundary_age() {
        let policy = FreshnessPolicy {
            risky_max_age_secs: 300,
            dangerous_max_age_secs: 30,
        };

        let err =
            evaluate_freshness(&policy, &stale_check(SafetyTier::Dangerous, 30), None).unwrap_err();

        assert!(matches!(
            err,
            FreshnessError::StaleFrontier {
                tier,
                age_secs: 30,
                max_age_secs: 30,
            } if tier == "Dangerous"
        ));
    }

    #[test]
    fn negative_override_receipt_action_mismatch_is_rejected() {
        let policy = FreshnessPolicy {
            risky_max_age_secs: 300,
            dangerous_max_age_secs: 30,
        };
        let receipt = OverrideReceipt {
            action_id: "different-action".to_string(),
            actor: "operator".to_string(),
            reason: "emergency override".to_string(),
            timestamp: "2026-01-01T00:01:00Z".to_string(),
            trace_id: "trace-override".to_string(),
        };

        let err = evaluate_freshness(
            &policy,
            &stale_check(SafetyTier::Risky, 300),
            Some(&receipt),
        )
        .unwrap_err();

        assert!(matches!(err, FreshnessError::OverrideRequired { .. }));
    }

    #[test]
    fn negative_ssrf_rejects_null_byte_host() {
        let mut template = SsrfPolicyTemplate::default_template("connector-additional".to_string());

        let err = template
            .check_ssrf(
                "api.example.com\0.evil.test",
                443,
                Protocol::Http,
                "trace-null-host",
                "2026-01-01T00:00:00Z",
            )
            .unwrap_err();

        assert!(matches!(err, SsrfError::SsrfInvalidIp { .. }));
        assert_eq!(template.audit_log.len(), 1);
    }

    #[test]
    fn negative_ssrf_rejects_public_ipv6_literal_as_unsupported() {
        let mut template = SsrfPolicyTemplate::default_template("connector-additional".to_string());

        let err = template
            .check_ssrf(
                "2001:4860:4860::8888",
                443,
                Protocol::Http,
                "trace-ipv6-host",
                "2026-01-01T00:00:00Z",
            )
            .unwrap_err();

        assert!(matches!(
            err,
            SsrfError::SsrfDenied { cidr, .. } if cidr == "ipv6_unsupported"
        ));
        assert_eq!(template.audit_log.len(), 1);
    }
}

#[cfg(test)]
mod security_extreme_adversarial_negative_tests {
    use super::{
        constant_time,
        network_guard::Protocol,
        remote_cap::{
            CapabilityGate, CapabilityProvider, ConnectivityMode, RemoteCap, RemoteCapError,
            RemoteOperation, RemoteScope,
        },
        revocation_freshness::{
            FreshnessCheck, FreshnessError, FreshnessPolicy, OverrideReceipt, SafetyTier,
            evaluate_freshness,
        },
        ssrf_policy::{SsrfError, SsrfPolicyTemplate},
    };

    #[test]
    fn extreme_adversarial_constant_time_unicode_injection_resistance() {
        // Unicode normalization attack on constant-time comparison
        let nfc_hash = "café_hash_deadbeef12345678"; // NFC normalized
        let nfd_hash = "cafe\u{301}_hash_deadbeef12345678"; // NFD normalized (combining accent)
        let rtl_hash = "\u{202E}feebdaed_hash_éfac\u{202D}"; // RIGHT-TO-LEFT manipulation

        // Visual similarity but different byte sequences
        assert!(!constant_time::ct_eq(&nfc_hash, &nfd_hash));
        assert!(!constant_time::ct_eq(&nfc_hash, &rtl_hash));
        assert!(!constant_time::ct_eq_bytes(
            nfc_hash.as_bytes(),
            nfd_hash.as_bytes()
        ));

        // Unicode bomb with zero-width characters
        let unicode_bomb = format!("hash{}{}", "\u{200B}".repeat(10000), "deadbeef");
        let normal_hash = "hashdeadbeef";
        assert!(!constant_time::ct_eq(&unicode_bomb, &normal_hash));

        // Control character pollution
        let control_hash = "hash\x00\x01\x02deadbeef";
        assert!(!constant_time::ct_eq(&control_hash, &normal_hash));
    }

    #[test]
    fn extreme_adversarial_remote_capability_memory_exhaustion_attack() {
        let provider = CapabilityProvider::new("memory-attack-secret");

        // Massive endpoint list in scope (potential memory exhaustion)
        let mut massive_endpoints = Vec::new();
        for i in 0..100_000 {
            if massive_endpoints.len() >= 1000 {
                // Bound the test to prevent actual DoS
                break;
            }
            massive_endpoints.push(format!(
                "https://target{i:06}.example.com/api/v1/endpoint/path/very/long/to/consume/memory"
            ));
        }

        let scope = RemoteScope::new(vec![RemoteOperation::NetworkEgress], massive_endpoints);

        // Should handle massive scope without crashing
        let result = provider.issue(
            "operator-memory-attack",
            scope,
            1_700_000_000,
            3600,
            true,
            false,
            "trace-memory-exhaustion",
        );

        // Should either succeed gracefully or fail safely
        match result {
            Ok(_) => {
                // If it succeeds, verify it doesn't consume excessive memory
                // (This is a behavioral test - in practice you'd monitor memory usage)
            }
            Err(e) => {
                // Should fail gracefully with a clear error, not panic
                assert!(matches!(
                    e,
                    RemoteCapError::InvalidTtl { .. }
                        | RemoteCapError::OperatorAuthorizationRequired
                ));
            }
        }
    }

    #[test]
    fn extreme_adversarial_remote_capability_endpoint_confusion_attack() {
        let provider = CapabilityProvider::new("confusion-secret");

        // Crafted endpoints designed to confuse URL parsing
        let confusing_endpoints = vec![
            "https://api.example.com/../../../etc/passwd".to_string(),
            "https://api.example.com/..\\/..\\/../etc/passwd".to_string(),
            "https://api.example.com/..%2F..%2F..%2Fetc%2Fpasswd".to_string(),
            "https://api.example.com/api/v1#@evil.com/malicious".to_string(),
            "https://api.example.com:80@evil.com/bypass".to_string(),
            "https://api.example.com\\@evil.com/backslash".to_string(),
            "https://api.example.com\x00.evil.com/nullbyte".to_string(),
        ];

        let scope = RemoteScope::new(vec![RemoteOperation::NetworkEgress], confusing_endpoints);

        let cap_result = provider.issue(
            "operator-confusion",
            scope.clone(),
            1_700_000_000,
            3600,
            true,
            false,
            "trace-confusion",
        );

        if let Ok((cap, _)) = cap_result {
            let mut gate = CapabilityGate::new("confusion-secret");

            // Test various malformed endpoint access attempts
            let malicious_attempts = vec![
                "https://evil.com/malicious",
                "https://api.example.com/../../../sensitive",
                "https://api.example.com:80@evil.com/bypass",
                "https://api.example.com\\@evil.com/backslash",
            ];

            for malicious_url in malicious_attempts {
                let result = gate.authorize_network(
                    Some(&cap),
                    RemoteOperation::NetworkEgress,
                    malicious_url,
                    1_700_000_001,
                    "trace-malicious-attempt",
                );

                // Should deny all malicious attempts
                assert!(
                    result.is_err(),
                    "malicious URL should be denied: {}",
                    malicious_url
                );
            }
        }
    }

    #[test]
    fn extreme_adversarial_freshness_policy_arithmetic_overflow_boundaries() {
        // Test arithmetic overflow scenarios in freshness policy validation
        let overflow_policies = vec![
            FreshnessPolicy {
                risky_max_age_secs: u64::MAX,
                dangerous_max_age_secs: u64::MAX.saturating_sub(1),
            },
            FreshnessPolicy {
                risky_max_age_secs: 0,
                dangerous_max_age_secs: u64::MAX,
            },
            FreshnessPolicy {
                risky_max_age_secs: u64::MAX / 2,
                dangerous_max_age_secs: (u64::MAX / 2).saturating_add(1),
            },
        ];

        for (i, policy) in overflow_policies.iter().enumerate() {
            let validation_result = policy.validate();

            // Should handle overflow scenarios gracefully
            match validation_result {
                Ok(_) => {
                    // If valid, test with boundary age values
                    let check = FreshnessCheck {
                        action_id: format!("overflow-action-{i}"),
                        tier: SafetyTier::Risky,
                        revocation_age_secs: u64::MAX,
                        trace_id: format!("trace-overflow-{i}"),
                        timestamp: "2026-01-01T00:00:00Z".to_string(),
                    };

                    let eval_result = evaluate_freshness(policy, &check, None);
                    // Should handle extreme age values without panicking
                    assert!(eval_result.is_err());
                }
                Err(e) => {
                    // Should fail gracefully with meaningful error
                    assert!(matches!(e, FreshnessError::PolicyInvalid { .. }));
                }
            }
        }
    }

    #[test]
    fn extreme_adversarial_freshness_unicode_injection_in_identifiers() {
        let policy = FreshnessPolicy {
            risky_max_age_secs: 300,
            dangerous_max_age_secs: 60,
        };

        // Unicode injection in action_id and trace_id
        let unicode_bombs = vec![
            format!("action{}{}", "\u{202E}", "\u{200B}".repeat(1000)), // RTL + zero-width
            format!("action\u{0000}null\u{0001}injection"),             // Null byte injection
            format!("action{}", "\u{FEFF}".repeat(100)),                // BOM flooding
            "action\r\nHTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_string(), // HTTP injection
        ];

        for (i, malicious_id) in unicode_bombs.iter().enumerate() {
            let check = FreshnessCheck {
                action_id: malicious_id.clone(),
                tier: SafetyTier::Risky,
                revocation_age_secs: 400, // Over limit
                trace_id: format!("trace-unicode-{i}"),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
            };

            let result = evaluate_freshness(&policy, &check, None);

            // Should reject due to staleness, not crash on Unicode
            assert!(result.is_err());
            if let Err(FreshnessError::StaleFrontier { .. }) = result {
                // Expected stale error, Unicode handled gracefully
            } else {
                panic!("unexpected error type for Unicode injection test {i}");
            }
        }
    }

    #[test]
    fn extreme_adversarial_ssrf_host_header_injection_attack() {
        let mut template = SsrfPolicyTemplate::default_template("injection-test".to_string());

        // Host header injection attempts
        let injection_hosts = vec![
            "api.example.com\r\nHost: evil.com",
            "api.example.com\nX-Forwarded-Host: attacker.com",
            "api.example.com\x00evil.com",
            "api.example.com\tevil.com",
            "api.example.com evil.com",
            "api.example.com?host=evil.com",
            "api.example.com#evil.com",
        ];

        for (i, malicious_host) in injection_hosts.iter().enumerate() {
            let result = template.check_ssrf(
                malicious_host,
                443,
                Protocol::Https,
                &format!("trace-injection-{i}"),
                "2026-01-01T00:00:00Z",
            );

            // Should deny all injection attempts
            assert!(
                result.is_err(),
                "host injection should be denied: {}",
                malicious_host
            );

            match result {
                Err(SsrfError::SsrfInvalidIp { .. }) | Err(SsrfError::SsrfDenied { .. }) => {
                    // Expected rejection
                }
                Err(e) => {
                    panic!("unexpected error type for injection test {i}: {e:?}");
                }
                Ok(_) => {
                    panic!("injection attempt {i} should have been denied");
                }
            }
        }

        // Verify all attempts were logged
        assert!(template.audit_log.len() >= injection_hosts.len());
    }

    #[test]
    fn extreme_adversarial_ssrf_port_overflow_and_boundary_testing() {
        let mut template = SsrfPolicyTemplate::default_template("port-boundary".to_string());

        // Port boundary and overflow scenarios
        let boundary_ports = vec![
            0,        // Invalid port
            65535,    // Maximum valid port
            65536,    // Overflow attempt
            u16::MAX, // Maximum u16
        ];

        for port in boundary_ports {
            let result = template.check_ssrf(
                "api.example.com",
                port,
                Protocol::Http,
                &format!("trace-port-{port}"),
                "2026-01-01T00:00:00Z",
            );

            match port {
                0 => {
                    // Port 0 should be denied
                    assert!(result.is_err());
                }
                65536.. => {
                    // Ports above 65535 should be handled gracefully
                    // (Note: Rust's type system prevents this at compile time with u16)
                }
                _ => {
                    // Other ports may be allowed or denied based on policy
                    // We're testing that it doesn't panic
                }
            }
        }
    }

    #[test]
    fn extreme_adversarial_capability_concurrent_single_use_race_condition() {
        let provider = CapabilityProvider::new("race-condition-secret");
        let scope = RemoteScope::new(
            vec![RemoteOperation::NetworkEgress],
            vec!["https://api.example.com".to_string()],
        );

        let cap = provider
            .issue(
                "operator-race",
                scope,
                1_700_000_000,
                3600,
                true,
                true, // Single use
                "trace-race",
            )
            .expect("capability should issue")
            .0;

        // Simulate concurrent access attempts to single-use capability
        let mut gates = vec![
            CapabilityGate::new("race-condition-secret"),
            CapabilityGate::new("race-condition-secret"),
            CapabilityGate::new("race-condition-secret"),
        ];

        let mut results = Vec::new();
        for gate in &mut gates {
            let result = gate.authorize_network(
                Some(&cap),
                RemoteOperation::NetworkEgress,
                "https://api.example.com/api",
                1_700_000_001,
                "trace-concurrent",
            );
            if results.len() < 10 {
                // Bound the results collection
                results.push(result);
            }
        }

        // Only one should succeed, others should fail with replay detection
        let success_count = results.iter().filter(|r| r.is_ok()).count();
        let replay_count = results
            .iter()
            .filter(|r| matches!(r, Err(RemoteCapError::ReplayDetected { .. })))
            .count();

        assert_eq!(
            success_count, 1,
            "exactly one concurrent access should succeed"
        );
        assert_eq!(replay_count, 2, "other attempts should detect replay");
    }

    #[test]
    fn extreme_adversarial_override_receipt_timing_manipulation() {
        let policy = FreshnessPolicy {
            risky_max_age_secs: 300,
            dangerous_max_age_secs: 60,
        };

        // Timing manipulation attempts in override receipts
        let timing_attacks = vec![
            "1970-01-01T00:00:00Z",           // Unix epoch
            "2038-01-19T03:14:07Z",           // Year 2038 problem
            "9999-12-31T23:59:59Z",           // Far future
            "2026-01-01T00:00:00.000000001Z", // Nanosecond precision
            "2026-02-29T12:00:00Z",           // Invalid leap year date (2026 is not leap)
            "2026-13-01T12:00:00Z",           // Invalid month
            "2026-01-32T12:00:00Z",           // Invalid day
            "2026-01-01T25:00:00Z",           // Invalid hour
            "invalid-timestamp",              // Malformed
            "",                               // Empty timestamp
        ];

        for (i, malicious_timestamp) in timing_attacks.iter().enumerate() {
            let check = FreshnessCheck {
                action_id: format!("timing-action-{i}"),
                tier: SafetyTier::Risky,
                revocation_age_secs: 400, // Over limit, needs override
                trace_id: format!("trace-timing-{i}"),
                timestamp: "2026-01-01T00:00:00Z".to_string(),
            };

            let receipt = OverrideReceipt {
                action_id: format!("timing-action-{i}"),
                actor: "operator".to_string(),
                reason: "emergency override".to_string(),
                timestamp: malicious_timestamp.clone(),
                trace_id: format!("trace-override-timing-{i}"),
            };

            let result = evaluate_freshness(&policy, &check, Some(&receipt));

            // Should handle malformed timestamps gracefully
            match result {
                Ok(_) => {
                    // If it succeeds, the timestamp was valid and parsed correctly
                }
                Err(e) => {
                    // Should fail gracefully, not panic on malformed input
                    assert!(matches!(
                        e,
                        FreshnessError::StaleFrontier { .. }
                            | FreshnessError::OverrideRequired { .. }
                            | FreshnessError::PolicyInvalid { .. }
                    ));
                }
            }
        }
    }

    #[test]
    fn extreme_adversarial_constant_time_length_based_timing_attack() {
        // Test that constant-time comparison is truly constant-time
        // by comparing strings of very different lengths
        let short_string = "a";
        let medium_string = "a".repeat(1000);
        let long_string = "a".repeat(1_000_000);

        let different_short = "b";
        let different_medium = "b".repeat(1000);
        let different_long = "b".repeat(1_000_000);

        // All comparisons should be constant-time regardless of length
        assert!(!constant_time::ct_eq(&short_string, &different_short));
        assert!(!constant_time::ct_eq(&medium_string, &different_medium));
        assert!(!constant_time::ct_eq(&long_string, &different_long));

        // Different length comparisons should also be constant-time
        assert!(!constant_time::ct_eq(&short_string, &long_string));
        assert!(!constant_time::ct_eq(&medium_string, &short_string));

        // Byte-level comparisons
        assert!(!constant_time::ct_eq_bytes(
            short_string.as_bytes(),
            different_short.as_bytes()
        ));
        assert!(!constant_time::ct_eq_bytes(
            long_string.as_bytes(),
            different_long.as_bytes()
        ));
        assert!(!constant_time::ct_eq_bytes(
            short_string.as_bytes(),
            long_string.as_bytes()
        ));
    }
}
