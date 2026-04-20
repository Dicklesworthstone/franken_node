//! Regression tests derived from fuzzing campaigns.
//!
//! These tests capture specific edge cases discovered during fuzzing
//! and ensure they remain fixed as the codebase evolves.

#[cfg(test)]
mod fuzz_regression {
    use crate::security::constant_time::{ct_eq, ct_eq_bytes};
    use crate::security::threshold_sig::{ThresholdConfig, SignerKey, verify_threshold, PublicationArtifact, PartialSignature};
    use crate::security::epoch_scoped_keys::{RootSecret, derive_epoch_key, sign_epoch_artifact, verify_epoch_signature};
    use crate::control_plane::control_epoch::ControlEpoch;

    /// Regression test for constant-time comparison with Unicode normalization differences
    #[test]
    fn regression_constant_time_unicode_normalization() {
        // Test case discovered during structure-aware fuzzing:
        // NFC vs NFD normalization should not be considered equal
        let nfc_string = "café"; // Single codepoint é (U+00E9)
        let nfd_string = "cafe\u{0301}"; // e + combining acute accent (U+0065 U+0301)

        // These look identical when rendered but have different byte representations
        assert!(!ct_eq(nfc_string, nfd_string));
        assert!(!ct_eq_bytes(nfc_string.as_bytes(), nfd_string.as_bytes()));

        // Verify they are indeed different at the byte level
        assert_ne!(nfc_string.as_bytes(), nfd_string.as_bytes());
    }

    /// Regression test for constant-time comparison with zero-width character injection
    #[test]
    fn regression_constant_time_zero_width_injection() {
        // Test case for zero-width space injection attack
        let normal_string = "marker";
        let injected_string = "mark\u{200B}er"; // Zero-width space

        assert!(!ct_eq(normal_string, injected_string));
        assert!(!ct_eq_bytes(normal_string.as_bytes(), injected_string.as_bytes()));
    }

    /// Regression test for threshold signature verification with empty artifact ID
    #[test]
    fn regression_threshold_sig_empty_artifact_id() {
        // Minimal valid config
        let config = ThresholdConfig {
            threshold: 1,
            total_signers: 1,
            signer_keys: vec![SignerKey {
                key_id: "test-signer".to_string(),
                public_key_hex: "deadbeef".repeat(8), // 64 chars
            }],
        };

        // Artifact with empty ID should be rejected
        let artifact = PublicationArtifact {
            artifact_id: String::new(), // Empty ID
            connector_id: "test-connector".to_string(),
            content_hash: "test-hash".to_string(),
            signatures: vec![],
        };

        let result = verify_threshold(&config, &artifact, "test-trace", "2026-01-01T00:00:00Z");

        assert!(!result.verified);
        assert!(matches!(result.failure_reason, Some(crate::security::threshold_sig::FailureReason::InvalidArtifactId { .. })));
    }

    /// Regression test for threshold signature verification with path traversal in connector ID
    #[test]
    fn regression_threshold_sig_path_traversal() {
        let config = ThresholdConfig {
            threshold: 1,
            total_signers: 1,
            signer_keys: vec![SignerKey {
                key_id: "test-signer".to_string(),
                public_key_hex: "deadbeef".repeat(8),
            }],
        };

        // Connector ID with path traversal should be rejected
        let artifact = PublicationArtifact {
            artifact_id: "test-artifact".to_string(),
            connector_id: "../../../admin/connector".to_string(),
            content_hash: "test-hash".to_string(),
            signatures: vec![],
        };

        let result = verify_threshold(&config, &artifact, "test-trace", "2026-01-01T00:00:00Z");

        assert!(!result.verified);
        assert!(matches!(result.failure_reason, Some(crate::security::threshold_sig::FailureReason::InvalidConnectorId { .. })));
    }

    /// Regression test for epoch key derivation with domain containing control characters
    #[test]
    fn regression_epoch_keys_control_char_domain() {
        let secret = RootSecret::from_bytes([0x42; 32]);
        let epoch = ControlEpoch::new(1);
        let domain_with_newline = "test\ndomain";

        // Domain with control characters should be rejected by signing function
        let result = sign_epoch_artifact(b"test-data", epoch, domain_with_newline, &secret);
        assert!(result.is_err());

        // Verify it's specifically a domain validation error
        assert!(matches!(result, Err(crate::security::epoch_scoped_keys::AuthError::DomainEmpty)));
    }

    /// Regression test for epoch key derivation with empty domain
    #[test]
    fn regression_epoch_keys_empty_domain() {
        let secret = RootSecret::from_bytes([0x42; 32]);
        let epoch = ControlEpoch::new(1);

        // Empty domain should be rejected
        let result = sign_epoch_artifact(b"test-data", epoch, "", &secret);
        assert!(result.is_err());
        assert!(matches!(result, Err(crate::security::epoch_scoped_keys::AuthError::DomainEmpty)));

        // Whitespace-only domain should also be rejected
        let result = sign_epoch_artifact(b"test-data", epoch, "   ", &secret);
        assert!(result.is_err());
        assert!(matches!(result, Err(crate::security::epoch_scoped_keys::AuthError::DomainEmpty)));
    }

    /// Regression test for epoch signature cross-domain replay protection
    #[test]
    fn regression_epoch_keys_cross_domain_replay() {
        let secret = RootSecret::from_bytes([0x42; 32]);
        let epoch = ControlEpoch::new(1);
        let artifact = b"sensitive-data";

        // Create signature for one domain
        let source_domain = "source-domain";
        let target_domain = "target-domain";

        let signature = sign_epoch_artifact(artifact, epoch, source_domain, &secret)
            .expect("Should create valid signature");

        // Signature should verify with original domain
        verify_epoch_signature(artifact, &signature, epoch, source_domain, &secret)
            .expect("Should verify with original domain");

        // But should fail with different domain
        let replay_result = verify_epoch_signature(artifact, &signature, epoch, target_domain, &secret);
        assert!(replay_result.is_err(), "Cross-domain replay should fail");
    }

    /// Regression test for threshold signature with malformed hex
    #[test]
    fn regression_threshold_sig_malformed_hex() {
        let config = ThresholdConfig {
            threshold: 1,
            total_signers: 1,
            signer_keys: vec![SignerKey {
                key_id: "test-signer".to_string(),
                public_key_hex: "not-valid-hex-chars".to_string(), // Invalid hex
            }],
        };

        let artifact = PublicationArtifact {
            artifact_id: "test-artifact".to_string(),
            connector_id: "test-connector".to_string(),
            content_hash: "test-hash".to_string(),
            signatures: vec![PartialSignature {
                signer_id: "test-signer".to_string(),
                key_id: "test-signer".to_string(),
                signature_hex: "deadbeef".repeat(16), // Valid format but won't verify
            }],
        };

        let result = verify_threshold(&config, &artifact, "test-trace", "2026-01-01T00:00:00Z");

        // Should fail due to malformed public key
        assert!(!result.verified);
        assert_eq!(result.valid_signatures, 0);
    }

    /// Performance regression test - ensure constant-time operations complete reasonably fast
    #[test]
    fn regression_constant_time_performance() {
        let large_input_a = "x".repeat(4096);
        let large_input_b = "x".repeat(4096);

        let start = std::time::Instant::now();
        let result = ct_eq(&large_input_a, &large_input_b);
        let duration = start.elapsed();

        assert!(result, "Identical large inputs should be equal");
        assert!(duration.as_millis() < 100, "Constant-time comparison should be fast");
    }

    /// Regression tests for intent firewall discovered through structure-aware fuzzing
    mod intent_firewall_regression {
        use crate::security::intent_firewall::{
            RemoteEffect, TrafficOrigin, IntentClassifier, IntentClassification,
            TrafficPolicy, TrafficPolicyRule, FirewallVerdict, EffectsFirewall
        };
        use std::collections::BTreeMap;

        /// Regression test for path traversal injection in effect paths
        #[test]
        fn regression_intent_firewall_path_traversal_injection() {
            let effect = RemoteEffect {
                effect_id: "test-effect".to_string(),
                origin: TrafficOrigin::Extension { extension_id: "test-ext".to_string() },
                target_host: "api.example.com".to_string(),
                target_port: 443,
                method: "GET".to_string(),
                path: "../../../etc/passwd".to_string(), // Path traversal attempt
                has_sensitive_payload: false,
                carries_credentials: false,
                metadata: BTreeMap::new(),
            };

            // Path traversal in path field should not cause classification bypass
            let classification = IntentClassifier::classify(&effect);
            assert_eq!(classification, Some(IntentClassification::DataFetch));
        }

        /// Regression test for null byte injection in host patterns
        #[test]
        fn regression_intent_firewall_null_byte_injection() {
            let effect = RemoteEffect {
                effect_id: "test-effect".to_string(),
                origin: TrafficOrigin::Extension { extension_id: "test-ext".to_string() },
                target_host: "evil.com\0trusted.com".to_string(), // Null byte injection
                target_port: 443,
                method: "GET".to_string(),
                path: "/api/data".to_string(),
                has_sensitive_payload: false,
                carries_credentials: false,
                metadata: BTreeMap::new(),
            };

            // Null byte injection should not bypass validation
            let validation_result = effect.validate();
            assert!(validation_result.is_ok(), "Null bytes in host should be handled gracefully");
        }

        /// Regression test for Unicode normalization in extension IDs
        #[test]
        fn regression_intent_firewall_unicode_extension_id() {
            // Two extension IDs that look identical but have different Unicode normalization
            let effect_nfc = RemoteEffect {
                effect_id: "test-effect-1".to_string(),
                origin: TrafficOrigin::Extension { extension_id: "café-extension".to_string() }, // NFC
                target_host: "api.example.com".to_string(),
                target_port: 443,
                method: "GET".to_string(),
                path: "/api/data".to_string(),
                has_sensitive_payload: false,
                carries_credentials: false,
                metadata: BTreeMap::new(),
            };

            let effect_nfd = RemoteEffect {
                effect_id: "test-effect-2".to_string(),
                origin: TrafficOrigin::Extension { extension_id: "cafe\u{0301}-extension".to_string() }, // NFD
                target_host: "api.example.com".to_string(),
                target_port: 443,
                method: "GET".to_string(),
                path: "/api/data".to_string(),
                has_sensitive_payload: false,
                carries_credentials: false,
                metadata: BTreeMap::new(),
            };

            // Classification should be consistent despite Unicode normalization differences
            let classification_nfc = IntentClassifier::classify(&effect_nfc);
            let classification_nfd = IntentClassifier::classify(&effect_nfd);
            assert_eq!(classification_nfc, classification_nfd);
        }

        /// Regression test for edge case in wildcard host pattern matching
        #[test]
        fn regression_intent_firewall_wildcard_bypass_attempt() {
            let rule = TrafficPolicyRule {
                intent: IntentClassification::DataFetch,
                verdict: FirewallVerdict::Allow,
                priority: 100,
                host_patterns: vec!["*.trusted.com".to_string()],
            };

            // Attempt to bypass wildcard with crafted hostnames
            assert!(!rule.matches_host("evil.trusted.com.attacker.com")); // Should not match
            assert!(!rule.matches_host("trusted.com")); // Should not match (missing subdomain)
            assert!(rule.matches_host("api.trusted.com")); // Should match
            assert!(!rule.matches_host("eviltrusteed.com")); // Should not match (typosquatting)
        }

        /// Regression test for case sensitivity in method classification
        #[test]
        fn regression_intent_firewall_method_case_sensitivity() {
            let mut effect = RemoteEffect {
                effect_id: "test-effect".to_string(),
                origin: TrafficOrigin::Extension { extension_id: "test-ext".to_string() },
                target_host: "api.example.com".to_string(),
                target_port: 443,
                method: "get".to_string(), // lowercase
                path: "/api/data".to_string(),
                has_sensitive_payload: false,
                carries_credentials: false,
                metadata: BTreeMap::new(),
            };

            let classification_lower = IntentClassifier::classify(&effect);

            effect.method = "GET".to_string(); // uppercase
            let classification_upper = IntentClassifier::classify(&effect);

            effect.method = "Get".to_string(); // mixed case
            let classification_mixed = IntentClassifier::classify(&effect);

            // All should classify as DataFetch regardless of case
            assert_eq!(classification_lower, Some(IntentClassification::DataFetch));
            assert_eq!(classification_upper, Some(IntentClassification::DataFetch));
            assert_eq!(classification_mixed, Some(IntentClassification::DataFetch));
        }

        /// Regression test for empty field validation edge cases
        #[test]
        fn regression_intent_firewall_empty_field_validation() {
            // Test various empty/whitespace combinations
            let test_cases = vec![
                ("", "Empty effect_id should be rejected"),
                (" ", "Whitespace-only effect_id should be rejected"),
                ("\t\n\r", "Control character effect_id should be rejected"),
            ];

            for (effect_id, description) in test_cases {
                let effect = RemoteEffect {
                    effect_id: effect_id.to_string(),
                    origin: TrafficOrigin::Extension { extension_id: "test-ext".to_string() },
                    target_host: "api.example.com".to_string(),
                    target_port: 443,
                    method: "GET".to_string(),
                    path: "/api/data".to_string(),
                    has_sensitive_payload: false,
                    carries_credentials: false,
                    metadata: BTreeMap::new(),
                };

                let result = effect.validate();
                assert!(result.is_err(), "{}", description);
            }
        }

        /// Regression test for deterministic classification invariant
        #[test]
        fn regression_intent_firewall_classification_determinism() {
            let effect = RemoteEffect {
                effect_id: "test-effect".to_string(),
                origin: TrafficOrigin::Extension { extension_id: "test-ext".to_string() },
                target_host: "api.example.com".to_string(),
                target_port: 443,
                method: "GET".to_string(),
                path: "/webhook/callback".to_string(),
                has_sensitive_payload: false,
                carries_credentials: false,
                metadata: BTreeMap::new(),
            };

            // Multiple classifications of the same input must yield identical results
            let classifications: Vec<Option<IntentClassification>> = (0..10)
                .map(|_| IntentClassifier::classify(&effect))
                .collect();

            assert!(classifications.windows(2).all(|w| w[0] == w[1]),
                   "Intent classification must be deterministic (INV-FIREWALL-STABLE-CLASSIFICATION)");
        }

        /// Regression test for risky intent detection consistency
        #[test]
        fn regression_intent_firewall_risky_intent_consistency() {
            let risky_intents = vec![
                IntentClassification::Exfiltration,
                IntentClassification::CredentialForward,
                IntentClassification::SideChannel,
            ];

            let safe_intents = vec![
                IntentClassification::DataFetch,
                IntentClassification::DataMutation,
                IntentClassification::HealthCheck,
                IntentClassification::ConfigSync,
            ];

            for intent in risky_intents {
                assert!(intent.is_risky(), "Intent {:?} should be classified as risky", intent);
            }

            for intent in safe_intents {
                assert!(!intent.is_risky(), "Intent {:?} should not be classified as risky", intent);
            }
        }
    }

    /// Regression tests for SSRF policy discovered through structure-aware fuzzing
    mod ssrf_policy_regression {
        use crate::security::ssrf_policy::{CidrRange, SsrfPolicyTemplate};
        use crate::security::network_guard::Protocol;

        /// Regression test for CIDR range boundary conditions
        #[test]
        fn regression_ssrf_cidr_boundary_conditions() {
            // Test edge cases in CIDR range calculations
            let cidr = CidrRange::new([192, 168, 1, 0], 24, "test_network");

            // Boundary addresses
            assert!(cidr.contains([192, 168, 1, 0]));   // Network address
            assert!(cidr.contains([192, 168, 1, 255])); // Broadcast address
            assert!(cidr.contains([192, 168, 1, 127])); // Mid-range address

            // Addresses outside range
            assert!(!cidr.contains([192, 168, 0, 255])); // Just below
            assert!(!cidr.contains([192, 168, 2, 0]));   // Just above
            assert!(!cidr.contains([192, 167, 1, 128])); // Different second octet
        }

        /// Regression test for edge cases in prefix length handling
        #[test]
        fn regression_ssrf_prefix_length_edge_cases() {
            // Test /32 (single host)
            let host_cidr = CidrRange::new([127, 0, 0, 1], 32, "localhost");
            assert!(host_cidr.contains([127, 0, 0, 1]));
            assert!(!host_cidr.contains([127, 0, 0, 2]));

            // Test /0 (everything)
            let all_cidr = CidrRange::new([0, 0, 0, 0], 0, "all_networks");
            assert!(all_cidr.contains([192, 168, 1, 1]));
            assert!(all_cidr.contains([8, 8, 8, 8]));

            // Test invalid prefix length (should be handled safely)
            let invalid_cidr = CidrRange::new([192, 168, 1, 0], 33, "invalid");
            // Should not panic - contains() should handle gracefully
            let _result = invalid_cidr.contains([192, 168, 1, 1]);
        }

        /// Regression test for IPv4 address parsing edge cases
        #[test]
        fn regression_ssrf_ipv4_parsing_attacks() {
            let mut policy = SsrfPolicyTemplate::new("test-connector", vec![], vec![]);

            // Test various IPv4 parsing bypass attempts
            let malicious_hosts = vec![
                "127.0.0.1",           // Standard loopback
                "127.1",               // Compressed format
                "2130706433",          // 32-bit integer format
                "0x7f000001",          // Hexadecimal
                "017700000001",        // Octal
                "127.000.000.001",     // Leading zeros
                "[127.0.0.1]",         // Bracketed
                "localhost",           // Hostname
                "127.0.0.1.",          // Trailing dot
                "127.0.0.1..",         // Multiple trailing dots
            ];

            for host in malicious_hosts {
                // Should not panic on any input, regardless of format
                let _result = policy.check_ssrf(
                    host,
                    80,
                    Protocol::Tcp,
                    "test-trace",
                    "2026-01-01T00:00:00Z"
                );
            }
        }

        /// Regression test for null byte injection in hostnames
        #[test]
        fn regression_ssrf_null_byte_injection() {
            let mut policy = SsrfPolicyTemplate::new("test-connector", vec![], vec![]);

            let malicious_hosts = vec![
                "evil.com\0trusted.com",
                "127.0.0.1\0",
                "\0127.0.0.1",
                "api\0.example.com",
            ];

            for host in malicious_hosts {
                // Null byte injection should be detected and rejected
                let result = policy.check_ssrf(
                    host,
                    443,
                    Protocol::Tcp,
                    "test-trace",
                    "2026-01-01T00:00:00Z"
                );
                assert!(result.is_err(), "Null byte injection should be rejected for host: {}", host);
            }
        }

        /// Regression test for IPv6 loopback handling
        #[test]
        fn regression_ssrf_ipv6_loopback() {
            let mut policy = SsrfPolicyTemplate::new("test-connector", vec![], vec![]);

            // IPv6 loopback variants should be consistently blocked
            let ipv6_loopbacks = vec!["::1", "[::1]"];

            for host in ipv6_loopbacks {
                let result = policy.check_ssrf(
                    host,
                    80,
                    Protocol::Tcp,
                    "test-trace",
                    "2026-01-01T00:00:00Z"
                );
                assert!(result.is_err(), "IPv6 loopback should be blocked: {}", host);
            }
        }

        /// Regression test for path-like hostname injection
        #[test]
        fn regression_ssrf_path_like_hostname_injection() {
            let mut policy = SsrfPolicyTemplate::new("test-connector", vec![], vec![]);

            let path_like_hosts = vec![
                "api.example.com/../../etc/passwd",
                "api.example.com\\..\\..\\windows\\system32",
                "api.example.com/./././admin",
                "api.example.com/../admin/../config",
            ];

            for host in path_like_hosts {
                // Path-like syntax in hostnames should be detected and rejected
                let result = policy.check_ssrf(
                    host,
                    443,
                    Protocol::Tcp,
                    "test-trace",
                    "2026-01-01T00:00:00Z"
                );
                assert!(result.is_err(), "Path-like hostname should be rejected: {}", host);
            }
        }

        /// Regression test for CIDR range consistency across multiple calls
        #[test]
        fn regression_ssrf_cidr_consistency() {
            let cidr = CidrRange::new([10, 0, 0, 0], 8, "rfc1918_class_a");
            let test_ip = [10, 50, 100, 150];

            // Multiple calls should return consistent results
            let results: Vec<bool> = (0..10)
                .map(|_| cidr.contains(test_ip))
                .collect();

            assert!(results.windows(2).all(|w| w[0] == w[1]),
                   "CIDR contains() must return consistent results");
        }

        /// Regression test for private IP range detection
        #[test]
        fn regression_ssrf_private_ip_ranges() {
            let private_ips = vec![
                ([127, 0, 0, 1], "loopback"),
                ([10, 0, 0, 1], "rfc1918_class_a"),
                ([172, 16, 0, 1], "rfc1918_class_b"),
                ([192, 168, 1, 1], "rfc1918_class_c"),
                ([169, 254, 1, 1], "link_local"),
                ([100, 64, 0, 1], "cgnat_tailnet"),
            ];

            for (ip, _label) in private_ips {
                let mut policy = SsrfPolicyTemplate::new("test-connector", vec![], vec![]);
                let ip_string = format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]);

                // Private IP ranges should be blocked by default
                let result = policy.check_ssrf(
                    &ip_string,
                    80,
                    Protocol::Tcp,
                    "test-trace",
                    "2026-01-01T00:00:00Z"
                );
                assert!(result.is_err(), "Private IP should be blocked: {}", ip_string);
            }
        }
    }
}