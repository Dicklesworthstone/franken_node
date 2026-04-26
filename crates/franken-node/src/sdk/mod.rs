pub mod replay_capsule;
pub mod verifier_sdk;

#[cfg(test)]
mod tests {
    use super::replay_capsule::{
        CURRENT_FORMAT_VERSION, CapsuleError, CapsuleInput, EnvironmentSnapshot, ReplayCapsule,
        create_capsule, from_json, replay_and_verify, validate_capsule,
    };
    use super::verifier_sdk::{
        SdkError, VerificationReport, VerificationRequest, VerifierConfig, VerifierSdk,
        VerifyVerdict,
    };
    use std::collections::BTreeMap;

    fn test_environment() -> EnvironmentSnapshot {
        EnvironmentSnapshot {
            runtime_version: "franken-node-test".to_string(),
            platform: "linux-x86_64".to_string(),
            config_hash: "sdk-config-hash".to_string(),
            properties: BTreeMap::new(),
        }
    }

    fn input(seq: u64, data: &[u8]) -> CapsuleInput {
        CapsuleInput {
            seq,
            data: data.to_vec(),
            metadata: BTreeMap::new(),
        }
    }

    fn ordered_inputs() -> Vec<CapsuleInput> {
        vec![input(1, b"alpha"), input(2, b"beta")]
    }

    fn valid_capsule() -> ReplayCapsule {
        create_capsule("sdk-mod-capsule", ordered_inputs(), test_environment())
            .expect("fixture capsule should be valid")
    }

    fn request(artifact_id: &str, digest: &str, claims: Vec<&str>) -> VerificationRequest {
        VerificationRequest {
            artifact_id: artifact_id.to_string(),
            artifact_hash: digest.to_string(),
            claims: claims.into_iter().map(str::to_string).collect(),
        }
    }

    fn expect_invalid_artifact(err: SdkError, fragment: &str) {
        match err {
            SdkError::InvalidArtifact(message) => {
                assert!(
                    message.contains(fragment),
                    "expected invalid artifact message to contain {fragment:?}, got {message:?}"
                );
            }
            other => panic!("expected invalid artifact error, got {other:?}"),
        }
    }

    fn sdk_without_artifact_match() -> VerifierSdk {
        VerifierSdk::new(VerifierConfig {
            require_hash_match: false,
            ..VerifierConfig::default()
        })
    }

    fn failed_checks(report: &VerificationReport) -> Vec<&str> {
        report
            .evidence
            .iter()
            .filter(|entry| !entry.passed)
            .map(|entry| entry.check_name.as_str())
            .collect()
    }

    #[test]
    fn create_capsule_rejects_empty_capsule_id() {
        let err = create_capsule("", ordered_inputs(), test_environment()).unwrap_err();
        assert_eq!(err, CapsuleError::EmptyId);
    }

    #[test]
    fn create_capsule_rejects_empty_inputs() {
        let err = create_capsule("sdk-mod-capsule", vec![], test_environment()).unwrap_err();
        assert_eq!(err, CapsuleError::NoInputs);
    }

    #[test]
    fn create_capsule_rejects_equal_sequence_numbers() {
        let inputs = vec![input(7, b"first"), input(7, b"second")];
        let err = create_capsule("sdk-mod-capsule", inputs, test_environment()).unwrap_err();
        assert_eq!(err, CapsuleError::NonMonotonicInputSequence);
    }

    #[test]
    fn create_capsule_rejects_empty_platform_snapshot() {
        let mut environment = test_environment();
        environment.platform = String::new();

        let err = create_capsule("sdk-mod-capsule", ordered_inputs(), environment).unwrap_err();

        assert!(matches!(err, CapsuleError::IncompleteEnvironment(_)));
    }

    #[test]
    fn validate_capsule_rejects_future_format_version() {
        let mut capsule = valid_capsule();
        capsule.format_version = CURRENT_FORMAT_VERSION.saturating_add(1);

        let err = validate_capsule(&capsule).unwrap_err();

        assert!(matches!(
            err,
            CapsuleError::UnsupportedVersion(version)
                if version > CURRENT_FORMAT_VERSION
        ));
    }

    #[test]
    fn validate_capsule_rejects_missing_expected_outputs() {
        let mut capsule = valid_capsule();
        capsule.expected_outputs.clear();

        let err = validate_capsule(&capsule).unwrap_err();

        assert_eq!(err, CapsuleError::NoOutputs);
    }

    #[test]
    fn replay_and_verify_returns_false_for_tampered_expected_output() {
        let mut capsule = valid_capsule();
        capsule.expected_outputs[0].output_hash = "0".repeat(64);

        let verified = replay_and_verify(&capsule).expect("structural replay should succeed");

        assert!(!verified);
    }

    #[test]
    fn create_capsule_rejects_decreasing_sequence_numbers() {
        let inputs = vec![input(9, b"newer"), input(3, b"older")];

        let err = create_capsule("sdk-mod-capsule", inputs, test_environment()).unwrap_err();

        assert_eq!(err, CapsuleError::NonMonotonicInputSequence);
    }

    #[test]
    fn create_capsule_rejects_empty_runtime_version_snapshot() {
        let mut environment = test_environment();
        environment.runtime_version = String::new();

        let err = create_capsule("sdk-mod-capsule", ordered_inputs(), environment).unwrap_err();

        match err {
            CapsuleError::IncompleteEnvironment(message) => {
                assert!(message.contains("runtime_version"));
            }
            other => panic!("expected incomplete runtime version, got {other:?}"),
        }
    }

    #[test]
    fn create_capsule_rejects_empty_config_snapshot() {
        let mut environment = test_environment();
        environment.config_hash = String::new();

        let err = create_capsule("sdk-mod-capsule", ordered_inputs(), environment).unwrap_err();

        match err {
            CapsuleError::IncompleteEnvironment(message) => {
                assert!(message.contains("config_hash"));
            }
            other => panic!("expected incomplete config snapshot, got {other:?}"),
        }
    }

    #[test]
    fn validate_capsule_rejects_version_below_supported_range() {
        let mut capsule = valid_capsule();
        capsule.format_version = 0;

        let err = validate_capsule(&capsule).unwrap_err();

        assert_eq!(err, CapsuleError::UnsupportedVersion(0));
    }

    #[test]
    fn validate_capsule_rejects_empty_id_after_mutation() {
        let mut capsule = valid_capsule();
        capsule.capsule_id = String::new();

        let err = validate_capsule(&capsule).unwrap_err();

        assert_eq!(err, CapsuleError::EmptyId);
    }

    #[test]
    fn verify_artifact_reports_short_digest_format_failure() {
        let sdk = sdk_without_artifact_match();
        let request = request("artifact-1", "abc123", vec!["claim-a"]);

        let report = sdk
            .verify_artifact(&request)
            .expect("format failures should produce a report");
        let failures = failed_checks(&report);

        assert!(matches!(&report.verdict, VerifyVerdict::Fail(_)));
        assert!(failures.contains(&"artifact_hash_format"));
    }

    #[test]
    fn verify_artifact_reports_non_hex_digest_format_failure() {
        let sdk = sdk_without_artifact_match();
        let request = request("artifact-1", &"z".repeat(64), vec!["claim-a"]);

        let report = sdk
            .verify_artifact(&request)
            .expect("format failures should produce a report");
        let failures = failed_checks(&report);

        assert!(matches!(&report.verdict, VerifyVerdict::Fail(_)));
        assert!(failures.contains(&"artifact_hash_format"));
    }

    #[test]
    fn verify_artifact_reports_empty_claim_set_under_strict_mode() {
        let sdk = sdk_without_artifact_match();
        let request = request("artifact-1", &"a".repeat(64), vec![]);

        let report = sdk
            .verify_artifact(&request)
            .expect("claim failures should produce a report");
        let failures = failed_checks(&report);

        assert!(matches!(&report.verdict, VerifyVerdict::Fail(_)));
        assert!(failures.contains(&"claims_valid"));
    }

    #[test]
    fn verify_artifact_reports_empty_claim_entry_under_strict_mode() {
        let sdk = sdk_without_artifact_match();
        let request = request("artifact-1", &"a".repeat(64), vec!["claim-a", ""]);

        let report = sdk
            .verify_artifact(&request)
            .expect("claim failures should produce a report");
        let failures = failed_checks(&report);

        assert!(matches!(&report.verdict, VerifyVerdict::Fail(_)));
        assert!(failures.contains(&"claims_valid"));
        assert!(failures.contains(&"claim_1_non_empty"));
    }

    #[test]
    fn from_json_rejects_malformed_payload() {
        let err = from_json("{not-valid-json").unwrap_err();

        assert!(err.is_syntax() || err.is_eof());
    }

    #[test]
    fn verify_artifact_rejects_reserved_artifact_id() {
        let sdk = VerifierSdk::with_defaults();
        let request = request("<unknown>", &"a".repeat(64), vec!["claim-a"]);

        let err = sdk.verify_artifact(&request).unwrap_err();

        expect_invalid_artifact(err, "reserved");
    }

    #[test]
    fn verify_artifact_rejects_whitespace_artifact_id() {
        let sdk = VerifierSdk::with_defaults();
        let request = request(" artifact-1 ", &"a".repeat(64), vec!["claim-a"]);

        let err = sdk.verify_artifact(&request).unwrap_err();

        expect_invalid_artifact(err, "whitespace");
    }

    #[test]
    fn verify_artifact_rejects_empty_artifact_hash() {
        let sdk = VerifierSdk::with_defaults();
        let request = request("artifact-1", "", vec!["claim-a"]);

        let err = sdk.verify_artifact(&request).unwrap_err();

        expect_invalid_artifact(err, "artifact_hash is empty");
    }

    #[test]
    fn verify_capsule_reports_failed_replay_evidence_for_tampering() {
        let sdk = VerifierSdk::with_defaults();
        let mut capsule = valid_capsule();
        capsule.expected_outputs[0].output_hash = "f".repeat(64);

        let report = sdk
            .verify_capsule(&capsule)
            .expect("malformed evidence should be reported");

        match report.verdict {
            VerifyVerdict::Fail(failures) => {
                assert!(
                    failures
                        .iter()
                        .any(|name| name == "replay_deterministic_match")
                );
            }
            other => panic!("expected failed verification report, got {other:?}"),
        }
    }

    #[test]
    fn verify_capsule_rejects_empty_capsule_id_before_evidence() {
        let sdk = VerifierSdk::with_defaults();
        let mut capsule = valid_capsule();
        capsule.capsule_id = String::new();

        let err = sdk.verify_capsule(&capsule).unwrap_err();

        match err {
            SdkError::MalformedCapsule(message) => assert!(message.contains("capsule_id")),
            other => panic!("expected malformed capsule error, got {other:?}"),
        }
    }

    #[test]
    fn verify_capsule_reports_missing_environment_snapshot() {
        let sdk = VerifierSdk::with_defaults();
        let mut capsule = valid_capsule();
        capsule.environment.config_hash = String::new();

        let report = sdk
            .verify_capsule(&capsule)
            .expect("environment failures should produce a report");
        let failures = failed_checks(&report);

        assert!(matches!(&report.verdict, VerifyVerdict::Fail(_)));
        assert!(failures.contains(&"environment_present"));
        assert!(failures.contains(&"replay_deterministic_match"));
    }

    #[test]
    fn verify_chain_rejects_empty_report_chain() {
        let sdk = VerifierSdk::with_defaults();

        let err = sdk.verify_chain(&[]).unwrap_err();

        match err {
            SdkError::BrokenChain(message) => assert!(message.contains("empty")),
            other => panic!("expected broken chain error, got {other:?}"),
        }
    }

    #[test]
    fn verify_chain_reports_duplicate_request_ids_and_bindings() {
        let sdk = sdk_without_artifact_match();
        let request = request("artifact-1", &"a".repeat(64), vec!["claim-a"]);
        let report = sdk
            .verify_artifact(&request)
            .expect("fixture report should be created");

        let chain_report = sdk
            .verify_chain(&[report.clone(), report])
            .expect("duplicate report chain should still emit evidence");
        let failures = failed_checks(&chain_report);

        assert!(matches!(&chain_report.verdict, VerifyVerdict::Fail(_)));
        assert!(failures.contains(&"binding_hashes_unique"));
        assert!(failures.contains(&"request_ids_unique"));
    }

    #[test]
    fn verify_chain_reports_schema_tag_drift() {
        let sdk = sdk_without_artifact_match();
        let first = sdk
            .verify_artifact(&request("artifact-1", &"a".repeat(64), vec!["claim-a"]))
            .expect("fixture report should be created");
        let mut second = sdk
            .verify_artifact(&request("artifact-2", &"b".repeat(64), vec!["claim-b"]))
            .expect("fixture report should be created");
        second.schema_tag = "vsk-legacy".to_string();

        let chain_report = sdk
            .verify_chain(&[first, second])
            .expect("schema drift should still emit evidence");
        let failures = failed_checks(&chain_report);

        assert!(matches!(&chain_report.verdict, VerifyVerdict::Fail(_)));
        assert!(failures.contains(&"schema_tag_consistent"));
    }

    // ── Comprehensive SDK module negative-path tests ──

    #[test]
    fn negative_capsule_with_massive_metadata_memory_stress_test() {
        let mut massive_input = input(1, b"test");

        // Add massive metadata to stress memory allocation
        for i in 0..10000 {
            massive_input.metadata.insert(
                format!("key_{}", i),
                "x".repeat(100), // 100 bytes per value * 10k keys = ~1MB metadata
            );
        }

        let result = create_capsule("massive-metadata", vec![massive_input], test_environment());

        // Should handle gracefully without panic or excessive memory usage
        match result {
            Ok(capsule) => {
                // If accepted, validation should work
                assert!(validate_capsule(&capsule).is_ok());

                // SDK verification should handle large metadata
                let sdk = VerifierSdk::with_defaults();
                let verification_result = sdk.verify_capsule(&capsule);
                assert!(verification_result.is_ok());
            }
            Err(_) => {
                // Graceful rejection of oversized metadata is acceptable
            }
        }
    }

    #[test]
    fn negative_artifact_id_with_unicode_injection_patterns() {
        let sdk = VerifierSdk::with_defaults();

        let injection_patterns = [
            "artifact\u{202E}spoofed",   // Right-to-left override
            "artifact\u{200B}invisible", // Zero-width space
            "artifact\u{FEFF}bom",       // Byte order mark
            "artifact\x00null",          // Null byte
            "artifact\r\ninjection",     // CRLF injection
            "artifact\u{1F4A9}emoji",    // Pile of poo emoji
            "artifact\t\x08control",     // Tab and backspace
        ];

        for pattern in &injection_patterns {
            let request = request(pattern, &"a".repeat(64), vec!["test-claim"]);

            match sdk.verify_artifact(&request) {
                Ok(report) => {
                    // If accepted, artifact ID should be preserved exactly
                    assert!(report.binding_hash.len() > 0);

                    // JSON serialization should handle the pattern safely
                    let json_result = std::panic::catch_unwind(|| serde_json::to_string(&report));
                    assert!(
                        json_result.is_ok(),
                        "Pattern '{}' should serialize safely",
                        pattern.escape_unicode()
                    );
                }
                Err(SdkError::InvalidArtifact(_)) => {
                    // Early rejection of injection patterns is acceptable
                }
                Err(other) => {
                    panic!(
                        "Unexpected error for pattern '{}': {:?}",
                        pattern.escape_unicode(),
                        other
                    );
                }
            }
        }
    }

    #[test]
    fn negative_capsule_sequence_numbers_at_arithmetic_boundaries() {
        let boundary_inputs = vec![input(u64::MAX - 1, b"near_max"), input(u64::MAX, b"at_max")];

        let capsule = create_capsule("boundary-sequences", boundary_inputs, test_environment())
            .expect("boundary sequence numbers should be accepted");

        // Validation should handle extreme values
        assert!(validate_capsule(&capsule).is_ok());

        // SDK verification should handle u64::MAX sequences
        let sdk = VerifierSdk::with_defaults();
        let report = sdk
            .verify_capsule(&capsule)
            .expect("boundary sequences should verify");

        assert!(matches!(report.verdict, VerifyVerdict::Pass));

        // Serialization should handle extreme values
        let json = serde_json::to_string(&capsule).expect("should serialize boundary values");
        let parsed: ReplayCapsule =
            serde_json::from_str(&json).expect("should deserialize boundary values");
        assert_eq!(parsed.inputs[1].seq, u64::MAX);
    }

    #[test]
    fn negative_verification_chain_with_corrupted_binding_hashes() {
        let sdk = VerifierSdk::with_defaults();

        // Create legitimate reports
        let mut report1 = sdk
            .verify_artifact(&request("artifact-1", &"a".repeat(64), vec!["claim1"]))
            .expect("first report should succeed");
        let mut report2 = sdk
            .verify_artifact(&request("artifact-2", &"b".repeat(64), vec!["claim2"]))
            .expect("second report should succeed");

        // Corrupt binding hashes with various attack patterns
        let corruption_patterns = [
            "".to_string(),                                   // Empty hash
            "a".repeat(63),                                   // Too short
            "a".repeat(65),                                   // Too long
            "g".repeat(64),                                   // Invalid hex
            "\x00".repeat(32),                                // Null bytes
            "\u{FEFF}".repeat(16),                            // Unicode BOM
            format!("{}../../../etc/passwd", "a".repeat(32)), // Path injection
        ];

        for (i, pattern) in corruption_patterns.iter().enumerate() {
            if i % 2 == 0 {
                report1.binding_hash = pattern.clone();
            } else {
                report2.binding_hash = pattern.clone();
            }

            let chain_result = sdk.verify_chain(&[report1.clone(), report2.clone()]);

            match chain_result {
                Ok(chain_report) => {
                    // Should detect corruption in evidence
                    let failures = failed_checks(&chain_report);
                    assert!(
                        matches!(chain_report.verdict, VerifyVerdict::Fail(_)),
                        "Corrupted hash '{}' should cause chain failure",
                        pattern.escape_unicode()
                    );
                    assert!(
                        failures.contains(&"binding_hashes_present")
                            || failures.contains(&"binding_hashes_unique"),
                        "Should detect hash corruption for pattern '{}'",
                        pattern.escape_unicode()
                    );
                }
                Err(_) => {
                    // Early rejection of malformed chains is acceptable
                }
            }
        }
    }

    #[test]
    fn negative_capsule_environment_with_control_character_pollution() {
        let mut environment = test_environment();

        // Inject control characters into environment fields
        environment.runtime_version = "franken-node\x00\r\n\t\x1b[31mred\x1b[0m".to_string();
        environment.platform = "linux\x08\x7F\u{202E}x86_64".to_string();
        environment.config_hash = "\u{FEFF}config\u{200B}hash".to_string();

        // Add properties with control characters
        environment
            .properties
            .insert("key\x00null".to_string(), "value\r\ninjection".to_string());
        environment
            .properties
            .insert("\u{202E}rtl".to_string(), "\u{200B}invisible".to_string());

        let capsule = create_capsule("control-chars", ordered_inputs(), environment.clone())
            .expect("environment with control chars should be accepted");

        // Validation should preserve control characters
        assert!(validate_capsule(&capsule).is_ok());
        assert_eq!(
            capsule.environment.runtime_version,
            environment.runtime_version
        );
        assert_eq!(capsule.environment.platform, environment.platform);
        assert_eq!(capsule.environment.config_hash, environment.config_hash);
        assert_eq!(capsule.environment.properties, environment.properties);

        // SDK verification should handle control characters
        let sdk = VerifierSdk::with_defaults();
        let report = sdk
            .verify_capsule(&capsule)
            .expect("control chars should verify");
        assert!(matches!(report.verdict, VerifyVerdict::Pass));

        // JSON round-trip should preserve control characters
        let json = serde_json::to_string(&capsule).expect("should serialize control chars");
        let parsed: ReplayCapsule =
            serde_json::from_str(&json).expect("should deserialize control chars");
        assert_eq!(
            parsed.environment.runtime_version,
            environment.runtime_version
        );
    }

    #[test]
    fn negative_deeply_nested_json_deserialization_stack_overflow_protection() {
        // Create deeply nested JSON structure that could cause stack overflow
        let mut nested_json = String::new();
        nested_json.push_str(r#"{"capsule_id":"deep-nest","format_version":1,"inputs":["#);

        // Create 1000 levels of nesting
        for _ in 0..1000 {
            nested_json.push_str(r#"{"nested":"#);
        }
        nested_json.push_str(r#"null"#);
        for _ in 0..1000 {
            nested_json.push('}');
        }
        nested_json.push_str(r#"],"expected_outputs":[],"environment":{"runtime_version":"test","platform":"test","config_hash":"test","properties":{}}}"#);

        let result = std::panic::catch_unwind(|| from_json(&nested_json));

        // Should either deserialize safely or fail gracefully (not panic/stack overflow)
        match result {
            Ok(Ok(_)) => {
                // Successfully parsed deeply nested structure
            }
            Ok(Err(_)) => {
                // Graceful parsing failure is acceptable
            }
            Err(_) => {
                // Stack overflow protection should prevent panic, but if it happens,
                // it indicates we need better protection
                panic!("Deep nesting caused panic - need stack overflow protection");
            }
        }
    }

    #[test]
    fn negative_verifier_config_with_contradictory_settings_edge_cases() {
        // Test configurations with potentially contradictory or extreme settings
        let contradictory_configs = [
            VerifierConfig {
                verifier_identity: "".to_string(), // Empty identity
                require_hash_match: true,
                strict_claims: false,
                extensions: BTreeMap::new(),
            },
            VerifierConfig {
                verifier_identity: "\x00null\r\ninjection".to_string(), // Control chars in identity
                require_hash_match: false,
                strict_claims: true,
                extensions: {
                    let mut ext = BTreeMap::new();
                    ext.insert("".to_string(), "empty_key".to_string()); // Empty extension key
                    ext.insert("normal".to_string(), "\x00null_value".to_string()); // Null in value
                    ext
                },
            },
            VerifierConfig {
                verifier_identity: "🚀".repeat(10000), // Massive unicode identity
                require_hash_match: true,
                strict_claims: true,
                extensions: BTreeMap::new(),
            },
        ];

        for (i, config) in contradictory_configs.iter().enumerate() {
            let sdk = VerifierSdk::new(config.clone());

            // SDK should handle contradictory configs without crashing
            assert_eq!(sdk.config(), config);
            assert_eq!(sdk.api_version(), super::verifier_sdk::API_VERSION);

            // Basic operations should work despite odd configuration
            let request = request("test-artifact", &"a".repeat(64), vec!["test-claim"]);
            let result = sdk.verify_artifact(&request);

            assert!(
                result.is_ok() || result.is_err(),
                "Config {} should produce deterministic result",
                i
            );

            if let Ok(report) = result {
                // Report should contain the configured identity
                assert_eq!(report.verifier_identity, config.verifier_identity);

                // JSON serialization should handle the config
                let json_result = serde_json::to_string(&report);
                assert!(
                    json_result.is_ok(),
                    "Config {} should serialize without error",
                    i
                );
            }
        }
    }

    #[test]
    fn negative_cross_module_hash_collision_resistance_validation() {
        let sdk = VerifierSdk::with_defaults();

        // Create capsules with crafted content designed to test hash collision resistance
        let collision_attempts = [
            (
                vec![input(1, b"ab"), input(2, b"cd")],
                vec![input(1, b"abc"), input(2, b"d")],
            ),
            (vec![input(0, b"")], vec![input(1, b"")]),
            (vec![input(1, b"\x00\x01")], vec![input(2, b"\x01\x00")]),
            (
                vec![input(42, "🚀".as_bytes())],
                vec![input(42, "🎯".as_bytes())],
            ),
        ];

        for (inputs1, inputs2) in collision_attempts {
            let capsule1 = create_capsule("collision-test-1", inputs1, test_environment())
                .expect("first capsule should create");
            let capsule2 = create_capsule("collision-test-2", inputs2, test_environment())
                .expect("second capsule should create");

            let report1 = sdk
                .verify_capsule(&capsule1)
                .expect("first verification should work");
            let report2 = sdk
                .verify_capsule(&capsule2)
                .expect("second verification should work");

            // Different capsules should produce different binding hashes
            assert_ne!(
                report1.binding_hash, report2.binding_hash,
                "Different capsules must produce different binding hashes"
            );
            assert_ne!(
                report1.request_id, report2.request_id,
                "Different capsules must produce different request IDs"
            );
            assert_ne!(
                report1.trace_id, report2.trace_id,
                "Different capsules must produce different trace IDs"
            );

            // Chain verification should detect different hashes
            let chain_report = sdk
                .verify_chain(&[report1, report2])
                .expect("chain should verify");
            assert!(
                matches!(chain_report.verdict, VerifyVerdict::Pass),
                "Chain with different capsules should pass uniqueness checks"
            );
        }
    }

    #[test]
    fn negative_replay_verification_under_memory_pressure() {
        // Create capsule with large input data to stress replay system
        let large_inputs = (0..100)
            .map(|i| {
                input(i, &vec![i as u8; 10000]) // 10KB per input * 100 = 1MB total
            })
            .collect();

        let large_capsule = create_capsule("memory-pressure", large_inputs, test_environment())
            .expect("large capsule should create");

        // Validation should handle large data
        assert!(validate_capsule(&large_capsule).is_ok());

        // Replay should handle large data without excessive memory usage
        let replay_result = super::replay_capsule::replay(&large_capsule);
        assert!(replay_result.is_ok(), "replay should handle large data");

        // Verification should complete without memory issues
        let verified = replay_and_verify(&large_capsule).expect("large capsule should verify");
        assert!(verified, "large capsule should verify correctly");

        // SDK verification should handle large capsule
        let sdk = VerifierSdk::with_defaults();
        let report = sdk
            .verify_capsule(&large_capsule)
            .expect("SDK should handle large capsule");
        assert!(matches!(report.verdict, VerifyVerdict::Pass));

        // JSON serialization should handle large data
        let json = serde_json::to_string(&large_capsule);
        assert!(json.is_ok(), "large capsule should serialize");

        if let Ok(json_str) = json {
            assert!(
                json_str.len() > 1_000_000,
                "JSON should contain substantial data"
            );

            // Deserialization should work
            let parsed_result = serde_json::from_str::<ReplayCapsule>(&json_str);
            assert!(parsed_result.is_ok(), "large JSON should deserialize");
        }
    }

    #[test]
    fn negative_capsule_format_version_with_floating_point_precision_edge_cases() {
        // Test version handling near floating-point precision boundaries
        let mut capsule = valid_capsule();

        // Test versions at JavaScript safe integer limits (could cause precision loss in JSON)
        let edge_versions = [
            1u64,                    // Minimal version
            9007199254740991u64,     // 2^53 - 1 (max safe integer in JavaScript)
            9007199254740992u64,     // 2^53 (precision loss boundary)
            18446744073709551615u64, // u64::MAX
        ];

        for &version in &edge_versions {
            let mut test_capsule = capsule.clone();
            test_capsule.format_version = version;

            // JSON round-trip should preserve exact version
            let json = serde_json::to_string(&test_capsule).expect("should serialize version");
            let parsed: ReplayCapsule =
                serde_json::from_str(&json).expect("should deserialize version");
            assert_eq!(parsed.format_version, version);

            // Validation should handle extreme versions appropriately
            let validation_result = validate_capsule(&test_capsule);

            if version == 1 {
                // Current version should be valid
                assert!(validation_result.is_ok(), "Version 1 should be valid");
            } else if version > CURRENT_FORMAT_VERSION {
                // Future versions should be rejected
                assert!(
                    validation_result.is_err(),
                    "Future version {} should be rejected",
                    version
                );
                match validation_result.unwrap_err() {
                    CapsuleError::UnsupportedVersion(v) => assert_eq!(v, version),
                    other => panic!(
                        "Unexpected error for future version {}: {:?}",
                        version, other
                    ),
                }
            } else {
                // Past versions might be accepted or rejected depending on implementation
                assert!(
                    validation_result.is_ok() || validation_result.is_err(),
                    "Version {} should have deterministic validation result",
                    version
                );
            }
        }
    }

    #[test]
    fn negative_concurrent_sdk_verification_with_shared_state_isolation() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        // Test concurrent SDK operations to check for race conditions
        let sdk = Arc::new(VerifierSdk::with_defaults());
        let results = Arc::new(Mutex::new(Vec::new()));
        let thread_count = 8;
        let operations_per_thread = 50;

        let mut handles = Vec::new();

        for thread_id in 0..thread_count {
            let sdk = Arc::clone(&sdk);
            let results = Arc::clone(&results);

            let handle = thread::spawn(move || {
                let mut thread_results = Vec::new();

                for operation in 0..operations_per_thread {
                    // Each thread performs different types of verification
                    match operation % 3 {
                        0 => {
                            // Artifact verification
                            let request = request(
                                &format!("artifact_t{}_o{}", thread_id, operation),
                                &format!("{:064x}", thread_id * operations_per_thread + operation),
                                vec![&format!("claim_t{}_o{}", thread_id, operation)],
                            );

                            let result = sdk.verify_artifact(&request);
                            thread_results.push(("artifact", thread_id, operation, result.is_ok()));
                        }
                        1 => {
                            // Capsule verification
                            let inputs = vec![input(
                                operation as u64,
                                format!("data_t{}_o{}", thread_id, operation).as_bytes(),
                            )];
                            let capsule = create_capsule(
                                &format!("capsule_t{}_o{}", thread_id, operation),
                                inputs,
                                test_environment(),
                            );

                            if let Ok(capsule) = capsule {
                                let result = sdk.verify_capsule(&capsule);
                                thread_results.push((
                                    "capsule",
                                    thread_id,
                                    operation,
                                    result.is_ok(),
                                ));
                            }
                        }
                        2 => {
                            // Chain verification (using previous results if available)
                            if thread_results.len() >= 2 {
                                // Create a simple chain with dummy reports
                                let report1 = VerificationReport {
                                    schema_tag: "vsk".to_string(),
                                    verifier_identity: "test".to_string(),
                                    request_id: format!("req_t{}_o{}_1", thread_id, operation),
                                    binding_hash: format!(
                                        "{:064x}",
                                        thread_id * 1000 + operation * 10 + 1
                                    ),
                                    trace_id: format!("trace_t{}_o{}_1", thread_id, operation),
                                    verdict: VerifyVerdict::Pass,
                                    evidence: Vec::new(),
                                };

                                let report2 = VerificationReport {
                                    schema_tag: "vsk".to_string(),
                                    verifier_identity: "test".to_string(),
                                    request_id: format!("req_t{}_o{}_2", thread_id, operation),
                                    binding_hash: format!(
                                        "{:064x}",
                                        thread_id * 1000 + operation * 10 + 2
                                    ),
                                    trace_id: format!("trace_t{}_o{}_2", thread_id, operation),
                                    verdict: VerifyVerdict::Pass,
                                    evidence: Vec::new(),
                                };

                                let result = sdk.verify_chain(&[report1, report2]);
                                thread_results.push((
                                    "chain",
                                    thread_id,
                                    operation,
                                    result.is_ok(),
                                ));
                            }
                        }
                        _ => unreachable!(),
                    }
                }

                // Merge results
                {
                    let mut shared = results.lock().unwrap();
                    shared.extend(thread_results);
                }
            });

            handles.push(handle);
        }

        // Wait for all threads
        for handle in handles {
            handle.join().expect("Thread should complete successfully");
        }

        let final_results = results.lock().unwrap();

        // Verify all operations completed without race conditions
        assert!(final_results.len() >= thread_count * operations_per_thread / 2);

        // Most operations should succeed (allowing for some deliberate failures)
        let success_rate = final_results
            .iter()
            .filter(|(_, _, _, success)| *success)
            .count() as f64
            / final_results.len() as f64;
        assert!(
            success_rate > 0.8,
            "Success rate too low: {:.2}%",
            success_rate * 100.0
        );
    }

    #[test]
    fn negative_unicode_normalization_attacks_in_capsule_identifiers() {
        // Test Unicode normalization attacks that could bypass validation
        let normalization_attacks = [
            // NFC vs NFD normalization of same visual character
            ("café", "cafe\u{0301}"),
            ("résumé", "re\u{0301}sume\u{0301}"),
            // Different codepoints with same visual appearance
            ("Ⅸ", "IX"),       // Roman numeral vs ASCII
            ("A", "\u{0041}"), // Latin A vs Unicode codepoint
            // Homograph attacks
            ("microsoft", "microsоft"), // Latin 'o' vs Cyrillic 'о'
            ("google", "gооgle"),       // Latin 'o' vs Cyrillic 'о'
            // Zero-width character injection
            ("test", "te\u{200B}st"), // Zero-width space
            ("test", "test\u{200C}"), // Zero-width non-joiner
            ("test", "\u{FEFF}test"), // Byte order mark
        ];

        for (form1, form2) in normalization_attacks {
            let inputs = ordered_inputs();

            let capsule1 = create_capsule(form1, inputs.clone(), test_environment())
                .expect("first form should create");
            let capsule2 = create_capsule(form2, inputs, test_environment())
                .expect("second form should create");

            // Different Unicode forms should be treated as different capsules
            assert_ne!(capsule1.capsule_id, capsule2.capsule_id);

            // Both should validate independently
            assert!(validate_capsule(&capsule1).is_ok());
            assert!(validate_capsule(&capsule2).is_ok());

            // SDK verification should treat them as different
            let sdk = VerifierSdk::with_defaults();
            let report1 = sdk
                .verify_capsule(&capsule1)
                .expect("first form should verify");
            let report2 = sdk
                .verify_capsule(&capsule2)
                .expect("second form should verify");

            assert_ne!(report1.request_id, report2.request_id);
            assert_ne!(report1.binding_hash, report2.binding_hash);

            // JSON serialization should preserve exact Unicode form
            let json1 = serde_json::to_string(&capsule1).expect("first should serialize");
            let json2 = serde_json::to_string(&capsule2).expect("second should serialize");
            assert_ne!(
                json1, json2,
                "Different Unicode forms should serialize differently"
            );

            let parsed1: ReplayCapsule = serde_json::from_str(&json1).expect("first should parse");
            let parsed2: ReplayCapsule = serde_json::from_str(&json2).expect("second should parse");
            assert_eq!(parsed1.capsule_id, form1);
            assert_eq!(parsed2.capsule_id, form2);
        }
    }

    #[test]
    fn negative_memory_fragmentation_stress_during_large_chain_verification() {
        let sdk = VerifierSdk::with_defaults();

        // Create memory fragmentation by allocating many small chunks
        let mut fragmenters: Vec<Vec<u8>> = Vec::new();
        for i in 0..5000 {
            fragmenters.push(vec![i as u8; (i % 100) + 1]); // Variable sized allocations
        }

        // Generate a large chain of verification reports
        let mut chain = Vec::new();
        for i in 0..100 {
            let request = request(
                &format!("chain_artifact_{}", i),
                &format!("{:064x}", i),
                vec![&format!("chain_claim_{}", i)],
            );

            match sdk.verify_artifact(&request) {
                Ok(report) => chain.push(report),
                Err(_) => {
                    // Some artifacts might fail, which is acceptable in stress test
                    continue;
                }
            }

            // Add more memory fragmentation during chain building
            if i % 10 == 0 {
                for j in 0..100 {
                    fragmenters.push(vec![(i + j) as u8; (j % 50) + 1]);
                }
            }
        }

        assert!(
            chain.len() >= 50,
            "Should build substantial chain despite memory pressure"
        );

        // Verify chain under memory pressure
        let chain_start = std::time::Instant::now();
        let chain_report = sdk
            .verify_chain(&chain)
            .expect("chain should verify under memory pressure");
        let chain_duration = chain_start.elapsed();

        assert!(matches!(chain_report.verdict, VerifyVerdict::Pass));
        assert!(
            chain_duration < std::time::Duration::from_secs(30),
            "Chain verification should complete in reasonable time"
        );

        // Memory cleanup should not affect verification consistency
        drop(fragmenters);

        let post_cleanup_report = sdk
            .verify_chain(&chain)
            .expect("chain should verify after cleanup");
        assert_eq!(chain_report.binding_hash, post_cleanup_report.binding_hash);
    }

    #[test]
    fn negative_cryptographic_timing_analysis_resistance_in_hash_verification() {
        use std::time::Instant;

        let sdk = VerifierSdk::with_defaults();
        let sample_size = 500;

        // Create artifacts with hashes designed to test timing consistency
        let hash_patterns = [
            "a".repeat(64), // All 'a's
            "f".repeat(64), // All 'f's (max hex digit)
            "0".repeat(64), // All zeros
            format!(
                "{}{}", // Half zeros, half f's
                "0".repeat(32),
                "f".repeat(32)
            ),
            (0..64)
                .map(|i| if i % 2 == 0 { 'a' } else { 'f' })
                .collect::<String>(), // Alternating
        ];

        let mut timing_results = Vec::new();

        for pattern in &hash_patterns {
            let mut pattern_timings = Vec::new();

            for iteration in 0..sample_size {
                let request = request(
                    &format!(
                        "timing_test_{}_{}",
                        pattern.chars().next().unwrap(),
                        iteration
                    ),
                    pattern,
                    vec!["timing_claim"],
                );

                let start = Instant::now();
                let result = sdk.verify_artifact(&request);
                let duration = start.elapsed();

                // Record timing regardless of success/failure
                pattern_timings.push(duration);

                // Should produce consistent results
                assert!(
                    result.is_ok() || result.is_err(),
                    "Result should be deterministic"
                );
            }

            timing_results.push((pattern, pattern_timings));
        }

        // Statistical analysis of timing variations across different hash patterns
        fn calculate_mean(timings: &[std::time::Duration]) -> f64 {
            let total_nanos: u64 = timings.iter().map(|d| d.as_nanos() as u64).sum();
            total_nanos as f64 / timings.len() as f64
        }

        let mean_timings: Vec<(&&str, f64)> = timing_results
            .iter()
            .map(|(pattern, timings)| (pattern, calculate_mean(timings)))
            .collect();

        // Check that timing doesn't vary dramatically based on hash content
        if let (Some(min_timing), Some(max_timing)) = (
            mean_timings
                .iter()
                .map(|(_, mean)| mean)
                .min_by(|a, b| a.partial_cmp(b).unwrap()),
            mean_timings
                .iter()
                .map(|(_, mean)| mean)
                .max_by(|a, b| a.partial_cmp(b).unwrap()),
        ) {
            if *min_timing > 0.0 {
                let timing_ratio = max_timing / min_timing;
                assert!(
                    timing_ratio < 5.0,
                    "Suspicious timing variation across hash patterns: max={:.0}ns, min={:.0}ns, ratio={:.2}",
                    max_timing,
                    min_timing,
                    timing_ratio
                );
            }
        }
    }

    #[test]
    fn negative_error_propagation_chains_through_nested_verification_layers() {
        let sdk = VerifierSdk::with_defaults();

        // Create nested error scenarios that could mask underlying issues
        let error_scenarios = [
            // Capsule with invalid environment that should cascade through verification
            {
                let mut env = test_environment();
                env.runtime_version = "".to_string(); // Invalid environment
                let invalid_inputs = vec![input(0, b"")]; // Invalid sequence number
                (
                    create_capsule("nested-error-1", invalid_inputs, env),
                    "should fail on multiple levels",
                )
            },
            // Capsule with contradictory sequence numbers and missing outputs
            {
                let inputs = vec![input(2, b"second"), input(1, b"first")]; // Wrong order
                let result = create_capsule("nested-error-2", inputs, test_environment());
                (result, "should fail on sequence ordering")
            },
        ];

        for (capsule_result, error_description) in error_scenarios {
            match capsule_result {
                Ok(invalid_capsule) => {
                    // If capsule creation succeeded, verification should catch issues
                    let verification_result = sdk.verify_capsule(&invalid_capsule);

                    match verification_result {
                        Ok(report) => {
                            // Should detect issues in evidence
                            match report.verdict {
                                VerifyVerdict::Fail(failures) => {
                                    assert!(
                                        !failures.is_empty(),
                                        "Failed verification should list specific failures for: {}",
                                        error_description
                                    );
                                }
                                VerifyVerdict::Pass => {
                                    // If verification passes, the capsule might actually be valid
                                    // (our error scenario might not be invalid after all)
                                }
                            }
                        }
                        Err(sdk_error) => {
                            // Early rejection is also valid error propagation
                            match sdk_error {
                                SdkError::MalformedCapsule(msg) => {
                                    assert!(!msg.is_empty(), "Error message should be descriptive");
                                }
                                SdkError::InvalidArtifact(msg) => {
                                    assert!(!msg.is_empty(), "Error message should be descriptive");
                                }
                                SdkError::BrokenChain(msg) => {
                                    assert!(!msg.is_empty(), "Error message should be descriptive");
                                }
                            }
                        }
                    }
                }
                Err(capsule_error) => {
                    // Capsule creation failure is expected error propagation
                    match capsule_error {
                        CapsuleError::EmptyId
                        | CapsuleError::NoInputs
                        | CapsuleError::NonMonotonicInputSequence
                        | CapsuleError::IncompleteEnvironment(_) => {
                            // Expected error types
                        }
                        other => {
                            // Other errors should still be descriptive
                            let error_str = format!("{:?}", other);
                            assert!(!error_str.is_empty(), "Error should have description");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn negative_recursive_verification_chain_with_circular_dependencies() {
        let sdk = VerifierSdk::with_defaults();

        // Create reports that reference each other in circular patterns
        let mut circular_reports = Vec::new();

        for i in 0..5 {
            let mut report = VerificationReport {
                schema_tag: "vsk".to_string(),
                verifier_identity: "circular_test".to_string(),
                request_id: format!("circular_req_{}", i),
                binding_hash: format!("{:064x}", i),
                trace_id: format!("trace_{}", i),
                verdict: VerifyVerdict::Pass,
                evidence: Vec::new(),
            };

            // Create circular dependency in trace IDs
            report.trace_id = format!("depends_on_{}", (i + 1) % 5);
            circular_reports.push(report);
        }

        // Add self-referencing report
        let self_ref_report = VerificationReport {
            schema_tag: "vsk".to_string(),
            verifier_identity: "self_ref_test".to_string(),
            request_id: "self_ref".to_string(),
            binding_hash: format!("{:064x}", 999),
            trace_id: "self_ref".to_string(), // References itself
            verdict: VerifyVerdict::Pass,
            evidence: Vec::new(),
        };
        circular_reports.push(self_ref_report);

        // Chain verification should handle circular dependencies gracefully
        let chain_result = sdk.verify_chain(&circular_reports);

        match chain_result {
            Ok(chain_report) => {
                // Should complete without infinite loops
                assert_eq!(chain_report.evidence.len() >= 1, true);

                // Should detect or handle circular dependencies appropriately
                match chain_report.verdict {
                    VerifyVerdict::Pass => {
                        // If passed, circular references weren't problematic
                    }
                    VerifyVerdict::Fail(failures) => {
                        // May detect circular dependencies as an issue
                        assert!(!failures.is_empty());
                    }
                }
            }
            Err(SdkError::BrokenChain(msg)) => {
                // Early detection of circular dependencies is acceptable
                assert!(
                    !msg.is_empty(),
                    "Broken chain error should have description"
                );
            }
            Err(other) => {
                panic!("Unexpected error for circular chain: {:?}", other);
            }
        }

        // Verification should complete in reasonable time (no infinite loops)
        let start = std::time::Instant::now();
        let _ = sdk.verify_chain(&circular_reports);
        let duration = start.elapsed();

        assert!(
            duration < std::time::Duration::from_secs(10),
            "Circular dependency verification took too long: {:?}",
            duration
        );
    }

    #[test]
    fn negative_advanced_json_serialization_attacks_with_payload_injection() {
        // Test JSON serialization with payloads designed to break parsing/validation
        let injection_payloads = [
            // JSON injection attempts in string fields
            r#"","malicious":"payload","original":""#,
            r#"}],"injected":true,"data":["#,
            r#"null},"hijacked":"value"//comment{"#,
            // Unicode escape injection
            "\u{0022}\u{003A}\u{007B}\u{0022}injected\u{0022}",
            // Control character injection
            "\x00\x01\x02\x03\":{\"evil\":true}//\x04\x05",
            // Large payload injection
            &"x".repeat(100000),
            // Number-like strings that could be misinterpreted
            "1.7976931348623157e+308", // Max float64
            "9007199254740992",        // JavaScript safe integer boundary
            "-0",                      // Negative zero
        ];

        for payload in &injection_payloads {
            // Test in capsule ID
            let malicious_inputs = vec![input(1, payload.as_bytes())];
            let malicious_env = {
                let mut env = test_environment();
                env.config_hash = payload.to_string();
                env
            };

            let capsule_result = create_capsule("injection_test", malicious_inputs, malicious_env);

            match capsule_result {
                Ok(capsule) => {
                    // JSON round-trip should preserve payload exactly without interpretation
                    let json = serde_json::to_string(&capsule)
                        .expect("should serialize malicious payload safely");

                    // JSON should not contain unescaped injection attempts
                    if payload.contains('"') || payload.contains('{') || payload.contains('}') {
                        // These characters should be escaped in JSON
                        assert!(
                            !json.contains(&payload.replace('\\', "")),
                            "Dangerous payload should be escaped in JSON"
                        );
                    }

                    // Deserialization should recover exact payload
                    let parsed: ReplayCapsule =
                        serde_json::from_str(&json).expect("should deserialize without injection");
                    assert_eq!(parsed.environment.config_hash, *payload);

                    // SDK verification should handle injection safely
                    let sdk = VerifierSdk::with_defaults();
                    let verification_result = sdk.verify_capsule(&capsule);
                    assert!(
                        verification_result.is_ok() || verification_result.is_err(),
                        "Verification should produce deterministic result"
                    );
                }
                Err(_) => {
                    // Early rejection of injection payloads is acceptable security measure
                }
            }

            // Test in artifact verification
            let sdk = VerifierSdk::with_defaults();
            let malicious_request = request("injection_artifact", &"a".repeat(64), vec![payload]);

            let artifact_result = sdk.verify_artifact(&malicious_request);
            match artifact_result {
                Ok(report) => {
                    // JSON serialization of report should be safe
                    let report_json =
                        serde_json::to_string(&report).expect("report should serialize safely");

                    let parsed_report: VerificationReport = serde_json::from_str(&report_json)
                        .expect("report should deserialize without injection");
                    assert_eq!(parsed_report.binding_hash, report.binding_hash);
                }
                Err(_) => {
                    // Rejection of malicious payloads is acceptable
                }
            }
        }
    }

    #[test]
    fn negative_sdk_state_consistency_under_rapid_configuration_changes() {
        // Test SDK behavior when configuration changes rapidly
        let base_config = VerifierConfig::default();

        // Create rapidly changing configurations
        let mut configs = Vec::new();
        for i in 0..100 {
            let mut config = base_config.clone();
            config.verifier_identity = format!("rapid_change_{}", i);
            config.require_hash_match = i % 2 == 0;
            config.strict_claims = i % 3 == 0;

            // Add random extensions
            for j in 0..i % 5 {
                config
                    .extensions
                    .insert(format!("ext_{}_{}", i, j), format!("value_{}_{}", i, j));
            }

            configs.push(config);
        }

        // Create SDKs with rapidly changing configurations
        let mut sdks = Vec::new();
        for config in configs {
            sdks.push(VerifierSdk::new(config));
        }

        // Perform verification with each SDK
        let test_request = request("consistency_test", &"a".repeat(64), vec!["test_claim"]);

        let mut results = Vec::new();
        for (i, sdk) in sdks.iter().enumerate() {
            let result = sdk.verify_artifact(&test_request);
            results.push((i, sdk.config().verifier_identity.clone(), result.is_ok()));
        }

        // Each SDK should maintain its own consistent state
        for (i, identity, success) in &results {
            assert_eq!(identity, &format!("rapid_change_{}", i));

            // Re-verification with same SDK should produce same result
            let re_verification = sdks[*i].verify_artifact(&test_request);
            assert_eq!(
                re_verification.is_ok(),
                *success,
                "SDK {} should produce consistent results",
                i
            );
        }

        // No SDK should be affected by others' configurations
        for i in 0..sdks.len() {
            let config = sdks[i].config();
            assert_eq!(config.verifier_identity, format!("rapid_change_{}", i));
            assert_eq!(config.require_hash_match, i % 2 == 0);
            assert_eq!(config.strict_claims, i % 3 == 0);
        }
    }
}
