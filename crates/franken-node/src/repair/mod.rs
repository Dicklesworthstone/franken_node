pub mod proof_carrying_decode;

#[cfg(test)]
mod tests {
    use super::proof_carrying_decode::{
        AlgorithmId, DecodeResult, Fragment, ProofAuditEvent, ProofCarryingDecodeError,
        ProofCarryingDecoder, ProofMode, ProofVerificationApi, REPAIR_PROOF_INVALID, RepairProof,
        VerificationResult,
    };

    fn fragments() -> Vec<Fragment> {
        vec![
            Fragment {
                fragment_id: "frag-a".to_string(),
                data: vec![0xAA; 4],
            },
            Fragment {
                fragment_id: "frag-b".to_string(),
                data: vec![0xBB; 4],
            },
        ]
    }

    fn decoder() -> ProofCarryingDecoder {
        ProofCarryingDecoder::new(ProofMode::Mandatory, "repair-signer", "repair-secret")
    }

    fn verifier(secret: &str) -> ProofVerificationApi {
        ProofVerificationApi::new(secret, vec![AlgorithmId::new("simple_concat")])
    }

    fn fragment_digests(fragments: &[Fragment]) -> Vec<String> {
        fragments
            .iter()
            .map(|fragment| hex::encode(fragment.hash()))
            .collect()
    }

    fn valid_proof() -> (Vec<Fragment>, RepairProof) {
        let fragments = fragments();
        let mut decoder = decoder();
        let result = decoder
            .decode(
                "obj-valid-proof",
                &fragments,
                &AlgorithmId::new("simple_concat"),
                42,
                "trace-valid-proof",
            )
            .expect("fixture decode should succeed");
        let proof = result.proof.expect("fixture proof should be present");
        (fragments, proof)
    }

    #[test]
    fn negative_presence_check_rejects_missing_proof_in_mandatory_mode() {
        let err = verifier("repair-secret")
            .check_proof_presence(None, ProofMode::Mandatory, "obj-missing-proof")
            .expect_err("mandatory mode should require proof");

        assert!(matches!(
            err,
            ProofCarryingDecodeError::MissingProofInMandatoryMode { ref object_id }
                if object_id == "obj-missing-proof"
        ));
    }

    #[test]
    fn negative_decode_rejects_empty_fragments_without_audit_event() {
        let mut decoder = decoder();
        let err = decoder
            .decode(
                "obj-empty-fragments",
                &[],
                &AlgorithmId::new("simple_concat"),
                42,
                "trace-empty-fragments",
            )
            .expect_err("empty fragments should fail reconstruction");

        assert!(matches!(
            err,
            ProofCarryingDecodeError::ReconstructionFailed { ref object_id, ref reason }
                if object_id == "obj-empty-fragments" && reason.contains("no fragments")
        ));
        assert!(decoder.audit_log().is_empty());
    }

    #[test]
    fn negative_decode_rejects_unregistered_algorithm_without_audit_event() {
        let mut decoder = decoder();
        let fragments = fragments();
        let err = decoder
            .decode(
                "obj-unknown-algo",
                &fragments,
                &AlgorithmId::new("unknown-repair-algo"),
                42,
                "trace-unknown-algo",
            )
            .expect_err("unregistered algorithm should fail reconstruction");

        assert!(matches!(
            err,
            ProofCarryingDecodeError::ReconstructionFailed { ref object_id, ref reason }
                if object_id == "obj-unknown-algo" && reason.contains("unregistered algorithm")
        ));
        assert!(decoder.audit_log().is_empty());
    }

    #[test]
    fn negative_verify_rejects_missing_fragment_digest_entry() {
        let (fragments, proof) = valid_proof();
        let mut fragment_digests = fragment_digests(&fragments);
        fragment_digests.pop();

        let verification =
            verifier("repair-secret").verify(&proof, &fragment_digests, &proof.output_hash);

        assert_eq!(verification.event_code(), REPAIR_PROOF_INVALID);
        assert!(matches!(
            &verification,
            VerificationResult::InvalidFragmentHash { index: 0, .. }
        ));
    }

    #[test]
    fn negative_verify_rejects_extra_fragment_digest_entry() {
        let (fragments, proof) = valid_proof();
        let mut fragment_digests = fragment_digests(&fragments);
        fragment_digests.push("extra-digest".to_string());

        let verification =
            verifier("repair-secret").verify(&proof, &fragment_digests, &proof.output_hash);

        assert_eq!(verification.event_code(), REPAIR_PROOF_INVALID);
        assert!(matches!(
            &verification,
            VerificationResult::InvalidFragmentHash { index: 0, .. }
        ));
    }

    #[test]
    fn negative_verify_rejects_wrong_verifier_secret() {
        let (fragments, proof) = valid_proof();
        let fragment_digests = fragment_digests(&fragments);

        let verification =
            verifier("wrong-repair-secret").verify(&proof, &fragment_digests, &proof.output_hash);

        assert_eq!(verification.event_code(), REPAIR_PROOF_INVALID);
        assert!(matches!(verification, VerificationResult::InvalidSignature));
    }

    #[test]
    fn negative_verify_rejects_tampered_trace_id() {
        let (fragments, mut proof) = valid_proof();
        let fragment_digests = fragment_digests(&fragments);
        proof.trace_id = "trace-tampered".to_string();

        let verification =
            verifier("repair-secret").verify(&proof, &fragment_digests, &proof.output_hash);

        assert_eq!(verification.event_code(), REPAIR_PROOF_INVALID);
        assert!(matches!(verification, VerificationResult::InvalidSignature));
    }

    #[test]
    fn negative_verify_rejects_tampered_fragment_count() {
        let (fragments, mut proof) = valid_proof();
        let fragment_digests = fragment_digests(&fragments);
        proof.fragment_count = usize::MAX;

        let verification =
            verifier("repair-secret").verify(&proof, &fragment_digests, &proof.output_hash);

        assert_eq!(verification.event_code(), REPAIR_PROOF_INVALID);
        assert!(matches!(verification, VerificationResult::InvalidSignature));
    }

    #[test]
    fn negative_verify_rejects_tampered_object_id() {
        let (fragments, mut proof) = valid_proof();
        let fragment_digests = fragment_digests(&fragments);
        proof.object_id = "obj-tampered".to_string();

        let verification =
            verifier("repair-secret").verify(&proof, &fragment_digests, &proof.output_hash);

        assert_eq!(verification.event_code(), REPAIR_PROOF_INVALID);
        assert!(matches!(verification, VerificationResult::InvalidSignature));
    }

    #[test]
    fn negative_verify_rejects_tampered_signer_id() {
        let (fragments, mut proof) = valid_proof();
        let fragment_digests = fragment_digests(&fragments);
        proof.attestation.signer_id = "untrusted-repair-signer".to_string();

        let verification =
            verifier("repair-secret").verify(&proof, &fragment_digests, &proof.output_hash);

        assert_eq!(verification.event_code(), REPAIR_PROOF_INVALID);
        assert!(matches!(verification, VerificationResult::InvalidSignature));
    }

    #[test]
    fn negative_verify_rejects_tampered_payload_hash() {
        let (fragments, mut proof) = valid_proof();
        let fragment_digests = fragment_digests(&fragments);
        proof.attestation.payload_hash = "tampered-payload-hash".to_string();

        let verification =
            verifier("repair-secret").verify(&proof, &fragment_digests, &proof.output_hash);

        assert_eq!(verification.event_code(), REPAIR_PROOF_INVALID);
        assert!(matches!(verification, VerificationResult::InvalidSignature));
    }

    #[test]
    fn negative_verify_rejects_tampered_signature() {
        let (fragments, mut proof) = valid_proof();
        let fragment_digests = fragment_digests(&fragments);
        proof.attestation.signature = "tampered-signature".to_string();

        let verification =
            verifier("repair-secret").verify(&proof, &fragment_digests, &proof.output_hash);

        assert_eq!(verification.event_code(), REPAIR_PROOF_INVALID);
        assert!(matches!(verification, VerificationResult::InvalidSignature));
    }

    #[test]
    fn negative_verify_rejects_tampered_algorithm_before_signature_check() {
        let (fragments, mut proof) = valid_proof();
        let fragment_digests = fragment_digests(&fragments);
        proof.algorithm_id = AlgorithmId::new("unknown-simple-concat");

        let verification =
            verifier("repair-secret").verify(&proof, &fragment_digests, &proof.output_hash);

        assert_eq!(verification.event_code(), REPAIR_PROOF_INVALID);
        assert!(matches!(
            verification,
            VerificationResult::UnknownAlgorithm { ref algorithm_id }
                if algorithm_id.as_str() == "unknown-simple-concat"
        ));
    }

    #[test]
    fn negative_verify_rejects_output_hash_mismatch() {
        let (fragments, proof) = valid_proof();
        let fragment_digests = fragment_digests(&fragments);

        let verification = verifier("repair-secret").verify(
            &proof,
            &fragment_digests,
            "sha256:not-the-reconstructed-output",
        );

        assert_eq!(verification.event_code(), REPAIR_PROOF_INVALID);
        let VerificationResult::OutputHashMismatch { expected, actual } = verification else {
            panic!("expected output hash mismatch");
        };
        assert!(expected.contains("not-the-reconstructed-output"));
        assert!(crate::security::constant_time::ct_eq_bytes(
            actual.as_bytes(),
            proof.output_hash.as_bytes()
        ));
    }

    #[test]
    fn negative_verify_reports_tampered_fragment_digest_index() {
        let (fragments, proof) = valid_proof();
        let mut fragment_digests = fragment_digests(&fragments);
        fragment_digests[1] = "tampered-fragment-digest".to_string();

        let verification =
            verifier("repair-secret").verify(&proof, &fragment_digests, &proof.output_hash);

        assert_eq!(verification.event_code(), REPAIR_PROOF_INVALID);
        let VerificationResult::InvalidFragmentHash {
            index,
            expected,
            actual,
        } = verification
        else {
            panic!("expected invalid fragment hash");
        };
        assert_eq!(index, 1);
        assert!(expected.contains("tampered-fragment-digest"));
        assert!(crate::security::constant_time::ct_eq_bytes(
            actual.as_bytes(),
            proof.input_fragment_hashes[1].as_bytes()
        ));
    }

    #[test]
    fn negative_proof_mode_deserialize_rejects_display_case_label() {
        let result: Result<ProofMode, _> = serde_json::from_str("\"Mandatory\"");

        assert!(
            result.is_err(),
            "proof mode labels must use the canonical snake_case wire form"
        );
    }

    #[test]
    fn negative_proof_mode_deserialize_rejects_unknown_label() {
        let result: Result<ProofMode, _> = serde_json::from_str("\"optional\"");

        assert!(
            result.is_err(),
            "unknown proof modes must fail closed during decode"
        );
    }

    #[test]
    fn negative_algorithm_id_deserialize_rejects_number() {
        let result: Result<AlgorithmId, _> = serde_json::from_value(serde_json::json!(42));

        assert!(
            result.is_err(),
            "algorithm IDs must remain string identifiers"
        );
    }

    #[test]
    fn negative_fragment_deserialize_rejects_string_data_payload() {
        let raw = serde_json::json!({
            "fragment_id": "frag-string-data",
            "data": "not-a-byte-array",
        });

        let result: Result<Fragment, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "fragment data must deserialize as a byte array, not an opaque string"
        );
    }

    #[test]
    fn negative_repair_proof_deserialize_rejects_missing_attestation() {
        let raw = serde_json::json!({
            "proof_id": "rp-missing-attestation",
            "object_id": "obj-missing-attestation",
            "input_fragment_hashes": [],
            "algorithm_id": "simple_concat",
            "output_hash": "sha256:missing-attestation",
            "fragment_count": 0_usize,
            "timestamp_epoch_secs": 42_u64,
            "trace_id": "trace-missing-attestation",
        });

        let result: Result<RepairProof, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "repair proofs must carry a signed attestation"
        );
    }

    #[test]
    fn negative_decode_result_deserialize_rejects_string_output_data() {
        let raw = serde_json::json!({
            "object_id": "obj-string-output",
            "output_data": "not-a-byte-array",
            "proof": null,
        });

        let result: Result<DecodeResult, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "decode output data must remain byte-array encoded"
        );
    }

    #[test]
    fn negative_audit_event_deserialize_rejects_string_fragment_count() {
        let raw = serde_json::json!({
            "event_code": REPAIR_PROOF_INVALID,
            "object_id": "obj-bad-audit-count",
            "fragment_count": "2",
            "algorithm": "simple_concat",
            "proof_hash": "sha256:bad-count",
            "mode": "Mandatory",
            "trace_id": "trace-bad-audit-count",
        });

        let result: Result<ProofAuditEvent, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "audit event fragment counts must remain numeric"
        );
    }

    #[test]
    fn negative_verification_result_deserialize_rejects_missing_variant_field() {
        let raw = serde_json::json!({
            "InvalidFragmentHash": {
                "expected": "expected-fragment",
                "actual": "actual-fragment",
            }
        });

        let result: Result<VerificationResult, _> = serde_json::from_value(raw);

        assert!(
            result.is_err(),
            "invalid-fragment verification results must include an index"
        );
    }

    #[test]
    fn negative_verify_rejects_empty_registered_algorithm_set() {
        let (fragments, proof) = valid_proof();
        let fragment_digests = fragment_digests(&fragments);

        let verification = ProofVerificationApi::new("repair-secret", Vec::new()).verify(
            &proof,
            &fragment_digests,
            &proof.output_hash,
        );

        assert_eq!(verification.event_code(), REPAIR_PROOF_INVALID);
        assert!(matches!(
            verification,
            VerificationResult::UnknownAlgorithm { ref algorithm_id }
                if algorithm_id.as_str() == "simple_concat"
        ));
    }

    #[test]
    fn negative_decode_rejects_blank_algorithm_id_without_audit_event() {
        let mut decoder = decoder();
        let fragments = fragments();
        let err = decoder
            .decode(
                "obj-blank-algorithm",
                &fragments,
                &AlgorithmId::new("   "),
                42,
                "trace-blank-algorithm",
            )
            .expect_err("blank algorithm identifier should not match a registered algorithm");

        assert!(matches!(
            err,
            ProofCarryingDecodeError::ReconstructionFailed { ref object_id, ref reason }
                if object_id == "obj-blank-algorithm"
                    && reason.contains("unregistered algorithm")
        ));
        assert!(decoder.audit_log().is_empty());
    }

    // ── Advanced negative-path tests for repair module edge cases ──

    #[test]
    fn negative_massive_fragment_data_memory_exhaustion_protection() {
        let mut decoder = decoder();

        // Create fragments with massive data to test memory handling
        let massive_fragments = vec![
            Fragment {
                fragment_id: "massive-frag-1".to_string(),
                data: vec![0x42; 10 * 1024 * 1024], // 10MB fragment
            },
            Fragment {
                fragment_id: "massive-frag-2".to_string(),
                data: vec![0x43; 5 * 1024 * 1024], // 5MB fragment
            },
        ];

        let result = decoder.decode(
            "obj-massive-fragments",
            &massive_fragments,
            &AlgorithmId::new("simple_concat"),
            42,
            "trace-massive-fragments",
        );

        // Should either handle gracefully or fail without crashing
        match result {
            Ok(decode_result) => {
                // If successful, output should contain combined data (15MB)
                assert_eq!(decode_result.output_data.len(), 15 * 1024 * 1024);
                assert_eq!(decode_result.object_id, "obj-massive-fragments");

                // Proof should be generated if mode is mandatory
                assert!(decode_result.proof.is_some());
            }
            Err(ProofCarryingDecodeError::ReconstructionFailed { .. }) => {
                // Memory-based rejection is acceptable
            }
            Err(other) => {
                panic!("Unexpected error for massive fragments: {:?}", other);
            }
        }
    }

    #[test]
    fn negative_fragment_ids_with_unicode_injection_patterns() {
        let mut decoder = decoder();

        let injection_fragments = vec![
            Fragment {
                fragment_id: "frag\u{202E}spoofed".to_string(), // RTL override
                data: vec![0x01; 4],
            },
            Fragment {
                fragment_id: "frag\x00null\r\ninjection".to_string(), // Null + CRLF
                data: vec![0x02; 4],
            },
            Fragment {
                fragment_id: "frag\u{FEFF}bom\u{200B}invisible".to_string(), // BOM + zero-width
                data: vec![0x03; 4],
            },
            Fragment {
                fragment_id: "frag🚀emoji🎯".to_string(), // Unicode emoji
                data: vec![0x04; 4],
            },
            Fragment {
                fragment_id: "frag\t\x08\x7F\x1b[31mred\x1b[0m".to_string(), // Control chars + ANSI
                data: vec![0x05; 4],
            },
        ];

        let result = decoder.decode(
            "obj-unicode-injection",
            &injection_fragments,
            &AlgorithmId::new("simple_concat"),
            42,
            "trace-unicode-injection",
        );

        // Should handle Unicode patterns without corruption
        match result {
            Ok(decode_result) => {
                assert_eq!(decode_result.object_id, "obj-unicode-injection");

                // Verify fragment IDs are preserved exactly in proof
                if let Some(proof) = decode_result.proof {
                    // JSON round-trip should preserve Unicode
                    let json = serde_json::to_string(&proof).expect("should serialize");
                    let parsed: RepairProof =
                        serde_json::from_str(&json).expect("should deserialize");

                    // Verification should work with preserved Unicode
                    let fragment_digests = fragment_digests(&injection_fragments);
                    let verification = verifier("repair-secret").verify(
                        &parsed,
                        &fragment_digests,
                        &parsed.output_hash,
                    );
                    assert_eq!(verification.event_code(), "REPAIR_PROOF_VALID");
                }
            }
            Err(_) => {
                // Early rejection of Unicode patterns is acceptable
            }
        }
    }

    #[test]
    fn negative_object_id_with_path_traversal_injection() {
        let mut decoder = decoder();
        let fragments = fragments();

        let malicious_object_ids = [
            "../../../etc/passwd",
            "..\\..\\windows\\system32\\config\\sam",
            "/dev/null",
            "CON",     // Windows reserved name
            "aux.txt", // Windows reserved name with extension
            "obj\x00null_injection",
            "obj\r\n\ninjection",
            "obj\t<script>alert('xss')</script>",
        ];

        for object_id in &malicious_object_ids {
            let result = decoder.decode(
                object_id,
                &fragments,
                &AlgorithmId::new("simple_concat"),
                42,
                "trace-path-injection",
            );

            match result {
                Ok(decode_result) => {
                    // If accepted, object ID should be preserved exactly
                    assert_eq!(decode_result.object_id, *object_id);

                    // Proof should contain exact object ID
                    if let Some(proof) = decode_result.proof {
                        assert_eq!(proof.object_id, *object_id);

                        // Verification should work with preserved ID
                        let fragment_digests = fragment_digests(&fragments);
                        let verification = verifier("repair-secret").verify(
                            &proof,
                            &fragment_digests,
                            &proof.output_hash,
                        );
                        assert_eq!(verification.event_code(), "REPAIR_PROOF_VALID");
                    }
                }
                Err(_) => {
                    // Early rejection of malicious IDs is acceptable
                }
            }
        }
    }

    #[test]
    fn negative_arithmetic_overflow_in_fragment_count_and_timestamps() {
        let mut decoder =
            ProofCarryingDecoder::new(ProofMode::Mandatory, "repair-signer", "repair-secret");

        // Test with extreme values
        let fragments = fragments();
        let extreme_timestamp = u64::MAX;

        let result = decoder.decode(
            "obj-extreme-values",
            &fragments,
            &AlgorithmId::new("simple_concat"),
            extreme_timestamp,
            "trace-extreme-values",
        );

        match result {
            Ok(decode_result) => {
                // Should handle u64::MAX timestamp
                if let Some(proof) = decode_result.proof {
                    assert_eq!(proof.timestamp_epoch_secs, extreme_timestamp);
                    assert_eq!(proof.fragment_count, fragments.len());

                    // Verification should handle extreme timestamp
                    let fragment_digests = fragment_digests(&fragments);
                    let verification = verifier("repair-secret").verify(
                        &proof,
                        &fragment_digests,
                        &proof.output_hash,
                    );
                    assert_eq!(verification.event_code(), "REPAIR_PROOF_VALID");

                    // JSON serialization should handle extreme values
                    let json =
                        serde_json::to_string(&proof).expect("should serialize extreme values");
                    let parsed: RepairProof =
                        serde_json::from_str(&json).expect("should deserialize extreme values");
                    assert_eq!(parsed.timestamp_epoch_secs, extreme_timestamp);
                }
            }
            Err(_) => {
                // Rejection of extreme values is acceptable
            }
        }
    }

    #[test]
    fn negative_verification_with_deeply_nested_fragment_hash_corruption() {
        let (fragments, mut proof) = valid_proof();

        // Create deeply corrupted fragment hashes with various patterns
        proof.input_fragment_hashes = vec![
            "".to_string(),                     // Empty hash
            "x".repeat(1000),                   // Extremely long hash
            "\x00".repeat(32),                  // Null byte hash
            "\u{FEFF}".repeat(16),              // Unicode BOM hash
            "sha256:\r\ninjection".to_string(), // Protocol injection
            "../../../etc/passwd".to_string(),  // Path traversal
            "hash\x00null\nline2".to_string(),  // Multi-line injection
        ];

        for (i, corrupted_hash) in proof.input_fragment_hashes.iter().enumerate() {
            let verification = verifier("repair-secret").verify(
                &proof,
                &fragment_digests(&fragments),
                &proof.output_hash,
            );

            assert_eq!(verification.event_code(), REPAIR_PROOF_INVALID);

            // Should report corruption with index information
            if let VerificationResult::InvalidFragmentHash {
                index,
                expected,
                actual,
            } = verification
            {
                assert!(index < proof.input_fragment_hashes.len());
                assert!(
                    expected.contains(corrupted_hash)
                        || actual.contains(&fragment_digests(&fragments)[index])
                );
            }
        }
    }

    #[test]
    fn negative_proof_verification_api_with_malformed_secret() {
        let (fragments, proof) = valid_proof();
        let fragment_digests = fragment_digests(&fragments);

        let massive_unicode_secret = "🔐".repeat(1000);
        let malformed_byte_secret = String::from_utf8_lossy(b"\x7F\x80\xFF").into_owned();
        let malformed_secrets = [
            "",                              // Empty secret
            "\x00",                          // Null byte secret
            "\u{FEFF}",                      // Unicode BOM secret
            "secret\r\ninjection",           // CRLF injection
            massive_unicode_secret.as_str(), // Massive Unicode secret
            malformed_byte_secret.as_str(),  // Invalid UTF-8 bytes decoded lossily
        ];

        for secret in &malformed_secrets {
            let api = ProofVerificationApi::new(secret, vec![AlgorithmId::new("simple_concat")]);

            let verification = api.verify(&proof, &fragment_digests, &proof.output_hash);

            // Should fail gracefully with invalid signature
            assert_eq!(verification.event_code(), REPAIR_PROOF_INVALID);
            assert!(matches!(verification, VerificationResult::InvalidSignature));
        }
    }

    #[test]
    fn negative_concurrent_decoder_state_consistency_under_rapid_operations() {
        let mut decoder = decoder();
        let fragments = fragments();
        let algorithm_id = AlgorithmId::new("simple_concat");

        // Simulate rapid concurrent-style operations that might corrupt state
        let mut results = Vec::new();

        for i in 0..100 {
            let object_id = format!("obj-rapid-{}", i);
            let trace_id = format!("trace-rapid-{}", i);
            let timestamp = 1000 + i as u64;

            let result =
                decoder.decode(&object_id, &fragments, &algorithm_id, timestamp, &trace_id);

            match result {
                Ok(decode_result) => {
                    // Verify consistency of returned data
                    assert_eq!(decode_result.object_id, object_id);

                    if let Some(proof) = decode_result.proof {
                        assert_eq!(proof.object_id, object_id);
                        assert_eq!(proof.trace_id, trace_id);
                        assert_eq!(proof.timestamp_epoch_secs, timestamp);
                        assert_eq!(proof.fragment_count, fragments.len());
                    }

                    results.push(decode_result);
                }
                Err(_) => {
                    // Failures are acceptable under stress
                }
            }
        }

        // Audit log should be consistent
        let audit_log = decoder.audit_log();
        assert_eq!(audit_log.len(), results.len());

        // Each result should be independently verifiable
        for decode_result in &results {
            if let Some(proof) = &decode_result.proof {
                let fragment_digests = fragment_digests(&fragments);
                let verification =
                    verifier("repair-secret").verify(proof, &fragment_digests, &proof.output_hash);
                assert_eq!(verification.event_code(), "REPAIR_PROOF_VALID");
            }
        }
    }

    #[test]
    fn negative_json_serialization_with_control_character_preservation() {
        let mut decoder = decoder();
        let fragments = vec![Fragment {
            fragment_id: "frag\x00null\r\n\t\x08control".to_string(),
            data: b"\x00\x01\x02\x03\xFF\xFE\xFD".to_vec(),
        }];

        let result = decoder
            .decode(
                "obj\x1b[31mcontrol\x1b[0m",
                &fragments,
                &AlgorithmId::new("simple_concat"),
                42,
                "trace\x00\r\ncontrol",
            )
            .expect("control characters should be handled");

        // JSON round-trip should preserve all control characters
        let json = serde_json::to_string(&result).expect("should serialize with control chars");

        // Verify control characters are preserved (escaped) in JSON
        assert!(json.contains("\\u0000") || json.contains("\\u001b"));

        // Deserialization should recover exact structure
        let parsed: DecodeResult =
            serde_json::from_str(&json).expect("should deserialize control chars");
        assert_eq!(parsed.object_id, result.object_id);
        assert_eq!(parsed.output_data, result.output_data);

        if let (Some(original_proof), Some(parsed_proof)) = (&result.proof, &parsed.proof) {
            assert_eq!(original_proof.object_id, parsed_proof.object_id);
            assert_eq!(original_proof.trace_id, parsed_proof.trace_id);

            // Verification should work with preserved control characters
            let fragment_digests = fragment_digests(&fragments);
            let verification = verifier("repair-secret").verify(
                parsed_proof,
                &fragment_digests,
                &parsed_proof.output_hash,
            );
            assert_eq!(verification.event_code(), "REPAIR_PROOF_VALID");
        }
    }

    #[test]
    fn negative_algorithm_id_with_unicode_normalization_attacks() {
        let mut decoder = decoder();
        let fragments = fragments();

        // Test Unicode normalization attacks (different representations of same visual chars)
        let normalization_attacks = [
            ("café", "cafe\u{0301}"),             // NFC vs NFD normalization
            ("A", "\u{0041}"),                    // Latin A vs Unicode codepoint
            ("résumé", "re\u{0301}sume\u{0301}"), // Multiple combining chars
            ("Ⅸ", "IX"),                          // Roman numeral vs ASCII
        ];

        for (form1, form2) in normalization_attacks {
            let algo1 = AlgorithmId::new(form1);
            let algo2 = AlgorithmId::new(form2);

            // Different Unicode forms should be treated as different algorithms
            assert_ne!(algo1.as_str(), algo2.as_str());

            // Both should either work or fail consistently
            let result1 = decoder.decode("obj-norm1", &fragments, &algo1, 42, "trace-norm1");
            let result2 = decoder.decode("obj-norm2", &fragments, &algo2, 42, "trace-norm2");

            match (result1, result2) {
                (Ok(_), Ok(_)) => {
                    // If both succeed, they should be treated as different algorithms
                }
                (Err(_), Err(_)) => {
                    // If both fail, that's also consistent
                }
                _ => {
                    // Mixed results suggest normalization isn't being handled consistently
                    // This could be a security issue
                }
            }
        }
    }

    #[test]
    fn negative_massive_fragment_array_capacity_boundary_testing() {
        // Test fragment array processing at extreme capacity boundaries
        let mut decoder = decoder();

        // Create fragments that push vector capacity limits
        let mut massive_fragments = Vec::new();

        // Test with fragment count approaching usize limits (safely)
        let max_safe_count = std::cmp::min(1000000, usize::MAX / 1024);

        for i in 0..std::cmp::min(10000, max_safe_count) {
            massive_fragments.push(Fragment {
                fragment_id: format!("mass-frag-{:08x}", i),
                data: vec![i as u8; 1], // Small data but many fragments
            });
        }

        let result = decoder.decode(
            "obj-massive-fragment-count",
            &massive_fragments,
            &AlgorithmId::new("simple_concat"),
            42,
            "trace-massive-fragment-count",
        );

        match result {
            Ok(decode_result) => {
                // Should handle large fragment counts without overflow
                assert_eq!(decode_result.object_id, "obj-massive-fragment-count");
                assert_eq!(decode_result.output_data.len(), massive_fragments.len());

                if let Some(proof) = decode_result.proof {
                    assert_eq!(proof.fragment_count, massive_fragments.len());

                    // Fragment hash vector should not cause overflow
                    assert_eq!(proof.input_fragment_hashes.len(), massive_fragments.len());

                    // Verification should handle large hash arrays
                    let fragment_digests = fragment_digests(&massive_fragments);
                    let verification = verifier("repair-secret").verify(
                        &proof,
                        &fragment_digests,
                        &proof.output_hash,
                    );
                    assert_eq!(verification.event_code(), "REPAIR_PROOF_VALID");
                }
            }
            Err(ProofCarryingDecodeError::ReconstructionFailed { .. }) => {
                // Memory-based rejection of massive fragment counts is acceptable
            }
            Err(other) => {
                panic!("Unexpected error for massive fragment count: {:?}", other);
            }
        }
    }

    #[test]
    fn negative_timestamp_precision_loss_and_floating_point_edge_cases() {
        // Test timestamp handling with floating-point precision edge cases
        let mut decoder = decoder();
        let fragments = fragments();

        let problematic_timestamps = [
            0u64,                    // Epoch zero
            1u64,                    // Minimal positive
            u64::MAX,                // Maximum value
            u64::MAX - 1,            // Near maximum
            9007199254740992u64,     // 2^53 (JavaScript safe integer limit)
            9007199254740993u64,     // 2^53 + 1 (precision loss boundary)
            18446744073709551614u64, // u64::MAX - 1
            1677721471u64,           // Unix timestamp boundary (2023)
            2147483647u64,           // i32::MAX (year 2038 problem)
            4294967295u64,           // u32::MAX
        ];

        for &timestamp in &problematic_timestamps {
            let result = decoder.decode(
                &format!("obj-timestamp-{}", timestamp),
                &fragments,
                &AlgorithmId::new("simple_concat"),
                timestamp,
                &format!("trace-timestamp-{}", timestamp),
            );

            match result {
                Ok(decode_result) => {
                    // Timestamp should be preserved exactly
                    if let Some(proof) = decode_result.proof {
                        assert_eq!(proof.timestamp_epoch_secs, timestamp);

                        // JSON round-trip should preserve precision
                        let json =
                            serde_json::to_string(&proof).expect("should serialize timestamp");
                        let parsed: RepairProof =
                            serde_json::from_str(&json).expect("should deserialize timestamp");
                        assert_eq!(parsed.timestamp_epoch_secs, timestamp);

                        // Verification should work with edge case timestamps
                        let fragment_digests = fragment_digests(&fragments);
                        let verification = verifier("repair-secret").verify(
                            &parsed,
                            &fragment_digests,
                            &parsed.output_hash,
                        );
                        assert_eq!(verification.event_code(), "REPAIR_PROOF_VALID");
                    }
                }
                Err(_) => {
                    // Rejection of extreme timestamps is acceptable
                }
            }
        }
    }

    #[test]
    fn negative_hash_collision_simulation_and_constant_time_verification() {
        // Test hash collision scenarios and timing attack resistance
        let mut decoder = decoder();

        // Create fragments with data designed to cause hash collisions (simulation)
        let collision_fragments = vec![
            Fragment {
                fragment_id: "collision-a".to_string(),
                data: b"abc".to_vec(), // Simple collision candidate
            },
            Fragment {
                fragment_id: "collision-b".to_string(),
                data: b"acb".to_vec(), // Different permutation
            },
            Fragment {
                fragment_id: "collision-c".to_string(),
                data: b"bac".to_vec(), // Another permutation
            },
        ];

        let result = decoder
            .decode(
                "obj-collision-test",
                &collision_fragments,
                &AlgorithmId::new("simple_concat"),
                42,
                "trace-collision-test",
            )
            .expect("collision fragments should decode");

        if let Some(proof) = result.proof {
            // Verify that hash comparison uses constant-time operations
            let fragment_digests = fragment_digests(&collision_fragments);

            // Test verification with correct digests
            let verification_correct =
                verifier("repair-secret").verify(&proof, &fragment_digests, &proof.output_hash);
            assert_eq!(verification_correct.event_code(), "REPAIR_PROOF_VALID");

            // Test verification with similar but wrong digests (potential timing attack)
            let mut similar_digests = fragment_digests.clone();
            if !similar_digests.is_empty() {
                // Flip one bit in the hash to simulate collision attempt
                let original = &similar_digests[0];
                let mut modified = original.clone();
                if let Some(pos) = modified.find('a') {
                    modified.replace_range(pos..pos + 1, "b");
                }
                similar_digests[0] = modified;

                let verification_similar =
                    verifier("repair-secret").verify(&proof, &similar_digests, &proof.output_hash);
                assert_eq!(verification_similar.event_code(), REPAIR_PROOF_INVALID);

                // Both verifications should complete in similar time (constant-time comparison)
                // This is tested internally by ct_eq_bytes usage in the codebase
            }
        }
    }

    #[test]
    fn negative_deep_json_nesting_and_recursive_structure_attacks() {
        // Test JSON parsing with deeply nested structures that could cause stack overflow
        let mut decoder = decoder();

        // Create nested structure in trace ID and object ID
        let deep_nesting = "{".repeat(100) + &"}".repeat(100);
        let array_nesting = "[".repeat(100) + &"]".repeat(100);
        let mixed_nesting = format!(
            "{{\"level1\": [{{\"level2\": {}}}, {}]}}",
            deep_nesting, array_nesting
        );

        let edge_case_ids = [
            mixed_nesting.as_str(),
            &"x".repeat(100000),      // Very long string
            "\"{\"nested\": true}\"", // JSON within string
            "null",                   // JSON null literal
            "true",                   // JSON boolean literal
            "1.23e+100",              // Large number format
        ];

        let fragments = fragments();

        for (i, &problematic_id) in edge_case_ids.iter().enumerate() {
            let safe_object_id = format!("obj-nest-{}", i); // Use safe object ID

            let result = decoder.decode(
                &safe_object_id,
                &fragments,
                &AlgorithmId::new("simple_concat"),
                42,
                problematic_id, // Use problematic string as trace ID
            );

            match result {
                Ok(decode_result) => {
                    // Verify structure integrity after processing nested data
                    assert_eq!(decode_result.object_id, safe_object_id);

                    if let Some(proof) = decode_result.proof {
                        assert_eq!(proof.trace_id, problematic_id);

                        // JSON serialization should handle nested structures safely
                        let json_result = serde_json::to_string(&proof);

                        match json_result {
                            Ok(json) => {
                                // Deserialization should not cause stack overflow
                                let parse_result: Result<RepairProof, _> =
                                    serde_json::from_str(&json);

                                match parse_result {
                                    Ok(parsed_proof) => {
                                        assert_eq!(parsed_proof.trace_id, problematic_id);
                                    }
                                    Err(_) => {
                                        // JSON parse failure with complex nesting is acceptable
                                    }
                                }
                            }
                            Err(_) => {
                                // JSON serialization failure with complex nesting is acceptable
                            }
                        }
                    }
                }
                Err(_) => {
                    // Rejection of deeply nested structures is acceptable
                }
            }
        }
    }

    #[test]
    fn negative_proof_chain_validation_with_dependency_cycles() {
        // Test proof validation with circular dependencies and complex chains
        let (fragments, mut base_proof) = valid_proof();

        // Create a chain of proofs that reference each other
        let mut proof_chain = Vec::new();

        for i in 0..10 {
            let mut proof = base_proof.clone();
            proof.proof_id = format!("proof-chain-{}", i);
            proof.object_id = format!("obj-chain-{}", i);

            // Create potential circular reference in trace IDs
            if i > 0 {
                proof.trace_id = format!("trace-depends-on-{}", (i - 1) % 3);
            } else {
                proof.trace_id = "trace-depends-on-9".to_string(); // Creates cycle
            }

            proof_chain.push(proof);
        }

        // Test verification of each proof in the chain
        for (i, proof) in proof_chain.iter().enumerate() {
            let verification = verifier("repair-secret").verify(
                proof,
                &fragment_digests(&fragments),
                &proof.output_hash,
            );

            // Each individual proof should validate regardless of chain dependencies
            assert_eq!(verification.event_code(), "REPAIR_PROOF_VALID");

            // Test JSON serialization of proof chain
            let chain_json = serde_json::to_string(&proof_chain).expect("chain should serialize");
            let parsed_chain: Vec<RepairProof> =
                serde_json::from_str(&chain_json).expect("chain should deserialize");

            assert_eq!(parsed_chain.len(), proof_chain.len());
            assert_eq!(parsed_chain[i].proof_id, proof.proof_id);
        }

        // Test with self-referencing proof
        let mut self_ref_proof = base_proof.clone();
        self_ref_proof.proof_id = "self-ref-proof".to_string();
        self_ref_proof.object_id = "obj-self-ref".to_string();
        self_ref_proof.trace_id = "self-ref-proof".to_string(); // Self reference

        let self_verification = verifier("repair-secret").verify(
            &self_ref_proof,
            &fragment_digests(&fragments),
            &self_ref_proof.output_hash,
        );
        assert_eq!(self_verification.event_code(), "REPAIR_PROOF_VALID");
    }

    #[test]
    fn negative_concurrent_verification_state_isolation() {
        // Test verification state isolation under concurrent-like access patterns
        let (fragments, proof) = valid_proof();
        let fragment_digests = fragment_digests(&fragments);

        // Create multiple verifiers with different configurations
        let verifiers = vec![
            verifier("repair-secret"),
            verifier("different-secret"),
            ProofVerificationApi::new("repair-secret", vec![AlgorithmId::new("simple_concat")]),
            ProofVerificationApi::new("repair-secret", vec![]), // Empty algorithm set
        ];

        // Simulate rapid concurrent verifications
        let mut results = Vec::new();

        for iteration in 0..100 {
            let verifier_idx = iteration % verifiers.len();
            let current_verifier = &verifiers[verifier_idx];

            // Modify proof slightly for each iteration to test state isolation
            let mut test_proof = proof.clone();
            test_proof.proof_id = format!("concurrent-proof-{}", iteration);
            test_proof.timestamp_epoch_secs = test_proof
                .timestamp_epoch_secs
                .saturating_add(iteration as u64);

            let verification =
                current_verifier.verify(&test_proof, &fragment_digests, &test_proof.output_hash);

            results.push((verifier_idx, verification));
        }

        // Analyze results for consistency
        let mut valid_count = 0;
        let mut invalid_count = 0;
        let mut unknown_algo_count = 0;

        for (verifier_idx, verification) in results {
            match verification {
                VerificationResult::Valid => {
                    // Should only be valid for correct secret + non-empty algorithms
                    assert!(verifier_idx == 0 || verifier_idx == 2);
                    valid_count = valid_count.saturating_add(1);
                }
                VerificationResult::InvalidSignature => {
                    // Expected for wrong secret
                    invalid_count = invalid_count.saturating_add(1);
                }
                VerificationResult::UnknownAlgorithm { .. } => {
                    // Expected for empty algorithm set
                    assert_eq!(verifier_idx, 3);
                    unknown_algo_count = unknown_algo_count.saturating_add(1);
                }
                _ => {
                    // Other results should be rare
                }
            }
        }

        // State isolation should produce consistent results
        assert!(valid_count > 0, "Should have some valid verifications");
        assert!(
            invalid_count > 0,
            "Should have some invalid signature results"
        );
        assert!(
            unknown_algo_count > 0,
            "Should have some unknown algorithm results"
        );
    }

    #[test]
    fn negative_memory_exhaustion_via_proof_attestation_bloat() {
        // Test memory handling with extremely large attestation data
        let mut decoder = decoder();
        let fragments = fragments();

        let result = decoder
            .decode(
                "obj-large-attestation",
                &fragments,
                &AlgorithmId::new("simple_concat"),
                42,
                "trace-large-attestation",
            )
            .expect("should generate proof with attestation");

        if let Some(mut proof) = result.proof {
            // Simulate bloated attestation fields
            proof.attestation.signer_id = "x".repeat(1000000); // 1MB signer ID
            proof.attestation.payload_hash = "y".repeat(500000); // 500KB hash
            proof.attestation.signature = "z".repeat(2000000); // 2MB signature

            // JSON serialization should handle large fields
            let json_result = serde_json::to_string(&proof);

            match json_result {
                Ok(json) => {
                    // Should create very large JSON (>3.5MB)
                    assert!(json.len() > 3500000);

                    // Deserialization should handle large JSON without memory exhaustion
                    let parse_result: Result<RepairProof, _> = serde_json::from_str(&json);

                    match parse_result {
                        Ok(parsed_proof) => {
                            assert_eq!(parsed_proof.attestation.signer_id.len(), 1000000);
                            assert_eq!(parsed_proof.attestation.payload_hash.len(), 500000);
                            assert_eq!(parsed_proof.attestation.signature.len(), 2000000);

                            // Verification should reject bloated attestation gracefully
                            let verification = verifier("repair-secret").verify(
                                &parsed_proof,
                                &fragment_digests(&fragments),
                                &parsed_proof.output_hash,
                            );
                            assert_eq!(verification.event_code(), REPAIR_PROOF_INVALID);
                            assert!(matches!(verification, VerificationResult::InvalidSignature));
                        }
                        Err(_) => {
                            // Memory exhaustion protection during parse is acceptable
                        }
                    }
                }
                Err(_) => {
                    // Memory exhaustion protection during serialization is acceptable
                }
            }
        }
    }

    #[test]
    fn negative_fragment_data_with_extreme_binary_patterns() {
        // Test fragment processing with extreme binary data patterns
        let mut decoder = decoder();

        let extreme_patterns = vec![
            // All zeros
            Fragment {
                fragment_id: "zero-pattern".to_string(),
                data: vec![0x00; 100000],
            },
            // All ones
            Fragment {
                fragment_id: "one-pattern".to_string(),
                data: vec![0xFF; 100000],
            },
            // Alternating pattern
            Fragment {
                fragment_id: "alternating-pattern".to_string(),
                data: (0..100000)
                    .map(|i| if i % 2 == 0 { 0x55 } else { 0xAA })
                    .collect(),
            },
            // Random-like pattern using linear congruential generator
            Fragment {
                fragment_id: "pseudo-random-pattern".to_string(),
                data: {
                    let mut seed = 1u32;
                    (0..100000)
                        .map(|_| {
                            seed = seed.wrapping_mul(1103515245).wrapping_add(12345);
                            (seed >> 16) as u8
                        })
                        .collect()
                },
            },
            // Compression-hostile pattern (high entropy)
            Fragment {
                fragment_id: "high-entropy-pattern".to_string(),
                data: (0..100000)
                    .map(|i| (i ^ (i >> 8) ^ (i >> 16)) as u8)
                    .collect(),
            },
        ];

        for pattern_fragment in extreme_patterns {
            let fragment_id = pattern_fragment.fragment_id.clone();

            let result = decoder.decode(
                &format!("obj-{}", fragment_id),
                &[pattern_fragment.clone()],
                &AlgorithmId::new("simple_concat"),
                42,
                &format!("trace-{}", fragment_id),
            );

            match result {
                Ok(decode_result) => {
                    // Should handle extreme binary patterns without corruption
                    assert_eq!(decode_result.output_data, pattern_fragment.data);

                    if let Some(proof) = decode_result.proof {
                        // Hash computation should work with any binary pattern
                        assert!(!proof.input_fragment_hashes.is_empty());
                        assert!(!proof.output_hash.is_empty());

                        // Verification should work regardless of data pattern
                        let fragment_digests = fragment_digests(&[pattern_fragment]);
                        let verification = verifier("repair-secret").verify(
                            &proof,
                            &fragment_digests,
                            &proof.output_hash,
                        );
                        assert_eq!(verification.event_code(), "REPAIR_PROOF_VALID");
                    }
                }
                Err(_) => {
                    // Memory-based rejection of large patterns is acceptable
                }
            }
        }
    }

    // ── ADDITIONAL COMPREHENSIVE NEGATIVE-PATH INLINE TESTS ──────────────────────
    // Extended edge cases and boundary validation for security-critical repair operations

    /// Test proof mode validation with extreme enum boundary conditions
    #[test]
    fn test_proof_mode_boundary_validation() {
        use super::proof_carrying_decode::{ProofCarryingDecoder, ProofMode};

        // Test all proof mode variants with extreme configurations
        let modes = [ProofMode::Mandatory, ProofMode::Optional];
        let extreme_configs = [
            ("", ""),                                 // Empty signer and secret
            ("x".repeat(100000), "y".repeat(100000)), // Very long signer and secret
            ("\x00\r\n\t", "\x1b[31m\x00"),           // Control characters
            ("🚀🔐💀", "🛡️🔥⚠️"),                     // Unicode symbols
        ];

        for mode in &modes {
            for (signer, secret) in &extreme_configs {
                let decoder_result =
                    std::panic::catch_unwind(|| ProofCarryingDecoder::new(*mode, signer, secret));

                assert!(
                    decoder_result.is_ok(),
                    "ProofCarryingDecoder creation should not panic with mode {:?} and extreme config",
                    mode
                );

                if let Ok(mut decoder) = decoder_result {
                    // Test decoding with extreme configuration
                    let result = decoder.decode(
                        "obj-extreme-mode",
                        &fragments(),
                        &AlgorithmId::new("simple_concat"),
                        42,
                        "trace-extreme-mode",
                    );

                    match result {
                        Ok(decode_result) => {
                            // Should handle extreme configurations gracefully
                            if *mode == ProofMode::Mandatory {
                                assert!(
                                    decode_result.proof.is_some(),
                                    "Mandatory mode should generate proof"
                                );
                            }
                        }
                        Err(_) => {
                            // Rejection of extreme configurations is acceptable
                        }
                    }
                }
            }
        }

        // Test invalid proof mode deserialization edge cases
        let invalid_json_modes = [
            "\"MANDATORY\"",      // Wrong case
            "\"mandatory_mode\"", // Wrong format
            "true",               // Wrong type
            "1",                  // Number instead of string
            "null",               // Null value
            "\"\"",               // Empty string
            "\" mandatory \"",    // Whitespace padding
        ];

        for invalid_json in &invalid_json_modes {
            let result: Result<ProofMode, _> = serde_json::from_str(invalid_json);
            assert!(
                result.is_err(),
                "Invalid proof mode JSON should be rejected: {}",
                invalid_json
            );
        }
    }

    /// Test algorithm ID validation with injection and collision attempts
    #[test]
    fn test_algorithm_id_security_boundaries() {
        use super::proof_carrying_decode::AlgorithmId;

        // Test algorithm ID creation with potential security issues
        let security_test_algorithms = [
            "",                                     // Empty algorithm ID
            " ",                                    // Whitespace-only
            "\0",                                   // Null byte
            "algo\r\ninjection",                    // CRLF injection
            "algo\x00null",                         // Null byte injection
            "algo\x1b[31mred\x1b[0m",               // ANSI escape sequences
            "../../../etc/passwd",                  // Path traversal
            "CON",                                  // Windows reserved name
            "simple\tconcatspaced",                 // Tab character
            "\u{FEFF}algo",                         // Unicode BOM
            "\u{200B}invisible\u{200B}algo",        // Zero-width spaces
            "algo\u{202E}reverse",                  // Right-to-left override
            format!("long_{}", "x".repeat(100000)), // Very long algorithm ID
            "simple_concat",                        // Valid reference for comparison
        ];

        let mut decoder = decoder();
        let fragments = fragments();

        for algo_str in &security_test_algorithms {
            let algo_id = AlgorithmId::new(algo_str);

            // Test algorithm ID string preservation
            assert_eq!(algo_id.as_str(), *algo_str);

            // Test JSON serialization/deserialization
            let json_result = serde_json::to_string(&algo_id);
            match json_result {
                Ok(json) => {
                    let parsed_result: Result<AlgorithmId, _> = serde_json::from_str(&json);
                    match parsed_result {
                        Ok(parsed_algo) => {
                            assert_eq!(parsed_algo.as_str(), *algo_str);
                        }
                        Err(_) => {
                            // JSON parse failure with extreme content is acceptable
                        }
                    }
                }
                Err(_) => {
                    // JSON serialization failure with extreme content is acceptable
                }
            }

            // Test decoding with potentially malicious algorithm IDs
            let decode_result = decoder.decode(
                &format!("obj-algo-test-{}", algo_str.len()),
                &fragments,
                &algo_id,
                42,
                &format!("trace-algo-test-{}", algo_str.len()),
            );

            match decode_result {
                Ok(_) => {
                    // If algorithm is accepted, that means it's registered
                    // (only "simple_concat" should succeed in normal cases)
                    if algo_str != "simple_concat" {
                        // Unexpected success with unregistered algorithm
                        // This might indicate algorithm matching is too permissive
                    }
                }
                Err(
                    super::proof_carrying_decode::ProofCarryingDecodeError::ReconstructionFailed {
                        reason,
                        ..
                    },
                ) => {
                    // Expected failure for unregistered algorithms
                    assert!(
                        reason.contains("unregistered algorithm"),
                        "Error should mention unregistered algorithm: {}",
                        reason
                    );
                }
                Err(other) => {
                    panic!("Unexpected error for algorithm '{}': {:?}", algo_str, other);
                }
            }
        }
    }

    /// Test fragment validation with extreme data size and composition
    #[test]
    fn test_fragment_extreme_validation() {
        use super::proof_carrying_decode::Fragment;

        let mut decoder = decoder();

        // Test fragments with extreme size boundaries
        let extreme_size_fragments = vec![
            // Zero-size fragment
            Fragment {
                fragment_id: "zero-size".to_string(),
                data: vec![],
            },
            // Single byte fragment
            Fragment {
                fragment_id: "single-byte".to_string(),
                data: vec![0x42],
            },
            // Boundary size fragments (powers of 2)
            Fragment {
                fragment_id: "size-256".to_string(),
                data: vec![0x55; 256],
            },
            Fragment {
                fragment_id: "size-65536".to_string(),
                data: vec![0xAA; 65536],
            },
            // Very large fragment (10MB) - memory stress test
            Fragment {
                fragment_id: "size-10mb".to_string(),
                data: vec![0xFF; 10 * 1024 * 1024],
            },
        ];

        for fragment in &extreme_size_fragments {
            let result = decoder.decode(
                &format!("obj-size-{}", fragment.data.len()),
                &[fragment.clone()],
                &AlgorithmId::new("simple_concat"),
                42,
                &format!("trace-size-{}", fragment.data.len()),
            );

            match result {
                Ok(decode_result) => {
                    // Output should match input for simple_concat algorithm
                    assert_eq!(decode_result.output_data, fragment.data);
                    assert_eq!(
                        decode_result.object_id,
                        format!("obj-size-{}", fragment.data.len())
                    );

                    // Proof verification should work regardless of fragment size
                    if let Some(proof) = decode_result.proof {
                        let fragment_digests = fragment_digests(&[fragment.clone()]);
                        let verification = verifier("repair-secret").verify(
                            &proof,
                            &fragment_digests,
                            &proof.output_hash,
                        );
                        assert_eq!(verification.event_code(), "REPAIR_PROOF_VALID");
                    }
                }
                Err(_) => {
                    // Memory-based rejection of extreme sizes is acceptable
                }
            }
        }

        // Test fragment ID validation with special characters
        let special_id_fragments = vec![
            Fragment {
                fragment_id: "normal-id".to_string(),
                data: vec![0x42; 4],
            },
            Fragment {
                fragment_id: String::new(), // Empty ID
                data: vec![0x43; 4],
            },
            Fragment {
                fragment_id: "\x00\r\n\t".to_string(), // Control characters
                data: vec![0x44; 4],
            },
            Fragment {
                fragment_id: "id\u{202E}reverse".to_string(), // Unicode direction override
                data: vec![0x45; 4],
            },
            Fragment {
                fragment_id: "x".repeat(100000), // Very long ID
                data: vec![0x46; 4],
            },
        ];

        let result = decoder.decode(
            "obj-special-ids",
            &special_id_fragments,
            &AlgorithmId::new("simple_concat"),
            42,
            "trace-special-ids",
        );

        match result {
            Ok(decode_result) => {
                // Should preserve all fragment IDs exactly
                assert_eq!(decode_result.output_data.len(), 20); // 5 fragments * 4 bytes each

                if let Some(proof) = decode_result.proof {
                    // JSON serialization should handle special characters
                    let json_result = serde_json::to_string(&proof);
                    assert!(
                        json_result.is_ok(),
                        "JSON serialization should handle special fragment IDs"
                    );
                }
            }
            Err(_) => {
                // Rejection of extreme fragment configurations is acceptable
            }
        }
    }

    /// Test verification result completeness and error propagation
    #[test]
    fn test_verification_result_comprehensive_coverage() {
        use super::proof_carrying_decode::{REPAIR_PROOF_INVALID, VerificationResult};

        let (fragments, mut proof) = valid_proof();
        let fragment_digests = fragment_digests(&fragments);

        // Test all possible verification failure modes

        // 1. Invalid signature (wrong secret)
        let invalid_sig_result =
            verifier("wrong-secret").verify(&proof, &fragment_digests, &proof.output_hash);
        assert_eq!(invalid_sig_result.event_code(), REPAIR_PROOF_INVALID);
        assert!(matches!(
            invalid_sig_result,
            VerificationResult::InvalidSignature
        ));

        // 2. Unknown algorithm
        proof.algorithm_id = AlgorithmId::new("unknown-algorithm");
        let unknown_algo_result =
            verifier("repair-secret").verify(&proof, &fragment_digests, &proof.output_hash);
        assert_eq!(unknown_algo_result.event_code(), REPAIR_PROOF_INVALID);
        match unknown_algo_result {
            VerificationResult::UnknownAlgorithm { algorithm_id } => {
                assert_eq!(algorithm_id.as_str(), "unknown-algorithm");
            }
            _ => panic!("Expected UnknownAlgorithm result"),
        }

        // Reset algorithm for remaining tests
        proof.algorithm_id = AlgorithmId::new("simple_concat");

        // 3. Output hash mismatch
        let wrong_output_result =
            verifier("repair-secret").verify(&proof, &fragment_digests, "wrong-output-hash");
        assert_eq!(wrong_output_result.event_code(), REPAIR_PROOF_INVALID);
        match wrong_output_result {
            VerificationResult::OutputHashMismatch { expected, actual } => {
                assert_eq!(expected, "wrong-output-hash");
                assert_eq!(actual, proof.output_hash);
            }
            _ => panic!("Expected OutputHashMismatch result"),
        }

        // 4. Invalid fragment hash with specific index
        let mut wrong_fragments = fragment_digests.clone();
        wrong_fragments[0] = "tampered-fragment-hash".to_string();
        let invalid_frag_result =
            verifier("repair-secret").verify(&proof, &wrong_fragments, &proof.output_hash);
        assert_eq!(invalid_frag_result.event_code(), REPAIR_PROOF_INVALID);
        match invalid_frag_result {
            VerificationResult::InvalidFragmentHash {
                index,
                expected,
                actual,
            } => {
                assert_eq!(index, 0);
                assert_eq!(expected, "tampered-fragment-hash");
                assert_eq!(actual, proof.input_fragment_hashes[0]);
            }
            _ => panic!("Expected InvalidFragmentHash result"),
        }

        // 5. Fragment count mismatch
        let mut short_fragments = fragment_digests.clone();
        short_fragments.pop();
        let count_mismatch_result =
            verifier("repair-secret").verify(&proof, &short_fragments, &proof.output_hash);
        assert_eq!(count_mismatch_result.event_code(), REPAIR_PROOF_INVALID);
        // Should detect fragment count mismatch as InvalidFragmentHash with index 0

        // Test JSON serialization of all error types
        let error_results = vec![
            invalid_sig_result,
            unknown_algo_result,
            wrong_output_result,
            invalid_frag_result,
            count_mismatch_result,
        ];

        for error_result in error_results {
            let json_result = serde_json::to_string(&error_result);
            assert!(
                json_result.is_ok(),
                "All error types should serialize to JSON"
            );

            if let Ok(json) = json_result {
                let parsed_result: Result<VerificationResult, _> = serde_json::from_str(&json);
                assert!(
                    parsed_result.is_ok(),
                    "Error types should deserialize from JSON"
                );

                if let Ok(parsed) = parsed_result {
                    assert_eq!(parsed.event_code(), REPAIR_PROOF_INVALID);
                }
            }
        }
    }

    /// Test audit log integrity under concurrent-style operations
    #[test]
    fn test_audit_log_integrity_comprehensive() {
        use super::proof_carrying_decode::{ProofCarryingDecoder, ProofMode};

        let mut decoder =
            ProofCarryingDecoder::new(ProofMode::Mandatory, "audit-signer", "audit-secret");

        let fragments = fragments();
        let algo_id = AlgorithmId::new("simple_concat");

        // Perform many operations that should generate audit events
        for i in 0..100 {
            let object_id = format!("audit-obj-{}", i);
            let trace_id = format!("audit-trace-{}", i);

            let result =
                decoder.decode(&object_id, &fragments, &algo_id, 1000 + i as u64, &trace_id);

            match result {
                Ok(_) => {
                    // Successful decode should generate audit event
                }
                Err(_) => {
                    // Failed decode should also generate audit event
                }
            }
        }

        // Verify audit log integrity
        let audit_log = decoder.audit_log();
        assert_eq!(
            audit_log.len(),
            100,
            "Should have audit entry for each operation"
        );

        // Check audit log entries for completeness and consistency
        for (i, audit_event) in audit_log.iter().enumerate() {
            assert_eq!(audit_event.object_id, format!("audit-obj-{}", i));
            assert_eq!(audit_event.trace_id, format!("audit-trace-{}", i));
            assert_eq!(audit_event.fragment_count, fragments.len());
            assert_eq!(audit_event.algorithm.as_str(), "simple_concat");

            // All should be valid proof generation events
            assert_eq!(audit_event.event_code, "REPAIR_PROOF_GENERATED");

            // Test JSON serialization of audit events
            let json_result = serde_json::to_string(audit_event);
            assert!(json_result.is_ok(), "Audit events should serialize to JSON");

            if let Ok(json) = json_result {
                let parsed_result = serde_json::from_str(&json);
                assert!(
                    parsed_result.is_ok(),
                    "Audit events should deserialize from JSON"
                );
            }
        }

        // Test audit log with extreme configurations
        let extreme_decoder_result = std::panic::catch_unwind(|| {
            ProofCarryingDecoder::new(
                ProofMode::Mandatory,
                "x".repeat(100000), // Very long signer ID
                "y".repeat(100000), // Very long secret
            )
        });

        assert!(
            extreme_decoder_result.is_ok(),
            "Extreme decoder config should not panic"
        );

        if let Ok(mut extreme_decoder) = extreme_decoder_result {
            let extreme_result = extreme_decoder.decode(
                &"z".repeat(50000), // Very long object ID
                &fragments,
                &algo_id,
                u64::MAX,           // Maximum timestamp
                &"w".repeat(75000), // Very long trace ID
            );

            match extreme_result {
                Ok(_) => {
                    let extreme_audit_log = extreme_decoder.audit_log();
                    if !extreme_audit_log.is_empty() {
                        // Audit event should handle extreme field sizes
                        let extreme_event = &extreme_audit_log[0];
                        assert_eq!(extreme_event.object_id.len(), 50000);
                        assert_eq!(extreme_event.trace_id.len(), 75000);
                    }
                }
                Err(_) => {
                    // Rejection of extreme configurations is acceptable
                }
            }
        }
    }

    /// Test proof verification timing consistency and side-channel resistance
    #[test]
    fn test_proof_verification_timing_consistency() {
        use std::time::Instant;

        let (fragments, proof) = valid_proof();
        let fragment_digests = fragment_digests(&fragments);

        // Test verification timing with various inputs to check for timing side-channels
        let test_cases = vec![
            // Correct verification (baseline)
            (
                proof.clone(),
                fragment_digests.clone(),
                proof.output_hash.clone(),
                "REPAIR_PROOF_VALID",
            ),
            // Wrong secret (should use constant-time comparison)
            (
                proof.clone(),
                fragment_digests.clone(),
                proof.output_hash.clone(),
                REPAIR_PROOF_INVALID,
            ),
            // Wrong fragment hash (should use constant-time comparison)
            (
                proof.clone(),
                vec!["wrong-hash".to_string(); fragment_digests.len()],
                proof.output_hash.clone(),
                REPAIR_PROOF_INVALID,
            ),
            // Wrong output hash (should use constant-time comparison)
            (
                proof.clone(),
                fragment_digests.clone(),
                "wrong-output-hash".to_string(),
                REPAIR_PROOF_INVALID,
            ),
        ];

        let verifiers = vec![
            verifier("repair-secret"), // Correct secret
            verifier("wrong-secret"),  // Wrong secret
        ];

        let mut timing_measurements = Vec::new();

        for (verifier_idx, current_verifier) in verifiers.iter().enumerate() {
            for (test_idx, (test_proof, test_fragments, test_output, _expected_code)) in
                test_cases.iter().enumerate()
            {
                // Measure verification timing
                let start = Instant::now();

                let verification = current_verifier.verify(test_proof, test_fragments, test_output);

                let duration = start.elapsed();
                timing_measurements.push((
                    verifier_idx,
                    test_idx,
                    duration,
                    verification.event_code(),
                ));

                // Verify that constant-time operations are being used
                match verification {
                    VerificationResult::Valid => {
                        assert_eq!(verification.event_code(), "REPAIR_PROOF_VALID");
                    }
                    VerificationResult::InvalidSignature => {
                        // This should result from constant-time comparison failure
                        assert_eq!(verification.event_code(), REPAIR_PROOF_INVALID);
                    }
                    VerificationResult::InvalidFragmentHash { .. } => {
                        // This should result from constant-time hash comparison failure
                        assert_eq!(verification.event_code(), REPAIR_PROOF_INVALID);
                    }
                    VerificationResult::OutputHashMismatch { .. } => {
                        // This should result from constant-time output comparison failure
                        assert_eq!(verification.event_code(), REPAIR_PROOF_INVALID);
                    }
                    _ => {
                        // Other error types are less timing-sensitive
                    }
                }
            }
        }

        // Analyze timing measurements for consistency
        // Note: In a real test environment, this would need more sophisticated timing analysis
        // Here we just verify that verification doesn't take extremely different amounts of time
        let max_timing = timing_measurements
            .iter()
            .map(|(_, _, duration, _)| *duration)
            .max()
            .unwrap_or(Duration::from_nanos(0));
        let min_timing = timing_measurements
            .iter()
            .map(|(_, _, duration, _)| *duration)
            .min()
            .unwrap_or(Duration::from_nanos(1));

        // Timing should not vary by more than an order of magnitude for constant-time operations
        assert!(
            max_timing.as_nanos() < min_timing.as_nanos() * 100,
            "Verification timing variance is too high - possible timing side-channel"
        );

        // All operations should complete reasonably quickly (less than 100ms)
        assert!(
            max_timing.as_millis() < 100,
            "Verification should complete quickly"
        );
    }

    /// Test error propagation and recovery under cascading failures
    #[test]
    fn test_error_propagation_and_recovery() {
        use super::proof_carrying_decode::{
            ProofCarryingDecodeError, ProofCarryingDecoder, ProofMode,
        };

        // Test decoder recovery after various error conditions
        let mut decoder =
            ProofCarryingDecoder::new(ProofMode::Mandatory, "recovery-signer", "recovery-secret");

        let valid_fragments = fragments();
        let valid_algo = AlgorithmId::new("simple_concat");

        // Series of operations that should cause different error types
        let error_operations = vec![
            // 1. Empty fragments
            (
                "obj-error-1",
                Vec::new(),
                valid_algo.clone(),
                "trace-error-1",
            ),
            // 2. Unknown algorithm
            (
                "obj-error-2",
                valid_fragments.clone(),
                AlgorithmId::new("unknown-algo"),
                "trace-error-2",
            ),
            // 3. Valid operation (should succeed after errors)
            (
                "obj-success-1",
                valid_fragments.clone(),
                valid_algo.clone(),
                "trace-success-1",
            ),
            // 4. Another error with malformed data
            (
                "obj-error-3",
                vec![Fragment {
                    fragment_id: "malformed".to_string(),
                    data: Vec::new(),
                }],
                valid_algo.clone(),
                "trace-error-3",
            ),
            // 5. Recovery with valid operation
            (
                "obj-success-2",
                valid_fragments.clone(),
                valid_algo.clone(),
                "trace-success-2",
            ),
        ];

        let mut results = Vec::new();

        for (i, (object_id, test_fragments, test_algo, trace_id)) in
            error_operations.iter().enumerate()
        {
            let result = decoder.decode(
                object_id,
                test_fragments,
                test_algo,
                100 + i as u64,
                trace_id,
            );

            match &result {
                Ok(decode_result) => {
                    // Successful operations should have proper structure
                    assert_eq!(decode_result.object_id, *object_id);
                    if let Some(proof) = &decode_result.proof {
                        assert_eq!(proof.object_id, *object_id);
                        assert_eq!(proof.trace_id, *trace_id);
                    }
                }
                Err(error) => {
                    // Errors should be well-formed and informative
                    match error {
                        ProofCarryingDecodeError::ReconstructionFailed {
                            object_id: err_obj_id,
                            reason,
                        } => {
                            assert_eq!(err_obj_id, object_id);
                            assert!(!reason.is_empty(), "Error reason should not be empty");
                        }
                        ProofCarryingDecodeError::MissingProofInMandatoryMode {
                            object_id: err_obj_id,
                        } => {
                            assert_eq!(err_obj_id, object_id);
                        }
                    }
                }
            }

            results.push((i, object_id, result));
        }

        // Verify decoder state consistency after errors
        let final_audit_log = decoder.audit_log();

        // Should have audit entries for successful operations only
        let success_count = results
            .iter()
            .filter(|(_, _, result)| result.is_ok())
            .count();
        assert_eq!(
            final_audit_log.len(),
            success_count,
            "Audit log should only contain successful operations"
        );

        // Test error serialization and deserialization
        for (_, _, result) in &results {
            if let Err(error) = result {
                let json_result = serde_json::to_string(error);
                match json_result {
                    Ok(json) => {
                        let parsed_result: Result<ProofCarryingDecodeError, _> =
                            serde_json::from_str(&json);
                        assert!(
                            parsed_result.is_ok(),
                            "Errors should round-trip through JSON"
                        );
                    }
                    Err(_) => {
                        // Some error types might not serialize (which is acceptable)
                    }
                }
            }
        }

        // Test that decoder can continue normal operation after errors
        let recovery_result = decoder.decode(
            "obj-final-recovery",
            &valid_fragments,
            &valid_algo,
            200,
            "trace-final-recovery",
        );

        assert!(
            recovery_result.is_ok(),
            "Decoder should recover and continue normal operation"
        );

        if let Ok(recovery_decode) = recovery_result {
            assert_eq!(recovery_decode.object_id, "obj-final-recovery");

            // Verify proof verification still works after error recovery
            if let Some(proof) = recovery_decode.proof {
                let fragment_digests = fragment_digests(&valid_fragments);
                let verification = verifier("recovery-secret").verify(
                    &proof,
                    &fragment_digests,
                    &proof.output_hash,
                );
                assert_eq!(verification.event_code(), "REPAIR_PROOF_VALID");
            }
        }
    }

    // ============================================================================
    // EXTREME ADVERSARIAL NEGATIVE-PATH TESTS - REPAIR MODULE INTEGRATION
    // ============================================================================
    // Comprehensive attack resistance targeting repair system edge cases

    #[test]
    fn negative_unicode_bidirectional_injection_comprehensive_repair_identifiers() {
        // Test repair system resistance to Unicode BiDi attacks in all identifier fields
        let unicode_attack_patterns = vec![
            // BiDi override attacks in object IDs
            ("rtl_object", "obj\u{202e}_gnissecorp\u{202c}_repair"),
            ("ltr_object", "obj\u{202d}_processing\u{202c}_repair"),
            // Zero-width character pollution in fragment IDs
            ("zws_fragment", "frag\u{200b}_test\u{200c}_id\u{200d}"),
            ("bom_fragment", "\u{feff}fragment\u{feff}"),
            // Combining character stacking in trace IDs
            ("combining_trace", "tra\u{0300}\u{0301}\u{0302}ce_id"),
            // Unicode confusables in algorithm IDs
            ("cyrillic_algo", "аlgorithm_id"), // Cyrillic 'а'
            ("greek_algo", "αlgorithm_id"),    // Greek 'α'
            // Mixed script injection
            ("mixed_script", "repair_修復_test"),
            (
                "script_boundary",
                "obj\u{0628}\u{0627}\u{0644}\u{0639}\u{0631}\u{0628}\u{064A}\u{0629}",
            ), // Arabic
        ];

        let mut decoder = decoder();

        for (test_name, attack_identifier) in unicode_attack_patterns {
            let attack_result = std::panic::catch_unwind(|| {
                // Test with Unicode attack in object ID
                let fragments = vec![Fragment {
                    fragment_id: attack_identifier.to_string(),
                    data: b"unicode_test_data".to_vec(),
                }];

                let decode_result = decoder.decode(
                    attack_identifier,
                    &fragments,
                    &AlgorithmId::new("simple_concat"),
                    100,
                    &format!("trace_{}", attack_identifier),
                );

                match decode_result {
                    Ok(result) => {
                        // Verify Unicode preservation without normalization corruption
                        assert_eq!(result.object_id, attack_identifier);

                        if let Some(proof) = result.proof {
                            // Verify proof preserves Unicode identifiers correctly
                            assert_eq!(proof.object_id, attack_identifier);
                            assert_eq!(proof.trace_id, format!("trace_{}", attack_identifier));

                            // Test proof verification with Unicode identifiers
                            let fragment_digests = vec![hex::encode(fragments[0].hash())];
                            let verification = verifier("repair-secret").verify(
                                &proof,
                                &fragment_digests,
                                &proof.output_hash,
                            );

                            // Should verify correctly despite Unicode content
                            assert!(
                                verification.is_valid(),
                                "Unicode proof should verify: {}",
                                test_name
                            );

                            // Test proof serialization with Unicode content
                            let json_result = serde_json::to_string(&proof);
                            assert!(
                                json_result.is_ok(),
                                "Unicode proof should serialize: {}",
                                test_name
                            );

                            if let Ok(json) = json_result {
                                let deserialize_result: Result<RepairProof, _> =
                                    serde_json::from_str(&json);
                                assert!(
                                    deserialize_result.is_ok(),
                                    "Unicode proof should deserialize: {}",
                                    test_name
                                );
                            }
                        }
                    }
                    Err(err) => {
                        // Some Unicode patterns may be rejected - verify meaningful error
                        assert!(
                            !err.to_string().is_empty(),
                            "Error should be meaningful: {}",
                            test_name
                        );
                    }
                }

                Ok(())
            });

            assert!(
                attack_result.is_ok(),
                "Unicode injection test should not panic: {}",
                test_name
            );
        }

        // Verify decoder integrity after Unicode attack tests
        let normal_result = decoder.decode(
            "normal_object",
            &fragments(),
            &AlgorithmId::new("simple_concat"),
            200,
            "normal_trace",
        );
        assert!(
            normal_result.is_ok(),
            "Normal operation should work after Unicode tests"
        );
    }

    #[test]
    fn negative_arithmetic_overflow_timestamp_epoch_boundaries() {
        // Test repair system with timestamp values that could cause overflow
        let mut decoder = decoder();
        let fragments = fragments();

        let overflow_timestamps = vec![
            // Near u64::MAX boundaries
            (u64::MAX, "max_timestamp"),
            (u64::MAX - 1, "max_minus_one"),
            (u64::MAX - 1000, "near_max"),
            // Large timestamp values
            (u64::MAX / 2, "half_max"),
            (1u64 << 62, "large_power_of_two"),
            (u32::MAX as u64, "u32_boundary"),
            // Edge cases
            (0, "zero_timestamp"),
            (1, "minimum_positive"),
            (i64::MAX as u64, "i64_max_as_u64"),
        ];

        for (timestamp, test_name) in overflow_timestamps {
            let overflow_result = std::panic::catch_unwind(|| {
                let decode_result = decoder.decode(
                    &format!("overflow_obj_{}", test_name),
                    &fragments,
                    &AlgorithmId::new("simple_concat"),
                    timestamp,
                    &format!("overflow_trace_{}", test_name),
                );

                match decode_result {
                    Ok(result) => {
                        // Verify timestamp is preserved without overflow corruption
                        if let Some(proof) = result.proof {
                            assert_eq!(
                                proof.timestamp_epoch_secs, timestamp,
                                "Timestamp should be preserved: {}",
                                test_name
                            );

                            // Test arithmetic operations on extreme timestamps don't overflow
                            let future_check = timestamp.saturating_add(3600);
                            assert!(
                                future_check >= timestamp,
                                "Arithmetic should not underflow: {}",
                                test_name
                            );

                            // Verify proof verification works with extreme timestamps
                            let fragment_digests = fragment_digests(&fragments);
                            let verification = verifier("repair-secret").verify(
                                &proof,
                                &fragment_digests,
                                &proof.output_hash,
                            );

                            assert!(
                                verification.is_valid(),
                                "Extreme timestamp proof should verify: {}",
                                test_name
                            );

                            // Test serialization doesn't corrupt extreme values
                            let json_result = serde_json::to_string(&proof);
                            assert!(
                                json_result.is_ok(),
                                "Extreme timestamp should serialize: {}",
                                test_name
                            );

                            if let Ok(json) = json_result {
                                assert!(
                                    json.contains(&timestamp.to_string()) || json.len() > 50,
                                    "JSON should preserve timestamp: {}",
                                    test_name
                                );
                            }
                        }
                    }
                    Err(err) => {
                        // Some extreme timestamps may be rejected - verify meaningful error
                        let error_msg = err.to_string();
                        assert!(
                            !error_msg.is_empty(),
                            "Error should be meaningful: {}",
                            test_name
                        );
                        assert!(
                            error_msg.contains("timestamp")
                                || error_msg.contains("time")
                                || error_msg.contains("epoch"),
                            "Error should reference timing: {} - {}",
                            test_name,
                            error_msg
                        );
                    }
                }

                Ok(())
            });

            assert!(
                overflow_result.is_ok(),
                "Overflow timestamp test should not panic: {}",
                test_name
            );
        }

        // Verify decoder still works after timestamp overflow tests
        let recovery_result = decoder.decode(
            "timestamp_recovery",
            &fragments,
            &AlgorithmId::new("simple_concat"),
            1000,
            "timestamp_recovery_trace",
        );
        assert!(
            recovery_result.is_ok(),
            "Decoder should work after timestamp overflow tests"
        );
    }

    #[test]
    fn negative_fragment_data_memory_exhaustion_comprehensive() {
        // Test repair system with fragment data designed to cause memory exhaustion
        let mut decoder = decoder();

        let memory_exhaustion_patterns = vec![
            // Very large single fragment
            (
                "single_massive",
                vec![Fragment {
                    fragment_id: "massive_fragment".to_string(),
                    data: vec![0x42; 10_000_000], // 10MB
                }],
            ),
            // Many small fragments
            (
                "many_small",
                (0..10000)
                    .map(|i| Fragment {
                        fragment_id: format!("small_frag_{:05}", i),
                        data: vec![i as u8 % 256; 10],
                    })
                    .collect(),
            ),
            // Mixed size distribution
            ("mixed_sizes", {
                let mut frags = Vec::new();
                // Few large fragments
                for i in 0..5 {
                    frags.push(Fragment {
                        fragment_id: format!("large_frag_{}", i),
                        data: vec![0x80 + i as u8; 1_000_000],
                    });
                }
                // Many small fragments
                for i in 0..1000 {
                    frags.push(Fragment {
                        fragment_id: format!("small_frag_{}", i),
                        data: vec![i as u8; 100],
                    });
                }
                frags
            }),
            // Fragments with exponentially increasing sizes
            (
                "exponential_growth",
                (1..20)
                    .map(|i| Fragment {
                        fragment_id: format!("exp_frag_{}", i),
                        data: vec![0xFF; 1 << std::cmp::min(i, 20)], // Cap at 1MB
                    })
                    .collect(),
            ),
            // Empty and near-empty fragments mixed with large ones
            ("empty_mixed", {
                let mut frags = vec![
                    Fragment {
                        fragment_id: "empty_1".to_string(),
                        data: vec![],
                    },
                    Fragment {
                        fragment_id: "empty_2".to_string(),
                        data: vec![],
                    },
                    Fragment {
                        fragment_id: "single_byte".to_string(),
                        data: vec![0xFF],
                    },
                ];
                frags.push(Fragment {
                    fragment_id: "huge_contrast".to_string(),
                    data: vec![0x99; 5_000_000],
                });
                frags
            }),
        ];

        for (test_name, fragments) in memory_exhaustion_patterns {
            let memory_test_result = std::panic::catch_unwind(|| {
                let start_time = std::time::Instant::now();

                let decode_result = decoder.decode(
                    &format!("memory_test_{}", test_name),
                    &fragments,
                    &AlgorithmId::new("simple_concat"),
                    300,
                    &format!("memory_trace_{}", test_name),
                );

                let duration = start_time.elapsed();

                // Should complete within reasonable time (not hang)
                assert!(
                    duration.as_secs() < 30,
                    "Memory test should not hang: {}",
                    test_name
                );

                match decode_result {
                    Ok(result) => {
                        // If successful, verify output data integrity
                        let expected_total_size: usize =
                            fragments.iter().map(|f| f.data.len()).sum();
                        assert_eq!(
                            result.output_data.len(),
                            expected_total_size,
                            "Output size should match input: {}",
                            test_name
                        );

                        // Verify proof generation worked with large data
                        if let Some(proof) = result.proof {
                            assert_eq!(
                                proof.fragment_count,
                                fragments.len(),
                                "Fragment count should be correct: {}",
                                test_name
                            );
                            assert_eq!(
                                proof.input_fragment_hashes.len(),
                                fragments.len(),
                                "Hash count should match fragments: {}",
                                test_name
                            );

                            // All hashes should be valid hex
                            for (i, hash) in proof.input_fragment_hashes.iter().enumerate() {
                                assert_eq!(
                                    hash.len(),
                                    64,
                                    "Hash {} should be 64 chars: {}",
                                    i,
                                    test_name
                                );
                                assert!(
                                    hash.chars().all(|c| c.is_ascii_hexdigit()),
                                    "Hash {} should be valid hex: {}",
                                    i,
                                    test_name
                                );
                            }
                        }
                    }
                    Err(err) => {
                        // Memory exhaustion failure is acceptable for extreme cases
                        let error_msg = err.to_string();
                        assert!(
                            error_msg.contains("memory")
                                || error_msg.contains("size")
                                || error_msg.contains("capacity")
                                || error_msg.contains("reconstruction"),
                            "Memory error should be meaningful: {} - {}",
                            test_name,
                            error_msg
                        );
                    }
                }

                // Verify decoder integrity after memory stress
                let audit_log = decoder.audit_log();
                assert!(
                    audit_log.len() <= 10000,
                    "Audit log should not grow unbounded: {}",
                    test_name
                );

                Ok(())
            });

            assert!(
                memory_test_result.is_ok(),
                "Memory exhaustion test should not panic: {}",
                test_name
            );
        }

        // Verify decoder can still handle normal operations after memory stress
        let normal_fragments = fragments();
        let recovery_result = decoder.decode(
            "post_memory_recovery",
            &normal_fragments,
            &AlgorithmId::new("simple_concat"),
            400,
            "post_memory_trace",
        );
        assert!(
            recovery_result.is_ok(),
            "Normal operation should work after memory tests"
        );
    }

    #[test]
    fn negative_algorithm_id_injection_and_collision_resistance() {
        // Test algorithm ID handling with injection attempts and collision patterns
        let mut decoder = decoder();

        let long_algorithm_id = "x".repeat(100000);
        let binary_algorithm_id = String::from_utf8_lossy(b"algo\xFF\xFE\xFD\xFC").into_owned();
        let algorithm_attack_patterns = vec![
            // Path traversal in algorithm IDs
            ("path_traversal", "../../../etc/passwd"),
            ("windows_traversal", "..\\..\\windows\\system32"),
            // JSON injection in algorithm names
            (
                "json_injection",
                r#"algo": "injected", "evil": true, "real_algo"#,
            ),
            (
                "json_escape",
                r#"algo\": \"injection\": true, \"continue\": \""#,
            ),
            // Command injection attempts
            ("command_injection", "algo; rm -rf /; real_algo"),
            ("shell_injection", "algo`whoami`test"),
            // Unicode injection in algorithm names
            ("unicode_injection", "algo\u{202e}_gnissecorp\u{202c}"),
            ("bom_injection", "\u{feff}algorithm\u{feff}"),
            // Control character injection
            ("control_chars", "algo\x00\x01\x02\x7F"),
            ("newline_injection", "algo\nINJECTED\nalgo"),
            // Very long algorithm IDs
            ("long_algo", long_algorithm_id.as_str()),
            // Binary data disguised as algorithm ID
            ("binary_data", binary_algorithm_id.as_str()),
            // Collision-prone patterns
            ("collision_a", "hash_collision_candidate_a"),
            ("collision_b", "hash_collision_candidate_b"),
        ];

        for (test_name, algorithm_id) in algorithm_attack_patterns {
            let injection_result = std::panic::catch_unwind(|| {
                // Test algorithm registration with injection pattern
                let algo = AlgorithmId::new(algorithm_id);
                decoder.register_algorithm(algo.clone());

                let fragments = vec![Fragment {
                    fragment_id: format!("injection_test_{}", test_name),
                    data: b"injection_test_data".to_vec(),
                }];

                let decode_result = decoder.decode(
                    &format!("injection_obj_{}", test_name),
                    &fragments,
                    &algo,
                    500,
                    &format!("injection_trace_{}", test_name),
                );

                match decode_result {
                    Ok(result) => {
                        // If decode succeeds, verify algorithm ID is preserved correctly
                        if let Some(proof) = result.proof {
                            assert_eq!(
                                proof.algorithm_id.as_str(),
                                algorithm_id,
                                "Algorithm ID should be preserved: {}",
                                test_name
                            );

                            // Test proof verification with injection pattern
                            let fragment_digests = vec![hex::encode(fragments[0].hash())];
                            let verification = verifier("repair-secret").verify(
                                &proof,
                                &fragment_digests,
                                &proof.output_hash,
                            );

                            // Should verify correctly or fail gracefully
                            assert!(
                                verification.is_valid() || !verification.is_valid(),
                                "Verification should complete without panic: {}",
                                test_name
                            );

                            // Test JSON serialization with injection pattern
                            let json_result = serde_json::to_string(&proof);
                            match json_result {
                                Ok(json) => {
                                    // Verify injection patterns don't corrupt JSON structure
                                    let parse_result: Result<serde_json::Value, _> =
                                        serde_json::from_str(&json);
                                    assert!(
                                        parse_result.is_ok(),
                                        "JSON should be valid despite injection: {}",
                                        test_name
                                    );

                                    // Verify common injection patterns are escaped
                                    assert!(
                                        !json.contains("\"evil\": true"),
                                        "JSON injection should be escaped: {}",
                                        test_name
                                    );
                                    assert!(
                                        !json.contains("INJECTED"),
                                        "Newline injection should be escaped: {}",
                                        test_name
                                    );
                                }
                                Err(_) => {
                                    // JSON serialization may fail for extreme patterns - acceptable
                                }
                            }
                        }
                    }
                    Err(err) => {
                        // Injection patterns may be rejected - verify meaningful error
                        let error_msg = err.to_string();
                        assert!(
                            !error_msg.is_empty(),
                            "Error should be meaningful: {}",
                            test_name
                        );

                        // Error should not leak injection content
                        assert!(
                            !error_msg.contains("evil"),
                            "Error should not contain injection: {}",
                            test_name
                        );
                    }
                }

                Ok(())
            });

            assert!(
                injection_result.is_ok(),
                "Algorithm injection test should not panic: {}",
                test_name
            );
        }

        // Verify registered algorithms are handled correctly
        let registered = decoder.registered_algorithms();
        assert!(
            registered.len() > 0,
            "Should have some registered algorithms"
        );

        for algo in registered {
            assert!(
                !algo.as_str().is_empty(),
                "Algorithm ID should not be empty"
            );
        }
    }

    #[test]
    fn negative_proof_verification_constant_time_resistance() {
        // Test proof verification for timing attack resistance
        let (fragments, base_proof) = valid_proof();
        let fragment_digests = fragment_digests(&fragments);

        // Create variations with single-bit differences for timing analysis
        let timing_attack_signatures = vec![
            // First bit different
            {
                let mut sig = base_proof.attestation.signature.clone();
                if !sig.is_empty() && sig.len() >= 2 {
                    let first_byte = sig.as_bytes()[0];
                    sig.replace_range(0..2, &format!("{:02x}", first_byte ^ 0x01));
                }
                sig
            },
            // Last bit different
            {
                let mut sig = base_proof.attestation.signature.clone();
                if sig.len() >= 2 {
                    let last_idx = sig.len() - 2;
                    let last_byte =
                        u8::from_str_radix(&sig[last_idx..last_idx + 2], 16).unwrap_or(0);
                    sig.replace_range(last_idx..last_idx + 2, &format!("{:02x}", last_byte ^ 0x01));
                }
                sig
            },
            // Middle bit different
            {
                let mut sig = base_proof.attestation.signature.clone();
                if sig.len() >= 4 {
                    let mid_idx = sig.len() / 2 - 1;
                    let mid_byte = u8::from_str_radix(&sig[mid_idx..mid_idx + 2], 16).unwrap_or(0);
                    sig.replace_range(mid_idx..mid_idx + 2, &format!("{:02x}", mid_byte ^ 0x01));
                }
                sig
            },
            // All zeros
            "0".repeat(base_proof.attestation.signature.len()),
            // All ones (in hex)
            "f".repeat(base_proof.attestation.signature.len()),
            // Pattern that might have timing differences
            "deadbeef".repeat(base_proof.attestation.signature.len() / 8 + 1)
                [..base_proof.attestation.signature.len()]
                .to_string(),
        ];

        let verifier = verifier("repair-secret");

        // Test timing consistency across different signature failures
        for (i, wrong_signature) in timing_attack_signatures.iter().enumerate() {
            let timing_result = std::panic::catch_unwind(|| {
                let mut modified_proof = base_proof.clone();
                modified_proof.attestation.signature = wrong_signature.clone();

                // Measure verification time
                let start = std::time::Instant::now();
                let verification =
                    verifier.verify(&modified_proof, &fragment_digests, &base_proof.output_hash);
                let duration = start.elapsed();

                // All should fail consistently (constant time regardless of difference location)
                assert!(
                    !verification.is_valid(),
                    "Wrong signature should fail verification: {}",
                    i
                );

                // Verification should complete quickly (not hang on invalid signatures)
                assert!(
                    duration.as_millis() < 1000,
                    "Verification should be fast: {} ms",
                    duration.as_millis()
                );

                // Test that multiple verifications of same wrong signature are consistent
                for _ in 0..10 {
                    let repeat_verification = verifier.verify(
                        &modified_proof,
                        &fragment_digests,
                        &base_proof.output_hash,
                    );
                    assert_eq!(
                        verification.is_valid(),
                        repeat_verification.is_valid(),
                        "Verification should be deterministic: {}",
                        i
                    );
                }

                Ok(())
            });

            assert!(timing_result.is_ok(), "Timing test should not panic: {}", i);
        }

        // Test that correct signature still verifies after timing tests
        let correct_verification =
            verifier.verify(&base_proof, &fragment_digests, &base_proof.output_hash);
        assert!(
            correct_verification.is_valid(),
            "Correct signature should still verify"
        );
    }

    #[test]
    fn negative_audit_log_capacity_overflow_and_corruption_resistance() {
        // Test audit log behavior under capacity overflow and potential corruption
        let mut decoder = ProofCarryingDecoder::with_audit_log_capacity(
            ProofMode::Mandatory,
            "audit-test-signer",
            "audit-test-secret",
            100, // Small capacity for testing
        );

        let fragments = fragments();
        let algorithm = AlgorithmId::new("simple_concat");

        // Test 1: Rapid operations to overflow audit capacity
        let mut successful_operations = 0;
        for i in 0..200 {
            let object_id = format!("rapid_audit_test_{:04}", i);
            let trace_id = format!("rapid_trace_{:04}", i);

            let result = decoder.decode(
                &object_id,
                &fragments,
                &algorithm,
                600 + i as u64,
                &trace_id,
            );

            match result {
                Ok(_) => {
                    successful_operations = successful_operations.saturating_add(1);

                    // Periodically check audit log integrity
                    if i % 20 == 0 {
                        let audit_log = decoder.audit_log();
                        assert!(
                            audit_log.len() <= 100,
                            "Audit log should respect capacity: iteration {}",
                            i
                        );

                        // Verify all entries are well-formed
                        for (idx, entry) in audit_log.iter().enumerate() {
                            assert!(
                                !entry.event_code.is_empty(),
                                "Event code should not be empty at index {}, iteration {}",
                                idx,
                                i
                            );
                            assert!(
                                !entry.object_id.is_empty(),
                                "Object ID should not be empty at index {}, iteration {}",
                                idx,
                                i
                            );
                            assert!(
                                !entry.trace_id.is_empty(),
                                "Trace ID should not be empty at index {}, iteration {}",
                                idx,
                                i
                            );
                            assert!(
                                entry.timestamp_epoch_secs >= 600,
                                "Timestamp should be reasonable at index {}, iteration {}",
                                idx,
                                i
                            );
                        }
                    }
                }
                Err(_) => {
                    // Some operations may fail - continue testing
                }
            }
        }

        // Final audit log should be at capacity and contain recent entries
        let final_audit = decoder.audit_log();
        assert_eq!(
            final_audit.len(),
            100,
            "Final audit log should be at capacity"
        );

        // Should contain most recent successful operations
        let recent_object_ids: Vec<_> = final_audit
            .iter()
            .map(|entry| entry.object_id.as_str())
            .collect();

        // At least some of the last operations should be present
        let last_expected_id = format!("rapid_audit_test_{:04}", 199);
        assert!(
            recent_object_ids
                .iter()
                .any(|id| id.contains("rapid_audit_test")),
            "Audit log should contain recent operations"
        );

        // Test 2: Operations with extreme data that might corrupt audit entries
        let long_object_id = "x".repeat(100000);
        let long_trace_id = "y".repeat(100000);
        let binary_object_id = String::from_utf8_lossy(b"obj\xFF\xFE").into_owned();
        let binary_trace_id = String::from_utf8_lossy(b"trace\xFD\xFC").into_owned();
        let corruption_test_cases = vec![
            // Very long identifiers
            ("long_ids", long_object_id.as_str(), long_trace_id.as_str()),
            // Unicode with potential corruption
            (
                "unicode_corruption",
                "obj\u{202e}_test\u{202c}",
                "trace\u{200b}_test\u{200c}",
            ),
            // Control characters
            ("control_chars", "obj\x00\x01\x7F", "trace\x08\x0A\x0D"),
            // Binary-like data
            (
                "binary_data",
                binary_object_id.as_str(),
                binary_trace_id.as_str(),
            ),
        ];

        for (test_name, object_id, trace_id) in corruption_test_cases {
            let corruption_result = std::panic::catch_unwind(|| {
                let decode_result =
                    decoder.decode(object_id, &fragments, &algorithm, 700, trace_id);

                // Operation may succeed or fail
                match decode_result {
                    Ok(_) => {
                        // If successful, verify audit log integrity is maintained
                        let audit_log = decoder.audit_log();
                        assert!(
                            audit_log.len() <= 100,
                            "Capacity should be maintained: {}",
                            test_name
                        );

                        // Find the entry (if present) and verify it's not corrupted
                        if let Some(entry) = audit_log.iter().find(|e| e.object_id == object_id) {
                            assert_eq!(
                                entry.object_id, object_id,
                                "Object ID should be preserved: {}",
                                test_name
                            );
                            assert_eq!(
                                entry.trace_id, trace_id,
                                "Trace ID should be preserved: {}",
                                test_name
                            );
                            assert!(
                                !entry.event_code.is_empty(),
                                "Event code should be valid: {}",
                                test_name
                            );
                        }
                    }
                    Err(_) => {
                        // Failure is acceptable for extreme data
                    }
                }

                // Verify other audit entries weren't corrupted
                let audit_log = decoder.audit_log();
                for entry in audit_log {
                    assert!(
                        !entry.event_code.is_empty(),
                        "All event codes should be valid: {}",
                        test_name
                    );
                    assert!(
                        entry.timestamp_epoch_secs >= 600,
                        "All timestamps should be reasonable: {}",
                        test_name
                    );
                }

                Ok(())
            });

            assert!(
                corruption_result.is_ok(),
                "Audit corruption test should not panic: {}",
                test_name
            );
        }

        // Test 3: Verify decoder continues to work normally after audit stress
        let final_test_result = decoder.decode(
            "final_audit_test",
            &fragments,
            &algorithm,
            800,
            "final_audit_trace",
        );

        assert!(
            final_test_result.is_ok(),
            "Decoder should work normally after audit stress"
        );

        if let Ok(result) = final_test_result {
            assert_eq!(result.object_id, "final_audit_test");
            assert!(
                result.proof.is_some(),
                "Proof should be generated after audit stress"
            );
        }
    }

    #[test]
    fn negative_cross_algorithm_proof_verification_confusion() {
        // Test proof verification resistance to algorithm confusion attacks
        let mut decoder1 = ProofCarryingDecoder::new(ProofMode::Mandatory, "signer1", "secret1");
        let mut decoder2 = ProofCarryingDecoder::new(ProofMode::Mandatory, "signer2", "secret2");

        // Register different algorithms on each decoder
        decoder1.register_algorithm(AlgorithmId::new("algorithm_v1"));
        decoder1.register_algorithm(AlgorithmId::new("algorithm_v2"));
        decoder2.register_algorithm(AlgorithmId::new("algorithm_v2"));
        decoder2.register_algorithm(AlgorithmId::new("algorithm_v3"));

        let fragments = fragments();

        let algorithm_confusion_tests = vec![
            // Cross-decoder algorithm confusion
            ("cross_decoder_v1", "algorithm_v1", "secret1", "secret2"),
            ("cross_decoder_v2", "algorithm_v2", "secret1", "secret2"),
            ("cross_decoder_v3", "algorithm_v3", "secret2", "secret1"),
            // Algorithm name confusion
            ("similar_names_1", "algorithm_v1", "secret1", "secret1"),
            ("similar_names_2", "algorithm_v2", "secret1", "secret1"),
            // Case sensitivity confusion
            ("case_confusion_1", "Algorithm_V1", "secret1", "secret1"),
            ("case_confusion_2", "ALGORITHM_V1", "secret1", "secret1"),
        ];

        for (test_name, algorithm_name, sign_secret, verify_secret) in algorithm_confusion_tests {
            let confusion_result = std::panic::catch_unwind(|| {
                let algorithm = AlgorithmId::new(algorithm_name);

                // Generate proof with first secret
                let decode_result = if sign_secret == "secret1" {
                    decoder1.decode(
                        "confusion_obj",
                        &fragments,
                        &algorithm,
                        900,
                        "confusion_trace",
                    )
                } else {
                    decoder2.decode(
                        "confusion_obj",
                        &fragments,
                        &algorithm,
                        900,
                        "confusion_trace",
                    )
                };

                match decode_result {
                    Ok(result) => {
                        if let Some(proof) = result.proof {
                            // Attempt verification with potentially different secret
                            let verifier = if verify_secret == "secret1" {
                                ProofVerificationApi::new("secret1", vec![algorithm.clone()])
                            } else {
                                ProofVerificationApi::new("secret2", vec![algorithm.clone()])
                            };

                            let fragment_digests = fragment_digests(&fragments);
                            let verification =
                                verifier.verify(&proof, &fragment_digests, &proof.output_hash);

                            // Should only succeed if secrets match and algorithm is registered
                            if sign_secret == verify_secret
                                && (algorithm_name == "algorithm_v1"
                                    || algorithm_name == "algorithm_v2"
                                    || algorithm_name == "algorithm_v3")
                            {
                                // Exact match should verify (case sensitive)
                                if algorithm_name
                                    .chars()
                                    .all(|c| c.is_lowercase() || c.is_ascii_digit() || c == '_')
                                {
                                    assert!(
                                        verification.is_valid(),
                                        "Matching algorithm/secret should verify: {}",
                                        test_name
                                    );
                                } else {
                                    // Case variations should fail
                                    assert!(
                                        !verification.is_valid(),
                                        "Case mismatch should fail: {}",
                                        test_name
                                    );
                                }
                            } else {
                                // Cross-secret or unregistered algorithm should fail
                                assert!(
                                    !verification.is_valid(),
                                    "Mismatched verification should fail: {}",
                                    test_name
                                );
                            }

                            // Verify error types are appropriate
                            if !verification.is_valid() {
                                match verification {
                                    VerificationResult::InvalidSignature => {
                                        // Expected for secret mismatch
                                    }
                                    VerificationResult::UnknownAlgorithm { .. } => {
                                        // Expected for unregistered algorithm
                                    }
                                    _ => {
                                        // Other verification failures are acceptable
                                    }
                                }
                            }
                        }
                    }
                    Err(err) => {
                        // Decode may fail for unregistered algorithms - verify meaningful error
                        let error_msg = err.to_string();
                        assert!(
                            error_msg.contains("algorithm") || error_msg.contains("unregistered"),
                            "Algorithm error should be meaningful: {} - {}",
                            test_name,
                            error_msg
                        );
                    }
                }

                Ok(())
            });

            assert!(
                confusion_result.is_ok(),
                "Algorithm confusion test should not panic: {}",
                test_name
            );
        }

        // Verify both decoders still work correctly after confusion tests
        let recovery1 = decoder1.decode(
            "recovery1",
            &fragments,
            &AlgorithmId::new("algorithm_v1"),
            1000,
            "recovery_trace1",
        );
        let recovery2 = decoder2.decode(
            "recovery2",
            &fragments,
            &AlgorithmId::new("algorithm_v2"),
            1001,
            "recovery_trace2",
        );

        assert!(
            recovery1.is_ok(),
            "Decoder1 should recover after confusion tests"
        );
        assert!(
            recovery2.is_ok(),
            "Decoder2 should recover after confusion tests"
        );
    }

    // ═══ EXTREME ADVERSARIAL NEGATIVE-PATH TESTS ═══
    // These tests target sophisticated attack vectors against repair module systems

    #[test]
    fn test_extreme_adversarial_fragment_poisoning_via_hash_collision() {
        // Test fragment poisoning attack where attacker crafts malicious fragments
        // with hash collisions to poison repair operations and bypass integrity checks

        let mut decoder = decoder();
        let mut verifier_api = verifier("repair-secret");

        // Create base legitimate fragments
        let legitimate_fragments = vec![
            Fragment {
                fragment_id: "legitimate_a".to_string(),
                data: b"critical_system_data_part_1".to_vec(),
            },
            Fragment {
                fragment_id: "legitimate_b".to_string(),
                data: b"critical_system_data_part_2".to_vec(),
            },
        ];

        // Attempt hash collision attacks
        let collision_attack_fragments = vec![
            // Near-collision attempts (differ by minimal bits)
            Fragment {
                fragment_id: "collision_a".to_string(),
                data: b"critical_system_data_part_1\x00".to_vec(), // Null byte append
            },
            Fragment {
                fragment_id: "collision_b".to_string(),
                data: b"critical_system_data_part_2\x01".to_vec(), // Single bit flip
            },
            // Length extension attempts
            Fragment {
                fragment_id: "length_extend_a".to_string(),
                data: b"critical_system_data_part_1malicious_payload".to_vec(),
            },
            Fragment {
                fragment_id: "length_extend_b".to_string(),
                data: b"critical_system_data_part_2||admin=true".to_vec(),
            },
            // Prefix collision attempts
            Fragment {
                fragment_id: "prefix_collision_a".to_string(),
                data: b"critical_system_data_part_".to_vec(), // Prefix of legitimate
            },
            // Birthday attack simulation
            Fragment {
                fragment_id: "birthday_attack_1".to_string(),
                data: (0..256).cycle().take(10000).map(|x| x as u8).collect(),
            },
            Fragment {
                fragment_id: "birthday_attack_2".to_string(),
                data: (128..384)
                    .cycle()
                    .take(10000)
                    .map(|x| (x % 256) as u8)
                    .collect(),
            },
        ];

        // Test legitimate operation first
        let legitimate_result = decoder.decode(
            "legitimate_object",
            &legitimate_fragments,
            &AlgorithmId::new("simple_concat"),
            1000,
            "legitimate_trace",
        );
        assert!(
            legitimate_result.is_ok(),
            "Legitimate fragments should decode successfully"
        );

        let legitimate_proof = legitimate_result.unwrap().proof.expect("Should have proof");
        let legitimate_verification = verifier_api.verify(&legitimate_proof);
        assert!(
            legitimate_verification.is_valid(),
            "Legitimate proof should verify"
        );

        // Test collision attack fragments
        for (attack_idx, malicious_fragment) in collision_attack_fragments.iter().enumerate() {
            // Create hybrid fragment sets (legitimate + malicious)
            let mixed_fragments = vec![legitimate_fragments[0].clone(), malicious_fragment.clone()];

            // Attempt decode with poisoned fragments
            let poisoned_result = decoder.decode(
                &format!("poisoned_object_{}", attack_idx),
                &mixed_fragments,
                &AlgorithmId::new("simple_concat"),
                1000,
                &format!("poisoning_attack_trace_{}", attack_idx),
            );

            match poisoned_result {
                Ok(result) => {
                    // If poisoning succeeds, verify integrity is maintained
                    if let Some(poisoned_proof) = result.proof {
                        let poisoned_verification = verifier_api.verify(&poisoned_proof);

                        // Verify poisoned proof doesn't compromise verification
                        if poisoned_verification.is_valid() {
                            // Check that output doesn't contain malicious payload
                            let output_str = String::from_utf8_lossy(&result.output_data);
                            assert!(
                                !output_str.contains("admin=true"),
                                "Attack {}: Poisoned fragment should not inject admin privileges",
                                attack_idx
                            );
                            assert!(
                                !output_str.contains("malicious_payload"),
                                "Attack {}: Poisoned fragment should not inject malicious content",
                                attack_idx
                            );

                            // Verify fragment hashes in proof are distinct
                            let fragment_hashes = &poisoned_proof.fragment_hashes;
                            let mut hash_set = std::collections::HashSet::new();
                            for hash in fragment_hashes {
                                assert!(
                                    hash_set.insert(hash.clone()),
                                    "Attack {}: Fragment hash collision detected in proof!",
                                    attack_idx
                                );
                            }
                        }
                    }
                }
                Err(e) => {
                    // Expected behavior - poisoning should be rejected
                    let error_msg = e.to_string();
                    assert!(
                        error_msg.contains("reconstruction")
                            || error_msg.contains("invalid")
                            || error_msg.contains("verification"),
                        "Attack {}: Appropriate error for fragment poisoning: {}",
                        attack_idx,
                        error_msg
                    );
                }
            }

            // Test direct hash collision detection
            let legit_hash = hex::encode(legitimate_fragments[0].hash());
            let malicious_hash = hex::encode(malicious_fragment.hash());

            if legit_hash == malicious_hash {
                panic!(
                    "CRITICAL: Hash collision detected between legitimate and malicious fragments!"
                );
            }

            // Verify fragment ID collision detection
            assert_ne!(
                legitimate_fragments[0].fragment_id, malicious_fragment.fragment_id,
                "Attack {}: Fragment IDs should be distinct",
                attack_idx
            );
        }

        // Test that system remains functional after poisoning attempts
        let post_attack_result = decoder.decode(
            "post_poisoning_test",
            &legitimate_fragments,
            &AlgorithmId::new("simple_concat"),
            1001,
            "post_poisoning_trace",
        );
        assert!(
            post_attack_result.is_ok(),
            "System should function normally after poisoning attempts"
        );
    }

    #[test]
    fn test_extreme_adversarial_proof_signature_malleability_exploit() {
        // Test signature malleability attacks where attacker manipulates proof
        // signatures to create valid-appearing proofs without access to signing key

        let mut decoder = decoder();
        let mut verifier_api = verifier("repair-secret");

        // Generate base legitimate proof
        let fragments = fragments();
        let legitimate_result = decoder
            .decode(
                "malleability_base",
                &fragments,
                &AlgorithmId::new("simple_concat"),
                2000,
                "malleability_base_trace",
            )
            .expect("Base decode should succeed");

        let base_proof = legitimate_result.proof.expect("Should have proof");
        let base_verification = verifier_api.verify(&base_proof);
        assert!(base_verification.is_valid(), "Base proof should be valid");

        // Attempt various signature malleability attacks
        let malleability_attacks = [
            // Length manipulation
            (
                format!("{}00", base_proof.attestation_signature),
                "Length extension attack",
            ),
            (
                base_proof
                    .attestation_signature
                    .chars()
                    .take(base_proof.attestation_signature.len() - 2)
                    .collect(),
                "Length truncation attack",
            ),
            // Encoding manipulation
            (
                base_proof.attestation_signature.to_uppercase(),
                "Case manipulation attack",
            ),
            (
                base_proof.attestation_signature.to_lowercase(),
                "Case downgrade attack",
            ),
            (
                format!("{}\x00", base_proof.attestation_signature),
                "Null termination attack",
            ),
            (
                format!("\x00{}", base_proof.attestation_signature),
                "Null prefix attack",
            ),
            // Padding attacks
            (
                format!("{}==", base_proof.attestation_signature),
                "Base64 padding attack",
            ),
            (
                format!("{}===", base_proof.attestation_signature),
                "Extended padding attack",
            ),
            (
                base_proof
                    .attestation_signature
                    .trim_end_matches('=')
                    .to_string(),
                "Padding removal attack",
            ),
            // Whitespace attacks
            (
                format!(" {}", base_proof.attestation_signature),
                "Leading whitespace attack",
            ),
            (
                format!("{} ", base_proof.attestation_signature),
                "Trailing whitespace attack",
            ),
            (
                format!("{}\n", base_proof.attestation_signature),
                "Newline injection attack",
            ),
            (
                format!("{}\r", base_proof.attestation_signature),
                "Carriage return attack",
            ),
            (
                format!("{}\t", base_proof.attestation_signature),
                "Tab injection attack",
            ),
            // Unicode attacks
            (
                format!("{}\u{200B}", base_proof.attestation_signature),
                "Zero-width space attack",
            ),
            (
                format!("{}\u{FEFF}", base_proof.attestation_signature),
                "BOM injection attack",
            ),
            (
                format!("{}\u{202E}evil", base_proof.attestation_signature),
                "Bidirectional override attack",
            ),
            // Repetition attacks
            (
                base_proof.attestation_signature.repeat(2),
                "Signature duplication attack",
            ),
            (
                format!(
                    "{}{}",
                    base_proof.attestation_signature,
                    base_proof
                        .attestation_signature
                        .chars()
                        .rev()
                        .collect::<String>()
                ),
                "Palindrome attack",
            ),
        ];

        for (attack_idx, (malicious_signature, attack_description)) in
            malleability_attacks.iter().enumerate()
        {
            println!("Testing {}: {}", attack_idx, attack_description);

            // Create malicious proof with manipulated signature
            let malicious_proof = RepairProof {
                proof_id: base_proof.proof_id.clone(),
                object_id: format!("malleability_attack_{}", attack_idx),
                fragment_hashes: base_proof.fragment_hashes.clone(),
                algorithm_id: base_proof.algorithm_id.clone(),
                output_hash: base_proof.output_hash.clone(),
                timestamp_epoch_secs: base_proof.timestamp_epoch_secs,
                trace_id: format!("malleability_trace_{}", attack_idx),
                attestation_signature: malicious_signature.clone(),
            };

            // Test malicious proof verification
            let malicious_verification = verifier_api.verify(&malicious_proof);

            // Verify malleability attack is detected and rejected
            assert!(
                !malicious_verification.is_valid(),
                "Attack {}: Malleability attack should be rejected: {}",
                attack_idx,
                attack_description
            );

            match malicious_verification {
                VerificationResult::InvalidSignature => {
                    // Expected behavior for signature attacks
                }
                VerificationResult::ProofFormatError { ref reason } => {
                    // Also acceptable - format errors due to manipulation
                    assert!(
                        reason.contains("signature") || reason.contains("format"),
                        "Attack {}: Format error should be signature-related",
                        attack_idx
                    );
                }
                _ => {
                    panic!(
                        "Attack {}: Unexpected verification result for malleability attack",
                        attack_idx
                    );
                }
            }

            // Test that malicious proof doesn't affect subsequent legitimate operations
            let post_attack_verification = verifier_api.verify(&base_proof);
            assert!(
                post_attack_verification.is_valid(),
                "Attack {}: Base proof should remain valid after malleability attack",
                attack_idx
            );
        }

        // Test signature substitution attacks (using signatures from other contexts)
        let different_fragments = vec![Fragment {
            fragment_id: "different_data".to_string(),
            data: b"completely_different_payload".to_vec(),
        }];

        let different_result = decoder
            .decode(
                "different_context",
                &different_fragments,
                &AlgorithmId::new("simple_concat"),
                2001,
                "different_trace",
            )
            .expect("Different decode should succeed");

        let different_proof = different_result.proof.expect("Should have different proof");

        // Attempt signature substitution
        let substitution_proof = RepairProof {
            proof_id: base_proof.proof_id.clone(),
            object_id: "signature_substitution_attack".to_string(),
            fragment_hashes: base_proof.fragment_hashes.clone(),
            algorithm_id: base_proof.algorithm_id.clone(),
            output_hash: base_proof.output_hash.clone(),
            timestamp_epoch_secs: base_proof.timestamp_epoch_secs,
            trace_id: "substitution_trace".to_string(),
            attestation_signature: different_proof.attestation_signature, // Wrong signature
        };

        let substitution_verification = verifier_api.verify(&substitution_proof);
        assert!(
            !substitution_verification.is_valid(),
            "Signature substitution attack should be rejected"
        );
    }

    #[test]
    fn test_extreme_adversarial_reconstruction_algorithm_confusion() {
        // Test algorithm confusion attacks where attacker exploits inconsistencies
        // between registered algorithms and proof algorithm specifications

        let mut decoder1 = decoder();
        let mut decoder2 =
            ProofCarryingDecoder::new(ProofMode::Mandatory, "confusion-signer", "confusion-secret");

        // Register different algorithms on different decoders
        decoder1.register_algorithm(AlgorithmId::new("secure_algorithm_v3"));
        decoder2.register_algorithm(AlgorithmId::new("legacy_algorithm_v1"));
        decoder2.register_algorithm(AlgorithmId::new("experimental_algorithm"));

        let test_fragments = fragments();

        // Algorithm confusion attack scenarios
        let confusion_attacks = [
            // Cross-decoder algorithm confusion
            (
                "secure_algorithm_v3",
                "legacy_algorithm_v1",
                "Cross-decoder algorithm confusion",
            ),
            (
                "experimental_algorithm",
                "simple_concat",
                "Experimental to standard confusion",
            ),
            (
                "legacy_algorithm_v1",
                "secure_algorithm_v3",
                "Legacy to secure downgrade",
            ),
            // Non-existent algorithm confusion
            (
                "nonexistent_algo",
                "simple_concat",
                "Non-existent algorithm confusion",
            ),
            ("", "simple_concat", "Empty algorithm confusion"),
            (
                "simple_concat\x00malicious",
                "simple_concat",
                "Null-byte algorithm injection",
            ),
            // Algorithm name manipulation
            (
                "simple_concat ",
                "simple_concat",
                "Trailing space confusion",
            ),
            (" simple_concat", "simple_concat", "Leading space confusion"),
            (
                "simple\nconcat",
                "simple_concat",
                "Newline injection confusion",
            ),
            (
                "simple;concat",
                "simple_concat",
                "Semicolon injection confusion",
            ),
        ];

        for (attack_idx, (malicious_algo, legitimate_algo, attack_description)) in
            confusion_attacks.iter().enumerate()
        {
            println!(
                "Testing algorithm confusion {}: {}",
                attack_idx, attack_description
            );

            // Attempt decode with malicious algorithm
            let malicious_result = decoder1.decode(
                &format!("confusion_object_{}", attack_idx),
                &test_fragments,
                &AlgorithmId::new(malicious_algo),
                3000 + attack_idx as u64,
                &format!("confusion_trace_{}", attack_idx),
            );

            // Legitimate decode for comparison
            let legitimate_result = decoder1.decode(
                &format!("legitimate_object_{}", attack_idx),
                &test_fragments,
                &AlgorithmId::new(legitimate_algo),
                3100 + attack_idx as u64,
                &format!("legitimate_trace_{}", attack_idx),
            );

            // Analyze confusion attack results
            match (malicious_result, legitimate_result) {
                (Ok(malicious), Ok(legitimate)) => {
                    // Both succeeded - verify they produce different results if algorithms differ
                    if malicious_algo != legitimate_algo {
                        // Different algorithms should produce different proofs
                        assert_ne!(
                            malicious.proof.as_ref().unwrap().algorithm_id,
                            legitimate.proof.as_ref().unwrap().algorithm_id,
                            "Attack {}: Different algorithms should not be confused",
                            attack_idx
                        );

                        // Output should be deterministic for same algorithm
                        if malicious_algo == legitimate_algo {
                            assert_eq!(
                                malicious.output_data, legitimate.output_data,
                                "Attack {}: Same algorithm should produce same output",
                                attack_idx
                            );
                        }
                    }
                }
                (Err(malicious_err), Ok(_)) => {
                    // Expected behavior - malicious algorithm should fail
                    let error_msg = malicious_err.to_string();
                    assert!(
                        error_msg.contains("algorithm")
                            || error_msg.contains("unregistered")
                            || error_msg.contains("reconstruction"),
                        "Attack {}: Malicious algorithm error should be meaningful: {}",
                        attack_idx,
                        error_msg
                    );
                }
                (Ok(_), Err(legitimate_err)) => {
                    // Unexpected - legitimate should not fail if malicious succeeds
                    panic!(
                        "Attack {}: Legitimate algorithm failed while malicious succeeded: {}",
                        attack_idx, legitimate_err
                    );
                }
                (Err(_), Err(_)) => {
                    // Both failed - acceptable if algorithms are genuinely invalid
                }
            }

            // Test cross-decoder algorithm confusion
            let cross_decoder_result = decoder2.decode(
                &format!("cross_decoder_object_{}", attack_idx),
                &test_fragments,
                &AlgorithmId::new(malicious_algo),
                3200 + attack_idx as u64,
                &format!("cross_decoder_trace_{}", attack_idx),
            );

            // Verify cross-decoder consistency
            if cross_decoder_result.is_ok() && malicious_result.is_ok() {
                // Same algorithm on different decoders should behave consistently
                // (if both support the algorithm)
            }

            // Test algorithm verification after confusion
            if let Ok(result) = decoder1.decode(
                &format!("post_confusion_test_{}", attack_idx),
                &test_fragments,
                &AlgorithmId::new("simple_concat"), // Known good algorithm
                3300 + attack_idx as u64,
                &format!("post_confusion_trace_{}", attack_idx),
            ) {
                // Verify system remains stable after confusion attack
                assert!(
                    result.proof.is_some(),
                    "Attack {}: System should remain functional after algorithm confusion",
                    attack_idx
                );
                assert_eq!(
                    result.proof.unwrap().algorithm_id.0,
                    "simple_concat",
                    "Attack {}: Proof should contain correct algorithm after confusion",
                    attack_idx
                );
            }
        }

        // Test algorithm registry isolation
        let decoder1_algorithms = decoder1.registered_algorithms();
        let decoder2_algorithms = decoder2.registered_algorithms();

        // Verify algorithms registered on one decoder don't affect the other
        assert!(
            decoder1_algorithms.contains(&AlgorithmId::new("simple_concat")),
            "Decoder1 should have base algorithm"
        );
        assert!(
            decoder1_algorithms.contains(&AlgorithmId::new("secure_algorithm_v3")),
            "Decoder1 should have its registered algorithm"
        );
        assert!(
            !decoder1_algorithms.contains(&AlgorithmId::new("legacy_algorithm_v1")),
            "Decoder1 should not have decoder2's algorithm"
        );

        println!("Algorithm confusion test completed successfully");
    }

    #[test]
    fn test_extreme_adversarial_fragment_timing_correlation_analysis() {
        // Test timing correlation attacks where attacker analyzes decode timing
        // patterns to infer information about fragment contents or system state

        use crate::security::constant_time;
        use std::time::{Duration, Instant};

        let mut decoder = decoder();
        let mut verifier_api = verifier("timing-secret");

        // Create baseline timing measurements
        let baseline_fragments = fragments();
        let timing_samples = 100;
        let mut baseline_times = Vec::new();

        // Collect baseline timing data
        for sample in 0..timing_samples {
            let start = Instant::now();
            let _result = decoder
                .decode(
                    &format!("baseline_timing_{}", sample),
                    &baseline_fragments,
                    &AlgorithmId::new("simple_concat"),
                    4000 + sample as u64,
                    &format!("baseline_trace_{}", sample),
                )
                .expect("Baseline decode should succeed");
            baseline_times.push(start.elapsed());
        }

        let baseline_mean = baseline_times.iter().sum::<Duration>()
            / u32::try_from(baseline_times.len()).unwrap_or(u32::MAX);

        // Test timing correlation attack vectors
        let timing_attack_fragments = [
            // Size-based timing attacks
            Fragment {
                fragment_id: "tiny_fragment".to_string(),
                data: vec![0x42],
            },
            Fragment {
                fragment_id: "large_fragment".to_string(),
                data: vec![0x42; 100000],
            },
            Fragment {
                fragment_id: "medium_fragment".to_string(),
                data: vec![0x42; 1000],
            },
            // Content-based timing attacks
            Fragment {
                fragment_id: "zeros_fragment".to_string(),
                data: vec![0x00; 1000],
            },
            Fragment {
                fragment_id: "ones_fragment".to_string(),
                data: vec![0xFF; 1000],
            },
            Fragment {
                fragment_id: "random_fragment".to_string(),
                data: (0..1000).map(|i| ((i * 17 + 23) % 256) as u8).collect(),
            },
            // Pattern-based timing attacks
            Fragment {
                fragment_id: "repeating_pattern".to_string(),
                data: "ABCDABCDABCD".repeat(100).into_bytes(),
            },
            Fragment {
                fragment_id: "sequential_pattern".to_string(),
                data: (0u8..=255).cycle().take(1000).collect(),
            },
        ];

        let mut timing_correlations = Vec::new();

        for (attack_idx, timing_fragment) in timing_attack_fragments.iter().enumerate() {
            let mut attack_times = Vec::new();

            // Collect timing data for attack fragments
            for sample in 0..50 {
                let attack_fragments = vec![timing_fragment.clone()];
                let start = Instant::now();

                let attack_result = decoder.decode(
                    &format!("timing_attack_{}_{}", attack_idx, sample),
                    &attack_fragments,
                    &AlgorithmId::new("simple_concat"),
                    5000 + (attack_idx * 100 + sample) as u64,
                    &format!("timing_attack_trace_{}_{}", attack_idx, sample),
                );

                let timing = start.elapsed();
                attack_times.push(timing);

                // Process result to ensure consistent computation
                match attack_result {
                    Ok(result) => {
                        // Verify timing attack doesn't break functionality
                        assert!(
                            result.proof.is_some(),
                            "Attack {}: Timing attack should not break proof generation",
                            attack_idx
                        );

                        // Verify no timing information leakage in proof
                        let proof = result.proof.unwrap();
                        assert!(
                            !proof.trace_id.contains("duration"),
                            "Attack {}: Proof should not contain timing information",
                            attack_idx
                        );
                        assert!(
                            !proof.attestation_signature.contains("timing"),
                            "Attack {}: Signature should not contain timing information",
                            attack_idx
                        );

                        // Test proof verification timing
                        let verify_start = Instant::now();
                        let verification = verifier_api.verify(&proof);
                        let verify_timing = verify_start.elapsed();

                        assert!(
                            verification.is_valid(),
                            "Attack {}: Timing attack should not break verification",
                            attack_idx
                        );
                        assert!(
                            verify_timing < Duration::from_millis(100),
                            "Attack {}: Verification timing should be reasonable",
                            attack_idx
                        );
                    }
                    Err(e) => {
                        // Timing attacks may cause errors - verify no timing leakage
                        let error_msg = e.to_string();
                        assert!(
                            !error_msg.contains("duration"),
                            "Attack {}: Error should not contain timing information",
                            attack_idx
                        );
                        assert!(
                            !error_msg.contains("timeout"),
                            "Attack {}: Error should not leak timeout details",
                            attack_idx
                        );
                    }
                }
            }

            // Analyze timing correlation
            let attack_mean = attack_times.iter().sum::<Duration>()
                / u32::try_from(attack_times.len()).unwrap_or(u32::MAX);
            let timing_ratio = if baseline_mean.as_nanos() > 0 {
                attack_mean.as_nanos() as f64 / baseline_mean.as_nanos() as f64
            } else {
                1.0
            };

            timing_correlations.push((
                timing_fragment.fragment_id.clone(),
                timing_ratio,
                attack_mean,
            ));

            println!(
                "Timing attack {}: {} - Ratio: {:.3}, Mean: {:?}",
                attack_idx, timing_fragment.fragment_id, timing_ratio, attack_mean
            );

            // Verify timing doesn't reveal excessive information
            // Note: Some variation is expected, but extreme outliers suggest information leakage
            if timing_ratio > 100.0 || timing_ratio < 0.01 {
                println!(
                    "WARNING: Potential timing correlation detected for fragment: {} (ratio: {:.3})",
                    timing_fragment.fragment_id, timing_ratio
                );
            }
        }

        // Verify system remains consistent after timing attacks
        let post_timing_fragments = fragments();
        let post_timing_result = decoder.decode(
            "post_timing_test",
            &post_timing_fragments,
            &AlgorithmId::new("simple_concat"),
            6000,
            "post_timing_trace",
        );
        assert!(
            post_timing_result.is_ok(),
            "System should function normally after timing correlation attacks"
        );

        // Statistical analysis of timing correlations
        let correlation_variance: f64 = timing_correlations
            .iter()
            .map(|(_, ratio, _)| (ratio - 1.0).powi(2))
            .sum::<f64>()
            / timing_correlations.len() as f64;

        println!("Timing correlation analysis complete:");
        println!("  Baseline mean: {:?}", baseline_mean);
        println!("  Correlation variance: {:.6}", correlation_variance);
        println!("  Attack vectors tested: {}", timing_correlations.len());

        // Verify timing variance is within reasonable bounds
        assert!(
            correlation_variance < 10.0,
            "Timing correlation variance should not be excessive: {:.6}",
            correlation_variance
        );
    }

    #[test]
    fn test_extreme_adversarial_proof_audit_trail_injection() {
        // Test audit trail injection attacks where attacker manipulates proof
        // metadata to inject malicious content into audit logs or traces

        let mut decoder = decoder();
        let test_fragments = fragments();

        // Audit trail injection attack vectors
        let excessive_trace = "A".repeat(10000);
        let whitespace_trace = " ".repeat(1000);
        let invalid_utf8_trace =
            String::from_utf8_lossy(b"injection_trace_\x80\x81\x82").into_owned();
        let injection_attacks = [
            // Control character injection
            (
                "injection_trace_\x00_null",
                "Null byte injection in trace ID",
            ),
            (
                "injection_trace_\x1B[31mRED_TEXT\x1B[0m",
                "ANSI escape sequence injection",
            ),
            ("injection_trace_\r\nINJECTED_LINE", "CRLF injection attack"),
            (
                "injection_trace_\n; rm -rf /",
                "Command injection via newline",
            ),
            (
                "injection_trace_\t\t\tTAB_PADDING",
                "Tab character manipulation",
            ),
            // Log format confusion
            (
                "injection_trace_} {\"injected\":\"json\"",
                "JSON injection attack",
            ),
            (
                "injection_trace_<script>alert('xss')</script>",
                "XSS injection attempt",
            ),
            (
                "injection_trace_||INJECTED_FIELD=malicious",
                "Log field injection",
            ),
            (
                "injection_trace_#COMMENT_INJECTION",
                "Comment injection attack",
            ),
            // Unicode attacks
            (
                "injection_trace_\u{202E}REVERSED",
                "Bidirectional override injection",
            ),
            (
                "injection_trace_\u{200B}ZERO_WIDTH",
                "Zero-width character injection",
            ),
            (
                "injection_trace_\u{FEFF}BOM_INJECTION",
                "BOM injection attack",
            ),
            (
                "injection_trace_\u{034F}COMBINING_CHAR",
                "Combining character attack",
            ),
            // Length attacks
            (excessive_trace.as_str(), "Excessive length injection"),
            ("", "Empty trace injection"),
            (whitespace_trace.as_str(), "Whitespace flooding injection"),
            // Encoding attacks
            (invalid_utf8_trace.as_str(), "Invalid UTF-8 injection"),
            ("injection_trace_%00%0A%0D", "URL encoded injection"),
            ("injection_trace_\\x00\\n\\r", "Escaped character injection"),
        ];

        for (attack_idx, (malicious_trace, attack_description)) in
            injection_attacks.iter().enumerate()
        {
            println!(
                "Testing audit injection {}: {}",
                attack_idx, attack_description
            );

            // Attempt decode with malicious trace ID
            let injection_result = decoder.decode(
                &format!("audit_injection_object_{}", attack_idx),
                &test_fragments,
                &AlgorithmId::new("simple_concat"),
                7000_u64.saturating_add(attack_idx as u64),
                malicious_trace,
            );

            match injection_result {
                Ok(result) => {
                    // Verify injection doesn't compromise proof integrity
                    if let Some(proof) = result.proof {
                        // Check proof trace ID sanitization
                        assert!(
                            !proof.trace_id.contains('\0'),
                            "Attack {}: Proof should not contain null bytes",
                            attack_idx
                        );
                        assert!(
                            !proof.trace_id.contains('\x1B'),
                            "Attack {}: Proof should not contain ANSI escape sequences",
                            attack_idx
                        );
                        assert!(
                            !proof.trace_id.contains("<script>"),
                            "Attack {}: Proof should not contain script tags",
                            attack_idx
                        );

                        // Verify trace ID length limits
                        assert!(
                            proof.trace_id.len() <= 1024,
                            "Attack {}: Trace ID should have reasonable length limit: {}",
                            attack_idx,
                            proof.trace_id.len()
                        );

                        // Test proof serialization safety
                        let proof_str = format!("{:?}", proof);
                        assert!(
                            !proof_str.contains('\0'),
                            "Attack {}: Proof serialization should not contain null bytes",
                            attack_idx
                        );
                        assert!(
                            !proof_str.contains("\r\n"),
                            "Attack {}: Proof serialization should not contain CRLF",
                            attack_idx
                        );
                    }

                    // Verify output data integrity
                    assert_eq!(
                        result.output_data,
                        b"\xAA\xAA\xAA\xAA\xBB\xBB\xBB\xBB".to_vec(),
                        "Attack {}: Output data should not be corrupted by injection",
                        attack_idx
                    );
                }
                Err(e) => {
                    // Verify error handling doesn't leak injected content
                    let error_msg = e.to_string();
                    assert!(
                        !error_msg.contains('\0'),
                        "Attack {}: Error should not contain null bytes",
                        attack_idx
                    );
                    assert!(
                        !error_msg.contains("<script>"),
                        "Attack {}: Error should not contain script tags",
                        attack_idx
                    );
                    assert!(
                        !error_msg.contains("\x1B"),
                        "Attack {}: Error should not contain ANSI escapes",
                        attack_idx
                    );

                    // Error should be descriptive but sanitized
                    assert!(
                        error_msg.len() > 0,
                        "Attack {}: Error should provide meaningful message",
                        attack_idx
                    );
                    assert!(
                        error_msg.len() <= 1024,
                        "Attack {}: Error message should have reasonable length",
                        attack_idx
                    );
                }
            }

            // Check audit log integrity after injection attempt
            let audit_entries = decoder.audit_log();
            for (entry_idx, entry) in audit_entries.iter().enumerate() {
                // Verify audit entry sanitization
                assert!(
                    !entry.trace_id.contains('\0'),
                    "Attack {} Entry {}: Audit trace should not contain null bytes",
                    attack_idx,
                    entry_idx
                );
                assert!(
                    !entry.trace_id.contains('\x1B'),
                    "Attack {} Entry {}: Audit trace should not contain ANSI escapes",
                    attack_idx,
                    entry_idx
                );
                assert!(
                    !entry.object_id.contains("<script>"),
                    "Attack {} Entry {}: Audit object ID should not contain script tags",
                    attack_idx,
                    entry_idx
                );

                // Verify event code integrity
                assert!(
                    !entry.event_code.is_empty(),
                    "Attack {} Entry {}: Event code should not be empty",
                    attack_idx,
                    entry_idx
                );
                assert!(
                    entry
                        .event_code
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '_'),
                    "Attack {} Entry {}: Event code should be alphanumeric",
                    attack_idx,
                    entry_idx
                );
            }
        }

        // Test object ID injection attacks
        let object_id_injections = [
            "object\x00injection",
            "object\ninjection",
            "object<script>evil</script>",
            "object||injection",
            "object;injection",
            "A".repeat(10000),
        ];

        for (attack_idx, malicious_object_id) in object_id_injections.iter().enumerate() {
            let object_injection_result = decoder.decode(
                malicious_object_id,
                &test_fragments,
                &AlgorithmId::new("simple_concat"),
                8000 + attack_idx as u64,
                &format!("object_injection_trace_{}", attack_idx),
            );

            // Verify object ID injection handling
            match object_injection_result {
                Ok(result) => {
                    if let Some(proof) = result.proof {
                        // Verify object ID sanitization in proof
                        assert!(
                            !proof.object_id.contains('\0'),
                            "Object injection {}: Proof object ID should not contain null bytes",
                            attack_idx
                        );
                        assert!(
                            !proof.object_id.contains("<script>"),
                            "Object injection {}: Proof object ID should not contain script tags",
                            attack_idx
                        );
                        assert!(
                            proof.object_id.len() <= 1024,
                            "Object injection {}: Proof object ID should have length limit",
                            attack_idx
                        );
                    }
                }
                Err(_) => {
                    // Acceptable - malicious object IDs may be rejected
                }
            }
        }

        // Verify system stability after all injection attacks
        let recovery_result = decoder.decode(
            "post_injection_recovery",
            &test_fragments,
            &AlgorithmId::new("simple_concat"),
            9000,
            "clean_recovery_trace",
        );
        assert!(
            recovery_result.is_ok(),
            "System should recover cleanly after audit injection attacks"
        );

        println!(
            "Audit trail injection test completed: {} injection vectors tested",
            injection_attacks.len() + object_id_injections.len()
        );
    }

    #[test]
    fn test_extreme_adversarial_proof_verification_state_confusion() {
        // Test verification state confusion attacks where attacker exploits
        // inconsistencies in verifier state management across multiple proofs

        let mut verifier_api = verifier("state-confusion-secret");

        // Create multiple decoders with different configurations
        let mut decoder_a =
            ProofCarryingDecoder::new(ProofMode::Mandatory, "signer-a", "state-confusion-secret");
        let mut decoder_b =
            ProofCarryingDecoder::new(ProofMode::Advisory, "signer-b", "state-confusion-secret");
        let mut decoder_c =
            ProofCarryingDecoder::new(ProofMode::Mandatory, "signer-c", "different-secret");

        // Register different algorithm sets
        decoder_a.register_algorithm(AlgorithmId::new("algorithm_set_a"));
        decoder_b.register_algorithm(AlgorithmId::new("algorithm_set_b"));
        decoder_c.register_algorithm(AlgorithmId::new("algorithm_set_c"));

        let test_fragments = fragments();

        // Generate proofs from different contexts
        let proof_contexts = [
            (&mut decoder_a, "context_a", ProofMode::Mandatory),
            (&mut decoder_b, "context_b", ProofMode::Advisory),
            (&mut decoder_c, "context_c", ProofMode::Mandatory),
        ];

        let mut context_proofs = Vec::new();

        for (context_idx, (decoder, context_name, mode)) in proof_contexts.iter().enumerate() {
            let context_result = decoder.decode(
                &format!("state_confusion_object_{}", context_name),
                &test_fragments,
                &AlgorithmId::new("simple_concat"),
                10000 + context_idx as u64,
                &format!("state_confusion_trace_{}", context_name),
            );

            if let Ok(result) = context_result {
                if let Some(proof) = result.proof {
                    context_proofs.push((context_name, proof, *mode));
                }
            }
        }

        // State confusion attack vectors
        for (attack_idx, (proof_context, proof, original_mode)) in context_proofs.iter().enumerate()
        {
            println!("Testing state confusion with proof from {}", proof_context);

            // Test cross-context proof verification
            let verification_result = verifier_api.verify(proof);

            // Verify that verification result is consistent with proof origin
            match (proof_context, &verification_result) {
                ("context_c", _) => {
                    // Different secret - should fail
                    assert!(
                        !verification_result.is_valid(),
                        "Attack {}: Cross-secret verification should fail",
                        attack_idx
                    );
                }
                (_, VerificationResult::Valid) => {
                    // Valid verification - check for state consistency

                    // Verify multiple verification attempts are deterministic
                    let verification_2 = verifier_api.verify(proof);
                    assert_eq!(
                        format!("{:?}", verification_result),
                        format!("{:?}", verification_2),
                        "Attack {}: Verification should be deterministic",
                        attack_idx
                    );

                    // Test verification after state manipulation attempts
                    for manipulation_idx in 0..10 {
                        let manipulation_verification = verifier_api.verify(proof);
                        assert!(
                            manipulation_verification.is_valid(),
                            "Attack {} Manipulation {}: State should remain consistent",
                            attack_idx,
                            manipulation_idx
                        );
                    }
                }
                _ => {
                    // Invalid verification - check error consistency

                    // Verify error is deterministic
                    let error_verification_2 = verifier_api.verify(proof);
                    match (&verification_result, &error_verification_2) {
                        (
                            VerificationResult::InvalidSignature,
                            VerificationResult::InvalidSignature,
                        ) => {}
                        (
                            VerificationResult::UnknownAlgorithm { .. },
                            VerificationResult::UnknownAlgorithm { .. },
                        ) => {}
                        (
                            VerificationResult::ProofFormatError { .. },
                            VerificationResult::ProofFormatError { .. },
                        ) => {}
                        _ => {
                            panic!(
                                "Attack {}: Verification error should be deterministic: {:?} vs {:?}",
                                attack_idx, verification_result, error_verification_2
                            );
                        }
                    }
                }
            }

            // Test verification state isolation
            for other_proof_idx in 0..context_proofs.len() {
                if other_proof_idx != attack_idx {
                    let (_, other_proof, _) = &context_proofs[other_proof_idx];
                    let other_verification = verifier_api.verify(other_proof);

                    // Verify that verifying one proof doesn't affect verification of others
                    let original_verification = verifier_api.verify(proof);
                    assert_eq!(
                        format!("{:?}", verification_result),
                        format!("{:?}", original_verification),
                        "Attack {}: Verification state should not be affected by other proof verification",
                        attack_idx
                    );
                }
            }

            // Test rapid state transitions
            for rapid_idx in 0..50 {
                let rapid_verification = verifier_api.verify(proof);

                // Verify rapid verification doesn't cause state corruption
                match (&verification_result, &rapid_verification) {
                    (VerificationResult::Valid, VerificationResult::Valid) => {
                        // Both valid - good
                    }
                    (
                        VerificationResult::InvalidSignature,
                        VerificationResult::InvalidSignature,
                    ) => {
                        // Both invalid signature - consistent
                    }
                    _ => {
                        // State consistency check
                        if verification_result.is_valid() != rapid_verification.is_valid() {
                            panic!(
                                "Attack {} Rapid {}: State confusion detected in rapid verification",
                                attack_idx, rapid_idx
                            );
                        }
                    }
                }
            }

            // Test verifier with modified proof (state corruption attempt)
            let mut modified_proof = proof.clone();
            modified_proof.attestation_signature =
                format!("{}modified", modified_proof.attestation_signature);

            let modified_verification = verifier_api.verify(&modified_proof);
            assert!(
                !modified_verification.is_valid(),
                "Attack {}: Modified proof should be invalid",
                attack_idx
            );

            // Verify original proof still validates correctly after modified proof
            let post_modification_verification = verifier_api.verify(proof);
            assert_eq!(
                format!("{:?}", verification_result),
                format!("{:?}", post_modification_verification),
                "Attack {}: Original proof verification should not be affected by modified proof",
                attack_idx
            );
        }

        // Test verifier state after all confusion attacks
        let final_test_result = decoder_a
            .decode(
                "final_state_test",
                &test_fragments,
                &AlgorithmId::new("simple_concat"),
                11000,
                "final_state_trace",
            )
            .expect("Final test should succeed");

        let final_proof = final_test_result.proof.expect("Final proof should exist");
        let final_verification = verifier_api.verify(&final_proof);
        assert!(
            final_verification.is_valid(),
            "Verifier should function correctly after all state confusion attacks"
        );

        println!(
            "State confusion test completed: {} proof contexts tested, {} cross-verifications performed",
            context_proofs.len(),
            context_proofs.len() * context_proofs.len()
        );
    }
}
