pub mod claim_compiler;

#[cfg(test)]
mod additional_negative_tests {
    use super::claim_compiler::{
        ClaimCompiler, ClaimRejectionReason, CompilationResult, CompiledContract, CompilerConfig,
        ScoreboardConfig, ScoreboardPipeline, ScoreboardRejectionReason, ScoreboardUpdateResult,
        error_codes, make_test_claim,
    };

    fn claims_mod_compiler(now_epoch_ms: u64) -> ClaimCompiler {
        ClaimCompiler::new(CompilerConfig::new(
            "claims-mod-signer",
            "claims-mod-key",
            now_epoch_ms,
        ))
    }

    fn claims_mod_contract(claim_id: &str, compiled_at_epoch_ms: u64) -> CompiledContract {
        let claim = make_test_claim(claim_id, "claims-mod-source");
        match claims_mod_compiler(compiled_at_epoch_ms).compile(&claim) {
            CompilationResult::Compiled { contract, .. } => contract,
            CompilationResult::Rejected { .. } => {
                panic!("fixture claim should compile");
            }
        }
    }

    fn claims_mod_scoreboard(now_epoch_ms: u64) -> ScoreboardPipeline {
        ScoreboardPipeline::new(ScoreboardConfig::new(
            "claims-mod-signer",
            "claims-mod-key",
            now_epoch_ms,
            60_000,
        ))
    }

    fn claims_mod_limited_scoreboard(
        now_epoch_ms: u64,
        max_contracts: usize,
    ) -> ScoreboardPipeline {
        let config =
            ScoreboardConfig::new("claims-mod-signer", "claims-mod-key", now_epoch_ms, 60_000)
                .with_max_contracts_per_publish(max_contracts);
        ScoreboardPipeline::new(config)
    }

    fn claims_mod_blocking_compiler(now_epoch_ms: u64, blocked_source: &str) -> ClaimCompiler {
        ClaimCompiler::new(
            CompilerConfig::new("claims-mod-signer", "claims-mod-key", now_epoch_ms)
                .with_blocked_source(blocked_source),
        )
    }

    fn assert_claim_rejected(
        result: CompilationResult,
        expected_reason: ClaimRejectionReason,
        expected_code: &str,
    ) {
        match result {
            CompilationResult::Rejected {
                reason, error_code, ..
            } => {
                assert_eq!(reason, expected_reason);
                assert_eq!(error_code, expected_code);
            }
            CompilationResult::Compiled { .. } => {
                panic!("claim should have been rejected");
            }
        }
    }

    fn assert_scoreboard_rejected(
        result: ScoreboardUpdateResult,
        expected_reason: ScoreboardRejectionReason,
        expected_code: &str,
    ) {
        match result {
            ScoreboardUpdateResult::Rejected { reason, error_code } => {
                assert_eq!(reason, expected_reason);
                assert_eq!(error_code, expected_code);
            }
            ScoreboardUpdateResult::Published { .. } => {
                panic!("scoreboard update should have been rejected");
            }
        }
    }

    #[test]
    fn negative_compile_prioritizes_invalid_source_before_empty_claim_text() {
        let mut claim = make_test_claim("claims-mod-null-source-precedence", "claims-mod-source");
        claim.source_id = "claims\0source".to_string();
        claim.claim_text.clear();

        assert_claim_rejected(
            claims_mod_compiler(10_000).compile(&claim),
            ClaimRejectionReason::InvalidSource,
            error_codes::ERR_CLAIM_SOURCE_INVALID,
        );
    }

    #[test]
    fn negative_compile_prioritizes_invalid_source_before_missing_evidence() {
        let mut claim = make_test_claim("claims-mod-source-before-evidence", "claims-mod-source");
        claim.source_id = "\0claims-mod-source".to_string();
        claim.evidence_uris.clear();

        assert_claim_rejected(
            claims_mod_compiler(10_000).compile(&claim),
            ClaimRejectionReason::InvalidSource,
            error_codes::ERR_CLAIM_SOURCE_INVALID,
        );
    }

    #[test]
    fn negative_compile_rejects_trimmed_evidence_uri_with_null_byte() {
        let mut claim = make_test_claim("claims-mod-trimmed-null-evidence", "claims-mod-source");
        claim.evidence_uris = vec!["  https://evidence.example.com/claim\0tail  ".to_string()];

        assert_claim_rejected(
            claims_mod_compiler(10_000).compile(&claim),
            ClaimRejectionReason::Unverifiable,
            error_codes::ERR_CLAIM_UNVERIFIABLE,
        );
    }

    #[test]
    fn negative_compile_rejects_mixed_evidence_with_relative_member() {
        let mut claim = make_test_claim("claims-mod-relative-evidence", "claims-mod-source");
        claim.evidence_uris = vec![
            "urn:claims-mod:valid".to_string(),
            "file://evidence/valid.json".to_string(),
            "../relative/evidence.json".to_string(),
        ];

        assert_claim_rejected(
            claims_mod_compiler(10_000).compile(&claim),
            ClaimRejectionReason::Unverifiable,
            error_codes::ERR_CLAIM_UNVERIFIABLE,
        );
    }

    #[test]
    fn negative_scoreboard_rejects_epoch_zero_contract_at_freshness_boundary() {
        let contract = claims_mod_contract("claims-mod-zero-stale-boundary", 0);
        let result = claims_mod_scoreboard(60_000).publish("claims-mod-zero-stale", &[contract]);

        assert_scoreboard_rejected(
            result,
            ScoreboardRejectionReason::StaleEvidence,
            error_codes::ERR_SCOREBOARD_STALE_EVIDENCE,
        );
    }

    #[test]
    fn negative_scoreboard_rejects_evidence_link_tamper() {
        let mut contract = claims_mod_contract("claims-mod-evidence-tamper", 10_000);
        contract.evidence_uris[0] = "https://evidence.example.com/tampered".to_string();
        let result =
            claims_mod_scoreboard(10_000).publish("claims-mod-evidence-tamper", &[contract]);

        assert_scoreboard_rejected(
            result,
            ScoreboardRejectionReason::SignatureInvalid,
            error_codes::ERR_SCOREBOARD_SIGNATURE_INVALID,
        );
    }

    #[test]
    fn negative_scoreboard_snapshot_rejects_signer_id_tamper() {
        let mut contract = claims_mod_contract("claims-mod-signer-tamper", 10_000);
        contract.signer_id = "claims-mod-other-signer".to_string();

        assert!(
            claims_mod_scoreboard(10_000)
                .build_snapshot("claims-mod-signer-tamper", &[contract])
                .is_none()
        );
    }

    #[test]
    fn negative_scoreboard_rate_limits_contract_set() {
        let first = claims_mod_contract("claims-mod-rate-a", 10_000);
        let second = claims_mod_contract("claims-mod-rate-b", 10_000);
        let result =
            claims_mod_limited_scoreboard(10_000, 1).publish("claims-mod-rate", &[first, second]);

        assert_scoreboard_rejected(
            result,
            ScoreboardRejectionReason::RateLimited,
            error_codes::ERR_SCOREBOARD_RATE_LIMITED,
        );
    }

    #[test]
    fn negative_scoreboard_rejects_one_stale_member_in_publish_batch() {
        let fresh = claims_mod_contract("claims-mod-fresh-member", 69_999);
        let stale = claims_mod_contract("claims-mod-stale-member", 0);
        let result =
            claims_mod_scoreboard(60_000).publish("claims-mod-mixed-stale", &[fresh, stale]);

        assert_scoreboard_rejected(
            result,
            ScoreboardRejectionReason::StaleEvidence,
            error_codes::ERR_SCOREBOARD_STALE_EVIDENCE,
        );
    }

    #[test]
    fn negative_compile_blocked_source_precedes_empty_claim_text() {
        let mut claim = make_test_claim("claims-mod-blocked-empty-text", "claims-mod-blocked");
        claim.claim_text.clear();

        assert_claim_rejected(
            claims_mod_blocking_compiler(10_000, "claims-mod-blocked").compile(&claim),
            ClaimRejectionReason::Blocked,
            error_codes::ERR_CLAIM_BLOCKED,
        );
    }

    #[test]
    fn negative_compile_blocked_source_normalizes_padded_claim_source() {
        let claim = make_test_claim("claims-mod-padded-blocked", " claims-mod-blocked ");

        assert_claim_rejected(
            claims_mod_blocking_compiler(10_000, "claims-mod-blocked").compile(&claim),
            ClaimRejectionReason::Blocked,
            error_codes::ERR_CLAIM_BLOCKED,
        );
    }

    #[test]
    fn negative_compile_rejects_evidence_uri_with_empty_scheme() {
        let mut claim = make_test_claim("claims-mod-empty-scheme", "claims-mod-source");
        claim.evidence_uris = vec!["://missing-scheme".to_string()];

        assert_claim_rejected(
            claims_mod_compiler(10_000).compile(&claim),
            ClaimRejectionReason::Unverifiable,
            error_codes::ERR_CLAIM_UNVERIFIABLE,
        );
    }

    #[test]
    fn negative_compile_rejects_uppercase_evidence_scheme() {
        let mut claim = make_test_claim("claims-mod-uppercase-scheme", "claims-mod-source");
        claim.evidence_uris = vec!["HTTPS://evidence.example.com/claim".to_string()];

        assert_claim_rejected(
            claims_mod_compiler(10_000).compile(&claim),
            ClaimRejectionReason::Unverifiable,
            error_codes::ERR_CLAIM_UNVERIFIABLE,
        );
    }

    #[test]
    fn negative_scoreboard_rejects_claim_id_tamper() {
        let mut contract = claims_mod_contract("claims-mod-claim-id-tamper", 10_000);
        contract.claim_id = "claims-mod-claim-id-tampered".to_string();
        let result =
            claims_mod_scoreboard(10_000).publish("claims-mod-claim-id-tamper", &[contract]);

        assert_scoreboard_rejected(
            result,
            ScoreboardRejectionReason::SignatureInvalid,
            error_codes::ERR_SCOREBOARD_SIGNATURE_INVALID,
        );
    }

    #[test]
    fn negative_scoreboard_rejects_source_id_tamper() {
        let mut contract = claims_mod_contract("claims-mod-source-id-tamper", 10_000);
        contract.source_id = "claims-mod-other-source".to_string();
        let result =
            claims_mod_scoreboard(10_000).publish("claims-mod-source-id-tamper", &[contract]);

        assert_scoreboard_rejected(
            result,
            ScoreboardRejectionReason::SignatureInvalid,
            error_codes::ERR_SCOREBOARD_SIGNATURE_INVALID,
        );
    }

    #[test]
    fn negative_scoreboard_rate_limit_precedes_signature_tamper() {
        let valid = claims_mod_contract("claims-mod-rate-valid", 10_000);
        let mut tampered = claims_mod_contract("claims-mod-rate-tampered", 10_000);
        tampered.signature.clear();
        let result = claims_mod_limited_scoreboard(10_000, 1)
            .publish("claims-mod-rate-before-signature", &[valid, tampered]);

        assert_scoreboard_rejected(
            result,
            ScoreboardRejectionReason::RateLimited,
            error_codes::ERR_SCOREBOARD_RATE_LIMITED,
        );
    }
}

#[cfg(test)]
mod tests {
    use super::claim_compiler::{
        ClaimCompiler, ClaimRejectionReason, CompilationResult, CompiledContract, CompilerConfig,
        ExternalClaim, ScoreboardConfig, ScoreboardPipeline, ScoreboardRejectionReason,
        ScoreboardUpdateResult, make_test_claim,
    };

    fn compiler(now_epoch_ms: u64) -> ClaimCompiler {
        ClaimCompiler::new(CompilerConfig::new(
            "scoreboard-signer",
            "test-key",
            now_epoch_ms,
        ))
    }

    fn compile_contract(claim_id: &str, compiled_at_epoch_ms: u64) -> CompiledContract {
        match compiler(compiled_at_epoch_ms).compile(&make_test_claim(claim_id, "source-A")) {
            CompilationResult::Compiled { contract, .. } => contract,
            CompilationResult::Rejected { reason, .. } => {
                panic!("fixture claim should compile, got {reason:?}")
            }
        }
    }

    fn scoreboard(now_epoch_ms: u64) -> ScoreboardPipeline {
        ScoreboardPipeline::new(ScoreboardConfig::new(
            "scoreboard-signer",
            "test-key",
            now_epoch_ms,
            60_000,
        ))
    }

    fn rejection_reason(result: CompilationResult) -> ClaimRejectionReason {
        match result {
            CompilationResult::Rejected { reason, .. } => reason,
            CompilationResult::Compiled { .. } => panic!("expected claim rejection"),
        }
    }

    fn scoreboard_rejection(result: ScoreboardUpdateResult) -> ScoreboardRejectionReason {
        match result {
            ScoreboardUpdateResult::Rejected { reason, .. } => reason,
            ScoreboardUpdateResult::Published { .. } => panic!("expected scoreboard rejection"),
        }
    }

    #[test]
    fn compile_rejects_source_id_containing_null_byte() {
        let claim = ExternalClaim {
            source_id: "source-A\0shadow".to_string(),
            ..make_test_claim("claim-null-source", "source-A")
        };

        let reason = rejection_reason(compiler(10_000).compile(&claim));

        assert!(matches!(reason, ClaimRejectionReason::InvalidSource));
    }

    #[test]
    fn compile_rejects_null_byte_evidence_uri() {
        let claim = ExternalClaim {
            evidence_uris: vec!["https://example.test/evidence\0.json".to_string()],
            ..make_test_claim("claim-null-evidence", "source-A")
        };

        let reason = rejection_reason(compiler(10_000).compile(&claim));

        assert!(matches!(reason, ClaimRejectionReason::Unverifiable));
    }

    #[test]
    fn compile_rejects_blank_member_in_mixed_evidence_list() {
        let claim = ExternalClaim {
            evidence_uris: vec![
                "https://example.test/evidence.json".to_string(),
                " \t ".to_string(),
            ],
            ..make_test_claim("claim-blank-evidence-member", "source-A")
        };

        let reason = rejection_reason(compiler(10_000).compile(&claim));

        assert!(matches!(reason, ClaimRejectionReason::Unverifiable));
    }

    #[test]
    fn compile_rejects_claim_text_with_only_control_whitespace() {
        let claim = ExternalClaim {
            claim_text: "\n\t\r".to_string(),
            ..make_test_claim("claim-control-whitespace", "source-A")
        };

        let reason = rejection_reason(compiler(10_000).compile(&claim));

        assert!(matches!(reason, ClaimRejectionReason::SyntaxInvalid));
    }

    #[test]
    fn scoreboard_publish_rejects_tampered_contract_text() {
        let mut contract = compile_contract("claim-tampered-text", 10_000);
        contract.claim_text = "The claim text changed after signing".to_string();

        let reason = scoreboard_rejection(scoreboard(20_000).publish("snap-tampered", &[contract]));

        assert!(matches!(
            reason,
            ScoreboardRejectionReason::SignatureInvalid
        ));
    }

    #[test]
    fn scoreboard_publish_rejects_tampered_signature() {
        let mut contract = compile_contract("claim-tampered-signature", 10_000);
        contract.signature = "0".repeat(64);

        let reason =
            scoreboard_rejection(scoreboard(20_000).publish("snap-signature", &[contract]));

        assert!(matches!(
            reason,
            ScoreboardRejectionReason::SignatureInvalid
        ));
    }

    #[test]
    fn scoreboard_publish_rejects_exact_staleness_boundary() {
        let contract = compile_contract("claim-stale-boundary", 10_000);

        let reason = scoreboard_rejection(scoreboard(70_000).publish("snap-stale", &[contract]));

        assert!(matches!(reason, ScoreboardRejectionReason::StaleEvidence));
    }

    #[test]
    fn scoreboard_publish_rejects_one_contract_when_limit_is_zero() {
        let contract = compile_contract("claim-zero-limit", 10_000);
        let pipeline = ScoreboardPipeline::new(
            ScoreboardConfig::new("scoreboard-signer", "test-key", 20_000, 60_000)
                .with_max_contracts_per_publish(0),
        );

        let reason = scoreboard_rejection(pipeline.publish("snap-zero-limit", &[contract]));

        assert!(matches!(reason, ScoreboardRejectionReason::RateLimited));
    }

    #[test]
    fn scoreboard_build_snapshot_returns_none_for_tampered_digest() {
        let mut contract = compile_contract("claim-tampered-digest", 10_000);
        contract.contract_digest = "0".repeat(64);

        let snapshot = scoreboard(20_000).build_snapshot("snap-digest", &[contract]);

        assert!(snapshot.is_none());
    }

    #[test]
    fn scoreboard_build_snapshot_returns_none_when_any_contract_is_stale() {
        let fresh = compile_contract("claim-fresh-member", 69_999);
        let stale = compile_contract("claim-stale-member", 10_000);

        let snapshot = scoreboard(70_000).build_snapshot("snap-mixed-stale", &[fresh, stale]);

        assert!(snapshot.is_none());
    }

    // === METAMORPHIC TESTING ===
    // MR: Claim-envelope encode/decode/re-encode invariance (Invertive Pattern)
    // Property: serialize(x) == serialize(deserialize(serialize(x)))
    // Detects: serialization instability, data loss, format drift
    #[cfg(test)]
    mod metamorphic_roundtrip_tests {
        use super::*;

        fn test_claim_roundtrip_invariance(claim: &ExternalClaim) {
            // Step 1: Serialize (encode) the original claim
            let encoded_original =
                serde_json::to_string(&claim).expect("original claim should serialize");

            // Step 2: Deserialize (decode) back to struct
            let decoded_claim: ExternalClaim =
                serde_json::from_str(&encoded_original).expect("encoded claim should deserialize");

            // Step 3: Re-serialize (re-encode) the decoded struct
            let re_encoded =
                serde_json::to_string(&decoded_claim).expect("decoded claim should re-serialize");

            // MR assertion: encode/decode/re-encode invariance
            assert_eq!(
                encoded_original, re_encoded,
                "Claim envelope serialization not invariant under roundtrip:\n\
                 Original:   {encoded_original}\n\
                 Re-encoded: {re_encoded}\n\
                 This indicates serialization instability or data loss"
            );

            // Verify structural equivalence too (catches non-canonical serialization)
            assert_eq!(
                *claim, decoded_claim,
                "Claim structure changed during roundtrip - data corruption detected"
            );
        }

        fn test_contract_roundtrip_invariance(contract: &CompiledContract) {
            let encoded_original =
                serde_json::to_string(&contract).expect("original contract should serialize");

            let decoded_contract: CompiledContract = serde_json::from_str(&encoded_original)
                .expect("encoded contract should deserialize");

            let re_encoded = serde_json::to_string(&decoded_contract)
                .expect("decoded contract should re-serialize");

            assert_eq!(
                encoded_original, re_encoded,
                "Contract envelope serialization not invariant under roundtrip"
            );

            assert_eq!(
                *contract, decoded_contract,
                "Contract structure changed during roundtrip"
            );
        }

        #[test]
        fn mr_claim_envelope_roundtrip_invariance() {
            // Test with basic claim
            let basic_claim = make_test_claim("mr-basic-claim", "mr-source");
            test_claim_roundtrip_invariance(&basic_claim);

            // Test with multi-evidence claim
            let multi_evidence = ExternalClaim {
                evidence_uris: vec![
                    "https://evidence1.example.com/proof".to_string(),
                    "file://local/evidence.json".to_string(),
                    "urn:evidence:hash:abc123".to_string(),
                ],
                ..make_test_claim("mr-multi-evidence", "mr-source")
            };
            test_claim_roundtrip_invariance(&multi_evidence);

            // Test with empty evidence
            let no_evidence = ExternalClaim {
                evidence_uris: vec![],
                ..make_test_claim("mr-no-evidence", "mr-source")
            };
            test_claim_roundtrip_invariance(&no_evidence);

            // Test with special characters in fields
            let special_chars = ExternalClaim {
                claim_id: "claim_with-special.chars@domain".to_string(),
                claim_text: "Claim with \"quotes\", newlines\n, and unicode: 🔒".to_string(),
                source_id: "source/with/slashes".to_string(),
                evidence_uris: vec!["https://example.com/path?param=value&other=true".to_string()],
            };
            test_claim_roundtrip_invariance(&special_chars);
        }

        #[test]
        fn mr_contract_envelope_roundtrip_invariance() {
            let claim = make_test_claim("mr-contract-roundtrip", "mr-source");
            let compiler = ClaimCompiler::new(CompilerConfig::new("mr-signer", "mr-key", 10_000));

            if let CompilationResult::Compiled { contract, .. } = compiler.compile(&claim) {
                test_contract_roundtrip_invariance(&contract);

                // Test contract with modified signature (still should roundtrip)
                let modified_contract = CompiledContract {
                    signature: "0".repeat(128), // Different signature format
                    ..contract
                };
                test_contract_roundtrip_invariance(&modified_contract);
            } else {
                panic!("Test fixture claim should compile for MR test");
            }
        }

        #[test]
        fn mr_compilation_result_roundtrip_invariance() {
            let claim = make_test_claim("mr-result-roundtrip", "mr-source");
            let compiler = ClaimCompiler::new(CompilerConfig::new("mr-signer", "mr-key", 10_000));

            let result = compiler.compile(&claim);

            // Test CompilationResult roundtrip
            let encoded_result =
                serde_json::to_string(&result).expect("compilation result should serialize");

            let decoded_result: CompilationResult =
                serde_json::from_str(&encoded_result).expect("encoded result should deserialize");

            let re_encoded_result =
                serde_json::to_string(&decoded_result).expect("decoded result should re-serialize");

            assert_eq!(
                encoded_result, re_encoded_result,
                "CompilationResult serialization not invariant under roundtrip"
            );

            assert_eq!(
                result, decoded_result,
                "CompilationResult structure changed during roundtrip"
            );
        }

        // === GOLDEN ARTIFACT TESTING ===
        // Golden file tests for claim envelope serialization with canonicalization

        use insta::Settings;
        use regex::Regex;

        /// Scrub non-deterministic values for golden comparison of claim envelopes
        fn scrub_claim_envelope(json: &str) -> String {
            let mut scrubbed = json.to_string();

            // UUIDs → [UUID]
            let uuid_re =
                Regex::new(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")
                    .unwrap();
            scrubbed = uuid_re.replace_all(&scrubbed, "[UUID]").to_string();

            // ISO timestamps → [TIMESTAMP]
            let ts_re =
                Regex::new(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})?")
                    .unwrap();
            scrubbed = ts_re.replace_all(&scrubbed, "[TIMESTAMP]").to_string();

            // Epoch timestamps → [EPOCH]
            let epoch_re = Regex::new(r"\b\d{10,13}\b").unwrap();
            scrubbed = epoch_re.replace_all(&scrubbed, "[EPOCH]").to_string();

            // SHA256 hashes → [HASH]
            let hash_re = Regex::new(r"sha256:[a-f0-9]{64}").unwrap();
            scrubbed = hash_re.replace_all(&scrubbed, "sha256:[HASH]").to_string();

            // Hex signatures → [SIG]
            let sig_re = Regex::new(r"[a-f0-9]{128,256}").unwrap();
            scrubbed = sig_re.replace_all(&scrubbed, "[SIG]").to_string();

            scrubbed
        }

        fn canonical_external_claim() -> ExternalClaim {
            ExternalClaim {
                claim_id: "claim-12345".to_string(),
                claim_type: "security-audit".to_string(),
                subject_extension_id: "npm:@acme/security-lib".to_string(),
                subject_version: "1.2.3".to_string(),
                issuer_identity: "security-auditor-corp".to_string(),
                claim_content: ClaimContent {
                    summary: "Comprehensive security audit passed with minor recommendations"
                        .to_string(),
                    detailed_findings: vec![
                        "No critical vulnerabilities found".to_string(),
                        "Input validation patterns are robust".to_string(),
                        "Authentication mechanisms properly implemented".to_string(),
                        "Recommendation: Add rate limiting to API endpoints".to_string(),
                    ],
                    risk_assessment: "LOW".to_string(),
                    compliance_tags: vec![
                        "SOC2-TYPE2".to_string(),
                        "NIST-800-53".to_string(),
                        "OWASP-TOP10".to_string(),
                    ],
                },
                validity_period: ValidityPeriod {
                    issued_at: "2026-04-21T00:00:00Z".to_string(),
                    expires_at: "2027-04-21T00:00:00Z".to_string(),
                    not_before: "2026-04-21T00:00:00Z".to_string(),
                },
                evidence_bundle: EvidenceBundle {
                    evidence_refs: vec![
                        "audit-report-2026-Q1.pdf".to_string(),
                        "penetration-test-results.json".to_string(),
                        "static-analysis-sarif.json".to_string(),
                    ],
                    attestation_signatures: vec![
                        "sig1:0123456789abcdef".to_string(),
                        "sig2:fedcba9876543210".to_string(),
                    ],
                    provenance_chain: vec![
                        "github.com/acme-corp/security-lib@v1.2.3".to_string(),
                        "build-server.acme.com/build/12345".to_string(),
                    ],
                },
            }
        }

        #[test]
        fn golden_external_claim_envelope_serialization() {
            let claim = canonical_external_claim();
            let serialized = serde_json::to_string_pretty(&claim).expect("claim should serialize");
            let scrubbed = scrub_claim_envelope(&serialized);

            insta::assert_snapshot!("external_claim_envelope", scrubbed);
        }

        #[test]
        fn golden_compiled_contract_envelope() {
            let claim = canonical_external_claim();
            let config = CompilerConfig::new("test-signer", "test-key-id", 60);
            let compiler = ClaimCompiler::new(config);

            let result = compiler
                .compile(&claim, "test-trace")
                .expect("compilation should succeed");

            let contract_json = serde_json::to_string_pretty(&result.compiled_contract)
                .expect("contract should serialize");
            let scrubbed = scrub_claim_envelope(&contract_json);

            insta::assert_snapshot!("compiled_contract_envelope", scrubbed);
        }

        #[test]
        fn golden_compilation_result_envelope() {
            let claim = canonical_external_claim();
            let config = CompilerConfig::new("test-signer", "test-key-id", 60);
            let compiler = ClaimCompiler::new(config);

            let result = compiler
                .compile(&claim, "test-trace")
                .expect("compilation should succeed");

            let result_json =
                serde_json::to_string_pretty(&result).expect("result should serialize");
            let scrubbed = scrub_claim_envelope(&result_json);

            insta::assert_snapshot!("compilation_result_envelope", scrubbed);
        }

        #[test]
        fn golden_claim_envelope_minimal() {
            // Test minimal claim envelope
            let minimal_claim = ExternalClaim {
                claim_id: "minimal-claim".to_string(),
                claim_type: "basic-validation".to_string(),
                subject_extension_id: "npm:@minimal/package".to_string(),
                subject_version: "0.1.0".to_string(),
                issuer_identity: "test-issuer".to_string(),
                claim_content: ClaimContent {
                    summary: "Basic validation passed".to_string(),
                    detailed_findings: vec![], // Empty findings
                    risk_assessment: "UNKNOWN".to_string(),
                    compliance_tags: vec![], // Empty tags
                },
                validity_period: ValidityPeriod {
                    issued_at: "2026-01-01T00:00:00Z".to_string(),
                    expires_at: "2026-12-31T23:59:59Z".to_string(),
                    not_before: "2026-01-01T00:00:00Z".to_string(),
                },
                evidence_bundle: EvidenceBundle {
                    evidence_refs: vec![],                         // Empty evidence
                    attestation_signatures: vec![],                // No signatures
                    provenance_chain: vec!["unknown".to_string()], // Minimal provenance
                },
            };

            let serialized = serde_json::to_string_pretty(&minimal_claim)
                .expect("minimal claim should serialize");
            let scrubbed = scrub_claim_envelope(&serialized);

            insta::assert_snapshot!("claim_envelope_minimal", scrubbed);
        }

        #[test]
        fn golden_claim_envelope_maximal() {
            // Test claim envelope with maximum data
            let maximal_claim = ExternalClaim {
                claim_id: "comprehensive-audit-12345-abcdef".to_string(),
                claim_type: "comprehensive-security-audit".to_string(),
                subject_extension_id: "npm:@enterprise/critical-security-framework".to_string(),
                subject_version: "2.5.1-enterprise.1".to_string(),
                issuer_identity: "tier-1-security-auditing-firm".to_string(),
                claim_content: ClaimContent {
                    summary: "Comprehensive enterprise security audit with penetration testing, static analysis, dependency scanning, and compliance validation".to_string(),
                    detailed_findings: vec![
                        "PASS: No critical vulnerabilities detected across 15,000 lines of code".to_string(),
                        "PASS: All authentication pathways use secure session management".to_string(),
                        "PASS: Input validation comprehensive with proper sanitization".to_string(),
                        "PASS: Cryptographic implementations follow FIPS-140-2 standards".to_string(),
                        "PASS: No hardcoded secrets or credentials found".to_string(),
                        "PASS: SQL injection attack vectors properly mitigated".to_string(),
                        "PASS: XSS prevention mechanisms correctly implemented".to_string(),
                        "PASS: CSRF protection active on all state-changing endpoints".to_string(),
                        "PASS: Access control properly enforces least-privilege principle".to_string(),
                        "INFO: Recommendation - Consider implementing additional rate limiting".to_string(),
                        "INFO: Recommendation - Add structured logging for security events".to_string(),
                        "INFO: Recommendation - Implement automated dependency scanning in CI".to_string(),
                    ],
                    risk_assessment: "LOW-ENTERPRISE-APPROVED".to_string(),
                    compliance_tags: vec![
                        "SOC2-TYPE2-2026-PASSED".to_string(),
                        "NIST-800-53-REV5-COMPLIANT".to_string(),
                        "OWASP-TOP10-2023-VALIDATED".to_string(),
                        "ISO27001-ALIGNED".to_string(),
                        "GDPR-PRIVACY-COMPLIANT".to_string(),
                        "FIPS-140-2-CRYPTOGRAPHY".to_string(),
                        "CIS-CONTROLS-V8-ALIGNED".to_string(),
                    ],
                },
                validity_period: ValidityPeriod {
                    issued_at: "2026-04-21T08:30:00.123Z".to_string(),
                    expires_at: "2027-04-21T08:30:00.123Z".to_string(),
                    not_before: "2026-04-21T08:30:00.123Z".to_string(),
                },
                evidence_bundle: EvidenceBundle {
                    evidence_refs: vec![
                        "comprehensive-audit-report-2026-Q1.pdf".to_string(),
                        "penetration-test-detailed-results.json".to_string(),
                        "static-analysis-sonarqube-report.sarif".to_string(),
                        "dependency-vulnerability-scan.json".to_string(),
                        "security-code-review-checklist.md".to_string(),
                        "compliance-validation-matrix.xlsx".to_string(),
                        "threat-model-analysis.drawio".to_string(),
                    ],
                    attestation_signatures: vec![
                        "lead-auditor-sig:a1b2c3d4e5f6789012345678901234567890abcdefabcdef1234567890abcdef".to_string(),
                        "senior-auditor-sig:fedcba0987654321098765432109876543210fedcba9876543210fedcba987654".to_string(),
                        "compliance-officer-sig:1111222233334444555566667777888899990000aaaabbbbccccddddeeeeffff".to_string(),
                        "external-validator-sig:fffeeedddcccbbbaaa9999888877776666555544443333222211110000ffff".to_string(),
                    ],
                    provenance_chain: vec![
                        "github.com/enterprise/critical-security-framework@v2.5.1-enterprise.1".to_string(),
                        "jenkins.enterprise.com/security-build/job/12345/build/67890".to_string(),
                        "artifactory.enterprise.com/enterprise-npm/critical-security-framework/2.5.1-enterprise.1".to_string(),
                        "security-scanner.enterprise.com/scan/98765/timestamp/1735689600".to_string(),
                    ],
                },
            };

            let serialized = serde_json::to_string_pretty(&maximal_claim)
                .expect("maximal claim should serialize");
            let scrubbed = scrub_claim_envelope(&serialized);

            insta::assert_snapshot!("claim_envelope_maximal", scrubbed);
        }

        #[test]
        fn golden_claim_envelope_roundtrip_canonical() {
            // Test that roundtrip serialization produces canonical results
            let claim = canonical_external_claim();

            let serialized_1 = serde_json::to_string(&claim).expect("first serialization");

            let deserialized: ExternalClaim =
                serde_json::from_str(&serialized_1).expect("deserialization should work");

            let serialized_2 = serde_json::to_string(&deserialized).expect("second serialization");

            // Both serializations should be identical (canonical)
            assert_eq!(
                serialized_1, serialized_2,
                "roundtrip serialization should be canonical"
            );

            let scrubbed = scrub_claim_envelope(&serialized_1);
            insta::assert_snapshot!("claim_envelope_roundtrip_canonical", scrubbed);
        }
    }
}
