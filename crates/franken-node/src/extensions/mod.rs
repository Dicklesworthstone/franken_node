pub mod artifact_contract;

#[cfg(test)]
mod tests {
    use super::artifact_contract::{
        AdmissionConfig, AdmissionDenialReason, AdmissionGate, AdmissionOutcome, CapabilityEntry,
        DriftCheckResult, EnforcementEngine, ExtensionArtifact, SCHEMA_VERSION, make_artifact,
        make_contract,
    };

    fn capabilities() -> Vec<CapabilityEntry> {
        vec![
            CapabilityEntry {
                capability_id: "fs.read".to_string(),
                scope: "filesystem:read".to_string(),
                max_calls_per_epoch: 100,
            },
            CapabilityEntry {
                capability_id: "net.egress".to_string(),
                scope: "network:egress".to_string(),
                max_calls_per_epoch: 10,
            },
        ]
    }

    fn trusted_gate() -> AdmissionGate {
        let mut config = AdmissionConfig::new(SCHEMA_VERSION);
        config
            .with_signer("signer-A")
            .expect("test signer registration should fit");
        AdmissionGate::new(config)
    }

    fn signed_contract() -> super::artifact_contract::CapabilityContract {
        make_contract(
            "contract-1",
            "ext-alpha",
            capabilities(),
            "signer-A",
            SCHEMA_VERSION,
            1,
        )
    }

    fn denial_reason(outcome: AdmissionOutcome) -> AdmissionDenialReason {
        match outcome {
            AdmissionOutcome::Denied { reason, .. } => reason,
            AdmissionOutcome::Accepted { .. } => panic!("expected admission denial"),
        }
    }

    fn assert_invalid_contract_detail(outcome: AdmissionOutcome, expected_detail: &str) {
        match denial_reason(outcome) {
            AdmissionDenialReason::InvalidContract { detail } => {
                assert!(
                    detail.contains(expected_detail),
                    "expected detail containing {expected_detail:?}, got {detail:?}"
                );
            }
            reason => panic!("expected invalid contract denial, got {reason:?}"),
        }
    }

    fn assert_invalid_capability_detail(outcome: AdmissionOutcome, expected_detail: &str) {
        match denial_reason(outcome) {
            AdmissionDenialReason::InvalidCapability { detail } => {
                assert!(
                    detail.contains(expected_detail),
                    "expected detail containing {expected_detail:?}, got {detail:?}"
                );
            }
            reason => panic!("expected invalid capability denial, got {reason:?}"),
        }
    }

    #[test]
    fn admission_denies_missing_contract() {
        let artifact = ExtensionArtifact {
            artifact_id: "artifact-1".to_string(),
            extension_id: "ext-alpha".to_string(),
            extension_version: "1.0.0".to_string(),
            capability_contract: None,
            payload_hash: "0".repeat(64),
        };

        let reason = denial_reason(trusted_gate().evaluate(&artifact));

        assert!(matches!(reason, AdmissionDenialReason::MissingContract));
    }

    #[test]
    fn admission_denies_schema_mismatch() {
        let contract = make_contract(
            "contract-schema",
            "ext-alpha",
            capabilities(),
            "signer-A",
            "capability-artifact-v0",
            1,
        );
        let artifact = make_artifact("artifact-schema", "ext-alpha", contract);

        let reason = denial_reason(trusted_gate().evaluate(&artifact));

        assert!(matches!(
            reason,
            AdmissionDenialReason::SchemaMismatch { .. }
        ));
    }

    #[test]
    fn admission_denies_untrusted_signer_even_with_valid_signature() {
        let contract = make_contract(
            "contract-untrusted",
            "ext-alpha",
            capabilities(),
            "signer-B",
            SCHEMA_VERSION,
            1,
        );
        let artifact = make_artifact("artifact-untrusted", "ext-alpha", contract);

        let reason = denial_reason(trusted_gate().evaluate(&artifact));

        assert!(matches!(reason, AdmissionDenialReason::SignatureInvalid));
    }

    #[test]
    fn admission_denies_tampered_contract_after_signing() {
        let mut contract = signed_contract();
        contract.capabilities[0].scope = "filesystem:write".to_string();
        let artifact = make_artifact("artifact-tampered", "ext-alpha", contract);

        let reason = denial_reason(trusted_gate().evaluate(&artifact));

        assert!(matches!(reason, AdmissionDenialReason::SignatureInvalid));
    }

    #[test]
    fn admission_denies_duplicate_capability_ids() {
        let duplicate_caps = vec![
            CapabilityEntry {
                capability_id: "fs.read".to_string(),
                scope: "filesystem:read".to_string(),
                max_calls_per_epoch: 100,
            },
            CapabilityEntry {
                capability_id: "fs.read".to_string(),
                scope: "filesystem:read:again".to_string(),
                max_calls_per_epoch: 100,
            },
        ];
        let contract = make_contract(
            "contract-duplicate",
            "ext-alpha",
            duplicate_caps,
            "signer-A",
            SCHEMA_VERSION,
            1,
        );
        let artifact = make_artifact("artifact-duplicate", "ext-alpha", contract);

        let reason = denial_reason(trusted_gate().evaluate(&artifact));

        assert!(matches!(
            reason,
            AdmissionDenialReason::InvalidCapability { .. }
        ));
    }

    #[test]
    fn admission_denies_zero_capability_call_limit() {
        let mut caps = capabilities();
        caps[0].max_calls_per_epoch = 0;
        let contract = make_contract(
            "contract-zero-limit",
            "ext-alpha",
            caps,
            "signer-A",
            SCHEMA_VERSION,
            1,
        );
        let artifact = make_artifact("artifact-zero-limit", "ext-alpha", contract);

        let reason = denial_reason(trusted_gate().evaluate(&artifact));

        assert!(matches!(
            reason,
            AdmissionDenialReason::InvalidCapability { .. }
        ));
    }

    #[test]
    fn admission_denies_artifact_extension_contract_mismatch() {
        let contract = signed_contract();
        let artifact = make_artifact("artifact-mismatch", "ext-beta", contract);

        let reason = denial_reason(trusted_gate().evaluate(&artifact));

        assert!(matches!(
            reason,
            AdmissionDenialReason::InvalidContract { .. }
        ));
    }

    #[test]
    fn admission_denies_uppercase_payload_hash() {
        let contract = signed_contract();
        let mut artifact = make_artifact("artifact-payload", "ext-alpha", contract);
        artifact.payload_hash = "A".repeat(64);

        let reason = denial_reason(trusted_gate().evaluate(&artifact));

        assert!(matches!(
            reason,
            AdmissionDenialReason::InvalidContract { .. }
        ));
    }

    #[test]
    fn enforcement_drift_reports_duplicate_and_unknown_active_capabilities() {
        let contract = signed_contract();
        let engine = EnforcementEngine::from_contract(&contract);
        let active = vec![
            "fs.read".to_string(),
            "fs.read".to_string(),
            "cap.unknown".to_string(),
        ];

        let result = engine.check_drift(&active);

        match result {
            DriftCheckResult::DriftDetected { missing, extra, .. } => {
                assert!(missing.contains(&"net.egress".to_string()));
                assert!(extra.contains(&"fs.read".to_string()));
                assert!(extra.contains(&"cap.unknown".to_string()));
            }
            DriftCheckResult::NoDrift { .. } => panic!("expected drift"),
        }
    }

    #[test]
    fn admission_denies_empty_artifact_id() {
        let contract = signed_contract();
        let artifact = make_artifact("", "ext-alpha", contract);

        assert_invalid_contract_detail(trusted_gate().evaluate(&artifact), "empty artifact_id");
    }

    #[test]
    fn admission_denies_reserved_artifact_id() {
        let contract = signed_contract();
        let artifact = make_artifact("<unknown>", "ext-alpha", contract);

        assert_invalid_contract_detail(
            trusted_gate().evaluate(&artifact),
            "artifact_id is reserved",
        );
    }

    #[test]
    fn admission_denies_whitespace_contract_id_even_when_signature_matches() {
        let contract = make_contract(
            " contract-1 ",
            "ext-alpha",
            capabilities(),
            "signer-A",
            SCHEMA_VERSION,
            1,
        );
        let artifact = make_artifact("artifact-whitespace-contract", "ext-alpha", contract);

        assert_invalid_contract_detail(trusted_gate().evaluate(&artifact), "contract_id contains");
    }

    #[test]
    fn admission_denies_empty_signature() {
        let mut contract = signed_contract();
        contract.signature.clear();
        let artifact = make_artifact("artifact-empty-signature", "ext-alpha", contract);

        assert_invalid_contract_detail(trusted_gate().evaluate(&artifact), "empty signature");
    }

    #[test]
    fn admission_denies_empty_capability_scope_even_when_signed() {
        let mut caps = capabilities();
        caps[0].scope.clear();
        let contract = make_contract(
            "contract-empty-scope",
            "ext-alpha",
            caps,
            "signer-A",
            SCHEMA_VERSION,
            1,
        );
        let artifact = make_artifact("artifact-empty-scope", "ext-alpha", contract);

        assert_invalid_capability_detail(
            trusted_gate().evaluate(&artifact),
            "empty capability_id or scope",
        );
    }

    #[test]
    fn admission_denies_whitespace_capability_id_even_when_signed() {
        let mut caps = capabilities();
        caps[0].capability_id = " fs.read ".to_string();
        let contract = make_contract(
            "contract-padded-capability",
            "ext-alpha",
            caps,
            "signer-A",
            SCHEMA_VERSION,
            1,
        );
        let artifact = make_artifact("artifact-padded-capability", "ext-alpha", contract);

        assert_invalid_capability_detail(trusted_gate().evaluate(&artifact), "leading or trailing");
    }

    #[test]
    fn enforcement_drift_reports_all_missing_when_active_set_is_empty() {
        let contract = signed_contract();
        let engine = EnforcementEngine::from_contract(&contract);

        match engine.check_drift(&[]) {
            DriftCheckResult::DriftDetected { missing, extra, .. } => {
                assert!(missing.contains(&"fs.read".to_string()));
                assert!(missing.contains(&"net.egress".to_string()));
                assert!(extra.is_empty());
            }
            DriftCheckResult::NoDrift { .. } => panic!("expected drift for empty active set"),
        }
    }

    #[test]
    fn enforcement_drift_treats_whitespace_active_id_as_extra_and_missing() {
        let contract = signed_contract();
        let engine = EnforcementEngine::from_contract(&contract);
        let active = vec![" fs.read ".to_string(), "net.egress".to_string()];

        match engine.check_drift(&active) {
            DriftCheckResult::DriftDetected { missing, extra, .. } => {
                assert!(missing.contains(&"fs.read".to_string()));
                assert!(extra.contains(&" fs.read ".to_string()));
            }
            DriftCheckResult::NoDrift { .. } => panic!("expected drift for padded active id"),
        }
    }

    #[test]
    fn enforcement_rejects_case_variant_capability_id() {
        let contract = signed_contract();
        let engine = EnforcementEngine::from_contract(&contract);

        assert!(!engine.is_permitted("FS.READ"));
    }

    #[test]
    fn admission_denies_empty_contract_extension_id_even_when_signed() {
        let contract = make_contract(
            "contract-empty-extension",
            "",
            capabilities(),
            "signer-A",
            SCHEMA_VERSION,
            1,
        );
        let artifact = make_artifact("artifact-empty-contract-extension", "ext-alpha", contract);

        assert_invalid_contract_detail(
            trusted_gate().evaluate(&artifact),
            "empty contract extension_id",
        );
    }

    #[test]
    fn admission_denies_whitespace_contract_extension_id_even_when_signed() {
        let contract = make_contract(
            "contract-padded-extension",
            " ext-alpha ",
            capabilities(),
            "signer-A",
            SCHEMA_VERSION,
            1,
        );
        let artifact = make_artifact("artifact-padded-contract-extension", "ext-alpha", contract);

        assert_invalid_contract_detail(
            trusted_gate().evaluate(&artifact),
            "contract extension_id contains",
        );
    }

    #[test]
    fn admission_denies_empty_signer_id_even_when_signature_matches() {
        let contract = make_contract(
            "contract-empty-signer",
            "ext-alpha",
            capabilities(),
            "",
            SCHEMA_VERSION,
            1,
        );
        let artifact = make_artifact("artifact-empty-signer", "ext-alpha", contract);

        assert_invalid_contract_detail(trusted_gate().evaluate(&artifact), "empty signer_id");
    }

    #[test]
    fn admission_denies_whitespace_signer_id_even_when_signature_matches() {
        let contract = make_contract(
            "contract-padded-signer",
            "ext-alpha",
            capabilities(),
            " signer-A ",
            SCHEMA_VERSION,
            1,
        );
        let artifact = make_artifact("artifact-padded-signer", "ext-alpha", contract);

        assert_invalid_contract_detail(trusted_gate().evaluate(&artifact), "signer_id contains");
    }

    #[test]
    fn admission_denies_zero_issued_epoch_even_when_signature_matches() {
        let contract = make_contract(
            "contract-zero-epoch",
            "ext-alpha",
            capabilities(),
            "signer-A",
            SCHEMA_VERSION,
            0,
        );
        let artifact = make_artifact("artifact-zero-epoch", "ext-alpha", contract);

        assert_invalid_contract_detail(trusted_gate().evaluate(&artifact), "issued_epoch_ms");
    }

    #[test]
    fn admission_denies_empty_capability_list_even_when_signed() {
        let contract = make_contract(
            "contract-empty-capabilities",
            "ext-alpha",
            Vec::new(),
            "signer-A",
            SCHEMA_VERSION,
            1,
        );
        let artifact = make_artifact("artifact-empty-capabilities", "ext-alpha", contract);

        assert_invalid_contract_detail(trusted_gate().evaluate(&artifact), "capability list");
    }

    #[test]
    fn admission_denies_short_payload_hash() {
        let contract = signed_contract();
        let mut artifact = make_artifact("artifact-short-payload", "ext-alpha", contract);
        artifact.payload_hash = "a".repeat(63);

        assert_invalid_contract_detail(trusted_gate().evaluate(&artifact), "payload_hash");
    }

    #[test]
    fn admission_denies_excessively_long_artifact_id() {
        let contract = signed_contract();
        let long_id = "x".repeat(1024);
        let artifact = make_artifact(&long_id, "ext-alpha", contract);

        assert_invalid_contract_detail(trusted_gate().evaluate(&artifact), "artifact_id");
    }

    #[test]
    fn admission_denies_capability_id_with_null_bytes() {
        let mut caps = capabilities();
        caps[0].capability_id = "fs\0read".to_string();
        let contract = make_contract(
            "contract-null-byte",
            "ext-alpha",
            caps,
            "signer-A",
            SCHEMA_VERSION,
            1,
        );
        let artifact = make_artifact("artifact-null-byte", "ext-alpha", contract);

        assert_invalid_capability_detail(
            trusted_gate().evaluate(&artifact),
            "capability_id contains",
        );
    }

    #[test]
    fn serde_rejects_negative_max_calls_per_epoch() {
        let json = r#"{
            "capability_id": "fs.read",
            "scope": "filesystem:read",
            "max_calls_per_epoch": -1
        }"#;

        assert!(serde_json::from_str::<CapabilityEntry>(json).is_err());
    }

    #[test]
    fn admission_denies_unicode_homograph_attack_in_capability_scope() {
        let mut caps = capabilities();
        // Use Cyrillic 'а' instead of Latin 'a'
        caps[0].scope = "filesystem:reаd".to_string();
        let contract = make_contract(
            "contract-homograph",
            "ext-alpha",
            caps,
            "signer-A",
            SCHEMA_VERSION,
            1,
        );
        let artifact = make_artifact("artifact-homograph", "ext-alpha", contract);

        assert_invalid_capability_detail(trusted_gate().evaluate(&artifact), "contains non-ASCII");
    }

    #[test]
    fn admission_denies_path_traversal_in_capability_scope() {
        let mut caps = capabilities();
        caps[0].scope = "filesystem:../../../etc/passwd".to_string();
        let contract = make_contract(
            "contract-traversal",
            "ext-alpha",
            caps,
            "signer-A",
            SCHEMA_VERSION,
            1,
        );
        let artifact = make_artifact("artifact-traversal", "ext-alpha", contract);

        assert_invalid_capability_detail(trusted_gate().evaluate(&artifact), "path traversal");
    }

    #[test]
    fn admission_denies_control_characters_in_extension_id() {
        let contract = make_contract(
            "contract-control-chars",
            "ext\r\n-alpha",
            capabilities(),
            "signer-A",
            SCHEMA_VERSION,
            1,
        );
        let artifact = make_artifact("artifact-control-chars", "ext\r\n-alpha", contract);

        assert_invalid_contract_detail(trusted_gate().evaluate(&artifact), "contains control");
    }

    #[test]
    fn admission_denies_payload_hash_with_non_hex_characters() {
        let contract = signed_contract();
        let mut artifact = make_artifact("artifact-non-hex", "ext-alpha", contract);
        artifact.payload_hash = "g".repeat(64); // 'g' is not a hex digit

        assert_invalid_contract_detail(trusted_gate().evaluate(&artifact), "payload_hash");
    }

    #[test]
    fn enforcement_rejects_capability_id_with_embedded_newlines() {
        let contract = signed_contract();
        let engine = EnforcementEngine::from_contract(&contract);

        // Should reject capability IDs that contain line breaks
        assert!(!engine.is_permitted("fs\nread"));
        assert!(!engine.is_permitted("fs\rread"));
        assert!(!engine.is_permitted("fs\r\nread"));
    }
}
