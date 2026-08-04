pub mod artifact_contract;

#[cfg(test)]
mod tests {
    use super::artifact_contract::{
        AdmissionConfig, AdmissionDenialReason, AdmissionGate, AdmissionOutcome, CapabilityEntry,
        DriftCheckResult, EnforcementEngine, ExtensionArtifact, SCHEMA_VERSION, make_artifact,
        make_contract,
    };
    // bd-o776s: prod admission now runs a TRUST-REGISTRY availability + revocation check
    // BEFORE contract/capability validation (artifact_contract::AdmissionGate::evaluate,
    // the `else` arm that denies with TrustRevoked "Trust registry not available for
    // validation"). The deliberately-invalid-contract tests below therefore need an
    // AVAILABLE registry carrying an Active, non-quarantined trust card for the artifact's
    // extension_id so admission gets PAST the trust precondition and reaches the contract /
    // capability validation that each test actually exercises.
    use crate::supply_chain::certification::{EvidenceType, VerifiedEvidenceRef};
    use crate::supply_chain::trust_card::{
        BehavioralProfile, CapabilityDeclaration, CapabilityRisk, CertificationLevel,
        ExtensionIdentity, ProvenanceSummary, PublisherIdentity, ReputationTrend, RevocationStatus,
        RiskAssessment, RiskLevel, TrustCardInput, TrustCardRegistry,
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

    /// bd-o776s: a healthy (Active, non-quarantined) trust-card input so the
    /// admission trust precondition passes and validation proceeds to the
    /// contract/capability checks under test.
    fn healthy_card_input(extension_id: &str) -> TrustCardInput {
        TrustCardInput {
            extension: ExtensionIdentity {
                extension_id: extension_id.to_string(),
                version: "1.0.0".to_string(),
            },
            publisher: PublisherIdentity {
                publisher_id: "pub-test".to_string(),
                display_name: "Test Publisher".to_string(),
            },
            certification_level: CertificationLevel::Gold,
            capability_declarations: vec![CapabilityDeclaration {
                name: "fs.read".to_string(),
                description: "Read filesystem".to_string(),
                risk: CapabilityRisk::Low,
            }],
            behavioral_profile: BehavioralProfile {
                network_access: false,
                filesystem_access: true,
                subprocess_access: false,
                profile_summary: "test profile".to_string(),
            },
            revocation_status: RevocationStatus::Active,
            provenance_summary: ProvenanceSummary {
                attestation_level: "slsa-l3".to_string(),
                source_uri: "fixture://trust-card/test".to_string(),
                artifact_hashes: vec![format!("sha256:{}", "a".repeat(64))],
                verified_at: "2026-01-01T00:00:00Z".to_string(),
            },
            reputation_score_basis_points: 900,
            reputation_trend: ReputationTrend::Stable,
            active_quarantine: false,
            dependency_trust_summary: Vec::new(),
            last_verified_timestamp: "2026-01-01T00:00:00Z".to_string(),
            user_facing_risk_assessment: RiskAssessment {
                level: RiskLevel::Low,
                summary: "test risk".to_string(),
            },
            evidence_refs: vec![VerifiedEvidenceRef {
                evidence_id: "ev-test-001".to_string(),
                evidence_type: EvidenceType::ProvenanceChain,
                verified_at_epoch: 1,
                verification_receipt_hash: "a".repeat(64),
            }],
        }
    }

    /// bd-o776s: registry seeded with Active, non-quarantined trust cards for the
    /// extension IDs the admission tests exercise (`ext-alpha`, `ext-beta`), so the
    /// trust precondition admits past it into contract/capability validation.
    fn healthy_trust_registry() -> TrustCardRegistry {
        let mut registry = TrustCardRegistry::default();
        for extension_id in ["ext-alpha", "ext-beta"] {
            registry
                .create(healthy_card_input(extension_id), 0, "test-trust-setup")
                .expect("healthy trust card registration should succeed");
        }
        registry
    }

    /// bd-o776s: evaluate an artifact through the trusted gate WITH an available,
    /// healthy trust registry (the precondition prod now requires before contract
    /// validation). Drop-in for the former `trusted_gate().evaluate(&artifact, None, 0)`.
    fn evaluate_admission(artifact: &ExtensionArtifact) -> AdmissionOutcome {
        let mut registry = healthy_trust_registry();
        trusted_gate().evaluate(artifact, Some(&mut registry), 0)
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

        let reason = denial_reason(evaluate_admission(&artifact));

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

        let reason = denial_reason(evaluate_admission(&artifact));

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

        let reason = denial_reason(evaluate_admission(&artifact));

        assert!(matches!(reason, AdmissionDenialReason::SignatureInvalid));
    }

    #[test]
    fn admission_denies_tampered_contract_after_signing() {
        let mut contract = signed_contract();
        contract.capabilities[0].scope = "filesystem:write".to_string();
        let artifact = make_artifact("artifact-tampered", "ext-alpha", contract);

        let reason = denial_reason(evaluate_admission(&artifact));

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

        let reason = denial_reason(evaluate_admission(&artifact));

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

        let reason = denial_reason(evaluate_admission(&artifact));

        assert!(matches!(
            reason,
            AdmissionDenialReason::InvalidCapability { .. }
        ));
    }

    #[test]
    fn admission_denies_artifact_extension_contract_mismatch() {
        let contract = signed_contract();
        let artifact = make_artifact("artifact-mismatch", "ext-beta", contract);

        let reason = denial_reason(evaluate_admission(&artifact));

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

        let reason = denial_reason(evaluate_admission(&artifact));

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

        // bd-o776s (classification A): `make_artifact("")` sets BOTH the contract's and the
        // artifact's `artifact_id` to "", and prod validates the contract-embedded
        // `artifact_id` first, so the denial detail is "empty contract artifact_id" rather
        // than the artifact-layer "empty artifact_id". Intent (empty artifact id denied as
        // InvalidContract) is preserved.
        assert_invalid_contract_detail(evaluate_admission(&artifact), "empty contract artifact_id");
    }

    #[test]
    fn admission_denies_reserved_artifact_id() {
        let contract = signed_contract();
        let artifact = make_artifact("<unknown>", "ext-alpha", contract);

        assert_invalid_contract_detail(evaluate_admission(&artifact), "artifact_id is reserved");
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

        assert_invalid_contract_detail(evaluate_admission(&artifact), "contract_id contains");
    }

    #[test]
    fn admission_denies_empty_signature() {
        let mut contract = signed_contract();
        contract.signature.clear();
        let artifact = make_artifact("artifact-empty-signature", "ext-alpha", contract);

        assert_invalid_contract_detail(evaluate_admission(&artifact), "empty signature");
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

        // bd-o776s (classification A): prod validates the capability scope via
        // `invalid_token_detail("capability scope", ..)`, so an empty scope is reported as
        // "empty capability scope" (not "empty capability_id or scope"). Intent (empty
        // capability scope denied as InvalidCapability) is preserved.
        assert_invalid_capability_detail(evaluate_admission(&artifact), "empty capability scope");
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

        assert_invalid_capability_detail(evaluate_admission(&artifact), "leading or trailing");
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
            evaluate_admission(&artifact),
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
            evaluate_admission(&artifact),
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

        assert_invalid_contract_detail(evaluate_admission(&artifact), "empty signer_id");
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

        assert_invalid_contract_detail(evaluate_admission(&artifact), "signer_id contains");
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

        assert_invalid_contract_detail(evaluate_admission(&artifact), "issued_epoch_ms");
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

        assert_invalid_contract_detail(evaluate_admission(&artifact), "capability list");
    }

    #[test]
    fn admission_denies_short_payload_hash() {
        let contract = signed_contract();
        let mut artifact = make_artifact("artifact-short-payload", "ext-alpha", contract);
        artifact.payload_hash = "a".repeat(63);

        assert_invalid_contract_detail(evaluate_admission(&artifact), "payload_hash");
    }

    #[test]
    fn admission_denies_excessively_long_artifact_id() {
        let contract = signed_contract();
        let long_id = "x".repeat(1024);
        let artifact = make_artifact(&long_id, "ext-alpha", contract);

        assert_invalid_contract_detail(evaluate_admission(&artifact), "artifact_id");
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

        assert_invalid_capability_detail(evaluate_admission(&artifact), "capability_id contains");
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

        assert_invalid_capability_detail(evaluate_admission(&artifact), "contains non-ASCII");
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

        assert_invalid_capability_detail(evaluate_admission(&artifact), "path traversal");
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

        // bd-o776s (classification A): prod's trust-registry precondition now runs first
        // and its own `validate_extension_id` rejects control characters in the
        // artifact.extension_id BEFORE the artifact-contract control-char check is reached,
        // so the denial reason is now TrustRevoked rather than InvalidContract. The intent
        // (control characters in the extension id are denied) is preserved and still
        // asserted via the "control characters" substring.
        match denial_reason(evaluate_admission(&artifact)) {
            AdmissionDenialReason::TrustRevoked { detail } => {
                assert!(
                    detail.contains("control characters"),
                    "expected control-character trust rejection, got {detail:?}"
                );
            }
            reason => panic!("expected trust-revoked denial for control chars, got {reason:?}"),
        }
    }

    #[test]
    fn admission_denies_payload_hash_with_non_hex_characters() {
        let contract = signed_contract();
        let mut artifact = make_artifact("artifact-non-hex", "ext-alpha", contract);
        artifact.payload_hash = "g".repeat(64); // 'g' is not a hex digit

        assert_invalid_contract_detail(evaluate_admission(&artifact), "payload_hash");
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
