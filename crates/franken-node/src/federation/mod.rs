//! Adversarial Trust Commons (ATC) federation layer.
//!
//! Privacy-preserving cross-deployment threat learning, robust aggregation,
//! and verifier-backed trust metrics for the ATC network.

pub mod atc_participation_weighting;
pub mod atc_reciprocity;

#[cfg(test)]
pub mod additional_edge_tests;

#[cfg(test)]
mod federation_root_negative_tests {
    use super::atc_participation_weighting::{
        AttestationEvidence, AttestationLevel, ParticipantIdentity, ParticipationWeightEngine,
        ReputationEvidence, StakeEvidence, WeightingConfig,
    };
    use super::atc_reciprocity::{
        AccessTier, ContributionMetrics, ReciprocityConfig, ReciprocityEngine,
        event_codes as reciprocity_events,
    };

    fn attestation(id: &str, level: AttestationLevel) -> AttestationEvidence {
        AttestationEvidence {
            attestation_id: format!("att-{id}"),
            issuer: "federation-root-test-ca".to_string(),
            level,
            issued_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2027-01-01T00:00:00Z".to_string(),
            signature_hex: "abcdef".to_string(),
        }
    }

    fn participant_with_attestation(id: &str) -> ParticipantIdentity {
        ParticipantIdentity {
            participant_id: id.to_string(),
            display_name: format!("Participant {id}"),
            attestations: vec![attestation(id, AttestationLevel::AuthorityCertified)],
            stake: Some(StakeEvidence {
                amount: 1000.0,
                deposited_at: "2026-01-01T00:00:00Z".to_string(),
                lock_duration_seconds: 86400 * 30,
                locked: true,
            }),
            reputation: Some(ReputationEvidence {
                score: 0.9,
                interaction_count: 200,
                tenure_seconds: 86400 * 90,
                contributions_accepted: 120,
                contributions_rejected: 0,
            }),
            cluster_hint: None,
        }
    }

    fn participant_without_attestation(id: &str) -> ParticipantIdentity {
        ParticipantIdentity {
            participant_id: id.to_string(),
            display_name: format!("Unattested {id}"),
            attestations: vec![],
            stake: Some(StakeEvidence {
                amount: 1_000_000.0,
                deposited_at: "2026-01-01T00:00:00Z".to_string(),
                lock_duration_seconds: 86400 * 365,
                locked: true,
            }),
            reputation: Some(ReputationEvidence {
                score: 1.0,
                interaction_count: 10_000,
                tenure_seconds: 86400 * 365,
                contributions_accepted: 10_000,
                contributions_rejected: 0,
            }),
            cluster_hint: None,
        }
    }

    fn metrics(
        id: &str,
        made: u64,
        consumed: u64,
        quality: f64,
        age_seconds: u64,
    ) -> ContributionMetrics {
        ContributionMetrics {
            participant_id: id.to_string(),
            contributions_made: made,
            intelligence_consumed: consumed,
            contribution_quality: quality,
            membership_age_seconds: age_seconds,
            has_exception: false,
            exception_reason: None,
            exception_expires_at: None,
        }
    }

    fn excepted_metrics(id: &str) -> ContributionMetrics {
        ContributionMetrics {
            has_exception: true,
            exception_reason: Some("manual federation exception".to_string()),
            exception_expires_at: Some("2027-01-01T00:00:00Z".to_string()),
            ..metrics(id, 0, 100, 0.0, 86400 * 90)
        }
    }

    #[test]
    fn federation_root_grace_access_does_not_override_missing_attestation() {
        let mut weighting = ParticipationWeightEngine::default();
        let mut reciprocity = ReciprocityEngine::default();
        let id = "missing-attestation-grace";

        let record = weighting.compute_weights(
            &[participant_without_attestation(id)],
            "federation-root-grace",
            "2026-04-17T00:00:00Z",
        );
        let decision =
            reciprocity.evaluate_access(&metrics(id, 0, 0, 0.0, 60), "2026-04-17T00:00:00Z");

        assert!(decision.grace_period_active);
        assert!(decision.granted);
        assert!(record.weights[0].rejected);
        assert_eq!(
            record.weights[0].rejection_reason.as_deref(),
            Some("no attestation evidence")
        );
    }

    #[test]
    fn federation_root_exception_access_does_not_override_missing_attestation() {
        let mut weighting = ParticipationWeightEngine::default();
        let mut reciprocity = ReciprocityEngine::default();
        let id = "missing-attestation-exception";

        let record = weighting.compute_weights(
            &[participant_without_attestation(id)],
            "federation-root-exception",
            "2026-04-17T00:00:00Z",
        );
        let decision = reciprocity.evaluate_access(&excepted_metrics(id), "2026-04-17T00:00:00Z");

        assert!(decision.exception_applied);
        assert_eq!(decision.tier, AccessTier::Standard);
        assert!(record.weights[0].rejected);
        assert_eq!(record.participants_rejected, 1);
    }

    #[test]
    fn federation_root_positive_weight_does_not_override_freerider_block() {
        let mut weighting = ParticipationWeightEngine::default();
        let mut reciprocity = ReciprocityEngine::default();
        let id = "weighted-freerider";

        let record = weighting.compute_weights(
            &[participant_with_attestation(id)],
            "federation-root-freerider",
            "2026-04-17T00:00:00Z",
        );
        let decision = reciprocity.evaluate_access(
            &metrics(id, 0, 500, 1.0, 86400 * 90),
            "2026-04-17T00:00:00Z",
        );

        assert!(record.weights[0].final_weight > 0.0);
        assert_eq!(decision.tier, AccessTier::Blocked);
        assert!(!decision.granted);
        assert!(decision.accessible_feeds.is_empty());
    }

    #[test]
    fn federation_root_infinite_quality_blocks_access_without_poisoning_weighting() {
        let mut weighting = ParticipationWeightEngine::default();
        let mut reciprocity = ReciprocityEngine::default();
        let id = "infinite-quality";

        let record = weighting.compute_weights(
            &[participant_with_attestation(id)],
            "federation-root-infinite-quality",
            "2026-04-17T00:00:00Z",
        );
        let decision = reciprocity.evaluate_access(
            &metrics(id, 10_000, 1, f64::INFINITY, 86400 * 90),
            "2026-04-17T00:00:00Z",
        );

        assert!(record.total_weight.is_finite());
        assert!(record.weights[0].final_weight.is_finite());
        assert_eq!(decision.quality_adjusted_ratio, 0.0);
        assert_eq!(decision.tier, AccessTier::Blocked);
    }

    #[test]
    fn federation_root_zero_quality_blocks_authority_weighted_identity() {
        let mut weighting = ParticipationWeightEngine::default();
        let mut reciprocity = ReciprocityEngine::default();
        let id = "zero-quality-authority";

        let record = weighting.compute_weights(
            &[participant_with_attestation(id)],
            "federation-root-zero-quality",
            "2026-04-17T00:00:00Z",
        );
        let decision = reciprocity.evaluate_access(
            &metrics(id, 999, 1, 0.0, 86400 * 90),
            "2026-04-17T00:00:00Z",
        );

        assert!(record.weights[0].attestation_component > 0.0);
        assert_eq!(decision.contribution_ratio, 1.0);
        assert_eq!(decision.quality_adjusted_ratio, 0.0);
        assert!(!decision.granted);
    }

    #[test]
    fn federation_root_sybil_penalty_survives_reciprocity_exception() {
        let mut weighting = ParticipationWeightEngine::default();
        let mut reciprocity = ReciprocityEngine::default();
        let mut participants = vec![
            participant_with_attestation("cluster-a"),
            participant_with_attestation("cluster-b"),
            participant_with_attestation("cluster-c"),
        ];
        for participant in &mut participants {
            participant.cluster_hint = Some("shared-test-cluster".to_string());
        }

        let record = weighting.compute_weights(
            &participants,
            "federation-root-sybil",
            "2026-04-17T00:00:00Z",
        );
        let decision =
            reciprocity.evaluate_access(&excepted_metrics("cluster-a"), "2026-04-17T00:00:00Z");

        assert_eq!(record.sybil_clusters_detected, 1);
        assert!(
            record
                .weights
                .iter()
                .all(|weight| weight.sybil_penalty > 0.0)
        );
        assert!(decision.exception_applied);
        assert_eq!(decision.tier, AccessTier::Standard);
    }

    #[test]
    fn federation_root_mixed_batch_keeps_rejected_identity_out_of_total_weight() {
        let mut weighting = ParticipationWeightEngine::default();
        let record = weighting.compute_weights(
            &[
                participant_with_attestation("accepted-member"),
                participant_without_attestation("rejected-member"),
            ],
            "federation-root-mixed",
            "2026-04-17T00:00:00Z",
        );

        assert_eq!(record.participants_rejected, 1);
        assert!(!record.weights[0].rejected);
        assert!(record.weights[1].rejected);
        assert_eq!(record.weights[1].final_weight, 0.0);
        assert_eq!(record.total_weight, record.weights[0].final_weight);
    }

    #[test]
    fn federation_root_blocked_reciprocity_batch_records_no_exceptions() {
        let mut reciprocity = ReciprocityEngine::new(ReciprocityConfig {
            grace_period_seconds: 0,
            ..ReciprocityConfig::default()
        });
        let blocked = vec![
            metrics("blocked-a", 0, 10, 1.0, 86400 * 90),
            metrics("blocked-b", 1, 1000, f64::NAN, 86400 * 90),
        ];

        let matrix =
            reciprocity.evaluate_batch(&blocked, "federation-root-blocked", "2026-04-17T00:00:00Z");

        assert_eq!(matrix.total_participants, 2);
        assert_eq!(matrix.freeriders_blocked, 2);
        assert_eq!(matrix.exceptions_active, 0);
        assert!(
            matrix
                .entries
                .iter()
                .all(|entry| entry.tier == AccessTier::Blocked)
        );
    }

    #[test]
    fn federation_root_empty_weight_batch_records_zero_weight() {
        let mut weighting = ParticipationWeightEngine::default();

        let record =
            weighting.compute_weights(&[], "federation-root-empty-weight", "2026-04-17T00:00:00Z");

        assert_eq!(record.participant_count, 0);
        assert_eq!(record.participants_rejected, 0);
        assert_eq!(record.participants_capped, 0);
        assert_eq!(record.sybil_clusters_detected, 0);
        assert_eq!(record.total_weight, 0.0);
        assert!(record.weights.is_empty());
        assert_eq!(weighting.audit_log().len(), 1);
    }

    #[test]
    fn federation_root_zero_attestation_identity_gets_no_weight_despite_strong_claims() {
        let mut weighting = ParticipationWeightEngine::default();

        let record = weighting.compute_weights(
            &[participant_without_attestation("untrusted-heavyweight")],
            "federation-root-untrusted-heavyweight",
            "2026-04-17T00:00:00Z",
        );

        let weight = &record.weights[0];
        assert!(weight.rejected);
        assert_eq!(weight.final_weight, 0.0);
        assert_eq!(record.total_weight, 0.0);
        assert_eq!(
            weight.rejection_reason.as_deref(),
            Some("no attestation evidence")
        );
    }

    #[test]
    fn federation_root_nan_stake_amount_cannot_poison_weight_totals() {
        let mut weighting = ParticipationWeightEngine::default();
        let mut participant = participant_with_attestation("nan-stake");
        participant.stake.as_mut().unwrap().amount = f64::NAN;

        let record = weighting.compute_weights(
            &[participant],
            "federation-root-nan-stake",
            "2026-04-17T00:00:00Z",
        );

        let weight = &record.weights[0];
        assert!(!weight.rejected);
        assert_eq!(weight.stake_component, 0.0);
        assert!(weight.raw_weight.is_finite());
        assert!(weight.final_weight.is_finite());
        assert!(record.total_weight.is_finite());
    }

    #[test]
    fn federation_root_infinite_reputation_score_is_damped_not_amplified() {
        let mut weighting = ParticipationWeightEngine::default();
        let mut participant = participant_with_attestation("infinite-reputation");
        participant.reputation.as_mut().unwrap().score = f64::INFINITY;

        let record = weighting.compute_weights(
            &[participant],
            "federation-root-infinite-reputation",
            "2026-04-17T00:00:00Z",
        );

        let weight = &record.weights[0];
        assert!(!weight.rejected);
        assert!(weight.reputation_component.is_finite());
        assert!(weight.reputation_component <= 0.6 + f64::EPSILON);
        assert!(weight.final_weight.is_finite());
    }

    #[test]
    fn federation_root_rejected_only_history_does_not_receive_interaction_credit() {
        let mut weighting = ParticipationWeightEngine::default();
        let mut participant = participant_with_attestation("rejected-only-history");
        participant.reputation = Some(ReputationEvidence {
            score: 1.0,
            interaction_count: 500,
            tenure_seconds: 86400 * 180,
            contributions_accepted: 0,
            contributions_rejected: 500,
        });

        let record = weighting.compute_weights(
            &[participant],
            "federation-root-rejected-only-history",
            "2026-04-17T00:00:00Z",
        );

        let weight = &record.weights[0];
        assert!(!weight.rejected);
        assert!(weight.reputation_component < 0.8);
        assert!(weight.final_weight.is_finite());
    }

    #[test]
    fn federation_root_grace_boundary_blocks_zero_contributor() {
        let mut reciprocity = ReciprocityEngine::default();
        let mut boundary = metrics(
            "grace-boundary-zero",
            0,
            100,
            1.0,
            ReciprocityConfig::default().grace_period_seconds,
        );
        boundary.has_exception = false;

        let decision = reciprocity.evaluate_access(&boundary, "2026-04-17T00:00:00Z");

        assert!(!decision.grace_period_active);
        assert!(!decision.exception_applied);
        assert_eq!(decision.tier, AccessTier::Blocked);
        assert!(!decision.granted);
        assert!(decision.accessible_feeds.is_empty());
    }

    #[test]
    fn federation_root_nan_quality_after_grace_blocks_access_and_logs_denial() {
        let mut reciprocity = ReciprocityEngine::default();
        let participant = metrics("nan-quality-after-grace", 10_000, 1, f64::NAN, 86400 * 90);

        let decision = reciprocity.evaluate_access(&participant, "2026-04-17T00:00:00Z");

        assert_eq!(decision.contribution_ratio, 1.0);
        assert_eq!(decision.quality_adjusted_ratio, 0.0);
        assert_eq!(decision.tier, AccessTier::Blocked);
        assert!(!decision.granted);
        assert_eq!(reciprocity.audit_log().len(), 1);
        assert_eq!(
            reciprocity.audit_log()[0].event_code,
            reciprocity_events::ACCESS_DENIED
        );
    }

    #[test]
    fn federation_root_empty_reciprocity_batch_emits_no_phantom_decisions() {
        let mut reciprocity = ReciprocityEngine::default();

        let matrix = reciprocity.evaluate_batch(
            &[],
            "federation-root-empty-reciprocity",
            "2026-04-17T00:00:00Z",
        );

        assert_eq!(matrix.total_participants, 0);
        assert_eq!(matrix.freeriders_blocked, 0);
        assert_eq!(matrix.exceptions_active, 0);
        assert!(matrix.entries.is_empty());
        assert!(matrix.tier_distribution.is_empty());
        assert!(reciprocity.audit_log().is_empty());
    }

    #[test]
    fn federation_root_attestation_level_rejects_camel_case_wire_value() {
        let result = serde_json::from_str::<AttestationLevel>("\"AuthorityCertified\"");

        assert!(result.is_err());
    }

    #[test]
    fn federation_root_access_tier_rejects_uppercase_wire_value() {
        let result = serde_json::from_str::<AccessTier>("\"STANDARD\"");

        assert!(result.is_err());
    }

    #[test]
    fn federation_root_participant_identity_rejects_object_attestations_field() {
        let result = serde_json::from_value::<ParticipantIdentity>(serde_json::json!({
            "participant_id": "bad-attestations-field",
            "display_name": "Bad Attestations Field",
            "attestations": {},
            "stake": null,
            "reputation": null,
            "cluster_hint": null
        }));

        assert!(result.is_err());
    }

    #[test]
    fn federation_root_stake_evidence_rejects_string_amount() {
        let result = serde_json::from_value::<StakeEvidence>(serde_json::json!({
            "amount": "1000.0",
            "deposited_at": "2026-01-01T00:00:00Z",
            "lock_duration_seconds": 2592000,
            "locked": true
        }));

        assert!(result.is_err());
    }

    #[test]
    fn federation_root_reputation_evidence_rejects_string_interaction_count() {
        let result = serde_json::from_value::<ReputationEvidence>(serde_json::json!({
            "score": 0.9,
            "interaction_count": "200",
            "tenure_seconds": 7776000,
            "contributions_accepted": 120,
            "contributions_rejected": 0
        }));

        assert!(result.is_err());
    }

    #[test]
    fn federation_root_contribution_metrics_rejects_string_quality() {
        let result = serde_json::from_value::<ContributionMetrics>(serde_json::json!({
            "participant_id": "bad-quality",
            "contributions_made": 10,
            "intelligence_consumed": 1,
            "contribution_quality": "1.0",
            "membership_age_seconds": 7776000,
            "has_exception": false,
            "exception_reason": null,
            "exception_expires_at": null
        }));

        assert!(result.is_err());
    }

    #[test]
    fn federation_root_reciprocity_config_rejects_string_grace_period() {
        let result = serde_json::from_value::<ReciprocityConfig>(serde_json::json!({
            "full_tier_min_ratio": 0.8,
            "standard_tier_min_ratio": 0.4,
            "limited_tier_min_ratio": 0.1,
            "grace_period_seconds": "604800",
            "grace_period_tier": "standard",
            "use_quality_adjustment": true
        }));

        assert!(result.is_err());
    }

    #[test]
    fn federation_root_weighting_config_rejects_string_sybil_min_size() {
        let result = serde_json::from_value::<WeightingConfig>(serde_json::json!({
            "attestation_weight": 0.4,
            "stake_weight": 0.3,
            "reputation_weight": 0.3,
            "new_participant_cap_fraction": 0.01,
            "established_tenure_seconds": 2592000,
            "established_interaction_count": 100,
            "sybil_attenuation_factor": 0.1,
            "sybil_cluster_min_size": "3"
        }));

        assert!(result.is_err());
    }

    /// Extreme adversarial test: Unicode BiDi override injection in participant IDs
    /// to exploit federation peer matching algorithms via visual spoofing attacks
    #[test]
    fn federation_root_participant_id_bidi_override_visual_spoofing_attack() {
        let mut weighting = ParticipationWeightEngine::default();
        // BiDi override to visually spoof "trusted-peer-001" as "100-reep-detsurt"
        let malicious_id = "trusted-peer-\u{202E}100-reep-detsurt\u{202C}";
        let mut participant = participant_with_attestation(malicious_id);
        participant.cluster_hint = Some("evil\u{200B}cluster".to_string()); // Zero-width space injection

        let record = weighting.compute_weights(
            &[participant],
            "federation-root-bidi-spoofing",
            "2026-04-17T00:00:00Z",
        );

        // System must handle Unicode exploitation without crashing
        assert_eq!(record.participant_count, 1);
        assert!(record.weights[0].final_weight.is_finite());
        // Should preserve exact Unicode in audit trail for forensics
        let audit_entries = weighting.audit_log();
        assert!(!audit_entries.is_empty());
        assert!(
            audit_entries[0]
                .notes
                .as_ref()
                .unwrap_or(&"".to_string())
                .contains('\u{202E}')
        );
    }

    /// Extreme adversarial test: Massive contribution metrics to trigger arithmetic overflow
    /// in weighted aggregation calculations during federation consensus rounds
    #[test]
    fn federation_root_contribution_metrics_arithmetic_overflow_consensus_attack() {
        let mut reciprocity = ReciprocityEngine::default();
        let massive_metrics = ContributionMetrics {
            participant_id: "overflow-attacker".to_string(),
            contributions_made: u64::MAX,
            intelligence_consumed: u64::MAX - 1,
            contribution_quality: f64::MAX,
            membership_age_seconds: u64::MAX,
            has_exception: false,
            exception_reason: None,
            exception_expires_at: None,
        };

        let decision = reciprocity.evaluate_access(&massive_metrics, "2026-04-17T00:00:00Z");

        // Arithmetic must remain bounded despite massive inputs
        assert!(decision.contribution_ratio.is_finite());
        assert!(decision.quality_adjusted_ratio.is_finite());
        assert!(decision.contribution_ratio <= 1.0 + f64::EPSILON);
        // Quality clamping should prevent infinite amplification
        assert!(
            decision.quality_adjusted_ratio <= 1.0 + f64::EPSILON
                || decision.quality_adjusted_ratio == 0.0
        );
        assert_ne!(decision.tier, AccessTier::Full); // Should not grant max privileges
    }

    /// Extreme adversarial test: Attestation signature with embedded null bytes and control
    /// characters to exploit downstream signature verification parsing vulnerabilities
    #[test]
    fn federation_root_attestation_signature_null_byte_control_char_injection() {
        let mut weighting = ParticipationWeightEngine::default();
        let malicious_attestation = AttestationEvidence {
            attestation_id: "att-control-injection".to_string(),
            issuer: "evil-ca\0real-ca\r\n".to_string(), // Null byte + CRLF injection
            level: AttestationLevel::AuthorityCertified,
            issued_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2027-01-01T00:00:00Z".to_string(),
            signature_hex: "deadbeef\0\x01\x02\x03\x1f\x7f".to_string(), // Control chars in hex
        };

        let mut participant = participant_with_attestation("control-char-victim");
        participant.attestations = vec![malicious_attestation];

        let record = weighting.compute_weights(
            &[participant],
            "federation-root-control-injection",
            "2026-04-17T00:00:00Z",
        );

        // System must handle control character injection safely
        assert_eq!(record.participant_count, 1);
        assert!(record.weights[0].final_weight.is_finite());
        // Audit log should preserve control chars for forensic analysis
        let audit_entries = weighting.audit_log();
        assert!(!audit_entries.is_empty());
    }

    /// Extreme adversarial test: Coordinated time manipulation attack via malformed
    /// timestamps to exploit federation epoch transition boundary conditions
    #[test]
    fn federation_root_epoch_boundary_timestamp_manipulation_race_attack() {
        let mut weighting = ParticipationWeightEngine::default();
        let mut reciprocity = ReciprocityEngine::default();

        // Time boundary exploitation: past, far future, malformed ISO formats
        let time_attack_vectors = [
            "1970-01-01T00:00:00Z",           // Unix epoch start
            "2099-12-31T23:59:59Z",           // Far future
            "2026-04-17T25:00:00Z",           // Invalid hour
            "2026-02-30T12:00:00Z",           // Invalid date
            "2026-04-17T12:00:00",            // Missing timezone
            "2026-04-17T12:00:00.999999999Z", // Nanosecond precision
        ];

        for (i, malicious_time) in time_attack_vectors.iter().enumerate() {
            let id = format!("time-attack-{}", i);
            let mut participant = participant_with_attestation(&id);

            // Corrupt timestamp fields in evidence
            if let Some(stake) = participant.stake.as_mut() {
                stake.deposited_at = malicious_time.to_string();
            }

            let record = weighting.compute_weights(
                &[participant],
                &format!("federation-root-time-attack-{}", i),
                malicious_time, // Use malformed time as evaluation time
            );

            // System must gracefully handle time boundary attacks
            assert_eq!(record.participant_count, 1);
            assert!(record.total_weight.is_finite());

            // Test reciprocity with same malformed time
            let decision = reciprocity
                .evaluate_access(&metrics(&id, 100, 10, 1.0, 86400 * 90), malicious_time);
            assert!(decision.contribution_ratio.is_finite());
        }
    }

    /// Extreme adversarial test: Memory exhaustion via recursive JSON structure nesting
    /// in exception reason fields to exploit federation state serialization paths
    #[test]
    fn federation_root_recursive_json_nesting_memory_exhaustion_attack() {
        let mut reciprocity = ReciprocityEngine::default();

        // Construct deeply nested JSON-like exception reason (simulated attack)
        let mut nested_reason = String::from("exception");
        for _ in 0..1000 {
            // Simulate deep nesting attempt
            nested_reason = format!("{{\"inner\": \"{}\"}}", nested_reason.replace('"', "\\\""));
            if nested_reason.len() > 100_000 {
                // Prevent actual memory exhaustion in test
                break;
            }
        }

        let malicious_metrics = ContributionMetrics {
            participant_id: "memory-exhaustion-attacker".to_string(),
            contributions_made: 1,
            intelligence_consumed: 1,
            contribution_quality: 1.0,
            membership_age_seconds: 86400 * 90,
            has_exception: true,
            exception_reason: Some(nested_reason),
            exception_expires_at: Some("2027-01-01T00:00:00Z".to_string()),
        };

        let decision = reciprocity.evaluate_access(&malicious_metrics, "2026-04-17T00:00:00Z");

        // System must handle large exception reasons without crashing
        assert!(decision.exception_applied);
        assert_eq!(decision.tier, AccessTier::Standard);

        // Audit log should be bounded despite large input
        let audit_entries = reciprocity.audit_log();
        assert!(!audit_entries.is_empty());
        for entry in audit_entries {
            if let Some(notes) = &entry.notes {
                assert!(notes.len() < 50_000); // Reasonable bound on log entry size
            }
        }
    }

    /// Extreme adversarial test: Participant batch with algorithmically crafted cluster hints
    /// designed to trigger worst-case O(n²) sybil detection performance degradation
    #[test]
    fn federation_root_sybil_detection_algorithmic_complexity_explosion_attack() {
        let mut weighting = ParticipationWeightEngine::new(WeightingConfig {
            sybil_cluster_min_size: 2, // Lower threshold for easier triggering
            ..WeightingConfig::default()
        });

        // Craft participant batch with overlapping cluster hints designed to maximize
        // comparison operations in sybil detection algorithm
        let mut participants = Vec::new();
        for i in 0..100 {
            let mut participant = participant_with_attestation(&format!("complexity-attack-{}", i));
            // Create overlapping cluster patterns that require maximum comparisons
            participant.cluster_hint = Some(format!(
                "cluster-{}-{}-{}",
                i % 10,
                (i + 1) % 10,
                (i + 2) % 10
            ));
            participants.push(participant);
        }

        let start = std::time::Instant::now();
        let record = weighting.compute_weights(
            &participants,
            "federation-root-complexity-attack",
            "2026-04-17T00:00:00Z",
        );
        let elapsed = start.elapsed();

        // Algorithm must complete in reasonable time despite adversarial input
        assert!(elapsed.as_millis() < 10_000); // Max 10 seconds for 100 participants
        assert_eq!(record.participant_count, 100);
        assert!(record.total_weight.is_finite());

        // Sybil detection should still function correctly
        assert!(record.sybil_clusters_detected > 0);
        assert!(record.weights.iter().any(|w| w.sybil_penalty > 0.0));
    }

    /// Extreme adversarial test: Concurrent modification race via rapid-fire batch evaluation
    /// while participant state mutations occur to exploit federation consensus windows
    #[test]
    fn federation_root_concurrent_batch_evaluation_state_corruption_race() {
        use std::sync::Arc;
        use std::thread;

        let reciprocity = Arc::new(std::sync::Mutex::new(ReciprocityEngine::default()));
        let base_metrics = metrics("race-participant", 100, 10, 1.0, 86400 * 90);

        // Simulate concurrent access patterns that could corrupt internal state
        let handles: Vec<_> = (0..10)
            .map(|thread_id| {
                let reciprocity_clone = Arc::clone(&reciprocity);
                let mut thread_metrics = base_metrics.clone();
                thread_metrics.participant_id = format!("race-participant-{}", thread_id);

                thread::spawn(move || {
                    let batch = vec![thread_metrics; 5]; // Small batches for rapid iteration
                    for i in 0..20 {
                        // 20 rapid evaluations per thread
                        let session_id = format!("race-session-{}-{}", thread_id, i);
                        if let Ok(mut engine) = reciprocity_clone.try_lock() {
                            let _matrix =
                                engine.evaluate_batch(&batch, &session_id, "2026-04-17T00:00:00Z");
                            // Intentionally brief lock to maximize contention
                        }
                        thread::yield_now(); // Encourage race conditions
                    }
                })
            })
            .collect();

        // Wait for all threads to complete
        for handle in handles {
            handle.join().unwrap();
        }

        // Verify engine state remains consistent after concurrent access
        let final_engine = reciprocity.lock().unwrap();
        let final_log = final_engine.audit_log();

        // State must be internally consistent despite concurrent access
        assert!(!final_log.is_empty());
        // All audit entries should have valid structure
        for entry in final_log {
            assert!(!entry.session_id.is_empty());
            assert!(!entry.participant_id.is_empty());
            assert!(entry.event_code >= 0);
        }
    }
}
