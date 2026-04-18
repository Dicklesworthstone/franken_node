//! Additional edge case tests for federation modules
//! These tests complement the existing comprehensive test suites by focusing on
//! boundary conditions, overflow scenarios, and resource exhaustion cases.

#[cfg(test)]
mod additional_federation_edge_tests {
    use super::super::atc_participation_weighting::*;
    use super::super::atc_reciprocity::*;

    const TS: &str = "2026-02-20T00:00:00Z";

    fn attestation(id: &str, level: AttestationLevel) -> AttestationEvidence {
        AttestationEvidence {
            attestation_id: format!("att-{id}"),
            issuer: "test-ca".to_string(),
            level,
            issued_at: "2025-01-01T00:00:00Z".to_string(),
            expires_at: "2027-01-01T00:00:00Z".to_string(),
            signature_hex: "deadbeef".to_string(),
        }
    }

    fn established_reputation() -> ReputationEvidence {
        ReputationEvidence {
            score: 0.9,
            interaction_count: 250,
            tenure_seconds: 86400 * 365,
            contributions_accepted: 90,
            contributions_rejected: 10,
        }
    }

    fn participant(
        id: &str,
        attestations: Vec<AttestationEvidence>,
        stake: Option<StakeEvidence>,
        reputation: Option<ReputationEvidence>,
        cluster_hint: Option<&str>,
    ) -> ParticipantIdentity {
        ParticipantIdentity {
            participant_id: id.to_string(),
            display_name: format!("Participant {id}"),
            attestations,
            stake,
            reputation,
            cluster_hint: cluster_hint.map(str::to_string),
        }
    }

    fn metrics(
        id: &str,
        made: u64,
        consumed: u64,
        quality: f64,
        membership_age_seconds: u64,
    ) -> ContributionMetrics {
        ContributionMetrics {
            participant_id: id.to_string(),
            contributions_made: made,
            intelligence_consumed: consumed,
            contribution_quality: quality,
            membership_age_seconds,
            has_exception: false,
            exception_reason: None,
            exception_expires_at: None,
        }
    }

    // === Arithmetic Overflow Edge Cases ===

    #[test]
    fn test_participation_counter_overflow_protection() {
        let mut engine = ParticipationWeightEngine::default();

        let mut reputation = established_reputation();
        reputation.contributions_accepted = u64::MAX;
        reputation.contributions_rejected = u64::MAX;
        reputation.interaction_count = u64::MAX;

        let identity = participant(
            "overflow-test",
            vec![attestation(
                "overflow-test",
                AttestationLevel::AuthorityCertified,
            )],
            None,
            Some(reputation),
            None,
        );

        let record = engine.compute_weights(&[identity], "overflow-batch", TS);

        assert!(record.total_weight.is_finite());
        assert_eq!(record.weights.len(), 1);
        assert!(record.weights[0].reputation_component.is_finite());
        assert!(record.weights[0].reputation_component <= 1.0);
    }

    #[test]
    fn test_large_participant_list_bounded_capacity() {
        let mut engine = ParticipationWeightEngine::default();

        let mut participants = Vec::new();
        for i in 0..10_000 {
            let id = format!("participant-{i}");
            participants.push(participant(
                &id,
                vec![AttestationEvidence {
                    signature_hex: format!("{i:08x}"),
                    ..attestation(&id, AttestationLevel::PeerVerified)
                }],
                None,
                None,
                None,
            ));
        }

        let record = engine.compute_weights(&participants, "large-batch", TS);

        assert!(record.total_weight.is_finite());
        assert_eq!(record.weights.len(), participants.len());
    }

    // === Malformed Timestamp Edge Cases ===

    #[test]
    fn test_malformed_timestamp_handling() {
        let mut engine = ParticipationWeightEngine::default();

        let malformed = AttestationEvidence {
            issued_at: "not-a-valid-timestamp".to_string(),
            expires_at: "also-invalid".to_string(),
            signature_hex: "baddata".to_string(),
            ..attestation("malformed-time", AttestationLevel::SelfSigned)
        };
        let identity = participant("malformed-time", vec![malformed], None, None, None);

        let record = engine.compute_weights(&[identity], "malformed-batch", TS);

        assert!(record.total_weight.is_finite());
        assert_eq!(record.weights.len(), 1);
        assert!(record.weights[0].final_weight.is_finite());
    }

    // === Reciprocity Engine Edge Cases ===

    #[test]
    fn test_reciprocity_extreme_contribution_ratios() {
        let mut engine = ReciprocityEngine::default();

        let extreme_metrics = metrics("extreme-contrib", u64::MAX, 1, 1.0, 86400 * 60);

        let decision = engine.evaluate_access(&extreme_metrics, TS);

        assert!(decision.contribution_ratio.is_finite());
        assert!(decision.quality_adjusted_ratio.is_finite());
        assert!(matches!(
            decision.tier,
            AccessTier::Blocked | AccessTier::Limited | AccessTier::Standard | AccessTier::Full
        ));
    }

    #[test]
    fn test_reciprocity_zero_division_protection() {
        let mut engine = ReciprocityEngine::default();

        let zero_metrics = metrics("zero-test", 1000, 0, 1.0, 86400 * 30);

        let decision = engine.evaluate_access(&zero_metrics, TS);

        assert!(decision.granted);
        assert!(matches!(decision.tier, AccessTier::Full));
    }

    // === Concurrent Access Simulation ===

    #[test]
    fn test_concurrent_weight_computation_isolation() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let engine = Arc::new(Mutex::new(ParticipationWeightEngine::default()));

        // Simulate concurrent access to the engine
        let handles: Vec<_> = (0..8)
            .map(|thread_id| {
                let engine_clone = Arc::clone(&engine);
                thread::spawn(move || {
                    let participant = ParticipantIdentity {
                        participant_id: format!("concurrent-{thread_id}"),
                        display_name: format!("Concurrent Test {thread_id}"),
                        attestations: vec![attestation(
                            &format!("concurrent-{thread_id}"),
                            AttestationLevel::PeerVerified,
                        )],
                        stake: None,
                        reputation: None,
                        cluster_hint: None,
                    };

                    let mut engine_lock = engine_clone.lock().expect("engine lock should open");
                    let record = engine_lock.compute_weights(
                        &[participant],
                        &format!("concurrent-batch-{thread_id}"),
                        TS,
                    );

                    assert!(record.total_weight.is_finite());
                    assert!(!record.weights.is_empty());
                    record
                })
            })
            .collect();

        // Wait for all threads and verify results
        for handle in handles {
            let record = handle.join().expect("Thread should complete successfully");
            assert!(record.total_weight >= 0.0);
        }
    }

    // === Resource Exhaustion Protection ===

    #[test]
    fn test_memory_pressure_protection() {
        let mut engine = ParticipationWeightEngine::default();

        let large_participant = participant(
            "memory-test",
            (0..100)
                .map(|i| AttestationEvidence {
                    attestation_id: format!("large-att-{i}"),
                    issuer: "memory-ca".repeat(10),
                    level: AttestationLevel::PeerVerified,
                    issued_at: "2025-01-01T00:00:00Z".to_string(),
                    expires_at: "2027-01-01T00:00:00Z".to_string(),
                    signature_hex: "f".repeat(128),
                })
                .collect(),
            None,
            Some(established_reputation()),
            Some(&"cluster".repeat(200)),
        );

        let record = engine.compute_weights(&[large_participant], "memory-batch", TS);

        assert!(record.total_weight.is_finite());
        assert_eq!(record.weights.len(), 1);
    }

    // === Negative Path Coverage ===

    #[test]
    fn test_zero_attestation_participant_is_rejected_without_weight() {
        let mut engine = ParticipationWeightEngine::default();
        let identity = participant("no-attestation", Vec::new(), None, None, None);

        let record = engine.compute_weights(&[identity], "zero-attestation-batch", TS);

        assert_eq!(record.participants_rejected, 1);
        assert!(record.weights[0].rejected);
        assert!(record.weights[0].final_weight <= f64::EPSILON);
        assert!(
            record.weights[0]
                .rejection_reason
                .as_deref()
                .unwrap_or_default()
                .contains("attestation")
        );
    }

    #[test]
    fn test_non_finite_stake_amount_is_sanitized_to_zero_component() {
        let mut engine = ParticipationWeightEngine::default();
        let identity = participant(
            "infinite-stake",
            vec![attestation("infinite-stake", AttestationLevel::VerifierBacked)],
            Some(StakeEvidence {
                amount: f64::INFINITY,
                deposited_at: "2025-06-01T00:00:00Z".to_string(),
                lock_duration_seconds: u64::MAX,
                locked: true,
            }),
            Some(established_reputation()),
            None,
        );

        let record = engine.compute_weights(&[identity], "infinite-stake-batch", TS);

        assert!(record.weights[0].final_weight.is_finite());
        assert!(record.weights[0].stake_component <= f64::EPSILON);
    }

    #[test]
    fn test_negative_stake_amount_is_sanitized_to_zero_component() {
        let mut engine = ParticipationWeightEngine::default();
        let identity = participant(
            "negative-stake",
            vec![attestation("negative-stake", AttestationLevel::VerifierBacked)],
            Some(StakeEvidence {
                amount: -100.0,
                deposited_at: "2025-06-01T00:00:00Z".to_string(),
                lock_duration_seconds: 86400 * 30,
                locked: true,
            }),
            Some(established_reputation()),
            None,
        );

        let record = engine.compute_weights(&[identity], "negative-stake-batch", TS);

        assert!(record.weights[0].final_weight.is_finite());
        assert!(record.weights[0].stake_component <= f64::EPSILON);
    }

    #[test]
    fn test_non_finite_reputation_score_does_not_poison_total_weight() {
        let mut engine = ParticipationWeightEngine::default();
        let mut reputation = established_reputation();
        reputation.score = f64::NAN;
        let identity = participant(
            "nan-reputation",
            vec![attestation("nan-reputation", AttestationLevel::VerifierBacked)],
            None,
            Some(reputation),
            None,
        );

        let record = engine.compute_weights(&[identity], "nan-reputation-batch", TS);

        assert!(record.total_weight.is_finite());
        assert!(record.weights[0].reputation_component.is_finite());
        assert!(record.weights[0].final_weight.is_finite());
    }

    #[test]
    fn test_sybil_cluster_without_attestations_stays_rejected() {
        let mut engine = ParticipationWeightEngine::default();
        let participants = [
            participant("sybil-a", Vec::new(), None, None, Some("shared-hint")),
            participant("sybil-b", Vec::new(), None, None, Some("shared-hint")),
            participant("sybil-c", Vec::new(), None, None, Some("shared-hint")),
        ];

        let record = engine.compute_weights(&participants, "untrusted-sybil-batch", TS);

        assert_eq!(record.sybil_clusters_detected, 1);
        assert_eq!(record.participants_rejected, participants.len());
        assert!(record.weights.iter().all(|weight| weight.rejected));
        assert!(record.weights.iter().all(|weight| weight.final_weight <= f64::EPSILON));
    }

    #[test]
    fn test_reciprocity_no_contribution_no_consumption_blocks_after_grace() {
        let mut engine = ReciprocityEngine::default();
        let no_activity = metrics("no-activity", 0, 0, 1.0, 86400 * 30);

        let decision = engine.evaluate_access(&no_activity, TS);

        assert!(!decision.granted);
        assert!(matches!(decision.tier, AccessTier::Blocked));
        assert!(!decision.grace_period_active);
        assert!(decision.accessible_feeds.is_empty());
    }

    #[test]
    fn test_reciprocity_nan_quality_denies_despite_raw_contribution() {
        let mut engine = ReciprocityEngine::default();
        let suspicious = metrics("nan-quality", 100, 100, f64::NAN, 86400 * 30);

        let decision = engine.evaluate_access(&suspicious, TS);

        assert!(decision.contribution_ratio.is_finite());
        assert!(decision.quality_adjusted_ratio <= f64::EPSILON);
        assert!(!decision.granted);
        assert!(matches!(decision.tier, AccessTier::Blocked));
    }

    #[test]
    fn test_reciprocity_negative_quality_denies_despite_raw_contribution() {
        let mut engine = ReciprocityEngine::default();
        let suspicious = metrics("negative-quality", 100, 100, -0.75, 86400 * 30);

        let decision = engine.evaluate_access(&suspicious, TS);

        assert!(decision.quality_adjusted_ratio <= f64::EPSILON);
        assert!(!decision.granted);
        assert!(matches!(decision.tier, AccessTier::Blocked));
    }

    #[test]
    fn test_reciprocity_infinite_quality_denies_without_non_finite_output() {
        let mut engine = ReciprocityEngine::default();
        let suspicious = metrics("infinite-quality", 100, 100, f64::INFINITY, 86400 * 30);

        let decision = engine.evaluate_access(&suspicious, TS);

        assert!(decision.contribution_ratio.is_finite());
        assert!(decision.quality_adjusted_ratio.is_finite());
        assert!(!decision.granted);
        assert!(matches!(decision.tier, AccessTier::Blocked));
    }

    #[test]
    fn test_blocked_grace_period_tier_denies_new_participant() {
        let mut engine = ReciprocityEngine::new(ReciprocityConfig {
            grace_period_tier: AccessTier::Blocked,
            ..ReciprocityConfig::default()
        });
        let new_participant = metrics("blocked-grace", 0, 0, 1.0, 60);

        let decision = engine.evaluate_access(&new_participant, TS);

        assert!(!decision.granted);
        assert!(decision.grace_period_active);
        assert!(matches!(decision.tier, AccessTier::Blocked));
        assert!(decision.accessible_feeds.is_empty());
    }

    #[test]
    fn test_reciprocity_batch_counts_multiple_denials_without_exceptions() {
        let mut engine = ReciprocityEngine::default();
        let participants = [
            metrics("freerider-a", 0, 100, 1.0, 86400 * 30),
            metrics("freerider-b", 1, 1000, 0.5, 86400 * 30),
        ];

        let matrix = engine.evaluate_batch(&participants, "blocked-batch", TS);

        assert_eq!(matrix.total_participants, participants.len());
        assert_eq!(matrix.freeriders_blocked, participants.len());
        assert_eq!(matrix.exceptions_active, 0);
        assert_eq!(
            matrix.tier_distribution.get("Blocked").copied().unwrap_or_default(),
            participants.len()
        );
        assert!(matrix.entries.iter().all(|entry| matches!(entry.tier, AccessTier::Blocked)));
    }
}
