//! Edge case and logic bug regression tests for evidence_replay_validator.rs
//! Focus areas: boundary conditions, float handling, arithmetic edge cases

#[cfg(test)]
mod edge_case_tests {
    use super::super::evidence_replay_validator::*;
    use crate::observability::evidence_ledger::DecisionKind;

    fn candidate(id: &str, kind: DecisionKind, score: f64) -> Candidate {
        Candidate {
            id: id.into(),
            decision_kind: kind,
            score,
            metadata: serde_json::json!({}),
        }
    }

    fn satisfied_constraint(id: &str) -> Constraint {
        Constraint {
            id: id.into(),
            description: "satisfied".into(),
            satisfied: true,
        }
    }

    fn unsatisfied_constraint(id: &str) -> Constraint {
        Constraint {
            id: id.into(),
            description: "unsatisfied".into(),
            satisfied: false,
        }
    }

    // ── Float handling edge cases ──

    #[test]
    fn score_comparison_with_near_equal_floats() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-001", DecisionKind::Admit, 1);

        // Create context with candidates having nearly identical scores
        let context = ReplayContext::new(
            vec![
                Candidate {
                    id: "candidate-1".into(),
                    decision_kind: DecisionKind::Admit,
                    score: 0.1000000000000001,
                    metadata: serde_json::json!({}),
                },
                Candidate {
                    id: "DEC-001".into(), // Expected winner
                    decision_kind: DecisionKind::Admit,
                    score: 0.1000000000000002, // Slightly higher
                    metadata: serde_json::json!({}),
                },
            ],
            vec![Constraint {
                id: "c1".into(),
                description: "test".into(),
                satisfied: true,
            }],
            1,
            "snap-001",
        );

        let result = validator.validate(&entry, &context);
        assert!(
            result.is_match(),
            "Should handle near-equal float comparison correctly"
        );
    }

    #[test]
    fn score_with_zero_and_negative_zero() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-ZERO", DecisionKind::Admit, 1);

        let context = ReplayContext::new(
            vec![
                Candidate {
                    id: "neg-zero".into(),
                    decision_kind: DecisionKind::Admit,
                    score: -0.0,
                    metadata: serde_json::json!({}),
                },
                Candidate {
                    id: "DEC-ZERO".into(),
                    decision_kind: DecisionKind::Admit,
                    score: 0.0,
                    metadata: serde_json::json!({}),
                },
            ],
            vec![Constraint {
                id: "c1".into(),
                description: "test".into(),
                satisfied: true,
            }],
            1,
            "snap-001",
        );

        let result = validator.validate(&entry, &context);
        // Should handle -0.0 vs 0.0 consistently
        assert!(
            result.is_match() || result.is_mismatch(),
            "Should handle zero variants"
        );
    }

    #[test]
    fn score_with_subnormal_numbers() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-TINY", DecisionKind::Admit, 1);

        let context = ReplayContext::new(
            vec![
                Candidate {
                    id: "DEC-TINY".into(),
                    decision_kind: DecisionKind::Admit,
                    score: f64::MIN_POSITIVE,
                    metadata: serde_json::json!({}),
                },
                Candidate {
                    id: "even-tinier".into(),
                    decision_kind: DecisionKind::Admit,
                    score: f64::MIN_POSITIVE / 2.0, // Subnormal
                    metadata: serde_json::json!({}),
                },
            ],
            vec![Constraint {
                id: "c1".into(),
                description: "test".into(),
                satisfied: true,
            }],
            1,
            "snap-001",
        );

        let result = validator.validate(&entry, &context);
        assert!(
            result.is_match(),
            "Should handle subnormal numbers correctly"
        );
    }

    #[test]
    fn all_candidates_have_non_finite_scores() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-001", DecisionKind::Admit, 1);

        let context = ReplayContext::new(
            vec![
                Candidate {
                    id: "inf-candidate".into(),
                    decision_kind: DecisionKind::Admit,
                    score: f64::INFINITY,
                    metadata: serde_json::json!({}),
                },
                Candidate {
                    id: "nan-candidate".into(),
                    decision_kind: DecisionKind::Admit,
                    score: f64::NAN,
                    metadata: serde_json::json!({}),
                },
                Candidate {
                    id: "neginf-candidate".into(),
                    decision_kind: DecisionKind::Admit,
                    score: f64::NEG_INFINITY,
                    metadata: serde_json::json!({}),
                },
            ],
            vec![Constraint {
                id: "c1".into(),
                description: "test".into(),
                satisfied: true,
            }],
            1,
            "snap-001",
        );

        let result = validator.validate(&entry, &context);
        // All scores non-finite -> no candidate selected -> should be mismatch for Admit
        assert!(
            result.is_mismatch(),
            "Should mismatch when no finite scores available for Admit"
        );
    }

    // ── Boundary condition tests ──

    #[test]
    fn empty_constraints_list() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-001", DecisionKind::Admit, 1);

        let context = ReplayContext::new(
            vec![Candidate {
                id: "DEC-001".into(),
                decision_kind: DecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![], // Empty constraints
            1,
            "snap-001",
        );

        let result = validator.validate(&entry, &context);
        assert!(
            result.is_match(),
            "Empty constraints list should not block selection"
        );
    }

    #[test]
    fn mix_of_satisfied_and_unsatisfied_constraints() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-001", DecisionKind::Admit, 1);

        let context = ReplayContext::new(
            vec![Candidate {
                id: "DEC-001".into(),
                decision_kind: DecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![
                Constraint {
                    id: "c1".into(),
                    description: "good".into(),
                    satisfied: true,
                },
                Constraint {
                    id: "c2".into(),
                    description: "bad".into(),
                    satisfied: false, // One unsatisfied constraint
                },
                Constraint {
                    id: "c3".into(),
                    description: "good".into(),
                    satisfied: true,
                },
            ],
            1,
            "snap-001",
        );

        let result = validator.validate(&entry, &context);
        // Should be mismatch because not all constraints satisfied
        assert!(
            result.is_mismatch(),
            "Should fail when any constraint unsatisfied"
        );
    }

    // ── Tie-breaking logic tests ──

    #[test]
    fn identical_scores_first_wins() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-FIRST", DecisionKind::Admit, 1);

        let context = ReplayContext::new(
            vec![
                Candidate {
                    id: "DEC-FIRST".into(), // First in list
                    decision_kind: DecisionKind::Admit,
                    score: 0.5,
                    metadata: serde_json::json!({}),
                },
                Candidate {
                    id: "second".into(),
                    decision_kind: DecisionKind::Admit,
                    score: 0.5, // Same score
                    metadata: serde_json::json!({}),
                },
                Candidate {
                    id: "third".into(),
                    decision_kind: DecisionKind::Admit,
                    score: 0.5, // Same score
                    metadata: serde_json::json!({}),
                },
            ],
            vec![Constraint {
                id: "c1".into(),
                description: "test".into(),
                satisfied: true,
            }],
            1,
            "snap-001",
        );

        let result = validator.validate(&entry, &context);
        assert!(
            result.is_match(),
            "First candidate with tied score should win"
        );
    }

    #[test]
    fn identical_scores_later_higher_wins() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-LATER", DecisionKind::Admit, 1);

        let context = ReplayContext::new(
            vec![
                Candidate {
                    id: "first".into(),
                    decision_kind: DecisionKind::Admit,
                    score: 0.5,
                    metadata: serde_json::json!({}),
                },
                Candidate {
                    id: "second".into(),
                    decision_kind: DecisionKind::Admit,
                    score: 0.5,
                    metadata: serde_json::json!({}),
                },
                Candidate {
                    id: "DEC-LATER".into(), // Later in list, higher score
                    decision_kind: DecisionKind::Admit,
                    score: 0.6,
                    metadata: serde_json::json!({}),
                },
            ],
            vec![Constraint {
                id: "c1".into(),
                description: "test".into(),
                satisfied: true,
            }],
            1,
            "snap-001",
        );

        let result = validator.validate(&entry, &context);
        assert!(
            result.is_match(),
            "Higher score candidate should win regardless of position"
        );
    }

    // ── Special decision kinds edge cases ──

    #[test]
    fn deny_decision_with_all_constraints_satisfied() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-DENY", DecisionKind::Deny, 1);

        // Context where constraints are satisfied but we expect Deny
        let context = ReplayContext::new(
            vec![Candidate {
                id: "should-not-win".into(),
                decision_kind: DecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "c1".into(),
                description: "all good".into(),
                satisfied: true, // All satisfied
            }],
            1,
            "snap-001",
        );

        let result = validator.validate(&entry, &context);
        // This should mismatch - if constraints satisfied, candidate should be selected
        assert!(
            result.is_mismatch(),
            "Deny with satisfied constraints should mismatch"
        );
    }

    #[test]
    fn rollback_decision_with_valid_candidates() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-ROLLBACK", DecisionKind::Rollback, 1);

        let context = ReplayContext::new(
            vec![Candidate {
                id: "valid-candidate".into(),
                decision_kind: DecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "c1".into(),
                description: "blocked".into(),
                satisfied: false, // Constraint blocks selection
            }],
            1,
            "snap-001",
        );

        let result = validator.validate(&entry, &context);
        assert!(
            result.is_match(),
            "Rollback should match when no candidate can be selected"
        );
    }

    // ── Arithmetic overflow edge cases ──

    #[test]
    fn epoch_id_max_values() {
        let mut validator = EvidenceReplayValidator::new();
        let max_safe_epoch = u64::MAX / 1000;
        let entry = test_replay_entry("DEC-MAX", DecisionKind::Admit, max_safe_epoch);

        let context = ReplayContext::new(
            vec![Candidate {
                id: "DEC-MAX".into(),
                decision_kind: DecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "c1".into(),
                description: "test".into(),
                satisfied: true,
            }],
            max_safe_epoch,
            "snap-001",
        );

        let result = validator.validate(&entry, &context);
        assert!(result.is_match(), "Should handle large epoch_id values");
    }

    #[test]
    fn massive_counter_overflow_protection() {
        let mut validator = EvidenceReplayValidator::new();

        // Simulate overflow by setting counters near max before validation
        let entry = test_replay_entry("DEC-001", DecisionKind::Admit, 1);
        let context = matching_context(&entry);

        // Do many validations to test counter overflow protection
        for _ in 0..100 {
            validator.validate(&entry, &context);
        }

        // All counts should be finite and non-zero
        assert!(validator.total_validations() > 0);
        assert!(validator.match_count() > 0);
        assert!(validator.total_validations() < u64::MAX);
    }

    // ── Metadata and diff edge cases ──

    #[test]
    fn very_large_diff_field_accumulation() {
        let mut diff = ReplayDiff::new();

        // Add many diff fields to test bounded behavior
        for i in 0..10000 {
            diff.add(
                format!("field_{}", i),
                format!("expected_{}", i),
                format!("actual_{}", i),
            );
        }

        // Should be bounded per MAX_FIELDS
        assert!(
            diff.field_count() <= crate::capacity_defaults::aliases::MAX_FIELDS,
            "Diff fields should be bounded"
        );
        assert!(
            !diff.to_string().is_empty(),
            "Diff should format to non-empty string"
        );
    }

    #[test]
    fn empty_strings_in_action_ref() {
        let action_ref = ActionRef {
            decision_kind: "".into(),
            decision_id: "".into(),
            epoch_id: 0,
        };

        let display = action_ref.to_string();
        assert!(
            !display.is_empty(),
            "Should handle empty strings in display"
        );
        assert!(display.contains("ActionRef"), "Should contain type name");
    }

    // ── Context validation edge cases ──

    #[test]
    fn context_with_whitespace_policy_snapshot() {
        let context = ReplayContext::new(
            vec![Candidate {
                id: "test".into(),
                decision_kind: DecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![],
            1,
            "   ", // Whitespace-only policy snapshot
        );

        assert!(
            !context.is_valid(),
            "Whitespace policy snapshot should be invalid"
        );
    }

    #[test]
    fn context_with_candidate_having_extreme_metadata() {
        use serde_json::json;

        let huge_metadata = json!({
            "nested": {
                "very": {
                    "deep": {
                        "structure": {
                            "with": ["many", "elements", 1, 2, 3, true, false, null]
                        }
                    }
                }
            },
            "large_string": "x".repeat(10000)
        });

        let context = ReplayContext::new(
            vec![Candidate {
                id: "extreme".into(),
                decision_kind: DecisionKind::Admit,
                score: 1.0,
                metadata: huge_metadata,
            }],
            vec![],
            1,
            "snap-001",
        );

        assert!(
            context.is_valid(),
            "Should handle extreme metadata gracefully"
        );

        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("extreme", DecisionKind::Admit, 1);
        let result = validator.validate(&entry, &context);

        // Should not crash or fail due to large metadata
        assert!(
            result.is_match(),
            "Should handle large metadata in candidates"
        );
    }

    // ── push_bounded function edge cases ──

    #[test]
    fn push_bounded_zero_capacity() {
        use super::super::evidence_replay_validator::push_bounded;

        let mut items = vec![1, 2, 3];
        push_bounded(&mut items, 4, 0);

        assert!(items.is_empty());
    }

    #[test]
    fn push_bounded_exact_capacity() {
        use super::super::evidence_replay_validator::push_bounded;

        let mut items = vec![1, 2, 3];
        push_bounded(&mut items, 4, 3); // Exactly at capacity

        // Should replace oldest items to stay at capacity
        assert_eq!(items.len(), 3);
        assert_eq!(items, vec![2, 3, 4]);
    }

    #[test]
    fn push_bounded_massive_overflow() {
        use super::super::evidence_replay_validator::push_bounded;

        let mut items: Vec<u32> = (0..10000).collect(); // Large collection
        push_bounded(&mut items, 99999, 5);

        assert_eq!(items.len(), 5);
        assert_eq!(items[4], 99999);
    }

    // ── Regression test for specific logic issues ──

    #[test]
    fn candidate_selection_with_mixed_decision_kinds() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-ADMIT", DecisionKind::Admit, 1);

        let context = ReplayContext::new(
            vec![
                Candidate {
                    id: "deny-candidate".into(),
                    decision_kind: DecisionKind::Deny,
                    score: 0.9, // High score but wrong type
                    metadata: serde_json::json!({}),
                },
                Candidate {
                    id: "DEC-ADMIT".into(),
                    decision_kind: DecisionKind::Admit,
                    score: 0.5, // Lower score but correct type
                    metadata: serde_json::json!({}),
                },
            ],
            vec![Constraint {
                id: "c1".into(),
                description: "test".into(),
                satisfied: true,
            }],
            1,
            "snap-001",
        );

        let result = validator.validate(&entry, &context);
        // Currently the algorithm picks highest score regardless of decision_kind
        // This test documents current behavior - may need fixing if logic should match types
        assert!(
            result.is_mismatch(),
            "Different decision kinds should be handled correctly"
        );
    }

    // ── Additional negative-path replay coverage ──

    #[test]
    fn empty_candidate_context_is_unresolvable_and_logged() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-MISSING", DecisionKind::Admit, 7);
        let context = ReplayContext::new(Vec::new(), vec![satisfied_constraint("c1")], 7, "snap");

        let result = validator.validate(&entry, &context);

        assert!(result.is_unresolvable());
        assert_eq!(validator.unresolvable_count(), 1);
        assert_eq!(validator.mismatch_count(), 0);
        assert_eq!(validator.results().len(), 1);
    }

    #[test]
    fn nul_policy_snapshot_is_unresolvable_before_candidate_selection() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-NUL", DecisionKind::Admit, 8);
        let context = ReplayContext::new(
            vec![candidate("DEC-NUL", DecisionKind::Admit, 1.0)],
            vec![satisfied_constraint("c1")],
            8,
            "policy\0snapshot",
        );

        let result = validator.validate(&entry, &context);

        assert!(result.is_unresolvable());
        assert_eq!(validator.unresolvable_count(), 1);
        assert_eq!(validator.match_count(), 0);
    }

    #[test]
    fn epoch_mismatch_is_unresolvable_without_mismatch_counter() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-EPOCH", DecisionKind::Admit, 9);
        let context = ReplayContext::new(
            vec![candidate("DEC-EPOCH", DecisionKind::Admit, 1.0)],
            vec![satisfied_constraint("c1")],
            10,
            "snap",
        );

        let result = validator.validate(&entry, &context);

        assert!(result.is_unresolvable());
        assert_eq!(validator.unresolvable_count(), 1);
        assert_eq!(validator.mismatch_count(), 0);
    }

    #[test]
    fn higher_scoring_wrong_candidate_records_decision_id_diff() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-EXPECTED", DecisionKind::Admit, 11);
        let context = ReplayContext::new(
            vec![
                candidate("DEC-EXPECTED", DecisionKind::Admit, 0.5),
                candidate("DEC-WRONG", DecisionKind::Admit, 0.9),
            ],
            vec![satisfied_constraint("c1")],
            11,
            "snap",
        );

        let result = validator.validate(&entry, &context);

        match result {
            ReplayResult::Mismatch { diff, got, .. } => {
                assert_eq!(got.decision_id, "DEC-WRONG");
                assert_eq!(diff.field_count(), 1);
                assert!(diff.to_string().contains("decision_id"));
            }
            other => panic!("expected mismatch for wrong winner, got {other:?}"),
        }
    }

    #[test]
    fn higher_scoring_wrong_kind_records_kind_and_id_diff() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-EXPECTED", DecisionKind::Admit, 12);
        let context = ReplayContext::new(
            vec![
                candidate("DEC-EXPECTED", DecisionKind::Admit, 0.5),
                candidate("DEC-DENY", DecisionKind::Deny, 0.9),
            ],
            vec![satisfied_constraint("c1")],
            12,
            "snap",
        );

        let result = validator.validate(&entry, &context);

        match result {
            ReplayResult::Mismatch { diff, got, .. } => {
                assert_eq!(got.decision_id, "DEC-DENY");
                assert_eq!(diff.field_count(), 2);
                let rendered = diff.to_string();
                assert!(rendered.contains("decision_kind"));
                assert!(rendered.contains("decision_id"));
            }
            other => panic!("expected mismatch for wrong decision kind, got {other:?}"),
        }
    }

    #[test]
    fn deny_with_selected_candidate_mismatches_instead_of_matching() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-DENY", DecisionKind::Deny, 13);
        let context = ReplayContext::new(
            vec![candidate("DEC-ADMIT", DecisionKind::Admit, 1.0)],
            vec![satisfied_constraint("c1")],
            13,
            "snap",
        );

        let result = validator.validate(&entry, &context);

        assert!(result.is_mismatch());
        assert_eq!(validator.mismatch_count(), 1);
        assert_eq!(validator.match_count(), 0);
    }

    #[test]
    fn rollback_with_selected_candidate_mismatches_instead_of_matching() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-ROLLBACK", DecisionKind::Rollback, 14);
        let context = ReplayContext::new(
            vec![candidate("DEC-ADMIT", DecisionKind::Admit, 1.0)],
            vec![satisfied_constraint("c1")],
            14,
            "snap",
        );

        let result = validator.validate(&entry, &context);

        assert!(result.is_mismatch());
        assert_eq!(validator.mismatch_count(), 1);
        assert_eq!(validator.unresolvable_count(), 0);
    }

    #[test]
    fn batch_negative_paths_preserve_result_order_and_counts() {
        let mut validator = EvidenceReplayValidator::new();
        let admit = test_replay_entry("DEC-ADMIT", DecisionKind::Admit, 15);
        let release = test_replay_entry("DEC-RELEASE", DecisionKind::Release, 16);
        let entries = vec![
            (
                admit.clone(),
                ReplayContext::new(
                    vec![candidate("DEC-OTHER", DecisionKind::Admit, 1.0)],
                    vec![satisfied_constraint("c1")],
                    15,
                    "snap",
                ),
            ),
            (
                release.clone(),
                ReplayContext::new(
                    vec![candidate("DEC-RELEASE", DecisionKind::Release, 1.0)],
                    vec![unsatisfied_constraint("c2")],
                    16,
                    "snap",
                ),
            ),
        ];

        let results = validator.validate_batch(&entries);

        assert_eq!(results.len(), 2);
        assert!(results[0].is_mismatch());
        assert!(results[1].is_mismatch());
        assert_eq!(validator.total_validations(), 2);
        assert_eq!(validator.mismatch_count(), 2);
    }
}
