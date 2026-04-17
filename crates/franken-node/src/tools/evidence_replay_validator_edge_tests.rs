//! Edge case tests for evidence_replay_validator.rs
//!
//! Tests focus on:
//! - Floating point precision issues in score comparison
//! - Input validation edge cases
//! - Resource exhaustion scenarios
//! - Error handling boundaries
//! - Determinism under extreme conditions

use crate::capacity_defaults::aliases::{MAX_FIELDS, MAX_RESULTS};
use crate::observability::evidence_ledger::{DecisionKind, EvidenceEntry};
use crate::tools::evidence_replay_validator::*;

/// Test floating point edge cases in score comparison
#[cfg(test)]
mod floating_point_edge_tests {
    use super::*;

    #[test]
    fn test_nan_scores_handling() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-NAN", DecisionKind::Admit, 1);

        // Context with NaN scores
        let context = ReplayContext::new(
            vec![
                Candidate {
                    id: "normal".to_string(),
                    decision_kind: DecisionKind::Admit,
                    score: 1.0,
                    metadata: serde_json::json!({}),
                },
                Candidate {
                    id: "nan".to_string(),
                    decision_kind: DecisionKind::Admit,
                    score: f64::NAN,
                    metadata: serde_json::json!({}),
                },
                Candidate {
                    id: "infinity".to_string(),
                    decision_kind: DecisionKind::Admit,
                    score: f64::INFINITY,
                    metadata: serde_json::json!({}),
                },
                Candidate {
                    id: "neg_infinity".to_string(),
                    decision_kind: DecisionKind::Admit,
                    score: f64::NEG_INFINITY,
                    metadata: serde_json::json!({}),
                },
            ],
            vec![Constraint {
                id: "always_true".to_string(),
                description: "always satisfied".to_string(),
                satisfied: true,
            }],
            1,
            "policy-snapshot",
        );

        // Should handle NaN/infinity gracefully without panicking
        let result = validator.validate(&entry, &context);

        // NaN comparisons are always false, so it should pick the first valid score
        // or handle this edge case appropriately
        match result {
            ReplayResult::Match
            | ReplayResult::Mismatch { .. }
            | ReplayResult::Unresolvable { .. } => {
                // Any of these outcomes is acceptable as long as it doesn't panic
            }
        }
    }

    #[test]
    fn test_very_close_scores() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-001", DecisionKind::Admit, 1);

        // Very close floating point scores that might have precision issues
        let candidates = vec![
            Candidate {
                id: "first".to_string(),
                decision_kind: DecisionKind::Admit,
                score: 0.1 + 0.2, // Classic floating point precision issue
                metadata: serde_json::json!({}),
            },
            Candidate {
                id: "second".to_string(),
                decision_kind: DecisionKind::Admit,
                score: 0.3, // Should be equal to 0.1 + 0.2 but might not be due to FP precision
                metadata: serde_json::json!({}),
            },
            Candidate {
                id: "third".to_string(),
                decision_kind: DecisionKind::Admit,
                score: 0.30000000000000004, // Slightly different due to precision
                metadata: serde_json::json!({}),
            },
        ];

        let context = ReplayContext::new(
            candidates,
            vec![Constraint {
                id: "always_true".to_string(),
                description: "always satisfied".to_string(),
                satisfied: true,
            }],
            1,
            "policy-snapshot",
        );

        // Should be deterministic despite floating point precision issues
        let result1 = validator.validate(&entry, &context);
        let mut validator2 = EvidenceReplayValidator::new();
        let result2 = validator2.validate(&entry, &context);

        // Results should be identical (deterministic)
        assert_eq!(result1, result2);
    }

    #[test]
    fn test_extreme_score_values() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-EXTREME", DecisionKind::Admit, 1);

        let candidates = vec![
            Candidate {
                id: "min".to_string(),
                decision_kind: DecisionKind::Admit,
                score: f64::MIN,
                metadata: serde_json::json!({}),
            },
            Candidate {
                id: "max".to_string(),
                decision_kind: DecisionKind::Admit,
                score: f64::MAX,
                metadata: serde_json::json!({}),
            },
            Candidate {
                id: "zero".to_string(),
                decision_kind: DecisionKind::Admit,
                score: 0.0,
                metadata: serde_json::json!({}),
            },
            Candidate {
                id: "neg_zero".to_string(),
                decision_kind: DecisionKind::Admit,
                score: -0.0,
                metadata: serde_json::json!({}),
            },
            Candidate {
                id: "epsilon".to_string(),
                decision_kind: DecisionKind::Admit,
                score: f64::EPSILON,
                metadata: serde_json::json!({}),
            },
        ];

        let context = ReplayContext::new(
            candidates,
            vec![Constraint {
                id: "always_true".to_string(),
                description: "always satisfied".to_string(),
                satisfied: true,
            }],
            1,
            "policy-snapshot",
        );

        // Should handle extreme values without issues
        let result = validator.validate(&entry, &context);
        assert!(matches!(
            result,
            ReplayResult::Match | ReplayResult::Mismatch { .. }
        ));
    }
}

/// Test input validation edge cases
#[cfg(test)]
mod input_validation_edge_tests {
    use super::*;

    #[test]
    fn test_empty_string_identifiers() {
        let mut validator = EvidenceReplayValidator::new();

        // Entry with empty decision_id
        let entry = EvidenceEntry {
            schema_version: "1.0".to_string(),
            entry_id: None,
            decision_id: "".to_string(), // Empty decision_id
            decision_kind: DecisionKind::Admit,
            decision_time: "2026-02-20T12:00:00Z".to_string(),
            timestamp_ms: 1000,
            trace_id: "trace".to_string(),
            epoch_id: 1,
            payload: serde_json::json!({}),
            size_bytes: 0,
        };

        // Context with empty candidate IDs
        let context = ReplayContext::new(
            vec![
                Candidate {
                    id: "".to_string(), // Empty candidate ID
                    decision_kind: DecisionKind::Admit,
                    score: 1.0,
                    metadata: serde_json::json!({}),
                },
                Candidate {
                    id: " ".to_string(), // Whitespace-only ID
                    decision_kind: DecisionKind::Admit,
                    score: 0.5,
                    metadata: serde_json::json!({}),
                },
            ],
            vec![Constraint {
                id: "".to_string(),          // Empty constraint ID
                description: "".to_string(), // Empty description
                satisfied: true,
            }],
            1,
            "", // Empty policy snapshot ID - should make context invalid
        );

        let result = validator.validate(&entry, &context);
        // Should be unresolvable due to empty policy snapshot ID
        assert!(result.is_unresolvable());
    }

    #[test]
    fn test_very_long_identifiers() {
        let mut validator = EvidenceReplayValidator::new();

        let long_id = "x".repeat(100_000); // 100KB identifier
        let long_description = "desc".repeat(50_000); // 200KB description

        let entry = EvidenceEntry {
            schema_version: "1.0".to_string(),
            entry_id: None,
            decision_id: long_id.clone(),
            decision_kind: DecisionKind::Admit,
            decision_time: "2026-02-20T12:00:00Z".to_string(),
            timestamp_ms: 1000,
            trace_id: "trace".repeat(10_000), // Long trace ID
            epoch_id: 1,
            payload: serde_json::json!({}),
            size_bytes: 0,
        };

        let context = ReplayContext::new(
            vec![Candidate {
                id: long_id.clone(),
                decision_kind: DecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "constraint".repeat(1000),
                description: long_description,
                satisfied: true,
            }],
            1,
            "policy".repeat(5000), // Long policy snapshot ID
        );

        // Should handle very long strings without issues
        let result = validator.validate(&entry, &context);
        assert!(result.is_match());
    }

    #[test]
    fn test_unicode_identifiers() {
        let mut validator = EvidenceReplayValidator::new();

        let unicode_id = "🔥决策🚀αβγ中文العربية";

        let entry = EvidenceEntry {
            schema_version: "1.0".to_string(),
            entry_id: None,
            decision_id: unicode_id.to_string(),
            decision_kind: DecisionKind::Admit,
            decision_time: "2026-02-20T12:00:00Z".to_string(),
            timestamp_ms: 1000,
            trace_id: "trace-🌟".to_string(),
            epoch_id: 1,
            payload: serde_json::json!({}),
            size_bytes: 0,
        };

        let context = ReplayContext::new(
            vec![Candidate {
                id: unicode_id.to_string(),
                decision_kind: DecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "约束-🎯".to_string(),
                description: "قيد الأمان".to_string(),
                satisfied: true,
            }],
            1,
            "策略快照-v1.0",
        );

        // Should handle Unicode identifiers correctly
        let result = validator.validate(&entry, &context);
        assert!(result.is_match());
    }

    #[test]
    fn test_special_character_identifiers() {
        let mut validator = EvidenceReplayValidator::new();

        let special_chars = "\0\n\r\t\"'\\<>{}[]()&|;$`!@#%^*+=~";

        let entry = EvidenceEntry {
            schema_version: "1.0".to_string(),
            entry_id: None,
            decision_id: special_chars.to_string(),
            decision_kind: DecisionKind::Admit,
            decision_time: "2026-02-20T12:00:00Z".to_string(),
            timestamp_ms: 1000,
            trace_id: "trace".to_string(),
            epoch_id: 1,
            payload: serde_json::json!({}),
            size_bytes: 0,
        };

        let context = ReplayContext::new(
            vec![Candidate {
                id: special_chars.to_string(),
                decision_kind: DecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "constraint-1".to_string(),
                description: "test".to_string(),
                satisfied: true,
            }],
            1,
            "policy-snapshot",
        );

        // Should handle special characters without issues
        let result = validator.validate(&entry, &context);
        assert!(result.is_match());
    }
}

/// Test negative replay outcomes and failure accounting
#[cfg(test)]
mod negative_replay_path_tests {
    use super::*;

    #[test]
    fn empty_candidates_make_context_unresolvable() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-NO-CANDIDATES", DecisionKind::Admit, 1);
        let context = ReplayContext::new(
            Vec::new(),
            vec![Constraint {
                id: "default".to_string(),
                description: "candidate set must be present".to_string(),
                satisfied: true,
            }],
            1,
            "policy-snapshot",
        );

        let result = validator.validate(&entry, &context);

        assert!(result.is_unresolvable());
        assert_eq!(validator.unresolvable_count(), 1);
        assert_eq!(validator.mismatch_count(), 0);
    }

    #[test]
    fn empty_policy_snapshot_make_context_unresolvable() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-NO-POLICY", DecisionKind::Admit, 1);
        let context = ReplayContext::new(
            vec![Candidate {
                id: "DEC-NO-POLICY".to_string(),
                decision_kind: DecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "default".to_string(),
                description: "policy snapshot must be present".to_string(),
                satisfied: true,
            }],
            1,
            "",
        );

        let result = validator.validate(&entry, &context);

        assert!(result.is_unresolvable());
        assert_eq!(validator.results()[0].0, "DEC-NO-POLICY");
    }

    #[test]
    fn all_non_finite_scores_for_admit_mismatch_with_no_candidate() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-NON-FINITE", DecisionKind::Admit, 1);
        let context = ReplayContext::new(
            vec![
                Candidate {
                    id: "nan".to_string(),
                    decision_kind: DecisionKind::Admit,
                    score: f64::NAN,
                    metadata: serde_json::json!({}),
                },
                Candidate {
                    id: "infinite".to_string(),
                    decision_kind: DecisionKind::Admit,
                    score: f64::INFINITY,
                    metadata: serde_json::json!({}),
                },
            ],
            vec![Constraint {
                id: "default".to_string(),
                description: "scores must be finite".to_string(),
                satisfied: true,
            }],
            1,
            "policy-snapshot",
        );

        let result = validator.validate(&entry, &context);

        if let ReplayResult::Mismatch { got, diff, .. } = result {
            assert_eq!(got.decision_kind, "none");
            assert_eq!(diff.field_count(), 1);
            assert!(
                diff.fields
                    .iter()
                    .any(|field| field.field_name == "selected_candidate")
            );
        } else {
            panic!("expected mismatch when no finite candidate can be selected");
        }
    }

    #[test]
    fn unsatisfied_constraints_for_admit_mismatch_with_no_candidate() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-CONSTRAINT-FAIL", DecisionKind::Admit, 1);
        let context = ReplayContext::new(
            vec![Candidate {
                id: "DEC-CONSTRAINT-FAIL".to_string(),
                decision_kind: DecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "deny-all".to_string(),
                description: "constraint intentionally fails".to_string(),
                satisfied: false,
            }],
            1,
            "policy-snapshot",
        );

        let result = validator.validate(&entry, &context);

        assert!(result.is_mismatch());
        assert_eq!(validator.mismatch_count(), 1);
        assert_eq!(validator.match_count(), 0);
    }

    #[test]
    fn epoch_mismatch_is_unresolvable_not_mismatch() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-EPOCH-MISMATCH", DecisionKind::Admit, 7);
        let context = ReplayContext::new(
            vec![Candidate {
                id: "DEC-EPOCH-MISMATCH".to_string(),
                decision_kind: DecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "default".to_string(),
                description: "epoch must match".to_string(),
                satisfied: true,
            }],
            8,
            "policy-snapshot",
        );

        let result = validator.validate(&entry, &context);

        assert!(result.is_unresolvable());
        assert_eq!(validator.unresolvable_count(), 1);
        assert_eq!(validator.mismatch_count(), 0);
    }

    #[test]
    fn decision_kind_mismatch_reports_decision_kind_diff() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-KIND-MISMATCH", DecisionKind::Admit, 1);
        let context = ReplayContext::new(
            vec![Candidate {
                id: "DEC-KIND-MISMATCH".to_string(),
                decision_kind: DecisionKind::Deny,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "default".to_string(),
                description: "kind mismatch".to_string(),
                satisfied: true,
            }],
            1,
            "policy-snapshot",
        );

        let result = validator.validate(&entry, &context);

        if let ReplayResult::Mismatch { diff, .. } = result {
            assert_eq!(diff.field_count(), 1);
            assert!(
                diff.fields
                    .iter()
                    .any(|field| field.field_name == "decision_kind")
            );
        } else {
            panic!("expected decision kind mismatch");
        }
    }

    #[test]
    fn candidate_id_mismatch_reports_decision_id_diff() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-ID-EXPECTED", DecisionKind::Admit, 1);
        let context = ReplayContext::new(
            vec![Candidate {
                id: "DEC-ID-ACTUAL".to_string(),
                decision_kind: DecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "default".to_string(),
                description: "id mismatch".to_string(),
                satisfied: true,
            }],
            1,
            "policy-snapshot",
        );

        let result = validator.validate(&entry, &context);

        if let ReplayResult::Mismatch { diff, .. } = result {
            assert_eq!(diff.field_count(), 1);
            assert!(
                diff.fields
                    .iter()
                    .any(|field| field.field_name == "decision_id")
            );
        } else {
            panic!("expected decision id mismatch");
        }
    }
}

/// Test resource exhaustion scenarios
#[cfg(test)]
mod resource_exhaustion_tests {
    use super::*;

    #[test]
    fn test_maximum_candidates_handling() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-MANY-CANDIDATES", DecisionKind::Admit, 1);

        // Create many candidates to test performance and memory usage
        let mut candidates = Vec::new();
        for i in 0..10_000 {
            candidates.push(Candidate {
                id: format!("candidate_{:05}", i),
                decision_kind: DecisionKind::Admit,
                score: (i as f64) / 10_000.0, // Ascending scores
                metadata: serde_json::json!({"index": i}),
            });
        }

        let context = ReplayContext::new(
            candidates,
            vec![Constraint {
                id: "always_true".to_string(),
                description: "always satisfied".to_string(),
                satisfied: true,
            }],
            1,
            "policy-snapshot",
        );

        // Should handle large number of candidates efficiently
        let result = validator.validate(&entry, &context);

        // Should select the highest scoring candidate
        if let ReplayResult::Mismatch { got, .. } = &result {
            assert!(got.decision_id.contains("09999")); // Should be the last (highest scoring) candidate
        }
    }

    #[test]
    fn test_maximum_constraints_handling() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-MANY-CONSTRAINTS", DecisionKind::Admit, 1);

        // Create many constraints
        let mut constraints = Vec::new();
        for i in 0..10_000 {
            constraints.push(Constraint {
                id: format!("constraint_{:05}", i),
                description: format!("Constraint {} description", i),
                satisfied: true, // All satisfied
            });
        }

        let context = ReplayContext::new(
            vec![Candidate {
                id: "DEC-MANY-CONSTRAINTS".to_string(),
                decision_kind: DecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            constraints,
            1,
            "policy-snapshot",
        );

        // Should handle large number of constraints
        let result = validator.validate(&entry, &context);
        assert!(result.is_match());
    }

    #[test]
    fn test_mixed_constraint_satisfaction() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-MIXED-CONSTRAINTS", DecisionKind::Deny, 1);

        // Mix of satisfied and unsatisfied constraints
        let mut constraints = Vec::new();
        for i in 0..1000 {
            constraints.push(Constraint {
                id: format!("constraint_{:04}", i),
                description: format!("Constraint {}", i),
                satisfied: i % 2 == 0, // Half satisfied, half not
            });
        }

        let context = ReplayContext::new(
            vec![Candidate {
                id: "some-candidate".to_string(),
                decision_kind: DecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            constraints,
            1,
            "policy-snapshot",
        );

        // Should correctly handle mixed constraint satisfaction
        // Since some constraints are unsatisfied, no candidate should be selected
        let result = validator.validate(&entry, &context);
        assert!(result.is_match()); // Deny/Rollback are expected to have no winner
    }

    #[test]
    fn test_results_accumulation_bounds() {
        let mut validator = EvidenceReplayValidator::new();

        // Validate more entries than MAX_RESULTS to test bounded accumulation
        for i in 0..(MAX_RESULTS + 100) {
            let entry = test_replay_entry(&format!("DEC-{:05}", i), DecisionKind::Admit, 1);
            let context = matching_context(&entry);
            validator.validate(&entry, &context);
        }

        // Results should be bounded to MAX_RESULTS
        assert!(
            validator.results().len() <= MAX_RESULTS,
            "Results should be bounded to {} but got {}",
            MAX_RESULTS,
            validator.results().len()
        );

        // Should contain the most recent results
        let last_result_id = &validator.results().last().unwrap().0;
        assert!(last_result_id.contains(&format!("{:05}", MAX_RESULTS + 99)));
    }

    #[test]
    fn test_diff_fields_bounds() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-DIFF-BOUNDS", DecisionKind::Admit, 1);

        let context = ReplayContext::new(
            vec![Candidate {
                id: "different-id".to_string(),    // Will cause mismatch
                decision_kind: DecisionKind::Deny, // Different kind - will cause another field diff
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "always_true".to_string(),
                description: "always satisfied".to_string(),
                satisfied: true,
            }],
            1,
            "policy-snapshot",
        );

        let result = validator.validate(&entry, &context);

        if let ReplayResult::Mismatch { diff, .. } = result {
            // Should have both decision_kind and decision_id differences
            assert_eq!(diff.field_count(), 2);
            assert!(diff.fields.iter().any(|f| f.field_name == "decision_kind"));
            assert!(diff.fields.iter().any(|f| f.field_name == "decision_id"));
        } else {
            panic!("Expected mismatch result");
        }
    }
}

/// Test error handling boundaries
#[cfg(test)]
mod error_handling_edge_tests {
    use super::*;

    #[test]
    fn test_epoch_overflow_scenarios() {
        let mut validator = EvidenceReplayValidator::new();

        // Test with maximum u64 values for epoch_id
        let entry = EvidenceEntry {
            schema_version: "1.0".to_string(),
            entry_id: None,
            decision_id: "DEC-EPOCH-MAX".to_string(),
            decision_kind: DecisionKind::Admit,
            decision_time: "2026-02-20T12:00:00Z".to_string(),
            timestamp_ms: u64::MAX,
            trace_id: "trace".to_string(),
            epoch_id: u64::MAX,
            payload: serde_json::json!({}),
            size_bytes: usize::MAX,
        };

        let context = ReplayContext::new(
            vec![Candidate {
                id: "DEC-EPOCH-MAX".to_string(),
                decision_kind: DecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            }],
            vec![Constraint {
                id: "always_true".to_string(),
                description: "always satisfied".to_string(),
                satisfied: true,
            }],
            u64::MAX,
            "policy-snapshot",
        );

        // Should handle maximum values without overflow
        let result = validator.validate(&entry, &context);
        assert!(result.is_match());
    }

    #[test]
    fn test_counter_overflow_protection() {
        let mut validator = EvidenceReplayValidator::new();

        // Manually set counters near u64::MAX to test overflow protection
        validator.total_validations = u64::MAX - 1;
        validator.match_count = u64::MAX - 1;
        validator.mismatch_count = u64::MAX - 1;
        validator.unresolvable_count = u64::MAX - 1;

        let entry = test_replay_entry("DEC-OVERFLOW-TEST", DecisionKind::Admit, 1);
        let context = matching_context(&entry);

        // This should increment counters using saturating arithmetic
        let result = validator.validate(&entry, &context);
        assert!(result.is_match());

        // Counters should saturate at MAX, not overflow
        assert_eq!(validator.total_validations(), u64::MAX);
        assert_eq!(validator.match_count(), u64::MAX);
    }

    #[test]
    fn test_metadata_serialization_edge_cases() {
        let mut validator = EvidenceReplayValidator::new();
        let entry = test_replay_entry("DEC-METADATA-EDGE", DecisionKind::Admit, 1);

        // Test with complex metadata that could cause serialization issues
        let complex_metadata = serde_json::json!({
            "nested": {
                "deeply": {
                    "nested": {
                        "object": {
                            "with": {
                                "many": {
                                    "levels": "value"
                                }
                            }
                        }
                    }
                }
            },
            "array": [1, 2, 3, null, true, false, "string"],
            "large_string": "x".repeat(10_000),
            "unicode": "🔥🌟🎉αβγ中文العربية",
            "special_chars": "\n\r\t\0\"'\\",
            "empty_values": {
                "null": null,
                "empty_string": "",
                "empty_array": [],
                "empty_object": {}
            }
        });

        let context = ReplayContext::new(
            vec![Candidate {
                id: "DEC-METADATA-EDGE".to_string(),
                decision_kind: DecisionKind::Admit,
                score: 1.0,
                metadata: complex_metadata,
            }],
            vec![Constraint {
                id: "always_true".to_string(),
                description: "always satisfied".to_string(),
                satisfied: true,
            }],
            1,
            "policy-snapshot",
        );

        // Should handle complex metadata without issues
        let result = validator.validate(&entry, &context);
        assert!(result.is_match());
    }
}

/// Test determinism under extreme conditions
#[cfg(test)]
mod determinism_stress_tests {
    use super::*;

    #[test]
    fn test_determinism_with_identical_scores() {
        // Test determinism when multiple candidates have identical scores
        let candidates = vec![
            Candidate {
                id: "candidate_a".to_string(),
                decision_kind: DecisionKind::Admit,
                score: 1.0,
                metadata: serde_json::json!({}),
            },
            Candidate {
                id: "candidate_b".to_string(),
                decision_kind: DecisionKind::Admit,
                score: 1.0, // Same score
                metadata: serde_json::json!({}),
            },
            Candidate {
                id: "candidate_c".to_string(),
                decision_kind: DecisionKind::Admit,
                score: 1.0, // Same score
                metadata: serde_json::json!({}),
            },
        ];

        let context = ReplayContext::new(
            candidates,
            vec![Constraint {
                id: "always_true".to_string(),
                description: "always satisfied".to_string(),
                satisfied: true,
            }],
            1,
            "policy-snapshot",
        );

        // Run multiple validations to ensure deterministic behavior
        let mut results = Vec::new();
        for i in 0..100 {
            let mut validator = EvidenceReplayValidator::new();
            let entry = test_replay_entry(&format!("DEC-{:03}", i), DecisionKind::Admit, 1);
            let result = validator.validate(&entry, &context);
            results.push(result);
        }

        // All results should be identical (deterministic selection with tied scores)
        let first_result = &results[0];
        for (i, result) in results.iter().enumerate() {
            assert_eq!(
                result, first_result,
                "Non-deterministic behavior at iteration {}",
                i
            );
        }
    }

    #[test]
    fn test_stress_validation_loop() {
        // Stress test with many validations to check for memory leaks or performance degradation
        let mut validator = EvidenceReplayValidator::new();

        for i in 0..1000 {
            let entry =
                test_replay_entry(&format!("STRESS-{:04}", i), DecisionKind::Admit, i as u64);
            let context = matching_context(&entry);

            let result = validator.validate(&entry, &context);
            assert!(result.is_match(), "Validation failed at iteration {}", i);
        }

        // All should have succeeded
        assert_eq!(validator.total_validations(), 1000);
        assert_eq!(validator.match_count(), 1000);
        assert_eq!(validator.mismatch_count(), 0);
        assert_eq!(validator.unresolvable_count(), 0);
    }
}
