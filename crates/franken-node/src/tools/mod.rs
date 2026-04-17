#[cfg(feature = "extended-surfaces")]
pub mod adversarial_resilience_metrics;
#[cfg(feature = "extended-surfaces")]
pub mod benchmark_methodology;
pub mod benchmark_suite;
#[cfg(feature = "extended-surfaces")]
pub mod compatibility_correctness_metrics;
#[cfg(feature = "extended-surfaces")]
pub mod containment_revocation_metrics;
pub mod counterfactual_replay;
#[cfg(feature = "extended-surfaces")]
pub mod enterprise_governance;
pub mod evidence_replay_validator;
#[cfg(feature = "extended-surfaces")]
pub mod external_replication_claims;
#[cfg(feature = "extended-surfaces")]
pub mod frontier_demo_gate;
#[cfg(feature = "extended-surfaces")]
pub mod migration_incident_datasets;
#[cfg(feature = "extended-surfaces")]
pub mod migration_speed_failure_metrics;
#[cfg(feature = "extended-surfaces")]
pub mod migration_validation_cohorts;
#[cfg(feature = "extended-surfaces")]
pub mod partner_lighthouse_programs;
#[cfg(feature = "extended-surfaces")]
pub mod performance_hardening_metrics;
#[cfg(feature = "extended-surfaces")]
pub mod profile_tuning_harness;
#[cfg(feature = "extended-surfaces")]
pub mod redteam_evaluations;
pub mod replay_bundle;
#[cfg(feature = "extended-surfaces")]
pub mod replay_determinism_metrics;
#[cfg(feature = "extended-surfaces")]
pub mod report_output_contract;
#[cfg(feature = "extended-surfaces")]
pub mod repro_bundle_export;
#[cfg(feature = "extended-surfaces")]
pub mod reputation_graph_apis;
#[cfg(feature = "extended-surfaces")]
pub mod safe_extension_onboarding;
#[cfg(feature = "extended-surfaces")]
pub mod security_ops_case_studies;
#[cfg(feature = "extended-surfaces")]
pub mod security_trust_metrics;
#[cfg(feature = "extended-surfaces")]
pub mod transparent_reports;
#[cfg(feature = "extended-surfaces")]
pub mod trust_economics_dashboard;
#[cfg(feature = "extended-surfaces")]
pub mod vef_perf_budget_gate;
#[cfg(feature = "extended-surfaces")]
pub mod verifier_benchmark_releases;
#[cfg(feature = "extended-surfaces")]
pub mod verifier_toolkit;
#[cfg(feature = "extended-surfaces")]
pub mod version_benchmark_standards;

#[cfg(test)]
mod benchmark_suite_conformance_tests;
#[cfg(test)]
mod evidence_replay_edge_cases;
#[cfg(test)]
mod replay_bundle_conformance_tests;
#[cfg(test)]
mod replay_bundle_logic_tests;

#[cfg(test)]
mod tools_root_negative_tests {
    use super::evidence_replay_validator::{
        Candidate, Constraint, EvidenceReplayValidator, ReplayContext, ReplayDiff, ReplayResult,
        test_replay_entry,
    };
    use crate::capacity_defaults::aliases::MAX_FIELDS;
    use crate::observability::evidence_ledger::DecisionKind;

    fn candidate(id: &str, decision_kind: DecisionKind, score: f64) -> Candidate {
        Candidate {
            id: id.to_string(),
            decision_kind,
            score,
            metadata: serde_json::json!({}),
        }
    }

    fn constraint(id: &str, satisfied: bool) -> Constraint {
        Constraint {
            id: id.to_string(),
            description: format!("constraint {id}"),
            satisfied,
        }
    }

    #[test]
    fn tools_root_replay_rejects_empty_candidate_context() {
        let entry = test_replay_entry("tools-empty-candidates", DecisionKind::Admit, 11);
        let context = ReplayContext::new(
            vec![],
            vec![constraint("must-exist", true)],
            entry.epoch_id,
            "policy-tools",
        );
        let mut validator = EvidenceReplayValidator::new();

        let result = validator.validate(&entry, &context);

        assert!(matches!(
            result,
            ReplayResult::Unresolvable { reason }
                if reason.contains("empty candidates")
        ));
        assert_eq!(validator.total_validations(), 1);
        assert_eq!(validator.unresolvable_count(), 1);
        assert_eq!(validator.results().len(), 1);
    }

    #[test]
    fn tools_root_replay_rejects_missing_policy_snapshot() {
        let entry = test_replay_entry("tools-empty-policy", DecisionKind::Release, 12);
        let context = ReplayContext::new(
            vec![candidate("tools-empty-policy", DecisionKind::Release, 1.0)],
            vec![constraint("policy-required", true)],
            entry.epoch_id,
            "",
        );
        let mut validator = EvidenceReplayValidator::new();

        let result = validator.validate(&entry, &context);

        assert!(matches!(result, ReplayResult::Unresolvable { .. }));
        assert_eq!(validator.match_count(), 0);
        assert_eq!(validator.unresolvable_count(), 1);
    }

    #[test]
    fn tools_root_replay_rejects_epoch_mismatch_before_candidate_choice() {
        let entry = test_replay_entry("tools-epoch-drift", DecisionKind::Quarantine, 13);
        let context = ReplayContext::new(
            vec![candidate(
                "tools-epoch-drift",
                DecisionKind::Quarantine,
                1.0,
            )],
            vec![constraint("epoch-required", true)],
            14,
            "policy-tools",
        );
        let mut validator = EvidenceReplayValidator::new();

        let result = validator.validate(&entry, &context);

        assert!(matches!(
            result,
            ReplayResult::Unresolvable { reason } if reason.contains("epoch mismatch")
        ));
        assert_eq!(validator.unresolvable_count(), 1);
        assert_eq!(validator.mismatch_count(), 0);
    }

    #[test]
    fn tools_root_unsatisfied_constraint_mismatches_release_decision() {
        let entry = test_replay_entry("tools-release-blocked", DecisionKind::Release, 15);
        let context = ReplayContext::new(
            vec![candidate(
                "tools-release-blocked",
                DecisionKind::Release,
                1.0,
            )],
            vec![constraint("release-blocked", false)],
            entry.epoch_id,
            "policy-tools",
        );
        let mut validator = EvidenceReplayValidator::new();

        let result = validator.validate(&entry, &context);

        assert!(matches!(
            result,
            ReplayResult::Mismatch { got, diff, .. }
                if got.decision_kind == "none" && diff.field_count() == 1
        ));
        assert_eq!(validator.mismatch_count(), 1);
    }

    #[test]
    fn tools_root_non_finite_scores_do_not_select_candidate() {
        let entry = test_replay_entry("tools-non-finite", DecisionKind::Escalate, 16);
        let context = ReplayContext::new(
            vec![
                candidate("tools-non-finite", DecisionKind::Escalate, f64::NAN),
                candidate("tools-other", DecisionKind::Escalate, f64::INFINITY),
            ],
            vec![constraint("scores-finite", true)],
            entry.epoch_id,
            "policy-tools",
        );
        let mut validator = EvidenceReplayValidator::new();

        let result = validator.validate(&entry, &context);

        assert!(matches!(
            result,
            ReplayResult::Mismatch { got, diff, .. }
                if got.decision_id == "none" && diff.to_string().contains("no candidate")
        ));
        assert_eq!(validator.match_count(), 0);
        assert_eq!(validator.mismatch_count(), 1);
    }

    #[test]
    fn tools_root_higher_scored_wrong_candidate_records_id_diff() {
        let entry = test_replay_entry("tools-expected", DecisionKind::Admit, 17);
        let context = ReplayContext::new(
            vec![
                candidate("tools-expected", DecisionKind::Admit, 0.2),
                candidate("tools-unexpected", DecisionKind::Admit, 0.9),
            ],
            vec![constraint("all-good", true)],
            entry.epoch_id,
            "policy-tools",
        );
        let mut validator = EvidenceReplayValidator::new();

        let result = validator.validate(&entry, &context);

        assert!(matches!(
            result,
            ReplayResult::Mismatch { diff, .. }
                if diff.to_string().contains("decision_id")
        ));
        assert_eq!(validator.mismatch_count(), 1);
    }

    #[test]
    fn tools_root_batch_with_invalid_entries_keeps_summary_not_all_match() {
        let missing_candidates = test_replay_entry("tools-batch-missing", DecisionKind::Admit, 18);
        let epoch_drift = test_replay_entry("tools-batch-drift", DecisionKind::Throttle, 19);
        let batch = vec![
            (
                missing_candidates.clone(),
                ReplayContext::new(vec![], vec![], 18, "policy-tools"),
            ),
            (
                epoch_drift.clone(),
                ReplayContext::new(
                    vec![candidate("tools-batch-drift", DecisionKind::Throttle, 1.0)],
                    vec![constraint("epoch", true)],
                    20,
                    "policy-tools",
                ),
            ),
        ];
        let mut validator = EvidenceReplayValidator::new();

        let results = validator.validate_batch(&batch);
        let summary = validator.summary_report();

        assert_eq!(results.len(), 2);
        assert!(results.iter().all(ReplayResult::is_unresolvable));
        assert_eq!(summary.total, 2);
        assert_eq!(summary.unresolvable, 2);
        assert!(!summary.all_match());
    }

    #[test]
    fn tools_root_deny_with_selectable_candidate_mismatches() {
        let entry = test_replay_entry("tools-deny-selectable", DecisionKind::Deny, 21);
        let context = ReplayContext::new(
            vec![candidate("tools-deny-selectable", DecisionKind::Admit, 1.0)],
            vec![constraint("deny-should-block", true)],
            entry.epoch_id,
            "policy-tools",
        );
        let mut validator = EvidenceReplayValidator::new();

        let result = validator.validate(&entry, &context);

        assert!(matches!(
            result,
            ReplayResult::Mismatch { diff, .. }
                if diff.to_string().contains("decision_kind")
        ));
        assert_eq!(validator.mismatch_count(), 1);
        assert_eq!(validator.match_count(), 0);
    }

    #[test]
    fn tools_root_rollback_with_selectable_candidate_mismatches() {
        let entry = test_replay_entry("tools-rollback-blocked", DecisionKind::Rollback, 22);
        let context = ReplayContext::new(
            vec![candidate(
                "tools-rollback-candidate",
                DecisionKind::Admit,
                1.0,
            )],
            vec![constraint("rollback-should-have-no-winner", true)],
            entry.epoch_id,
            "policy-tools",
        );
        let mut validator = EvidenceReplayValidator::new();

        let result = validator.validate(&entry, &context);

        assert!(matches!(
            result,
            ReplayResult::Mismatch { got, diff, .. }
                if got.decision_kind == "admit" && diff.field_count() == 2
        ));
        assert_eq!(validator.mismatch_count(), 1);
    }

    #[test]
    fn tools_root_unsatisfied_constraint_blocks_matching_top_candidate() {
        let entry = test_replay_entry("tools-blocked-match", DecisionKind::Escalate, 23);
        let context = ReplayContext::new(
            vec![
                candidate("tools-blocked-match", DecisionKind::Escalate, 10.0),
                candidate("tools-lower", DecisionKind::Escalate, 1.0),
            ],
            vec![
                constraint("all-inputs-present", true),
                constraint("operator-approval", false),
            ],
            entry.epoch_id,
            "policy-tools",
        );
        let mut validator = EvidenceReplayValidator::new();

        let result = validator.validate(&entry, &context);

        assert!(matches!(
            result,
            ReplayResult::Mismatch { got, diff, .. }
                if got.decision_id == "none" && diff.field_count() == 1
        ));
        assert_eq!(validator.mismatch_count(), 1);
    }

    #[test]
    fn tools_root_candidate_kind_mismatch_records_kind_only_diff() {
        let entry = test_replay_entry("tools-kind-only", DecisionKind::Quarantine, 24);
        let context = ReplayContext::new(
            vec![candidate("tools-kind-only", DecisionKind::Release, 1.0)],
            vec![constraint("kind-drift", true)],
            entry.epoch_id,
            "policy-tools",
        );
        let mut validator = EvidenceReplayValidator::new();

        let result = validator.validate(&entry, &context);

        assert!(matches!(
            result,
            ReplayResult::Mismatch { diff, .. }
                if diff.field_count() == 1 && diff.to_string().contains("decision_kind")
        ));
        assert_eq!(validator.mismatch_count(), 1);
    }

    #[test]
    fn tools_root_tie_keeps_first_wrong_candidate() {
        let entry = test_replay_entry("tools-tie-expected", DecisionKind::Throttle, 25);
        let context = ReplayContext::new(
            vec![
                candidate("tools-tie-first", DecisionKind::Throttle, 0.5),
                candidate("tools-tie-expected", DecisionKind::Throttle, 0.5),
            ],
            vec![constraint("tie-deterministic", true)],
            entry.epoch_id,
            "policy-tools",
        );
        let mut validator = EvidenceReplayValidator::new();

        let result = validator.validate(&entry, &context);

        assert!(matches!(
            result,
            ReplayResult::Mismatch { got, diff, .. }
                if got.decision_id == "tools-tie-first"
                    && diff.to_string().contains("decision_id")
        ));
        assert_eq!(validator.mismatch_count(), 1);
    }

    #[test]
    fn tools_root_batch_mixed_failures_counts_each_class() {
        let mismatch = test_replay_entry("tools-mixed-mismatch", DecisionKind::Admit, 26);
        let unresolved = test_replay_entry("tools-mixed-unresolved", DecisionKind::Release, 27);
        let batch = vec![
            (
                mismatch.clone(),
                ReplayContext::new(
                    vec![candidate("tools-mixed-other", DecisionKind::Admit, 1.0)],
                    vec![constraint("candidate-present", true)],
                    mismatch.epoch_id,
                    "policy-tools",
                ),
            ),
            (
                unresolved.clone(),
                ReplayContext::new(vec![], vec![constraint("missing-candidate", true)], 27, ""),
            ),
        ];
        let mut validator = EvidenceReplayValidator::new();

        let results = validator.validate_batch(&batch);
        let summary = validator.summary_report();

        assert_eq!(results.len(), 2);
        assert!(results[0].is_mismatch());
        assert!(results[1].is_unresolvable());
        assert_eq!(summary.mismatches, 1);
        assert_eq!(summary.unresolvable, 1);
        assert!(!summary.all_match());
    }

    #[test]
    fn tools_root_repeated_invalid_contexts_store_per_entry_results() {
        let first = test_replay_entry("tools-invalid-first", DecisionKind::Admit, 28);
        let second = test_replay_entry("tools-invalid-second", DecisionKind::Release, 29);
        let invalid = ReplayContext::new(vec![], vec![], first.epoch_id, "");
        let mut validator = EvidenceReplayValidator::new();

        let first_result = validator.validate(&first, &invalid);
        let second_result = validator.validate(&second, &invalid);

        assert!(first_result.is_unresolvable());
        assert!(second_result.is_unresolvable());
        assert_eq!(validator.total_validations(), 2);
        assert_eq!(validator.results()[0].0, "tools-invalid-first");
        assert_eq!(validator.results()[1].0, "tools-invalid-second");
    }

    #[test]
    fn tools_root_empty_batch_leaves_summary_empty_and_not_all_match() {
        let mut validator = EvidenceReplayValidator::new();

        let results = validator.validate_batch(&[]);
        let summary = validator.summary_report();

        assert!(results.is_empty());
        assert!(validator.results().is_empty());
        assert_eq!(summary.total, 0);
        assert_eq!(summary.matches, 0);
        assert_eq!(summary.mismatches, 0);
        assert_eq!(summary.unresolvable, 0);
        assert!(!summary.all_match());
    }

    #[test]
    fn tools_root_invalid_context_takes_precedence_over_epoch_drift() {
        let entry = test_replay_entry("tools-invalid-before-epoch", DecisionKind::Admit, 30);
        let context = ReplayContext::new(
            vec![candidate(
                "tools-invalid-before-epoch",
                DecisionKind::Admit,
                1.0,
            )],
            vec![constraint("epoch-drift-hidden", true)],
            31,
            "",
        );
        let mut validator = EvidenceReplayValidator::new();

        let result = validator.validate(&entry, &context);

        assert!(matches!(
            result,
            ReplayResult::Unresolvable { reason }
                if reason.contains("invalid context") && !reason.contains("epoch mismatch")
        ));
        assert_eq!(validator.unresolvable_count(), 1);
        assert_eq!(validator.mismatch_count(), 0);
    }

    #[test]
    fn tools_root_nonfinite_expected_candidate_skips_to_finite_wrong_candidate() {
        let entry = test_replay_entry("tools-nonfinite-expected", DecisionKind::Admit, 32);
        let context = ReplayContext::new(
            vec![
                candidate("tools-nonfinite-expected", DecisionKind::Admit, f64::NAN),
                candidate("tools-finite-wrong", DecisionKind::Release, 0.0),
            ],
            vec![constraint("finite-required", true)],
            entry.epoch_id,
            "policy-tools",
        );
        let mut validator = EvidenceReplayValidator::new();

        let result = validator.validate(&entry, &context);

        assert!(matches!(
            result,
            ReplayResult::Mismatch { got, diff, .. }
                if got.decision_id == "tools-finite-wrong"
                    && got.decision_kind == "release"
                    && diff.field_count() == 2
        ));
        assert_eq!(validator.mismatch_count(), 1);
        assert_eq!(validator.match_count(), 0);
    }

    #[test]
    fn tools_root_all_negative_scores_still_select_best_finite_candidate() {
        let entry = test_replay_entry("tools-negative-expected", DecisionKind::Throttle, 33);
        let context = ReplayContext::new(
            vec![
                candidate("tools-negative-expected", DecisionKind::Throttle, -100.0),
                candidate("tools-negative-wrong", DecisionKind::Throttle, -0.1),
            ],
            vec![constraint("negative-scores-finite", true)],
            entry.epoch_id,
            "policy-tools",
        );
        let mut validator = EvidenceReplayValidator::new();

        let result = validator.validate(&entry, &context);

        assert!(matches!(
            result,
            ReplayResult::Mismatch { got, diff, .. }
                if got.decision_id == "tools-negative-wrong"
                    && diff.to_string().contains("decision_id")
        ));
        assert_eq!(validator.mismatch_count(), 1);
    }

    #[test]
    fn tools_root_mismatch_display_for_blocked_candidate_names_no_selection() {
        let entry = test_replay_entry("tools-display-blocked", DecisionKind::Escalate, 34);
        let context = ReplayContext::new(
            vec![candidate(
                "tools-display-blocked",
                DecisionKind::Escalate,
                1.0,
            )],
            vec![constraint("operator-denied", false)],
            entry.epoch_id,
            "policy-tools",
        );
        let mut validator = EvidenceReplayValidator::new();

        let result = validator.validate(&entry, &context);
        let rendered = result.to_string();

        assert!(result.is_mismatch());
        assert!(rendered.contains("MISMATCH"));
        assert!(rendered.contains("none (no candidate selected)"));
        assert_eq!(validator.mismatch_count(), 1);
    }

    #[test]
    fn tools_root_replay_diff_bounded_overflow_discards_oldest_fields() {
        let mut diff = ReplayDiff::new();

        for index in 0..(MAX_FIELDS + 3) {
            diff.add(
                format!("field-{index}"),
                format!("expected-{index}"),
                format!("actual-{index}"),
            );
        }
        let rendered = diff.to_string();

        assert_eq!(diff.field_count(), MAX_FIELDS);
        assert!(!rendered.contains("field-0 expected=expected-0"));
        assert!(!rendered.contains("field-1 expected=expected-1"));
        assert!(!rendered.contains("field-2 expected=expected-2"));
        assert!(rendered.contains(&format!(
            "field-{} expected=expected-{}",
            MAX_FIELDS + 2,
            MAX_FIELDS + 2
        )));
    }
}
