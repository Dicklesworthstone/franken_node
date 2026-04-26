pub mod audience_token;
pub mod cancellation_injection;
pub mod cancellation_protocol;
pub mod control_epoch;
pub mod control_lane_mapping;
pub mod control_lane_policy;
pub mod divergence_gate;
pub mod dpor_exploration;
pub mod epoch_transition_barrier;
pub mod evidence_replay_gate;
pub mod fleet_transport;
pub mod fork_detection;
pub mod key_role_separation;
pub mod marker_stream;
pub mod mmr_proofs;
pub mod transition_abort;

#[cfg(test)]
mod control_plane_conformance_tests;

#[cfg(test)]
mod metamorphic_epoch_tests;

#[cfg(test)]
mod epoch_window_negative_tests {
    use super::control_epoch::{
        ControlEpoch, EpochError, EpochRejectionReason, EpochStore, ValidityWindowPolicy,
        check_artifact_epoch,
    };

    fn policy() -> ValidityWindowPolicy {
        ValidityWindowPolicy::new(ControlEpoch::new(10), 2)
    }

    #[test]
    fn artifact_epoch_rejects_empty_artifact_id() {
        let rejection = check_artifact_epoch("", ControlEpoch::new(10), &policy(), "trace-empty")
            .expect_err("empty artifact ids must fail closed");

        assert_eq!(
            rejection.rejection_reason,
            EpochRejectionReason::InvalidArtifactId
        );
        assert_eq!(rejection.code(), "EPOCH_REJECT_INVALID_ARTIFACT_ID");
    }

    #[test]
    fn artifact_epoch_rejects_reserved_artifact_id() {
        let rejection = check_artifact_epoch(
            "<unknown>",
            ControlEpoch::new(10),
            &policy(),
            "trace-reserved",
        )
        .expect_err("reserved artifact ids must fail closed");

        assert_eq!(
            rejection.rejection_reason,
            EpochRejectionReason::InvalidArtifactId
        );
    }

    #[test]
    fn artifact_epoch_rejects_whitespace_padded_artifact_id() {
        let rejection = check_artifact_epoch(
            " artifact-1 ",
            ControlEpoch::new(10),
            &policy(),
            "trace-whitespace",
        )
        .expect_err("artifact ids must be canonical");

        assert_eq!(
            rejection.rejection_reason,
            EpochRejectionReason::InvalidArtifactId
        );
    }

    #[test]
    fn artifact_epoch_rejects_future_epoch() {
        let rejection = check_artifact_epoch(
            "artifact-1",
            ControlEpoch::new(11),
            &policy(),
            "trace-future",
        )
        .expect_err("future artifact epochs must fail closed");

        assert_eq!(
            rejection.rejection_reason,
            EpochRejectionReason::FutureEpoch
        );
        assert_eq!(rejection.code(), "EPOCH_REJECT_FUTURE");
    }

    #[test]
    fn artifact_epoch_rejects_epoch_outside_lookback_window() {
        let rejection = check_artifact_epoch(
            "artifact-1",
            ControlEpoch::new(7),
            &policy(),
            "trace-expired",
        )
        .expect_err("stale artifact epochs must fail closed");

        assert_eq!(
            rejection.rejection_reason,
            EpochRejectionReason::ExpiredEpoch
        );
        assert_eq!(rejection.code(), "EPOCH_REJECT_EXPIRED");
    }

    #[test]
    fn epoch_advance_rejects_empty_manifest_hash() {
        let mut store = EpochStore::new();

        let err = store
            .epoch_advance("", 1_700_000_000, "trace-empty")
            .unwrap_err();

        assert_eq!(err.code(), "EPOCH_INVALID_MANIFEST");
        assert_eq!(store.epoch_read(), ControlEpoch::GENESIS);
    }

    #[test]
    fn epoch_set_rejects_regression_to_current_epoch() {
        let mut store = EpochStore::new();

        let err = store
            .epoch_set(0, "manifest-a", 1_700_000_000, "trace-regression")
            .unwrap_err();

        assert!(matches!(
            err,
            EpochError::EpochRegression {
                current,
                attempted
            } if current.is_genesis() && attempted.is_genesis()
        ));
        assert_eq!(store.transition_count(), 0);
    }

    #[test]
    fn epoch_set_rejects_empty_manifest_after_monotonic_check() {
        let mut store = EpochStore::new();

        let err = store
            .epoch_set(1, "", 1_700_000_000, "trace-empty-set")
            .unwrap_err();

        assert!(matches!(err, EpochError::InvalidManifestHash { .. }));
        assert_eq!(store.epoch_read(), ControlEpoch::GENESIS);
    }

    #[test]
    fn epoch_advance_rejects_counter_overflow() {
        let mut store = EpochStore::recover(u64::MAX);

        let err = store
            .epoch_advance("manifest-max", 1_700_000_000, "trace-overflow")
            .unwrap_err();

        assert!(matches!(
            err,
            EpochError::EpochOverflow { current } if current.value() == u64::MAX
        ));
        assert_eq!(store.epoch_read().value(), u64::MAX);
    }
}

#[cfg(test)]
mod tests {
    use super::control_epoch::{
        ControlEpoch, EpochError, EpochRejectionReason, EpochStore, ValidityWindowPolicy,
        check_artifact_epoch,
    };
    use super::transition_abort::{
        AbortError, ForceTransitionPolicy, ParticipantAbortState, TransitionAbortEvent,
        TransitionAbortManager, TransitionAbortReason,
    };
    use std::collections::BTreeSet;

    fn participants(ids: &[&str]) -> BTreeSet<String> {
        ids.iter().map(|id| (*id).to_string()).collect()
    }

    fn force_policy(
        skippable: &[&str],
        max_skippable: usize,
        operator_id: &str,
        audit_reason: &str,
    ) -> ForceTransitionPolicy {
        ForceTransitionPolicy::new(
            participants(skippable),
            max_skippable,
            operator_id,
            audit_reason,
        )
    }

    fn abort_state(participant_id: &str, current_epoch: u64) -> ParticipantAbortState {
        ParticipantAbortState {
            participant_id: participant_id.to_string(),
            had_acked: false,
            current_epoch,
            in_flight_items: 0,
        }
    }

    #[test]
    fn negative_epoch_advance_rejects_empty_manifest_hash() {
        let mut store = EpochStore::new();

        let err = store
            .epoch_advance("", 100, "trace-empty-manifest")
            .expect_err("empty manifest hash must not advance epoch");

        assert!(matches!(err, EpochError::InvalidManifestHash { .. }));
        assert_eq!(store.epoch_read(), ControlEpoch::GENESIS);
    }

    #[test]
    fn negative_epoch_set_rejects_equal_current_epoch() {
        let mut store = EpochStore::recover(7);

        let err = store
            .epoch_set(7, "manifest-hash", 100, "trace-equal-epoch")
            .expect_err("setting current epoch again must be rejected");

        assert!(matches!(
            err,
            EpochError::EpochRegression {
                current,
                attempted
            } if current == ControlEpoch::new(7) && attempted == ControlEpoch::new(7)
        ));
    }

    #[test]
    fn negative_epoch_advance_rejects_overflow() {
        let mut store = EpochStore::recover(u64::MAX);

        let err = store
            .epoch_advance("manifest-hash", 100, "trace-overflow")
            .expect_err("epoch at u64::MAX must not advance");

        assert!(matches!(
            err,
            EpochError::EpochOverflow { current } if current == ControlEpoch::new(u64::MAX)
        ));
    }

    #[test]
    fn negative_artifact_epoch_rejects_blank_artifact_id() {
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(10), 1);

        let rejection =
            check_artifact_epoch("  ", ControlEpoch::new(10), &policy, "trace-blank-artifact")
                .expect_err("blank artifact IDs must be rejected");

        assert_eq!(
            rejection.rejection_reason,
            EpochRejectionReason::InvalidArtifactId
        );
        assert_eq!(rejection.code(), "EPOCH_REJECT_INVALID_ARTIFACT_ID");
    }

    #[test]
    fn negative_artifact_epoch_rejects_future_epoch() {
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(10), 1);

        let rejection = check_artifact_epoch(
            "artifact-1",
            ControlEpoch::new(11),
            &policy,
            "trace-future-artifact",
        )
        .expect_err("future artifact epochs must fail closed");

        assert_eq!(
            rejection.rejection_reason,
            EpochRejectionReason::FutureEpoch
        );
        assert_eq!(rejection.code(), "EPOCH_REJECT_FUTURE");
    }

    #[test]
    fn negative_artifact_epoch_rejects_expired_epoch() {
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(10), 1);

        let rejection = check_artifact_epoch(
            "artifact-1",
            ControlEpoch::new(8),
            &policy,
            "trace-expired-artifact",
        )
        .expect_err("artifact older than lookback window must be rejected");

        assert_eq!(
            rejection.rejection_reason,
            EpochRejectionReason::ExpiredEpoch
        );
        assert_eq!(rejection.code(), "EPOCH_REJECT_EXPIRED");
    }

    #[test]
    fn negative_force_policy_rejects_missing_operator() {
        let manager = TransitionAbortManager::new();
        let policy = force_policy(&["node-a"], 1, "", "manual recovery");
        let known = participants(&["node-a", "node-b"]);

        let err = manager
            .validate_force_policy(&policy, &known)
            .expect_err("force policy must have explicit operator identity");

        assert_eq!(err, AbortError::NoOperator);
    }

    #[test]
    fn negative_force_policy_rejects_missing_reason() {
        let manager = TransitionAbortManager::new();
        let policy = force_policy(&["node-a"], 1, "operator-1", "");
        let known = participants(&["node-a", "node-b"]);

        let err = manager
            .validate_force_policy(&policy, &known)
            .expect_err("force policy must have explicit audit reason");

        assert_eq!(err, AbortError::NoReason);
    }

    #[test]
    fn negative_force_policy_rejects_over_limit_skip_set() {
        let manager = TransitionAbortManager::new();
        let policy = force_policy(&["node-a", "node-b"], 1, "operator-1", "manual recovery");
        let known = participants(&["node-a", "node-b", "node-c"]);

        let err = manager
            .validate_force_policy(&policy, &known)
            .expect_err("force policy cannot skip more participants than allowed");

        assert!(matches!(err, AbortError::OverLimit { skipped: 2, max: 1 }));
    }

    #[test]
    fn negative_force_policy_rejects_unknown_participant() {
        let manager = TransitionAbortManager::new();
        let policy = force_policy(&["node-missing"], 1, "operator-1", "manual recovery");
        let known = participants(&["node-a", "node-b"]);

        let err = manager
            .validate_force_policy(&policy, &known)
            .expect_err("force policy scope must be limited to known participants");

        assert!(matches!(
            err,
            AbortError::UnknownParticipant { participant_id } if participant_id == "node-missing"
        ));
    }

    #[test]
    fn negative_force_policy_rejects_skipping_all_participants() {
        let manager = TransitionAbortManager::new();
        let policy = force_policy(&["node-a", "node-b"], 2, "operator-1", "manual recovery");
        let known = participants(&["node-a", "node-b"]);

        let err = manager
            .validate_force_policy(&policy, &known)
            .expect_err("force policy cannot skip every participant");

        assert!(matches!(err, AbortError::AllSkipped { total: 2 }));
    }

    #[test]
    fn negative_artifact_id_validation_precedes_future_epoch_rejection() {
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(20), 5);

        let rejection = check_artifact_epoch(
            "<unknown>",
            ControlEpoch::new(21),
            &policy,
            "trace-invalid-first",
        )
        .expect_err("reserved artifact ID must fail before epoch ordering checks");

        assert_eq!(
            rejection.rejection_reason,
            EpochRejectionReason::InvalidArtifactId
        );
        assert_eq!(rejection.artifact_epoch, ControlEpoch::new(21));
    }

    #[test]
    fn negative_hot_reloaded_window_rejects_previously_valid_epoch() {
        let mut policy = ValidityWindowPolicy::new(ControlEpoch::new(20), 5);
        check_artifact_epoch(
            "artifact-window-edge",
            ControlEpoch::new(15),
            &policy,
            "trace-wide-window",
        )
        .expect("artifact at lower boundary should be valid before shrink");

        policy.set_max_lookback(4);
        let rejection = check_artifact_epoch(
            "artifact-window-edge",
            ControlEpoch::new(15),
            &policy,
            "trace-shrunk-window",
        )
        .expect_err("shrinking the validity window must fail closed");

        assert_eq!(
            rejection.rejection_reason,
            EpochRejectionReason::ExpiredEpoch
        );
        assert_eq!(policy.min_accepted_epoch(), ControlEpoch::new(16));
    }

    #[test]
    fn negative_epoch_set_whitespace_manifest_does_not_record_transition() {
        let mut store = EpochStore::recover(4);

        let err = store
            .epoch_set(5, " \t\n ", 1_700_000_000, "trace-blank-forward")
            .expect_err("forward epoch set with blank manifest must be rejected");

        assert!(matches!(err, EpochError::InvalidManifestHash { .. }));
        assert_eq!(store.epoch_read(), ControlEpoch::new(4));
        assert_eq!(store.committed_epoch(), ControlEpoch::new(4));
        assert_eq!(store.transition_count(), 0);
    }

    #[test]
    fn negative_blank_skippable_participant_precedes_over_limit_error() {
        let manager = TransitionAbortManager::new();
        let policy = force_policy(&["", "node-a"], 1, "operator-1", "manual recovery");
        let known = participants(&["node-a", "node-b"]);

        let err = manager
            .validate_force_policy(&policy, &known)
            .expect_err("blank skippable participant must fail before count limits");

        assert!(matches!(
            err,
            AbortError::UnknownParticipant { participant_id } if participant_id.is_empty()
        ));
    }

    #[test]
    fn negative_blank_known_participant_rejects_force_policy() {
        let manager = TransitionAbortManager::new();
        let policy = force_policy(&["node-a"], 1, "operator-1", "manual recovery");
        let known = participants(&["", "node-a", "node-b"]);

        let err = manager
            .validate_force_policy(&policy, &known)
            .expect_err("known participant registry must not contain blank IDs");

        assert!(matches!(
            err,
            AbortError::UnknownParticipant { participant_id } if participant_id.is_empty()
        ));
    }

    #[test]
    fn negative_empty_participant_abort_event_fails_no_partial_check() {
        let event = TransitionAbortEvent::new(
            "barrier-empty",
            TransitionAbortReason::Timeout { elapsed_ms: 500 },
            9,
            10,
            Vec::new(),
            500,
            1_700_000_000,
            "trace-empty-abort",
        );

        assert!(!event.verify_no_partial_state());
        assert_eq!(event.pre_epoch, 9);
        assert_eq!(event.proposed_epoch, 10);
    }

    #[test]
    fn negative_participant_on_proposed_epoch_fails_no_partial_check() {
        let event = TransitionAbortEvent::new(
            "barrier-partial",
            TransitionAbortReason::ParticipantFailure {
                participant_id: "node-b".to_string(),
                detail: "acked proposed epoch".to_string(),
            },
            9,
            10,
            vec![abort_state("node-a", 9), abort_state("node-b", 10)],
            250,
            1_700_000_001,
            "trace-partial-abort",
        );

        assert!(!event.verify_no_partial_state());
        assert_eq!(event.participant_states.len(), 2);
    }

    #[test]
    fn negative_record_abort_keeps_partial_state_visible() {
        let mut manager = TransitionAbortManager::new();

        let event = manager.record_abort(
            "barrier-recorded-partial",
            TransitionAbortReason::Cancellation {
                source: "operator".to_string(),
            },
            12,
            13,
            vec![abort_state("node-a", 12), abort_state("node-b", 13)],
            100,
            1_700_000_002,
            "trace-recorded-partial",
        );

        assert!(!event.verify_no_partial_state());
        assert_eq!(manager.abort_count(), 1);
        assert_eq!(manager.audit_log().len(), 1);
        assert_eq!(
            manager.abort_events()[0].barrier_id,
            "barrier-recorded-partial"
        );
    }
}
