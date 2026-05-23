use frankenengine_node::control_plane::control_epoch::{
    ControlEpoch, EpochRejectionReason, ValidityWindowPolicy, check_artifact_epoch,
};
use proptest::prelude::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EpochDecision {
    Accepted,
    Rejected(EpochRejectionReason),
}

#[derive(Debug, Clone, Copy)]
enum PolicyReloadOrder {
    CurrentThenLookback,
    LookbackThenCurrent,
}

fn decision_for_policy(policy: &ValidityWindowPolicy, artifact_epoch: u64) -> EpochDecision {
    match check_artifact_epoch(
        "bundle/replay-chunk-0001",
        ControlEpoch::new(artifact_epoch),
        policy,
        "trace-control-epoch-metamorphic",
    ) {
        Ok(()) => EpochDecision::Accepted,
        Err(rejection) => EpochDecision::Rejected(rejection.rejection_reason),
    }
}

fn decision_for(artifact_epoch: u64, current_epoch: u64, lookback: u64) -> EpochDecision {
    let policy = ValidityWindowPolicy::new(ControlEpoch::new(current_epoch), lookback);
    decision_for_policy(&policy, artifact_epoch)
}

fn decision_after_hot_reload(
    artifact_epoch: u64,
    current_epoch: u64,
    lookback: u64,
    order: PolicyReloadOrder,
) -> EpochDecision {
    let mut policy = ValidityWindowPolicy::new(ControlEpoch::GENESIS, 0);
    match order {
        PolicyReloadOrder::CurrentThenLookback => {
            policy.set_current_epoch(ControlEpoch::new(current_epoch));
            policy.set_max_lookback(lookback);
        }
        PolicyReloadOrder::LookbackThenCurrent => {
            policy.set_max_lookback(lookback);
            policy.set_current_epoch(ControlEpoch::new(current_epoch));
        }
    }
    decision_for_policy(&policy, artifact_epoch)
}

#[test]
fn widening_validity_window_never_rejects_previously_accepted_past_epochs() {
    for current_epoch in 8_u64..=96 {
        for narrow_lookback in 0_u64..=8 {
            for extra_lookback in 0_u64..=8 {
                let wide_lookback = narrow_lookback + extra_lookback;

                for distance in 0_u64..=16 {
                    if distance > current_epoch {
                        continue;
                    }

                    let artifact_epoch = current_epoch - distance;
                    let narrow = decision_for(artifact_epoch, current_epoch, narrow_lookback);
                    let wide = decision_for(artifact_epoch, current_epoch, wide_lookback);

                    if narrow == EpochDecision::Accepted {
                        assert_eq!(
                            wide,
                            EpochDecision::Accepted,
                            "widening lookback {narrow_lookback}->{wide_lookback} rejected accepted artifact: current={current_epoch} artifact={artifact_epoch}"
                        );
                    }

                    if distance > wide_lookback {
                        assert_eq!(
                            wide,
                            EpochDecision::Rejected(EpochRejectionReason::ExpiredEpoch),
                            "artifact outside widened lookback should stay expired: current={current_epoch} artifact={artifact_epoch} wide={wide_lookback}"
                        );
                    }
                }

                for future_delta in 1_u64..=8 {
                    let future_epoch = current_epoch + future_delta;
                    assert_eq!(
                        decision_for(future_epoch, current_epoch, narrow_lookback),
                        EpochDecision::Rejected(EpochRejectionReason::FutureEpoch),
                        "future epoch should reject under narrow lookback"
                    );
                    assert_eq!(
                        decision_for(future_epoch, current_epoch, wide_lookback),
                        EpochDecision::Rejected(EpochRejectionReason::FutureEpoch),
                        "future epoch should reject under wide lookback"
                    );
                }
            }
        }
    }
}

#[test]
fn shifting_current_and_artifact_epochs_preserves_relative_validity_decision() {
    for current_epoch in 10_i64..=80 {
        let current_epoch_u64 = match u64::try_from(current_epoch) {
            Ok(epoch) => epoch,
            Err(_) => continue,
        };

        for lookback in 0_u64..=8 {
            for relative_offset in -12_i64..=6 {
                let artifact_epoch = current_epoch + relative_offset;
                if artifact_epoch < 0 {
                    continue;
                }
                let artifact_epoch_u64 = match u64::try_from(artifact_epoch) {
                    Ok(epoch) => epoch,
                    Err(_) => continue,
                };

                let original = decision_for(artifact_epoch_u64, current_epoch_u64, lookback);

                for shift in [1_u64, 7, 32] {
                    let shifted_current = current_epoch_u64 + shift;
                    let shifted_artifact = artifact_epoch_u64 + shift;
                    let shifted = decision_for(shifted_artifact, shifted_current, lookback);

                    assert_eq!(
                        shifted, original,
                        "translation invariance failed: current={current_epoch} artifact={artifact_epoch} shift={shift} lookback={lookback}"
                    );
                }
            }
        }
    }
}

#[test]
fn hot_reloaded_policy_matches_fresh_policy_across_epoch_boundaries() {
    for current_epoch in [0_u64, 1, 2, 8, 64, 512] {
        for lookback in [0_u64, 1, 2, 8, 128] {
            let min_accepted = current_epoch.saturating_sub(lookback);
            let mut artifact_epochs =
                vec![ControlEpoch::GENESIS.value(), min_accepted, current_epoch];
            if let Some(before_min) = min_accepted.checked_sub(1) {
                artifact_epochs.push(before_min);
            }
            if let Some(before_current) = current_epoch.checked_sub(1) {
                artifact_epochs.push(before_current);
            }
            if let Some(future_epoch) = current_epoch.checked_add(1) {
                artifact_epochs.push(future_epoch);
            }

            for artifact_epoch in artifact_epochs {
                let fresh = decision_for(artifact_epoch, current_epoch, lookback);
                for order in [
                    PolicyReloadOrder::CurrentThenLookback,
                    PolicyReloadOrder::LookbackThenCurrent,
                ] {
                    assert_eq!(
                        decision_after_hot_reload(artifact_epoch, current_epoch, lookback, order),
                        fresh,
                        "hot reload order diverged from fresh policy: current={current_epoch} lookback={lookback} artifact={artifact_epoch} order={order:?}"
                    );
                }
            }
        }
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: 128,
        ..ProptestConfig::default()
    })]

    #[test]
    fn validity_window_boundaries_are_inclusive_and_saturating(
        current_epoch in any::<u64>(),
        lookback in any::<u64>(),
        future_delta in 1_u64..=64,
    ) {
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(current_epoch), lookback);
        let min_accepted_epoch = current_epoch.saturating_sub(lookback);

        prop_assert_eq!(
            policy.min_accepted_epoch(),
            ControlEpoch::new(min_accepted_epoch),
            "min_accepted_epoch must saturate instead of underflowing"
        );
        prop_assert_eq!(
            decision_for(min_accepted_epoch, current_epoch, lookback),
            EpochDecision::Accepted,
            "minimum accepted epoch must be inside the inclusive validity window"
        );
        prop_assert_eq!(
            decision_for(current_epoch, current_epoch, lookback),
            EpochDecision::Accepted,
            "current epoch must be accepted"
        );

        if let Some(before_min) = min_accepted_epoch.checked_sub(1) {
            prop_assert_eq!(
                decision_for(before_min, current_epoch, lookback),
                EpochDecision::Rejected(EpochRejectionReason::ExpiredEpoch),
                "epoch immediately before the inclusive minimum must be expired"
            );
        }

        if let Some(future_epoch) = current_epoch.checked_add(future_delta) {
            prop_assert_eq!(
                decision_for(future_epoch, current_epoch, lookback),
                EpochDecision::Rejected(EpochRejectionReason::FutureEpoch),
                "future epochs must reject regardless of lookback width"
            );
        }
    }
}
