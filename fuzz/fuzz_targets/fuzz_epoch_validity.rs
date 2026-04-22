#![no_main]

use arbitrary::Arbitrary;
use frankenengine_node::control_plane::control_epoch::{
    check_artifact_epoch, ControlEpoch, EpochArtifactEvent, EpochError, EpochRejectionReason,
    EpochStore, ValidityWindowPolicy,
};
use libfuzzer_sys::fuzz_target;
use serde::de::DeserializeOwned;

const MAX_TEXT_BYTES: usize = 4_112;
const MAX_OPS: usize = 32;
const MAX_EPOCH_TEXT_BYTES: usize = 4_096;
const RESERVED_ARTIFACT_ID: &str = "<unknown>";

#[derive(Debug, Clone, Arbitrary)]
struct FuzzInput {
    current_epoch: u64,
    max_lookback: u64,
    artifact_epoch: u64,
    artifact_id: String,
    trace_id: String,
    initial_epoch: u64,
    operations: Vec<EpochOperation>,
}

#[derive(Debug, Clone, Arbitrary)]
enum EpochOperation {
    Advance {
        manifest_hash: String,
        timestamp: u64,
        trace_id: String,
    },
    Set {
        target_epoch: u64,
        manifest_hash: String,
        timestamp: u64,
        trace_id: String,
    },
}

fuzz_target!(|input: FuzzInput| {
    fuzz_validity_window(&input);
    fuzz_epoch_store_schedule(&input);
});

fn fuzz_validity_window(input: &FuzzInput) {
    let artifact_id = bounded_text(&input.artifact_id);
    let trace_id = bounded_text(&input.trace_id);
    let artifact_epoch = ControlEpoch::new(input.artifact_epoch);
    let policy =
        ValidityWindowPolicy::new(ControlEpoch::new(input.current_epoch), input.max_lookback);

    assert_eq!(
        policy.min_accepted_epoch().value(),
        input.current_epoch.saturating_sub(input.max_lookback)
    );
    json_roundtrip(&policy);

    let result = check_artifact_epoch(&artifact_id, artifact_epoch, &policy, &trace_id);
    match expected_rejection_reason(&artifact_id, input.artifact_epoch, &policy) {
        None => {
            result.expect("valid artifact epoch must be accepted");
            let event = EpochArtifactEvent::accepted(
                &artifact_id,
                artifact_epoch,
                policy.current_epoch(),
                &trace_id,
            );
            assert!(event.rejection_reason.is_none());
            json_roundtrip(&event);
        }
        Some(expected_reason) => {
            let rejection = result.expect_err("invalid artifact epoch must fail closed");
            assert_eq!(rejection.rejection_reason, expected_reason);
            assert_eq!(rejection.artifact_id, artifact_id);
            assert_eq!(rejection.artifact_epoch, artifact_epoch);
            assert_eq!(rejection.current_epoch, policy.current_epoch());
            assert_eq!(rejection.trace_id, trace_id);
            let event = rejection.to_rejected_event();
            assert_eq!(event.rejection_reason, Some(expected_reason));
            json_roundtrip(&rejection);
            json_roundtrip(&event);
        }
    }
}

fn fuzz_epoch_store_schedule(input: &FuzzInput) {
    let mut store = EpochStore::recover(input.initial_epoch);
    let mut expected_current = input.initial_epoch;

    for operation in input.operations.iter().take(MAX_OPS) {
        match operation {
            EpochOperation::Advance {
                manifest_hash,
                timestamp,
                trace_id,
            } => {
                let manifest_hash = bounded_text(manifest_hash);
                let trace_id = bounded_text(trace_id);
                let result = store.epoch_advance(&manifest_hash, *timestamp, &trace_id);

                if invalid_required_text(&manifest_hash) {
                    assert!(matches!(
                        result,
                        Err(EpochError::InvalidManifestHash { .. })
                    ));
                } else if expected_current == u64::MAX {
                    assert!(matches!(result, Err(EpochError::EpochOverflow { .. })));
                } else {
                    let transition = result.expect("valid advance must produce a transition");
                    assert_eq!(transition.old_epoch.value(), expected_current);
                    expected_current = expected_current.saturating_add(1);
                    assert_eq!(transition.new_epoch.value(), expected_current);
                    assert_eq!(transition.timestamp, *timestamp);
                    assert_eq!(transition.manifest_hash, manifest_hash);
                    assert_eq!(transition.trace_id, trace_id);
                    assert!(transition.verify());
                    json_roundtrip(&transition);
                }
            }
            EpochOperation::Set {
                target_epoch,
                manifest_hash,
                timestamp,
                trace_id,
            } => {
                let manifest_hash = bounded_text(manifest_hash);
                let trace_id = bounded_text(trace_id);
                let result = store.epoch_set(*target_epoch, &manifest_hash, *timestamp, &trace_id);

                if *target_epoch <= expected_current {
                    assert!(matches!(result, Err(EpochError::EpochRegression { .. })));
                } else if invalid_required_text(&manifest_hash) {
                    assert!(matches!(
                        result,
                        Err(EpochError::InvalidManifestHash { .. })
                    ));
                } else {
                    let transition = result.expect("valid epoch set must produce a transition");
                    assert_eq!(transition.old_epoch.value(), expected_current);
                    expected_current = *target_epoch;
                    assert_eq!(transition.new_epoch.value(), expected_current);
                    assert_eq!(transition.timestamp, *timestamp);
                    assert_eq!(transition.manifest_hash, manifest_hash);
                    assert_eq!(transition.trace_id, trace_id);
                    assert!(transition.verify());
                    json_roundtrip(&transition);
                }
            }
        }

        assert_eq!(store.epoch_read().value(), expected_current);
        assert_eq!(store.committed_epoch().value(), expected_current);
        assert!(store.transition_count() <= 4_096);
        assert!(store
            .transitions()
            .iter()
            .all(|transition| transition.verify()));
    }
}

fn expected_rejection_reason(
    artifact_id: &str,
    artifact_epoch: u64,
    policy: &ValidityWindowPolicy,
) -> Option<EpochRejectionReason> {
    if invalid_artifact_id(artifact_id) {
        return Some(EpochRejectionReason::InvalidArtifactId);
    }
    if artifact_epoch > policy.current_epoch().value() {
        return Some(EpochRejectionReason::FutureEpoch);
    }
    if artifact_epoch < policy.min_accepted_epoch().value() {
        return Some(EpochRejectionReason::ExpiredEpoch);
    }
    None
}

fn invalid_artifact_id(artifact_id: &str) -> bool {
    let trimmed = artifact_id.trim();
    trimmed.is_empty()
        || trimmed == RESERVED_ARTIFACT_ID
        || trimmed != artifact_id
        || artifact_id.contains('\0')
        || artifact_id.starts_with('/')
        || artifact_id.contains('\\')
        || artifact_id.split('/').any(|segment| segment == "..")
        || artifact_id.len() > MAX_EPOCH_TEXT_BYTES
}

fn invalid_required_text(value: &str) -> bool {
    let trimmed = value.trim();
    trimmed.is_empty()
        || trimmed != value
        || value.contains('\0')
        || value.len() > MAX_EPOCH_TEXT_BYTES
}

fn bounded_text(value: &str) -> String {
    value.chars().take(MAX_TEXT_BYTES).collect()
}

fn json_roundtrip<T>(value: &T)
where
    T: serde::Serialize + DeserializeOwned + PartialEq + std::fmt::Debug,
{
    let encoded = serde_json::to_string(value).expect("epoch value JSON encode");
    let decoded: T = serde_json::from_str(&encoded).expect("epoch value JSON decode");
    assert_eq!(&decoded, value);
}
