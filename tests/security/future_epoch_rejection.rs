//! Security conformance tests for fail-closed epoch validity windows (bd-2xv8).
//!
//! Normative checks:
//! - reject future-epoch artifacts
//! - reject expired artifacts outside lookback
//! - accept boundary epochs

#[path = "../../crates/franken-node/src/control_plane/control_epoch.rs"]
mod control_epoch;

use control_epoch::{
    ControlEpoch, EpochRejectionReason, ValidityWindowPolicy, check_artifact_epoch,
};

#[test]
fn rejects_future_epoch_artifact() {
    let policy = ValidityWindowPolicy::new(ControlEpoch::new(20), 1);
    let err = check_artifact_epoch(
        "artifact-future",
        ControlEpoch::new(21),
        &policy,
        "trace-future",
    )
    .expect_err("future epoch should fail-closed");

    assert_eq!(err.rejection_reason, EpochRejectionReason::FutureEpoch);
    assert_eq!(err.current_epoch, ControlEpoch::new(20));
    let event = err.to_rejected_event();
    assert_eq!(event.event_code, "EPOCH_ARTIFACT_REJECTED");
    assert_eq!(event.artifact_id, "artifact-future");
    assert_eq!(event.trace_id, "trace-future");
}

#[test]
fn rejects_expired_epoch_artifact() {
    let policy = ValidityWindowPolicy::new(ControlEpoch::new(20), 3);
    let err = check_artifact_epoch(
        "artifact-expired",
        ControlEpoch::new(16),
        &policy,
        "trace-expired",
    )
    .expect_err("expired epoch should be rejected");

    assert_eq!(err.rejection_reason, EpochRejectionReason::ExpiredEpoch);
    assert_eq!(err.current_epoch, ControlEpoch::new(20));
    let event = err.to_rejected_event();
    assert_eq!(event.event_code, "EPOCH_ARTIFACT_REJECTED");
    assert_eq!(event.artifact_id, "artifact-expired");
    assert_eq!(event.trace_id, "trace-expired");
}

#[test]
fn accepts_current_and_lower_window_boundary() {
    let policy = ValidityWindowPolicy::new(ControlEpoch::new(20), 3);

    let current = check_artifact_epoch(
        "artifact-current",
        ControlEpoch::new(20),
        &policy,
        "trace-current",
    );
    assert!(current.is_ok());

    let lower = check_artifact_epoch(
        "artifact-boundary",
        ControlEpoch::new(17),
        &policy,
        "trace-boundary",
    );
    assert!(lower.is_ok());
}
