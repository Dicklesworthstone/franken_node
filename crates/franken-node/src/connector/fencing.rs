//! Singleton-writer fencing validation.
//!
//! Guards connector state writes with a lease-based fencing mechanism.
//! Each writer must hold a valid, non-stale lease with a matching
//! object_id before writes are permitted.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::control_plane::control_epoch::{
    ControlEpoch, EpochArtifactEvent, EpochRejection, EpochRejectionReason, ValidityWindowPolicy,
    check_artifact_epoch,
};

/// Stable event codes for epoch-scoped validity checks.
pub mod epoch_event_codes {
    pub const EPOCH_CHECK_PASSED: &str = "EPV-001";
    pub const FUTURE_EPOCH_REJECTED: &str = "EPV-002";
    pub const STALE_EPOCH_REJECTED: &str = "EPV-003";
    pub const EPOCH_SCOPE_LOGGED: &str = "EPV-004";
    pub const INVALID_ARTIFACT_ID_REJECTED: &str = "EPV-006";
}

/// A lease that grants write permission to a specific state object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Lease {
    pub lease_seq: u64,
    pub object_id: String,
    pub epoch: ControlEpoch,
    pub holder_id: String,
    pub acquired_at: String,
    pub expires_at: String,
}

/// A write request carrying a fence token.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FencedWrite {
    pub fence_seq: Option<u64>,
    pub target_object_id: String,
    pub payload: serde_json::Value,
}

/// Fencing error codes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FencingError {
    #[serde(rename = "WRITE_UNFENCED")]
    WriteUnfenced,
    #[serde(rename = "WRITE_STALE_FENCE")]
    WriteStaleFence { write_seq: u64, current_seq: u64 },
    #[serde(rename = "WRITE_FENCE_MISMATCH")]
    WriteFenceMismatch {
        write_seq: u64,
        lease_seq: u64,
        current_seq: u64,
    },
    #[serde(rename = "LEASE_EXPIRED")]
    LeaseExpired {
        expires_at: String,
        current_time: String,
    },
    #[serde(rename = "LEASE_OBJECT_MISMATCH")]
    LeaseObjectMismatch {
        lease_object: String,
        target_object: String,
    },
    #[serde(rename = "LEASE_EPOCH_REJECTED")]
    EpochRejected { rejection: EpochRejection },
}

impl FencingError {
    #[must_use]
    pub fn epoch_event_code(&self) -> Option<&'static str> {
        match self {
            Self::EpochRejected { rejection } => Some(match rejection.rejection_reason {
                EpochRejectionReason::InvalidArtifactId => {
                    epoch_event_codes::INVALID_ARTIFACT_ID_REJECTED
                }
                EpochRejectionReason::FutureEpoch => epoch_event_codes::FUTURE_EPOCH_REJECTED,
                EpochRejectionReason::ExpiredEpoch => epoch_event_codes::STALE_EPOCH_REJECTED,
            }),
            _ => None,
        }
    }
}

impl fmt::Display for FencingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::WriteUnfenced => write!(f, "WRITE_UNFENCED: write has no fence token"),
            Self::WriteStaleFence {
                write_seq,
                current_seq,
            } => write!(
                f,
                "WRITE_STALE_FENCE: write seq {write_seq} < current fence {current_seq}"
            ),
            Self::WriteFenceMismatch {
                write_seq,
                lease_seq,
                current_seq,
            } => write!(
                f,
                "WRITE_FENCE_MISMATCH: write seq {write_seq}, lease seq {lease_seq}, current fence {current_seq}"
            ),
            Self::LeaseExpired {
                expires_at,
                current_time,
            } => write!(
                f,
                "LEASE_EXPIRED: lease expired at {expires_at}, current time {current_time}"
            ),
            Self::LeaseObjectMismatch {
                lease_object,
                target_object,
            } => write!(
                f,
                "LEASE_OBJECT_MISMATCH: lease for '{lease_object}', target '{target_object}'"
            ),
            Self::EpochRejected { rejection } => write!(
                f,
                "LEASE_EPOCH_REJECTED: artifact={} artifact_epoch={} current_epoch={} reason={}",
                rejection.artifact_id,
                rejection.artifact_epoch.value(),
                rejection.current_epoch.value(),
                rejection.code()
            ),
        }
    }
}

impl std::error::Error for FencingError {}

/// The fencing state for a single state object.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FenceState {
    pub object_id: String,
    pub current_seq: u64,
    pub current_holder: Option<String>,
}

/// Structured epoch-scope log for accepted high-impact operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochScopeLog {
    pub event_code: String,
    pub artifact_type: String,
    pub artifact_id: String,
    pub artifact_epoch: ControlEpoch,
    pub current_epoch: ControlEpoch,
    pub trace_id: String,
}

impl EpochScopeLog {
    fn for_fencing_token(
        artifact_id: &str,
        artifact_epoch: ControlEpoch,
        current_epoch: ControlEpoch,
        trace_id: &str,
    ) -> Self {
        Self {
            event_code: epoch_event_codes::EPOCH_SCOPE_LOGGED.to_string(),
            artifact_type: "fencing_token".to_string(),
            artifact_id: artifact_id.to_string(),
            artifact_epoch,
            current_epoch,
            trace_id: trace_id.to_string(),
        }
    }
}

/// Result of epoch-scoped fencing validation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochScopedWriteOutcome {
    pub epoch_check_event_code: String,
    pub epoch_event: EpochArtifactEvent,
    pub scope_log: EpochScopeLog,
}

impl FenceState {
    /// Create a new fence state with seq=0 (no fence yet).
    pub fn new(object_id: String) -> Self {
        Self {
            object_id,
            current_seq: 0,
            current_holder: None,
        }
    }

    /// Acquire a new lease, advancing the fence sequence.
    pub fn acquire_lease(
        &mut self,
        holder_id: String,
        acquired_at: String,
        expires_at: String,
    ) -> Lease {
        self.acquire_lease_with_epoch(holder_id, acquired_at, expires_at, ControlEpoch::GENESIS)
    }

    /// Acquire a new lease bound to a specific control epoch.
    pub fn acquire_lease_with_epoch(
        &mut self,
        holder_id: String,
        acquired_at: String,
        expires_at: String,
        epoch: ControlEpoch,
    ) -> Lease {
        self.current_seq = self.current_seq.saturating_add(1);
        self.current_holder = Some(holder_id.clone());
        Lease {
            lease_seq: self.current_seq,
            object_id: self.object_id.clone(),
            epoch,
            holder_id,
            acquired_at,
            expires_at,
        }
    }

    /// Validate a fenced write against the current fence state.
    pub fn validate_write(
        &self,
        write: &FencedWrite,
        lease: &Lease,
        current_time: &str,
    ) -> Result<(), FencingError> {
        // Check fence token presence
        let fence_seq = write.fence_seq.ok_or(FencingError::WriteUnfenced)?;

        // Check staleness
        if fence_seq < self.current_seq {
            return Err(FencingError::WriteStaleFence {
                write_seq: fence_seq,
                current_seq: self.current_seq,
            });
        }

        if fence_seq != lease.lease_seq || fence_seq != self.current_seq {
            return Err(FencingError::WriteFenceMismatch {
                write_seq: fence_seq,
                lease_seq: lease.lease_seq,
                current_seq: self.current_seq,
            });
        }

        // Check lease expiry (fail-closed: expired AT the boundary)
        if current_time >= lease.expires_at.as_str() {
            return Err(FencingError::LeaseExpired {
                expires_at: lease.expires_at.clone(),
                current_time: current_time.to_string(),
            });
        }

        // Check object linkage
        if self.object_id != write.target_object_id {
            return Err(FencingError::LeaseObjectMismatch {
                lease_object: self.object_id.clone(),
                target_object: write.target_object_id.clone(),
            });
        }

        if lease.object_id != write.target_object_id {
            return Err(FencingError::LeaseObjectMismatch {
                lease_object: lease.object_id.clone(),
                target_object: write.target_object_id.clone(),
            });
        }

        Ok(())
    }

    /// Validate a fenced write, requiring canonical epoch-window acceptance.
    pub fn validate_write_epoch_scoped(
        &self,
        write: &FencedWrite,
        lease: &Lease,
        current_time: &str,
        validity_policy: &ValidityWindowPolicy,
        trace_id: &str,
    ) -> Result<EpochScopedWriteOutcome, FencingError> {
        let artifact_id = format!("fencing:{}:{}", lease.object_id, lease.lease_seq);
        check_artifact_epoch(&artifact_id, lease.epoch, validity_policy, trace_id)
            .map_err(|rejection| FencingError::EpochRejected { rejection })?;

        self.validate_write(write, lease, current_time)?;

        let current_epoch = validity_policy.current_epoch();
        Ok(EpochScopedWriteOutcome {
            epoch_check_event_code: epoch_event_codes::EPOCH_CHECK_PASSED.to_string(),
            epoch_event: EpochArtifactEvent::accepted(
                &artifact_id,
                lease.epoch,
                current_epoch,
                trace_id,
            ),
            scope_log: EpochScopeLog::for_fencing_token(
                &artifact_id,
                lease.epoch,
                current_epoch,
                trace_id,
            ),
        })
    }
}

/// A rejection receipt for audit logging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RejectionReceipt {
    pub object_id: String,
    pub error: FencingError,
    pub write_seq: Option<u64>,
    pub current_fence_seq: u64,
    pub timestamp: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::control_epoch::ValidityWindowPolicy;
    use serde_json::json;

    #[test]
    fn new_fence_state_seq_zero() {
        let fs = FenceState::new("obj-1".into());
        assert_eq!(fs.current_seq, 0);
        assert!(fs.current_holder.is_none());
    }

    #[test]
    fn acquire_lease_increments_seq() {
        let mut fs = FenceState::new("obj-1".into());
        let l1 = fs.acquire_lease(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2026-12-31T00:00:00Z".into(),
        );
        assert_eq!(l1.lease_seq, 1);
        let l2 = fs.acquire_lease(
            "writer-b".into(),
            "2026-01-02T00:00:00Z".into(),
            "2026-12-31T00:00:00Z".into(),
        );
        assert_eq!(l2.lease_seq, 2);
        assert_eq!(fs.current_seq, 2);
    }

    #[test]
    fn valid_fenced_write_accepted() {
        let mut fs = FenceState::new("obj-1".into());
        let lease = fs.acquire_lease(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
        );
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: "obj-1".into(),
            payload: json!({"data": "test"}),
        };
        assert!(
            fs.validate_write(&write, &lease, "2026-06-01T00:00:00Z")
                .is_ok()
        );
    }

    #[test]
    fn unfenced_write_rejected() {
        let mut fs = FenceState::new("obj-1".into());
        let lease = fs.acquire_lease(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
        );
        let write = FencedWrite {
            fence_seq: None,
            target_object_id: "obj-1".into(),
            payload: json!({}),
        };
        let err = fs
            .validate_write(&write, &lease, "2026-06-01T00:00:00Z")
            .unwrap_err();
        assert_eq!(err, FencingError::WriteUnfenced);
    }

    #[test]
    fn stale_fenced_write_rejected() {
        let mut fs = FenceState::new("obj-1".into());
        let _l1 = fs.acquire_lease(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
        );
        let l2 = fs.acquire_lease(
            "writer-b".into(),
            "2026-01-02T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
        );
        // Try to write with old seq=1, current is 2
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: "obj-1".into(),
            payload: json!({}),
        };
        let err = fs
            .validate_write(&write, &l2, "2026-06-01T00:00:00Z")
            .unwrap_err();
        assert!(matches!(err, FencingError::WriteStaleFence { .. }));
    }

    #[test]
    fn expired_lease_rejected() {
        let mut fs = FenceState::new("obj-1".into());
        let lease = fs.acquire_lease(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2026-02-01T00:00:00Z".into(),
        );
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: "obj-1".into(),
            payload: json!({}),
        };
        let err = fs
            .validate_write(&write, &lease, "2026-06-01T00:00:00Z")
            .unwrap_err();
        assert!(matches!(err, FencingError::LeaseExpired { .. }));
    }

    #[test]
    fn object_mismatch_rejected() {
        let mut fs = FenceState::new("obj-1".into());
        let lease = fs.acquire_lease(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
        );
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: "obj-DIFFERENT".into(),
            payload: json!({}),
        };
        let err = fs
            .validate_write(&write, &lease, "2026-06-01T00:00:00Z")
            .unwrap_err();
        assert!(matches!(err, FencingError::LeaseObjectMismatch { .. }));
    }

    #[test]
    fn monotonic_fence_sequence() {
        let mut fs = FenceState::new("obj-1".into());
        let mut prev_seq = 0u64;
        for i in 0..10 {
            let lease = fs.acquire_lease(
                format!("writer-{i}"),
                "2026-01-01T00:00:00Z".into(),
                "2030-01-01T00:00:00Z".into(),
            );
            assert!(lease.lease_seq > prev_seq);
            prev_seq = lease.lease_seq;
        }
    }

    #[test]
    fn serde_roundtrip_lease() {
        let mut fs = FenceState::new("obj-1".into());
        let lease = fs.acquire_lease("w".into(), "t1".into(), "t2".into());
        let json = serde_json::to_string(&lease).unwrap();
        let parsed: Lease = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.lease_seq, lease.lease_seq);
    }

    #[test]
    fn serde_roundtrip_error() {
        let err = FencingError::WriteStaleFence {
            write_seq: 1,
            current_seq: 5,
        };
        let json = serde_json::to_string(&err).unwrap();
        let parsed: FencingError = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed, err);
    }

    #[test]
    fn error_display_stable() {
        let err = FencingError::WriteUnfenced;
        assert!(err.to_string().contains("WRITE_UNFENCED"));
    }

    #[test]
    fn lease_can_carry_epoch_stamp() {
        let mut fs = FenceState::new("obj-epoch".into());
        let lease = fs.acquire_lease_with_epoch(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
            ControlEpoch::new(11),
        );
        assert_eq!(lease.epoch, ControlEpoch::new(11));
    }

    #[test]
    fn epoch_scoped_validation_accepts_current_epoch() {
        let mut fs = FenceState::new("obj-epoch-accept".into());
        let lease = fs.acquire_lease_with_epoch(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
            ControlEpoch::new(5),
        );
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: "obj-epoch-accept".into(),
            payload: json!({"ok": true}),
        };
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(5), 2);

        let outcome = fs
            .validate_write_epoch_scoped(&write, &lease, "2026-06-01T00:00:00Z", &policy, "t-1")
            .unwrap();
        assert_eq!(
            outcome.epoch_check_event_code,
            epoch_event_codes::EPOCH_CHECK_PASSED
        );
        assert_eq!(
            outcome.scope_log.event_code,
            epoch_event_codes::EPOCH_SCOPE_LOGGED
        );
    }

    #[test]
    fn epoch_scoped_validation_rejects_future_epoch() {
        let mut fs = FenceState::new("obj-epoch-future".into());
        let lease = fs.acquire_lease_with_epoch(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
            ControlEpoch::new(8),
        );
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: "obj-epoch-future".into(),
            payload: json!({"ok": true}),
        };
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(7), 2);

        let err = fs
            .validate_write_epoch_scoped(
                &write,
                &lease,
                "2026-06-01T00:00:00Z",
                &policy,
                "t-future",
            )
            .unwrap_err();
        match err {
            FencingError::EpochRejected { rejection } => {
                assert_eq!(
                    rejection.rejection_reason,
                    EpochRejectionReason::FutureEpoch
                );
            }
            _ => unreachable!("expected epoch rejection"),
        }
    }

    #[test]
    fn epoch_scoped_validation_rejects_invalid_artifact_id() {
        let mut fs = FenceState::new(" obj-epoch-invalid ".into());
        let lease = fs.acquire_lease_with_epoch(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
            ControlEpoch::new(5),
        );
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: " obj-epoch-invalid ".into(),
            payload: json!({"ok": true}),
        };
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(5), 2);

        let err = fs
            .validate_write_epoch_scoped(
                &write,
                &lease,
                "2026-06-01T00:00:00Z",
                &policy,
                "t-invalid",
            )
            .unwrap_err();
        match &err {
            FencingError::EpochRejected { rejection } => {
                assert_eq!(
                    rejection.rejection_reason,
                    EpochRejectionReason::InvalidArtifactId
                );
            }
            _ => unreachable!("expected epoch rejection"),
        }
        assert_eq!(
            err.epoch_event_code(),
            Some(epoch_event_codes::INVALID_ARTIFACT_ID_REJECTED)
        );
    }

    #[test]
    fn lease_expired_at_exact_boundary_is_rejected() {
        let mut fs = FenceState::new("obj-1".into());
        let lease = fs.acquire_lease(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2026-06-01T00:00:00Z".into(),
        );
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: "obj-1".into(),
            payload: json!({"data": "boundary"}),
        };
        // Write at exact expiry instant must be rejected (fail-closed).
        let result = fs.validate_write(&write, &lease, "2026-06-01T00:00:00Z");
        assert!(
            result.is_err(),
            "write at exact lease expiry must be rejected"
        );
        assert!(matches!(result, Err(FencingError::LeaseExpired { .. })));
    }

    #[test]
    fn epoch_scoped_validation_rejects_expired_epoch() {
        let mut fs = FenceState::new("obj-epoch-stale".into());
        let lease = fs.acquire_lease_with_epoch(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
            ControlEpoch::new(2),
        );
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: "obj-epoch-stale".into(),
            payload: json!({"ok": true}),
        };
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(5), 1);

        let err = fs
            .validate_write_epoch_scoped(&write, &lease, "2026-06-01T00:00:00Z", &policy, "t-old")
            .unwrap_err();

        match &err {
            FencingError::EpochRejected { rejection } => {
                assert_eq!(
                    rejection.rejection_reason,
                    EpochRejectionReason::ExpiredEpoch
                );
            }
            _ => unreachable!("expected expired epoch rejection"),
        }
        assert_eq!(
            err.epoch_event_code(),
            Some(epoch_event_codes::STALE_EPOCH_REJECTED)
        );
    }

    #[test]
    fn epoch_rejection_precedes_unfenced_write_rejection() {
        let mut fs = FenceState::new("obj-epoch-first".into());
        let lease = fs.acquire_lease_with_epoch(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
            ControlEpoch::new(9),
        );
        let write = FencedWrite {
            fence_seq: None,
            target_object_id: "obj-epoch-first".into(),
            payload: json!({"ok": false}),
        };
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(7), 2);

        let err = fs
            .validate_write_epoch_scoped(
                &write,
                &lease,
                "2026-06-01T00:00:00Z",
                &policy,
                "t-future-first",
            )
            .unwrap_err();

        assert!(matches!(
            err,
            FencingError::EpochRejected {
                rejection: EpochRejection {
                    rejection_reason: EpochRejectionReason::FutureEpoch,
                    ..
                }
            }
        ));
    }

    #[test]
    fn expired_lease_rejection_precedes_object_mismatch() {
        let mut fs = FenceState::new("obj-expired-first".into());
        let lease = fs.acquire_lease(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2026-02-01T00:00:00Z".into(),
        );
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: "different-object".into(),
            payload: json!({}),
        };

        let err = fs
            .validate_write(&write, &lease, "2026-03-01T00:00:00Z")
            .unwrap_err();

        assert!(matches!(err, FencingError::LeaseExpired { .. }));
    }

    #[test]
    fn stale_fence_error_reports_write_and_current_sequences() {
        let mut fs = FenceState::new("obj-stale-fields".into());
        let _old = fs.acquire_lease(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
        );
        let current = fs.acquire_lease(
            "writer-b".into(),
            "2026-01-02T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
        );
        let write = FencedWrite {
            fence_seq: Some(0),
            target_object_id: "obj-stale-fields".into(),
            payload: json!({}),
        };

        let err = fs
            .validate_write(&write, &current, "2026-06-01T00:00:00Z")
            .unwrap_err();

        assert_eq!(
            err,
            FencingError::WriteStaleFence {
                write_seq: 0,
                current_seq: 2
            }
        );
    }

    #[test]
    fn object_mismatch_error_display_includes_both_object_ids() {
        let err = FencingError::LeaseObjectMismatch {
            lease_object: "lease-object".into(),
            target_object: "target-object".into(),
        };

        let rendered = err.to_string();

        assert!(rendered.contains("LEASE_OBJECT_MISMATCH"));
        assert!(rendered.contains("lease-object"));
        assert!(rendered.contains("target-object"));
        assert_eq!(err.epoch_event_code(), None);
    }

    #[test]
    fn non_epoch_fencing_errors_have_no_epoch_event_code() {
        let errors = [
            FencingError::WriteUnfenced,
            FencingError::WriteStaleFence {
                write_seq: 1,
                current_seq: 2,
            },
            FencingError::WriteFenceMismatch {
                write_seq: 3,
                lease_seq: 2,
                current_seq: 3,
            },
            FencingError::LeaseExpired {
                expires_at: "2026-01-01T00:00:00Z".into(),
                current_time: "2026-01-01T00:00:00Z".into(),
            },
            FencingError::LeaseObjectMismatch {
                lease_object: "a".into(),
                target_object: "b".into(),
            },
        ];

        assert!(errors.iter().all(|err| err.epoch_event_code().is_none()));
    }

    #[test]
    fn rejection_receipt_can_capture_unfenced_write_context() {
        let receipt = RejectionReceipt {
            object_id: "obj-rejected".into(),
            error: FencingError::WriteUnfenced,
            write_seq: None,
            current_fence_seq: 7,
            timestamp: "2026-06-01T00:00:00Z".into(),
        };

        assert_eq!(receipt.write_seq, None);
        assert_eq!(receipt.current_fence_seq, 7);
        assert_eq!(
            receipt.error.to_string(),
            "WRITE_UNFENCED: write has no fence token"
        );
    }

    #[test]
    fn unfenced_write_rejection_precedes_expired_lease() {
        let mut fs = FenceState::new("obj-unfenced-first".into());
        let lease = fs.acquire_lease(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2026-02-01T00:00:00Z".into(),
        );
        let write = FencedWrite {
            fence_seq: None,
            target_object_id: "obj-unfenced-first".into(),
            payload: json!({}),
        };

        let err = fs
            .validate_write(&write, &lease, "2026-03-01T00:00:00Z")
            .unwrap_err();

        assert_eq!(err, FencingError::WriteUnfenced);
    }

    #[test]
    fn stale_fence_rejection_precedes_expired_lease() {
        let mut fs = FenceState::new("obj-stale-first".into());
        let _old = fs.acquire_lease(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2026-02-01T00:00:00Z".into(),
        );
        let current = fs.acquire_lease(
            "writer-b".into(),
            "2026-01-02T00:00:00Z".into(),
            "2026-02-01T00:00:00Z".into(),
        );
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: "obj-stale-first".into(),
            payload: json!({}),
        };

        let err = fs
            .validate_write(&write, &current, "2026-03-01T00:00:00Z")
            .unwrap_err();

        assert_eq!(
            err,
            FencingError::WriteStaleFence {
                write_seq: 1,
                current_seq: 2
            }
        );
    }

    #[test]
    fn future_epoch_rejection_preserves_fencing_artifact_context() {
        let mut fs = FenceState::new("obj-future-context".into());
        let lease = fs.acquire_lease_with_epoch(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
            ControlEpoch::new(9),
        );
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: "obj-future-context".into(),
            payload: json!({}),
        };
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(7), 1);

        let err = fs
            .validate_write_epoch_scoped(
                &write,
                &lease,
                "2026-06-01T00:00:00Z",
                &policy,
                "trace-future-context",
            )
            .unwrap_err();

        match err {
            FencingError::EpochRejected { rejection } => {
                assert_eq!(rejection.artifact_id, "fencing:obj-future-context:1");
                assert_eq!(rejection.artifact_epoch, ControlEpoch::new(9));
                assert_eq!(rejection.current_epoch, ControlEpoch::new(7));
                assert_eq!(
                    rejection.rejection_reason,
                    EpochRejectionReason::FutureEpoch
                );
                assert_eq!(rejection.trace_id, "trace-future-context");
            }
            _ => unreachable!("expected future epoch rejection"),
        }
    }

    #[test]
    fn epoch_scoped_validation_rejects_stale_fence_after_epoch_acceptance() {
        let mut fs = FenceState::new("obj-epoch-stale-fence".into());
        let _old = fs.acquire_lease_with_epoch(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
            ControlEpoch::new(5),
        );
        let lease = fs.acquire_lease_with_epoch(
            "writer-b".into(),
            "2026-01-02T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
            ControlEpoch::new(5),
        );
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: "obj-epoch-stale-fence".into(),
            payload: json!({}),
        };
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(5), 0);

        let err = fs
            .validate_write_epoch_scoped(
                &write,
                &lease,
                "2026-06-01T00:00:00Z",
                &policy,
                "trace-stale-fence",
            )
            .unwrap_err();

        assert_eq!(
            err,
            FencingError::WriteStaleFence {
                write_seq: 1,
                current_seq: 2
            }
        );
    }

    #[test]
    fn epoch_scoped_validation_rejects_expired_lease_after_epoch_acceptance() {
        let mut fs = FenceState::new("obj-epoch-expired-lease".into());
        let lease = fs.acquire_lease_with_epoch(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2026-02-01T00:00:00Z".into(),
            ControlEpoch::new(5),
        );
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: "obj-epoch-expired-lease".into(),
            payload: json!({}),
        };
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(5), 0);

        let err = fs
            .validate_write_epoch_scoped(
                &write,
                &lease,
                "2026-03-01T00:00:00Z",
                &policy,
                "trace-expired-lease",
            )
            .unwrap_err();

        assert_eq!(
            err,
            FencingError::LeaseExpired {
                expires_at: "2026-02-01T00:00:00Z".into(),
                current_time: "2026-03-01T00:00:00Z".into()
            }
        );
    }

    #[test]
    fn epoch_scoped_validation_rejects_object_mismatch_after_epoch_acceptance() {
        let mut fs = FenceState::new("obj-epoch-mismatch".into());
        let lease = fs.acquire_lease_with_epoch(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
            ControlEpoch::new(5),
        );
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: "obj-other".into(),
            payload: json!({}),
        };
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(5), 0);

        let err = fs
            .validate_write_epoch_scoped(
                &write,
                &lease,
                "2026-06-01T00:00:00Z",
                &policy,
                "trace-object-mismatch",
            )
            .unwrap_err();

        assert_eq!(
            err,
            FencingError::LeaseObjectMismatch {
                lease_object: "obj-epoch-mismatch".into(),
                target_object: "obj-other".into()
            }
        );
    }

    #[test]
    fn future_fence_sequence_rejected_without_waiting_for_expiry() {
        let mut fs = FenceState::new("obj-future-fence".into());
        let lease = fs.acquire_lease(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2026-02-01T00:00:00Z".into(),
        );
        let write = FencedWrite {
            fence_seq: Some(2),
            target_object_id: "obj-future-fence".into(),
            payload: json!({}),
        };

        let err = fs
            .validate_write(&write, &lease, "2026-03-01T00:00:00Z")
            .unwrap_err();

        assert_eq!(
            err,
            FencingError::WriteFenceMismatch {
                write_seq: 2,
                lease_seq: 1,
                current_seq: 1
            }
        );
    }

    #[test]
    fn stale_lease_with_current_write_sequence_is_rejected() {
        let mut fs = FenceState::new("obj-stale-lease".into());
        let stale_lease = fs.acquire_lease(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
        );
        let _current_lease = fs.acquire_lease(
            "writer-b".into(),
            "2026-01-02T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
        );
        let write = FencedWrite {
            fence_seq: Some(2),
            target_object_id: "obj-stale-lease".into(),
            payload: json!({}),
        };

        let err = fs
            .validate_write(&write, &stale_lease, "2026-06-01T00:00:00Z")
            .unwrap_err();

        assert_eq!(
            err,
            FencingError::WriteFenceMismatch {
                write_seq: 2,
                lease_seq: 1,
                current_seq: 2
            }
        );
    }

    #[test]
    fn fence_mismatch_error_display_includes_all_sequences() {
        let err = FencingError::WriteFenceMismatch {
            write_seq: 9,
            lease_seq: 4,
            current_seq: 7,
        };

        let rendered = err.to_string();

        assert!(rendered.contains("WRITE_FENCE_MISMATCH"));
        assert!(rendered.contains("write seq 9"));
        assert!(rendered.contains("lease seq 4"));
        assert!(rendered.contains("current fence 7"));
        assert_eq!(err.epoch_event_code(), None);
    }

    #[test]
    fn epoch_scoped_validation_rejects_lease_sequence_mismatch_after_epoch_acceptance() {
        let mut fs = FenceState::new("obj-epoch-stale-lease".into());
        let stale_lease = fs.acquire_lease_with_epoch(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
            ControlEpoch::new(5),
        );
        let _current_lease = fs.acquire_lease_with_epoch(
            "writer-b".into(),
            "2026-01-02T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
            ControlEpoch::new(5),
        );
        let write = FencedWrite {
            fence_seq: Some(2),
            target_object_id: "obj-epoch-stale-lease".into(),
            payload: json!({}),
        };
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(5), 0);

        let err = fs
            .validate_write_epoch_scoped(
                &write,
                &stale_lease,
                "2026-06-01T00:00:00Z",
                &policy,
                "trace-stale-lease",
            )
            .unwrap_err();

        assert_eq!(
            err,
            FencingError::WriteFenceMismatch {
                write_seq: 2,
                lease_seq: 1,
                current_seq: 2
            }
        );
    }

    #[test]
    fn fence_mismatch_precedes_object_mismatch_for_forged_current_sequence() {
        let mut fs = FenceState::new("obj-mismatch-first".into());
        let stale_lease = fs.acquire_lease(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
        );
        let _current_lease = fs.acquire_lease(
            "writer-b".into(),
            "2026-01-02T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
        );
        let write = FencedWrite {
            fence_seq: Some(2),
            target_object_id: "different-object".into(),
            payload: json!({}),
        };

        let err = fs
            .validate_write(&write, &stale_lease, "2026-06-01T00:00:00Z")
            .unwrap_err();

        assert!(matches!(err, FencingError::WriteFenceMismatch { .. }));
    }

    #[test]
    fn fence_mismatch_precedes_expired_lease_for_forged_current_sequence() {
        let mut fs = FenceState::new("obj-expired-mismatch-first".into());
        let stale_lease = fs.acquire_lease(
            "writer-a".into(),
            "2026-01-01T00:00:00Z".into(),
            "2026-02-01T00:00:00Z".into(),
        );
        let _current_lease = fs.acquire_lease(
            "writer-b".into(),
            "2026-01-02T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
        );
        let write = FencedWrite {
            fence_seq: Some(2),
            target_object_id: "obj-expired-mismatch-first".into(),
            payload: json!({}),
        };

        let err = fs
            .validate_write(&write, &stale_lease, "2026-03-01T00:00:00Z")
            .unwrap_err();

        assert!(matches!(err, FencingError::WriteFenceMismatch { .. }));
    }

    #[test]
    fn foreign_lease_rejected_even_when_write_sequence_matches_foreign_lease() {
        let fs = FenceState::new("obj-local".into());
        let foreign_lease = Lease {
            lease_seq: 1,
            object_id: "obj-local".into(),
            epoch: ControlEpoch::GENESIS,
            holder_id: "writer-foreign".into(),
            acquired_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2030-01-01T00:00:00Z".into(),
        };
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: "obj-local".into(),
            payload: json!({}),
        };

        let err = fs
            .validate_write(&write, &foreign_lease, "2026-06-01T00:00:00Z")
            .unwrap_err();

        assert_eq!(
            err,
            FencingError::WriteFenceMismatch {
                write_seq: 1,
                lease_seq: 1,
                current_seq: 0
            }
        );
    }

    #[test]
    fn negative_foreign_zero_sequence_lease_cannot_write_other_object() {
        let fs = FenceState::new("obj-local-zero".into());
        let foreign_lease = Lease {
            lease_seq: 0,
            object_id: "obj-foreign-zero".into(),
            epoch: ControlEpoch::GENESIS,
            holder_id: "writer-foreign".into(),
            acquired_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2030-01-01T00:00:00Z".into(),
        };
        let write = FencedWrite {
            fence_seq: Some(0),
            target_object_id: "obj-foreign-zero".into(),
            payload: json!({}),
        };

        let err = fs
            .validate_write(&write, &foreign_lease, "2026-06-01T00:00:00Z")
            .unwrap_err();

        assert_eq!(
            err,
            FencingError::LeaseObjectMismatch {
                lease_object: "obj-local-zero".into(),
                target_object: "obj-foreign-zero".into()
            }
        );
    }

    #[test]
    fn negative_foreign_current_sequence_lease_cannot_pivot_target_object() {
        let mut fs = FenceState::new("obj-local-current".into());
        let _local_lease = fs.acquire_lease(
            "writer-local".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
        );
        let foreign_lease = Lease {
            lease_seq: 1,
            object_id: "obj-foreign-current".into(),
            epoch: ControlEpoch::GENESIS,
            holder_id: "writer-foreign".into(),
            acquired_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2030-01-01T00:00:00Z".into(),
        };
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: "obj-foreign-current".into(),
            payload: json!({}),
        };

        let err = fs
            .validate_write(&write, &foreign_lease, "2026-06-01T00:00:00Z")
            .unwrap_err();

        assert!(matches!(err, FencingError::LeaseObjectMismatch { .. }));
    }

    #[test]
    fn negative_empty_target_object_rejected_even_with_matching_forged_lease() {
        let mut fs = FenceState::new("obj-nonempty".into());
        let _local_lease = fs.acquire_lease(
            "writer-local".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
        );
        let forged_lease = Lease {
            lease_seq: 1,
            object_id: String::new(),
            epoch: ControlEpoch::GENESIS,
            holder_id: "writer-forged".into(),
            acquired_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2030-01-01T00:00:00Z".into(),
        };
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: String::new(),
            payload: json!({}),
        };

        let err = fs
            .validate_write(&write, &forged_lease, "2026-06-01T00:00:00Z")
            .unwrap_err();

        assert_eq!(
            err,
            FencingError::LeaseObjectMismatch {
                lease_object: "obj-nonempty".into(),
                target_object: String::new()
            }
        );
    }

    #[test]
    fn negative_epoch_scoped_foreign_target_rejected_after_epoch_acceptance() {
        let mut fs = FenceState::new("obj-epoch-local".into());
        let _local_lease = fs.acquire_lease_with_epoch(
            "writer-local".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
            ControlEpoch::new(5),
        );
        let foreign_lease = Lease {
            lease_seq: 1,
            object_id: "obj-epoch-foreign".into(),
            epoch: ControlEpoch::new(5),
            holder_id: "writer-foreign".into(),
            acquired_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2030-01-01T00:00:00Z".into(),
        };
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: "obj-epoch-foreign".into(),
            payload: json!({}),
        };
        let policy = ValidityWindowPolicy::new(ControlEpoch::new(5), 0);

        let err = fs
            .validate_write_epoch_scoped(
                &write,
                &foreign_lease,
                "2026-06-01T00:00:00Z",
                &policy,
                "trace-epoch-foreign",
            )
            .unwrap_err();

        assert_eq!(
            err,
            FencingError::LeaseObjectMismatch {
                lease_object: "obj-epoch-local".into(),
                target_object: "obj-epoch-foreign".into()
            }
        );
    }

    #[test]
    fn negative_expired_foreign_lease_still_fails_closed_at_expiry_boundary() {
        let mut fs = FenceState::new("obj-expired-local".into());
        let _local_lease = fs.acquire_lease(
            "writer-local".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
        );
        let foreign_lease = Lease {
            lease_seq: 1,
            object_id: "obj-expired-foreign".into(),
            epoch: ControlEpoch::GENESIS,
            holder_id: "writer-foreign".into(),
            acquired_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2026-06-01T00:00:00Z".into(),
        };
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: "obj-expired-foreign".into(),
            payload: json!({}),
        };

        let err = fs
            .validate_write(&write, &foreign_lease, "2026-06-01T00:00:00Z")
            .unwrap_err();

        assert_eq!(
            err,
            FencingError::LeaseExpired {
                expires_at: "2026-06-01T00:00:00Z".into(),
                current_time: "2026-06-01T00:00:00Z".into()
            }
        );
    }

    #[test]
    fn negative_state_object_mismatch_precedes_forged_lease_object_mismatch() {
        let mut fs = FenceState::new("obj-state".into());
        let _local_lease = fs.acquire_lease(
            "writer-local".into(),
            "2026-01-01T00:00:00Z".into(),
            "2030-01-01T00:00:00Z".into(),
        );
        let forged_lease = Lease {
            lease_seq: 1,
            object_id: "obj-lease".into(),
            epoch: ControlEpoch::GENESIS,
            holder_id: "writer-forged".into(),
            acquired_at: "2026-01-01T00:00:00Z".into(),
            expires_at: "2030-01-01T00:00:00Z".into(),
        };
        let write = FencedWrite {
            fence_seq: Some(1),
            target_object_id: "obj-target".into(),
            payload: json!({}),
        };

        let err = fs
            .validate_write(&write, &forged_lease, "2026-06-01T00:00:00Z")
            .unwrap_err();

        assert_eq!(
            err,
            FencingError::LeaseObjectMismatch {
                lease_object: "obj-state".into(),
                target_object: "obj-target".into()
            }
        );
    }
}
