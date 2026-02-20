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
        self.current_seq += 1;
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

        // Check lease expiry
        if current_time > lease.expires_at.as_str() {
            return Err(FencingError::LeaseExpired {
                expires_at: lease.expires_at.clone(),
                current_time: current_time.to_string(),
            });
        }

        // Check object linkage
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
            _ => panic!("expected epoch rejection"),
        }
    }
}
