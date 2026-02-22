//! bd-2gr: product-layer epoch guard for trust-sensitive operations.
//!
//! Enforces fail-closed epoch validation for operation/artifact admission and
//! exposes stable rejection codes (`STALE_EPOCH_REJECTED`, `FUTURE_EPOCH_REJECTED`).
//! Also wires epoch-scoped signing/verification through bd-3cs3 primitives.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::control_plane::control_epoch::{
    ControlEpoch, EpochArtifactEvent, EpochRejection, EpochRejectionReason, ValidityWindowPolicy,
    check_artifact_epoch,
};
use crate::security::epoch_scoped_keys::{
    AuthError, RootSecret, Signature, sign_epoch_artifact, verify_epoch_signature,
};

pub const EPOCH_OPERATION_ACCEPTED: &str = "EPOCH_OPERATION_ACCEPTED";
pub const STALE_EPOCH_REJECTED: &str = "STALE_EPOCH_REJECTED";
pub const FUTURE_EPOCH_REJECTED: &str = "FUTURE_EPOCH_REJECTED";
pub const EPOCH_UNAVAILABLE: &str = "EPOCH_UNAVAILABLE";
pub const EPOCH_SIGNATURE_VERIFIED: &str = "EPOCH_SIGNATURE_VERIFIED";
pub const EPOCH_SIGNATURE_REJECTED: &str = "EPOCH_SIGNATURE_REJECTED";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochGuardEvent {
    pub event_code: String,
    pub artifact_id: Option<String>,
    pub current_epoch: u64,
    pub presented_epoch: Option<u64>,
    pub detail: String,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EpochGuardError {
    EpochUnavailable {
        detail: String,
    },
    EpochMismatch {
        presented_epoch: ControlEpoch,
        current_epoch: ControlEpoch,
    },
    FutureEpochRejected {
        presented_epoch: ControlEpoch,
        current_epoch: ControlEpoch,
    },
    ArtifactRejected(EpochRejection),
    SignatureRejected {
        reason: String,
    },
}

impl EpochGuardError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::EpochUnavailable { .. } => EPOCH_UNAVAILABLE,
            Self::EpochMismatch { .. } => STALE_EPOCH_REJECTED,
            Self::FutureEpochRejected { .. } => FUTURE_EPOCH_REJECTED,
            Self::ArtifactRejected(rejection) => match rejection.rejection_reason {
                EpochRejectionReason::FutureEpoch => FUTURE_EPOCH_REJECTED,
                EpochRejectionReason::ExpiredEpoch => STALE_EPOCH_REJECTED,
            },
            Self::SignatureRejected { .. } => EPOCH_SIGNATURE_REJECTED,
        }
    }
}

impl fmt::Display for EpochGuardError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EpochUnavailable { detail } => {
                write!(f, "{}: {detail}", self.code())
            }
            Self::EpochMismatch {
                presented_epoch,
                current_epoch,
            } => write!(
                f,
                "{}: presented epoch {} is stale (current={})",
                self.code(),
                presented_epoch.value(),
                current_epoch.value()
            ),
            Self::FutureEpochRejected {
                presented_epoch,
                current_epoch,
            } => write!(
                f,
                "{}: presented epoch {} is in the future (current={})",
                self.code(),
                presented_epoch.value(),
                current_epoch.value()
            ),
            Self::ArtifactRejected(rejection) => write!(
                f,
                "{}: artifact={} artifact_epoch={} current_epoch={}",
                self.code(),
                rejection.artifact_id,
                rejection.artifact_epoch.value(),
                rejection.current_epoch.value()
            ),
            Self::SignatureRejected { reason } => {
                write!(f, "{}: {reason}", self.code())
            }
        }
    }
}

impl std::error::Error for EpochGuardError {}

impl From<EpochRejection> for EpochGuardError {
    fn from(value: EpochRejection) -> Self {
        Self::ArtifactRejected(value)
    }
}

impl From<AuthError> for EpochGuardError {
    fn from(value: AuthError) -> Self {
        Self::SignatureRejected {
            reason: value.to_string(),
        }
    }
}

pub trait EpochSource {
    fn current_epoch(&self) -> Result<ControlEpoch, EpochGuardError>;
}

impl EpochSource for ControlEpoch {
    fn current_epoch(&self) -> Result<ControlEpoch, EpochGuardError> {
        Ok(*self)
    }
}

#[derive(Debug, Clone)]
pub struct StaticEpochSource {
    epoch: ControlEpoch,
    available: bool,
}

impl StaticEpochSource {
    #[must_use]
    pub fn available(epoch: ControlEpoch) -> Self {
        Self {
            epoch,
            available: true,
        }
    }

    #[must_use]
    pub fn unavailable(epoch: ControlEpoch) -> Self {
        Self {
            epoch,
            available: false,
        }
    }

    pub fn set_epoch(&mut self, epoch: ControlEpoch) {
        self.epoch = epoch;
    }
}

impl EpochSource for StaticEpochSource {
    fn current_epoch(&self) -> Result<ControlEpoch, EpochGuardError> {
        if self.available {
            Ok(self.epoch)
        } else {
            Err(EpochGuardError::EpochUnavailable {
                detail: "epoch source unavailable".to_string(),
            })
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EpochTaggedArtifact {
    artifact_id: String,
    creation_epoch: ControlEpoch,
    domain: String,
    payload: Vec<u8>,
    signature: Signature,
}

impl EpochTaggedArtifact {
    pub fn new_signed(
        artifact_id: &str,
        creation_epoch: ControlEpoch,
        domain: &str,
        payload: Vec<u8>,
        root_secret: &RootSecret,
    ) -> Result<Self, EpochGuardError> {
        let signature = sign_epoch_artifact(&payload, creation_epoch, domain, root_secret)?;
        Ok(Self {
            artifact_id: artifact_id.to_string(),
            creation_epoch,
            domain: domain.to_string(),
            payload,
            signature,
        })
    }

    #[must_use]
    pub fn artifact_id(&self) -> &str {
        &self.artifact_id
    }

    #[must_use]
    pub fn creation_epoch(&self) -> ControlEpoch {
        self.creation_epoch
    }

    #[must_use]
    pub fn domain(&self) -> &str {
        &self.domain
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    #[must_use]
    pub fn signature(&self) -> &Signature {
        &self.signature
    }
}

#[derive(Debug, Clone)]
pub struct EpochGuard {
    max_lookback: u64,
}

impl EpochGuard {
    #[must_use]
    pub fn new(max_lookback: u64) -> Self {
        Self { max_lookback }
    }

    #[must_use]
    pub fn max_lookback(&self) -> u64 {
        self.max_lookback
    }

    pub fn validate_operation_epoch<S: EpochSource>(
        &self,
        presented_epoch: ControlEpoch,
        source: &S,
        trace_id: &str,
    ) -> Result<EpochGuardEvent, EpochGuardError> {
        let current = source.current_epoch()?;
        if presented_epoch < current {
            return Err(EpochGuardError::EpochMismatch {
                presented_epoch,
                current_epoch: current,
            });
        }
        if presented_epoch > current {
            return Err(EpochGuardError::FutureEpochRejected {
                presented_epoch,
                current_epoch: current,
            });
        }
        Ok(EpochGuardEvent {
            event_code: EPOCH_OPERATION_ACCEPTED.to_string(),
            artifact_id: None,
            current_epoch: current.value(),
            presented_epoch: Some(presented_epoch.value()),
            detail: "operation bound to current epoch".to_string(),
            trace_id: trace_id.to_string(),
        })
    }

    pub fn validate_artifact_epoch<S: EpochSource>(
        &self,
        artifact_id: &str,
        artifact_epoch: ControlEpoch,
        source: &S,
        trace_id: &str,
    ) -> Result<EpochArtifactEvent, EpochGuardError> {
        let current = source.current_epoch()?;
        let policy = ValidityWindowPolicy::new(current, self.max_lookback);
        check_artifact_epoch(artifact_id, artifact_epoch, &policy, trace_id)
            .map_err(EpochGuardError::from)?;
        Ok(EpochArtifactEvent::accepted(
            artifact_id,
            artifact_epoch,
            current,
            trace_id,
        ))
    }

    pub fn verify_tagged_artifact<S: EpochSource>(
        &self,
        artifact: &EpochTaggedArtifact,
        source: &S,
        root_secret: &RootSecret,
        trace_id: &str,
    ) -> Result<Vec<EpochGuardEvent>, EpochGuardError> {
        let epoch_event = self.validate_artifact_epoch(
            artifact.artifact_id(),
            artifact.creation_epoch(),
            source,
            trace_id,
        )?;
        verify_epoch_signature(
            artifact.payload(),
            artifact.signature(),
            artifact.creation_epoch(),
            artifact.domain(),
            root_secret,
        )?;
        Ok(vec![
            EpochGuardEvent {
                event_code: epoch_event.event_code,
                artifact_id: Some(artifact.artifact_id().to_string()),
                current_epoch: epoch_event.current_epoch.value(),
                presented_epoch: Some(artifact.creation_epoch().value()),
                detail: "artifact epoch accepted".to_string(),
                trace_id: trace_id.to_string(),
            },
            EpochGuardEvent {
                event_code: EPOCH_SIGNATURE_VERIFIED.to_string(),
                artifact_id: Some(artifact.artifact_id().to_string()),
                current_epoch: source.current_epoch()?.value(),
                presented_epoch: Some(artifact.creation_epoch().value()),
                detail: "signature verified against epoch-scoped key".to_string(),
                trace_id: trace_id.to_string(),
            },
        ])
    }
}

impl Default for EpochGuard {
    fn default() -> Self {
        Self::new(1)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Instant;

    use super::*;
    use crate::security::epoch_scoped_keys::sign_epoch_artifact;

    fn root_secret() -> RootSecret {
        RootSecret::from_hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .expect("valid root secret")
    }

    #[test]
    fn operation_epoch_exact_match_passes() {
        let guard = EpochGuard::default();
        let source = StaticEpochSource::available(ControlEpoch::new(7));
        let event = guard
            .validate_operation_epoch(ControlEpoch::new(7), &source, "trace-op-ok")
            .expect("operation should pass");
        assert_eq!(event.event_code, EPOCH_OPERATION_ACCEPTED);
    }

    #[test]
    fn stale_epoch_operation_rejected() {
        let guard = EpochGuard::default();
        let source = StaticEpochSource::available(ControlEpoch::new(8));
        let err = guard
            .validate_operation_epoch(ControlEpoch::new(7), &source, "trace-op-stale")
            .expect_err("stale should reject");
        assert_eq!(err.code(), STALE_EPOCH_REJECTED);
    }

    #[test]
    fn future_epoch_operation_rejected() {
        let guard = EpochGuard::default();
        let source = StaticEpochSource::available(ControlEpoch::new(8));
        let err = guard
            .validate_operation_epoch(ControlEpoch::new(9), &source, "trace-op-future")
            .expect_err("future should reject");
        assert_eq!(err.code(), FUTURE_EPOCH_REJECTED);
    }

    #[test]
    fn fail_closed_when_epoch_source_unavailable() {
        let guard = EpochGuard::default();
        let source = StaticEpochSource::unavailable(ControlEpoch::new(8));
        let err = guard
            .validate_operation_epoch(ControlEpoch::new(8), &source, "trace-unavailable")
            .expect_err("unavailable must fail closed");
        assert_eq!(err.code(), EPOCH_UNAVAILABLE);
    }

    #[test]
    fn fail_closed_unavailable_returns_within_100ms() {
        let guard = EpochGuard::default();
        let source = StaticEpochSource::unavailable(ControlEpoch::new(8));
        let started = Instant::now();
        let err = guard
            .validate_operation_epoch(ControlEpoch::new(8), &source, "trace-unavailable-latency")
            .expect_err("unavailable must fail closed");
        assert_eq!(err.code(), EPOCH_UNAVAILABLE);
        assert!(
            started.elapsed().as_millis() < 100,
            "epoch unavailable path must return quickly"
        );
    }

    #[test]
    fn artifact_epoch_window_rejections_are_stable() {
        let guard = EpochGuard::new(1);
        let source = StaticEpochSource::available(ControlEpoch::new(10));

        let stale = guard
            .validate_artifact_epoch(
                "artifact-stale",
                ControlEpoch::new(7),
                &source,
                "trace-stale",
            )
            .expect_err("expired should reject");
        assert_eq!(stale.code(), STALE_EPOCH_REJECTED);

        let future = guard
            .validate_artifact_epoch(
                "artifact-future",
                ControlEpoch::new(11),
                &source,
                "trace-future",
            )
            .expect_err("future should reject");
        assert_eq!(future.code(), FUTURE_EPOCH_REJECTED);
    }

    #[test]
    fn epoch_scoped_signature_rejects_cross_epoch_verification() {
        let root = root_secret();
        let payload = b"artifact";
        let signature = sign_epoch_artifact(payload, ControlEpoch::new(5), "trust", &root).unwrap();
        let verify =
            verify_epoch_signature(payload, &signature, ControlEpoch::new(6), "trust", &root);
        assert!(
            verify.is_err(),
            "signature must fail under different epoch key"
        );
    }

    #[test]
    fn tagged_artifact_creation_epoch_is_preserved() {
        let root = root_secret();
        let artifact = EpochTaggedArtifact::new_signed(
            "artifact-1",
            ControlEpoch::new(9),
            "trust",
            b"hello".to_vec(),
            &root,
        )
        .unwrap();
        assert_eq!(artifact.creation_epoch(), ControlEpoch::new(9));
    }

    #[test]
    fn verify_tagged_artifact_emits_epoch_and_signature_events() {
        let root = root_secret();
        let guard = EpochGuard::new(1);
        let source = StaticEpochSource::available(ControlEpoch::new(9));
        let artifact = EpochTaggedArtifact::new_signed(
            "artifact-verify",
            ControlEpoch::new(9),
            "trust",
            b"payload".to_vec(),
            &root,
        )
        .expect("artifact signs");

        let events = guard
            .verify_tagged_artifact(&artifact, &source, &root, "trace-verify")
            .expect("artifact verifies");
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_code, "EPOCH_ARTIFACT_ACCEPTED");
        assert_eq!(events[1].event_code, EPOCH_SIGNATURE_VERIFIED);
    }
}
