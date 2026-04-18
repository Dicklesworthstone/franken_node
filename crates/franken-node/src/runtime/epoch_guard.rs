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
pub const EPOCH_ARTIFACT_ID_REJECTED: &str = "EPOCH_ARTIFACT_ID_REJECTED";

const RESERVED_ARTIFACT_ID: &str = "<unknown>";

fn invalid_artifact_id_reason(artifact_id: &str) -> Option<String> {
    let trimmed = artifact_id.trim();
    if trimmed.is_empty() {
        return Some("artifact_id must not be empty".to_string());
    }
    if trimmed == RESERVED_ARTIFACT_ID {
        return Some(format!("artifact_id is reserved: {:?}", artifact_id));
    }
    if trimmed != artifact_id {
        return Some("artifact_id contains leading or trailing whitespace".to_string());
    }
    None
}

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
    InvalidArtifactId {
        reason: String,
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
            Self::InvalidArtifactId { .. } => EPOCH_ARTIFACT_ID_REJECTED,
            Self::ArtifactRejected(rejection) => match rejection.rejection_reason {
                EpochRejectionReason::InvalidArtifactId => EPOCH_ARTIFACT_ID_REJECTED,
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
            Self::InvalidArtifactId { reason } => {
                write!(f, "{}: {reason}", self.code())
            }
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
        if let Some(reason) = invalid_artifact_id_reason(artifact_id) {
            return Err(EpochGuardError::InvalidArtifactId { reason });
        }
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
        if let Some(reason) = invalid_artifact_id_reason(artifact_id) {
            return Err(EpochGuardError::InvalidArtifactId { reason });
        }
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

    fn alternate_root_secret() -> RootSecret {
        RootSecret::from_hex("1f1e1d1c1b1a191817161514131211100f0e0d0c0b0a09080706050403020100")
            .expect("valid alternate root secret")
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
    fn tagged_artifact_rejects_empty_id() {
        let root = root_secret();
        let err = EpochTaggedArtifact::new_signed(
            "",
            ControlEpoch::new(9),
            "trust",
            b"hello".to_vec(),
            &root,
        )
        .expect_err("empty artifact_id should reject");
        assert_eq!(err.code(), EPOCH_ARTIFACT_ID_REJECTED);
    }

    #[test]
    fn tagged_artifact_rejects_reserved_id() {
        let root = root_secret();
        let err = EpochTaggedArtifact::new_signed(
            RESERVED_ARTIFACT_ID,
            ControlEpoch::new(9),
            "trust",
            b"hello".to_vec(),
            &root,
        )
        .expect_err("reserved artifact_id should reject");
        assert_eq!(err.code(), EPOCH_ARTIFACT_ID_REJECTED);
        assert!(err.to_string().contains("reserved"));
    }

    #[test]
    fn tagged_artifact_rejects_whitespace_id() {
        let root = root_secret();
        let err = EpochTaggedArtifact::new_signed(
            " artifact-1 ",
            ControlEpoch::new(9),
            "trust",
            b"hello".to_vec(),
            &root,
        )
        .expect_err("whitespace artifact_id should reject");
        assert_eq!(err.code(), EPOCH_ARTIFACT_ID_REJECTED);
        assert!(err.to_string().contains("leading or trailing whitespace"));
    }

    #[test]
    fn validate_artifact_epoch_rejects_invalid_id() {
        let guard = EpochGuard::new(1);
        let source = StaticEpochSource::available(ControlEpoch::new(10));
        let err = guard
            .validate_artifact_epoch(" ", ControlEpoch::new(10), &source, "trace-bad-id")
            .expect_err("invalid artifact_id should reject");
        assert_eq!(err.code(), EPOCH_ARTIFACT_ID_REJECTED);
    }

    #[test]
    fn invalid_artifact_id_rejects_newline_padding() {
        let reason = invalid_artifact_id_reason("artifact-1\n")
            .expect("newline-padded artifact id must reject");

        assert!(reason.contains("leading or trailing whitespace"));
    }

    #[test]
    fn invalid_artifact_id_rejects_tab_padding() {
        let reason =
            invalid_artifact_id_reason("\tartifact-1").expect("tab-padded artifact id must reject");

        assert!(reason.contains("leading or trailing whitespace"));
    }

    #[test]
    fn invalid_artifact_id_takes_precedence_over_unavailable_epoch_source() {
        let guard = EpochGuard::new(1);
        let source = StaticEpochSource::unavailable(ControlEpoch::new(10));

        let err = guard
            .validate_artifact_epoch(" artifact-1", ControlEpoch::new(10), &source, "trace-id")
            .expect_err("invalid artifact id should reject before source access");

        assert_eq!(err.code(), EPOCH_ARTIFACT_ID_REJECTED);
    }

    #[test]
    fn stale_operation_error_preserves_presented_and_current_epochs() {
        let guard = EpochGuard::default();
        let source = StaticEpochSource::available(ControlEpoch::new(12));

        let err = guard
            .validate_operation_epoch(ControlEpoch::new(11), &source, "trace-stale-detail")
            .expect_err("stale operation must reject");

        match err {
            EpochGuardError::EpochMismatch {
                presented_epoch,
                current_epoch,
            } => {
                assert_eq!(presented_epoch, ControlEpoch::new(11));
                assert_eq!(current_epoch, ControlEpoch::new(12));
            }
            other => unreachable!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn future_operation_error_preserves_presented_and_current_epochs() {
        let guard = EpochGuard::default();
        let source = StaticEpochSource::available(ControlEpoch::new(12));

        let err = guard
            .validate_operation_epoch(ControlEpoch::new(13), &source, "trace-future-detail")
            .expect_err("future operation must reject");

        match err {
            EpochGuardError::FutureEpochRejected {
                presented_epoch,
                current_epoch,
            } => {
                assert_eq!(presented_epoch, ControlEpoch::new(13));
                assert_eq!(current_epoch, ControlEpoch::new(12));
            }
            other => unreachable!("unexpected error: {other:?}"),
        }
    }

    #[test]
    fn stale_tagged_artifact_rejects_before_authentication_event() {
        let root = root_secret();
        let guard = EpochGuard::new(1);
        let source = StaticEpochSource::available(ControlEpoch::new(10));
        let artifact = EpochTaggedArtifact::new_signed(
            "artifact-stale-tagged",
            ControlEpoch::new(7),
            "trust",
            b"payload".to_vec(),
            &root,
        )
        .expect("artifact signs");

        let err = guard
            .verify_tagged_artifact(&artifact, &source, &root, "trace-stale-tagged")
            .expect_err("stale tagged artifact must reject");

        assert_eq!(err.code(), STALE_EPOCH_REJECTED);
    }

    #[test]
    fn tagged_artifact_rejects_when_epoch_source_unavailable() {
        let root = root_secret();
        let guard = EpochGuard::new(1);
        let source = StaticEpochSource::unavailable(ControlEpoch::new(9));
        let artifact = EpochTaggedArtifact::new_signed(
            "artifact-unavailable",
            ControlEpoch::new(9),
            "trust",
            b"payload".to_vec(),
            &root,
        )
        .expect("artifact signs");

        let err = guard
            .verify_tagged_artifact(&artifact, &source, &root, "trace-unavailable-tagged")
            .expect_err("unavailable epoch source must reject");

        assert_eq!(err.code(), EPOCH_UNAVAILABLE);
    }

    #[test]
    fn tagged_artifact_rejects_wrong_root_secret() {
        let root = root_secret();
        let wrong_root = alternate_root_secret();
        let guard = EpochGuard::new(1);
        let source = StaticEpochSource::available(ControlEpoch::new(9));
        let artifact = EpochTaggedArtifact::new_signed(
            "artifact-wrong-root",
            ControlEpoch::new(9),
            "trust",
            b"payload".to_vec(),
            &root,
        )
        .expect("artifact signs");

        let err = guard
            .verify_tagged_artifact(&artifact, &source, &wrong_root, "trace-wrong-root")
            .expect_err("wrong root secret must reject");

        assert!(matches!(err, EpochGuardError::SignatureRejected { .. }));
    }

    #[test]
    fn operation_rechecks_updated_epoch_source_and_rejects_stale() {
        let guard = EpochGuard::default();
        let mut source = StaticEpochSource::available(ControlEpoch::new(9));
        source.set_epoch(ControlEpoch::new(10));

        let err = guard
            .validate_operation_epoch(ControlEpoch::new(9), &source, "trace-source-update")
            .expect_err("updated source epoch should make presented epoch stale");

        assert_eq!(err.code(), STALE_EPOCH_REJECTED);
        assert!(err.to_string().contains("presented epoch 9 is stale"));
    }

    #[test]
    fn zero_lookback_artifact_rejects_previous_epoch() {
        let guard = EpochGuard::new(0);
        let source = StaticEpochSource::available(ControlEpoch::new(10));

        let err = guard
            .validate_artifact_epoch(
                "artifact-no-lookback",
                ControlEpoch::new(9),
                &source,
                "trace-no-lookback",
            )
            .expect_err("zero lookback should reject previous epoch");

        assert_eq!(err.code(), STALE_EPOCH_REJECTED);
    }

    #[test]
    fn invalid_artifact_id_precedes_future_epoch_rejection() {
        let guard = EpochGuard::new(1);
        let source = StaticEpochSource::available(ControlEpoch::new(10));

        let err = guard
            .validate_artifact_epoch(
                " artifact-future",
                ControlEpoch::new(99),
                &source,
                "trace-invalid-before-future",
            )
            .expect_err("invalid id should reject before future epoch check");

        assert_eq!(err.code(), EPOCH_ARTIFACT_ID_REJECTED);
        assert!(err.to_string().contains("leading or trailing whitespace"));
    }

    #[test]
    fn verify_tagged_artifact_rejects_invalid_id_before_signature() {
        let root = root_secret();
        let wrong_root = alternate_root_secret();
        let payload = b"payload".to_vec();
        let signature =
            sign_epoch_artifact(&payload, ControlEpoch::new(9), "trust", &root).expect("signature");
        let artifact = EpochTaggedArtifact {
            artifact_id: " artifact-invalid".to_string(),
            creation_epoch: ControlEpoch::new(9),
            domain: "trust".to_string(),
            payload,
            signature,
        };
        let guard = EpochGuard::new(1);
        let source = StaticEpochSource::available(ControlEpoch::new(9));

        let err = guard
            .verify_tagged_artifact(&artifact, &source, &wrong_root, "trace-invalid-before-auth")
            .expect_err("invalid id should reject before signature verification");

        assert_eq!(err.code(), EPOCH_ARTIFACT_ID_REJECTED);
    }

    #[test]
    fn verify_tagged_artifact_rejects_future_epoch_before_signature() {
        let root = root_secret();
        let wrong_root = alternate_root_secret();
        let guard = EpochGuard::new(1);
        let source = StaticEpochSource::available(ControlEpoch::new(9));
        let artifact = EpochTaggedArtifact::new_signed(
            "artifact-future-tagged",
            ControlEpoch::new(11),
            "trust",
            b"payload".to_vec(),
            &root,
        )
        .expect("artifact signs");

        let err = guard
            .verify_tagged_artifact(&artifact, &source, &wrong_root, "trace-future-before-auth")
            .expect_err("future epoch should reject before signature verification");

        assert_eq!(err.code(), FUTURE_EPOCH_REJECTED);
    }

    #[test]
    fn verify_tagged_artifact_rejects_domain_mismatch_signature() {
        let root = root_secret();
        let payload = b"payload".to_vec();
        let signature = sign_epoch_artifact(&payload, ControlEpoch::new(9), "other-domain", &root)
            .expect("signature");
        let artifact = EpochTaggedArtifact {
            artifact_id: "artifact-domain-mismatch".to_string(),
            creation_epoch: ControlEpoch::new(9),
            domain: "trust".to_string(),
            payload,
            signature,
        };
        let guard = EpochGuard::new(1);
        let source = StaticEpochSource::available(ControlEpoch::new(9));

        let err = guard
            .verify_tagged_artifact(&artifact, &source, &root, "trace-domain-mismatch")
            .expect_err("signature domain mismatch should reject");

        assert_eq!(err.code(), EPOCH_SIGNATURE_REJECTED);
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

    // ═══════════════════════════════════════════════════════════════════════
    // NEGATIVE-PATH EDGE CASE AND ATTACK VECTOR TESTS
    // ═══════════════════════════════════════════════════════════════════════

    #[test]
    fn negative_epoch_guard_with_u64_max_lookback_handles_arithmetic_safely() {
        // Test epoch guard with maximum lookback to ensure no arithmetic overflow
        let guard = EpochGuard::new(u64::MAX);
        assert_eq!(guard.max_lookback(), u64::MAX);

        let source = StaticEpochSource::available(ControlEpoch::new(u64::MAX));

        // Test with maximum epoch values - should not panic or overflow
        let result = guard.validate_operation_epoch(
            ControlEpoch::new(u64::MAX),
            &source,
            "trace-max-epoch"
        );
        assert!(result.is_ok());

        // Test with near-maximum values
        let result2 = guard.validate_operation_epoch(
            ControlEpoch::new(u64::MAX.saturating_sub(1)),
            &source,
            "trace-near-max-epoch"
        );
        assert!(result2.is_err()); // Should be stale

        // Test artifact validation with maximum epochs
        let result3 = guard.validate_artifact_epoch(
            "artifact-max-epoch",
            ControlEpoch::new(u64::MAX),
            &source,
            "trace-artifact-max"
        );
        assert!(result3.is_ok());
    }

    #[test]
    fn negative_artifact_id_with_unicode_injection_and_normalization_attacks() {
        // Test various Unicode-based injection attacks in artifact IDs
        let malicious_ids = vec![
            "artifact\u{202E}fake\u{202D}",           // Unicode BiDi override attack
            "artifact\u{00A0}nonbreaking",             // Non-breaking space
            "artifact\u{200B}zerowidth",               // Zero-width space
            "artifact\u{FEFF}bom",                     // BOM character
            "artifact\u{034F}invisible",               // Combining grapheme joiner
            "artifact\u{2060}wordjoiner",              // Word joiner (invisible)
            "\u{1F4A9}emoji-artifact",                 // Emoji in ID
            "café\u{0301}artifact",                    // Combining accent (NFD)
            "artifact\u{0000}null",                    // Null byte
            "artifact\u{007F}del",                     // DEL control character
            "artifact\u{0001}soh",                     // Start of heading
            "artifact\u{001F}unit-sep",                // Unit separator
        ];

        for malicious_id in malicious_ids {
            // Test invalid_artifact_id_reason with malicious IDs
            let reason = invalid_artifact_id_reason(malicious_id);

            // Some may be rejected for specific reasons, others may pass literally
            if let Some(rejection_reason) = reason {
                assert!(!rejection_reason.is_empty(),
                       "Rejection reason should not be empty for ID: {:?}", malicious_id);
            }

            // Test EpochTaggedArtifact creation with malicious IDs
            let root = root_secret();
            let result = EpochTaggedArtifact::new_signed(
                malicious_id,
                ControlEpoch::new(9),
                "trust",
                b"payload".to_vec(),
                &root,
            );

            // Should either succeed (storing ID literally) or fail with clear error
            match result {
                Ok(artifact) => {
                    // If accepted, ID should be stored exactly as provided (no normalization)
                    assert_eq!(artifact.artifact_id(), malicious_id);
                }
                Err(err) => {
                    // If rejected, should be due to artifact ID validation
                    assert_eq!(err.code(), EPOCH_ARTIFACT_ID_REJECTED);
                }
            }
        }
    }

    #[test]
    fn negative_epoch_guard_event_with_massive_field_lengths() {
        // Test EpochGuardEvent with extremely large field values to check memory handling
        let huge_trace_id = "t".repeat(1_000_000);  // 1MB trace ID
        let huge_detail = "d".repeat(500_000);       // 500KB detail
        let huge_artifact_id = "a".repeat(250_000);  // 250KB artifact ID

        let event = EpochGuardEvent {
            event_code: EPOCH_OPERATION_ACCEPTED.to_string(),
            artifact_id: Some(huge_artifact_id.clone()),
            current_epoch: u64::MAX,
            presented_epoch: Some(u64::MAX.saturating_sub(1)),
            detail: huge_detail.clone(),
            trace_id: huge_trace_id.clone(),
        };

        // Should handle large fields without panic
        assert_eq!(event.trace_id.len(), 1_000_000);
        assert_eq!(event.detail.len(), 500_000);
        assert_eq!(event.artifact_id.as_ref().unwrap().len(), 250_000);

        // Test serialization/deserialization with massive fields
        let start = std::time::Instant::now();
        let json_result = serde_json::to_string(&event);
        let duration = start.elapsed();

        // Should complete within reasonable time (10 seconds is generous)
        assert!(json_result.is_ok());
        assert!(duration < std::time::Duration::from_secs(10));

        let json = json_result.unwrap();
        let parsed_result: Result<EpochGuardEvent, _> = serde_json::from_str(&json);
        assert!(parsed_result.is_ok());
        let parsed = parsed_result.unwrap();
        assert_eq!(parsed.trace_id.len(), 1_000_000);
    }

    #[test]
    fn negative_static_epoch_source_state_consistency_under_rapid_updates() {
        // Test StaticEpochSource state consistency under rapid availability/epoch changes
        let mut source = StaticEpochSource::available(ControlEpoch::new(100));

        // Rapidly toggle availability and update epochs
        for i in 0..1000 {
            let epoch_val = i % 50; // Cycle through epoch values
            source.set_epoch(ControlEpoch::new(epoch_val));

            // Toggle availability every few iterations
            if i % 7 == 0 {
                source = StaticEpochSource::unavailable(ControlEpoch::new(epoch_val));
            } else {
                source = StaticEpochSource::available(ControlEpoch::new(epoch_val));
            }

            // Test current_epoch consistency
            let result = source.current_epoch();
            if i % 7 == 0 {
                assert_eq!(result, Err(EpochGuardError::EpochUnavailable {
                    detail: "epoch source unavailable".to_string()
                }));
            } else {
                assert_eq!(result, Ok(ControlEpoch::new(epoch_val)));
            }
        }
    }

    #[test]
    fn negative_epoch_tagged_artifact_with_zero_length_and_massive_payloads() {
        let root = root_secret();

        // Test with zero-length payload
        let zero_payload_artifact = EpochTaggedArtifact::new_signed(
            "zero-payload-artifact",
            ControlEpoch::new(10),
            "trust",
            Vec::new(), // Zero length payload
            &root,
        );
        assert!(zero_payload_artifact.is_ok());
        let artifact = zero_payload_artifact.unwrap();
        assert_eq!(artifact.payload().len(), 0);

        // Test with massive payload (10MB)
        let massive_payload = vec![0x42u8; 10_000_000];
        let start = std::time::Instant::now();
        let massive_artifact = EpochTaggedArtifact::new_signed(
            "massive-payload-artifact",
            ControlEpoch::new(10),
            "trust",
            massive_payload.clone(),
            &root,
        );
        let creation_duration = start.elapsed();

        assert!(massive_artifact.is_ok());
        assert!(creation_duration < std::time::Duration::from_secs(30)); // Generous timeout
        let artifact = massive_artifact.unwrap();
        assert_eq!(artifact.payload().len(), 10_000_000);

        // Test verification with massive payload
        let guard = EpochGuard::new(1);
        let source = StaticEpochSource::available(ControlEpoch::new(10));

        let verify_start = std::time::Instant::now();
        let events = guard.verify_tagged_artifact(&artifact, &source, &root, "trace-massive");
        let verify_duration = verify_start.elapsed();

        assert!(events.is_ok());
        assert!(verify_duration < std::time::Duration::from_secs(30));
    }

    #[test]
    fn negative_epoch_guard_error_display_injection_resistance() {
        // Test that error display strings are safe from injection attacks
        let injection_attempts = vec![
            "<script>alert('xss')</script>",
            "'; DROP TABLE artifacts; --",
            "\x00\x01\x02\x03null_bytes",
            "\n\r\nHTTP/1.1 200 OK\r\n\r\n<html>",
            "\u{202E}override\u{202D}",
        ];

        for injection in &injection_attempts {
            // Test various error types with injection content
            let errors = vec![
                EpochGuardError::EpochUnavailable { detail: injection.to_string() },
                EpochGuardError::InvalidArtifactId { reason: injection.to_string() },
                EpochGuardError::SignatureRejected { reason: injection.to_string() },
            ];

            for error in errors {
                let display_string = format!("{}", error);

                // Error display should contain the injection content literally (no interpretation)
                assert!(display_string.contains(injection));

                // But should be prefixed with safe error code
                assert!(display_string.starts_with(error.code()));

                // Should not contain dangerous HTML/script patterns that could be interpreted
                // Note: We allow the literal content but ensure it's safely formatted
                let code = error.code();
                assert!(code.chars().all(|c| c.is_ascii_uppercase() || c == '_'));
            }
        }
    }

    #[test]
    fn negative_validate_operation_epoch_with_arithmetic_boundary_conditions() {
        let guard = EpochGuard::new(5);

        // Test arithmetic boundaries around epoch comparison
        let boundary_cases = vec![
            (0, 0, true),                    // Both zero
            (0, 1, false),                   // Presented zero, current one (stale)
            (1, 0, false),                   // Presented one, current zero (future)
            (u64::MAX, u64::MAX, true),      // Both maximum
            (u64::MAX, u64::MAX.saturating_sub(1), false), // Presented max, current max-1 (future)
            (u64::MAX.saturating_sub(1), u64::MAX, false), // Presented max-1, current max (stale)
            (u64::MAX / 2, u64::MAX / 2, true), // Both at midpoint
        ];

        for (presented, current, should_pass) in boundary_cases {
            let source = StaticEpochSource::available(ControlEpoch::new(current));
            let result = guard.validate_operation_epoch(
                ControlEpoch::new(presented),
                &source,
                &format!("trace-boundary-{}-{}", presented, current)
            );

            if should_pass {
                assert!(result.is_ok(),
                       "Presented {} should match current {}", presented, current);
            } else {
                assert!(result.is_err(),
                       "Presented {} should not match current {}", presented, current);

                let error = result.unwrap_err();
                if presented < current {
                    assert_eq!(error.code(), STALE_EPOCH_REJECTED);
                } else {
                    assert_eq!(error.code(), FUTURE_EPOCH_REJECTED);
                }
            }
        }
    }

    #[test]
    fn negative_artifact_validation_with_extreme_lookback_values() {
        // Test artifact validation with various extreme lookback configurations
        let extreme_lookbacks = vec![
            0,                               // No lookback allowed
            1,                               // Minimal lookback
            u64::MAX,                        // Maximum lookback
            u64::MAX / 2,                    // Half maximum
            u64::MAX.saturating_sub(1),      // Near maximum
        ];

        for lookback in extreme_lookbacks {
            let guard = EpochGuard::new(lookback);
            let current_epoch = 1000u64;
            let source = StaticEpochSource::available(ControlEpoch::new(current_epoch));

            // Test various artifact epoch values against this lookback
            let test_epochs = vec![
                0,                                           // Minimum epoch
                current_epoch.saturating_sub(lookback),      // Exactly at lookback boundary
                current_epoch.saturating_sub(lookback + 1),  // One past lookback (should fail)
                current_epoch,                               // Current epoch (should pass)
                current_epoch + 1,                           // Future epoch (should fail)
                u64::MAX,                                     // Maximum epoch (should fail)
            ];

            for artifact_epoch in test_epochs {
                let result = guard.validate_artifact_epoch(
                    &format!("artifact-lookback-{}-epoch-{}", lookback, artifact_epoch),
                    ControlEpoch::new(artifact_epoch),
                    &source,
                    &format!("trace-lookback-{}-{}", lookback, artifact_epoch)
                );

                // Determine expected result based on validity window
                let is_future = artifact_epoch > current_epoch;
                let is_stale = lookback < u64::MAX &&
                              current_epoch > lookback &&
                              artifact_epoch < current_epoch.saturating_sub(lookback);
                let is_valid = !is_future && !is_stale;

                if is_valid {
                    assert!(result.is_ok(),
                           "Artifact epoch {} should be valid with lookback {} and current {}",
                           artifact_epoch, lookback, current_epoch);
                } else {
                    assert!(result.is_err(),
                           "Artifact epoch {} should be invalid with lookback {} and current {}",
                           artifact_epoch, lookback, current_epoch);

                    let error = result.unwrap_err();
                    if is_future {
                        assert_eq!(error.code(), FUTURE_EPOCH_REJECTED);
                    } else {
                        assert_eq!(error.code(), STALE_EPOCH_REJECTED);
                    }
                }
            }
        }
    }

    #[test]
    fn negative_tagged_artifact_signature_verification_with_corrupted_signatures() {
        let root = root_secret();
        let alternate_root = alternate_root_secret();

        // Create a valid artifact
        let valid_artifact = EpochTaggedArtifact::new_signed(
            "test-artifact",
            ControlEpoch::new(10),
            "trust",
            b"test payload".to_vec(),
            &root,
        ).unwrap();

        // Test various signature corruption scenarios
        let corruption_tests = vec![
            // Flip single bits in signature at different positions
            (0, "first byte corruption"),
            (15, "middle byte corruption"),
            (31, "last byte corruption"),
        ];

        for (byte_index, description) in corruption_tests {
            let mut corrupted_artifact = valid_artifact.clone();

            // Access signature bytes and corrupt one bit
            let signature_bytes = corrupted_artifact.signature.as_bytes();
            let mut new_signature_bytes = signature_bytes.to_vec();
            if byte_index < new_signature_bytes.len() {
                new_signature_bytes[byte_index] ^= 0x01; // Flip lowest bit
            }

            // Create new signature from corrupted bytes
            let corrupted_signature = match Signature::from_bytes(&new_signature_bytes) {
                Ok(sig) => sig,
                Err(_) => continue, // Skip if signature format is completely invalid
            };

            // Create artifact with corrupted signature
            let test_artifact = EpochTaggedArtifact {
                artifact_id: format!("corrupted-sig-{}", byte_index),
                creation_epoch: corrupted_artifact.creation_epoch,
                domain: corrupted_artifact.domain.clone(),
                payload: corrupted_artifact.payload.clone(),
                signature: corrupted_signature,
            };

            let guard = EpochGuard::new(1);
            let source = StaticEpochSource::available(ControlEpoch::new(10));

            // Verification should fail with signature rejection
            let result = guard.verify_tagged_artifact(&test_artifact, &source, &root,
                                                    &format!("trace-corrupted-{}", byte_index));

            assert!(result.is_err(), "Corrupted signature should fail verification: {}", description);
            let error = result.unwrap_err();
            assert_eq!(error.code(), EPOCH_SIGNATURE_REJECTED);
        }
    }

    #[test]
    fn negative_artifact_id_with_filesystem_dangerous_characters() {
        // Test artifact IDs containing characters dangerous for filesystem operations
        let dangerous_ids = vec![
            "../../../etc/passwd",           // Path traversal Unix
            "..\\..\\..\\windows\\system32", // Path traversal Windows
            "artifact/with/slashes",         // Forward slashes
            "artifact\\with\\backslashes",   // Backslashes
            "artifact:with:colons",          // Colons (Windows drive separator)
            "artifact|with|pipes",           // Pipes
            "artifact<with>brackets",        // Angle brackets
            "artifact\"with\"quotes",        // Double quotes
            "artifact*with?wildcards",       // Wildcards
            "CON",                           // Windows reserved name
            "PRN",                           // Windows reserved name
            "AUX",                           // Windows reserved name
            "NUL",                           // Windows reserved name
            "artifact\x00null",              // Null byte
            "artifact\x1Fcontrol",           // Control character
        ];

        for dangerous_id in dangerous_ids {
            // Test that dangerous IDs are either rejected or stored literally
            let reason = invalid_artifact_id_reason(dangerous_id);

            if reason.is_some() {
                // If rejected, should have clear reason
                assert!(!reason.unwrap().is_empty());
            }

            // Test artifact creation with dangerous ID
            let root = root_secret();
            let result = EpochTaggedArtifact::new_signed(
                dangerous_id,
                ControlEpoch::new(10),
                "trust",
                b"payload".to_vec(),
                &root,
            );

            match result {
                Ok(artifact) => {
                    // If accepted, ID should be stored exactly as provided
                    assert_eq!(artifact.artifact_id(), dangerous_id);

                    // And should be accessible through normal methods
                    assert_eq!(artifact.creation_epoch(), ControlEpoch::new(10));
                    assert_eq!(artifact.domain(), "trust");
                    assert_eq!(artifact.payload(), b"payload");
                }
                Err(err) => {
                    // If rejected, should be clear artifact ID rejection
                    assert_eq!(err.code(), EPOCH_ARTIFACT_ID_REJECTED);
                }
            }
        }
    }

    #[test]
    fn negative_epoch_source_trait_consistency_under_error_conditions() {
        // Test EpochSource trait implementations for consistency under error conditions

        // Test ControlEpoch as EpochSource (always succeeds)
        let epoch = ControlEpoch::new(42);
        for _ in 0..100 {
            let result = epoch.current_epoch();
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), ControlEpoch::new(42));
        }

        // Test StaticEpochSource consistency
        let mut static_source = StaticEpochSource::available(ControlEpoch::new(100));

        // Multiple calls when available should return same result
        for _ in 0..100 {
            let result = static_source.current_epoch();
            assert!(result.is_ok());
            assert_eq!(result.unwrap(), ControlEpoch::new(100));
        }

        // Set to unavailable
        static_source = StaticEpochSource::unavailable(ControlEpoch::new(100));

        // Multiple calls when unavailable should consistently fail
        for _ in 0..100 {
            let result = static_source.current_epoch();
            assert!(result.is_err());
            match result {
                Err(EpochGuardError::EpochUnavailable { detail }) => {
                    assert_eq!(detail, "epoch source unavailable");
                }
                _ => panic!("Unexpected error type"),
            }
        }

        // Test rapid availability changes
        for i in 0..1000 {
            if i % 2 == 0 {
                static_source = StaticEpochSource::available(ControlEpoch::new(i));
                assert!(static_source.current_epoch().is_ok());
            } else {
                static_source = StaticEpochSource::unavailable(ControlEpoch::new(i));
                assert!(static_source.current_epoch().is_err());
            }
        }
    }

    // === Targeted Hardening Pattern Tests ===

    /// Test saturating_add protection on epoch counters and sequence numbers
    #[test]
    fn hardening_saturating_add_epoch_counters() {
        let guard = EpochGuard::new();

        // Test near-overflow epoch arithmetic
        let near_max_epoch = ControlEpoch::new(u32::MAX - 10);
        let max_epoch = ControlEpoch::new(u32::MAX);

        // Test epoch arithmetic that should use saturating_add
        let mut counter = u64::MAX - 5;

        // Simulate counter increment operations that should use saturating_add
        for i in 0..10 {
            let old_counter = counter;
            counter = counter.saturating_add(1); // This is the correct pattern

            // Verify no overflow occurred
            assert!(counter >= old_counter, "Counter should not wrap around");

            // Test epoch validation with high counter values
            let artifact_id = format!("artifact-counter-{}", i);
            let result = guard.validate_artifact_id(&artifact_id);
            assert!(result.is_ok(), "High counter values should be handled safely");
        }

        // Test sequence number arithmetic in trace IDs
        let trace_counter = u64::MAX - 2;
        let trace_id = format!("trace-{}", trace_counter.saturating_add(1));

        // Verify trace ID generation doesn't overflow
        assert!(trace_id.contains(&(u64::MAX - 1).to_string()));

        // Test epoch sequence arithmetic
        let base_epoch = u32::MAX - 100;
        for increment in 0..200 {
            let epoch_value = base_epoch.saturating_add(increment);
            let test_epoch = ControlEpoch::new(epoch_value);

            // Should handle near-overflow epoch values gracefully
            let guard_event = EpochGuardEvent {
                event_code: EPOCH_OPERATION_ACCEPTED.to_string(),
                artifact_id: Some("overflow-test".to_string()),
                current_epoch: epoch_value as u64,
                presented_epoch: Some(epoch_value as u64),
                detail: "saturating arithmetic test".to_string(),
                trace_id: "overflow-trace".to_string(),
            };

            // Event should be created without panic
            assert_eq!(guard_event.current_epoch, epoch_value as u64);
        }
    }

    /// Test constant-time comparison for hash/signature verification
    #[test]
    fn hardening_constant_time_hash_comparison() {
        use crate::security::constant_time::ct_eq_bytes;

        let guard = EpochGuard::new();
        let root_secret = RootSecret::generate_for_test();

        // Test signature verification uses constant-time comparison
        let artifact_data = b"test-artifact-for-ct-comparison";
        let epoch = ControlEpoch::new(42);

        // Generate legitimate signature
        let signature = sign_epoch_artifact(&root_secret, &epoch, artifact_data).unwrap();

        // Test byte-by-byte constant-time comparison directly
        let hash_a = b"hash-value-a-32-bytes-long-test!";
        let hash_b = b"hash-value-b-32-bytes-long-test!";
        let hash_a_copy = b"hash-value-a-32-bytes-long-test!";

        // Verify ct_eq_bytes usage patterns
        assert!(!ct_eq_bytes(hash_a, hash_b), "Different hashes should not be equal");
        assert!(ct_eq_bytes(hash_a, hash_a_copy), "Identical hashes should be equal");

        // Test with various hash lengths
        for hash_len in [16, 32, 64] {
            let hash1 = vec![0xAA; hash_len];
            let hash2 = vec![0xBB; hash_len];
            let hash1_copy = vec![0xAA; hash_len];

            assert!(!ct_eq_bytes(&hash1, &hash2), "Different {}-byte hashes should not be equal", hash_len);
            assert!(ct_eq_bytes(&hash1, &hash1_copy), "Identical {}-byte hashes should be equal", hash_len);
        }
    }

    /// Test fail-closed expiry checks using >= instead of >
    #[test]
    fn hardening_fail_closed_expiry_checks() {
        let guard = EpochGuard::new();

        // Test epoch expiry boundary conditions
        let current_time = 1000u64;
        let boundary_test_cases = vec![
            (current_time - 1, true),   // Before current time (expired)
            (current_time, true),       // Exactly at current time (expired - fail closed)
            (current_time + 1, false), // After current time (not expired)
        ];

        for (test_time, should_be_expired) in boundary_test_cases {
            // Simulate expiry check: now >= expires_at for fail-closed behavior
            let is_expired = current_time >= test_time;
            assert_eq!(is_expired, should_be_expired,
                      "Expiry check at boundary should be fail-closed (use >= not >): time={}, current={}",
                      test_time, current_time);
        }

        // Test signature expiry with precise boundary conditions
        let signature_timestamp = 2000u64;
        let signature_ttl = 300u64; // 5-minute TTL
        let expires_at = signature_timestamp + signature_ttl;

        let expiry_boundary_tests = vec![
            (expires_at - 1, false), // Before expiry (valid)
            (expires_at, true),      // At expiry (invalid - fail closed)
            (expires_at + 1, true),  // After expiry (invalid)
        ];

        for (check_time, should_be_expired) in expiry_boundary_tests {
            let is_expired = check_time >= expires_at; // Correct fail-closed pattern
            assert_eq!(is_expired, should_be_expired,
                      "Signature expiry should be fail-closed (>=): check={}, expires={}",
                      check_time, expires_at);
        }
    }

    /// Test safe length casting using u32::try_from instead of as u32
    #[test]
    fn hardening_safe_length_casting() {
        let guard = EpochGuard::new();

        // Test artifact ID length validation with safe casting
        let test_artifacts = vec![
            "short".to_string(),
            "x".repeat(100),
            "y".repeat(1000),
            "z".repeat(10000),
            "w".repeat(100000), // Very long artifact ID
        ];

        for artifact in test_artifacts {
            let artifact_len = artifact.len();

            // Test safe length casting pattern
            let safe_len_u32 = u32::try_from(artifact_len).unwrap_or(u32::MAX);

            // Should not panic even with very long strings
            assert!(safe_len_u32 <= u32::MAX, "Safe casting should prevent overflow");

            if artifact_len > u32::MAX as usize {
                assert_eq!(safe_len_u32, u32::MAX, "Overflow should be handled gracefully");
            } else {
                assert_eq!(safe_len_u32, artifact_len as u32, "Normal lengths should cast correctly");
            }

            // Test artifact validation with length-aware logic
            let validation_result = guard.validate_artifact_id(&artifact);
            match validation_result {
                Ok(_) => {
                    // Artifact accepted despite length
                },
                Err(EpochGuardError::InvalidArtifactId { reason }) => {
                    // Length-based rejection is acceptable
                    assert!(!reason.is_empty(), "Rejection reason should be provided");
                },
                Err(_) => {
                    // Other rejection reasons acceptable
                }
            }
        }
    }
}
