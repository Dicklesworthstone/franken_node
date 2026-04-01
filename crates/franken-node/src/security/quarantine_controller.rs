//! bd-274s: Automated quarantine controller for Bayesian adversary risk.
//!
//! Applies deterministic thresholds to posterior risk values and emits signed
//! evidence entries for reproducible control actions:
//! `throttle`, `isolate`, `quarantine`, `revoke`.

use std::cmp::Ordering;

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
#[allow(unused_imports)]
use sha2::{Digest, Sha256};

use crate::security::adversary_graph::AdversaryPosterior;

pub const EVD_QUAR_CTRL_001: &str = "EVD-QUAR-CTRL-001";
pub const EVD_QUAR_CTRL_002: &str = "EVD-QUAR-CTRL-002";

#[derive(Debug, Clone, thiserror::Error, PartialEq)]
pub enum QuarantineControllerError {
    #[error("threshold `{name}` must be in [0.0, 1.0], got {value}")]
    InvalidThresholdValue { name: &'static str, value: f64 },
    #[error("threshold ordering must be throttle <= isolate <= quarantine <= revoke")]
    InvalidThresholdOrder,
    #[error("signing key must not be empty")]
    InvalidSigningKey,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ControlAction {
    Throttle,
    Isolate,
    Quarantine,
    Revoke,
}

impl ControlAction {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Throttle => "throttle",
            Self::Isolate => "isolate",
            Self::Quarantine => "quarantine",
            Self::Revoke => "revoke",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct QuarantineThresholdPolicy {
    pub throttle: f64,
    pub isolate: f64,
    pub quarantine: f64,
    pub revoke: f64,
}

impl Default for QuarantineThresholdPolicy {
    fn default() -> Self {
        Self {
            throttle: 0.45,
            isolate: 0.60,
            quarantine: 0.75,
            revoke: 0.90,
        }
    }
}

impl QuarantineThresholdPolicy {
    pub fn validate(&self) -> Result<(), QuarantineControllerError> {
        for (name, value) in [
            ("throttle", self.throttle),
            ("isolate", self.isolate),
            ("quarantine", self.quarantine),
            ("revoke", self.revoke),
        ] {
            if !(0.0..=1.0).contains(&value) {
                return Err(QuarantineControllerError::InvalidThresholdValue { name, value });
            }
        }

        if !(self.throttle <= self.isolate
            && self.isolate <= self.quarantine
            && self.quarantine <= self.revoke)
        {
            return Err(QuarantineControllerError::InvalidThresholdOrder);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedEvidenceEntry {
    pub event_code: String,
    pub principal_id: String,
    pub action: ControlAction,
    pub posterior: f64,
    pub trace_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlDecision {
    pub principal_id: String,
    pub action: ControlAction,
    pub posterior: f64,
    pub threshold: f64,
    pub signed_evidence: SignedEvidenceEntry,
}

#[derive(Debug, Clone)]
pub struct QuarantineController {
    policy: QuarantineThresholdPolicy,
    signing_key: String,
}

impl QuarantineController {
    pub fn new(
        policy: QuarantineThresholdPolicy,
        signing_key: impl Into<String>,
    ) -> Result<Self, QuarantineControllerError> {
        policy.validate()?;
        let signing_key = signing_key.into();
        if signing_key.is_empty() {
            return Err(QuarantineControllerError::InvalidSigningKey);
        }
        Ok(Self {
            policy,
            signing_key,
        })
    }

    #[must_use]
    pub fn policy(&self) -> &QuarantineThresholdPolicy {
        &self.policy
    }

    #[must_use]
    pub fn action_for_posterior(&self, posterior: f64) -> Option<ControlAction> {
        if !posterior.is_finite() || posterior >= self.policy.revoke {
            Some(ControlAction::Revoke)
        } else if posterior >= self.policy.quarantine {
            Some(ControlAction::Quarantine)
        } else if posterior >= self.policy.isolate {
            Some(ControlAction::Isolate)
        } else if posterior >= self.policy.throttle {
            Some(ControlAction::Throttle)
        } else {
            None
        }
    }

    #[must_use]
    pub fn decide_for_posterior(
        &self,
        principal_id: &str,
        posterior: f64,
        trace_id: &str,
    ) -> Option<ControlDecision> {
        let action = self.action_for_posterior(posterior)?;
        let threshold = match action {
            ControlAction::Throttle => self.policy.throttle,
            ControlAction::Isolate => self.policy.isolate,
            ControlAction::Quarantine => self.policy.quarantine,
            ControlAction::Revoke => self.policy.revoke,
        };
        let signed_evidence = SignedEvidenceEntry {
            event_code: EVD_QUAR_CTRL_001.to_string(),
            principal_id: principal_id.to_string(),
            action,
            posterior,
            trace_id: trace_id.to_string(),
            signature: self.sign_evidence(principal_id, action, posterior, trace_id),
        };

        Some(ControlDecision {
            principal_id: principal_id.to_string(),
            action,
            posterior,
            threshold,
            signed_evidence,
        })
    }

    #[must_use]
    pub fn evaluate_posteriors(&self, posteriors: &[AdversaryPosterior]) -> Vec<ControlDecision> {
        let mut decisions: Vec<ControlDecision> = posteriors
            .iter()
            .filter_map(|posterior| {
                self.decide_for_posterior(
                    &posterior.principal_id,
                    posterior.posterior,
                    &posterior.last_trace_id,
                )
            })
            .collect();

        // Deterministic output ordering for reproducible replay.
        decisions.sort_by(|left, right| {
            right
                .posterior
                .partial_cmp(&left.posterior)
                .unwrap_or(Ordering::Equal)
                .then_with(|| left.principal_id.cmp(&right.principal_id))
        });
        let _event_code = EVD_QUAR_CTRL_002;
        decisions
    }

    #[must_use]
    pub fn verify_signature(&self, entry: &SignedEvidenceEntry) -> bool {
        let expected = self.sign_evidence(
            &entry.principal_id,
            entry.action,
            entry.posterior,
            &entry.trace_id,
        );
        crate::security::constant_time::ct_eq(&entry.signature, &expected)
    }

    fn sign_evidence(
        &self,
        principal_id: &str,
        action: ControlAction,
        posterior: f64,
        trace_id: &str,
    ) -> String {
        let payload = format!(
            "{principal_id}|{}|{posterior:.12}|{trace_id}",
            action.as_str()
        );
        let mut mac = Hmac::<Sha256>::new_from_slice(self.signing_key.as_bytes())
            .expect("HMAC accepts arbitrary signing key lengths");
        mac.update(payload.as_bytes());
        let digest = mac.finalize().into_bytes();
        format!("sha256:{}", hex::encode(digest))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::Digest;

    fn posterior(principal_id: &str, posterior: f64, trace_id: &str) -> AdversaryPosterior {
        AdversaryPosterior {
            principal_id: principal_id.to_string(),
            alpha: 1,
            beta: 1,
            posterior,
            evidence_count: 1,
            last_trace_id: trace_id.to_string(),
            evidence_hash: "sha256:test".to_string(),
        }
    }

    #[test]
    fn invalid_policy_order_is_rejected() {
        let err = QuarantineController::new(
            QuarantineThresholdPolicy {
                throttle: 0.7,
                isolate: 0.6,
                quarantine: 0.8,
                revoke: 0.9,
            },
            "salt",
        )
        .expect_err("must reject invalid threshold order");
        assert_eq!(err, QuarantineControllerError::InvalidThresholdOrder);
    }

    #[test]
    fn empty_signing_key_is_rejected() {
        let err = QuarantineController::new(QuarantineThresholdPolicy::default(), "")
            .expect_err("must reject empty signing key");
        assert_eq!(err, QuarantineControllerError::InvalidSigningKey);
    }

    #[test]
    fn threshold_mapping_covers_all_actions() {
        let controller = QuarantineController::new(QuarantineThresholdPolicy::default(), "salt")
            .expect("controller");

        assert_eq!(
            controller.action_for_posterior(0.46),
            Some(ControlAction::Throttle)
        );
        assert_eq!(
            controller.action_for_posterior(0.61),
            Some(ControlAction::Isolate)
        );
        assert_eq!(
            controller.action_for_posterior(0.80),
            Some(ControlAction::Quarantine)
        );
        assert_eq!(
            controller.action_for_posterior(0.95),
            Some(ControlAction::Revoke)
        );
        assert_eq!(controller.action_for_posterior(0.10), None);
    }

    #[test]
    fn non_finite_posteriors_fail_closed_to_revoke() {
        let controller = QuarantineController::new(QuarantineThresholdPolicy::default(), "salt")
            .expect("controller");

        assert_eq!(
            controller.action_for_posterior(f64::NAN),
            Some(ControlAction::Revoke)
        );
        assert_eq!(
            controller.action_for_posterior(f64::NEG_INFINITY),
            Some(ControlAction::Revoke)
        );
        assert_eq!(
            controller.action_for_posterior(f64::INFINITY),
            Some(ControlAction::Revoke)
        );
    }

    #[test]
    fn signed_evidence_is_deterministic() {
        let controller = QuarantineController::new(QuarantineThresholdPolicy::default(), "salt")
            .expect("controller");
        let a = controller
            .decide_for_posterior("ext:a", 0.91, "trace-a")
            .expect("decision");
        let b = controller
            .decide_for_posterior("ext:a", 0.91, "trace-a")
            .expect("decision");
        assert_eq!(a.signed_evidence.signature, b.signed_evidence.signature);
    }

    #[test]
    fn signed_evidence_uses_hmac_not_plain_hash() {
        let controller = QuarantineController::new(QuarantineThresholdPolicy::default(), "salt")
            .expect("controller");
        let decision = controller
            .decide_for_posterior("ext:a", 0.91, "trace-a")
            .expect("decision");
        let plain_digest = format!(
            "sha256:{:x}",
            Sha256::digest(b"ext:a|revoke|0.910000000000|trace-a")
        );

        assert_ne!(decision.signed_evidence.signature, plain_digest);
    }

    #[test]
    fn signature_verification_detects_tampering() {
        let controller = QuarantineController::new(QuarantineThresholdPolicy::default(), "salt")
            .expect("controller");
        let mut decision = controller
            .decide_for_posterior("ext:a", 0.91, "trace-a")
            .expect("decision");

        assert!(controller.verify_signature(&decision.signed_evidence));

        decision.signed_evidence.trace_id = "trace-b".to_string();
        assert!(!controller.verify_signature(&decision.signed_evidence));
    }

    #[test]
    fn evaluate_posteriors_returns_deterministic_order() {
        let controller = QuarantineController::new(QuarantineThresholdPolicy::default(), "salt")
            .expect("controller");

        let decisions = controller.evaluate_posteriors(&[
            posterior("ext:a", 0.66, "trace-a"),
            posterior("ext:c", 0.95, "trace-c"),
            posterior("ext:b", 0.80, "trace-b"),
        ]);

        let ids: Vec<&str> = decisions.iter().map(|d| d.principal_id.as_str()).collect();
        assert_eq!(ids, vec!["ext:c", "ext:b", "ext:a"]);
    }
}
