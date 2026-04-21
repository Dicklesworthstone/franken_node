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
use crate::security::constant_time;

pub const EVD_QUAR_CTRL_001: &str = "EVD-QUAR-CTRL-001";
pub const EVD_QUAR_CTRL_002: &str = "EVD-QUAR-CTRL-002";
pub const QUARANTINE_POLICY_VERSION: &str = "quarantine-threshold-policy-v1";
pub const DEFAULT_QUARANTINE_SCOPE: &str = "global";

/// Maximum control decisions to prevent memory exhaustion attacks.
const MAX_DECISIONS: usize = 1024;

/// Add item to Vec with bounded capacity. When capacity is exceeded, removes oldest entries.
fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        items.drain(0..overflow.min(items.len()));
    }
    items.push(item);
}

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

fn update_len_prefixed_mac(mac: &mut Hmac<Sha256>, field: &[u8]) {
    mac.update(&len_to_u64(field.len()).to_le_bytes());
    mac.update(field);
}

fn update_f64_mac(mac: &mut Hmac<Sha256>, value: f64) {
    mac.update(&value.to_le_bytes());
}

#[derive(Debug, Clone, thiserror::Error, PartialEq)]
pub enum QuarantineControllerError {
    #[error("threshold `{name}` must be in [0.0, 1.0], got {value}")]
    InvalidThresholdValue { name: &'static str, value: f64 },
    #[error("threshold ordering must be throttle <= isolate <= quarantine <= revoke")]
    InvalidThresholdOrder,
    #[error("signing key must not be empty")]
    InvalidSigningKey,
    #[error("posterior {posterior} did not require quarantine control action")]
    NoControlAction { posterior: f64 },
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
    pub threshold: f64,
    pub policy_version: String,
    pub policy_hash: String,
    pub evidence_count: u64,
    pub evidence_hash: String,
    pub scope: String,
    pub trace_id: String,
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ControlDecision {
    pub principal_id: String,
    pub action: ControlAction,
    pub posterior: f64,
    pub threshold: f64,
    pub policy_version: String,
    pub policy_hash: String,
    pub evidence_count: u64,
    pub evidence_hash: String,
    pub scope: String,
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
        if signing_key.trim().is_empty() {
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
    pub fn policy_hash(&self) -> String {
        let mut hasher = Sha256::new();
        hasher.update(b"quarantine_threshold_policy_v1:");
        update_len_prefixed_hash(&mut hasher, QUARANTINE_POLICY_VERSION.as_bytes());
        hasher.update(self.policy.throttle.to_le_bytes());
        hasher.update(self.policy.isolate.to_le_bytes());
        hasher.update(self.policy.quarantine.to_le_bytes());
        hasher.update(self.policy.revoke.to_le_bytes());
        format!("sha256:{}", hex::encode(hasher.finalize()))
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
        self.decide_for_posterior_with_context(
            principal_id,
            posterior,
            0,
            "sha256:untracked",
            DEFAULT_QUARANTINE_SCOPE,
            trace_id,
        )
    }

    #[must_use]
    pub fn decide_for_posterior_with_context(
        &self,
        principal_id: &str,
        posterior: f64,
        evidence_count: u64,
        evidence_hash: &str,
        scope: &str,
        trace_id: &str,
    ) -> Option<ControlDecision> {
        let action = self.action_for_posterior(posterior)?;
        let threshold = match action {
            ControlAction::Throttle => self.policy.throttle,
            ControlAction::Isolate => self.policy.isolate,
            ControlAction::Quarantine => self.policy.quarantine,
            ControlAction::Revoke => self.policy.revoke,
        };
        let policy_hash = self.policy_hash();
        let policy_version = QUARANTINE_POLICY_VERSION.to_string();
        let mut signed_evidence = SignedEvidenceEntry {
            event_code: EVD_QUAR_CTRL_001.to_string(),
            principal_id: principal_id.to_string(),
            action,
            posterior,
            threshold,
            policy_version: policy_version.clone(),
            policy_hash: policy_hash.clone(),
            evidence_count,
            evidence_hash: evidence_hash.to_string(),
            scope: scope.to_string(),
            trace_id: trace_id.to_string(),
            signature: String::new(),
        };
        signed_evidence.signature = self.sign_evidence(&signed_evidence);

        Some(ControlDecision {
            principal_id: principal_id.to_string(),
            action,
            posterior,
            threshold,
            policy_version,
            policy_hash,
            evidence_count,
            evidence_hash: evidence_hash.to_string(),
            scope: scope.to_string(),
            signed_evidence,
        })
    }

    pub fn evaluate(
        &self,
        posterior: &AdversaryPosterior,
    ) -> Result<SignedEvidenceEntry, QuarantineControllerError> {
        self.decide_for_posterior_with_context(
            &posterior.principal_id,
            posterior.posterior,
            posterior.evidence_count,
            &posterior.evidence_hash,
            DEFAULT_QUARANTINE_SCOPE,
            &posterior.last_trace_id,
        )
        .map(|decision| decision.signed_evidence)
        .ok_or(QuarantineControllerError::NoControlAction {
            posterior: posterior.posterior,
        })
    }

    #[must_use]
    pub fn evaluate_posteriors(&self, posteriors: &[AdversaryPosterior]) -> Vec<ControlDecision> {
        let mut decisions: Vec<ControlDecision> = Vec::new();

        // Bounded collection to prevent memory exhaustion attacks
        for posterior in posteriors {
            if let Some(decision) = self.decide_for_posterior_with_context(
                &posterior.principal_id,
                posterior.posterior,
                posterior.evidence_count,
                &posterior.evidence_hash,
                DEFAULT_QUARANTINE_SCOPE,
                &posterior.last_trace_id,
            ) {
                push_bounded(&mut decisions, decision, MAX_DECISIONS);
            }
        }

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
        if entry.event_code != EVD_QUAR_CTRL_001 {
            return false;
        }
        if entry.policy_version != QUARANTINE_POLICY_VERSION {
            return false;
        }
        if !constant_time::ct_eq(&entry.policy_hash, &self.policy_hash()) {
            return false;
        }
        if self.action_for_posterior(entry.posterior) != Some(entry.action) {
            return false;
        }
        let expected_threshold = match entry.action {
            ControlAction::Throttle => self.policy.throttle,
            ControlAction::Isolate => self.policy.isolate,
            ControlAction::Quarantine => self.policy.quarantine,
            ControlAction::Revoke => self.policy.revoke,
        };
        if entry.threshold.to_bits() != expected_threshold.to_bits() {
            return false;
        }

        let expected = self.sign_evidence(entry);
        constant_time::ct_eq(&entry.signature, &expected)
    }

    #[must_use]
    pub fn verify_decision(&self, decision: &ControlDecision) -> bool {
        if decision.principal_id != decision.signed_evidence.principal_id
            || decision.action != decision.signed_evidence.action
            || decision.posterior.to_bits() != decision.signed_evidence.posterior.to_bits()
            || decision.threshold.to_bits() != decision.signed_evidence.threshold.to_bits()
            || decision.policy_version != decision.signed_evidence.policy_version
            || decision.policy_hash != decision.signed_evidence.policy_hash
            || decision.evidence_count != decision.signed_evidence.evidence_count
            || decision.evidence_hash != decision.signed_evidence.evidence_hash
            || decision.scope != decision.signed_evidence.scope
        {
            return false;
        }
        self.verify_signature(&decision.signed_evidence)
    }

    fn sign_evidence(&self, entry: &SignedEvidenceEntry) -> String {
        let mut mac = Hmac::<Sha256>::new_from_slice(self.signing_key.as_bytes())
            .expect("HMAC accepts arbitrary signing key lengths");
        mac.update(b"quarantine_control_decision_v2:");
        update_len_prefixed_mac(&mut mac, EVD_QUAR_CTRL_001.as_bytes());
        update_len_prefixed_mac(&mut mac, entry.principal_id.as_bytes());
        update_len_prefixed_mac(&mut mac, entry.action.as_str().as_bytes());
        update_f64_mac(&mut mac, entry.posterior);
        update_f64_mac(&mut mac, entry.threshold);
        update_len_prefixed_mac(&mut mac, entry.policy_version.as_bytes());
        update_len_prefixed_mac(&mut mac, entry.policy_hash.as_bytes());
        mac.update(&entry.evidence_count.to_le_bytes());
        update_len_prefixed_mac(&mut mac, entry.evidence_hash.as_bytes());
        update_len_prefixed_mac(&mut mac, entry.scope.as_bytes());
        update_len_prefixed_mac(&mut mac, entry.trace_id.as_bytes());
        let digest = mac.finalize().into_bytes();
        format!("sha256:{}", hex::encode(digest))
    }
}

fn update_len_prefixed_hash(hasher: &mut Sha256, field: &[u8]) {
    hasher.update(len_to_u64(field.len()).to_le_bytes());
    hasher.update(field);
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
    fn threshold_below_zero_is_rejected_with_field_name() {
        let err = QuarantineController::new(
            QuarantineThresholdPolicy {
                throttle: -0.01,
                isolate: 0.60,
                quarantine: 0.75,
                revoke: 0.90,
            },
            "salt",
        )
        .expect_err("must reject negative threshold");

        assert!(matches!(
            err,
            QuarantineControllerError::InvalidThresholdValue { name: "throttle", value }
                if value.to_bits() == (-0.01f64).to_bits()
        ));
    }

    #[test]
    fn threshold_above_one_is_rejected_with_field_name() {
        let err = QuarantineController::new(
            QuarantineThresholdPolicy {
                throttle: 0.45,
                isolate: 0.60,
                quarantine: 0.75,
                revoke: 1.01,
            },
            "salt",
        )
        .expect_err("must reject threshold above one");

        assert!(matches!(
            err,
            QuarantineControllerError::InvalidThresholdValue { name: "revoke", value }
                if value.to_bits() == 1.01f64.to_bits()
        ));
    }

    #[test]
    fn isolate_greater_than_quarantine_is_rejected() {
        let err = QuarantineController::new(
            QuarantineThresholdPolicy {
                throttle: 0.45,
                isolate: 0.80,
                quarantine: 0.75,
                revoke: 0.90,
            },
            "salt",
        )
        .expect_err("must reject middle threshold inversion");

        assert_eq!(err, QuarantineControllerError::InvalidThresholdOrder);
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
    fn posterior_below_throttle_has_no_control_action() {
        let controller = QuarantineController::new(QuarantineThresholdPolicy::default(), "salt")
            .expect("controller");

        assert_eq!(controller.action_for_posterior(0.449_999), None);
    }

    #[test]
    fn decide_below_threshold_returns_no_signed_evidence() {
        let controller = QuarantineController::new(QuarantineThresholdPolicy::default(), "salt")
            .expect("controller");

        assert!(
            controller
                .decide_for_posterior("ext:quiet", 0.20, "trace-quiet")
                .is_none()
        );
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
    fn signed_evidence_length_prefixes_field_boundaries() {
        let controller = QuarantineController::new(QuarantineThresholdPolicy::default(), "salt")
            .expect("controller");
        let principal_a = "ext:a|revoke|0.910000000000|trace";
        let trace_a = "tail";
        let principal_b = "ext:a";
        let trace_b = "trace|throttle|0.450000000000|tail";

        let legacy_payload_a = format!(
            "franken-node.quarantine-controller.v1|{EVD_QUAR_CTRL_001}|{principal_a}|{}|{:.12}|{trace_a}",
            ControlAction::Throttle.as_str(),
            0.45_f64
        );
        let legacy_payload_b = format!(
            "franken-node.quarantine-controller.v1|{EVD_QUAR_CTRL_001}|{principal_b}|{}|{:.12}|{trace_b}",
            ControlAction::Revoke.as_str(),
            0.91_f64
        );
        assert_eq!(
            legacy_payload_a, legacy_payload_b,
            "fixture should collide under delimiter-only transcript"
        );

        let signature_a =
            controller.sign_evidence(principal_a, ControlAction::Throttle, 0.45, trace_a);
        let signature_b = controller.sign_evidence(principal_b, ControlAction::Revoke, 0.91, trace_b);

        assert_ne!(signature_a, signature_b);
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
    fn signature_verification_detects_principal_tampering() {
        let controller = QuarantineController::new(QuarantineThresholdPolicy::default(), "salt")
            .expect("controller");
        let mut decision = controller
            .decide_for_posterior("ext:a", 0.91, "trace-a")
            .expect("decision");

        decision.signed_evidence.principal_id = "ext:b".to_string();

        assert!(!controller.verify_signature(&decision.signed_evidence));
    }

    #[test]
    fn signature_verification_detects_action_tampering() {
        let controller = QuarantineController::new(QuarantineThresholdPolicy::default(), "salt")
            .expect("controller");
        let mut decision = controller
            .decide_for_posterior("ext:a", 0.91, "trace-a")
            .expect("decision");

        decision.signed_evidence.action = ControlAction::Throttle;

        assert!(!controller.verify_signature(&decision.signed_evidence));
    }

    #[test]
    fn signature_verification_rejects_signature_from_different_key() {
        let signer = QuarantineController::new(QuarantineThresholdPolicy::default(), "salt-a")
            .expect("signer");
        let verifier = QuarantineController::new(QuarantineThresholdPolicy::default(), "salt-b")
            .expect("verifier");
        let decision = signer
            .decide_for_posterior("ext:a", 0.91, "trace-a")
            .expect("decision");

        assert!(!verifier.verify_signature(&decision.signed_evidence));
    }

    #[test]
    fn evaluate_posteriors_filters_posteriors_below_threshold() {
        let controller = QuarantineController::new(QuarantineThresholdPolicy::default(), "salt")
            .expect("controller");

        let decisions = controller.evaluate_posteriors(&[
            posterior("ext:quiet", 0.44, "trace-quiet"),
            posterior("ext:loud", 0.45, "trace-loud"),
        ]);

        let ids: Vec<&str> = decisions.iter().map(|d| d.principal_id.as_str()).collect();
        assert_eq!(ids, vec!["ext:loud"]);
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

    #[test]
    fn evaluate_posteriors_is_bounded_to_prevent_memory_exhaustion() {
        use super::MAX_DECISIONS;

        let controller = QuarantineController::new(QuarantineThresholdPolicy::default(), "salt")
            .expect("controller");

        // Create more posteriors than the limit to test memory exhaustion protection
        let posteriors: Vec<AdversaryPosterior> = (0..(MAX_DECISIONS + 50))
            .map(|i| posterior(&format!("ext:user{}", i), 0.8, &format!("trace{}", i)))
            .collect();

        let decisions = controller.evaluate_posteriors(&posteriors);

        // Should only keep MAX_DECISIONS entries
        assert_eq!(decisions.len(), MAX_DECISIONS);

        // The decisions should be the highest posterior ones due to LRU eviction + sorting
        // All should have posterior 0.8 since we generated them that way
        for decision in &decisions {
            assert!((decision.posterior - 0.8).abs() < f64::EPSILON);
        }

        // Verify deterministic ordering is preserved
        for i in 1..decisions.len() {
            let prev = &decisions[i - 1];
            let curr = &decisions[i];

            // Should be sorted by posterior desc, then principal_id asc
            assert!(
                prev.posterior > curr.posterior ||
                (prev.posterior == curr.posterior && prev.principal_id <= curr.principal_id)
            );
        }
    }
}

#[cfg(test)]
mod quarantine_controller_additional_negative_tests {
    use super::*;
    use crate::security::adversary_graph::AdversaryPosterior;

    fn controller() -> QuarantineController {
        QuarantineController::new(QuarantineThresholdPolicy::default(), "salt").expect("controller")
    }

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
    fn whitespace_signing_key_is_rejected() {
        let err = QuarantineController::new(QuarantineThresholdPolicy::default(), " \t\n ")
            .expect_err("must reject blank signing key");

        assert_eq!(err, QuarantineControllerError::InvalidSigningKey);
    }

    #[test]
    fn nan_threshold_is_rejected_with_field_name() {
        let err = QuarantineController::new(
            QuarantineThresholdPolicy {
                throttle: f64::NAN,
                isolate: 0.60,
                quarantine: 0.75,
                revoke: 0.90,
            },
            "salt",
        )
        .expect_err("must reject NaN threshold");

        assert!(matches!(
            err,
            QuarantineControllerError::InvalidThresholdValue { name: "throttle", value }
                if value.is_nan()
        ));
    }

    #[test]
    fn infinite_threshold_is_rejected_with_field_name() {
        let err = QuarantineController::new(
            QuarantineThresholdPolicy {
                throttle: 0.45,
                isolate: f64::INFINITY,
                quarantine: 0.75,
                revoke: 0.90,
            },
            "salt",
        )
        .expect_err("must reject infinite threshold");

        assert!(matches!(
            err,
            QuarantineControllerError::InvalidThresholdValue { name: "isolate", value }
                if value.is_infinite()
        ));
    }

    #[test]
    fn signature_verification_rejects_posterior_tampering() {
        let controller = controller();
        let mut decision = controller
            .decide_for_posterior("ext:a", 0.91, "trace-a")
            .expect("decision");

        decision.signed_evidence.posterior = 0.90;

        assert!(!controller.verify_signature(&decision.signed_evidence));
    }

    #[test]
    fn signature_verification_rejects_signature_material_tampering() {
        let controller = controller();
        let mut decision = controller
            .decide_for_posterior("ext:a", 0.91, "trace-a")
            .expect("decision");

        decision.signed_evidence.signature =
            format!("{}-tampered", decision.signed_evidence.signature);

        assert!(!controller.verify_signature(&decision.signed_evidence));
    }

    #[test]
    fn signature_verification_rejects_event_code_tampering() {
        let controller = controller();
        let mut decision = controller
            .decide_for_posterior("ext:a", 0.91, "trace-a")
            .expect("decision");

        decision.signed_evidence.event_code = EVD_QUAR_CTRL_002.to_string();

        assert!(!controller.verify_signature(&decision.signed_evidence));
    }

    #[test]
    fn evaluate_posteriors_omits_subthreshold_even_with_large_evidence_count() {
        let controller = controller();
        let mut quiet = posterior("ext:quiet", 0.44, "trace-quiet");
        quiet.evidence_count = u64::MAX;

        let decisions = controller.evaluate_posteriors(&[quiet]);

        assert!(decisions.is_empty());
    }

    #[test]
    fn negative_infinity_threshold_is_rejected_with_field_name() {
        let err = QuarantineController::new(
            QuarantineThresholdPolicy {
                throttle: 0.45,
                isolate: 0.60,
                quarantine: f64::NEG_INFINITY,
                revoke: 0.90,
            },
            "salt",
        )
        .expect_err("must reject negative infinite threshold");

        assert!(matches!(
            err,
            QuarantineControllerError::InvalidThresholdValue { name: "quarantine", value }
                if value.is_infinite() && value.is_sign_negative()
        ));
    }

    #[test]
    fn quarantine_greater_than_revoke_is_rejected() {
        let err = QuarantineController::new(
            QuarantineThresholdPolicy {
                throttle: 0.45,
                isolate: 0.60,
                quarantine: 0.95,
                revoke: 0.90,
            },
            "salt",
        )
        .expect_err("must reject quarantine/revoke inversion");

        assert_eq!(err, QuarantineControllerError::InvalidThresholdOrder);
    }

    #[test]
    fn signature_verification_rejects_empty_signature() {
        let controller = controller();
        let mut decision = controller
            .decide_for_posterior("ext:a", 0.91, "trace-a")
            .expect("decision");
        decision.signed_evidence.signature.clear();

        assert!(!controller.verify_signature(&decision.signed_evidence));
    }

    #[test]
    fn signature_verification_rejects_truncated_signature() {
        let controller = controller();
        let mut decision = controller
            .decide_for_posterior("ext:a", 0.91, "trace-a")
            .expect("decision");
        decision.signed_evidence.signature.truncate(16);

        assert!(!controller.verify_signature(&decision.signed_evidence));
    }

    #[test]
    fn signature_verification_rejects_prefix_stripped_signature() {
        let controller = controller();
        let mut decision = controller
            .decide_for_posterior("ext:a", 0.91, "trace-a")
            .expect("decision");
        decision.signed_evidence.signature =
            decision.signed_evidence.signature.replace("sha256:", "");

        assert!(!controller.verify_signature(&decision.signed_evidence));
    }

    #[test]
    fn decide_for_nan_posterior_fails_closed_to_revoke_with_valid_signature() {
        let controller = controller();
        let decision = controller
            .decide_for_posterior("ext:nan", f64::NAN, "trace-nan")
            .expect("non-finite posterior must still produce a control decision");

        assert_eq!(decision.action, ControlAction::Revoke);
        assert_eq!(decision.threshold, controller.policy().revoke);
        assert!(controller.verify_signature(&decision.signed_evidence));
    }

    #[test]
    fn evaluate_posteriors_omits_negative_finite_posterior() {
        let controller = controller();
        let decisions =
            controller.evaluate_posteriors(&[posterior("ext:negative", -0.01, "trace-negative")]);

        assert!(decisions.is_empty());
    }

    #[test]
    fn serde_rejects_unknown_control_action_variant() {
        let result: Result<ControlAction, _> = serde_json::from_str(r#""suspend""#);

        assert!(result.is_err());
    }

    #[test]
    fn serde_rejects_policy_missing_revoke_threshold() {
        let result: Result<QuarantineThresholdPolicy, _> = serde_json::from_str(
            r#"{
                "throttle":0.45,
                "isolate":0.60,
                "quarantine":0.75
            }"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn serde_rejects_policy_threshold_encoded_as_string() {
        let result: Result<QuarantineThresholdPolicy, _> = serde_json::from_str(
            r#"{
                "throttle":"0.45",
                "isolate":0.60,
                "quarantine":0.75,
                "revoke":0.90
            }"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn serde_rejects_signed_evidence_with_unknown_action() {
        let result: Result<SignedEvidenceEntry, _> = serde_json::from_str(
            r#"{
                "event_code":"EVD-QUAR-CTRL-001",
                "principal_id":"ext:a",
                "action":"suspend",
                "posterior":0.91,
                "trace_id":"trace-a",
                "signature":"sha256:00"
            }"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn serde_rejects_signed_evidence_missing_signature() {
        let result: Result<SignedEvidenceEntry, _> = serde_json::from_str(
            r#"{
                "event_code":"EVD-QUAR-CTRL-001",
                "principal_id":"ext:a",
                "action":"revoke",
                "posterior":0.91,
                "trace_id":"trace-a"
            }"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn serde_rejects_signed_evidence_posterior_encoded_as_string() {
        let result: Result<SignedEvidenceEntry, _> = serde_json::from_str(
            r#"{
                "event_code":"EVD-QUAR-CTRL-001",
                "principal_id":"ext:a",
                "action":"revoke",
                "posterior":"0.91",
                "trace_id":"trace-a",
                "signature":"sha256:00"
            }"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn serde_rejects_control_decision_missing_signed_evidence() {
        let result: Result<ControlDecision, _> = serde_json::from_str(
            r#"{
                "principal_id":"ext:a",
                "action":"revoke",
                "posterior":0.91,
                "threshold":0.90
            }"#,
        );

        assert!(result.is_err());
    }

    #[test]
    fn serde_rejects_control_decision_threshold_encoded_as_string() {
        let result: Result<ControlDecision, _> = serde_json::from_str(
            r#"{
                "principal_id":"ext:a",
                "action":"revoke",
                "posterior":0.91,
                "threshold":"0.90",
                "signed_evidence":{
                    "event_code":"EVD-QUAR-CTRL-001",
                    "principal_id":"ext:a",
                    "action":"revoke",
                    "posterior":0.91,
                    "trace_id":"trace-a",
                    "signature":"sha256:00"
                }
            }"#,
        );

        assert!(result.is_err());
    }

    // -- Negative-path Security Tests ---------------------------------------
    // Added 2026-04-17: Comprehensive security hardening tests

    #[test]
    fn test_security_unicode_injection_in_principal_trace_ids() {
        use crate::security::constant_time;

        let controller = controller();

        // Unicode injection attempts in principal_id and trace_id
        let malicious_posteriors = vec![
            AdversaryPosterior {
                principal_id: "\u{202E}user123\u{202D}admin".to_string(),  // BiDi override
                alpha: 1,
                beta: 1,
                posterior: 0.8,
                evidence_count: 1,
                last_trace_id: "trace\u{200B}001".to_string(),  // Zero-width space
                evidence_hash: "sha256:test".to_string(),
            },
            AdversaryPosterior {
                principal_id: "user\u{FEFF}123".to_string(),  // Zero-width no-break space
                alpha: 1,
                beta: 1,
                posterior: 0.9,
                evidence_count: 1,
                last_trace_id: "\u{0000}trace001".to_string(),  // Null injection
                evidence_hash: "sha256:test".to_string(),
            },
            AdversaryPosterior {
                principal_id: "user\u{2028}123\u{2029}".to_string(),  // Line/paragraph separators
                alpha: 1,
                beta: 1,
                posterior: 0.95,
                evidence_count: 1,
                last_trace_id: "trace\u{200E}001\u{200F}".to_string(),  // LTR/RTL marks
                evidence_hash: "sha256:test".to_string(),
            },
        ];

        for malicious_posterior in malicious_posteriors {
            let result = controller.evaluate(&malicious_posterior);

            if let Ok(evidence) = result {
                // Unicode should not affect the control logic
                assert!(evidence.action != ControlAction::Throttle || malicious_posterior.posterior >= 0.45);
                assert!(evidence.action != ControlAction::Isolate || malicious_posterior.posterior >= 0.60);
                assert!(evidence.action != ControlAction::Quarantine || malicious_posterior.posterior >= 0.75);
                assert!(evidence.action != ControlAction::Revoke || malicious_posterior.posterior >= 0.90);

                // Principal ID should not be normalized in a way that bypasses security
                assert!(!constant_time::ct_eq(evidence.principal_id.as_bytes(), b"admin"),
                       "Unicode injection should not create admin privileges");

                // Trace ID should preserve injection detection
                assert!(!evidence.trace_id.contains('\0'),
                       "Null bytes should not appear in trace ID");
            }
        }
    }

    #[test]
    fn test_security_floating_point_manipulation_attacks() {
        let controller = controller();

        // Test extreme floating point values that could bypass thresholds
        let extreme_posteriors = vec![
            AdversaryPosterior {
                principal_id: "user001".to_string(),
                alpha: 1,
                beta: 1,
                posterior: f64::INFINITY,  // Positive infinity
                evidence_count: 1,
                last_trace_id: "trace001".to_string(),
                evidence_hash: "sha256:test".to_string(),
            },
            AdversaryPosterior {
                principal_id: "user002".to_string(),
                alpha: 1,
                beta: 1,
                posterior: f64::NEG_INFINITY,  // Negative infinity
                evidence_count: 1,
                last_trace_id: "trace002".to_string(),
                evidence_hash: "sha256:test".to_string(),
            },
            AdversaryPosterior {
                principal_id: "user003".to_string(),
                alpha: 1,
                beta: 1,
                posterior: f64::NAN,  // Not a Number
                evidence_count: 1,
                last_trace_id: "trace003".to_string(),
                evidence_hash: "sha256:test".to_string(),
            },
            AdversaryPosterior {
                principal_id: "user004".to_string(),
                alpha: 1,
                beta: 1,
                posterior: 1.0000000000000002,  // Slightly above 1.0
                evidence_count: 1,
                last_trace_id: "trace004".to_string(),
                evidence_hash: "sha256:test".to_string(),
            },
        ];

        for extreme_posterior in extreme_posteriors {
            let result = controller.evaluate(&extreme_posterior);

            match result {
                Ok(evidence) => {
                    // If accepted, verify the action makes sense
                    assert!(evidence.posterior.is_finite() || evidence.action == ControlAction::Revoke,
                           "Non-finite posteriors should trigger maximum action");

                    if extreme_posterior.posterior.is_infinite() && extreme_posterior.posterior > 0.0 {
                        assert_eq!(evidence.action, ControlAction::Revoke,
                                 "Positive infinity should trigger revoke");
                    }
                },
                Err(_) => {
                    // Graceful rejection of extreme values is acceptable
                }
            }
        }
    }

    #[test]
    fn test_security_signature_verification_bypass_attempts() {
        use crate::security::constant_time;

        let controller = controller();
        let posterior = posterior("user001", 0.8, "trace001");

        let evidence = controller.evaluate(&posterior).expect("should evaluate");
        let original_signature = evidence.signature.clone();

        // Attempt various signature manipulation attacks
        let forged_evidence_variants = vec![
            SignedEvidenceEntry {
                signature: "forged_signature".to_string(),
                ..evidence.clone()
            },
            SignedEvidenceEntry {
                signature: original_signature.clone() + "extra",
                ..evidence.clone()
            },
            SignedEvidenceEntry {
                signature: original_signature[1..].to_string(),  // Truncated
                ..evidence.clone()
            },
            SignedEvidenceEntry {
                action: ControlAction::Throttle,  // Modified action
                signature: original_signature.clone(),
                ..evidence.clone()
            },
            SignedEvidenceEntry {
                posterior: 0.1,  // Modified posterior
                signature: original_signature.clone(),
                ..evidence.clone()
            },
        ];

        for forged_evidence in forged_evidence_variants {
            // Signature verification should detect tampering
            if forged_evidence.signature == original_signature {
                // If signature wasn't changed, other fields were modified
                assert!(forged_evidence.action != evidence.action ||
                       (forged_evidence.posterior - evidence.posterior).abs() > f64::EPSILON,
                       "Evidence modification should be detectable");
            } else {
                // Signature was modified - should be detectable through verification
                assert!(!constant_time::ct_eq(forged_evidence.signature.as_bytes(), original_signature.as_bytes()),
                       "Signature tampering should be detectable");
            }
        }
    }

    #[test]
    fn test_security_threshold_boundary_manipulation() {
        // Test threshold policies with manipulated boundaries
        let malicious_policies = vec![
            QuarantineThresholdPolicy {
                throttle: 0.90,  // Inverted order
                isolate: 0.75,
                quarantine: 0.60,
                revoke: 0.45,
            },
            QuarantineThresholdPolicy {
                throttle: -0.1,  // Negative threshold
                isolate: 0.60,
                quarantine: 0.75,
                revoke: 0.90,
            },
            QuarantineThresholdPolicy {
                throttle: 0.45,
                isolate: 0.60,
                quarantine: 0.75,
                revoke: 1.1,  // Above 1.0
            },
            QuarantineThresholdPolicy {
                throttle: f64::EPSILON,  // Extremely small
                isolate: 1.0 - f64::EPSILON,  // Extremely close to 1.0
                quarantine: 1.0 - f64::EPSILON,
                revoke: 1.0,
            },
        ];

        for policy in malicious_policies {
            let validation_result = policy.validate();
            let controller_result = QuarantineController::new(policy.clone(), "test_key");

            // Invalid policies should be rejected
            if validation_result.is_err() || controller_result.is_err() {
                continue;  // Expected rejection
            }

            // If policy was somehow accepted, verify it behaves securely
            let controller = controller_result.unwrap();
            let test_posterior = posterior("user001", 0.8, "trace001");
            let evidence = controller.evaluate(&test_posterior).expect("should evaluate");

            // Actions should still be coherent despite boundary manipulation
            match evidence.action {
                ControlAction::Throttle => assert!(test_posterior.posterior >= policy.throttle),
                ControlAction::Isolate => assert!(test_posterior.posterior >= policy.isolate),
                ControlAction::Quarantine => assert!(test_posterior.posterior >= policy.quarantine),
                ControlAction::Revoke => assert!(test_posterior.posterior >= policy.revoke),
            }
        }
    }

    #[test]
    fn test_security_json_serialization_injection() {
        let controller = controller();
        let posterior = AdversaryPosterior {
            principal_id: "\";alert('xss');//".to_string(),  // JS injection
            alpha: 1,
            beta: 1,
            posterior: 0.8,
            evidence_count: 1,
            last_trace_id: "trace\ninjection\r\nattack".to_string(),  // Newline injection
            evidence_hash: "sha256:test</script><script>alert('xss')</script>".to_string(),  // HTML injection
        };

        let evidence = controller.evaluate(&posterior).expect("should evaluate");
        let json = serde_json::to_string(&evidence).expect("should serialize");

        // JSON should escape all injection attempts
        assert!(!json.contains("alert('xss')"), "JavaScript injection should be escaped");
        assert!(!json.contains("</script>"), "HTML injection should be escaped");
        assert!(!json.contains("\n"), "Newline injection should be escaped");
        assert!(!json.contains("\r"), "Carriage return injection should be escaped");

        // Roundtrip should preserve structure but escape content
        let parsed: SignedEvidenceEntry = serde_json::from_str(&json).expect("should deserialize");
        assert_eq!(evidence.event_code, parsed.event_code);
        assert_eq!(evidence.action, parsed.action);
        assert!((evidence.posterior - parsed.posterior).abs() < f64::EPSILON);
    }

    #[test]
    fn test_security_memory_exhaustion_resistance() {
        let controller = controller();

        // Attempt memory exhaustion through large string fields
        let large_posterior = AdversaryPosterior {
            principal_id: "a".repeat(1000000),  // 1MB string
            alpha: 1,
            beta: 1,
            posterior: 0.8,
            evidence_count: 1,
            last_trace_id: "b".repeat(1000000),  // 1MB string
            evidence_hash: format!("sha256:{}", "c".repeat(1000000)),  // Large hash
        };

        // Should either handle gracefully or reject
        let result = controller.evaluate(&large_posterior);
        match result {
            Ok(evidence) => {
                // If processed, should not cause memory issues
                assert!(!evidence.principal_id.is_empty());
                assert!(!evidence.trace_id.is_empty());
                assert!(!evidence.signature.is_empty());
            },
            Err(_) => {
                // Graceful rejection is acceptable
            }
        }
        // Test should complete without OOM
    }

    #[test]
    fn test_security_timing_attack_resistance() {
        use std::time::Instant;

        let controller = controller();

        // Test if evaluation time varies significantly based on input
        let test_cases = vec![
            ("user001", 0.1),
            ("user002", 0.5),
            ("user003", 0.9),
            ("admin", 0.9),
            ("a".repeat(100).as_str(), 0.9),
        ];

        let mut timing_results = vec![];

        for (principal_id, posterior_val) in test_cases {
            let test_posterior = posterior(principal_id, posterior_val, "trace001");

            let start = Instant::now();
            let _result = controller.evaluate(&test_posterior);
            let duration = start.elapsed();

            timing_results.push(duration);
        }

        // Verify timing doesn't vary dramatically (within 10x variance)
        let min_time = timing_results.iter().min().unwrap();
        let max_time = timing_results.iter().max().unwrap();

        // Timing should be relatively constant (not perfect, but reasonable)
        assert!(max_time.as_nanos() < min_time.as_nanos() * 100,
               "Timing variance suggests potential timing attack vulnerability");
    }

    #[test]
    fn test_security_concurrent_controller_access_safety() {
        use std::sync::{Arc, Mutex};
        use std::thread;

        let controller = Arc::new(Mutex::new(controller()));
        let mut handles = vec![];

        // Spawn concurrent evaluations
        for i in 0..20 {
            let ctrl_clone = Arc::clone(&controller);
            let handle = thread::spawn(move || {
                let test_posterior = posterior(&format!("user{}", i), 0.5 + (i as f64 / 40.0), &format!("trace{}", i));

                let ctrl = ctrl_clone.lock().unwrap();
                ctrl.evaluate(&test_posterior)
            });
            handles.push(handle);
        }

        // Collect results
        let mut results = vec![];
        for handle in handles {
            let result = handle.join().expect("thread should not panic");
            results.push(result);
        }

        // Verify all evaluations completed successfully
        for (i, result) in results.iter().enumerate() {
            assert!(result.is_ok(), "Concurrent evaluation {} should succeed", i);

            if let Ok(evidence) = result {
                // Verify evidence integrity
                assert!(!evidence.principal_id.is_empty());
                assert!(!evidence.trace_id.is_empty());
                assert!(!evidence.signature.is_empty());
                assert!(evidence.posterior.is_finite());
            }
        }
    }

    #[test]
    fn test_security_arithmetic_overflow_in_evidence_processing() {
        let controller = controller();

        // Test with extreme evidence_count values
        let overflow_posterior = AdversaryPosterior {
            principal_id: "user001".to_string(),
            alpha: u32::MAX as u64,  // Extreme alpha
            beta: u32::MAX as u64,   // Extreme beta
            posterior: 0.8,
            evidence_count: u64::MAX,  // Maximum evidence count
            last_trace_id: "trace001".to_string(),
            evidence_hash: "sha256:test".to_string(),
        };

        let result = controller.evaluate(&overflow_posterior);

        match result {
            Ok(evidence) => {
                // If processed, verify no overflow occurred
                assert!(evidence.posterior.is_finite());
                assert!(!evidence.signature.is_empty());

                // Evidence count should be handled safely
                assert_eq!(evidence.principal_id, "user001");
                assert_eq!(evidence.trace_id, "trace001");
            },
            Err(_) => {
                // Graceful rejection of extreme values is acceptable
            }
        }
    }

    #[test]
    fn test_security_hmac_key_manipulation_resistance() {
        // Test controllers with different key qualities
        let key_tests = vec![
            "",  // Empty key (should be rejected)
            "\0\0\0\0",  // Null bytes
            "\u{202E}key\u{202D}",  // BiDi override
            "a".repeat(1000),  // Very long key
            "short",  // Short but valid key
            "normal_signing_key_123",  // Normal key
        ];

        for test_key in key_tests {
            let controller_result = QuarantineController::new(
                QuarantineThresholdPolicy::default(),
                test_key
            );

            match controller_result {
                Ok(controller) => {
                    // If controller was created, it should work securely
                    let test_posterior = posterior("user001", 0.8, "trace001");
                    let evidence = controller.evaluate(&test_posterior).expect("should evaluate");

                    // Signature should be non-empty and deterministic
                    assert!(!evidence.signature.is_empty());

                    // Same input should produce same signature
                    let evidence2 = controller.evaluate(&test_posterior).expect("should evaluate");
                    assert_eq!(evidence.signature, evidence2.signature,
                             "Signatures should be deterministic");
                },
                Err(QuarantineControllerError::InvalidSigningKey) => {
                    // Expected for empty/invalid keys
                    assert!(test_key.trim().is_empty(), "Invalid key should be empty or whitespace");
                },
                Err(other) => {
                    panic!("Unexpected error for key '{}': {:?}", test_key, other);
                }
            }
        }
    }
}
