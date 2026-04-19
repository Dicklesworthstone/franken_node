//! bd-1nl1: Proof-carrying speculative execution governance for hot paths.
//!
//! Speculative transforms are gated by signed proof receipts and interface allowlists.
//! If any proof or guard check fails, execution degrades to a deterministic safe
//! baseline with no correctness regression.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

/// Report schema version.
pub const SCHEMA_VERSION: &str = "speculation-proof-v1.0";

pub mod event_codes {
    pub const SPECULATION_GUARD_START: &str = "SPECULATION_GUARD_START";
    pub const SPECULATION_PROOF_ACCEPTED: &str = "SPECULATION_PROOF_ACCEPTED";
    pub const SPECULATION_ACTIVATED: &str = "SPECULATION_ACTIVATED";
    pub const SPECULATION_DEGRADED: &str = "SPECULATION_DEGRADED";
    pub const SPECULATION_SAFE_BASELINE_USED: &str = "SPECULATION_SAFE_BASELINE_USED";
}

pub mod error_codes {
    pub const ERR_SPEC_MISSING_PROOF: &str = "ERR_SPEC_MISSING_PROOF";
    pub const ERR_SPEC_EXPIRED_PROOF: &str = "ERR_SPEC_EXPIRED_PROOF";
    pub const ERR_SPEC_SIGNATURE_INVALID: &str = "ERR_SPEC_SIGNATURE_INVALID";
    pub const ERR_SPEC_INTERFACE_MISMATCH: &str = "ERR_SPEC_INTERFACE_MISMATCH";
    pub const ERR_SPEC_INTERFACE_UNAPPROVED: &str = "ERR_SPEC_INTERFACE_UNAPPROVED";
    pub const ERR_SPEC_GUARD_REJECTED: &str = "ERR_SPEC_GUARD_REJECTED";
    pub const ERR_SPEC_TRANSFORM_MISMATCH: &str = "ERR_SPEC_TRANSFORM_MISMATCH";
}

pub mod invariants {
    pub const INV_SPEC_PROOF_REQUIRED: &str = "INV-SPEC-PROOF-REQUIRED";
    pub const INV_SPEC_FAIL_CLOSED_TO_BASELINE: &str = "INV-SPEC-FAIL-CLOSED-TO-BASELINE";
    pub const INV_SPEC_APPROVED_INTERFACE_ONLY: &str = "INV-SPEC-APPROVED-INTERFACE-ONLY";
    pub const INV_SPEC_DETERMINISTIC_BASELINE: &str = "INV-SPEC-DETERMINISTIC-BASELINE";
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SpeculationTransform {
    BranchPredict,
    CacheWarmup,
    ParallelProbe,
}

impl SpeculationTransform {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BranchPredict => "branch_predict",
            Self::CacheWarmup => "cache_warmup",
            Self::ParallelProbe => "parallel_probe",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofReceipt {
    pub receipt_id: String,
    pub transform: SpeculationTransform,
    pub interface_id: String,
    pub proof_hash: String,
    pub signer_id: String,
    pub signature: String,
    pub expires_epoch_ms: u64,
    pub trace_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GuardFailureReason {
    MissingReceipt,
    ExpiredReceipt,
    SignatureInvalid,
    InterfaceMismatch,
    InterfaceUnapproved,
    GuardRejected,
    TransformMismatch,
}

impl GuardFailureReason {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingReceipt => error_codes::ERR_SPEC_MISSING_PROOF,
            Self::ExpiredReceipt => error_codes::ERR_SPEC_EXPIRED_PROOF,
            Self::SignatureInvalid => error_codes::ERR_SPEC_SIGNATURE_INVALID,
            Self::InterfaceMismatch => error_codes::ERR_SPEC_INTERFACE_MISMATCH,
            Self::InterfaceUnapproved => error_codes::ERR_SPEC_INTERFACE_UNAPPROVED,
            Self::GuardRejected => error_codes::ERR_SPEC_GUARD_REJECTED,
            Self::TransformMismatch => error_codes::ERR_SPEC_TRANSFORM_MISMATCH,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BaselineMode {
    DeterministicSafe,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActivationDecision {
    Activated {
        receipt_id: String,
        interface_id: String,
        event_code: String,
    },
    Degraded {
        reason: GuardFailureReason,
        baseline_mode: BaselineMode,
        event_code: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutionOutcome {
    pub decision: ActivationDecision,
    pub output_digest: String,
    pub trace_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardConfig {
    pub approved_interfaces: BTreeSet<String>,
    pub accepted_signers: BTreeSet<String>,
    pub now_epoch_ms: u64,
}

impl GuardConfig {
    pub fn new(now_epoch_ms: u64) -> Self {
        Self {
            approved_interfaces: BTreeSet::new(),
            accepted_signers: BTreeSet::new(),
            now_epoch_ms,
        }
    }

    pub fn with_interface(mut self, interface_id: impl Into<String>) -> Self {
        self.approved_interfaces.insert(interface_id.into());
        self
    }

    pub fn with_signer(mut self, signer_id: impl Into<String>) -> Self {
        self.accepted_signers.insert(signer_id.into());
        self
    }
}

pub struct ProofExecutor {
    config: GuardConfig,
}

impl ProofExecutor {
    pub fn new(config: GuardConfig) -> Self {
        Self { config }
    }

    /// Decide whether speculative transform can activate.
    ///
    /// INV-SPEC-PROOF-REQUIRED: no activation without proof receipt.
    /// INV-SPEC-APPROVED-INTERFACE-ONLY: activation only on approved interfaces.
    /// INV-SPEC-FAIL-CLOSED-TO-BASELINE: any guard failure degrades safely.
    pub fn evaluate_activation(
        &self,
        transform: SpeculationTransform,
        interface_id: &str,
        receipt: Option<&ProofReceipt>,
        guard_ok: bool,
    ) -> ActivationDecision {
        if !self.config.approved_interfaces.contains(interface_id) {
            return ActivationDecision::Degraded {
                reason: GuardFailureReason::InterfaceUnapproved,
                baseline_mode: BaselineMode::DeterministicSafe,
                event_code: event_codes::SPECULATION_DEGRADED.to_string(),
            };
        }

        let Some(receipt) = receipt else {
            return ActivationDecision::Degraded {
                reason: GuardFailureReason::MissingReceipt,
                baseline_mode: BaselineMode::DeterministicSafe,
                event_code: event_codes::SPECULATION_DEGRADED.to_string(),
            };
        };

        if receipt.interface_id != interface_id {
            return ActivationDecision::Degraded {
                reason: GuardFailureReason::InterfaceMismatch,
                baseline_mode: BaselineMode::DeterministicSafe,
                event_code: event_codes::SPECULATION_DEGRADED.to_string(),
            };
        }

        if receipt.transform != transform {
            return ActivationDecision::Degraded {
                reason: GuardFailureReason::TransformMismatch,
                baseline_mode: BaselineMode::DeterministicSafe,
                event_code: event_codes::SPECULATION_DEGRADED.to_string(),
            };
        }

        if receipt.expires_epoch_ms <= self.config.now_epoch_ms {
            return ActivationDecision::Degraded {
                reason: GuardFailureReason::ExpiredReceipt,
                baseline_mode: BaselineMode::DeterministicSafe,
                event_code: event_codes::SPECULATION_DEGRADED.to_string(),
            };
        }

        if !self.config.accepted_signers.contains(&receipt.signer_id) || !verify_signature(receipt)
        {
            return ActivationDecision::Degraded {
                reason: GuardFailureReason::SignatureInvalid,
                baseline_mode: BaselineMode::DeterministicSafe,
                event_code: event_codes::SPECULATION_DEGRADED.to_string(),
            };
        }

        if !guard_ok {
            return ActivationDecision::Degraded {
                reason: GuardFailureReason::GuardRejected,
                baseline_mode: BaselineMode::DeterministicSafe,
                event_code: event_codes::SPECULATION_DEGRADED.to_string(),
            };
        }

        ActivationDecision::Activated {
            receipt_id: receipt.receipt_id.clone(),
            interface_id: interface_id.to_string(),
            event_code: event_codes::SPECULATION_ACTIVATED.to_string(),
        }
    }

    /// Execute with fail-closed deterministic fallback.
    pub fn execute_with_fallback(
        &self,
        transform: SpeculationTransform,
        interface_id: &str,
        receipt: Option<&ProofReceipt>,
        guard_ok: bool,
        baseline_input: &[u8],
    ) -> ExecutionOutcome {
        let trace_id = receipt
            .map(|r| r.trace_id.clone())
            .unwrap_or_else(|| "trace:missing-proof".to_string());

        let decision = self.evaluate_activation(transform, interface_id, receipt, guard_ok);
        let output_digest = match &decision {
            ActivationDecision::Activated { receipt_id, .. } => digest_fields(
                b"proof_executor_active_v1:",
                &[transform.as_str().as_bytes(), receipt_id.as_bytes()],
            ),
            ActivationDecision::Degraded { .. } => deterministic_baseline_digest(baseline_input),
        };

        ExecutionOutcome {
            decision,
            output_digest,
            trace_id,
        }
    }
}

/// Deterministic safe baseline digest used when speculation is denied.
pub fn deterministic_baseline_digest(input: &[u8]) -> String {
    digest_bytes(input)
}

fn digest_bytes(input: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(b"proof_executor_digest_v1:");
    hasher.update(input);
    hex::encode(hasher.finalize())
}

fn digest_fields(domain: &[u8], fields: &[&[u8]]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    for field in fields {
        hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(field);
    }
    hex::encode(hasher.finalize())
}

fn signature_digest(
    receipt_id: &str,
    proof_hash: &str,
    signer_id: &str,
    expires_epoch_ms: u64,
) -> String {
    // Length-prefixed encoding prevents delimiter-collision ambiguity.
    let mut hasher = Sha256::new();
    hasher.update(b"proof_executor_signature_v1:");
    for field in [receipt_id, proof_hash, signer_id] {
        hasher.update(u64::try_from(field.len()).unwrap_or(u64::MAX).to_le_bytes());
        hasher.update(field.as_bytes());
    }
    hasher.update(expires_epoch_ms.to_le_bytes());
    hex::encode(hasher.finalize())
}

fn proof_hash_for(transform: SpeculationTransform, interface_id: &str) -> String {
    digest_fields(
        b"proof_executor_proof_v1:",
        &[transform.as_str().as_bytes(), interface_id.as_bytes()],
    )
}

fn verify_signature(receipt: &ProofReceipt) -> bool {
    if receipt.receipt_id.trim().is_empty()
        || receipt.receipt_id != receipt.receipt_id.trim()
        || receipt.interface_id.trim().is_empty()
        || receipt.interface_id != receipt.interface_id.trim()
        || receipt.proof_hash.trim().is_empty()
        || receipt.proof_hash != receipt.proof_hash.trim()
        || receipt.signer_id.trim().is_empty()
        || receipt.signer_id != receipt.signer_id.trim()
        || receipt.signature.trim().is_empty()
        || receipt.signature != receipt.signature.trim()
        || receipt.trace_id.trim().is_empty()
        || receipt.trace_id != receipt.trace_id.trim()
    {
        return false;
    }

    let expected_proof_hash = proof_hash_for(receipt.transform, &receipt.interface_id);
    if !crate::security::constant_time::ct_eq(&receipt.proof_hash, &expected_proof_hash) {
        return false;
    }

    let expected = signature_digest(
        &receipt.receipt_id,
        &receipt.proof_hash,
        &receipt.signer_id,
        receipt.expires_epoch_ms,
    );
    crate::security::constant_time::ct_eq(&receipt.signature, &expected)
}

pub fn make_receipt(
    receipt_id: &str,
    transform: SpeculationTransform,
    interface_id: &str,
    signer_id: &str,
    expires_epoch_ms: u64,
    trace_id: &str,
) -> ProofReceipt {
    let proof_hash = proof_hash_for(transform, interface_id);
    let signature = signature_digest(receipt_id, &proof_hash, signer_id, expires_epoch_ms);
    ProofReceipt {
        receipt_id: receipt_id.to_string(),
        transform,
        interface_id: interface_id.to_string(),
        proof_hash,
        signer_id: signer_id.to_string(),
        signature,
        expires_epoch_ms,
        trace_id: trace_id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn executor(now_epoch_ms: u64) -> ProofExecutor {
        let cfg = GuardConfig::new(now_epoch_ms)
            .with_interface("franken_engine::hotpath")
            .with_signer("validator-A");
        ProofExecutor::new(cfg)
    }

    #[test]
    fn activation_requires_approved_interface() {
        let ex = executor(10_000);
        let receipt = make_receipt(
            "r1",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            "validator-A",
            20_000,
            "trace-1",
        );
        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::unapproved",
            Some(&receipt),
            true,
            b"safe",
        );
        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::InterfaceUnapproved,
                ..
            }
        ));
    }

    #[test]
    fn activation_requires_receipt() {
        let ex = executor(10_000);
        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            None,
            true,
            b"safe",
        );
        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::MissingReceipt,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_expired_receipt() {
        let ex = executor(30_000);
        let receipt = make_receipt(
            "r1",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            "validator-A",
            20_000,
            "trace-2",
        );
        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );
        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::ExpiredReceipt,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_transform_mismatch() {
        let ex = executor(10_000);
        let receipt = make_receipt(
            "r1",
            SpeculationTransform::CacheWarmup,
            "franken_engine::hotpath",
            "validator-A",
            20_000,
            "trace-3",
        );
        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );
        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::TransformMismatch,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_bad_signature() {
        let ex = executor(10_000);
        let mut receipt = make_receipt(
            "r1",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            "validator-A",
            20_000,
            "trace-4",
        );
        receipt.signature = "tampered".to_string();
        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );
        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_guard_failure() {
        let ex = executor(10_000);
        let receipt = make_receipt(
            "r1",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            "validator-A",
            20_000,
            "trace-5",
        );
        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            false,
            b"safe",
        );
        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::GuardRejected,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_unaccepted_signer_even_with_valid_signature() {
        let ex = executor(10_000);
        let receipt = make_receipt(
            "r-untrusted",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            "validator-B",
            20_000,
            "trace-untrusted",
        );
        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );

        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_tampered_receipt_id_signature_binding() {
        let ex = executor(10_000);
        let mut receipt = make_receipt(
            "r-original",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            "validator-A",
            20_000,
            "trace-receipt-id",
        );
        receipt.receipt_id = "r-tampered".to_string();
        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );

        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_tampered_proof_hash_signature_binding() {
        let ex = executor(10_000);
        let mut receipt = make_receipt(
            "r-proof",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            "validator-A",
            20_000,
            "trace-proof",
        );
        receipt.proof_hash.push_str("-tampered");
        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );

        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn unapproved_interface_takes_priority_over_missing_receipt() {
        let ex = executor(10_000);
        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::not-approved",
            None,
            true,
            b"safe",
        );

        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::InterfaceUnapproved,
                ..
            }
        ));
    }

    #[test]
    fn expired_receipt_takes_priority_over_invalid_signature() {
        let ex = executor(30_000);
        let mut receipt = make_receipt(
            "r-expired-tampered",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            "validator-A",
            20_000,
            "trace-expired-tampered",
        );
        receipt.signature = "tampered".to_string();
        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );

        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::ExpiredReceipt,
                ..
            }
        ));
    }

    #[test]
    fn missing_receipt_uses_missing_proof_trace_id() {
        let ex = executor(10_000);
        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            None,
            true,
            b"safe",
        );

        assert_eq!(out.trace_id, "trace:missing-proof");
        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::MissingReceipt,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_receipt_bound_to_different_interface() {
        let ex = executor(10_000);
        let receipt = make_receipt(
            "r-interface",
            SpeculationTransform::BranchPredict,
            "franken_engine::other_hotpath",
            "validator-A",
            20_000,
            "trace-interface",
        );

        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );

        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::InterfaceMismatch,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_empty_receipt_id_even_with_matching_signature() {
        let ex = executor(10_000);
        let mut receipt = make_receipt(
            "r-empty-id",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            "validator-A",
            20_000,
            "trace-empty-id",
        );
        receipt.receipt_id = String::new();
        receipt.signature = signature_digest(
            &receipt.receipt_id,
            &receipt.proof_hash,
            &receipt.signer_id,
            receipt.expires_epoch_ms,
        );

        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );

        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_whitespace_receipt_id() {
        let ex = executor(10_000);
        let mut receipt = make_receipt(
            "r-space-id",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            "validator-A",
            20_000,
            "trace-space-id",
        );
        receipt.receipt_id = " r-space-id ".to_string();
        receipt.signature = signature_digest(
            &receipt.receipt_id,
            &receipt.proof_hash,
            &receipt.signer_id,
            receipt.expires_epoch_ms,
        );

        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );

        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_empty_proof_hash_even_with_matching_signature() {
        let ex = executor(10_000);
        let mut receipt = make_receipt(
            "r-empty-proof",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            "validator-A",
            20_000,
            "trace-empty-proof",
        );
        receipt.proof_hash = String::new();
        receipt.signature = signature_digest(
            &receipt.receipt_id,
            &receipt.proof_hash,
            &receipt.signer_id,
            receipt.expires_epoch_ms,
        );

        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );

        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_proof_hash_for_other_interface_even_with_valid_signature() {
        let ex = executor(10_000);
        let mut receipt = make_receipt(
            "r-other-proof",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            "validator-A",
            20_000,
            "trace-other-proof",
        );
        receipt.proof_hash = proof_hash_for(
            SpeculationTransform::BranchPredict,
            "franken_engine::other_hotpath",
        );
        receipt.signature = signature_digest(
            &receipt.receipt_id,
            &receipt.proof_hash,
            &receipt.signer_id,
            receipt.expires_epoch_ms,
        );

        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );

        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_blank_trace_id_even_with_matching_signature() {
        let ex = executor(10_000);
        let mut receipt = make_receipt(
            "r-blank-trace",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            "validator-A",
            20_000,
            "trace-before-blank",
        );
        receipt.trace_id = " \t ".to_string();

        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );

        assert_eq!(out.trace_id, " \t ");
        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_empty_interface_id_even_if_allowlisted() {
        let cfg = GuardConfig::new(10_000)
            .with_interface("")
            .with_signer("validator-A");
        let ex = ProofExecutor::new(cfg);
        let receipt = make_receipt(
            "r-empty-interface",
            SpeculationTransform::BranchPredict,
            "",
            "validator-A",
            20_000,
            "trace-empty-interface",
        );

        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "",
            Some(&receipt),
            true,
            b"safe",
        );

        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_padded_interface_id_even_if_allowlisted() {
        let padded_interface = " franken_engine::hotpath ";
        let cfg = GuardConfig::new(10_000)
            .with_interface(padded_interface)
            .with_signer("validator-A");
        let ex = ProofExecutor::new(cfg);
        let receipt = make_receipt(
            "r-padded-interface",
            SpeculationTransform::BranchPredict,
            padded_interface,
            "validator-A",
            20_000,
            "trace-padded-interface",
        );

        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            padded_interface,
            Some(&receipt),
            true,
            b"safe",
        );

        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_empty_signer_id_even_if_accepted() {
        let cfg = GuardConfig::new(10_000)
            .with_interface("franken_engine::hotpath")
            .with_signer("");
        let ex = ProofExecutor::new(cfg);
        let receipt = make_receipt(
            "r-empty-signer",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            "",
            20_000,
            "trace-empty-signer",
        );

        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );

        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_padded_signer_id_even_if_accepted() {
        let padded_signer = " validator-A ";
        let cfg = GuardConfig::new(10_000)
            .with_interface("franken_engine::hotpath")
            .with_signer(padded_signer);
        let ex = ProofExecutor::new(cfg);
        let receipt = make_receipt(
            "r-padded-signer",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            padded_signer,
            20_000,
            "trace-padded-signer",
        );

        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );

        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_empty_signature() {
        let ex = executor(10_000);
        let mut receipt = make_receipt(
            "r-empty-signature",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            "validator-A",
            20_000,
            "trace-empty-signature",
        );
        receipt.signature = String::new();

        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );

        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_padded_signature() {
        let ex = executor(10_000);
        let mut receipt = make_receipt(
            "r-padded-signature",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            "validator-A",
            20_000,
            "trace-padded-signature",
        );
        receipt.signature = format!(" {} ", receipt.signature);

        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );

        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn activation_rejects_padded_proof_hash_even_if_signature_rebound() {
        let ex = executor(10_000);
        let mut receipt = make_receipt(
            "r-padded-proof",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            "validator-A",
            20_000,
            "trace-padded-proof",
        );
        receipt.proof_hash = format!(" {} ", receipt.proof_hash);
        receipt.signature = signature_digest(
            &receipt.receipt_id,
            &receipt.proof_hash,
            &receipt.signer_id,
            receipt.expires_epoch_ms,
        );

        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );

        assert!(matches!(
            out.decision,
            ActivationDecision::Degraded {
                reason: GuardFailureReason::SignatureInvalid,
                ..
            }
        ));
    }

    #[test]
    fn activation_succeeds_with_valid_receipt() {
        let ex = executor(10_000);
        let receipt = make_receipt(
            "r1",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            "validator-A",
            20_000,
            "trace-6",
        );
        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );
        assert!(matches!(out.decision, ActivationDecision::Activated { .. }));
    }

    #[test]
    fn deterministic_baseline_is_stable() {
        let a = deterministic_baseline_digest(b"same-input");
        let b = deterministic_baseline_digest(b"same-input");
        let c = deterministic_baseline_digest(b"different-input");
        assert_eq!(a, b);
        assert_ne!(a, c);
    }

    #[test]
    fn degraded_path_uses_deterministic_baseline_digest() {
        let ex = executor(10_000);
        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            None,
            true,
            b"safe-baseline",
        );
        assert_eq!(
            out.output_digest,
            deterministic_baseline_digest(b"safe-baseline")
        );
    }

    #[test]
    fn receipt_at_exact_expiry_boundary_degrades() {
        let ex = executor(10_000);
        let receipt = make_receipt(
            "r-boundary",
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            "validator-A",
            10_000, // expires_epoch_ms == now_epoch_ms
            "trace-boundary",
        );
        let out = ex.execute_with_fallback(
            SpeculationTransform::BranchPredict,
            "franken_engine::hotpath",
            Some(&receipt),
            true,
            b"safe",
        );
        assert!(
            matches!(
                out.decision,
                ActivationDecision::Degraded {
                    reason: GuardFailureReason::ExpiredReceipt,
                    ..
                }
            ),
            "receipt at exact expiry boundary must degrade (fail-closed)"
        );
    }
}
