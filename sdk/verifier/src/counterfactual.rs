//! Counterfactual replay receipt verification for external verifiers.
//!
//! The producer-side counterfactual replay tool signs the deterministic JSON
//! emitted by `tools::counterfactual_replay::to_canonical_json`. This module
//! mirrors that key-sorted JSON canonicalization and verifies the detached
//! Ed25519 receipt signature without depending on franken-node internals.

use std::fmt;

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use subtle::ConstantTimeEq;

use crate::bundle::{
    BundleError, CapabilityPolicyProfile, CapabilityPostcondition, CapabilityProof,
    CapabilityRevocationFreshness, CapabilityScope, EffectKind, verify_capability_proof_schema,
    verify_ed25519_signature,
};

/// Errors returned while verifying signed counterfactual replay receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CounterfactualReceiptError {
    Json(String),
    BaselineIntegrityHashMissing,
    BaselineIntegrityHashMalformed { actual: String },
    ResultsEnvelopeMalformed { actual: String },
    CounterfactualBundleHashMissing,
    CounterfactualBundleHashMalformed { actual: String },
    SweepResultBundleHashMissing { index: usize },
    SweepResultBundleHashMalformed { index: usize, actual: String },
    CounterfactualBundleHashMismatch { expected: String, actual: String },
    Signature(BundleError),
}

impl fmt::Display for CounterfactualReceiptError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(message) => {
                write!(formatter, "counterfactual receipt JSON error: {message}")
            }
            Self::BaselineIntegrityHashMissing => {
                write!(formatter, "baseline bundle integrity_hash is missing")
            }
            Self::BaselineIntegrityHashMalformed { actual } => write!(
                formatter,
                "baseline bundle integrity_hash must be a 64-nybble hex digest: got {actual}"
            ),
            Self::ResultsEnvelopeMalformed { actual } => write!(
                formatter,
                "counterfactual receipt results must be a non-empty array when present: got {actual}"
            ),
            Self::CounterfactualBundleHashMissing => {
                write!(
                    formatter,
                    "counterfactual receipt metadata.bundle_hash is missing"
                )
            }
            Self::CounterfactualBundleHashMalformed { actual } => write!(
                formatter,
                "counterfactual receipt metadata.bundle_hash must be a 64-nybble hex digest: got {actual}"
            ),
            Self::SweepResultBundleHashMissing { index } => {
                write!(
                    formatter,
                    "counterfactual receipt results[{index}].metadata.bundle_hash is missing"
                )
            }
            Self::SweepResultBundleHashMalformed { index, actual } => write!(
                formatter,
                "counterfactual receipt results[{index}].metadata.bundle_hash must be a 64-nybble hex digest: got {actual}"
            ),
            Self::CounterfactualBundleHashMismatch { expected, actual } => write!(
                formatter,
                "counterfactual receipt bundle hash mismatch: expected {expected}, got {actual}"
            ),
            Self::Signature(source) => {
                write!(
                    formatter,
                    "counterfactual receipt signature invalid: {source}"
                )
            }
        }
    }
}

impl std::error::Error for CounterfactualReceiptError {}

/// Standard result type returned by counterfactual receipt verification.
pub type CounterfactualReceiptResult<T> = Result<T, CounterfactualReceiptError>;

/// Counterfactual capability decision emitted by a producing runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CounterfactualCapabilityDecision {
    Allow,
    Deny,
}

impl CounterfactualCapabilityDecision {
    const fn label(self) -> &'static str {
        match self {
            Self::Allow => "allow",
            Self::Deny => "deny",
        }
    }
}

/// Capability attempt that an external verifier can replay without runtime access.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CounterfactualCapabilityRequest {
    pub actor: String,
    pub audience: String,
    pub requested_scope: CapabilityScope,
    pub policy_profile: CapabilityPolicyProfile,
    pub epoch: u64,
    pub side_effect_kind: EffectKind,
    pub observed_postconditions: Vec<CapabilityPostcondition>,
}

/// Offline validation report for a counterfactual capability decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CounterfactualCapabilityValidation {
    pub proof_id: String,
    pub proof_hash: String,
    pub actor: String,
    pub audience: String,
    pub scope: CapabilityScope,
    pub policy_profile: String,
    pub epoch: u64,
    pub side_effect_kind: String,
    pub decision: String,
    pub expected_decision: String,
    pub allowed: bool,
    pub reason: String,
    pub postcondition_count: usize,
}

/// Errors returned while replaying counterfactual capability decisions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CounterfactualCapabilityError {
    Proof(BundleError),
    DecisionMismatch {
        expected: String,
        actual: String,
        reason: String,
    },
}

impl fmt::Display for CounterfactualCapabilityError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Proof(source) => {
                write!(
                    formatter,
                    "counterfactual capability proof invalid: {source}"
                )
            }
            Self::DecisionMismatch {
                expected,
                actual,
                reason,
            } => write!(
                formatter,
                "counterfactual capability decision mismatch: expected {expected}, got {actual} ({reason})"
            ),
        }
    }
}

impl std::error::Error for CounterfactualCapabilityError {}

/// Standard result type returned by counterfactual capability validation.
pub type CounterfactualCapabilityResult<T> = Result<T, CounterfactualCapabilityError>;

/// Verify a signed counterfactual replay receipt.
///
/// `baseline_bundle` may be any serializable baseline bundle shape that carries
/// an `integrity_hash` field. `counterfactual_output` may be either a
/// `CounterfactualResult`-shaped object with `metadata.bundle_hash` or a sweep
/// output with `results[*].metadata.bundle_hash`. The Ed25519 signature covers
/// only the deterministic JSON bytes of `counterfactual_output`, matching
/// `tools::counterfactual_replay::to_canonical_json`.
///
/// # Examples
///
/// ```rust,ignore
/// use frankenengine_verifier_sdk::counterfactual::verify_counterfactual_receipt;
///
/// verify_counterfactual_receipt(
///     &baseline_bundle,
///     &counterfactual_output,
///     &verifying_key,
///     &signature_bytes,
/// )?;
/// ```
pub fn verify_counterfactual_receipt<B, O>(
    baseline_bundle: &B,
    counterfactual_output: &O,
    verifying_key: &VerifyingKey,
    signature_bytes: &[u8],
) -> CounterfactualReceiptResult<()>
where
    B: Serialize,
    O: Serialize,
{
    let baseline_value = to_value(baseline_bundle)?;
    let expected_bundle_hash = extract_nonempty_string(&baseline_value, &["integrity_hash"])
        .ok_or(CounterfactualReceiptError::BaselineIntegrityHashMissing)?;
    validate_bundle_hash(expected_bundle_hash)
        .map_err(|actual| CounterfactualReceiptError::BaselineIntegrityHashMalformed { actual })?;
    let counterfactual_value = to_value(counterfactual_output)?;
    ensure_counterfactual_references_bundle(&counterfactual_value, expected_bundle_hash)?;
    let canonical = canonical_json_bytes(&counterfactual_value)?;
    verify_ed25519_signature(verifying_key, &canonical, signature_bytes)
        .map_err(CounterfactualReceiptError::Signature)
}

/// Replay a capability allow/deny decision against an independently checkable proof.
pub fn validate_counterfactual_capability_decision(
    proof: &CapabilityProof,
    request: &CounterfactualCapabilityRequest,
    decision: CounterfactualCapabilityDecision,
) -> CounterfactualCapabilityResult<CounterfactualCapabilityValidation> {
    let proof_hash =
        verify_capability_proof_schema(proof).map_err(CounterfactualCapabilityError::Proof)?;
    let denial_reason = counterfactual_capability_denial_reason(proof, request);
    let expected_decision = if denial_reason.is_some() {
        CounterfactualCapabilityDecision::Deny
    } else {
        CounterfactualCapabilityDecision::Allow
    };
    let reason =
        denial_reason.unwrap_or_else(|| "proof and request bindings permit capability".to_string());

    if decision != expected_decision {
        return Err(CounterfactualCapabilityError::DecisionMismatch {
            expected: expected_decision.label().to_string(),
            actual: decision.label().to_string(),
            reason,
        });
    }

    Ok(CounterfactualCapabilityValidation {
        proof_id: proof.proof_id.clone(),
        proof_hash,
        actor: request.actor.clone(),
        audience: request.audience.clone(),
        scope: request.requested_scope.clone(),
        policy_profile: capability_policy_profile_label(request.policy_profile).to_string(),
        epoch: request.epoch,
        side_effect_kind: effect_kind_label(request.side_effect_kind).to_string(),
        decision: decision.label().to_string(),
        expected_decision: expected_decision.label().to_string(),
        allowed: decision == CounterfactualCapabilityDecision::Allow,
        reason,
        postcondition_count: request.observed_postconditions.len(),
    })
}

fn counterfactual_capability_denial_reason(
    proof: &CapabilityProof,
    request: &CounterfactualCapabilityRequest,
) -> Option<String> {
    if !matches!(
        proof.revocation_freshness,
        CapabilityRevocationFreshness::Fresh { .. }
    ) {
        return Some("capability proof lacks fresh revocation evidence".to_string());
    }
    if !constant_time_eq(&proof.actor, &request.actor) {
        return Some("actor binding mismatch".to_string());
    }
    if !constant_time_eq(&proof.audience, &request.audience) {
        return Some("audience binding mismatch".to_string());
    }
    if proof.policy_profile != request.policy_profile {
        return Some("policy profile binding mismatch".to_string());
    }
    if proof.epoch != request.epoch {
        return Some("epoch binding mismatch".to_string());
    }
    if proof.side_effect_kind != request.side_effect_kind {
        return Some("side effect kind binding mismatch".to_string());
    }
    if !proof.scopes.contains(&request.requested_scope) {
        return Some("requested scope is outside capability proof".to_string());
    }
    if proof.expected_postconditions != request.observed_postconditions {
        return Some("observed postconditions do not match proof".to_string());
    }
    None
}

fn capability_policy_profile_label(profile: CapabilityPolicyProfile) -> &'static str {
    match profile {
        CapabilityPolicyProfile::Strict => "strict",
        CapabilityPolicyProfile::Balanced => "balanced",
        CapabilityPolicyProfile::LegacyRisky => "legacy_risky",
    }
}

fn effect_kind_label(kind: EffectKind) -> &'static str {
    match kind {
        EffectKind::FsRead => "fs_read",
        EffectKind::FsWrite => "fs_write",
        EffectKind::NetConnect => "net_connect",
        EffectKind::HttpRequest => "http_request",
        EffectKind::Spawn => "spawn",
        EffectKind::ModuleResolve => "module_resolve",
    }
}

fn to_value<T: Serialize>(value: &T) -> Result<Value, CounterfactualReceiptError> {
    serde_json::to_value(value)
        .map_err(|source| CounterfactualReceiptError::Json(source.to_string()))
}

fn ensure_counterfactual_references_bundle(
    output: &Value,
    expected_bundle_hash: &str,
) -> Result<(), CounterfactualReceiptError> {
    if let Some(results_value) = output.get("results") {
        let results = results_value.as_array().ok_or_else(|| {
            CounterfactualReceiptError::ResultsEnvelopeMalformed {
                actual: describe_value_kind(results_value),
            }
        })?;
        if results.is_empty() {
            return Err(CounterfactualReceiptError::ResultsEnvelopeMalformed {
                actual: "array(len=0)".to_string(),
            });
        }
        if let Some(actual_value) = extract_value(output, &["metadata", "bundle_hash"]) {
            let actual = actual_value.as_str().ok_or_else(|| {
                CounterfactualReceiptError::CounterfactualBundleHashMalformed {
                    actual: describe_value_kind(actual_value),
                }
            })?;
            if actual.trim().is_empty() {
                return Err(
                    CounterfactualReceiptError::CounterfactualBundleHashMalformed {
                        actual: actual.to_string(),
                    },
                );
            }
            validate_bundle_hash(actual).map_err(|actual| {
                CounterfactualReceiptError::CounterfactualBundleHashMalformed { actual }
            })?;
            if !constant_time_eq(actual, expected_bundle_hash) {
                return Err(
                    CounterfactualReceiptError::CounterfactualBundleHashMismatch {
                        expected: expected_bundle_hash.to_string(),
                        actual: actual.to_string(),
                    },
                );
            }
        }
        for (index, result) in results.iter().enumerate() {
            let actual = extract_nonempty_string(result, &["metadata", "bundle_hash"])
                .ok_or(CounterfactualReceiptError::SweepResultBundleHashMissing { index })?;
            validate_bundle_hash(actual).map_err(|actual| {
                CounterfactualReceiptError::SweepResultBundleHashMalformed { index, actual }
            })?;
            if !constant_time_eq(actual, expected_bundle_hash) {
                return Err(
                    CounterfactualReceiptError::CounterfactualBundleHashMismatch {
                        expected: expected_bundle_hash.to_string(),
                        actual: actual.to_string(),
                    },
                );
            }
        }
        return Ok(());
    }

    let actual = extract_nonempty_string(output, &["metadata", "bundle_hash"])
        .ok_or(CounterfactualReceiptError::CounterfactualBundleHashMissing)?;
    validate_bundle_hash(actual).map_err(|actual| {
        CounterfactualReceiptError::CounterfactualBundleHashMalformed { actual }
    })?;
    if !constant_time_eq(actual, expected_bundle_hash) {
        return Err(
            CounterfactualReceiptError::CounterfactualBundleHashMismatch {
                expected: expected_bundle_hash.to_string(),
                actual: actual.to_string(),
            },
        );
    }
    Ok(())
}

fn extract_value<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    let mut cursor = value;
    for segment in path {
        cursor = cursor.get(*segment)?;
    }
    Some(cursor)
}

fn describe_value_kind(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(boolean) => format!("bool({boolean})"),
        Value::Number(number) => format!("number({number})"),
        Value::String(string) => format!("string({string})"),
        Value::Array(items) => format!("array(len={})", items.len()),
        Value::Object(object) => format!("object(len={})", object.len()),
    }
}

fn extract_string<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    extract_value(value, path)?.as_str()
}

fn extract_nonempty_string<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let value = extract_string(value, path)?;
    if value.trim().is_empty() {
        None
    } else {
        Some(value)
    }
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    bool::from(left.as_bytes().ct_eq(right.as_bytes()))
}

fn validate_bundle_hash(value: &str) -> Result<(), String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        Err(value.to_string())
    }
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, CounterfactualReceiptError> {
    let canonical = canonicalize_json(value);
    serde_json::to_vec(&canonical)
        .map_err(|source| CounterfactualReceiptError::Json(source.to_string()))
}

fn canonicalize_json(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            let mut out = serde_json::Map::with_capacity(map.len());
            for key in keys {
                if let Some(value) = map.get(key) {
                    out.insert(key.to_string(), canonicalize_json(value));
                }
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json).collect()),
        _ => value.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use serde_json::json;

    const TEST_BUNDLE_HASH: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn sign_counterfactual_value(value: &Value, signing_key: &SigningKey) -> Vec<u8> {
        let canonical = canonical_json_bytes(value).expect("test canonical JSON should serialize");
        signing_key.sign(&canonical).to_bytes().to_vec()
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_sweep_result_missing_bundle_hash() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {}}
            ]
        });
        let signing_key = SigningKey::from_bytes(&[7_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("sweep result missing bundle_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::SweepResultBundleHashMissing { index: 1 }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_accepts_sweep_when_all_results_match_bundle_hash() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}}
            ]
        });
        let signing_key = SigningKey::from_bytes(&[8_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect("sweep with matching bundle_hash on every result should verify");
    }

    #[test]
    fn verify_counterfactual_receipt_accepts_matching_top_level_bundle_hash_for_sweep() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}}
            ],
            "metadata": {"bundle_hash": TEST_BUNDLE_HASH}
        });
        let signing_key = SigningKey::from_bytes(&[26_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect("matching top-level bundle_hash should verify for sweep receipts");
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_conflicting_top_level_bundle_hash_for_sweep() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let conflicting_hash = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}}
            ],
            "metadata": {"bundle_hash": conflicting_hash}
        });
        let signing_key = SigningKey::from_bytes(&[27_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("conflicting top-level bundle_hash must fail closed for sweep receipts");

        assert_eq!(
            err,
            CounterfactualReceiptError::CounterfactualBundleHashMismatch {
                expected: TEST_BUNDLE_HASH.to_string(),
                actual: conflicting_hash.to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_empty_top_level_bundle_hash_for_sweep() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}}
            ],
            "metadata": {"bundle_hash": "   "}
        });
        let signing_key = SigningKey::from_bytes(&[28_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("empty top-level bundle_hash must fail closed for sweep receipts");

        assert_eq!(
            err,
            CounterfactualReceiptError::CounterfactualBundleHashMalformed {
                actual: "   ".to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_non_string_top_level_bundle_hash_for_sweep() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}}
            ],
            "metadata": {"bundle_hash": 7}
        });
        let signing_key = SigningKey::from_bytes(&[29_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("non-string top-level bundle_hash must fail closed for sweep receipts");

        assert_eq!(
            err,
            CounterfactualReceiptError::CounterfactualBundleHashMalformed {
                actual: "number(7)".to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_object_results_envelope() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
            "metadata": {"bundle_hash": TEST_BUNDLE_HASH}
        });
        let signing_key = SigningKey::from_bytes(&[21_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("object results envelope must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::ResultsEnvelopeMalformed {
                actual: "object(len=1)".to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_string_results_envelope() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": "not-an-array",
            "metadata": {"bundle_hash": TEST_BUNDLE_HASH}
        });
        let signing_key = SigningKey::from_bytes(&[22_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("string results envelope must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::ResultsEnvelopeMalformed {
                actual: "string(not-an-array)".to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_null_results_envelope() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": Value::Null,
            "metadata": {"bundle_hash": TEST_BUNDLE_HASH}
        });
        let signing_key = SigningKey::from_bytes(&[23_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("null results envelope must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::ResultsEnvelopeMalformed {
                actual: "null".to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_empty_results_envelope() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": [],
            "metadata": {"bundle_hash": TEST_BUNDLE_HASH}
        });
        let signing_key = SigningKey::from_bytes(&[24_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("empty results envelope must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::ResultsEnvelopeMalformed {
                actual: "array(len=0)".to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_empty_baseline_integrity_hash() {
        let baseline_bundle = json!({"integrity_hash": "   "});
        let counterfactual_output = json!({
            "metadata": {"bundle_hash": TEST_BUNDLE_HASH}
        });
        let signing_key = SigningKey::from_bytes(&[9_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("empty baseline integrity_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::BaselineIntegrityHashMissing
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_empty_counterfactual_bundle_hash() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "metadata": {"bundle_hash": "   "}
        });
        let signing_key = SigningKey::from_bytes(&[10_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("empty signed counterfactual bundle_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::CounterfactualBundleHashMissing
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_empty_sweep_result_bundle_hash() {
        let baseline_bundle = json!({"integrity_hash": TEST_BUNDLE_HASH});
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {"bundle_hash": "  "}}
            ]
        });
        let signing_key = SigningKey::from_bytes(&[11_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("empty sweep result bundle_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::SweepResultBundleHashMissing { index: 1 }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_malformed_baseline_integrity_hash() {
        let baseline_bundle = json!({"integrity_hash": "not-a-hash"});
        let counterfactual_output = json!({
            "metadata": {"bundle_hash": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}
        });
        let signing_key = SigningKey::from_bytes(&[12_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("malformed baseline integrity_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::BaselineIntegrityHashMalformed {
                actual: "not-a-hash".to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_whitespace_padded_baseline_integrity_hash() {
        let baseline_bundle = json!({
            "integrity_hash": format!(" {TEST_BUNDLE_HASH} ")
        });
        let counterfactual_output = json!({
            "metadata": {"bundle_hash": TEST_BUNDLE_HASH}
        });
        let signing_key = SigningKey::from_bytes(&[15_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("whitespace-padded baseline integrity_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::BaselineIntegrityHashMalformed {
                actual: format!(" {TEST_BUNDLE_HASH} "),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_uppercase_baseline_integrity_hash() {
        let baseline_bundle = json!({
            "integrity_hash": TEST_BUNDLE_HASH.to_uppercase()
        });
        let counterfactual_output = json!({
            "metadata": {"bundle_hash": TEST_BUNDLE_HASH}
        });
        let signing_key = SigningKey::from_bytes(&[18_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("uppercase baseline integrity_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::BaselineIntegrityHashMalformed {
                actual: TEST_BUNDLE_HASH.to_uppercase(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_malformed_counterfactual_bundle_hash() {
        let baseline_bundle = json!({ "integrity_hash": TEST_BUNDLE_HASH });
        let counterfactual_output = json!({
            "metadata": {"bundle_hash": "bad-hash"}
        });
        let signing_key = SigningKey::from_bytes(&[13_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("malformed signed counterfactual bundle_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::CounterfactualBundleHashMalformed {
                actual: "bad-hash".to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_whitespace_padded_counterfactual_bundle_hash() {
        let baseline_bundle = json!({ "integrity_hash": TEST_BUNDLE_HASH });
        let counterfactual_output = json!({
            "metadata": {"bundle_hash": format!(" {TEST_BUNDLE_HASH} ")}
        });
        let signing_key = SigningKey::from_bytes(&[16_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("whitespace-padded signed counterfactual bundle_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::CounterfactualBundleHashMalformed {
                actual: format!(" {TEST_BUNDLE_HASH} "),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_uppercase_counterfactual_bundle_hash() {
        let baseline_bundle = json!({ "integrity_hash": TEST_BUNDLE_HASH });
        let counterfactual_output = json!({
            "metadata": {"bundle_hash": TEST_BUNDLE_HASH.to_uppercase()}
        });
        let signing_key = SigningKey::from_bytes(&[19_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("uppercase signed counterfactual bundle_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::CounterfactualBundleHashMalformed {
                actual: TEST_BUNDLE_HASH.to_uppercase(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_malformed_sweep_result_bundle_hash() {
        let baseline_bundle = json!({ "integrity_hash": TEST_BUNDLE_HASH });
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {"bundle_hash": "still-not-a-hash"}}
            ]
        });
        let signing_key = SigningKey::from_bytes(&[14_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("malformed sweep result bundle_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::SweepResultBundleHashMalformed {
                index: 1,
                actual: "still-not-a-hash".to_string(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_uppercase_sweep_result_bundle_hash() {
        let baseline_bundle = json!({ "integrity_hash": TEST_BUNDLE_HASH });
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH.to_uppercase()}}
            ]
        });
        let signing_key = SigningKey::from_bytes(&[20_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("uppercase sweep result bundle_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::SweepResultBundleHashMalformed {
                index: 1,
                actual: TEST_BUNDLE_HASH.to_uppercase(),
            }
        );
    }

    #[test]
    fn verify_counterfactual_receipt_rejects_whitespace_padded_sweep_result_bundle_hash() {
        let baseline_bundle = json!({ "integrity_hash": TEST_BUNDLE_HASH });
        let counterfactual_output = json!({
            "results": [
                {"metadata": {"bundle_hash": TEST_BUNDLE_HASH}},
                {"metadata": {"bundle_hash": format!(" {TEST_BUNDLE_HASH} ")}}
            ]
        });
        let signing_key = SigningKey::from_bytes(&[17_u8; 32]);
        let signature_bytes = sign_counterfactual_value(&counterfactual_output, &signing_key);

        let err = verify_counterfactual_receipt(
            &baseline_bundle,
            &counterfactual_output,
            &signing_key.verifying_key(),
            &signature_bytes,
        )
        .expect_err("whitespace-padded sweep result bundle_hash must fail closed");

        assert_eq!(
            err,
            CounterfactualReceiptError::SweepResultBundleHashMalformed {
                index: 1,
                actual: format!(" {TEST_BUNDLE_HASH} "),
            }
        );
    }
}
