//! Counterfactual replay receipt verification for external verifiers.
//!
//! The producer-side counterfactual replay tool signs the deterministic JSON
//! emitted by `tools::counterfactual_replay::to_canonical_json`. This module
//! mirrors that key-sorted JSON canonicalization and verifies the detached
//! Ed25519 receipt signature without depending on franken-node internals.

use std::fmt;

use ed25519_dalek::VerifyingKey;
use serde::Serialize;
use serde_json::Value;

use crate::bundle::{BundleError, verify_ed25519_signature};

/// Errors returned while verifying signed counterfactual replay receipts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CounterfactualReceiptError {
    Json(String),
    BaselineIntegrityHashMissing,
    BaselineIntegrityHashMalformed { actual: String },
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

/// Verify a signed counterfactual replay receipt.
///
/// `baseline_bundle` may be any serializable baseline bundle shape that carries
/// an `integrity_hash` field. `counterfactual_output` may be either a
/// `CounterfactualResult`-shaped object with `metadata.bundle_hash` or a sweep
/// output with `results[*].metadata.bundle_hash`. The Ed25519 signature covers
/// only the deterministic JSON bytes of `counterfactual_output`, matching
/// `tools::counterfactual_replay::to_canonical_json`.
pub fn verify_counterfactual_receipt<B, O>(
    baseline_bundle: &B,
    counterfactual_output: &O,
    verifying_key: &VerifyingKey,
    signature_bytes: &[u8],
) -> Result<(), CounterfactualReceiptError>
where
    B: Serialize,
    O: Serialize,
{
    let baseline_value = to_value(baseline_bundle)?;
    let expected_bundle_hash = extract_nonempty_string(&baseline_value, &["integrity_hash"])
        .ok_or(CounterfactualReceiptError::BaselineIntegrityHashMissing)?;
    validate_bundle_hash(expected_bundle_hash).map_err(|actual| {
        CounterfactualReceiptError::BaselineIntegrityHashMalformed { actual }
    })?;
    let counterfactual_value = to_value(counterfactual_output)?;
    ensure_counterfactual_references_bundle(&counterfactual_value, expected_bundle_hash)?;
    let canonical = canonical_json_bytes(&counterfactual_value)?;
    verify_ed25519_signature(verifying_key, &canonical, signature_bytes)
        .map_err(CounterfactualReceiptError::Signature)
}

fn to_value<T: Serialize>(value: &T) -> Result<Value, CounterfactualReceiptError> {
    serde_json::to_value(value)
        .map_err(|source| CounterfactualReceiptError::Json(source.to_string()))
}

fn ensure_counterfactual_references_bundle(
    output: &Value,
    expected_bundle_hash: &str,
) -> Result<(), CounterfactualReceiptError> {
    if let Some(results) = value_results(output) {
        if results.is_empty() {
            return Err(CounterfactualReceiptError::CounterfactualBundleHashMissing);
        }
        for (index, result) in results.iter().enumerate() {
            let actual = extract_nonempty_string(result, &["metadata", "bundle_hash"])
                .ok_or(CounterfactualReceiptError::SweepResultBundleHashMissing { index })?;
            validate_bundle_hash(actual).map_err(|actual| {
                CounterfactualReceiptError::SweepResultBundleHashMalformed { index, actual }
            })?;
            if actual != expected_bundle_hash {
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
    validate_bundle_hash(actual)
        .map_err(|actual| CounterfactualReceiptError::CounterfactualBundleHashMalformed {
            actual,
        })?;
    if actual != expected_bundle_hash {
        return Err(
            CounterfactualReceiptError::CounterfactualBundleHashMismatch {
                expected: expected_bundle_hash.to_string(),
                actual: actual.to_string(),
            },
        );
    }
    Ok(())
}

fn value_results(value: &Value) -> Option<&[Value]> {
    value.get("results").and_then(Value::as_array).map(Vec::as_slice)
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

        assert_eq!(err, CounterfactualReceiptError::BaselineIntegrityHashMissing);
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

        assert_eq!(err, CounterfactualReceiptError::CounterfactualBundleHashMissing);
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
}

fn extract_string<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let mut cursor = value;
    for segment in path {
        cursor = cursor.get(*segment)?;
    }
    cursor.as_str()
}

fn extract_nonempty_string<'a>(value: &'a Value, path: &[&str]) -> Option<&'a str> {
    let value = extract_string(value, path)?;
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn validate_bundle_hash(value: &str) -> Result<(), String> {
    if value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
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
                out.insert(key.to_string(), canonicalize_json(&map[key]));
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(canonicalize_json).collect()),
        _ => value.clone(),
    }
}
