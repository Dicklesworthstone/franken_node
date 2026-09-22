//! Verifier SDK independent counterfactual receipt verification tests.
//!
//! Validates that the SDK can independently verify counterfactual receipts
//! and detect payload tampering without depending on the runtime crate.

use ed25519_dalek::{Signer, SigningKey};
use frankenengine_verifier_sdk::bundle::BundleError;
use frankenengine_verifier_sdk::counterfactual::{
    CounterfactualReceiptError, canonical_json_bytes, verify_counterfactual_receipt,
};
use serde_json::json;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

const TEST_BUNDLE_HASH: &str =
    "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

#[test]
fn counterfactual_receipt_roundtrip_and_tamper_detection() -> TestResult {
    let baseline_bundle = json!({
        "schema_version": "v1.0",
        "bundle_id": "INC-SDK-CF-VERIFY-001",
        "integrity_hash": TEST_BUNDLE_HASH,
    });

    let output = json!({
        "metadata": {
            "bundle_hash": TEST_BUNDLE_HASH,
            "policy": "strict",
            "confidence": 95,
        },
        "summary_statistics": {
            "total_decisions": 10,
            "changed_decisions": 0,
        },
        "results": [
            {
                "metadata": {
                    "bundle_hash": TEST_BUNDLE_HASH,
                },
                "decision": "observe",
            }
        ]
    });

    let signing_key = SigningKey::from_bytes(&[17_u8; 32]);
    let canonical = canonical_json_bytes(&output)?;
    let signature = signing_key.sign(&canonical);
    let signature_bytes = signature.to_bytes();

    // Valid verification passes
    verify_counterfactual_receipt(
        &baseline_bundle,
        &output,
        &signing_key.verifying_key(),
        &signature_bytes,
    )?;

    // Tampering output fails verification
    let mut tampered_output = output.clone();
    tampered_output["summary_statistics"]["changed_decisions"] = json!(1);

    let err = verify_counterfactual_receipt(
        &baseline_bundle,
        &tampered_output,
        &signing_key.verifying_key(),
        &signature_bytes,
    )
    .expect_err("tampered counterfactual output unexpectedly verified");

    if err != CounterfactualReceiptError::Signature(BundleError::Ed25519SignatureInvalid) {
        return Err(format!("unexpected tamper verification error: {err}").into());
    }

    Ok(())
}
