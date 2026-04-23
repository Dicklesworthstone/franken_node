//! Doctor Close-Condition JSON Output Conformance Harness
//!
//! Tests canonical CloseConditionReceipt JSON serialization against reference vectors.
//! Validates doctor close-condition output contract using artifacts/10.23/doctor_close_condition_vectors.json.
//!
//! Coverage:
//! - Round-trip JSON serialization/deserialization
//! - Schema version validation
//! - Composite verdict computation logic
//! - Failing dimensions array correctness
//! - Signature structure conformance
//! - Canonical hash computation

use frankenengine_node::ops::close_condition::{
    CloseConditionReceipt, CloseConditionReceiptCore, CloseConditionReceiptSignature,
    L1ProductOracle, L2EngineBoundaryOracle, OracleColor, ReleasePolicyLinkage,
    SplitContractCheck, SplitContractSummary, TamperEvidence,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

/// Load reference vectors from embedded artifact file.
const DOCTOR_CLOSE_CONDITION_VECTORS_JSON: &str =
    include_str!("../../../artifacts/10.23/doctor_close_condition_vectors.json");

#[derive(Debug, Deserialize)]
struct DoctorCloseConditionConformanceVectors {
    #[allow(dead_code)]
    bead_id: String,
    schema_version: String,
    receipt_schema_version: String,
    #[allow(dead_code)]
    description: String,
    vectors: Vec<DoctorCloseConditionVector>,
}

#[derive(Debug, Deserialize)]
struct DoctorCloseConditionVector {
    name: String,
    input_receipt: RawCloseConditionReceipt,
    expected_hash: String,
    expected_composite_verdict: String,
    expected_failing_dimensions: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RawCloseConditionReceipt {
    schema_version: String,
    receipt_path: String,
    generated_at_utc: String,
    #[serde(rename = "L1_product_oracle")]
    l1_product_oracle: RawL1ProductOracle,
    #[serde(rename = "L2_engine_boundary_oracle")]
    l2_engine_boundary_oracle: RawL2EngineBoundaryOracle,
    release_policy_linkage: RawReleasePolicyLinkage,
    composite_verdict: String,
    failing_dimensions: Vec<String>,
    tamper_evidence: RawTamperEvidence,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RawL1ProductOracle {
    verdict: String,
    source_path: String,
    corpus_version: Option<String>,
    total_test_cases: u64,
    passed_test_cases: u64,
    failed_test_cases: u64,
    errored_test_cases: u64,
    skipped_test_cases: u64,
    pass_rate_pct: f64,
    required_pass_rate_pct: f64,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RawL2EngineBoundaryOracle {
    verdict: String,
    source: String,
    contract_ref: String,
    checks: Vec<RawSplitContractCheck>,
    summary: RawSplitContractSummary,
    blocking_findings: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RawSplitContractCheck {
    id: String,
    status: String,
    details: Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RawSplitContractSummary {
    total_checks: u64,
    passed_checks: u64,
    failing_checks: u64,
    overall_verdict: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RawReleasePolicyLinkage {
    verdict: String,
    source: String,
    ci_outputs_accessible: bool,
    ci_output_ref: Option<String>,
    consumed_oracles: Vec<String>,
    blocking_findings: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RawTamperEvidence {
    algorithm: String,
    canonicalization: String,
    hash_scope: String,
    sha256: String,
    signature: RawSignature,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
struct RawSignature {
    algorithm: String,
    public_key_hex: String,
    key_id: String,
    key_source: String,
    signing_identity: String,
    trust_scope: String,
    signed_payload_sha256: String,
    signature_hex: String,
}

impl From<RawCloseConditionReceipt> for CloseConditionReceipt {
    fn from(raw: RawCloseConditionReceipt) -> Self {
        let composite_verdict = match raw.composite_verdict.as_str() {
            "Green" => OracleColor::Green,
            "Red" => OracleColor::Red,
            _ => panic!("Unknown composite verdict: {}", raw.composite_verdict),
        };

        let l1_verdict = match raw.l1_product_oracle.verdict.as_str() {
            "Green" => OracleColor::Green,
            "Red" => OracleColor::Red,
            _ => panic!("Unknown L1 verdict: {}", raw.l1_product_oracle.verdict),
        };

        let l2_verdict = match raw.l2_engine_boundary_oracle.verdict.as_str() {
            "Green" => OracleColor::Green,
            "Red" => OracleColor::Red,
            _ => panic!("Unknown L2 verdict: {}", raw.l2_engine_boundary_oracle.verdict),
        };

        let release_verdict = match raw.release_policy_linkage.verdict.as_str() {
            "Green" => OracleColor::Green,
            "Red" => OracleColor::Red,
            _ => panic!("Unknown release verdict: {}", raw.release_policy_linkage.verdict),
        };

        let l1_product_oracle = L1ProductOracle {
            verdict: l1_verdict,
            source_path: raw.l1_product_oracle.source_path,
            corpus_version: raw.l1_product_oracle.corpus_version,
            total_test_cases: raw.l1_product_oracle.total_test_cases,
            passed_test_cases: raw.l1_product_oracle.passed_test_cases,
            failed_test_cases: raw.l1_product_oracle.failed_test_cases,
            errored_test_cases: raw.l1_product_oracle.errored_test_cases,
            skipped_test_cases: raw.l1_product_oracle.skipped_test_cases,
            pass_rate_pct: raw.l1_product_oracle.pass_rate_pct,
            required_pass_rate_pct: raw.l1_product_oracle.required_pass_rate_pct,
        };

        let l2_checks: Vec<SplitContractCheck> = raw
            .l2_engine_boundary_oracle
            .checks
            .into_iter()
            .map(|check| SplitContractCheck {
                id: check.id,
                status: match check.status.as_str() {
                    "Green" => OracleColor::Green,
                    "Red" => OracleColor::Red,
                    _ => panic!("Unknown check status: {}", check.status),
                },
                details: check.details,
            })
            .collect();

        let l2_summary = SplitContractSummary {
            total_checks: raw.l2_engine_boundary_oracle.summary.total_checks,
            passed_checks: raw.l2_engine_boundary_oracle.summary.passed_checks,
            failing_checks: raw.l2_engine_boundary_oracle.summary.failing_checks,
            overall_verdict: match raw.l2_engine_boundary_oracle.summary.overall_verdict.as_str() {
                "Green" => OracleColor::Green,
                "Red" => OracleColor::Red,
                _ => panic!("Unknown summary verdict: {}", raw.l2_engine_boundary_oracle.summary.overall_verdict),
            },
        };

        let l2_engine_boundary_oracle = L2EngineBoundaryOracle {
            verdict: l2_verdict,
            source: raw.l2_engine_boundary_oracle.source,
            contract_ref: raw.l2_engine_boundary_oracle.contract_ref,
            checks: l2_checks,
            summary: l2_summary,
            blocking_findings: raw.l2_engine_boundary_oracle.blocking_findings,
        };

        let release_policy_linkage = ReleasePolicyLinkage {
            verdict: release_verdict,
            source: raw.release_policy_linkage.source,
            ci_outputs_accessible: raw.release_policy_linkage.ci_outputs_accessible,
            ci_output_ref: raw.release_policy_linkage.ci_output_ref,
            consumed_oracles: raw.release_policy_linkage.consumed_oracles,
            blocking_findings: raw.release_policy_linkage.blocking_findings,
        };

        let signature = CloseConditionReceiptSignature {
            algorithm: raw.tamper_evidence.signature.algorithm,
            public_key_hex: raw.tamper_evidence.signature.public_key_hex,
            key_id: raw.tamper_evidence.signature.key_id,
            key_source: raw.tamper_evidence.signature.key_source,
            signing_identity: raw.tamper_evidence.signature.signing_identity,
            trust_scope: raw.tamper_evidence.signature.trust_scope,
            signed_payload_sha256: raw.tamper_evidence.signature.signed_payload_sha256,
            signature_hex: raw.tamper_evidence.signature.signature_hex,
        };

        let tamper_evidence = TamperEvidence {
            algorithm: raw.tamper_evidence.algorithm,
            canonicalization: raw.tamper_evidence.canonicalization,
            hash_scope: raw.tamper_evidence.hash_scope,
            sha256: raw.tamper_evidence.sha256,
            signature,
        };

        let core = CloseConditionReceiptCore {
            schema_version: raw.schema_version,
            receipt_path: raw.receipt_path,
            generated_at_utc: raw.generated_at_utc,
            l1_product_oracle,
            l2_engine_boundary_oracle,
            release_policy_linkage,
            composite_verdict,
            failing_dimensions: raw.failing_dimensions,
        };

        Self {
            core,
            tamper_evidence,
        }
    }
}

/// Compute canonical hash for CloseConditionReceipt using domain-separated SHA256.
fn compute_canonical_hash(receipt: &CloseConditionReceipt) -> String {
    // For this test, we'll use the core receipt (excluding signature) for hashing
    let core_json = serde_json::to_string(&receipt.core)
        .expect("receipt core should serialize to JSON");

    let mut hasher = Sha256::new();
    hasher.update(b"close_condition_receipt_v1:");
    hasher.update(core_json.as_bytes());
    let hash = hasher.finalize();

    format!("sha256:{}", hex::encode(hash))
}

/// Load and parse conformance vectors from embedded artifact.
fn load_conformance_vectors() -> DoctorCloseConditionConformanceVectors {
    serde_json::from_str(DOCTOR_CLOSE_CONDITION_VECTORS_JSON)
        .expect("embedded doctor close-condition vectors should parse as JSON")
}

#[test]
fn doctor_close_condition_schema_version_matches_vectors() {
    let vectors = load_conformance_vectors();
    assert_eq!(
        vectors.receipt_schema_version,
        "oracle-close-condition-receipt/v1",
        "Receipt schema version in vectors should match expected constant"
    );
}

#[test]
fn doctor_close_condition_round_trip_conformance() {
    let vectors = load_conformance_vectors();

    for vector in &vectors.vectors {
        // Test round-trip: RawCloseConditionReceipt → CloseConditionReceipt → JSON → CloseConditionReceipt
        let receipt: CloseConditionReceipt = vector.input_receipt.clone().into();

        // Serialize to JSON
        let receipt_json = serde_json::to_string(&receipt)
            .unwrap_or_else(|e| panic!(
                "Vector '{}' should serialize to JSON: {}", vector.name, e
            ));

        // Deserialize back
        let roundtrip_receipt: CloseConditionReceipt = serde_json::from_str(&receipt_json)
            .unwrap_or_else(|e| panic!(
                "Vector '{}' JSON should deserialize back to CloseConditionReceipt: {}", vector.name, e
            ));

        // Core fields should be preserved
        assert_eq!(
            receipt.core.schema_version,
            roundtrip_receipt.core.schema_version,
            "Vector '{}': schema_version lost in round-trip", vector.name
        );

        assert_eq!(
            receipt.core.composite_verdict,
            roundtrip_receipt.core.composite_verdict,
            "Vector '{}': composite_verdict lost in round-trip", vector.name
        );

        assert_eq!(
            receipt.core.failing_dimensions,
            roundtrip_receipt.core.failing_dimensions,
            "Vector '{}': failing_dimensions lost in round-trip", vector.name
        );
    }
}

#[test]
fn doctor_close_condition_composite_verdict_conformance() {
    let vectors = load_conformance_vectors();

    for vector in &vectors.vectors {
        let receipt: CloseConditionReceipt = vector.input_receipt.clone().into();

        // Composite verdict should match expected
        let expected_verdict = match vector.expected_composite_verdict.as_str() {
            "Green" => OracleColor::Green,
            "Red" => OracleColor::Red,
            _ => panic!("Unknown expected verdict: {}", vector.expected_composite_verdict),
        };

        assert_eq!(
            receipt.core.composite_verdict,
            expected_verdict,
            "Vector '{}': composite verdict mismatch", vector.name
        );

        // Failing dimensions should match expected
        assert_eq!(
            receipt.core.failing_dimensions,
            vector.expected_failing_dimensions,
            "Vector '{}': failing dimensions mismatch", vector.name
        );
    }
}

#[test]
fn doctor_close_condition_canonical_hash_conformance() {
    let vectors = load_conformance_vectors();

    for vector in &vectors.vectors {
        let receipt: CloseConditionReceipt = vector.input_receipt.clone().into();
        let computed_hash = compute_canonical_hash(&receipt);

        assert_eq!(
            computed_hash,
            vector.expected_hash,
            "Vector '{}': canonical hash mismatch\n  computed: {}\n  expected: {}",
            vector.name, computed_hash, vector.expected_hash
        );
    }
}

#[test]
fn doctor_close_condition_deterministic_serialization_conformance() {
    let vectors = load_conformance_vectors();

    for vector in &vectors.vectors {
        let receipt: CloseConditionReceipt = vector.input_receipt.clone().into();

        // Same receipt should serialize identically multiple times
        let json1 = serde_json::to_string(&receipt).unwrap();
        let json2 = serde_json::to_string(&receipt).unwrap();

        assert_eq!(
            json1, json2,
            "Vector '{}': deterministic serialization failed", vector.name
        );

        // JSON should be parseable as generic Value
        let _: Value = serde_json::from_str(&json1)
            .unwrap_or_else(|e| panic!(
                "Vector '{}': serialized JSON is not valid: {}", vector.name, e
            ));
    }
}

#[test]
fn doctor_close_condition_schema_version_validation() {
    let vectors = load_conformance_vectors();

    for vector in &vectors.vectors {
        let receipt: CloseConditionReceipt = vector.input_receipt.clone().into();

        // Schema version should match expected constant
        assert_eq!(
            receipt.core.schema_version,
            "oracle-close-condition-receipt/v1",
            "Vector '{}': schema version should match constant", vector.name
        );
    }
}

#[test]
fn doctor_close_condition_signature_structure_conformance() {
    let vectors = load_conformance_vectors();

    for vector in &vectors.vectors {
        let receipt: CloseConditionReceipt = vector.input_receipt.clone().into();

        // Signature should have required fields
        assert!(!receipt.tamper_evidence.signature.algorithm.is_empty(),
            "Vector '{}': signature algorithm should not be empty", vector.name);

        assert!(!receipt.tamper_evidence.signature.public_key_hex.is_empty(),
            "Vector '{}': public key hex should not be empty", vector.name);

        assert!(!receipt.tamper_evidence.signature.key_id.is_empty(),
            "Vector '{}': key ID should not be empty", vector.name);

        assert!(!receipt.tamper_evidence.signature.signature_hex.is_empty(),
            "Vector '{}': signature hex should not be empty", vector.name);

        // Algorithm should be Ed25519
        assert_eq!(
            receipt.tamper_evidence.signature.algorithm,
            "Ed25519",
            "Vector '{}': signature algorithm should be Ed25519", vector.name
        );
    }
}

#[test]
fn doctor_close_condition_failing_dimensions_logic_conformance() {
    let vectors = load_conformance_vectors();

    for vector in &vectors.vectors {
        let receipt: CloseConditionReceipt = vector.input_receipt.clone().into();

        // Composite verdict logic validation
        match receipt.core.composite_verdict {
            OracleColor::Green => {
                assert!(
                    receipt.core.failing_dimensions.is_empty(),
                    "Vector '{}': GREEN verdict should have no failing dimensions", vector.name
                );
            }
            OracleColor::Red => {
                assert!(
                    !receipt.core.failing_dimensions.is_empty(),
                    "Vector '{}': RED verdict should have at least one failing dimension", vector.name
                );

                // Validate failing dimensions correspond to actual oracle failures
                if receipt.core.l1_product_oracle.verdict == OracleColor::Red {
                    assert!(
                        receipt.core.failing_dimensions.contains(&"L1_product_oracle".to_string()),
                        "Vector '{}': L1 failure should be in failing dimensions", vector.name
                    );
                }

                if receipt.core.l2_engine_boundary_oracle.verdict == OracleColor::Red {
                    assert!(
                        receipt.core.failing_dimensions.contains(&"L2_engine_boundary_oracle".to_string()),
                        "Vector '{}': L2 failure should be in failing dimensions", vector.name
                    );
                }
            }
        }
    }
}