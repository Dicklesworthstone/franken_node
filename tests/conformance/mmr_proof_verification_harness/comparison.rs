//! Comparison utilities for MMR conformance testing.

use super::traits::TestResult;
use serde_json::Value as JsonValue;

/// Comparison modes for test verification
#[derive(Debug, Clone, Copy)]
pub enum ComparisonMode {
    /// Exact byte-for-byte comparison
    Exact,
    /// Structural comparison ignoring formatting
    Structural,
    /// Fuzzy comparison with tolerance
    Fuzzy { tolerance: f64 },
}

/// Compare two values using the specified comparison mode
pub fn compare_values(
    expected: &JsonValue,
    actual: &JsonValue,
    mode: ComparisonMode,
) -> TestResult {
    match mode {
        ComparisonMode::Exact => compare_exact(expected, actual),
        ComparisonMode::Structural => compare_structural(expected, actual),
        ComparisonMode::Fuzzy { tolerance } => compare_fuzzy(expected, actual, tolerance),
    }
}

/// Exact comparison
fn compare_exact(expected: &JsonValue, actual: &JsonValue) -> TestResult {
    if expected == actual {
        TestResult::pass()
    } else {
        TestResult::fail_with_details(
            "Exact comparison failed",
            serde_json::json!({
                "expected": expected,
                "actual": actual,
                "comparison_mode": "exact"
            }),
        )
    }
}

/// Structural comparison (ignores field order in objects)
fn compare_structural(expected: &JsonValue, actual: &JsonValue) -> TestResult {
    match compare_structural_recursive(expected, actual) {
        Ok(()) => TestResult::pass(),
        Err(diff) => TestResult::fail_with_details("Structural comparison failed", diff),
    }
}

fn compare_structural_recursive(
    expected: &JsonValue,
    actual: &JsonValue,
) -> Result<(), JsonValue> {
    match (expected, actual) {
        (JsonValue::Object(exp_obj), JsonValue::Object(act_obj)) => {
            // Check all expected keys are present
            for (key, exp_val) in exp_obj {
                match act_obj.get(key) {
                    Some(act_val) => {
                        compare_structural_recursive(exp_val, act_val)
                            .map_err(|diff| {
                                serde_json::json!({
                                    "path": format!(".{}", key),
                                    "difference": diff
                                })
                            })?;
                    }
                    None => {
                        return Err(serde_json::json!({
                            "error": "missing_key",
                            "key": key,
                            "expected": exp_val
                        }));
                    }
                }
            }

            // Check for unexpected keys
            for key in act_obj.keys() {
                if !exp_obj.contains_key(key) {
                    return Err(serde_json::json!({
                        "error": "unexpected_key",
                        "key": key,
                        "actual": act_obj.get(key)
                    }));
                }
            }

            Ok(())
        }
        (JsonValue::Array(exp_arr), JsonValue::Array(act_arr)) => {
            if exp_arr.len() != act_arr.len() {
                return Err(serde_json::json!({
                    "error": "array_length_mismatch",
                    "expected_length": exp_arr.len(),
                    "actual_length": act_arr.len()
                }));
            }

            for (i, (exp_item, act_item)) in exp_arr.iter().zip(act_arr.iter()).enumerate() {
                compare_structural_recursive(exp_item, act_item)
                    .map_err(|diff| {
                        serde_json::json!({
                            "path": format!("[{}]", i),
                            "difference": diff
                        })
                    })?;
            }

            Ok(())
        }
        _ => {
            if expected == actual {
                Ok(())
            } else {
                Err(serde_json::json!({
                    "error": "value_mismatch",
                    "expected": expected,
                    "actual": actual
                }))
            }
        }
    }
}

/// Fuzzy comparison with tolerance for numeric values
fn compare_fuzzy(expected: &JsonValue, actual: &JsonValue, tolerance: f64) -> TestResult {
    match compare_fuzzy_recursive(expected, actual, tolerance) {
        Ok(()) => TestResult::pass(),
        Err(diff) => TestResult::fail_with_details(
            format!("Fuzzy comparison failed (tolerance: {})", tolerance),
            diff,
        ),
    }
}

fn compare_fuzzy_recursive(
    expected: &JsonValue,
    actual: &JsonValue,
    tolerance: f64,
) -> Result<(), JsonValue> {
    match (expected, actual) {
        (JsonValue::Number(exp_num), JsonValue::Number(act_num)) => {
            let exp_f64 = exp_num.as_f64().unwrap_or(0.0);
            let act_f64 = act_num.as_f64().unwrap_or(0.0);

            let diff = (exp_f64 - act_f64).abs();
            let relative_error = if exp_f64 != 0.0 {
                diff / exp_f64.abs()
            } else {
                diff
            };

            if relative_error <= tolerance {
                Ok(())
            } else {
                Err(serde_json::json!({
                    "error": "numeric_tolerance_exceeded",
                    "expected": exp_f64,
                    "actual": act_f64,
                    "difference": diff,
                    "relative_error": relative_error,
                    "tolerance": tolerance
                }))
            }
        }
        (JsonValue::Object(exp_obj), JsonValue::Object(act_obj)) => {
            for (key, exp_val) in exp_obj {
                match act_obj.get(key) {
                    Some(act_val) => {
                        compare_fuzzy_recursive(exp_val, act_val, tolerance)
                            .map_err(|diff| {
                                serde_json::json!({
                                    "path": format!(".{}", key),
                                    "difference": diff
                                })
                            })?;
                    }
                    None => {
                        return Err(serde_json::json!({
                            "error": "missing_key",
                            "key": key
                        }));
                    }
                }
            }
            Ok(())
        }
        (JsonValue::Array(exp_arr), JsonValue::Array(act_arr)) => {
            if exp_arr.len() != act_arr.len() {
                return Err(serde_json::json!({
                    "error": "array_length_mismatch",
                    "expected_length": exp_arr.len(),
                    "actual_length": act_arr.len()
                }));
            }

            for (i, (exp_item, act_item)) in exp_arr.iter().zip(act_arr.iter()).enumerate() {
                compare_fuzzy_recursive(exp_item, act_item, tolerance)
                    .map_err(|diff| {
                        serde_json::json!({
                            "path": format!("[{}]", i),
                            "difference": diff
                        })
                    })?;
            }

            Ok(())
        }
        _ => compare_structural_recursive(expected, actual),
    }
}

/// Helper to compare error codes
pub fn assert_error_code(expected: &str, actual: &crate::ProofError) -> TestResult {
    let actual_code = actual.code();
    if expected == actual_code {
        TestResult::pass()
    } else {
        TestResult::fail_with_details(
            "Error code mismatch",
            serde_json::json!({
                "expected_code": expected,
                "actual_code": actual_code,
                "actual_error": actual.to_string()
            }),
        )
    }
}

/// Helper to compare hash values (case-insensitive hex)
pub fn assert_hash_equal(expected: &str, actual: &str) -> TestResult {
    let exp_normalized = expected.to_lowercase();
    let act_normalized = actual.to_lowercase();

    if exp_normalized == act_normalized {
        TestResult::pass()
    } else {
        TestResult::fail_with_details(
            "Hash mismatch",
            serde_json::json!({
                "expected": expected,
                "actual": actual,
                "expected_normalized": exp_normalized,
                "actual_normalized": act_normalized
            }),
        )
    }
}

/// Helper to verify proof structure validity
pub fn assert_proof_valid(proof: &crate::InclusionProof) -> TestResult {
    // Check basic proof constraints
    if proof.leaf_index >= proof.tree_size {
        return TestResult::fail(format!(
            "Leaf index {} >= tree size {}",
            proof.leaf_index, proof.tree_size
        ));
    }

    // Check audit path length is reasonable
    let expected_max_path_len = if proof.tree_size <= 1 {
        0
    } else {
        64.min((64 - (proof.tree_size - 1).leading_zeros()) as usize)
    };

    if proof.audit_path.len() > expected_max_path_len {
        return TestResult::fail(format!(
            "Audit path too long: {} > {} for tree size {}",
            proof.audit_path.len(),
            expected_max_path_len,
            proof.tree_size
        ));
    }

    // Check hash formats
    if proof.leaf_hash.len() != 64 {
        return TestResult::fail(format!(
            "Invalid leaf hash length: {} (expected 64)",
            proof.leaf_hash.len()
        ));
    }

    for (i, hash) in proof.audit_path.iter().enumerate() {
        if hash.len() != 64 {
            return TestResult::fail(format!(
                "Invalid audit path hash length at index {}: {} (expected 64)",
                i,
                hash.len()
            ));
        }
    }

    TestResult::pass()
}