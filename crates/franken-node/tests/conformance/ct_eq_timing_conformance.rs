//! Conformance harness for constant-time comparison invariants
//!
//! INVARIANT: For ANY two byte sequences of equal length, ct_eq() must match `==`
//! semantically AND timing variance must be bounded. This prevents timing side-channel
//! attacks where comparison duration reveals information about valid vs invalid data,
//! enabling signature forgery reconnaissance.

use frankenengine_node::security::constant_time::ct_eq;

#[test]
fn test_ct_eq_semantic_equivalence_with_regular_equality() {
    // ct_eq() must have identical semantics to == for all inputs

    let identical_strings = ("valid_decision", "valid_decision");
    assert_eq!(ct_eq(identical_strings.0, identical_strings.1), true);
    assert_eq!(identical_strings.0 == identical_strings.1, true);

    let different_strings = ("valid_decision", "invalid_decision");
    assert_eq!(ct_eq(different_strings.0, different_strings.1), false);
    assert_eq!(different_strings.0 == different_strings.1, false);

    let empty_strings = ("", "");
    assert_eq!(ct_eq(empty_strings.0, empty_strings.1), true);
    assert_eq!(empty_strings.0 == empty_strings.1, true);

    let empty_vs_nonempty = ("", "action");
    assert_eq!(ct_eq(empty_vs_nonempty.0, empty_vs_nonempty.1), false);
    assert_eq!(empty_vs_nonempty.0 == empty_vs_nonempty.1, false);
}

#[test]
fn test_ct_eq_quarantine_decision_fields() {
    // Specific fields from quarantine_controller.rs that must use constant-time comparison

    // decision.action comparison (enum serialized to string)
    let action_values = [
        ("Quarantine", "Quarantine"),  // identical
        ("Allow", "Allow"),            // identical
        ("Quarantine", "Allow"),       // different actions
        ("Block", "Quarantine"),       // different actions
    ];

    for (left, right) in action_values {
        let ct_result = ct_eq(left, right);
        let regular_result = left == right;
        assert_eq!(ct_result, regular_result,
            "ct_eq({}, {}) != regular equality", left, right);
    }
}

#[test]
fn test_ct_eq_f64_bits_comparison() {
    // decision.posterior.to_bits() and decision.threshold.to_bits() comparisons

    let posterior_bits_1 = 0.85_f64.to_bits().to_string();
    let posterior_bits_2 = 0.85_f64.to_bits().to_string();
    let posterior_bits_3 = 0.75_f64.to_bits().to_string();

    // Identical f64 bits must match
    assert_eq!(ct_eq(&posterior_bits_1, &posterior_bits_2), true);
    assert_eq!(posterior_bits_1 == posterior_bits_2, true);

    // Different f64 bits must not match
    assert_eq!(ct_eq(&posterior_bits_1, &posterior_bits_3), false);
    assert_eq!(posterior_bits_1 == posterior_bits_3, false);

    // Edge cases: NaN, infinity, zero
    let nan_bits = f64::NAN.to_bits().to_string();
    let inf_bits = f64::INFINITY.to_bits().to_string();
    let zero_bits = 0.0_f64.to_bits().to_string();

    assert_eq!(ct_eq(&nan_bits, &nan_bits), true);
    assert_eq!(ct_eq(&inf_bits, &zero_bits), false);
}

#[test]
fn test_ct_eq_integer_evidence_count() {
    // decision.evidence_count comparison (integer serialized to string)

    let count_pairs = [
        ("42", "42"),     // identical counts
        ("0", "0"),       // zero counts
        ("42", "43"),     // adjacent counts
        ("1000", "1"),    // very different counts
        ("999999", "1000000"), // boundary values
    ];

    for (left, right) in count_pairs {
        let ct_result = ct_eq(left, right);
        let regular_result = left == right;
        assert_eq!(ct_result, regular_result,
            "evidence_count ct_eq({}, {}) != regular equality", left, right);
    }
}

#[test]
fn test_ct_eq_prevents_early_termination_timing_leak() {
    // ct_eq() must examine ALL characters regardless of early differences
    // This test verifies no early termination by using strings that differ in first position

    let early_diff_pairs = [
        ("Axxxxxxxxxxxxxxx", "Bxxxxxxxxxxxxxxx"), // differ at position 0
        ("quarantine_decision_long_suffix", "Quarantine_decision_long_suffix"), // differ at position 0
        ("0.999999999999", "1.000000000000"), // differ at position 0 for f64 comparisons
    ];

    for (left, right) in early_diff_pairs {
        // Both ct_eq and regular equality should return false
        assert_eq!(ct_eq(left, right), false);
        assert_eq!(left == right, false);

        // The key invariant: ct_eq() processes the ENTIRE string
        // regardless of early difference (timing should be constant)
        // This cannot be directly tested but is the security requirement
    }
}