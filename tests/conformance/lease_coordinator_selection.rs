//! Conformance tests for bd-2vs4: Lease coordinator selection and quorum.

use frankenengine_node::connector::lease_coordinator::*;

fn cands() -> Vec<CoordinatorCandidate> {
    vec![
        CoordinatorCandidate {
            node_id: "n1".into(),
            weight: 10,
        },
        CoordinatorCandidate {
            node_id: "n2".into(),
            weight: 5,
        },
        CoordinatorCandidate {
            node_id: "n3".into(),
            weight: 8,
        },
    ]
}

fn qcfg() -> QuorumConfig {
    QuorumConfig::default_config()
}

fn sig(id: &str, hash: &str) -> QuorumSignature {
    QuorumSignature {
        signer_id: id.into(),
        signature: compute_test_signature(id, hash),
    }
}

const EXPECTED_FAILURE_CAP: usize = 256;

fn assert_failure_cap_fuzz_case(
    label: &str,
    signatures: Vec<QuorumSignature>,
    known_signers: Vec<String>,
    expected_classified_code: Option<&str>,
) {
    let verification = verify_quorum(
        &qcfg(),
        "lease-failure-cap",
        "Dangerous",
        &signatures,
        &known_signers,
        "payload-a",
        "trace-failure-cap",
        "ts",
    );
    let expected_failures = signatures.len().saturating_add(1).min(EXPECTED_FAILURE_CAP);
    let actual_codes: Vec<&str> = verification
        .failures
        .iter()
        .map(VerificationFailure::code)
        .collect();

    assert!(!verification.passed, "{label}");
    assert_eq!(verification.required, 3, "{label}");
    assert_eq!(verification.received, 0, "{label}");
    assert_eq!(verification.failures.len(), expected_failures, "{label}");
    assert!(
        verification.failures.len() <= EXPECTED_FAILURE_CAP,
        "{label}"
    );

    if signatures.len() < EXPECTED_FAILURE_CAP {
        assert!(
            actual_codes.contains(&"LC_BELOW_QUORUM"),
            "{label}: expected LC_BELOW_QUORUM in {actual_codes:?}"
        );
    }

    if let Some(expected_code) = expected_classified_code {
        assert!(
            actual_codes.contains(&expected_code),
            "{label}: expected {expected_code} in {actual_codes:?}"
        );
    }
}

#[test]
fn inv_lc_deterministic() {
    let s1 = select_coordinator(&cands(), "l1", "tr").unwrap();
    let s2 = select_coordinator(&cands(), "l1", "tr").unwrap();
    assert_eq!(s1.selected, s2.selected, "INV-LC-DETERMINISTIC violated");
}

#[test]
fn inv_lc_quorum_tier_standard() {
    let known = vec!["s1".to_string()];
    let sigs = vec![sig("s1", "h")];
    let v = verify_quorum(&qcfg(), "l1", "Standard", &sigs, &known, "h", "tr", "ts");
    assert!(
        v.passed,
        "INV-LC-QUORUM-TIER: Standard with 1 sig should pass"
    );
}

#[test]
fn inv_lc_quorum_tier_risky_needs_two() {
    let known = vec!["s1".to_string()];
    let sigs = vec![sig("s1", "h")];
    let v = verify_quorum(&qcfg(), "l1", "Risky", &sigs, &known, "h", "tr", "ts");
    assert!(
        !v.passed,
        "INV-LC-QUORUM-TIER: Risky with 1 sig should fail"
    );
}

#[test]
fn inv_lc_verify_classified_below_quorum() {
    let known = vec!["s1".to_string()];
    let sigs = vec![sig("s1", "h")];
    let v = verify_quorum(&qcfg(), "l1", "Dangerous", &sigs, &known, "h", "tr", "ts");
    assert!(
        v.failures
            .iter()
            .any(|failure| matches!(failure, VerificationFailure::BelowQuorum { .. }))
    );
}

#[test]
fn inv_lc_verify_classified_invalid_sig() {
    let known = vec!["s1".to_string()];
    let sigs = vec![QuorumSignature {
        signer_id: "s1".into(),
        signature: "bad".into(),
    }];
    let v = verify_quorum(&qcfg(), "l1", "Standard", &sigs, &known, "h", "tr", "ts");
    assert!(
        v.failures
            .iter()
            .any(|f| f.code() == "LC_INVALID_SIGNATURE")
    );
}

#[test]
fn inv_lc_verify_classified_unknown_signer() {
    let known = vec!["s1".to_string()];
    let sigs = vec![sig("s1", "h"), sig("unknown", "h")];
    let v = verify_quorum(&qcfg(), "l1", "Standard", &sigs, &known, "h", "tr", "ts");
    assert!(
        v.failures
            .iter()
            .any(|failure| matches!(failure, VerificationFailure::UnknownSigner { .. }))
    );
}

#[test]
fn inv_lc_replay() {
    let known = vec!["s1".to_string(), "s2".to_string()];
    let sigs = vec![sig("s1", "h"), sig("s2", "h")];
    let v1 = verify_quorum(&qcfg(), "l1", "Risky", &sigs, &known, "h", "tr", "ts");
    let v2 = verify_quorum(&qcfg(), "l1", "Risky", &sigs, &known, "h", "tr", "ts");
    assert_eq!(v1.passed, v2.passed, "INV-LC-REPLAY violated");
    assert_eq!(v1.received, v2.received);
}

#[test]
fn lease_coordinator_quorum_failure_cap_fuzz_matrix() {
    let fuzz_sizes = [
        0,
        1,
        2,
        EXPECTED_FAILURE_CAP - 1,
        EXPECTED_FAILURE_CAP,
        EXPECTED_FAILURE_CAP + 1,
        EXPECTED_FAILURE_CAP.saturating_mul(2),
    ];

    for size in fuzz_sizes {
        let unknown_signatures: Vec<QuorumSignature> = (0..size)
            .map(|idx| QuorumSignature {
                signer_id: format!("unknown-{idx}"),
                signature: "not-a-valid-signature".to_string(),
            })
            .collect();
        assert_failure_cap_fuzz_case(
            &format!("unknown-signers-{size}"),
            unknown_signatures,
            Vec::new(),
            (size > 0).then_some("LC_UNKNOWN_SIGNER"),
        );

        let known_signers: Vec<String> = (0..size).map(|idx| format!("known-{idx}")).collect();
        let invalid_signatures: Vec<QuorumSignature> = (0..size)
            .map(|idx| QuorumSignature {
                signer_id: format!("known-{idx}"),
                signature: "not-a-valid-signature".to_string(),
            })
            .collect();
        assert_failure_cap_fuzz_case(
            &format!("invalid-known-signers-{size}"),
            invalid_signatures,
            known_signers,
            (size > 0).then_some("LC_INVALID_SIGNATURE"),
        );
    }
}
