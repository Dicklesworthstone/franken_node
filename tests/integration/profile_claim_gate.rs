//! Integration tests for bd-ck2h: Conformance profile matrix.

use frankenengine_node::connector::conformance_profile::*;

fn cap(name: &str, passed: bool) -> CapabilityResult {
    CapabilityResult {
        capability: name.to_string(),
        passed,
        details: if passed { "ok" } else { "failed" }.to_string(),
    }
}

fn mvp_results() -> Vec<CapabilityResult> {
    vec![
        cap("serialization", true),
        cap("auth", true),
        cap("lifecycle", true),
        cap("fencing", true),
        cap("frame_parsing", true),
    ]
}

#[test]
fn inv_cpm_matrix() {
    let m = ProfileMatrix::standard();
    m.validate().unwrap();
    let mvp = m.required_for(Profile::Mvp).unwrap();
    assert_eq!(mvp.len(), 5);
    let full = m.required_for(Profile::Full).unwrap();
    assert_eq!(full.len(), 13);
}

#[test]
fn inv_cpm_measured() {
    let m = ProfileMatrix::standard();
    // Only 2 results — missing results detected
    let partial = vec![cap("serialization", true), cap("auth", true)];
    let eval = evaluate_claim(&m, Profile::Mvp, &partial, 1).unwrap();
    assert_eq!(eval.verdict, "FAIL");
    let missing: Vec<_> = eval.results.iter().filter(|r| r.details == "no test result").collect();
    assert_eq!(missing.len(), 3);
}

#[test]
fn inv_cpm_blocked() {
    let m = ProfileMatrix::standard();
    let mut results = mvp_results();
    results[0].passed = false;
    let err = publish_claim(&m, Profile::Mvp, &results, 1).unwrap_err();
    assert_eq!(err.code(), "CPM_CLAIM_BLOCKED");
}

#[test]
fn inv_cpm_metadata() {
    let m = ProfileMatrix::standard();
    let eval = evaluate_claim(&m, Profile::Mvp, &mvp_results(), 2).unwrap();
    assert_eq!(eval.metadata.profile_name, "MVP");
    assert_eq!(eval.metadata.version, 2);
    assert_eq!(eval.metadata.capabilities_passed, 5);
    assert_eq!(eval.metadata.capabilities_total, 5);
    assert!(eval.can_publish);
}
