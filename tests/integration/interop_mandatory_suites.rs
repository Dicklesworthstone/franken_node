//! Integration tests for bd-35by: Mandatory interop suites.

use frankenengine_node::connector::interop_suite::*;

#[test]
fn inv_iop_serialization() {
    let pass = check_serialization("s1", "data", "encoded", "encoded");
    assert!(pass.passed, "INV-IOP-SERIALIZATION: matching round-trip must pass");
    let fail = check_serialization("s2", "data", "bad", "good");
    assert!(!fail.passed, "INV-IOP-SERIALIZATION: mismatch must fail");
    assert!(fail.reproducer.is_some(), "failure must include reproducer");
}

#[test]
fn inv_iop_object_id() {
    let pass = check_object_id("o1", "id-abc", "id-abc");
    assert!(pass.passed, "INV-IOP-OBJECT-ID: deterministic IDs must match");
    let fail = check_object_id("o2", "id-abc", "id-xyz");
    assert!(!fail.passed, "INV-IOP-OBJECT-ID: differing IDs must fail");
}

#[test]
fn inv_iop_signature() {
    let pass = check_signature("sig1", true, "verified");
    assert!(pass.passed, "INV-IOP-SIGNATURE: valid sig must pass");
    let fail = check_signature("sig2", false, "bad key");
    assert!(!fail.passed, "INV-IOP-SIGNATURE: invalid sig must fail");
}

#[test]
fn inv_iop_revocation() {
    let agree = check_revocation("rev1", true, true);
    assert!(agree.passed, "INV-IOP-REVOCATION: agreement must pass");
    let disagree = check_revocation("rev2", true, false);
    assert!(!disagree.passed, "INV-IOP-REVOCATION: disagreement must fail");
}

#[test]
fn inv_iop_source_diversity() {
    let sufficient = check_source_diversity("sd1", 3, 2);
    assert!(sufficient.passed, "INV-IOP-SOURCE-DIVERSITY: enough sources must pass");
    let insufficient = check_source_diversity("sd2", 1, 3);
    assert!(!insufficient.passed, "INV-IOP-SOURCE-DIVERSITY: too few must fail");
}
