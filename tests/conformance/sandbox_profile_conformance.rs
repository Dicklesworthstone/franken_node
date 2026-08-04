//! Sandbox profile conformance tests (bd-3ua7).
//!
//! Verifies profile ordering, policy compilation determinism,
//! downgrade blocking, capability grants, and audit logging.

use frankenengine_node::security::sandbox_policy_compiler::*;

// === Profile ordering ===

#[test]
fn profiles_form_strict_total_order() {
    let levels: Vec<u8> = SandboxProfile::ALL.iter().map(|p| p.level()).collect();
    for i in 1..levels.len() {
        assert!(
            levels[i] > levels[i - 1],
            "profiles must be strictly ordered"
        );
    }
}

// === Policy compilation determinism ===

#[test]
fn compilation_is_deterministic() {
    for p in &SandboxProfile::ALL {
        let a = compile_policy(*p);
        let b = compile_policy(*p);
        assert_eq!(a, b, "policy for {p} must be deterministic");
    }
}

#[test]
fn all_profiles_have_6_capabilities() {
    for p in &SandboxProfile::ALL {
        let policy = compile_policy(*p);
        assert_eq!(policy.grants.len(), 6);
    }
}

// === Downgrade blocking ===

#[test]
fn downgrade_blocked_without_override() {
    let mut t = ProfileTracker::new("conn-1".into(), SandboxProfile::Permissive);
    let err = t
        .change_profile(SandboxProfile::Strict, "test".into(), "t".into(), false)
        .unwrap_err();
    assert!(matches!(err, SandboxError::DowngradeBlocked { .. }));
}

// bd-4sh1w: this used to be `upgrade_always_allowed`, asserting that
// Strict -> Moderate -> Permissive succeeded through `change_profile` with
// `allow_downgrade: false`. That was the one genuinely unguarded transition in
// the module — and it is the direction that GRANTS authority, since Permissive
// compiles fs_write / process_exec / network_access all to `Allow`. Relaxation
// now needs its own call plus an operator justification.
#[test]
fn relaxation_is_refused_by_change_profile() {
    let mut t = ProfileTracker::new("conn-1".into(), SandboxProfile::Strict);
    let err = t
        .change_profile(
            SandboxProfile::Permissive,
            "upgrade".into(),
            "t".into(),
            false,
        )
        .unwrap_err();
    assert!(matches!(err, SandboxError::RelaxationBlocked { .. }));

    // The tightening override does not authorize relaxation either.
    let err = t
        .change_profile(
            SandboxProfile::Permissive,
            "upgrade".into(),
            "t".into(),
            true,
        )
        .unwrap_err();
    assert!(matches!(err, SandboxError::RelaxationBlocked { .. }));
    assert_eq!(t.current_profile, SandboxProfile::Strict);
}

#[test]
fn relaxation_succeeds_through_its_own_entry_point() {
    let mut t = ProfileTracker::new("conn-1".into(), SandboxProfile::Strict);
    t.relax_profile(
        SandboxProfile::Moderate,
        "connector needs net".into(),
        "t".into(),
    )
    .unwrap();
    t.relax_profile(
        SandboxProfile::Permissive,
        "operator sign-off #42".into(),
        "t".into(),
    )
    .unwrap();
    assert_eq!(t.current_profile, SandboxProfile::Permissive);

    // The justification is auditable.
    assert_eq!(
        t.audit_log.last().map(|r| r.reason.as_str()),
        Some("operator sign-off #42")
    );
}

#[test]
fn relax_profile_cannot_be_used_to_tighten() {
    // Otherwise it would be a bypass of the `allow_downgrade` guard.
    let mut t = ProfileTracker::new("conn-1".into(), SandboxProfile::Permissive);
    let err = t
        .relax_profile(SandboxProfile::Strict, "sneaky".into(), "t".into())
        .unwrap_err();
    assert!(matches!(err, SandboxError::CompileError { .. }));
    assert_eq!(t.current_profile, SandboxProfile::Permissive);
}

// === Capability grants ===

#[test]
fn strict_denies_all() {
    let policy = compile_policy(SandboxProfile::Strict);
    for g in &policy.grants {
        assert_eq!(g.access, AccessLevel::Deny);
    }
}

#[test]
fn permissive_allows_all() {
    let policy = compile_policy(SandboxProfile::Permissive);
    for g in &policy.grants {
        assert_eq!(g.access, AccessLevel::Allow);
    }
}

// === Audit logging ===

#[test]
fn initial_assignment_audited() {
    let t = ProfileTracker::new("conn-1".into(), SandboxProfile::Strict);
    assert_eq!(t.audit_log.len(), 1);
    assert_eq!(t.audit_log[0].old_profile, None);
    assert_eq!(t.audit_log[0].new_profile, SandboxProfile::Strict);
}

#[test]
fn profile_change_audited() {
    // bd-4sh1w: Strict -> Moderate is a relaxation, so it routes through
    // `relax_profile`. The audit record it produces is identical in shape.
    let mut t = ProfileTracker::new("conn-1".into(), SandboxProfile::Strict);
    t.relax_profile(SandboxProfile::Moderate, "needs net".into(), "t".into())
        .unwrap();
    assert_eq!(t.audit_log.len(), 2);
    let last = &t.audit_log[1];
    assert_eq!(last.old_profile, Some(SandboxProfile::Strict));
    assert_eq!(last.new_profile, SandboxProfile::Moderate);
}

// === Policy validation ===

#[test]
fn standard_policies_valid() {
    for p in &SandboxProfile::ALL {
        let policy = compile_policy(*p);
        assert!(validate_policy(&policy).is_ok());
    }
}
