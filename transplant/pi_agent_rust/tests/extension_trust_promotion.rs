//! Extension trust promotion/demotion lifecycle integration tests (bd-21nj4, SEC-2.4).
//!
//! Tests the quarantine → restricted → trusted state machine, operator
//! acknowledgment requirements, hostcall gating by trust state, and audit
//! trail generation.

mod common;

use pi::extension_preflight::{
    ExtensionTrustState, ExtensionTrustTracker, InstallRecommendation, InstallTimeRiskReport,
    TRUST_LIFECYCLE_SCHEMA, TrustTransitionError, TrustTransitionKind, classify_extension_source,
    initial_trust_state, is_hostcall_allowed_for_trust,
};
use pi::extensions::ExtensionPolicy;

// ============================================================================
// Helpers
// ============================================================================

fn tracker(state: ExtensionTrustState) -> ExtensionTrustTracker {
    ExtensionTrustTracker::new("test-ext", state)
}

fn classify(source: &str) -> InstallTimeRiskReport {
    let policy = ExtensionPolicy::default();
    classify_extension_source("test-ext", source, &policy)
}

// ============================================================================
// Schema stability
// ============================================================================

#[test]
fn trust_lifecycle_schema_is_stable() {
    assert_eq!(TRUST_LIFECYCLE_SCHEMA, "pi.ext.trust_lifecycle.v1");
}

// ============================================================================
// Trust state properties
// ============================================================================

#[test]
fn quarantined_blocks_all_dangerous_hostcalls() {
    let s = ExtensionTrustState::Quarantined;
    assert!(!s.allows_dangerous_hostcalls());
    assert!(!s.allows_read_hostcalls());
    assert!(s.is_quarantined());
}

#[test]
fn restricted_allows_read_but_not_dangerous() {
    let s = ExtensionTrustState::Restricted;
    assert!(!s.allows_dangerous_hostcalls());
    assert!(s.allows_read_hostcalls());
    assert!(!s.is_quarantined());
}

#[test]
fn trusted_allows_everything() {
    let s = ExtensionTrustState::Trusted;
    assert!(s.allows_dangerous_hostcalls());
    assert!(s.allows_read_hostcalls());
    assert!(!s.is_quarantined());
}

// ============================================================================
// Trust state serde
// ============================================================================

#[test]
fn trust_state_serde_roundtrip() {
    for state in [
        ExtensionTrustState::Quarantined,
        ExtensionTrustState::Restricted,
        ExtensionTrustState::Trusted,
    ] {
        let json = serde_json::to_string(&state).unwrap();
        let back: ExtensionTrustState = serde_json::from_str(&json).unwrap();
        assert_eq!(back, state);
    }
}

#[test]
fn trust_state_serde_names_stable() {
    assert_eq!(
        serde_json::to_string(&ExtensionTrustState::Quarantined).unwrap(),
        "\"quarantined\""
    );
    assert_eq!(
        serde_json::to_string(&ExtensionTrustState::Restricted).unwrap(),
        "\"restricted\""
    );
    assert_eq!(
        serde_json::to_string(&ExtensionTrustState::Trusted).unwrap(),
        "\"trusted\""
    );
}

#[test]
fn trust_state_display_strings() {
    assert_eq!(
        format!("{}", ExtensionTrustState::Quarantined),
        "quarantined"
    );
    assert_eq!(format!("{}", ExtensionTrustState::Restricted), "restricted");
    assert_eq!(format!("{}", ExtensionTrustState::Trusted), "trusted");
}

// ============================================================================
// Promotion: quarantined → restricted
// ============================================================================

#[test]
fn promote_quarantined_to_restricted() {
    let mut t = tracker(ExtensionTrustState::Quarantined);
    let event = t.promote("manual review passed", true, None, None).unwrap();
    assert_eq!(event.from_state, ExtensionTrustState::Quarantined);
    assert_eq!(event.to_state, ExtensionTrustState::Restricted);
    assert_eq!(event.kind, TrustTransitionKind::Promote);
    assert!(event.operator_acknowledged);
    assert_eq!(t.state(), ExtensionTrustState::Restricted);
}

// ============================================================================
// Promotion: restricted → trusted
// ============================================================================

#[test]
fn promote_restricted_to_trusted() {
    let mut t = tracker(ExtensionTrustState::Restricted);
    let event = t.promote("verified safe", true, None, None).unwrap();
    assert_eq!(event.from_state, ExtensionTrustState::Restricted);
    assert_eq!(event.to_state, ExtensionTrustState::Trusted);
    assert_eq!(t.state(), ExtensionTrustState::Trusted);
}

// ============================================================================
// Promotion requires operator acknowledgment
// ============================================================================

#[test]
fn promote_without_ack_is_rejected() {
    let mut t = tracker(ExtensionTrustState::Quarantined);
    let err = t.promote("no ack", false, None, None).unwrap_err();
    match err {
        TrustTransitionError::OperatorAckRequired { from, to } => {
            assert_eq!(from, ExtensionTrustState::Quarantined);
            assert_eq!(to, ExtensionTrustState::Restricted);
        }
        other => panic!("expected OperatorAckRequired, got: {other}"),
    }
    // State should not have changed.
    assert_eq!(t.state(), ExtensionTrustState::Quarantined);
}

// ============================================================================
// Cannot skip levels
// ============================================================================

#[test]
fn cannot_promote_already_trusted() {
    let mut t = tracker(ExtensionTrustState::Trusted);
    let err = t.promote("extra promote", true, None, None).unwrap_err();
    matches!(err, TrustTransitionError::InvalidTransition { .. });
}

// ============================================================================
// Risk score thresholds gate promotion
// ============================================================================

#[test]
fn promote_to_restricted_blocked_by_low_risk_score() {
    let mut t = tracker(ExtensionTrustState::Quarantined);
    let err = t.promote("low score", true, Some(10), None).unwrap_err();
    match err {
        TrustTransitionError::RiskTooHigh {
            target,
            risk_score,
            max_allowed,
        } => {
            assert_eq!(target, ExtensionTrustState::Restricted);
            assert_eq!(risk_score, 10);
            assert_eq!(max_allowed, 30);
        }
        other => panic!("expected RiskTooHigh, got: {other}"),
    }
}

#[test]
fn promote_to_trusted_blocked_by_medium_risk_score() {
    let mut t = tracker(ExtensionTrustState::Restricted);
    let err = t.promote("medium score", true, Some(40), None).unwrap_err();
    match err {
        TrustTransitionError::RiskTooHigh {
            target,
            risk_score,
            max_allowed,
        } => {
            assert_eq!(target, ExtensionTrustState::Trusted);
            assert_eq!(risk_score, 40);
            assert_eq!(max_allowed, 50);
        }
        other => panic!("expected RiskTooHigh, got: {other}"),
    }
}

#[test]
fn promote_to_restricted_allowed_at_threshold() {
    let mut t = tracker(ExtensionTrustState::Quarantined);
    t.promote("at threshold", true, Some(30), None).unwrap();
    assert_eq!(t.state(), ExtensionTrustState::Restricted);
}

#[test]
fn promote_to_trusted_allowed_at_threshold() {
    let mut t = tracker(ExtensionTrustState::Restricted);
    t.promote("at threshold", true, Some(50), None).unwrap();
    assert_eq!(t.state(), ExtensionTrustState::Trusted);
}

// ============================================================================
// Demotion
// ============================================================================

#[test]
fn demote_trusted_to_quarantined() {
    let mut t = tracker(ExtensionTrustState::Trusted);
    let event = t.demote("suspicious behavior detected").unwrap();
    assert_eq!(event.from_state, ExtensionTrustState::Trusted);
    assert_eq!(event.to_state, ExtensionTrustState::Quarantined);
    assert_eq!(event.kind, TrustTransitionKind::Demote);
    assert!(!event.operator_acknowledged);
    assert_eq!(t.state(), ExtensionTrustState::Quarantined);
}

#[test]
fn demote_restricted_to_quarantined() {
    let mut t = tracker(ExtensionTrustState::Restricted);
    let event = t.demote("policy violation").unwrap();
    assert_eq!(event.from_state, ExtensionTrustState::Restricted);
    assert_eq!(event.to_state, ExtensionTrustState::Quarantined);
    assert_eq!(t.state(), ExtensionTrustState::Quarantined);
}

#[test]
fn demote_already_quarantined_is_error() {
    let mut t = tracker(ExtensionTrustState::Quarantined);
    let err = t.demote("already quarantined").unwrap_err();
    matches!(err, TrustTransitionError::InvalidTransition { .. });
}

// ============================================================================
// Demotion does not require operator ack
// ============================================================================

#[test]
fn demotion_event_has_no_operator_ack() {
    let mut t = tracker(ExtensionTrustState::Trusted);
    let event = t.demote("runtime anomaly").unwrap();
    assert!(!event.operator_acknowledged);
}

// ============================================================================
// Full lifecycle: quarantine → restrict → trust → demote → re-promote
// ============================================================================

#[test]
fn full_lifecycle_roundtrip() {
    let mut t = tracker(ExtensionTrustState::Quarantined);

    // Step 1: Promote to restricted.
    t.promote("initial review", true, Some(60), None).unwrap();
    assert_eq!(t.state(), ExtensionTrustState::Restricted);

    // Step 2: Promote to trusted.
    t.promote("full review", true, Some(80), None).unwrap();
    assert_eq!(t.state(), ExtensionTrustState::Trusted);

    // Step 3: Demote back to quarantine.
    t.demote("anomaly detected").unwrap();
    assert_eq!(t.state(), ExtensionTrustState::Quarantined);

    // Step 4: Re-promote to restricted.
    t.promote("re-reviewed", true, Some(70), None).unwrap();
    assert_eq!(t.state(), ExtensionTrustState::Restricted);

    // Verify history has 4 events.
    assert_eq!(t.history().len(), 4);
}

// ============================================================================
// History / audit trail
// ============================================================================

#[test]
fn history_tracks_all_transitions() {
    let mut t = tracker(ExtensionTrustState::Quarantined);
    t.promote("step1", true, None, None).unwrap();
    t.promote("step2", true, None, None).unwrap();
    t.demote("step3").unwrap();

    let history = t.history();
    assert_eq!(history.len(), 3);
    assert_eq!(history[0].reason, "step1");
    assert_eq!(history[1].reason, "step2");
    assert_eq!(history[2].reason, "step3");
}

#[test]
fn history_jsonl_produces_valid_json_lines() {
    let mut t = tracker(ExtensionTrustState::Quarantined);
    t.promote("review", true, None, None).unwrap();
    t.demote("incident").unwrap();

    let jsonl = t.history_jsonl().unwrap();
    let lines: Vec<&str> = jsonl.lines().collect();
    assert_eq!(lines.len(), 2);
    for line in &lines {
        let v: serde_json::Value = serde_json::from_str(line).unwrap();
        assert_eq!(v["schema"], TRUST_LIFECYCLE_SCHEMA);
        assert_eq!(v["extension_id"], "test-ext");
    }
}

#[test]
fn transition_event_json_roundtrip() {
    let mut t = tracker(ExtensionTrustState::Quarantined);
    t.promote("test", true, Some(75), Some(InstallRecommendation::Review))
        .unwrap();

    let event = &t.history()[0];
    let json = event.to_json().unwrap();
    let back: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(back["from_state"], "quarantined");
    assert_eq!(back["to_state"], "restricted");
    assert_eq!(back["kind"], "promote");
    assert_eq!(back["operator_acknowledged"], true);
    assert_eq!(back["risk_score"], 75);
    assert_eq!(back["recommendation"], "review");
}

// ============================================================================
// Initial trust state from risk report
// ============================================================================

#[test]
fn clean_extension_starts_trusted() {
    let report = classify("const x = 1;");
    let state = initial_trust_state(&report);
    assert_eq!(state, ExtensionTrustState::Trusted);
}

#[test]
fn risky_extension_starts_quarantined() {
    let report = classify("eval('bad');");
    let state = initial_trust_state(&report);
    assert_eq!(state, ExtensionTrustState::Quarantined);
}

#[test]
fn review_extension_starts_quarantined() {
    let report = classify(r#"const api_key = "sk-ant-api03-test123";"#);
    assert_eq!(report.recommendation, InstallRecommendation::Review);
    let state = initial_trust_state(&report);
    assert_eq!(state, ExtensionTrustState::Quarantined);
}

#[test]
fn tracker_from_risk_report_auto_quarantines() {
    let report = classify("eval('bad');");
    let t = ExtensionTrustTracker::from_risk_report(&report);
    assert_eq!(t.state(), ExtensionTrustState::Quarantined);
    assert_eq!(t.extension_id(), "test-ext");
}

#[test]
fn tracker_from_clean_report_auto_trusts() {
    let report = classify("const x = 1;");
    let t = ExtensionTrustTracker::from_risk_report(&report);
    assert_eq!(t.state(), ExtensionTrustState::Trusted);
}

// ============================================================================
// Hostcall gating by trust state
// ============================================================================

#[test]
fn quarantined_allows_registration_hostcalls() {
    let s = ExtensionTrustState::Quarantined;
    assert!(is_hostcall_allowed_for_trust(s, "register"));
    assert!(is_hostcall_allowed_for_trust(s, "tool"));
    assert!(is_hostcall_allowed_for_trust(s, "slash_command"));
    assert!(is_hostcall_allowed_for_trust(s, "log"));
}

#[test]
fn quarantined_blocks_read_hostcalls() {
    let s = ExtensionTrustState::Quarantined;
    assert!(!is_hostcall_allowed_for_trust(s, "read"));
    assert!(!is_hostcall_allowed_for_trust(s, "list"));
    assert!(!is_hostcall_allowed_for_trust(s, "stat"));
}

#[test]
fn quarantined_blocks_dangerous_hostcalls() {
    let s = ExtensionTrustState::Quarantined;
    assert!(!is_hostcall_allowed_for_trust(s, "write"));
    assert!(!is_hostcall_allowed_for_trust(s, "exec"));
    assert!(!is_hostcall_allowed_for_trust(s, "env"));
    assert!(!is_hostcall_allowed_for_trust(s, "http"));
}

#[test]
fn restricted_allows_read_hostcalls() {
    let s = ExtensionTrustState::Restricted;
    assert!(is_hostcall_allowed_for_trust(s, "read"));
    assert!(is_hostcall_allowed_for_trust(s, "list"));
    assert!(is_hostcall_allowed_for_trust(s, "stat"));
    assert!(is_hostcall_allowed_for_trust(s, "ui"));
}

#[test]
fn restricted_blocks_dangerous_hostcalls() {
    let s = ExtensionTrustState::Restricted;
    assert!(!is_hostcall_allowed_for_trust(s, "write"));
    assert!(!is_hostcall_allowed_for_trust(s, "exec"));
    assert!(!is_hostcall_allowed_for_trust(s, "env"));
    assert!(!is_hostcall_allowed_for_trust(s, "http"));
    assert!(!is_hostcall_allowed_for_trust(s, "fs_write"));
    assert!(!is_hostcall_allowed_for_trust(s, "fs_delete"));
}

#[test]
fn trusted_allows_all_hostcalls() {
    let s = ExtensionTrustState::Trusted;
    assert!(is_hostcall_allowed_for_trust(s, "read"));
    assert!(is_hostcall_allowed_for_trust(s, "write"));
    assert!(is_hostcall_allowed_for_trust(s, "exec"));
    assert!(is_hostcall_allowed_for_trust(s, "env"));
    assert!(is_hostcall_allowed_for_trust(s, "http"));
    assert!(is_hostcall_allowed_for_trust(s, "register"));
}

#[test]
fn unknown_hostcall_category_requires_trusted() {
    assert!(!is_hostcall_allowed_for_trust(
        ExtensionTrustState::Quarantined,
        "unknown_category"
    ));
    assert!(!is_hostcall_allowed_for_trust(
        ExtensionTrustState::Restricted,
        "unknown_category"
    ));
    assert!(is_hostcall_allowed_for_trust(
        ExtensionTrustState::Trusted,
        "unknown_category"
    ));
}

// ============================================================================
// Error display
// ============================================================================

#[test]
fn trust_transition_error_display() {
    let err = TrustTransitionError::OperatorAckRequired {
        from: ExtensionTrustState::Quarantined,
        to: ExtensionTrustState::Restricted,
    };
    let msg = format!("{err}");
    assert!(msg.contains("operator acknowledgment"));
    assert!(msg.contains("quarantined"));
    assert!(msg.contains("restricted"));

    let err = TrustTransitionError::InvalidTransition {
        from: ExtensionTrustState::Trusted,
        to: ExtensionTrustState::Trusted,
    };
    let msg = format!("{err}");
    assert!(msg.contains("invalid"));

    let err = TrustTransitionError::RiskTooHigh {
        target: ExtensionTrustState::Restricted,
        risk_score: 10,
        max_allowed: 30,
    };
    let msg = format!("{err}");
    assert!(msg.contains("10"));
    assert!(msg.contains("30"));
}

// ============================================================================
// Determinism
// ============================================================================

#[test]
fn trust_state_ordering_matches_privilege_level() {
    // Quarantined < Restricted < Trusted in terms of privilege.
    assert!(ExtensionTrustState::Quarantined < ExtensionTrustState::Restricted);
    assert!(ExtensionTrustState::Restricted < ExtensionTrustState::Trusted);
}
