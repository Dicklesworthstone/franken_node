//! bd-djpur: `IsolationLevel::Permissive` must enforce the bridge on mutating
//! cross-zone actions.
//!
//! `IsolationLevel::Permissive` is documented — in both `security::trust_zone`
//! and the sibling `connector::trust_zone` — as "cross-zone reads allowed, writes
//! require bridge authorization". The `security` module implemented the first
//! half and silently waived the second: its match arm was an empty block whose
//! comment read "reads are allowed, writes need bridge. Since we have a proof, we
//! allow it." `req.action` was never inspected and `allowed_cross_zone_targets`
//! was never consulted, even though `Strict` and `Custom` both enforce it.
//!
//! A zone registered `Permissive` with an EMPTY allowed-target list could
//! therefore push any mutating action into any other zone — including a `Strict`
//! one — while `to_report()` still reported `INV_ZTS_ISOLATE: true`. The
//! non-emptiness check on `authorization_proof` is not a substitute: it runs for
//! every isolation level, so it cannot be what distinguishes a bridged write from
//! an unbridged one.
//!
//! These tests drive the public `ZoneSegmentationEngine` API so the contract runs
//! in the default `cargo test` lane rather than only on the inline-test lane.

use frankenengine_node::security::trust_zone::{
    CrossZoneRequest, IsolationLevel, SegmentationError, ZonePolicy, ZoneSegmentationEngine,
    event_codes::{ZTS_003_CROSS_ZONE_AUTHORIZED, ZTS_004_ISOLATION_VIOLATION},
    is_read_only_action,
};

const PROOF: &str = "dual-owner-bridge-token";

fn zone(id: &str, isolation: IsolationLevel) -> ZonePolicy {
    ZonePolicy::new(id, 80, 5, isolation)
}

fn zone_with_targets(id: &str, isolation: IsolationLevel, targets: &[&str]) -> ZonePolicy {
    let mut policy = zone(id, isolation);
    for target in targets {
        policy.allowed_cross_zone_targets.push((*target).to_string());
    }
    policy
}

#[test]
fn permissive_zone_cannot_push_an_unbridged_write_into_a_strict_zone() {
    // The exact repro from the bead.
    let mut engine = ZoneSegmentationEngine::new();
    engine
        .register_zone(zone("attacker", IsolationLevel::Permissive))
        .expect("register attacker zone");
    engine
        .register_zone(zone("victim", IsolationLevel::Strict))
        .expect("register victim zone");

    let request = CrossZoneRequest::new("attacker", "victim", "write:delete_all", "attacker", PROOF);

    assert_eq!(
        engine.authorize_cross_zone(&request),
        Err(SegmentationError::IsolationViolation),
        "a non-empty authorization proof is not a bridge"
    );
    assert_eq!(engine.event_count(ZTS_003_CROSS_ZONE_AUTHORIZED), 0);
    assert_eq!(engine.event_count(ZTS_004_ISOLATION_VIOLATION), 1);
}

#[test]
fn permissive_zone_allows_reads_without_a_bridge() {
    // The other half of the documented rule must keep working, or "permissive"
    // would just be a slower "strict".
    let mut engine = ZoneSegmentationEngine::new();
    engine
        .register_zone(zone("analytics", IsolationLevel::Permissive))
        .expect("register source zone");
    engine
        .register_zone(zone("prod", IsolationLevel::Strict))
        .expect("register target zone");

    let request = CrossZoneRequest::new("analytics", "prod", "read:metrics", "reader", PROOF);

    assert_eq!(engine.authorize_cross_zone(&request), Ok(()));
    assert_eq!(engine.event_count(ZTS_003_CROSS_ZONE_AUTHORIZED), 1);
}

#[test]
fn permissive_zone_allows_writes_to_a_bridged_target() {
    let mut engine = ZoneSegmentationEngine::new();
    engine
        .register_zone(zone_with_targets(
            "staging",
            IsolationLevel::Permissive,
            &["prod"],
        ))
        .expect("register source zone");
    engine
        .register_zone(zone("prod", IsolationLevel::Strict))
        .expect("register target zone");

    let request = CrossZoneRequest::new("staging", "prod", "write:promote", "operator", PROOF);

    assert_eq!(engine.authorize_cross_zone(&request), Ok(()));
    assert_eq!(engine.event_count(ZTS_003_CROSS_ZONE_AUTHORIZED), 1);
}

#[test]
fn unrecognized_action_verbs_are_treated_as_writes() {
    // The classifier fails closed, so a verb nobody has taught it about tightens
    // the gate rather than opening it. `connector::trust_zone`'s previous
    // `action == "write" || action == "delete"` check did the opposite: every
    // other verb — including `write:delete_all` — counted as a read.
    let mut engine = ZoneSegmentationEngine::new();
    engine
        .register_zone(zone("source", IsolationLevel::Permissive))
        .expect("register source zone");
    engine
        .register_zone(zone("target", IsolationLevel::Strict))
        .expect("register target zone");

    for action in ["update", "put", "truncate", "insert", "migrate", "frobnicate"] {
        let request = CrossZoneRequest::new("source", "target", action, "actor", PROOF);
        assert_eq!(
            engine.authorize_cross_zone(&request),
            Err(SegmentationError::IsolationViolation),
            "'{action}' must be treated as mutating"
        );
    }

    assert_eq!(engine.event_count(ZTS_003_CROSS_ZONE_AUTHORIZED), 0);
}

#[test]
fn read_classification_matches_the_documented_verb_set() {
    for action in ["read", "GET", "list/zones", "query.plan", "describe", "stat"] {
        assert!(is_read_only_action(action), "'{action}' should be a read");
    }
    for action in [
        "write",
        "delete",
        "write:delete_all",
        "readable-nonsense",
        "",
        "   ",
        ":read",
    ] {
        assert!(
            !is_read_only_action(action),
            "'{action}' must be treated as mutating"
        );
    }
}
