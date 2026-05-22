//! Metamorphic and conformance tests for the security replay window.
//!
//! The replay window is exercised through `RevocationFreshnessGate` nonce
//! consumption: adding duplicate nonce observations must be idempotent with
//! respect to final window state, and capacity overflow must retain the most
//! recent suffix without growing beyond the configured maximum. The
//! conformance matrix also pins fail-closed anti-replay behavior for denial
//! paths that must not burn nonces.

use frankenengine_node::capacity_defaults::aliases::MAX_CONSUMED_NONCES;
use frankenengine_node::security::constant_time::ct_eq;
use frankenengine_node::security::revocation_freshness_gate::{
    FreshnessError, FreshnessProof, GateDecision, RevocationFreshnessGate, SafetyTier,
};
use std::fmt::Debug;

const CURRENT_EPOCH: u64 = 1_000;
const ACTION_ID: &str = "telemetry_config";
const CRITICAL_ACTION_ID: &str = "key_rotate";
const STANDARD_ACTION_ID: &str = "policy_deploy";
const UNKNOWN_ACTION_ID: &str = "unclassified_action";

type TestResult<T = ()> = Result<T, String>;

#[derive(Debug)]
struct CoverageRow {
    id: &'static str,
    requirement: &'static str,
}

fn test_sig(proof: &FreshnessProof) -> String {
    format!("sig-{}-{}", proof.nonce, proof.epoch)
}

fn gate() -> RevocationFreshnessGate {
    gate_with_tiers(vec![(ACTION_ID.to_string(), SafetyTier::Advisory)])
}

fn tiered_gate() -> RevocationFreshnessGate {
    gate_with_tiers(vec![
        (CRITICAL_ACTION_ID.to_string(), SafetyTier::Critical),
        (STANDARD_ACTION_ID.to_string(), SafetyTier::Standard),
        (ACTION_ID.to_string(), SafetyTier::Advisory),
    ])
}

fn gate_with_tiers(tier_table: Vec<(String, SafetyTier)>) -> RevocationFreshnessGate {
    RevocationFreshnessGate::new(Box::new(test_sig), tier_table)
}

fn proof_for(nonce: &str) -> FreshnessProof {
    proof_for_tier(SafetyTier::Advisory, CURRENT_EPOCH, nonce)
}

fn proof_for_tier(tier: SafetyTier, epoch: u64, nonce: &str) -> FreshnessProof {
    let mut proof = FreshnessProof {
        timestamp: 1_700_000_000,
        credentials_checked: vec![
            "credential-alpha".to_string(),
            "credential-beta".to_string(),
        ],
        nonce: nonce.to_string(),
        signature: String::new(),
        tier,
        epoch,
    };
    proof.signature = test_sig(&proof);
    proof
}

fn ensure(condition: bool, message: impl Into<String>) -> TestResult {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn ensure_eq<T>(actual: &T, expected: &T, context: &str) -> TestResult
where
    T: Debug + PartialEq,
{
    if actual == expected {
        Ok(())
    } else {
        Err(format!(
            "{context}: expected {expected:?}, actual {actual:?}"
        ))
    }
}

fn insert_nonce(gate: &mut RevocationFreshnessGate, nonce: &str, trace_id: &str) -> TestResult {
    let proof = proof_for(nonce);
    let result = gate.check(&proof, CURRENT_EPOCH, true, false, ACTION_ID, trace_id);
    ensure(
        result.as_ref().is_ok_and(|decision| decision.allowed),
        format!("fresh nonce {nonce} should be accepted, got {result:?}"),
    )
}

fn check(
    gate: &mut RevocationFreshnessGate,
    proof: &FreshnessProof,
    authenticated: bool,
    owner_bypass: bool,
    action_id: &str,
    trace_id: &str,
) -> Result<GateDecision, FreshnessError> {
    gate.check(
        proof,
        CURRENT_EPOCH,
        authenticated,
        owner_bypass,
        action_id,
        trace_id,
    )
}

fn nonce_for(prefix: &str, idx: usize) -> String {
    format!("{prefix}-{idx:06}")
}

fn trace_for(prefix: &str, idx: usize) -> String {
    format!("trace-{prefix}-{idx:06}")
}

fn expect_allowed(decision: &GateDecision, degraded: bool, event_code: &str) -> TestResult {
    ensure(decision.allowed, "gate decision should allow")?;
    ensure_eq(&decision.degraded, &degraded, "degraded flag")?;
    ensure_eq(&decision.event_code.as_str(), &event_code, "event code")
}

fn expect_error_code(result: Result<GateDecision, FreshnessError>, code: &str) -> TestResult {
    match result {
        Ok(decision) => Err(format!(
            "expected {code}, but gate allowed decision {decision:?}"
        )),
        Err(error) => ensure_eq(&error.code(), &code, "freshness error code"),
    }
}

fn expect_replay(result: Result<GateDecision, FreshnessError>, expected_nonce: &str) -> TestResult {
    match result {
        Err(FreshnessError::ReplayDetected { nonce }) if ct_eq(&nonce, expected_nonce) => Ok(()),
        Err(error) => Err(format!(
            "expected replay for nonce {expected_nonce}, got {error:?}"
        )),
        Ok(decision) => Err(format!(
            "expected replay for nonce {expected_nonce}, got allowed decision {decision:?}"
        )),
    }
}

fn assert_all_requirements_covered(rows: &[CoverageRow]) -> TestResult {
    let required_ids = [
        "RFG-CONF-FRESH-CONSUMES",
        "RFG-CONF-REPLAY-PRECHECK",
        "RFG-CONF-UNAUTH-NO-CONSUME",
        "RFG-CONF-TAMPER-NO-CONSUME",
        "RFG-CONF-UNKNOWN-ACTION-NO-CONSUME",
        "RFG-CONF-CRITICAL-STALE-NO-CONSUME",
        "RFG-CONF-STANDARD-BYPASS-CONSUMES",
        "RFG-CONF-ADVISORY-STALE-CONSUMES",
        "RFG-CONF-FIFO-CAPACITY",
        "RFG-CONF-DUPLICATE-NO-REFRESH",
    ];

    for required_id in required_ids {
        let present = rows
            .iter()
            .any(|row| row.id == required_id && !row.requirement.trim().is_empty());
        ensure(present, missing_coverage_message(required_id))?;
    }
    Ok(())
}

fn missing_coverage_message(required_id: &str) -> String {
    format!("missing or empty conformance row {required_id}")
}

#[test]
fn anti_replay_conformance_matrix_covers_fail_closed_nonce_contracts() -> TestResult {
    let mut covered = Vec::new();

    let mut accepted_gate = tiered_gate();
    let accepted = proof_for_tier(SafetyTier::Critical, CURRENT_EPOCH, "rfg-conf-fresh");
    let decision = check(
        &mut accepted_gate,
        &accepted,
        true,
        false,
        CRITICAL_ACTION_ID,
        "trace-rfg-conf-fresh",
    )
    .map_err(|error| format!("fresh proof should pass: {error:?}"))?;
    expect_allowed(&decision, false, "RFG-001")?;
    ensure(
        accepted_gate.is_nonce_consumed(&accepted.nonce),
        "fresh accepted proof must consume its nonce",
    )?;
    covered.push(CoverageRow {
        id: "RFG-CONF-FRESH-CONSUMES",
        requirement: "fresh classified authenticated proofs must consume their nonce exactly once",
    });

    let mut duplicate = proof_for_tier(SafetyTier::Critical, 0, &accepted.nonce);
    duplicate.signature = test_sig(&duplicate);
    let duplicate_result = check(
        &mut accepted_gate,
        &duplicate,
        true,
        false,
        CRITICAL_ACTION_ID,
        "trace-rfg-conf-replay",
    );
    expect_replay(duplicate_result, &accepted.nonce)?;
    ensure_eq(
        &accepted_gate.consumed_nonce_count(),
        &1,
        "duplicate replay must not grow consumed nonce set",
    )?;
    covered.push(CoverageRow {
        id: "RFG-CONF-REPLAY-PRECHECK",
        requirement: "reused nonces must fail as replay before stale/freshness semantics consume state",
    });

    let mut unauth_gate = tiered_gate();
    let unauth = proof_for_tier(SafetyTier::Advisory, CURRENT_EPOCH, "rfg-conf-unauth");
    expect_error_code(
        check(
            &mut unauth_gate,
            &unauth,
            false,
            false,
            ACTION_ID,
            "trace-rfg-conf-unauth",
        ),
        "ERR_RFG_UNAUTHENTICATED",
    )?;
    ensure(
        !unauth_gate.is_nonce_consumed(&unauth.nonce),
        "unauthenticated denial must not consume nonce",
    )?;
    covered.push(CoverageRow {
        id: "RFG-CONF-UNAUTH-NO-CONSUME",
        requirement: "unauthenticated denials must fail closed without burning replay nonces",
    });

    let mut tamper_gate = tiered_gate();
    let mut tampered = proof_for_tier(SafetyTier::Advisory, CURRENT_EPOCH, "rfg-conf-tamper");
    tampered.signature = "wrong-signature".to_string();
    expect_error_code(
        check(
            &mut tamper_gate,
            &tampered,
            true,
            false,
            ACTION_ID,
            "trace-rfg-conf-tamper",
        ),
        "ERR_RFG_TAMPERED",
    )?;
    ensure(
        !tamper_gate.is_nonce_consumed(&tampered.nonce),
        "tampered proof denial must not consume nonce",
    )?;
    covered.push(CoverageRow {
        id: "RFG-CONF-TAMPER-NO-CONSUME",
        requirement: "tampered proofs must fail before nonce consumption",
    });

    let mut unknown_gate = tiered_gate();
    let unknown = proof_for_tier(SafetyTier::Advisory, CURRENT_EPOCH, "rfg-conf-unknown");
    expect_error_code(
        check(
            &mut unknown_gate,
            &unknown,
            true,
            false,
            UNKNOWN_ACTION_ID,
            "trace-rfg-conf-unknown",
        ),
        "ERR_RFG_TAMPERED",
    )?;
    ensure(
        !unknown_gate.is_nonce_consumed(&unknown.nonce),
        "unknown action denial must not consume nonce",
    )?;
    covered.push(CoverageRow {
        id: "RFG-CONF-UNKNOWN-ACTION-NO-CONSUME",
        requirement: "unclassified actions must fail closed without consuming nonce state",
    });

    let mut stale_critical_gate = tiered_gate();
    let stale_critical =
        proof_for_tier(SafetyTier::Critical, CURRENT_EPOCH - 1, "rfg-conf-critical");
    expect_error_code(
        check(
            &mut stale_critical_gate,
            &stale_critical,
            true,
            true,
            CRITICAL_ACTION_ID,
            "trace-rfg-conf-critical",
        ),
        "ERR_RFG_STALE",
    )?;
    ensure(
        !stale_critical_gate.is_nonce_consumed(&stale_critical.nonce),
        "critical stale denial must not consume nonce even with owner bypass",
    )?;
    covered.push(CoverageRow {
        id: "RFG-CONF-CRITICAL-STALE-NO-CONSUME",
        requirement: "critical stale proofs must fail closed and ignore owner bypass",
    });

    let mut standard_gate = tiered_gate();
    let stale_standard =
        proof_for_tier(SafetyTier::Standard, CURRENT_EPOCH - 5, "rfg-conf-standard");
    let decision = check(
        &mut standard_gate,
        &stale_standard,
        true,
        true,
        STANDARD_ACTION_ID,
        "trace-rfg-conf-standard",
    )
    .map_err(|error| format!("standard owner bypass should pass: {error:?}"))?;
    expect_allowed(&decision, true, "RFG-003")?;
    expect_replay(
        check(
            &mut standard_gate,
            &stale_standard,
            true,
            true,
            STANDARD_ACTION_ID,
            "trace-rfg-conf-standard-replay",
        ),
        &stale_standard.nonce,
    )?;
    covered.push(CoverageRow {
        id: "RFG-CONF-STANDARD-BYPASS-CONSUMES",
        requirement: "standard owner-bypass success must consume nonce and reject replay",
    });

    let mut advisory_gate = tiered_gate();
    let stale_advisory = proof_for_tier(
        SafetyTier::Advisory,
        CURRENT_EPOCH - 10,
        "rfg-conf-advisory",
    );
    let decision = check(
        &mut advisory_gate,
        &stale_advisory,
        true,
        false,
        ACTION_ID,
        "trace-rfg-conf-advisory",
    )
    .map_err(|error| format!("advisory stale warning should pass: {error:?}"))?;
    expect_allowed(&decision, true, "RFG-003")?;
    ensure(
        advisory_gate.is_nonce_consumed(&stale_advisory.nonce),
        "advisory degraded success must consume nonce",
    )?;
    covered.push(CoverageRow {
        id: "RFG-CONF-ADVISORY-STALE-CONSUMES",
        requirement: "advisory degraded success must be replay-protected after warning",
    });

    let mut saturated = gate();
    let overflow = 3_usize;
    let total_insertions = MAX_CONSUMED_NONCES.saturating_add(overflow);
    for idx in 0..total_insertions {
        let nonce = nonce_for("rfg-conf-capacity", idx);
        let trace_id = trace_for("rfg-conf-capacity", idx);
        insert_nonce(&mut saturated, &nonce, &trace_id)?;
        ensure(
            saturated.consumed_nonce_count() <= MAX_CONSUMED_NONCES,
            "replay window must stay bounded during capacity conformance run",
        )?;
    }
    ensure_eq(
        &saturated.consumed_nonce_count(),
        &MAX_CONSUMED_NONCES,
        "saturated replay window size",
    )?;
    ensure(
        !saturated.is_nonce_consumed(&nonce_for("rfg-conf-capacity", 0)),
        "oldest nonce must be evicted after overflow",
    )?;
    ensure(
        saturated.is_nonce_consumed(&nonce_for("rfg-conf-capacity", overflow)),
        "first retained nonce must stay in bounded window",
    )?;
    covered.push(CoverageRow {
        id: "RFG-CONF-FIFO-CAPACITY",
        requirement: "replay cache must cap at MAX_CONSUMED_NONCES and evict oldest insertions",
    });

    let mut no_refresh_gate = gate();
    let duplicate_nonce = "rfg-conf-no-refresh";
    insert_nonce(
        &mut no_refresh_gate,
        duplicate_nonce,
        "trace-rfg-conf-no-refresh-first",
    )?;
    expect_replay(
        check(
            &mut no_refresh_gate,
            &proof_for(duplicate_nonce),
            true,
            false,
            ACTION_ID,
            "trace-rfg-conf-no-refresh-duplicate",
        ),
        duplicate_nonce,
    )?;
    for idx in 0..MAX_CONSUMED_NONCES {
        let nonce = nonce_for("rfg-conf-no-refresh", idx);
        let trace_id = trace_for("rfg-conf-no-refresh", idx);
        insert_nonce(&mut no_refresh_gate, &nonce, &trace_id)?;
    }
    ensure(
        !no_refresh_gate.is_nonce_consumed(duplicate_nonce),
        "duplicate replay must not refresh FIFO eviction order",
    )?;
    covered.push(CoverageRow {
        id: "RFG-CONF-DUPLICATE-NO-REFRESH",
        requirement: "replayed nonce observations must not move entries to the recent end",
    });

    assert_all_requirements_covered(&covered)
}

#[test]
fn duplicate_augmented_replay_stream_preserves_window_state_and_fifo_capacity() -> TestResult {
    let seed_nonces: Vec<String> = (0..32)
        .map(|idx| nonce_for("rwmm-idempotent", idx))
        .collect();

    let mut unique_only = gate();
    let mut duplicate_augmented = gate();

    for nonce in &seed_nonces {
        insert_nonce(&mut unique_only, nonce, "trace-rwmm-unique")?;

        insert_nonce(
            &mut duplicate_augmented,
            nonce,
            "trace-rwmm-augmented-first",
        )?;
        let count_after_first_insert = duplicate_augmented.consumed_nonce_count();
        let duplicate = proof_for(nonce);
        let duplicate_result = duplicate_augmented.check(
            &duplicate,
            CURRENT_EPOCH,
            true,
            false,
            ACTION_ID,
            "trace-rwmm-augmented-duplicate",
        );

        expect_replay(duplicate_result, nonce)?;
        ensure_eq(
            &duplicate_augmented.consumed_nonce_count(),
            &count_after_first_insert,
            "duplicate insertion must not grow the replay window",
        )?;
    }

    ensure_eq(
        &duplicate_augmented.consumed_nonce_count(),
        &unique_only.consumed_nonce_count(),
        "duplicate-augmented stream should converge to unique-only window size",
    )?;
    for nonce in &seed_nonces {
        ensure_eq(
            &duplicate_augmented.is_nonce_consumed(nonce),
            &unique_only.is_nonce_consumed(nonce),
            "duplicate augmentation changed membership",
        )?;
    }

    let overflow = 17_usize;
    let total_insertions = MAX_CONSUMED_NONCES.saturating_add(overflow);
    let mut saturated = gate();

    for idx in 0..total_insertions {
        let nonce = nonce_for("rwmm-capacity", idx);
        let trace_id = trace_for("rwmm-capacity", idx);
        insert_nonce(&mut saturated, &nonce, &trace_id)?;
        ensure(
            saturated.consumed_nonce_count() <= MAX_CONSUMED_NONCES,
            "replay window grew beyond MAX_CONSUMED_NONCES",
        )?;
    }

    ensure_eq(
        &saturated.consumed_nonce_count(),
        &MAX_CONSUMED_NONCES,
        "saturated replay window should stop at exactly MAX_CONSUMED_NONCES",
    )?;

    for idx in 0..overflow {
        let evicted = nonce_for("rwmm-capacity", idx);
        ensure(
            !saturated.is_nonce_consumed(&evicted),
            "FIFO replay window should evict oldest nonce",
        )?;
    }

    for idx in overflow..total_insertions {
        let retained = nonce_for("rwmm-capacity", idx);
        ensure(
            saturated.is_nonce_consumed(&retained),
            "FIFO replay window should retain recent nonce",
        )?;
    }
    Ok(())
}

#[test]
fn duplicate_replay_attempt_does_not_refresh_fifo_eviction_order() -> TestResult {
    let oldest_nonce = "rwmm-order-oldest";
    let mut unique_only = gate();
    let mut duplicate_augmented = gate();

    insert_nonce(&mut unique_only, oldest_nonce, "trace-rwmm-order-unique")?;
    insert_nonce(
        &mut duplicate_augmented,
        oldest_nonce,
        "trace-rwmm-order-duplicate-first",
    )?;

    let duplicate = proof_for(oldest_nonce);
    let duplicate_result = duplicate_augmented.check(
        &duplicate,
        CURRENT_EPOCH,
        true,
        false,
        ACTION_ID,
        "trace-rwmm-order-duplicate-replay",
    );
    expect_replay(duplicate_result, oldest_nonce)?;
    ensure_eq(
        &duplicate_augmented.consumed_nonce_count(),
        &unique_only.consumed_nonce_count(),
        "duplicate replay attempt must not grow the window",
    )?;

    for idx in 1..=MAX_CONSUMED_NONCES {
        let nonce = nonce_for("rwmm-order", idx);
        let trace_id = trace_for("rwmm-order", idx);
        insert_nonce(&mut unique_only, &nonce, &trace_id)?;
        insert_nonce(&mut duplicate_augmented, &nonce, &trace_id)?;

        ensure(
            duplicate_augmented.consumed_nonce_count() <= MAX_CONSUMED_NONCES,
            "duplicate-augmented replay window grew past MAX_CONSUMED_NONCES",
        )?;
    }

    ensure_eq(
        &duplicate_augmented.consumed_nonce_count(),
        &unique_only.consumed_nonce_count(),
        "duplicate replay attempt changed final window size after overflow",
    )?;
    ensure_eq(
        &duplicate_augmented.is_nonce_consumed(oldest_nonce),
        &unique_only.is_nonce_consumed(oldest_nonce),
        "duplicate replay attempt refreshed FIFO position for {oldest_nonce}",
    )?;
    ensure(
        !duplicate_augmented.is_nonce_consumed(oldest_nonce),
        "oldest nonce should be evicted after MAX_CONSUMED_NONCES newer unique inserts",
    )
}
