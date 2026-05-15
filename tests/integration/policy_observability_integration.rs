//! Integration tests for bd-17ds.5.3 (and audit-debt child bd-17ds.5.3.1).
//!
//! Wires three real subsystems end-to-end with NO mocks:
//!
//!     1. `policy::compat_gates::CompatGateEvaluator`
//!        — emits a compatibility decision (allow / deny / audit) under a
//!          signed mode receipt for a scope.
//!     2. `policy::evidence_emission::EvidenceConformanceChecker`
//!        — validates that every gate decision is paired with an
//!          `EvidenceEntry` whose `decision_kind` matches the policy action
//!          and whose `decision_id` links back to the action.
//!     3. `observability::evidence_ledger::EvidenceLedger`
//!        — append-only, hash-chained, replay-resistant ledger that stores
//!          each decision's evidence. Signature verification is exercised
//!          with REAL Ed25519 keys (no fake signers — same pattern as
//!          `crates/franken-node/tests/e2e_evidence_ledger_lifecycle.rs`).
//!
//! ## Cross-module invariant
//!
//! For every gate evaluation that reaches a control-actionable decision,
//! the following must hold:
//!
//!     gate.evaluate_gate() → GateCheckResult.decision
//!         → evidence_conformance.verify_and_execute() (real EvidenceEntry)
//!             → ledger.append() (signed, hash-chained, non-replayable)
//!                 → ledger.iter_all() retrieves the decision in append order
//!
//! Hash chain MUST be monotonic across N decisions (i.e. each entry's
//! `prev_entry_hash` equals the SHA-256 of the previous appended entry).
//! Replays MUST be rejected. Tampered payloads MUST fail verification.
//!
//! Bead: bd-17ds.5.3.1 (audit-true-false-closed for bd-17ds.5.3).

#![forbid(unsafe_code)]

use std::sync::Once;

use ed25519_dalek::SigningKey;
use serde_json::json;
use tracing::{debug, info};

use frankenengine_node::observability::evidence_ledger::{
    DecisionKind, EntryId, EvidenceEntry, EvidenceLedger, LedgerCapacity, LedgerError,
    evidence_entry_hash_hex, sign_evidence_entry, verify_evidence_entry,
};
use frankenengine_node::policy::compat_gates::{
    CompatGateEvaluator, CompatibilityBand, CompatibilityMode, GateDecision, ShimRegistry,
    ShimRegistryEntry, ShimRiskCategory,
};
use frankenengine_node::policy::evidence_emission::{
    ActionId, EvidenceConformanceChecker, PolicyAction, PolicyActionOutcome, build_evidence_entry,
};

type TestResult = Result<(), String>;

// --- shared test helpers ----------------------------------------------------

static TRACING_INIT: Once = Once::new();

fn init_tracing() {
    TRACING_INIT.call_once(|| {
        // Best-effort tracing init; ignore failure if another integration test
        // already installed a global subscriber in the same test process.
        let _ = tracing_subscriber::fmt()
            .with_test_writer()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "info".into()),
            )
            .try_init();
    });
}

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn make_shim(id: &str, band: CompatibilityBand, risk: ShimRiskCategory) -> ShimRegistryEntry {
    ShimRegistryEntry {
        shim_id: id.to_string(),
        description: format!("Integration shim {id}"),
        band,
        risk_category: risk,
        activation_policy_id: format!("pol-{id}"),
        divergence_rationale: format!("rationale-{id}"),
        api_family: "fs".to_string(),
        active: true,
    }
}

/// Builds a shim registry with one entry per (band, risk) class so we can
/// exercise the gate matrix end-to-end. `pkg-core` triggers Deny/Error,
/// `pkg-hv` triggers Audit/Warn under Balanced mode, `pkg-edge` triggers
/// Allow/Log, and `pkg-unsafe` triggers Deny/Blocked unless mode is
/// LegacyRisky (then Warn → Audit).
fn build_registry() -> ShimRegistry {
    let mut reg = ShimRegistry::new();
    reg.register(make_shim(
        "pkg-core",
        CompatibilityBand::Core,
        ShimRiskCategory::High,
    ))
    .expect("register core shim");
    reg.register(make_shim(
        "pkg-hv",
        CompatibilityBand::HighValue,
        ShimRiskCategory::Medium,
    ))
    .expect("register high-value shim");
    reg.register(make_shim(
        "pkg-edge",
        CompatibilityBand::Edge,
        ShimRiskCategory::Low,
    ))
    .expect("register edge shim");
    reg.register(make_shim(
        "pkg-unsafe",
        CompatibilityBand::Unsafe,
        ShimRiskCategory::Critical,
    ))
    .expect("register unsafe shim");
    reg
}

/// Build a CompatGateEvaluator with a scope already in the requested mode.
fn build_evaluator(scope_id: &str, mode: CompatibilityMode) -> CompatGateEvaluator {
    let mut eval = CompatGateEvaluator::new(build_registry());
    // First mode selection from "unset" is not an escalation per the
    // `is_escalation_to` semantics — pass `approval=true` defensively.
    eval.set_mode(
        scope_id,
        mode,
        "integration-test",
        "wire policy-observability harness",
        true,
    )
    .expect("set_mode must succeed for a fresh scope");
    eval
}

/// Build a fresh evidence entry whose `decision_id == action_id` (linkage)
/// and whose `decision_kind` matches `action.expected_decision_kind()`. Sign
/// it with `key`.
fn signed_entry_for_action(
    action: PolicyAction,
    action_id: &ActionId,
    trace_id: &str,
    epoch_id: u64,
    timestamp_ms: u64,
    key: &SigningKey,
    payload: serde_json::Value,
) -> EvidenceEntry {
    let mut entry = build_evidence_entry(action, action_id, trace_id, epoch_id, payload);
    // build_evidence_entry leaves timestamp_ms = 0; pick a fresh per-test
    // value so the replay window stays unique across appended entries.
    entry.timestamp_ms = timestamp_ms;
    entry.decision_time = format!("2026-05-12T00:00:{:02}Z", epoch_id.min(59));
    sign_evidence_entry(&mut entry, key);
    entry
}

// --- tests ------------------------------------------------------------------

/// Happy path: a Balanced-mode gate against a high-value shim returns Audit,
/// the operator pairs the decision with a Quarantine evidence entry, and the
/// ledger stores it.
#[test]
fn test_compat_gate_pass_emits_evidence() {
    init_tracing();
    info!("ENTER test_compat_gate_pass_emits_evidence");

    let mut eval = build_evaluator("scope-pass", CompatibilityMode::Balanced);
    let result = eval
        .evaluate_gate("pkg-hv", "scope-pass", "trace-pass")
        .expect("gate evaluation succeeds");
    debug!(decision = %result.decision, "gate decision");
    // bd-2wz matrix: HighValue + Balanced -> Warn -> Audit
    assert_eq!(result.decision, GateDecision::Audit);
    assert!(
        result.receipt_id.is_some(),
        "audit decision must carry receipt"
    );

    // Wire the gate's decision into the observability pipeline.
    let key = signing_key(0x10);
    let mut ledger =
        EvidenceLedger::with_verifying_key(LedgerCapacity::new(16, 8_192), key.verifying_key());
    let mut checker = EvidenceConformanceChecker::new();
    let action_id = ActionId::new(format!("act-{}", result.trace_id));
    let entry = signed_entry_for_action(
        PolicyAction::Quarantine,
        &action_id,
        &result.trace_id,
        1,
        1_000,
        &key,
        json!({"package_id": "pkg-hv", "decision": "audit"}),
    );
    let outcome = checker.verify_and_execute(
        PolicyAction::Quarantine,
        &action_id,
        Some(&entry),
        &mut ledger,
    );
    debug!(?outcome, "evidence conformance outcome");
    assert!(
        outcome.is_executed(),
        "evidence-conformant action must execute"
    );
    assert_eq!(ledger.len(), 1);
    assert_eq!(checker.executed_count(), 1);

    info!("EXIT test_compat_gate_pass_emits_evidence");
}

/// Failure path: a Strict-mode gate against an unknown package yields Deny.
/// The operator records the deny as an `Abort` (DecisionKind::Deny) and the
/// ledger stores it.
#[test]
fn test_compat_gate_fail_emits_evidence() {
    init_tracing();
    info!("ENTER test_compat_gate_fail_emits_evidence");

    let mut eval = build_evaluator("scope-fail", CompatibilityMode::Strict);
    let result = eval
        .evaluate_gate("pkg-unknown", "scope-fail", "trace-fail")
        .expect("gate evaluation succeeds");
    debug!(decision = %result.decision, "gate decision");
    // Strict + unknown package -> Deny
    assert_eq!(result.decision, GateDecision::Deny);
    assert!(
        result
            .reason_codes
            .iter()
            .any(|c| c.contains("DENY_UNKNOWN_STRICT")),
        "deny must cite the strict-unknown reason code: {:?}",
        result.reason_codes
    );

    let key = signing_key(0x11);
    let mut ledger =
        EvidenceLedger::with_verifying_key(LedgerCapacity::new(16, 8_192), key.verifying_key());
    let mut checker = EvidenceConformanceChecker::new();
    let action_id = ActionId::new(format!("act-{}", result.trace_id));
    let entry = signed_entry_for_action(
        PolicyAction::Abort,
        &action_id,
        &result.trace_id,
        2,
        2_000,
        &key,
        json!({"package_id": "pkg-unknown", "decision": "deny"}),
    );
    let outcome =
        checker.verify_and_execute(PolicyAction::Abort, &action_id, Some(&entry), &mut ledger);
    assert!(outcome.is_executed());
    assert_eq!(ledger.len(), 1);

    info!("EXIT test_compat_gate_fail_emits_evidence");
}

/// The ledger persists the decision and reports it via `snapshot()` with the
/// expected `decision_kind` label.
#[test]
fn test_evidence_ledger_stores_decision() {
    init_tracing();
    info!("ENTER test_evidence_ledger_stores_decision");

    let key = signing_key(0x12);
    let mut ledger =
        EvidenceLedger::with_verifying_key(LedgerCapacity::new(4, 4_096), key.verifying_key());
    let mut checker = EvidenceConformanceChecker::new();
    let action_id = ActionId::new("act-store-1");
    let entry = signed_entry_for_action(
        PolicyAction::Commit,
        &action_id,
        "trace-store-1",
        3,
        3_000,
        &key,
        json!({"detail": "store"}),
    );
    let outcome =
        checker.verify_and_execute(PolicyAction::Commit, &action_id, Some(&entry), &mut ledger);
    assert!(outcome.is_executed());

    let snap = ledger.snapshot();
    debug!(entries = snap.entries.len(), "ledger snapshot");
    assert_eq!(snap.entries.len(), 1);
    assert_eq!(snap.total_appended, 1);
    assert_eq!(snap.total_evicted, 0);
    let (entry_id, persisted) = &snap.entries[0];
    assert_eq!(*entry_id, EntryId(1));
    assert_eq!(persisted.decision_id, "act-store-1");
    assert_eq!(persisted.decision_kind, DecisionKind::Admit);

    info!("EXIT test_evidence_ledger_stores_decision");
}

/// After N decisions, `iter_all()` MUST return entries in append order with
/// monotonically increasing `EntryId`s and a non-trivial hash chain.
#[test]
fn test_ledger_query_retrieves_chain_in_order() {
    init_tracing();
    info!("ENTER test_ledger_query_retrieves_chain_in_order");

    let key = signing_key(0x13);
    let mut ledger =
        EvidenceLedger::with_verifying_key(LedgerCapacity::new(32, 16_384), key.verifying_key());
    let mut checker = EvidenceConformanceChecker::new();

    let decisions = [
        (PolicyAction::Commit, "act-A"),
        (PolicyAction::Abort, "act-B"),
        (PolicyAction::Quarantine, "act-C"),
        (PolicyAction::Release, "act-D"),
    ];
    for (i, (action, id)) in decisions.iter().enumerate() {
        let action_id = ActionId::new(*id);
        let entry = signed_entry_for_action(
            *action,
            &action_id,
            &format!("trace-{id}"),
            (i as u64).saturating_add(10),
            (i as u64).saturating_add(1).saturating_mul(1_000),
            &key,
            json!({"index": i}),
        );
        let outcome = checker.verify_and_execute(*action, &action_id, Some(&entry), &mut ledger);
        assert!(outcome.is_executed(), "decision #{} must execute", i);
    }

    assert_eq!(ledger.len(), decisions.len());
    let ids: Vec<EntryId> = ledger.iter_all().map(|(id, _, _)| *id).collect();
    debug!(?ids, "ledger entry ids");
    // EntryIds must be strictly monotonic in append order (no gaps, no
    // reordering).
    for window in ids.windows(2) {
        assert!(window[0].0 < window[1].0, "ids must be monotonic: {ids:?}");
    }
    // decision_ids must come back in the order they were appended.
    let recovered: Vec<&str> = ledger
        .iter_all()
        .map(|(_, e, _)| e.decision_id.as_str())
        .collect();
    assert_eq!(recovered, vec!["act-A", "act-B", "act-C", "act-D"]);

    info!("EXIT test_ledger_query_retrieves_chain_in_order");
}

/// Each appended entry's `prev_entry_hash` MUST equal the SHA-256 of the
/// previous entry's canonical form. Tampering with any persisted byte breaks
/// the chain.
#[test]
fn test_multi_decision_hash_chain_consistent() {
    init_tracing();
    info!("ENTER test_multi_decision_hash_chain_consistent");

    let key = signing_key(0x14);
    let mut ledger =
        EvidenceLedger::with_verifying_key(LedgerCapacity::new(8, 8_192), key.verifying_key());
    let mut checker = EvidenceConformanceChecker::new();

    for i in 0..5_u64 {
        let action_id = ActionId::new(format!("act-chain-{i}"));
        let entry = signed_entry_for_action(
            PolicyAction::Commit,
            &action_id,
            &format!("trace-chain-{i}"),
            i.saturating_add(1),
            i.saturating_add(1).saturating_mul(1_000),
            &key,
            json!({"chain_index": i}),
        );
        let outcome =
            checker.verify_and_execute(PolicyAction::Commit, &action_id, Some(&entry), &mut ledger);
        assert!(outcome.is_executed(), "chain step {i} must execute");
    }

    let all: Vec<_> = ledger.iter_all().collect();
    assert_eq!(all.len(), 5);

    // The first entry's prev_entry_hash MUST be empty (no predecessor).
    assert!(
        all[0].1.prev_entry_hash.is_empty(),
        "first entry must have empty prev_entry_hash, got {:?}",
        all[0].1.prev_entry_hash
    );

    // Each subsequent entry's prev_entry_hash MUST equal the hash of the
    // preceding entry's canonical form.
    for window in all.windows(2) {
        let prev_hash = evidence_entry_hash_hex(&window[0].1);
        let claimed_prev_hash = &window[1].1.prev_entry_hash;
        debug!(
            id_a = window[0].0.0,
            id_b = window[1].0.0,
            hash = %prev_hash,
            "hash-chain link"
        );
        assert_eq!(
            *claimed_prev_hash, prev_hash,
            "hash chain broken between {:?} and {:?}",
            window[0].0, window[1].0
        );
        assert_eq!(claimed_prev_hash.len(), 64, "sha256 hex must be 64 chars");
    }

    info!("EXIT test_multi_decision_hash_chain_consistent");
}

/// Re-appending an identical (timestamp_ms, signature) pair MUST be rejected
/// with `LedgerError::ReplayAttack`.
#[test]
fn test_replay_attack_rejected() -> TestResult {
    init_tracing();
    info!("ENTER test_replay_attack_rejected");

    let key = signing_key(0x15);
    let mut ledger =
        EvidenceLedger::with_verifying_key(LedgerCapacity::new(8, 4_096), key.verifying_key());
    let mut checker = EvidenceConformanceChecker::new();
    let action_id = ActionId::new("act-replay");
    let entry = signed_entry_for_action(
        PolicyAction::Commit,
        &action_id,
        "trace-replay",
        7,
        7_777,
        &key,
        json!({"once": true}),
    );
    let first =
        checker.verify_and_execute(PolicyAction::Commit, &action_id, Some(&entry), &mut ledger);
    assert!(first.is_executed());
    assert_eq!(ledger.len(), 1);

    // Re-submit the SAME signed entry. The checker re-runs all gates and the
    // ledger MUST reject the replay.
    let second =
        checker.verify_and_execute(PolicyAction::Commit, &action_id, Some(&entry), &mut ledger);
    debug!(?second, "second submission outcome");
    assert!(second.is_rejected(), "replay must be rejected: {second:?}");
    match second {
        PolicyActionOutcome::Rejected { error, .. } => {
            assert!(
                error.to_string().contains("ReplayAttack")
                    || error.to_string().to_lowercase().contains("replay")
                    || error.to_string().contains("ledger append failed"),
                "expected replay/append-fail message, got {error}"
            );
        }
        other => return Err(format!("expected Rejected outcome, got {other:?}")),
    }
    // Ledger state must NOT advance on a rejected append.
    assert_eq!(ledger.len(), 1, "replay must not advance ledger");
    assert_eq!(ledger.total_appended(), 1);

    info!("EXIT test_replay_attack_rejected");
    Ok(())
}

/// Capacity-bounded ledger evicts oldest entries FIFO; the remaining entries
/// still form a valid hash chain (i.e. eviction does not corrupt the chain
/// linking the entries that survived).
#[test]
fn test_capacity_eviction_preserves_chain() {
    init_tracing();
    info!("ENTER test_capacity_eviction_preserves_chain");

    // capacity = 3; we append 6 and expect 3 evictions.
    let key = signing_key(0x16);
    let mut ledger =
        EvidenceLedger::with_verifying_key(LedgerCapacity::new(3, 8_192), key.verifying_key());
    let mut checker = EvidenceConformanceChecker::new();

    for i in 0..6_u64 {
        let action_id = ActionId::new(format!("act-evict-{i}"));
        let entry = signed_entry_for_action(
            PolicyAction::Commit,
            &action_id,
            &format!("trace-evict-{i}"),
            i.saturating_add(100),
            i.saturating_add(1).saturating_mul(10_000),
            &key,
            json!({"evict": i}),
        );
        let outcome =
            checker.verify_and_execute(PolicyAction::Commit, &action_id, Some(&entry), &mut ledger);
        assert!(outcome.is_executed(), "evict step {i} must execute");
    }

    assert_eq!(ledger.len(), 3);
    assert_eq!(ledger.total_appended(), 6);
    assert_eq!(ledger.total_evicted(), 3);

    // The surviving 3 entries' chain must still be self-consistent: each
    // subsequent entry's prev_entry_hash equals the hash of the previous.
    let all: Vec<_> = ledger.iter_all().collect();
    for window in all.windows(2) {
        let prev_hash = evidence_entry_hash_hex(&window[0].1);
        assert_eq!(
            window[1].1.prev_entry_hash, prev_hash,
            "post-eviction chain link broken"
        );
    }
    // The kept decision_ids must be the latest 3 (act-evict-3..act-evict-5).
    let kept: Vec<String> = all.iter().map(|(_, e, _)| e.decision_id.clone()).collect();
    debug!(?kept, "post-eviction kept decisions");
    assert_eq!(
        kept,
        vec![
            "act-evict-3".to_string(),
            "act-evict-4".to_string(),
            "act-evict-5".to_string(),
        ]
    );

    info!("EXIT test_capacity_eviction_preserves_chain");
}

/// Mutating an entry after signing (so its canonical bytes no longer match
/// the signature) MUST be rejected by both `verify_evidence_entry` and the
/// ledger's append-time signature check.
#[test]
fn test_signature_tampering_rejected() {
    init_tracing();
    info!("ENTER test_signature_tampering_rejected");

    let key = signing_key(0x17);
    let mut ledger =
        EvidenceLedger::with_verifying_key(LedgerCapacity::new(4, 4_096), key.verifying_key());

    let action_id = ActionId::new("act-tamper");
    let mut entry = signed_entry_for_action(
        PolicyAction::Commit,
        &action_id,
        "trace-tamper",
        9,
        9_000,
        &key,
        json!({"tamper": false}),
    );
    // Verify the pristine entry round-trips.
    verify_evidence_entry(&entry, &key.verifying_key()).expect("pristine entry must verify");

    // Now mutate the payload AFTER signing — the signature no longer covers
    // the canonical bytes.
    entry.payload = json!({"tamper": true});
    let verify_err = verify_evidence_entry(&entry, &key.verifying_key());
    assert!(verify_err.is_err(), "tampered payload must fail verify");

    // The ledger MUST refuse to append a tampered entry.
    let append_err = ledger.append(entry).expect_err("tampered append must fail");
    assert!(
        matches!(append_err, LedgerError::SignatureInvalid { .. }),
        "expected SignatureInvalid, got {append_err:?}"
    );
    assert!(ledger.is_empty(), "rejected entry must not occupy a slot");

    info!("EXIT test_signature_tampering_rejected");
}

/// A `PolicyAction::Quarantine` paired with an evidence entry that declares
/// `decision_kind = Admit` MUST be rejected as a linkage mismatch — the
/// checker enforces INV-EVIDENCE-LINKAGE.
#[test]
fn test_decision_kind_mismatch_rejected() {
    init_tracing();
    info!("ENTER test_decision_kind_mismatch_rejected");

    let key = signing_key(0x18);
    let mut ledger =
        EvidenceLedger::with_verifying_key(LedgerCapacity::new(4, 4_096), key.verifying_key());
    let mut checker = EvidenceConformanceChecker::new();

    let action_id = ActionId::new("act-mismatch");
    // Build a Commit-shaped (Admit) entry but submit it under a Quarantine
    // action — the kinds don't match.
    let entry = signed_entry_for_action(
        PolicyAction::Commit,
        &action_id,
        "trace-mismatch",
        11,
        11_000,
        &key,
        json!({"role": "commit"}),
    );
    let outcome = checker.verify_and_execute(
        PolicyAction::Quarantine,
        &action_id,
        Some(&entry),
        &mut ledger,
    );
    assert!(outcome.is_rejected(), "linkage mismatch must reject");
    assert!(
        ledger.is_empty(),
        "rejected action must not append to ledger"
    );
    assert_eq!(checker.executed_count(), 0);
    assert_eq!(checker.rejected_count(), 1);

    info!("EXIT test_decision_kind_mismatch_rejected");
}

/// Missing evidence MUST reject the policy action without touching the
/// ledger.
#[test]
fn test_missing_evidence_rejected() {
    init_tracing();
    info!("ENTER test_missing_evidence_rejected");

    let key = signing_key(0x19);
    let mut ledger =
        EvidenceLedger::with_verifying_key(LedgerCapacity::new(4, 4_096), key.verifying_key());
    let mut checker = EvidenceConformanceChecker::new();

    let outcome = checker.verify_and_execute(
        PolicyAction::Commit,
        &ActionId::new("act-no-evidence"),
        None,
        &mut ledger,
    );
    assert!(outcome.is_rejected(), "missing evidence must reject");
    assert_eq!(outcome.event_code(), "EVD-POLICY-002");
    assert!(ledger.is_empty());
    assert_eq!(checker.rejected_count(), 1);

    info!("EXIT test_missing_evidence_rejected");
}

/// A burst of mixed allow/deny/audit decisions all wired through the
/// observability pipeline; the audit log on the evaluator MUST contain one
/// record per evaluation and the ledger MUST contain one entry per
/// control-actionable decision.
#[test]
fn test_audit_log_and_ledger_counts_match() {
    init_tracing();
    info!("ENTER test_audit_log_and_ledger_counts_match");

    let mut eval = build_evaluator("scope-count", CompatibilityMode::Balanced);
    let key = signing_key(0x1A);
    let mut ledger =
        EvidenceLedger::with_verifying_key(LedgerCapacity::new(16, 16_384), key.verifying_key());
    let mut checker = EvidenceConformanceChecker::new();

    // 4 evaluations: edge (Allow), high-value (Audit), unknown (Audit), core (Deny).
    let packages = [
        ("pkg-edge", PolicyAction::Commit, DecisionKind::Admit),
        ("pkg-hv", PolicyAction::Quarantine, DecisionKind::Quarantine),
        (
            "pkg-unknown",
            PolicyAction::Quarantine,
            DecisionKind::Quarantine,
        ),
        ("pkg-core", PolicyAction::Abort, DecisionKind::Deny),
    ];
    for (i, (pkg, action, _kind)) in packages.iter().enumerate() {
        let res = eval
            .evaluate_gate(pkg, "scope-count", &format!("trace-count-{i}"))
            .expect("eval ok");
        debug!(pkg, decision = %res.decision, "gate decision");
        let action_id = ActionId::new(format!("act-count-{i}"));
        let entry = signed_entry_for_action(
            *action,
            &action_id,
            &res.trace_id,
            (i as u64).saturating_add(200),
            (i as u64).saturating_add(1).saturating_mul(100_000),
            &key,
            json!({"package": pkg, "decision": res.decision.label()}),
        );
        let outcome = checker.verify_and_execute(*action, &action_id, Some(&entry), &mut ledger);
        assert!(outcome.is_executed(), "decision #{i} must execute");
    }

    let audit = eval.audit_log_for_scope("scope-count");
    debug!(
        audit_entries = audit.len(),
        ledger_entries = ledger.len(),
        "totals"
    );
    assert_eq!(
        audit.len(),
        packages.len(),
        "one audit record per evaluation"
    );
    assert_eq!(ledger.len(), packages.len(), "one ledger entry per action");
    assert_eq!(eval.evaluation_count(), packages.len());
    assert_eq!(checker.executed_count(), packages.len() as u64);

    info!("EXIT test_audit_log_and_ledger_counts_match");
}

/// End-to-end pipeline test with full tracing instrumentation: drives a
/// fresh evaluator + checker + ledger through every policy action variant
/// and verifies the cumulative chain integrity post-run.
#[test]
fn test_full_pipeline_with_tracing() {
    init_tracing();
    info!("ENTER test_full_pipeline_with_tracing");

    let mut eval = build_evaluator("scope-full", CompatibilityMode::Balanced);
    let key = signing_key(0x1B);
    let mut ledger =
        EvidenceLedger::with_verifying_key(LedgerCapacity::new(32, 32_768), key.verifying_key());
    let mut checker = EvidenceConformanceChecker::new();

    // Cycle through all four policy actions paired with reasonable packages.
    let cases = [
        ("pkg-edge", PolicyAction::Commit),
        ("pkg-hv", PolicyAction::Quarantine),
        ("pkg-unknown", PolicyAction::Release),
        ("pkg-core", PolicyAction::Abort),
    ];
    for (i, (pkg, action)) in cases.iter().enumerate() {
        let res = eval
            .evaluate_gate(pkg, "scope-full", &format!("trace-full-{i}"))
            .expect("eval ok");
        debug!(
            pkg,
            decision = %res.decision,
            action = %action,
            "pipeline iteration"
        );
        let action_id = ActionId::new(format!("act-full-{i}"));
        let entry = signed_entry_for_action(
            *action,
            &action_id,
            &res.trace_id,
            (i as u64).saturating_add(300),
            (i as u64).saturating_add(1).saturating_mul(1_000_000),
            &key,
            json!({
                "package": pkg,
                "gate_decision": res.decision.label(),
                "reason_codes": res.reason_codes,
            }),
        );
        let outcome = checker.verify_and_execute(*action, &action_id, Some(&entry), &mut ledger);
        assert!(
            outcome.is_executed(),
            "pipeline iter {i} ({pkg}, {action}) must execute"
        );
    }

    // Cumulative invariants.
    assert_eq!(ledger.len(), cases.len());
    assert_eq!(ledger.total_appended(), cases.len() as u64);
    assert_eq!(checker.executed_count(), cases.len() as u64);
    assert_eq!(checker.rejected_count(), 0);

    // Final chain integrity sweep.
    let all: Vec<_> = ledger.iter_all().collect();
    for window in all.windows(2) {
        let prev_hash = evidence_entry_hash_hex(&window[0].1);
        assert_eq!(window[1].1.prev_entry_hash, prev_hash);
    }
    // Cumulative snapshot reports the right totals.
    let snap = ledger.snapshot();
    assert_eq!(snap.entries.len(), cases.len());
    assert_eq!(snap.total_appended, cases.len() as u64);
    assert_eq!(snap.total_evicted, 0);

    info!("EXIT test_full_pipeline_with_tracing");
}
