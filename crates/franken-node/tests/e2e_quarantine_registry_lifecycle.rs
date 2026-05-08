//! Mock-free end-to-end test for the supply-chain quarantine state machine.
//!
//! Drives the public surface of
//! `frankenengine_node::supply_chain::quarantine::QuarantineRegistry` through
//! the full lifecycle — both the lift path (clear & resume) and the recall
//! path (artifact removal):
//!
//!   Lift:   initiate → record_propagation → enforce_quarantine →
//!           start_drain → complete_drain → lift_quarantine
//!   Recall: initiate → record_propagation → enforce_quarantine →
//!           generate_impact_report → trigger_recall →
//!           record_recall_receipt → complete_recall
//!
//! Bead: bd-1r7r8.
//!
//! Coverage:
//!   - happy paths for both terminal states (Lifted, RecallCompleted),
//!   - INV-QUAR-IDEMPOTENT — a duplicate order_id is rejected with
//!     `ERR_QUAR_DUPLICATE_ORDER_ID`,
//!   - state machine — calling `start_drain` before `enforce_quarantine`
//!     returns `ERR_QUAR_INVALID_TRANSITION`,
//!   - integrity — a recall receipt with a mismatched recall_id is
//!     rejected (constant-time compared) with
//!     `ERR_RECALL_RECEIPT_MISMATCH`,
//!   - clearance — `lift_quarantine` with empty justification is rejected
//!     with `ERR_LIFT_REQUIRES_CLEARANCE`,
//!   - audit-trail integrity verifies via `verify_audit_integrity`,
//!   - critical-severity orders fast-path directly into `Enforced` state.
//!
//! No mocks: real state-machine, real BTreeMap-backed records, real audit
//! trail, real constant-time `recall_id` comparison. Each phase emits a
//! structured tracing event PLUS a JSON-line on stderr so a CI failure can
//! be reconstructed from the test transcript alone.

use std::sync::Once;
use std::time::Instant;

use frankenengine_node::supply_chain::quarantine::{
    QuarantineClearance, QuarantineMode, QuarantineOrder, QuarantineReason, QuarantineRegistry,
    QuarantineScope, QuarantineSeverity, QuarantineState, RecallOrder, RecallReceipt,
};
use serde_json::json;
use tracing::{error, info};

static TEST_TRACING_INIT: Once = Once::new();

fn init_test_tracing() {
    TEST_TRACING_INIT.call_once(|| {
        let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    });
}

#[derive(serde::Serialize)]
struct PhaseLog<'a> {
    timestamp: String,
    test_name: &'a str,
    phase: &'a str,
    duration_ms: u64,
    success: bool,
    detail: serde_json::Value,
}

struct Harness {
    test_name: &'static str,
    started: Instant,
}

const QUARANTINE_ORDER_FIXTURE_SIGNATURE: &str =
    "sha256:4516c63acce5f11fe6b750c98e1ea51c8fe384e5c211c829ea9894962ba928cb";

impl Harness {
    fn new(test_name: &'static str) -> Self {
        init_test_tracing();
        let h = Self {
            test_name,
            started: Instant::now(),
        };
        h.log_phase("setup", true, json!({}));
        h
    }

    fn log_phase(&self, phase: &str, success: bool, detail: serde_json::Value) {
        let entry = PhaseLog {
            timestamp: chrono::Utc::now().to_rfc3339(),
            test_name: self.test_name,
            phase,
            duration_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            success,
            detail,
        };
        eprintln!(
            "{}",
            serde_json::to_string(&entry).expect("phase log serializes")
        );
        if success {
            info!(
                test = self.test_name,
                phase = phase,
                duration_ms = entry.duration_ms,
                "phase completed"
            );
        } else {
            error!(
                test = self.test_name,
                phase = phase,
                duration_ms = entry.duration_ms,
                "phase failed"
            );
        }
    }
}

fn order(
    order_id: &str,
    extension_id: &str,
    severity: QuarantineSeverity,
    issued_at: &str,
) -> QuarantineOrder {
    QuarantineOrder {
        order_id: order_id.to_string(),
        scope: QuarantineScope::AllVersions {
            extension_id: extension_id.to_string(),
        },
        mode: QuarantineMode::Hard,
        severity,
        reason: QuarantineReason::SupplyChainAttack,
        justification: format!("incident-{order_id}"),
        issued_by: "security-ops@example.com".to_string(),
        issued_at: issued_at.to_string(),
        signature: QUARANTINE_ORDER_FIXTURE_SIGNATURE.to_string(),
        trace_id: format!("trace-{order_id}"),
        grace_period_secs: 3600,
    }
}

fn clearance(order_id: &str, justification: &str, cleared_at: &str) -> QuarantineClearance {
    QuarantineClearance {
        order_id: order_id.to_string(),
        cleared_by: "incident-response@example.com".to_string(),
        justification: justification.to_string(),
        re_verification_evidence: "audit-report-2026-04-26".to_string(),
        cleared_at: cleared_at.to_string(),
        signature: "ed25519:clearance-sig".to_string(),
        trace_id: format!("trace-clearance-{order_id}"),
    }
}

#[test]
fn e2e_quarantine_order_fixture_uses_deterministic_signature_material() {
    let fixture = order(
        "QO-SIGNATURE-001",
        "npm:@e2e/signature-pkg",
        QuarantineSeverity::High,
        "2026-04-26T22:00:00Z",
    );

    let digest = fixture
        .signature
        .strip_prefix("sha256:")
        .expect("fixture signature should be tagged as sha256 material");
    assert_eq!(digest.len(), 64);
    assert!(digest.chars().all(|ch| ch.is_ascii_hexdigit()));

    let lowered = fixture.signature.to_ascii_lowercase();
    assert!(!lowered.contains("placeholder"));
    assert!(!lowered.contains("fake"));
}

#[test]
fn e2e_quarantine_lift_path_full_lifecycle() {
    let h = Harness::new("e2e_quarantine_lift_path_full_lifecycle");

    let mut reg = QuarantineRegistry::new();
    assert_eq!(reg.total_quarantines(), 0);
    h.log_phase("registry_built", true, json!({}));

    // ── ACT: initiate (High severity → starts in Initiated) ────────
    let extension_id = "npm:@e2e/risky-pkg";
    let issued = "2026-04-26T22:00:00Z";
    let record = reg
        .initiate_quarantine(order(
            "QO-LIFT-001",
            extension_id,
            QuarantineSeverity::High,
            issued,
        ))
        .expect("initiate accepted");
    assert_eq!(record.state, QuarantineState::Initiated);
    assert_eq!(reg.total_quarantines(), 1);
    assert!(reg.is_quarantined(extension_id));
    h.log_phase("initiated", true, json!({"order": "QO-LIFT-001"}));

    // ── ACT: propagate, enforce, drain, complete drain ─────────────
    reg.record_propagation("QO-LIFT-001", "node-a", "2026-04-26T22:00:01Z")
        .expect("propagation a");
    reg.record_propagation("QO-LIFT-001", "node-b", "2026-04-26T22:00:02Z")
        .expect("propagation b");
    h.log_phase("propagated", true, json!({"nodes": 2}));

    reg.enforce_quarantine("QO-LIFT-001", "2026-04-26T22:00:03Z")
        .expect("enforce");
    h.log_phase("enforced", true, json!({}));

    reg.start_drain("QO-LIFT-001", "2026-04-26T22:00:04Z")
        .expect("start drain");
    reg.complete_drain("QO-LIFT-001", "2026-04-26T22:00:05Z")
        .expect("complete drain");
    let r = reg.get_record("QO-LIFT-001").expect("record");
    assert_eq!(r.state, QuarantineState::Isolated);
    h.log_phase("isolated", true, json!({}));

    // ── ASSERT: lift requires non-empty justification ───────────────
    let bad = clearance("QO-LIFT-001", "   ", "2026-04-26T22:00:06Z");
    let bad_err = reg
        .lift_quarantine(bad)
        .expect_err("empty justification rejected");
    assert!(bad_err.code.contains("LIFT_REQUIRES_CLEARANCE"));
    h.log_phase(
        "empty_clearance_rejected",
        true,
        json!({"code": bad_err.code}),
    );

    // ── ACT: lift with valid clearance ──────────────────────────────
    let good = clearance(
        "QO-LIFT-001",
        "vendor patched + re-audited",
        "2026-04-26T22:00:07Z",
    );
    reg.lift_quarantine(good).expect("lift succeeds");
    let final_record = reg.get_record("QO-LIFT-001").expect("record after lift");
    assert_eq!(final_record.state, QuarantineState::Lifted);
    assert!(
        !reg.is_quarantined(extension_id),
        "lifted extension must no longer report as quarantined"
    );
    h.log_phase("lifted", true, json!({}));

    // ── ASSERT: audit trail integrity holds ─────────────────────────
    let integrity_ok = reg.verify_audit_integrity().expect("audit verify ok");
    assert!(integrity_ok, "audit integrity must hold");
    let audits = reg.audit_trail();
    assert!(
        audits.len() >= 6,
        "expected at least 6 audit entries (init+2 props+enforce+drain+complete+lift), got {}",
        audits.len()
    );
    h.log_phase("audit_integrity", true, json!({"entries": audits.len()}));
}

#[test]
fn e2e_quarantine_recall_path_full_lifecycle() {
    let h = Harness::new("e2e_quarantine_recall_path_full_lifecycle");

    let mut reg = QuarantineRegistry::new();
    let extension_id = "npm:@e2e/recall-pkg";

    // ── Critical severity → fast-path enforced on initiate ──────────
    let crit = order(
        "QO-RECALL-001",
        extension_id,
        QuarantineSeverity::Critical,
        "2026-04-26T22:10:00Z",
    );
    let record = reg.initiate_quarantine(crit).expect("initiate critical");
    assert_eq!(
        record.state,
        QuarantineState::Enforced,
        "critical severity should fast-path to Enforced"
    );
    h.log_phase("critical_fast_path_enforced", true, json!({}));

    // ── ACT: impact report ──────────────────────────────────────────
    let impact = reg
        .generate_impact_report(
            "QO-RECALL-001",
            42,
            vec!["api-tokens".to_string(), "session-cookies".to_string()],
            vec!["npm:@e2e/dependent".to_string()],
            7,
            vec!["rotate-tokens".to_string(), "force-logout".to_string()],
            "2026-04-26T22:10:30Z",
        )
        .expect("impact report");
    assert_eq!(impact.installations_affected, 42);
    h.log_phase(
        "impact_reported",
        true,
        json!({"installations": impact.installations_affected}),
    );

    // ── ACT: drain to Isolated before triggering the recall ─────────
    reg.start_drain("QO-RECALL-001", "2026-04-26T22:10:40Z")
        .expect("start drain");
    reg.complete_drain("QO-RECALL-001", "2026-04-26T22:10:50Z")
        .expect("complete drain");
    let isolated = reg.get_record("QO-RECALL-001").expect("record");
    assert_eq!(isolated.state, QuarantineState::Isolated);
    h.log_phase("drained_to_isolated", true, json!({}));

    // ── ACT: trigger_recall ─────────────────────────────────────────
    let recall = RecallOrder {
        recall_id: "RC-001".to_string(),
        quarantine_order_id: "QO-RECALL-001".to_string(),
        scope: QuarantineScope::AllVersions {
            extension_id: extension_id.to_string(),
        },
        reason: "confirmed compromise".to_string(),
        issued_by: "security-ops@example.com".to_string(),
        issued_at: "2026-04-26T22:11:00Z".to_string(),
        signature: "ed25519:recall-sig".to_string(),
        trace_id: "trace-recall-001".to_string(),
    };
    reg.trigger_recall(recall).expect("trigger_recall");
    let r = reg.get_record("QO-RECALL-001").expect("record");
    assert_eq!(r.state, QuarantineState::RecallTriggered);
    h.log_phase("recall_triggered", true, json!({}));

    // ── ASSERT: receipt with mismatched recall_id is rejected ───────
    let bogus_receipt = RecallReceipt {
        node_id: "node-evil".to_string(),
        recall_id: "RC-999-FAKE".to_string(),
        removed: true,
        removal_method: "crypto_erase".to_string(),
        removed_at: "2026-04-26T22:11:30Z".to_string(),
        artifact_hash: "sha256:fake".to_string(),
    };
    let mismatch_err = reg
        .record_recall_receipt("QO-RECALL-001", bogus_receipt)
        .expect_err("mismatched recall_id rejected");
    assert!(
        mismatch_err.code.contains("RECALL_RECEIPT_MISMATCH"),
        "expected RECEIPT_MISMATCH, got {mismatch_err:?}"
    );
    h.log_phase(
        "mismatched_recall_id_rejected",
        true,
        json!({"code": mismatch_err.code}),
    );

    // ── ACT: real receipts from two nodes ───────────────────────────
    for node in ["node-a", "node-b"] {
        let receipt = RecallReceipt {
            node_id: node.to_string(),
            recall_id: "RC-001".to_string(),
            removed: true,
            removal_method: "crypto_erase".to_string(),
            removed_at: "2026-04-26T22:11:45Z".to_string(),
            artifact_hash: format!("sha256:{node}-removed"),
        };
        reg.record_recall_receipt("QO-RECALL-001", receipt)
            .expect("receipt accepted");
    }
    let pct = reg.recall_completion_pct("QO-RECALL-001", 2);
    assert!(
        (pct - 100.0).abs() < f64::EPSILON,
        "completion pct must be 100.0% with 2/2 receipts, got {pct}"
    );
    h.log_phase("receipts_recorded", true, json!({"completion_pct": pct}));

    // ── ACT: complete_recall ────────────────────────────────────────
    reg.complete_recall("QO-RECALL-001", "2026-04-26T22:12:00Z")
        .expect("complete_recall");
    let r = reg.get_record("QO-RECALL-001").expect("record");
    assert_eq!(r.state, QuarantineState::RecallCompleted);
    assert_eq!(reg.total_recalls(), 1);
    assert!(
        !reg.is_quarantined(extension_id),
        "recalled extension must no longer report active quarantine"
    );
    h.log_phase("recall_completed", true, json!({"total_recalls": 1}));

    // ── ASSERT: integrity holds across the full recall path ─────────
    assert!(reg.verify_audit_integrity().expect("verify"));
    h.log_phase("audit_integrity_after_recall", true, json!({}));
}

#[test]
fn e2e_quarantine_rejects_duplicate_order_and_invalid_transition() {
    let h = Harness::new("e2e_quarantine_rejects_duplicate_order_and_invalid_transition");

    let mut reg = QuarantineRegistry::new();

    // ── Initiate one order, then attempt a duplicate order_id ───────
    reg.initiate_quarantine(order(
        "QO-DUP",
        "npm:@e2e/dup-pkg",
        QuarantineSeverity::Medium,
        "2026-04-26T22:20:00Z",
    ))
    .expect("first initiate");

    // Duplicate must be rejected.
    let dup_err = reg
        .initiate_quarantine(order(
            "QO-DUP",
            "npm:@e2e/some-other-pkg",
            QuarantineSeverity::Medium,
            "2026-04-26T22:20:01Z",
        ))
        .expect_err("duplicate order_id rejected");
    assert!(
        dup_err.code.contains("DUPLICATE_ORDER_ID"),
        "expected DUPLICATE_ORDER_ID, got {dup_err:?}"
    );
    h.log_phase(
        "duplicate_order_rejected",
        true,
        json!({"code": dup_err.code}),
    );

    // ── start_drain before enforce → INVALID_TRANSITION ─────────────
    reg.initiate_quarantine(order(
        "QO-TRANS",
        "npm:@e2e/transition-pkg",
        QuarantineSeverity::Medium,
        "2026-04-26T22:20:10Z",
    ))
    .expect("init for transition test");
    // (Skip enforce.)
    let trans_err = reg
        .start_drain("QO-TRANS", "2026-04-26T22:20:11Z")
        .expect_err("start_drain before enforce rejected");
    assert!(
        trans_err.code.contains("INVALID_TRANSITION"),
        "expected INVALID_TRANSITION, got {trans_err:?}"
    );
    h.log_phase(
        "invalid_transition_rejected",
        true,
        json!({"code": trans_err.code}),
    );

    // ── Already-active extension cannot be re-quarantined ───────────
    let already_err = reg
        .initiate_quarantine(order(
            "QO-DUP-EXT",
            "npm:@e2e/dup-pkg",
            QuarantineSeverity::Low,
            "2026-04-26T22:20:20Z",
        ))
        .expect_err("re-quarantining same extension rejected");
    assert!(
        already_err.code.contains("ALREADY_ACTIVE"),
        "expected ALREADY_ACTIVE, got {already_err:?}"
    );
    h.log_phase(
        "already_active_extension_rejected",
        true,
        json!({"code": already_err.code}),
    );
}
