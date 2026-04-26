//! Mock-free end-to-end test for the control-plane epoch state machine.
//!
//! Drives the public surface of
//! `frankenengine_node::control_plane::control_epoch` through the full
//! invariant matrix:
//!
//!   - INV-EPOCH-MONOTONIC      `epoch_advance` only ever increases the epoch
//!   - INV-EPOCH-NO-GAP         `epoch_advance` advances by exactly +1
//!   - INV-EPOCH-SIGNED-EVENT   every `EpochTransition.verify()` returns true
//!   - INV-EPOCH-DURABLE        `recover(committed)` round-trips state across
//!                              a simulated restart
//!   - epoch_set: regression to `<= current` is rejected with
//!                `EpochError::EpochRegression`
//!   - manifest_hash empty/whitespace → `EpochError::InvalidManifestHash`
//!   - check_artifact_epoch matrix:
//!       * current epoch         → accepted
//!       * within max_lookback   → accepted
//!       * future epoch          → rejected `FutureEpoch`
//!       * older than lookback   → rejected `ExpiredEpoch`
//!       * empty artifact_id     → rejected `InvalidArtifactId`
//!       * reserved "<unknown>"  → rejected `InvalidArtifactId`
//!       * null byte in id       → rejected `InvalidArtifactId`
//!       * leading slash in id   → rejected `InvalidArtifactId`
//!       * ../ traversal in id   → rejected `InvalidArtifactId`
//!
//! Bead: bd-2xm9v.
//!
//! No mocks: real `EpochStore`, real SHA-256-backed MAC on every transition,
//! real `ValidityWindowPolicy`. Each phase emits a structured tracing event
//! plus a JSON-line on stderr so a CI failure can be reconstructed from the
//! test transcript alone.

use std::sync::Once;
use std::time::Instant;

use frankenengine_node::control_plane::control_epoch::{
    ControlEpoch, EpochError, EpochRejectionReason, EpochStore, ValidityWindowPolicy,
    check_artifact_epoch,
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

#[test]
fn e2e_epoch_store_full_lifecycle_advance_set_recover() {
    let h = Harness::new("e2e_epoch_store_full_lifecycle_advance_set_recover");

    // ── ARRANGE: real store at genesis ──────────────────────────────
    let mut store = EpochStore::new();
    assert_eq!(store.epoch_read(), ControlEpoch::GENESIS);
    assert_eq!(store.committed_epoch(), ControlEpoch::GENESIS);
    assert_eq!(store.transition_count(), 0);
    h.log_phase("genesis", true, json!({"epoch": 0u64}));

    // ── ACT: advance by 1, twice — INV-EPOCH-MONOTONIC + INV-EPOCH-NO-GAP
    let t1 = store
        .epoch_advance("sha256:manifest-001", 1_745_750_000, "trace-adv-1")
        .expect("advance to 1");
    assert_eq!(t1.old_epoch, ControlEpoch::GENESIS);
    assert_eq!(t1.new_epoch, ControlEpoch::new(1));
    assert!(
        t1.verify(),
        "INV-EPOCH-SIGNED-EVENT: MAC must verify on the issued transition"
    );
    h.log_phase("advance_to_1", true, json!({"mac_ok": true}));

    let t2 = store
        .epoch_advance("sha256:manifest-002", 1_745_750_010, "trace-adv-2")
        .expect("advance to 2");
    assert_eq!(t2.old_epoch, ControlEpoch::new(1));
    assert_eq!(t2.new_epoch, ControlEpoch::new(2));
    assert!(t2.verify());
    assert_eq!(store.epoch_read(), ControlEpoch::new(2));
    assert_eq!(store.committed_epoch(), ControlEpoch::new(2));
    assert_eq!(store.transition_count(), 2);
    h.log_phase(
        "advance_to_2",
        true,
        json!({"history": store.transition_count()}),
    );

    // ── ASSERT: empty manifest_hash is rejected ─────────────────────
    let bad_manifest = store.epoch_advance("", 1_745_750_020, "trace-bad");
    match bad_manifest {
        Err(EpochError::InvalidManifestHash { reason }) => {
            assert!(reason.contains("empty") || reason.contains("whitespace"));
            h.log_phase(
                "empty_manifest_rejected",
                true,
                json!({"reason": reason}),
            );
        }
        other => panic!("expected InvalidManifestHash, got {other:?}"),
    }
    // Rejection must NOT advance the epoch.
    assert_eq!(store.epoch_read(), ControlEpoch::new(2));

    // ── ACT: epoch_set jumps forward (skips ahead) ──────────────────
    let t10 = store
        .epoch_set(
            10,
            "sha256:manifest-jump",
            1_745_750_030,
            "trace-jump",
        )
        .expect("jump to 10");
    assert_eq!(t10.old_epoch, ControlEpoch::new(2));
    assert_eq!(t10.new_epoch, ControlEpoch::new(10));
    assert!(t10.verify());
    assert_eq!(store.epoch_read(), ControlEpoch::new(10));
    h.log_phase("epoch_set_jump", true, json!({"new_epoch": 10}));

    // ── ASSERT: regression rejected ─────────────────────────────────
    let regression = store.epoch_set(
        9,
        "sha256:manifest-regress",
        1_745_750_040,
        "trace-regress",
    );
    match regression {
        Err(EpochError::EpochRegression { current, attempted }) => {
            assert_eq!(current, ControlEpoch::new(10));
            assert_eq!(attempted, ControlEpoch::new(9));
            h.log_phase("regression_rejected", true, json!({"current": 10, "attempted": 9}));
        }
        other => panic!("expected EpochRegression, got {other:?}"),
    }
    // Equal-to-current is also a regression.
    let equal = store.epoch_set(
        10,
        "sha256:manifest-eq",
        1_745_750_050,
        "trace-eq",
    );
    assert!(matches!(equal, Err(EpochError::EpochRegression { .. })));
    assert_eq!(store.epoch_read(), ControlEpoch::new(10));
    h.log_phase("equal_rejected", true, json!({}));

    // ── ASSERT: INV-EPOCH-DURABLE — recover sees committed epoch ────
    let committed = store.committed_epoch();
    let recovered = EpochStore::recover(committed.value());
    assert_eq!(recovered.epoch_read(), committed);
    assert_eq!(recovered.committed_epoch(), committed);
    h.log_phase(
        "durable_recover",
        true,
        json!({"committed": committed.value()}),
    );

    // ── ASSERT: every transition still self-verifies ────────────────
    for t in store.transitions() {
        assert!(t.verify(), "transition MAC must verify: {t:?}");
    }
    h.log_phase("all_macs_verify", true, json!({"count": store.transition_count()}));
}

#[test]
fn e2e_epoch_store_advance_overflow_is_fail_closed() {
    let h = Harness::new("e2e_epoch_store_advance_overflow_is_fail_closed");

    // Recover into a store at the u64 ceiling — the next advance must overflow.
    let mut store = EpochStore::recover(u64::MAX);
    assert_eq!(store.epoch_read().value(), u64::MAX);
    let err = store
        .epoch_advance("sha256:overflow", 0, "trace-overflow")
        .expect_err("u64::MAX advance must overflow");
    match err {
        EpochError::EpochOverflow { current } => {
            assert_eq!(current.value(), u64::MAX);
            h.log_phase("overflow_rejected", true, json!({"current": u64::MAX}));
        }
        other => panic!("expected EpochOverflow, got {other:?}"),
    }
    // Epoch must NOT advance after overflow rejection.
    assert_eq!(store.epoch_read().value(), u64::MAX);
}

#[test]
fn e2e_check_artifact_epoch_full_validity_window_matrix() {
    let h = Harness::new("e2e_check_artifact_epoch_full_validity_window_matrix");

    // Window: current=10, max_lookback=2 → accept [8, 10].
    let policy = ValidityWindowPolicy::new(ControlEpoch::new(10), 2);
    assert_eq!(policy.min_accepted_epoch(), ControlEpoch::new(8));
    h.log_phase(
        "policy_built",
        true,
        json!({"current": 10, "max_lookback": 2, "min_accepted": 8}),
    );

    // ── HAPPY PATH: current epoch accepted ─────────────────────────
    check_artifact_epoch(
        "art-current",
        ControlEpoch::new(10),
        &policy,
        "trace-current",
    )
    .expect("current epoch accepted");
    h.log_phase("current_accepted", true, json!({}));

    // ── HAPPY PATH: within lookback accepted ───────────────────────
    check_artifact_epoch(
        "art-lookback-edge",
        ControlEpoch::new(8),
        &policy,
        "trace-lookback",
    )
    .expect("min accepted epoch is on the boundary");
    h.log_phase("lookback_edge_accepted", true, json!({}));

    // ── REJECT: future epoch ────────────────────────────────────────
    let future = check_artifact_epoch(
        "art-future",
        ControlEpoch::new(11),
        &policy,
        "trace-future",
    )
    .expect_err("future epoch rejected");
    assert!(matches!(
        future.rejection_reason,
        EpochRejectionReason::FutureEpoch
    ));
    assert_eq!(future.code(), "EPOCH_REJECT_FUTURE");
    h.log_phase("future_rejected", true, json!({"code": future.code()}));

    // ── REJECT: expired epoch ───────────────────────────────────────
    let expired = check_artifact_epoch(
        "art-expired",
        ControlEpoch::new(7),
        &policy,
        "trace-expired",
    )
    .expect_err("expired epoch rejected");
    assert!(matches!(
        expired.rejection_reason,
        EpochRejectionReason::ExpiredEpoch
    ));
    assert_eq!(expired.code(), "EPOCH_REJECT_EXPIRED");
    h.log_phase("expired_rejected", true, json!({"code": expired.code()}));

    // ── REJECT: invalid artifact_id (empty) ─────────────────────────
    let empty = check_artifact_epoch("", ControlEpoch::new(10), &policy, "trace-empty")
        .expect_err("empty artifact_id rejected");
    assert!(matches!(
        empty.rejection_reason,
        EpochRejectionReason::InvalidArtifactId
    ));
    assert_eq!(empty.code(), "EPOCH_REJECT_INVALID_ARTIFACT_ID");
    h.log_phase("empty_artifact_rejected", true, json!({}));

    // ── REJECT: reserved "<unknown>" sentinel ───────────────────────
    let reserved = check_artifact_epoch(
        "<unknown>",
        ControlEpoch::new(10),
        &policy,
        "trace-reserved",
    )
    .expect_err("reserved artifact_id rejected");
    assert!(matches!(
        reserved.rejection_reason,
        EpochRejectionReason::InvalidArtifactId
    ));
    h.log_phase("reserved_artifact_rejected", true, json!({}));

    // ── REJECT: leading whitespace ──────────────────────────────────
    let whitespace = check_artifact_epoch(
        " art-leading-space",
        ControlEpoch::new(10),
        &policy,
        "trace-ws",
    )
    .expect_err("leading-whitespace artifact_id rejected");
    assert!(matches!(
        whitespace.rejection_reason,
        EpochRejectionReason::InvalidArtifactId
    ));
    h.log_phase("whitespace_artifact_rejected", true, json!({}));

    // ── REJECT: null byte ───────────────────────────────────────────
    let null = check_artifact_epoch(
        "art-with-\0null",
        ControlEpoch::new(10),
        &policy,
        "trace-null",
    )
    .expect_err("null-byte artifact_id rejected");
    assert!(matches!(
        null.rejection_reason,
        EpochRejectionReason::InvalidArtifactId
    ));
    h.log_phase("null_byte_rejected", true, json!({}));

    // ── REJECT: leading slash ───────────────────────────────────────
    let slash = check_artifact_epoch(
        "/abs/path",
        ControlEpoch::new(10),
        &policy,
        "trace-slash",
    )
    .expect_err("absolute artifact_id rejected");
    assert!(matches!(
        slash.rejection_reason,
        EpochRejectionReason::InvalidArtifactId
    ));
    h.log_phase("absolute_path_rejected", true, json!({}));

    // ── REJECT: ../ traversal ───────────────────────────────────────
    let traversal = check_artifact_epoch(
        "ok/../bad",
        ControlEpoch::new(10),
        &policy,
        "trace-traversal",
    )
    .expect_err("traversal artifact_id rejected");
    assert!(matches!(
        traversal.rejection_reason,
        EpochRejectionReason::InvalidArtifactId
    ));
    h.log_phase("traversal_rejected", true, json!({}));

    // ── REJECT: backslash ───────────────────────────────────────────
    let backslash = check_artifact_epoch(
        "evil\\backslash",
        ControlEpoch::new(10),
        &policy,
        "trace-backslash",
    )
    .expect_err("backslash artifact_id rejected");
    assert!(matches!(
        backslash.rejection_reason,
        EpochRejectionReason::InvalidArtifactId
    ));
    h.log_phase("backslash_rejected", true, json!({}));

    // ── ASSERT: rejection ordering — invalid artifact_id wins over future
    let priority = check_artifact_epoch(
        "",                       // invalid id
        ControlEpoch::new(99),    // also future
        &policy,
        "trace-priority",
    )
    .expect_err("invalid id checked before future epoch");
    assert!(matches!(
        priority.rejection_reason,
        EpochRejectionReason::InvalidArtifactId
    ));
    h.log_phase("invalid_id_wins_over_future", true, json!({}));
}

#[test]
fn e2e_check_artifact_epoch_at_genesis_zero_lookback() {
    let h = Harness::new("e2e_check_artifact_epoch_at_genesis_zero_lookback");

    // Genesis with zero lookback: ONLY epoch 0 is accepted.
    let policy = ValidityWindowPolicy::new(ControlEpoch::GENESIS, 0);
    assert_eq!(policy.min_accepted_epoch(), ControlEpoch::GENESIS);

    check_artifact_epoch(
        "art-genesis",
        ControlEpoch::GENESIS,
        &policy,
        "trace-gen",
    )
    .expect("genesis itself is accepted under zero-lookback policy");
    h.log_phase("genesis_accepted", true, json!({}));

    let any_future = check_artifact_epoch(
        "art-anything",
        ControlEpoch::new(1),
        &policy,
        "trace-future-1",
    )
    .expect_err("any non-genesis epoch is future under zero-lookback at genesis");
    assert!(matches!(
        any_future.rejection_reason,
        EpochRejectionReason::FutureEpoch
    ));
    h.log_phase("epoch_1_rejected_as_future", true, json!({}));
}
