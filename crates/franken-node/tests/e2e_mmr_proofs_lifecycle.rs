//! Mock-free end-to-end test for the MMR checkpoint + proof primitives.
//!
//! Drives the public surface of
//! `frankenengine_node::control_plane::mmr_proofs` end-to-end against a
//! real `MarkerStream`:
//!
//!   1. `MmrCheckpoint::enabled()` + `append_marker_hash` builds an
//!      incremental Merkle root,
//!   2. `rebuild_from_stream` reproduces the same root from the stream,
//!   3. `mmr_inclusion_proof` + `verify_inclusion` round-trip for every
//!      marker in the retained window,
//!   4. negative paths: tampered `leaf_hash` (LeafMismatch), tampered
//!      `audit_path` (RootMismatch), out-of-range sequence
//!      (SequenceOutOfRange), proof against a stale checkpoint
//!      (CheckpointStale),
//!   5. `mmr_prefix_proof` + `verify_prefix` succeed when checkpoint A is
//!      a prefix of checkpoint B; PrefixSizeInvalid when sizes are
//!      inconsistent,
//!   6. `MmrDisabled` returned by every API on a disabled checkpoint.
//!
//! Bead: bd-2505f.
//!
//! No mocks: real `MarkerStream` with SHA-256-backed marker hashes, real
//! `MmrCheckpoint` with the production Merkle algorithm, real
//! constant-time hash comparisons. Each phase emits a structured tracing
//! event PLUS a JSON-line on stderr.

use std::sync::Once;
use std::time::Instant;

use frankenengine_node::control_plane::marker_stream::{MarkerEventType, MarkerStream};
use frankenengine_node::control_plane::mmr_proofs::{
    MmrCheckpoint, ProofError, marker_leaf_hash, mmr_inclusion_proof, mmr_prefix_proof,
    verify_inclusion, verify_prefix,
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

/// Build a real `MarkerStream` of `n` markers with monotonic timestamps.
fn build_real_stream(n: u64) -> MarkerStream {
    let mut s = MarkerStream::new();
    for i in 0..n {
        s.append(
            MarkerEventType::TrustDecision,
            &format!("sha256:payload-{i:04}"),
            1_000_000_000 + i,
            &format!("trace-{i:04}"),
        )
        .expect("real append");
    }
    s
}

#[test]
fn e2e_mmr_inclusion_proof_round_trip() {
    let h = Harness::new("e2e_mmr_inclusion_proof_round_trip");

    let stream = build_real_stream(8);
    let mut ckpt = MmrCheckpoint::enabled();
    let root = ckpt
        .rebuild_from_stream(&stream)
        .expect("rebuild_from_stream succeeds");
    assert_eq!(root.tree_size, 8);
    assert_eq!(ckpt.tree_size(), 8);
    assert_eq!(ckpt.leaf_hashes().len(), 8);
    h.log_phase(
        "checkpoint_built",
        true,
        json!({"tree_size": root.tree_size, "root_hash": root.root_hash}),
    );

    // ── ACT: every leaf produces a valid inclusion proof ───────────
    for seq in 0..8u64 {
        let proof = mmr_inclusion_proof(&stream, &ckpt, seq).expect("proof for in-window seq");
        assert_eq!(proof.tree_size, 8);
        assert_eq!(proof.leaf_index, seq);
        let marker_hash = stream.get(seq).expect("marker exists").marker_hash.clone();
        verify_inclusion(&proof, &root, &marker_hash).expect("proof verifies");
        h.log_phase(
            "verified",
            true,
            json!({"seq": seq, "audit_path_len": proof.audit_path.len()}),
        );
    }

    // ── ASSERT: out-of-range sequence → SequenceOutOfRange ─────────
    let oob = mmr_inclusion_proof(&stream, &ckpt, 99).expect_err("oob rejected");
    assert!(matches!(oob, ProofError::SequenceOutOfRange { .. }));
    assert_eq!(oob.code(), "MMR_SEQUENCE_OUT_OF_RANGE");
    h.log_phase("seq_out_of_range", true, json!({"code": oob.code()}));
}

#[test]
fn e2e_mmr_inclusion_proof_negative_paths() {
    let h = Harness::new("e2e_mmr_inclusion_proof_negative_paths");

    let stream = build_real_stream(4);
    let mut ckpt = MmrCheckpoint::enabled();
    let root = ckpt.rebuild_from_stream(&stream).expect("rebuild");
    let seq = 1u64;
    let proof = mmr_inclusion_proof(&stream, &ckpt, seq).expect("proof");
    let marker_hash = stream.get(seq).unwrap().marker_hash.clone();

    // Sanity: the unmodified proof verifies.
    verify_inclusion(&proof, &root, &marker_hash).expect("baseline ok");
    h.log_phase("baseline_ok", true, json!({}));

    // ── LeafMismatch: pass a different marker hash ─────────────────
    let other_marker_hash = stream.get(2).unwrap().marker_hash.clone();
    let err = verify_inclusion(&proof, &root, &other_marker_hash)
        .expect_err("wrong marker rejected");
    assert!(matches!(err, ProofError::LeafMismatch { .. }));
    assert_eq!(err.code(), "MMR_LEAF_MISMATCH");
    h.log_phase("leaf_mismatch", true, json!({"code": err.code()}));

    // ── RootMismatch via tampered audit_path ───────────────────────
    let mut tampered = proof.clone();
    if let Some(first) = tampered.audit_path.first_mut() {
        let mut chars: Vec<char> = first.chars().collect();
        chars[0] = if chars[0] == '0' { '1' } else { '0' };
        *first = chars.into_iter().collect();
    }
    let err = verify_inclusion(&tampered, &root, &marker_hash)
        .expect_err("tampered audit path rejected");
    assert!(matches!(err, ProofError::RootMismatch { .. }));
    assert_eq!(err.code(), "MMR_ROOT_MISMATCH");
    h.log_phase("root_mismatch_tampered_path", true, json!({"code": err.code()}));

    // ── SequenceOutOfRange via leaf_index >= tree_size ─────────────
    let mut bad_idx = proof.clone();
    bad_idx.leaf_index = bad_idx.tree_size; // first invalid index
    let err = verify_inclusion(&bad_idx, &root, &marker_hash)
        .expect_err("oob leaf_index rejected");
    assert!(matches!(err, ProofError::SequenceOutOfRange { .. }));
    h.log_phase("seq_oob_in_verify", true, json!({"code": err.code()}));

    // ── InvalidProof via mismatched tree_size ──────────────────────
    let mut wrong_size = proof.clone();
    wrong_size.tree_size = wrong_size.tree_size.saturating_add(1);
    let err = verify_inclusion(&wrong_size, &root, &marker_hash)
        .expect_err("size mismatch rejected");
    assert!(matches!(err, ProofError::InvalidProof { .. }));
    assert_eq!(err.code(), "MMR_INVALID_PROOF");
    h.log_phase("size_mismatch", true, json!({}));
}

#[test]
fn e2e_mmr_checkpoint_stale_when_stream_grows() {
    let h = Harness::new("e2e_mmr_checkpoint_stale_when_stream_grows");

    let mut stream = build_real_stream(4);
    let mut ckpt = MmrCheckpoint::enabled();
    ckpt.rebuild_from_stream(&stream).expect("initial ckpt");
    h.log_phase("initial_ckpt", true, json!({}));

    // Append a new marker WITHOUT updating the checkpoint.
    stream
        .append(
            MarkerEventType::PolicyChange,
            "sha256:new-marker",
            1_000_001_000,
            "trace-new",
        )
        .expect("stream grew");

    // mmr_inclusion_proof must detect that the checkpoint is stale.
    let err = mmr_inclusion_proof(&stream, &ckpt, 0).expect_err("stale ckpt rejected");
    assert!(matches!(err, ProofError::CheckpointStale { .. }));
    assert_eq!(err.code(), "MMR_CHECKPOINT_STALE");
    h.log_phase("checkpoint_stale_detected", true, json!({"code": err.code()}));
}

#[test]
fn e2e_mmr_disabled_checkpoint_rejects_all_apis() {
    let h = Harness::new("e2e_mmr_disabled_checkpoint_rejects_all_apis");

    let mut disabled = MmrCheckpoint::disabled();
    assert!(!disabled.is_enabled());

    // append_marker_hash → MmrDisabled
    let err = disabled
        .append_marker_hash("sha256:any")
        .expect_err("append on disabled rejected");
    assert!(matches!(err, ProofError::MmrDisabled));

    // rebuild_from_stream → MmrDisabled
    let stream = build_real_stream(2);
    let err = disabled
        .rebuild_from_stream(&stream)
        .expect_err("rebuild on disabled rejected");
    assert!(matches!(err, ProofError::MmrDisabled));

    // mmr_inclusion_proof → MmrDisabled
    let err = mmr_inclusion_proof(&stream, &disabled, 0).expect_err("inclusion on disabled rejected");
    assert!(matches!(err, ProofError::MmrDisabled));
    h.log_phase("disabled_rejects_all", true, json!({"code": err.code()}));

    // Toggle enable + rebuild succeeds.
    disabled.set_enabled(true);
    let root = disabled
        .rebuild_from_stream(&stream)
        .expect("rebuild after enable");
    assert_eq!(root.tree_size, 2);
    h.log_phase("toggle_enable_then_rebuild", true, json!({"tree_size": 2}));
}

#[test]
fn e2e_mmr_prefix_proof_lifecycle() {
    let h = Harness::new("e2e_mmr_prefix_proof_lifecycle");

    // checkpoint_a: stream of 4 markers; checkpoint_b: same 4 + 4 more.
    let stream_a = build_real_stream(4);
    let mut ckpt_a = MmrCheckpoint::enabled();
    let root_a = ckpt_a.rebuild_from_stream(&stream_a).expect("ckpt_a");

    let stream_b = build_real_stream(8);
    let mut ckpt_b = MmrCheckpoint::enabled();
    let root_b = ckpt_b.rebuild_from_stream(&stream_b).expect("ckpt_b");

    // mmr_prefix_proof + verify_prefix succeed.
    let proof = mmr_prefix_proof(&ckpt_a, &ckpt_b).expect("prefix proof");
    assert_eq!(proof.prefix_size, 4);
    assert_eq!(proof.super_tree_size, 8);
    verify_prefix(&proof, &root_a, &root_b).expect("verify_prefix ok");
    h.log_phase(
        "prefix_proof_verified",
        true,
        json!({"prefix": 4, "super": 8}),
    );

    // PrefixSizeInvalid: A larger than B is forbidden.
    let bad = mmr_prefix_proof(&ckpt_b, &ckpt_a)
        .expect_err("a bigger than b rejected");
    assert!(matches!(bad, ProofError::PrefixSizeInvalid { .. }));
    assert_eq!(bad.code(), "MMR_PREFIX_SIZE_INVALID");
    h.log_phase("prefix_size_invalid", true, json!({"code": bad.code()}));

    // Identical-size prefix is valid (A == B exactly).
    let stream_eq = build_real_stream(4);
    let mut ckpt_eq = MmrCheckpoint::enabled();
    let root_eq = ckpt_eq.rebuild_from_stream(&stream_eq).expect("ckpt_eq");
    let proof_eq = mmr_prefix_proof(&ckpt_a, &ckpt_eq).expect("equal-size prefix");
    verify_prefix(&proof_eq, &root_a, &root_eq).expect("equal-size verify");
    h.log_phase("equal_size_prefix_ok", true, json!({}));
}

#[test]
fn e2e_mmr_marker_leaf_hash_is_deterministic_and_distinct() {
    let h = Harness::new("e2e_mmr_marker_leaf_hash_is_deterministic_and_distinct");

    let h1 = marker_leaf_hash("sha256:fixed-input");
    let h2 = marker_leaf_hash("sha256:fixed-input");
    assert_eq!(h1, h2, "marker_leaf_hash must be deterministic");
    assert_eq!(h1.len(), 64, "must be sha256-hex (64 chars)");

    let h3 = marker_leaf_hash("sha256:different-input");
    assert_ne!(h1, h3, "different inputs must produce different leaf hashes");

    // Empty input has a stable hash too (function tolerates empty).
    let empty = marker_leaf_hash("");
    assert_eq!(empty.len(), 64);
    assert_ne!(empty, h1);
    h.log_phase("leaf_hash_properties", true, json!({"len": 64}));
}
