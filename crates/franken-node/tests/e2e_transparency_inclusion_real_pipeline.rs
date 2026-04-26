//! Mock-free end-to-end test for the transparency-log inclusion pipeline.
//!
//! Exercises the full public surface of
//! `frankenengine_node::supply_chain::transparency_verifier` against a real
//! Merkle tree built from `leaf_hash` and validated through `verify_inclusion`.
//! No mocks, no test fixtures from production code (bd-2nrre): the proofs are
//! constructed on the fly using only the public API and verified through the
//! same path connector install/update would take.
//!
//! Bead: bd-fepag.
//!
//! Coverage targets every `ProofFailure` variant plus the success path:
//!   - missing required proof   → `ProofFailure::ProofMissing`
//!   - tampered leaf_hash       → `ProofFailure::LeafMismatch`
//!   - bad metadata bounds      → `ProofFailure::PathInvalid`
//!   - unpinned root            → `ProofFailure::RootNotPinned`
//!   - empty/whitespace ids     → `ProofFailure::InvalidArtifactId / InvalidConnectorId`
//!   - valid proof, single leaf → verified=true
//!   - valid proof, multi-leaf  → all proofs verify against the same root
//!
//! Each phase emits a structured tracing event AND a JSON-line on stderr so a
//! CI failure can be reconstructed from the test transcript alone.

use std::sync::Once;
use std::time::Instant;

use frankenengine_node::supply_chain::transparency_verifier::{
    InclusionProof, LogRoot, ProofFailure, ProofReceipt, TransparencyPolicy, leaf_hash,
    recompute_root, verify_inclusion,
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

/// Build a real Merkle inclusion proof set using only the public API.
///
/// Tree topology (size 4, balanced binary):
///   root
///   ├── n01 = pair(L0, L1)
///   │   ├── L0 = leaf_hash(items[0])
///   │   └── L1 = leaf_hash(items[1])
///   └── n23 = pair(L2, L3)
///       ├── L2 = leaf_hash(items[2])
///       └── L3 = leaf_hash(items[3])
///
/// We never call the private `hash_pair`; we recover the canonical pair hash by
/// running `recompute_root` over a 1-deep proof and treating the resulting root
/// as the parent. This is the same primitive `verify_inclusion` uses, so by
/// construction the proofs we emit are accepted by the verifier.
fn build_balanced_proofs(items: &[&str]) -> (String, Vec<InclusionProof>) {
    assert_eq!(items.len(), 4, "balanced helper handles size-4 trees only");

    let leaves: Vec<String> = items.iter().map(|s| leaf_hash(s)).collect();

    // Pair hashes via recompute_root (level 1 of the tree).
    let pair = |left: &str, right: &str| -> String {
        let depth_one = InclusionProof {
            leaf_index: 0,
            tree_size: 2,
            leaf_hash: left.to_string(),
            audit_path: vec![right.to_string()],
        };
        recompute_root(&depth_one)
    };

    let n01 = pair(&leaves[0], &leaves[1]);
    let n23 = pair(&leaves[2], &leaves[3]);
    // Root via another size-2 proof, this time treating the inner nodes as leaves.
    let root = {
        let p = InclusionProof {
            leaf_index: 0,
            tree_size: 2,
            leaf_hash: n01.clone(),
            audit_path: vec![n23.clone()],
        };
        recompute_root(&p)
    };

    let proofs = vec![
        InclusionProof {
            leaf_index: 0,
            tree_size: 4,
            leaf_hash: leaves[0].clone(),
            audit_path: vec![leaves[1].clone(), n23.clone()],
        },
        InclusionProof {
            leaf_index: 1,
            tree_size: 4,
            leaf_hash: leaves[1].clone(),
            audit_path: vec![leaves[0].clone(), n23.clone()],
        },
        InclusionProof {
            leaf_index: 2,
            tree_size: 4,
            leaf_hash: leaves[2].clone(),
            audit_path: vec![leaves[3].clone(), n01.clone()],
        },
        InclusionProof {
            leaf_index: 3,
            tree_size: 4,
            leaf_hash: leaves[3].clone(),
            audit_path: vec![leaves[2].clone(), n01.clone()],
        },
    ];

    (root, proofs)
}

fn pinned_policy(root: &str, tree_size: u64) -> TransparencyPolicy {
    TransparencyPolicy {
        required: true,
        pinned_roots: vec![LogRoot {
            tree_size,
            root_hash: root.to_string(),
        }],
    }
}

fn assert_failure(receipt: &ProofReceipt, want: &ProofFailure) {
    assert!(
        !receipt.verified,
        "expected failure receipt, got verified=true: {receipt:?}"
    );
    assert!(
        !receipt.proof_valid,
        "expected proof_valid=false, got: {receipt:?}"
    );
    assert!(
        !receipt.log_root_matched,
        "expected log_root_matched=false, got: {receipt:?}"
    );
    assert_eq!(
        receipt.failure_reason.as_ref(),
        Some(want),
        "wrong failure reason: {receipt:?}"
    );
}

#[test]
fn e2e_transparency_inclusion_real_pipeline_full_coverage() {
    let h = Harness::new("e2e_transparency_inclusion_real_pipeline_full_coverage");

    // ── ARRANGE ────────────────────────────────────────────────────
    let artifacts = ["sha256:art-alpha", "sha256:art-bravo", "sha256:art-charlie", "sha256:art-delta"];
    let (root, proofs) = build_balanced_proofs(&artifacts);
    h.log_phase(
        "tree_built",
        true,
        json!({
            "tree_size": 4u64,
            "root_hash": root,
            "leaf_hashes": proofs.iter().map(|p| &p.leaf_hash).collect::<Vec<_>>(),
        }),
    );

    let policy = pinned_policy(&root, 4);

    // ── ACT + ASSERT: success path for every leaf ──────────────────
    for proof in &proofs {
        let receipt = verify_inclusion(
            &policy,
            Some(proof),
            &proof.leaf_hash,
            "conn-real-1",
            "art-real-1",
            "trace-success",
            "2026-04-26T22:00:00Z",
        );
        assert!(
            receipt.verified && receipt.proof_valid && receipt.log_root_matched,
            "expected verified receipt for leaf {}, got {receipt:?}",
            proof.leaf_index
        );
        assert!(receipt.failure_reason.is_none());
        h.log_phase(
            "verify_success",
            true,
            json!({"leaf_index": proof.leaf_index, "trace_id": receipt.trace_id}),
        );
    }

    // ── ACT + ASSERT: ProofMissing when policy.required and no proof ─
    let missing = verify_inclusion(
        &policy,
        None,
        &proofs[0].leaf_hash,
        "conn-real-1",
        "art-real-1",
        "trace-missing",
        "2026-04-26T22:00:01Z",
    );
    assert_failure(&missing, &ProofFailure::ProofMissing);
    h.log_phase("verify_missing_rejected", true, json!({"trace": missing.trace_id}));

    // ── ACT + ASSERT: ProofMissing-not-required → passes through ───
    let optional_policy = TransparencyPolicy {
        required: false,
        pinned_roots: vec![],
    };
    let optional = verify_inclusion(
        &optional_policy,
        None,
        &proofs[0].leaf_hash,
        "conn-real-1",
        "art-real-1",
        "trace-optional",
        "2026-04-26T22:00:02Z",
    );
    assert!(
        optional.verified && optional.proof_valid,
        "optional policy should accept missing proof: {optional:?}"
    );
    h.log_phase("optional_pass_through", true, json!({}));

    // ── ACT + ASSERT: LeafMismatch when artifact_hash diverges ─────
    let leaf_mismatch = verify_inclusion(
        &policy,
        Some(&proofs[0]),
        "sha256:not-the-leaf",
        "conn-real-1",
        "art-real-1",
        "trace-leaf-mismatch",
        "2026-04-26T22:00:03Z",
    );
    assert_failure(
        &leaf_mismatch,
        &ProofFailure::LeafMismatch {
            expected: "sha256:not-the-leaf".into(),
            actual: proofs[0].leaf_hash.clone(),
        },
    );
    h.log_phase("verify_leaf_mismatch", true, json!({}));

    // ── ACT + ASSERT: PathInvalid when leaf_index >= tree_size ─────
    let oob = InclusionProof {
        leaf_index: 99,
        tree_size: 4,
        leaf_hash: proofs[0].leaf_hash.clone(),
        audit_path: proofs[0].audit_path.clone(),
    };
    let path_invalid = verify_inclusion(
        &policy,
        Some(&oob),
        &proofs[0].leaf_hash,
        "conn-real-1",
        "art-real-1",
        "trace-path-invalid",
        "2026-04-26T22:00:04Z",
    );
    match path_invalid.failure_reason.as_ref() {
        Some(ProofFailure::PathInvalid { .. }) => {
            h.log_phase("verify_path_invalid", true, json!({}));
        }
        other => panic!("expected PathInvalid, got {other:?}"),
    }
    assert!(!path_invalid.verified);

    // ── ACT + ASSERT: RootNotPinned when policy roots empty ────────
    let unpinned_policy = TransparencyPolicy {
        required: true,
        pinned_roots: vec![],
    };
    let not_pinned = verify_inclusion(
        &unpinned_policy,
        Some(&proofs[0]),
        &proofs[0].leaf_hash,
        "conn-real-1",
        "art-real-1",
        "trace-not-pinned",
        "2026-04-26T22:00:05Z",
    );
    match not_pinned.failure_reason.as_ref() {
        Some(ProofFailure::RootNotPinned { root_hash }) => {
            assert_eq!(root_hash, &root, "computed root should be reported");
            h.log_phase("verify_root_not_pinned", true, json!({"root": root_hash}));
        }
        other => panic!("expected RootNotPinned, got {other:?}"),
    }
    assert!(!not_pinned.verified);

    // ── ACT + ASSERT: PathInvalid surfaces tampered audit_path ────
    let mut tampered = proofs[0].clone();
    // Flip a single hex digit in the sibling, preserving length so length-prefix
    // hash framing still parses but the recomputed root diverges from the pin.
    let mut sibling: Vec<char> = tampered.audit_path[0].chars().collect();
    sibling[0] = if sibling[0] == '0' { '1' } else { '0' };
    tampered.audit_path[0] = sibling.into_iter().collect();
    let tampered_receipt = verify_inclusion(
        &policy,
        Some(&tampered),
        &tampered.leaf_hash,
        "conn-real-1",
        "art-real-1",
        "trace-tampered",
        "2026-04-26T22:00:06Z",
    );
    // A tampered audit path produces a recomputed root that is not pinned.
    match tampered_receipt.failure_reason.as_ref() {
        Some(ProofFailure::RootNotPinned { .. }) => {
            h.log_phase("verify_tampered_path", true, json!({}));
        }
        other => panic!("expected RootNotPinned for tampered audit path, got {other:?}"),
    }
    assert!(!tampered_receipt.verified);

    // ── ACT + ASSERT: InvalidArtifactId when id is whitespace ──────
    let bad_artifact = verify_inclusion(
        &policy,
        Some(&proofs[0]),
        &proofs[0].leaf_hash,
        "conn-real-1",
        "  ",
        "trace-bad-art",
        "2026-04-26T22:00:07Z",
    );
    match bad_artifact.failure_reason.as_ref() {
        Some(ProofFailure::InvalidArtifactId { reason }) => {
            assert!(reason.contains("empty") || reason.contains("whitespace"));
            h.log_phase("verify_bad_artifact_id", true, json!({"reason": reason}));
        }
        other => panic!("expected InvalidArtifactId, got {other:?}"),
    }

    // ── ACT + ASSERT: InvalidConnectorId when id has null byte ─────
    let bad_connector = verify_inclusion(
        &policy,
        Some(&proofs[0]),
        &proofs[0].leaf_hash,
        "conn-with-\0null",
        "art-real-1",
        "trace-bad-conn",
        "2026-04-26T22:00:08Z",
    );
    match bad_connector.failure_reason.as_ref() {
        Some(ProofFailure::InvalidConnectorId { reason }) => {
            assert!(reason.contains("null"));
            h.log_phase("verify_bad_connector_id", true, json!({"reason": reason}));
        }
        other => panic!("expected InvalidConnectorId, got {other:?}"),
    }

    h.log_phase("teardown", true, json!({}));
}

#[test]
fn e2e_transparency_inclusion_single_leaf_tree_round_trip() {
    let h = Harness::new("e2e_transparency_inclusion_single_leaf_tree_round_trip");

    // Size-1 tree: the leaf hash is the root and the audit path is empty.
    // This exercises the boundary the size-4 helper does not reach.
    let leaf = leaf_hash("sha256:lonely-artifact");
    let proof = InclusionProof {
        leaf_index: 0,
        tree_size: 1,
        leaf_hash: leaf.clone(),
        audit_path: vec![],
    };
    let computed = recompute_root(&proof);
    assert_eq!(computed, leaf, "size-1 root must equal its only leaf");
    h.log_phase(
        "size1_tree_built",
        true,
        json!({"root": computed, "leaf": leaf}),
    );

    let policy = pinned_policy(&computed, 1);
    let receipt = verify_inclusion(
        &policy,
        Some(&proof),
        &leaf,
        "conn-singleton",
        "art-singleton",
        "trace-singleton",
        "2026-04-26T22:00:09Z",
    );
    assert!(
        receipt.verified && receipt.proof_valid && receipt.log_root_matched,
        "singleton-tree proof must verify: {receipt:?}"
    );
    h.log_phase("size1_verified", true, json!({"trace": receipt.trace_id}));

    // Negative: a singleton policy must still reject a proof with an off-by-one
    // tree_size, because pinning binds (tree_size, root_hash) jointly.
    let off_by_one = InclusionProof {
        tree_size: 2,
        ..proof.clone()
    };
    let off_receipt = verify_inclusion(
        &policy,
        Some(&off_by_one),
        &leaf,
        "conn-singleton",
        "art-singleton",
        "trace-singleton-off",
        "2026-04-26T22:00:10Z",
    );
    assert!(
        !off_receipt.verified,
        "joint (tree_size, root) pin must reject mismatched size: {off_receipt:?}"
    );
    h.log_phase("size_size_pin_enforced", true, json!({}));
}
