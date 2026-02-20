//! Conformance tests for bd-1dar: optional MMR checkpoints + proof APIs.
//!
//! Validates:
//! - inclusion proof generation/verification
//! - prefix proof generation/verification
//! - fail-closed disabled behavior
//! - deterministic replay of proof material

use frankenengine_node::control_plane::marker_stream::{MarkerEventType, MarkerStream};
use frankenengine_node::control_plane::mmr_proofs::{
    mmr_inclusion_proof, mmr_prefix_proof, verify_inclusion, verify_prefix, MmrCheckpoint, MmrRoot,
};

fn stream_with_markers(count: u64) -> MarkerStream {
    let mut stream = MarkerStream::new();
    for i in 0..count {
        stream
            .append(
                MarkerEventType::PolicyChange,
                &format!("payload-{i:08x}"),
                1_700_000_000 + i,
                &format!("trace-{i:08}"),
            )
            .expect("append");
    }
    stream
}

fn checkpoint(stream: &MarkerStream) -> MmrCheckpoint {
    let mut cp = MmrCheckpoint::enabled();
    cp.rebuild_from_stream(stream).expect("rebuild");
    cp
}

#[test]
fn inclusion_proof_validates_for_boundary_markers() {
    let stream = stream_with_markers(16);
    let cp = checkpoint(&stream);
    let root = cp.root().expect("root");

    for seq in [0_u64, 8_u64, 15_u64] {
        let proof = mmr_inclusion_proof(&stream, &cp, seq).expect("proof");
        let marker = stream.get(seq).expect("marker");
        verify_inclusion(&proof, root, &marker.marker_hash).expect("verify");
    }
}

#[test]
fn inclusion_proof_rejects_non_member_hash() {
    let stream = stream_with_markers(8);
    let cp = checkpoint(&stream);
    let root = cp.root().expect("root");

    let proof = mmr_inclusion_proof(&stream, &cp, 3).expect("proof");
    let err = verify_inclusion(&proof, root, &"not-a-member".to_string()).expect_err("reject");
    assert_eq!(err.code(), "MMR_LEAF_MISMATCH");
}

#[test]
fn prefix_proof_verifies_for_initial_segment() {
    let cp_small = checkpoint(&stream_with_markers(5));
    let cp_large = checkpoint(&stream_with_markers(10));
    let proof = mmr_prefix_proof(&cp_small, &cp_large).expect("prefix proof");
    verify_prefix(
        &proof,
        cp_small.root().expect("small root"),
        cp_large.root().expect("large root"),
    )
    .expect("verify prefix");
}

#[test]
fn prefix_proof_rejects_reversed_inputs() {
    let cp_small = checkpoint(&stream_with_markers(5));
    let cp_large = checkpoint(&stream_with_markers(10));
    let err = mmr_prefix_proof(&cp_large, &cp_small).expect_err("invalid order");
    assert_eq!(err.code(), "MMR_PREFIX_SIZE_INVALID");
}

#[test]
fn disabled_mode_is_fail_closed() {
    let stream = stream_with_markers(4);
    let cp = MmrCheckpoint::disabled();
    let err = mmr_inclusion_proof(&stream, &cp, 0).expect_err("disabled");
    assert_eq!(err.code(), "MMR_DISABLED");
}

#[test]
fn deterministic_proof_material_for_identical_inputs() {
    let stream = stream_with_markers(12);
    let cp = checkpoint(&stream);

    let p1 = mmr_inclusion_proof(&stream, &cp, 7).expect("p1");
    let p2 = mmr_inclusion_proof(&stream, &cp, 7).expect("p2");
    assert_eq!(p1, p2, "proof generation must be deterministic");
}

#[test]
fn proof_size_is_logarithmic_scale() {
    let stream = stream_with_markers(10_000);
    let cp = checkpoint(&stream);
    let proof = mmr_inclusion_proof(&stream, &cp, 9_999).expect("proof");
    assert!(proof.audit_path.len() <= 14, "audit path too large");
}

#[test]
fn root_identity_is_stable_under_repeat_builds() {
    let stream = stream_with_markers(32);

    let cp1 = checkpoint(&stream);
    let cp2 = checkpoint(&stream);
    let r1: &MmrRoot = cp1.root().expect("r1");
    let r2: &MmrRoot = cp2.root().expect("r2");
    assert_eq!(r1, r2);
}
