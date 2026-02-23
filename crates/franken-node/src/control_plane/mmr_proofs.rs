//! bd-1dar: Optional MMR checkpoints + inclusion/prefix proofs.
//!
//! Provides deterministic proof primitives for external verifiers:
//! - optional/togglable checkpoint state
//! - inclusion proofs for marker hashes
//! - prefix proofs between two checkpoints
//! - fail-closed verification errors with stable codes

use std::fmt;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::control_plane::marker_stream::MarkerStream;

/// Canonical hash string type used by proof APIs.
pub type Hash = String;

/// Current Merkle root for a checkpointed stream state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrRoot {
    pub tree_size: u64,
    pub root_hash: Hash,
}

/// Inclusion proof for one marker in a specific checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub leaf_hash: Hash,
    pub audit_path: Vec<Hash>,
}

/// Prefix proof that one checkpoint is an initial segment of another.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrefixProof {
    pub prefix_size: u64,
    pub super_tree_size: u64,
    pub prefix_root_hash: Hash,
    pub super_root_hash: Hash,
    pub prefix_root_from_super: Hash,
}

/// Errors for MMR checkpoint/proof operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProofError {
    MmrDisabled,
    EmptyCheckpoint,
    SequenceOutOfRange {
        sequence: u64,
        tree_size: u64,
    },
    CheckpointStale {
        checkpoint_tree_size: u64,
        stream_tree_size: u64,
    },
    PrefixSizeInvalid {
        prefix_size: u64,
        super_tree_size: u64,
    },
    InvalidProof {
        reason: String,
    },
    LeafMismatch {
        expected: Hash,
        actual: Hash,
    },
    RootMismatch {
        expected: Hash,
        actual: Hash,
    },
}

impl ProofError {
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            Self::MmrDisabled => "MMR_DISABLED",
            Self::EmptyCheckpoint => "MMR_EMPTY_CHECKPOINT",
            Self::SequenceOutOfRange { .. } => "MMR_SEQUENCE_OUT_OF_RANGE",
            Self::CheckpointStale { .. } => "MMR_CHECKPOINT_STALE",
            Self::PrefixSizeInvalid { .. } => "MMR_PREFIX_SIZE_INVALID",
            Self::InvalidProof { .. } => "MMR_INVALID_PROOF",
            Self::LeafMismatch { .. } => "MMR_LEAF_MISMATCH",
            Self::RootMismatch { .. } => "MMR_ROOT_MISMATCH",
        }
    }
}

impl fmt::Display for ProofError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MmrDisabled => write!(f, "MMR_DISABLED: checkpoint is disabled"),
            Self::EmptyCheckpoint => write!(f, "MMR_EMPTY_CHECKPOINT: no markers available"),
            Self::SequenceOutOfRange {
                sequence,
                tree_size,
            } => write!(
                f,
                "MMR_SEQUENCE_OUT_OF_RANGE: sequence={sequence} tree_size={tree_size}"
            ),
            Self::CheckpointStale {
                checkpoint_tree_size,
                stream_tree_size,
            } => write!(
                f,
                "MMR_CHECKPOINT_STALE: checkpoint={checkpoint_tree_size} stream={stream_tree_size}"
            ),
            Self::PrefixSizeInvalid {
                prefix_size,
                super_tree_size,
            } => write!(
                f,
                "MMR_PREFIX_SIZE_INVALID: prefix_size={prefix_size} super_tree_size={super_tree_size}"
            ),
            Self::InvalidProof { reason } => write!(f, "MMR_INVALID_PROOF: {reason}"),
            Self::LeafMismatch { expected, actual } => {
                write!(f, "MMR_LEAF_MISMATCH: expected={expected} actual={actual}")
            }
            Self::RootMismatch { expected, actual } => {
                write!(f, "MMR_ROOT_MISMATCH: expected={expected} actual={actual}")
            }
        }
    }
}

impl std::error::Error for ProofError {}

/// Optional checkpoint state for marker-stream Merkle roots.
///
/// The checkpoint is read-only with respect to `MarkerStream`: enable/disable
/// toggles never mutate stream contents.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MmrCheckpoint {
    enabled: bool,
    leaf_hashes: Vec<Hash>,
    latest_root: Option<MmrRoot>,
}

impl MmrCheckpoint {
    #[must_use]
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            leaf_hashes: Vec::new(),
            latest_root: None,
        }
    }

    #[must_use]
    pub fn enabled() -> Self {
        Self::new(true)
    }

    #[must_use]
    pub fn disabled() -> Self {
        Self::new(false)
    }

    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub fn set_enabled(&mut self, enabled: bool) {
        self.enabled = enabled;
    }

    #[must_use]
    pub fn tree_size(&self) -> u64 {
        self.leaf_hashes.len() as u64
    }

    #[must_use]
    pub fn root(&self) -> Option<&MmrRoot> {
        self.latest_root.as_ref()
    }

    #[must_use]
    pub fn leaf_hashes(&self) -> &[Hash] {
        &self.leaf_hashes
    }

    /// Append one marker hash and update the checkpoint root.
    pub fn append_marker_hash(&mut self, marker_hash: &str) -> Result<MmrRoot, ProofError> {
        if !self.enabled {
            return Err(ProofError::MmrDisabled);
        }

        self.leaf_hashes.push(marker_leaf_hash(marker_hash));
        let root_hash =
            merkle_root_from_leaf_hashes(&self.leaf_hashes).ok_or(ProofError::EmptyCheckpoint)?;
        let root = MmrRoot {
            tree_size: self.tree_size(),
            root_hash,
        };
        self.latest_root = Some(root.clone());
        Ok(root)
    }

    /// Rebuild checkpoint state from an existing marker stream.
    pub fn rebuild_from_stream(&mut self, stream: &MarkerStream) -> Result<MmrRoot, ProofError> {
        if !self.enabled {
            return Err(ProofError::MmrDisabled);
        }

        self.leaf_hashes = stream
            .range(0, stream.len() as u64)
            .iter()
            .map(|marker| marker_leaf_hash(&marker.marker_hash))
            .collect();

        let root_hash =
            merkle_root_from_leaf_hashes(&self.leaf_hashes).ok_or(ProofError::EmptyCheckpoint)?;
        let root = MmrRoot {
            tree_size: self.tree_size(),
            root_hash,
        };
        self.latest_root = Some(root.clone());
        Ok(root)
    }

    /// Synchronize checkpoint state with stream contents.
    ///
    /// If stream length regresses (e.g., torn-tail recovery), this rebuilds from
    /// scratch to preserve determinism.
    pub fn sync_from_stream(&mut self, stream: &MarkerStream) -> Result<MmrRoot, ProofError> {
        if !self.enabled {
            return Err(ProofError::MmrDisabled);
        }

        let stream_size = stream.len();
        if stream_size <= self.leaf_hashes.len() {
            return self.rebuild_from_stream(stream);
        }

        while self.leaf_hashes.len() < stream_size {
            let idx = self.leaf_hashes.len() as u64;
            let marker = stream.get(idx).ok_or(ProofError::InvalidProof {
                reason: format!("marker missing at sequence {idx}"),
            })?;
            self.leaf_hashes.push(marker_leaf_hash(&marker.marker_hash));
        }

        let root_hash =
            merkle_root_from_leaf_hashes(&self.leaf_hashes).ok_or(ProofError::EmptyCheckpoint)?;
        let root = MmrRoot {
            tree_size: self.tree_size(),
            root_hash,
        };
        self.latest_root = Some(root.clone());
        Ok(root)
    }
}

/// Build an inclusion proof for a marker sequence in the provided stream.
pub fn mmr_inclusion_proof(
    stream: &MarkerStream,
    checkpoint: &MmrCheckpoint,
    seq: u64,
) -> Result<InclusionProof, ProofError> {
    if !checkpoint.is_enabled() {
        return Err(ProofError::MmrDisabled);
    }

    let stream_size = stream.len() as u64;
    if stream_size == 0 {
        return Err(ProofError::EmptyCheckpoint);
    }

    if checkpoint.tree_size() != stream_size {
        return Err(ProofError::CheckpointStale {
            checkpoint_tree_size: checkpoint.tree_size(),
            stream_tree_size: stream_size,
        });
    }

    if seq >= stream_size {
        return Err(ProofError::SequenceOutOfRange {
            sequence: seq,
            tree_size: stream_size,
        });
    }

    let leaf_hashes: Vec<Hash> = stream
        .range(0, stream_size)
        .iter()
        .map(|marker| marker_leaf_hash(&marker.marker_hash))
        .collect();

    let leaf_index = seq as usize;
    let leaf_hash = leaf_hashes[leaf_index].clone();
    let audit_path =
        merkle_audit_path(&leaf_hashes, leaf_index).ok_or(ProofError::InvalidProof {
            reason: format!("failed to construct audit path for seq {seq}"),
        })?;

    Ok(InclusionProof {
        leaf_index: seq,
        tree_size: stream_size,
        leaf_hash,
        audit_path,
    })
}

/// Verify an inclusion proof against a root and marker hash.
pub fn verify_inclusion(
    proof: &InclusionProof,
    root: &MmrRoot,
    marker_hash: &Hash,
) -> Result<(), ProofError> {
    if proof.tree_size == 0 || root.tree_size == 0 {
        return Err(ProofError::EmptyCheckpoint);
    }

    if proof.tree_size != root.tree_size {
        return Err(ProofError::InvalidProof {
            reason: format!(
                "tree size mismatch proof={} root={}",
                proof.tree_size, root.tree_size
            ),
        });
    }

    if proof.leaf_index >= proof.tree_size {
        return Err(ProofError::SequenceOutOfRange {
            sequence: proof.leaf_index,
            tree_size: proof.tree_size,
        });
    }

    let expected_leaf = marker_leaf_hash(marker_hash);
    if expected_leaf != proof.leaf_hash {
        return Err(ProofError::LeafMismatch {
            expected: expected_leaf,
            actual: proof.leaf_hash.clone(),
        });
    }

    let mut current = proof.leaf_hash.clone();
    let mut index = proof.leaf_index as usize;
    for sibling in &proof.audit_path {
        current = if index.is_multiple_of(2) {
            hash_pair(&current, sibling)
        } else {
            hash_pair(sibling, &current)
        };
        index /= 2;
    }

    if current != root.root_hash {
        return Err(ProofError::RootMismatch {
            expected: root.root_hash.clone(),
            actual: current,
        });
    }

    Ok(())
}

/// Build a prefix proof showing checkpoint A is a prefix of checkpoint B.
pub fn mmr_prefix_proof(
    checkpoint_a: &MmrCheckpoint,
    checkpoint_b: &MmrCheckpoint,
) -> Result<PrefixProof, ProofError> {
    if !checkpoint_a.is_enabled() || !checkpoint_b.is_enabled() {
        return Err(ProofError::MmrDisabled);
    }

    let root_a = checkpoint_root_or_err(checkpoint_a)?;
    let root_b = checkpoint_root_or_err(checkpoint_b)?;

    if root_a.tree_size > root_b.tree_size {
        return Err(ProofError::PrefixSizeInvalid {
            prefix_size: root_a.tree_size,
            super_tree_size: root_b.tree_size,
        });
    }

    let prefix_size = root_a.tree_size as usize;
    let prefix_root_from_super =
        merkle_root_from_leaf_hashes(&checkpoint_b.leaf_hashes[..prefix_size])
            .ok_or(ProofError::EmptyCheckpoint)?;

    Ok(PrefixProof {
        prefix_size: root_a.tree_size,
        super_tree_size: root_b.tree_size,
        prefix_root_hash: root_a.root_hash.clone(),
        super_root_hash: root_b.root_hash.clone(),
        prefix_root_from_super,
    })
}

/// Verify a prefix proof against two explicit roots.
pub fn verify_prefix(
    proof: &PrefixProof,
    root_a: &MmrRoot,
    root_b: &MmrRoot,
) -> Result<(), ProofError> {
    if proof.prefix_size > proof.super_tree_size {
        return Err(ProofError::PrefixSizeInvalid {
            prefix_size: proof.prefix_size,
            super_tree_size: proof.super_tree_size,
        });
    }

    if root_a.tree_size != proof.prefix_size || root_b.tree_size != proof.super_tree_size {
        return Err(ProofError::InvalidProof {
            reason: "proof sizes do not match provided roots".to_string(),
        });
    }

    if proof.prefix_root_hash != root_a.root_hash {
        return Err(ProofError::RootMismatch {
            expected: root_a.root_hash.clone(),
            actual: proof.prefix_root_hash.clone(),
        });
    }

    if proof.super_root_hash != root_b.root_hash {
        return Err(ProofError::RootMismatch {
            expected: root_b.root_hash.clone(),
            actual: proof.super_root_hash.clone(),
        });
    }

    if proof.prefix_root_from_super != root_a.root_hash {
        return Err(ProofError::RootMismatch {
            expected: root_a.root_hash.clone(),
            actual: proof.prefix_root_from_super.clone(),
        });
    }

    Ok(())
}

#[must_use]
pub fn marker_leaf_hash(marker_hash: &str) -> Hash {
    sha256_hex(format!("leaf:{marker_hash}").as_bytes())
}

fn checkpoint_root_or_err(checkpoint: &MmrCheckpoint) -> Result<&MmrRoot, ProofError> {
    checkpoint.root().ok_or(ProofError::EmptyCheckpoint)
}

fn merkle_audit_path(leaf_hashes: &[Hash], leaf_index: usize) -> Option<Vec<Hash>> {
    if leaf_hashes.is_empty() || leaf_index >= leaf_hashes.len() {
        return None;
    }

    let mut level = leaf_hashes.to_vec();
    let mut idx = leaf_index;
    let mut path = Vec::new();

    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(level.last()?.clone());
        }

        let sibling_idx = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };
        path.push(level[sibling_idx].clone());

        let mut next = Vec::with_capacity(level.len() / 2);
        for chunk in level.chunks(2) {
            next.push(hash_pair(&chunk[0], &chunk[1]));
        }
        level = next;
        idx /= 2;
    }

    Some(path)
}

fn merkle_root_from_leaf_hashes(leaf_hashes: &[Hash]) -> Option<Hash> {
    if leaf_hashes.is_empty() {
        return None;
    }

    let mut level = leaf_hashes.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(level.last()?.clone());
        }

        let mut next = Vec::with_capacity(level.len() / 2);
        for chunk in level.chunks(2) {
            next.push(hash_pair(&chunk[0], &chunk[1]));
        }
        level = next;
    }

    level.into_iter().next()
}

fn hash_pair(left: &str, right: &str) -> Hash {
    sha256_hex(format!("node:{left}:{right}").as_bytes())
}

fn sha256_hex(input: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(b"mmr_proofs_v1:");
    hasher.update(input);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control_plane::marker_stream::MarkerEventType;

    fn build_stream(count: u64) -> MarkerStream {
        let mut stream = MarkerStream::new();
        for i in 0..count {
            stream
                .append(
                    MarkerEventType::PolicyChange,
                    &format!("payload-{i:016x}"),
                    1_700_000_000 + i,
                    &format!("trace-{i:04}"),
                )
                .expect("append marker");
        }
        stream
    }

    fn build_checkpoint(stream: &MarkerStream) -> MmrCheckpoint {
        let mut checkpoint = MmrCheckpoint::enabled();
        checkpoint
            .rebuild_from_stream(stream)
            .expect("rebuild checkpoint");
        checkpoint
    }

    #[test]
    fn checkpoint_disabled_blocks_build_and_proofs() {
        let stream = build_stream(3);
        let mut checkpoint = MmrCheckpoint::disabled();
        let err = checkpoint
            .rebuild_from_stream(&stream)
            .expect_err("disabled");
        assert_eq!(err.code(), "MMR_DISABLED");

        let err = mmr_inclusion_proof(&stream, &checkpoint, 0).expect_err("disabled proof");
        assert_eq!(err.code(), "MMR_DISABLED");
    }

    #[test]
    fn inclusion_proof_verifies_first_middle_last() {
        let stream = build_stream(10);
        let checkpoint = build_checkpoint(&stream);
        let root = checkpoint.root().expect("root");

        for seq in [0_u64, 5_u64, 9_u64] {
            let proof = mmr_inclusion_proof(&stream, &checkpoint, seq).expect("proof");
            let marker = stream.get(seq).expect("marker");
            verify_inclusion(&proof, root, &marker.marker_hash).expect("verify");
        }
    }

    #[test]
    fn inclusion_proof_rejects_wrong_marker_hash() {
        let stream = build_stream(5);
        let checkpoint = build_checkpoint(&stream);
        let root = checkpoint.root().expect("root");
        let proof = mmr_inclusion_proof(&stream, &checkpoint, 2).expect("proof");

        let err = verify_inclusion(&proof, root, &"wrong-hash".to_string()).expect_err("reject");
        assert_eq!(err.code(), "MMR_LEAF_MISMATCH");
    }

    #[test]
    fn inclusion_proof_rejects_out_of_range_sequence() {
        let stream = build_stream(4);
        let checkpoint = build_checkpoint(&stream);
        let err = mmr_inclusion_proof(&stream, &checkpoint, 9).expect_err("out of range");
        assert_eq!(err.code(), "MMR_SEQUENCE_OUT_OF_RANGE");
    }

    #[test]
    fn inclusion_proof_rejects_stale_checkpoint() {
        let stream = build_stream(4);
        let mut checkpoint = MmrCheckpoint::enabled();
        checkpoint
            .append_marker_hash(&stream.get(0).expect("marker").marker_hash)
            .expect("append");
        let err = mmr_inclusion_proof(&stream, &checkpoint, 0).expect_err("stale");
        assert_eq!(err.code(), "MMR_CHECKPOINT_STALE");
    }

    #[test]
    fn prefix_proof_verifies_matching_prefix() {
        let stream_a = build_stream(5);
        let stream_b = build_stream(10);
        let checkpoint_a = build_checkpoint(&stream_a);
        let checkpoint_b = build_checkpoint(&stream_b);

        let proof = mmr_prefix_proof(&checkpoint_a, &checkpoint_b).expect("prefix proof");
        verify_prefix(
            &proof,
            checkpoint_a.root().expect("root_a"),
            checkpoint_b.root().expect("root_b"),
        )
        .expect("verify prefix");
    }

    #[test]
    fn prefix_proof_rejects_invalid_order() {
        let stream_small = build_stream(3);
        let stream_large = build_stream(9);
        let checkpoint_small = build_checkpoint(&stream_small);
        let checkpoint_large = build_checkpoint(&stream_large);

        let err = mmr_prefix_proof(&checkpoint_large, &checkpoint_small).expect_err("invalid");
        assert_eq!(err.code(), "MMR_PREFIX_SIZE_INVALID");
    }

    #[test]
    fn reenable_and_rebuild_from_stream() {
        let stream = build_stream(7);
        let mut checkpoint = MmrCheckpoint::enabled();
        checkpoint
            .rebuild_from_stream(&stream)
            .expect("initial rebuild");
        let original_root = checkpoint.root().expect("root").root_hash.clone();

        checkpoint.set_enabled(false);
        checkpoint.set_enabled(true);
        checkpoint
            .rebuild_from_stream(&stream)
            .expect("rebuild after enable");
        let rebuilt_root = checkpoint.root().expect("root").root_hash.clone();

        assert_eq!(original_root, rebuilt_root);
    }

    #[test]
    fn proof_size_is_log_n() {
        let stream = build_stream(10_000);
        let checkpoint = build_checkpoint(&stream);
        let proof = mmr_inclusion_proof(&stream, &checkpoint, 9_999).expect("proof");
        assert!(
            proof.audit_path.len() <= 14,
            "expected <= 14, got {}",
            proof.audit_path.len()
        );
    }

    #[test]
    fn serde_roundtrip_proofs() {
        let stream = build_stream(8);
        let checkpoint = build_checkpoint(&stream);
        let proof = mmr_inclusion_proof(&stream, &checkpoint, 3).expect("proof");

        let json = serde_json::to_string(&proof).expect("serialize");
        let parsed: InclusionProof = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(proof, parsed);

        let prefix =
            mmr_prefix_proof(&build_checkpoint(&build_stream(3)), &checkpoint).expect("prefix");
        let json = serde_json::to_string(&prefix).expect("serialize");
        let parsed: PrefixProof = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(prefix, parsed);
    }
}
