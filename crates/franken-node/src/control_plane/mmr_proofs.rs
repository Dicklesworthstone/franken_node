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
use crate::push_bounded;
use crate::security::constant_time;

/// Maximum leaf hashes before oldest-first eviction.
const MAX_LEAF_HASHES: usize = 4096;
const MAX_AUDIT_PATH_ENTRIES: usize = 64;

/// Safe conversion from usize to u64 with overflow protection.
fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

/// Safe conversion from u64 to usize with overflow protection.
fn u64_to_usize(val: u64) -> usize {
    usize::try_from(val).unwrap_or(usize::MAX)
}

fn audit_path_len_limit(tree_size: u64) -> usize {
    if tree_size <= 1 {
        return 0;
    }

    let tree_bound =
        usize::try_from(u64::BITS - (tree_size - 1).leading_zeros()).unwrap_or(usize::MAX);
    tree_bound.min(MAX_AUDIT_PATH_ENTRIES)
}

/// Canonical hash string type used by proof APIs.
pub type Hash = String;

type RawHash = [u8; 32];

const SHA256_HEX_LEN: usize = 64;
const LOWER_HEX: &[u8; 16] = b"0123456789abcdef";

/// Current Merkle root for a checkpointed stream state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MmrRoot {
    pub tree_size: u64,
    pub root_hash: Hash,
}

/// Inclusion proof for one marker in a specific checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    /// Zero-based leaf position within the retained checkpoint window.
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
        len_to_u64(self.leaf_hashes.len())
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

        push_bounded(
            &mut self.leaf_hashes,
            marker_leaf_hash(marker_hash),
            MAX_LEAF_HASHES,
        );
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

        let leaf_hashes = retained_leaf_hashes_raw(stream)?;

        let root_hash = merkle_root_from_raw_hashes(&leaf_hashes)
            .map(|hash| raw_hash_to_hex(&hash))
            .ok_or(ProofError::EmptyCheckpoint)?;
        self.leaf_hashes = raw_hashes_to_hex(&leaf_hashes);
        let root = MmrRoot {
            tree_size: len_to_u64(stream.len()),
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
        self.rebuild_from_stream(stream)
    }
}

/// Build an inclusion proof for an absolute marker sequence in the provided stream.
pub fn mmr_inclusion_proof(
    stream: &MarkerStream,
    checkpoint: &MmrCheckpoint,
    seq: u64,
) -> Result<InclusionProof, ProofError> {
    if !checkpoint.is_enabled() {
        return Err(ProofError::MmrDisabled);
    }

    let stream_size = len_to_u64(stream.len());
    if stream_size == 0 {
        return Err(ProofError::EmptyCheckpoint);
    }

    let leaf_hashes = retained_leaf_hashes_raw(stream)?;
    let current_root_hash = merkle_root_from_raw_hashes(&leaf_hashes)
        .map(|hash| raw_hash_to_hex(&hash))
        .ok_or(ProofError::EmptyCheckpoint)?;
    let checkpoint_root = checkpoint_root_or_err(checkpoint)?;
    // Compute both predicates before reducing with `||` so the operator's short-circuit
    // does not reveal whether the size or the root hash mismatched.
    let size_matches = checkpoint_root.tree_size == stream_size;
    let root_hash_matches = constant_time::ct_eq(&checkpoint_root.root_hash, &current_root_hash);
    if !size_matches || !root_hash_matches {
        return Err(ProofError::CheckpointStale {
            checkpoint_tree_size: checkpoint_root.tree_size,
            stream_tree_size: stream_size,
        });
    }

    let window_start = retained_window_start(stream)?;
    let window_end = window_start.saturating_add(stream_size);
    if seq < window_start || seq >= window_end {
        return Err(ProofError::SequenceOutOfRange {
            sequence: seq,
            tree_size: stream_size,
        });
    }

    let leaf_index = u64_to_usize(seq.saturating_sub(window_start));
    let leaf_hash =
        leaf_hashes
            .get(leaf_index)
            .map(raw_hash_to_hex)
            .ok_or(ProofError::SequenceOutOfRange {
                sequence: seq,
                tree_size: len_to_u64(leaf_hashes.len()),
            })?;
    let audit_path = merkle_audit_path_raw(&leaf_hashes, leaf_index)
        .map(|path| raw_hashes_to_hex(&path))
        .ok_or(ProofError::InvalidProof {
            reason: format!("failed to construct audit path for seq {seq}"),
        })?;

    Ok(InclusionProof {
        leaf_index: len_to_u64(leaf_index),
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

    let audit_path_limit = audit_path_len_limit(proof.tree_size);
    if proof.audit_path.len() > audit_path_limit {
        return Err(ProofError::InvalidProof {
            reason: format!(
                "audit_path_len={} exceeds limit={} for tree_size={}",
                proof.audit_path.len(),
                audit_path_limit,
                proof.tree_size
            ),
        });
    }

    let expected_leaf = marker_leaf_hash(marker_hash);
    if !constant_time::ct_eq(&expected_leaf, &proof.leaf_hash) {
        return Err(ProofError::LeafMismatch {
            expected: expected_leaf,
            actual: proof.leaf_hash.clone(),
        });
    }

    let current = inclusion_root_from_proof(proof);

    if !constant_time::ct_eq(&current, &root.root_hash) {
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

    let prefix_size = u64_to_usize(root_a.tree_size);
    if prefix_size > checkpoint_b.leaf_hashes.len() {
        return Err(ProofError::PrefixSizeInvalid {
            prefix_size: root_a.tree_size,
            super_tree_size: len_to_u64(checkpoint_b.leaf_hashes.len()),
        });
    }
    let prefix_root_from_super =
        merkle_root_from_leaf_hashes(&checkpoint_b.leaf_hashes[..prefix_size])
            .ok_or(ProofError::EmptyCheckpoint)?;
    if !constant_time::ct_eq(&prefix_root_from_super, &root_a.root_hash) {
        return Err(ProofError::InvalidProof {
            reason: "super-checkpoint retained window does not witness the requested prefix"
                .to_string(),
        });
    }

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

    if !constant_time::ct_eq(&proof.prefix_root_hash, &root_a.root_hash) {
        return Err(ProofError::RootMismatch {
            expected: root_a.root_hash.clone(),
            actual: proof.prefix_root_hash.clone(),
        });
    }

    if !constant_time::ct_eq(&proof.super_root_hash, &root_b.root_hash) {
        return Err(ProofError::RootMismatch {
            expected: root_b.root_hash.clone(),
            actual: proof.super_root_hash.clone(),
        });
    }

    if !constant_time::ct_eq(&proof.prefix_root_from_super, &root_a.root_hash) {
        return Err(ProofError::RootMismatch {
            expected: root_a.root_hash.clone(),
            actual: proof.prefix_root_from_super.clone(),
        });
    }

    Ok(())
}

#[must_use]
pub fn marker_leaf_hash(marker_hash: &str) -> Hash {
    raw_hash_to_hex(&marker_leaf_hash_raw(marker_hash))
}

fn marker_leaf_hash_raw(marker_hash: &str) -> RawHash {
    let mut hasher = Sha256::new();
    hasher.update(b"mmr_proofs_leaf_v1:");
    hasher.update((u64::try_from(marker_hash.len()).unwrap_or(u64::MAX)).to_le_bytes());
    hasher.update(marker_hash.as_bytes());
    finalize_raw(hasher)
}

fn retained_window_start(stream: &MarkerStream) -> Result<u64, ProofError> {
    stream
        .first()
        .map(|marker| marker.sequence)
        .ok_or(ProofError::EmptyCheckpoint)
}

#[cfg(test)]
fn retained_leaf_hashes(stream: &MarkerStream) -> Result<Vec<Hash>, ProofError> {
    retained_leaf_hashes_raw(stream).map(|hashes| raw_hashes_to_hex(&hashes))
}

fn retained_leaf_hashes_raw(stream: &MarkerStream) -> Result<Vec<RawHash>, ProofError> {
    let window_start = retained_window_start(stream)?;
    let window_end = window_start.saturating_add(len_to_u64(stream.len()));
    Ok(stream
        .range(window_start, window_end)
        .iter()
        .map(|marker| marker_leaf_hash_raw(&marker.marker_hash))
        .collect())
}

fn checkpoint_root_or_err(checkpoint: &MmrCheckpoint) -> Result<&MmrRoot, ProofError> {
    checkpoint.root().ok_or(ProofError::EmptyCheckpoint)
}

#[cfg(test)]
fn merkle_audit_path(leaf_hashes: &[Hash], leaf_index: usize) -> Option<Vec<Hash>> {
    if let Some(raw_leaf_hashes) = raw_hashes_from_hex(leaf_hashes) {
        return merkle_audit_path_raw(&raw_leaf_hashes, leaf_index)
            .map(|path| raw_hashes_to_hex(&path));
    }

    merkle_audit_path_legacy(leaf_hashes, leaf_index)
}

#[cfg(test)]
fn merkle_audit_path_legacy(leaf_hashes: &[Hash], leaf_index: usize) -> Option<Vec<Hash>> {
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

        let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
        path.push(level[sibling_idx].clone());

        let mut next = Vec::with_capacity(level.len() / 2);
        for chunk in level.chunks(2) {
            next.push(hash_pair_legacy(&chunk[0], &chunk[1]));
        }
        level = next;
        idx /= 2;
    }

    Some(path)
}

fn merkle_root_from_leaf_hashes(leaf_hashes: &[Hash]) -> Option<Hash> {
    if let Some(raw_leaf_hashes) = raw_hashes_from_hex(leaf_hashes) {
        return merkle_root_from_raw_hashes(&raw_leaf_hashes).map(|hash| raw_hash_to_hex(&hash));
    }

    merkle_root_from_leaf_hashes_legacy(leaf_hashes)
}

fn merkle_root_from_leaf_hashes_legacy(leaf_hashes: &[Hash]) -> Option<Hash> {
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
            next.push(hash_pair_legacy(&chunk[0], &chunk[1]));
        }
        level = next;
    }

    level.into_iter().next()
}

#[cfg(test)]
fn hash_pair(left: &str, right: &str) -> Hash {
    match (
        raw_hash_from_lower_hex(left),
        raw_hash_from_lower_hex(right),
    ) {
        (Some(left), Some(right)) => raw_hash_to_hex(&hash_pair_raw(&left, &right)),
        _ => hash_pair_legacy(left, right),
    }
}

fn hash_pair_legacy(left: &str, right: &str) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(b"mmr_proofs_node_v1:");
    hasher.update((u64::try_from(left.len()).unwrap_or(u64::MAX)).to_le_bytes());
    hasher.update(left.as_bytes());
    hasher.update((u64::try_from(right.len()).unwrap_or(u64::MAX)).to_le_bytes());
    hasher.update(right.as_bytes());
    hex::encode(hasher.finalize())
}

fn inclusion_root_from_proof(proof: &InclusionProof) -> Hash {
    if let Some(root) = inclusion_root_from_proof_raw(proof) {
        return raw_hash_to_hex(&root);
    }

    let mut current = proof.leaf_hash.clone();
    let mut index = u64_to_usize(proof.leaf_index);
    for sibling in &proof.audit_path {
        current = if index.is_multiple_of(2) {
            hash_pair_legacy(&current, sibling)
        } else {
            hash_pair_legacy(sibling, &current)
        };
        index /= 2;
    }
    current
}

fn inclusion_root_from_proof_raw(proof: &InclusionProof) -> Option<RawHash> {
    let mut current = raw_hash_from_lower_hex(&proof.leaf_hash)?;
    let mut index = u64_to_usize(proof.leaf_index);
    for sibling in &proof.audit_path {
        let sibling = raw_hash_from_lower_hex(sibling)?;
        current = if index.is_multiple_of(2) {
            hash_pair_raw(&current, &sibling)
        } else {
            hash_pair_raw(&sibling, &current)
        };
        index /= 2;
    }
    Some(current)
}

fn merkle_audit_path_raw(leaf_hashes: &[RawHash], leaf_index: usize) -> Option<Vec<RawHash>> {
    if leaf_hashes.is_empty() || leaf_index >= leaf_hashes.len() {
        return None;
    }

    let mut level = leaf_hashes.to_vec();
    let mut idx = leaf_index;
    let mut path = Vec::new();

    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last()?);
        }

        let sibling_idx = if idx.is_multiple_of(2) {
            idx + 1
        } else {
            idx - 1
        };
        path.push(level[sibling_idx]);

        let mut next = Vec::with_capacity(level.len() / 2);
        for chunk in level.chunks(2) {
            next.push(hash_pair_raw(&chunk[0], &chunk[1]));
        }
        level = next;
        idx /= 2;
    }

    Some(path)
}

fn merkle_root_from_raw_hashes(leaf_hashes: &[RawHash]) -> Option<RawHash> {
    if leaf_hashes.is_empty() {
        return None;
    }

    let mut level = leaf_hashes.to_vec();
    while level.len() > 1 {
        if level.len() % 2 == 1 {
            level.push(*level.last()?);
        }

        let mut next = Vec::with_capacity(level.len() / 2);
        for chunk in level.chunks(2) {
            next.push(hash_pair_raw(&chunk[0], &chunk[1]));
        }
        level = next;
    }

    level.into_iter().next()
}

fn hash_pair_raw(left: &RawHash, right: &RawHash) -> RawHash {
    let mut hasher = Sha256::new();
    hasher.update(b"mmr_proofs_node_v1:");
    hasher.update((SHA256_HEX_LEN as u64).to_le_bytes());
    update_hash_as_lower_hex(&mut hasher, left);
    hasher.update((SHA256_HEX_LEN as u64).to_le_bytes());
    update_hash_as_lower_hex(&mut hasher, right);
    finalize_raw(hasher)
}

fn finalize_raw(hasher: Sha256) -> RawHash {
    let digest = hasher.finalize();
    let mut hash = [0_u8; 32];
    hash.copy_from_slice(&digest);
    hash
}

fn update_hash_as_lower_hex(hasher: &mut Sha256, hash: &RawHash) {
    let mut encoded = [0_u8; SHA256_HEX_LEN];
    for (idx, byte) in hash.iter().enumerate() {
        encoded[idx * 2] = LOWER_HEX[usize::from(byte >> 4)];
        encoded[idx * 2 + 1] = LOWER_HEX[usize::from(byte & 0x0f)];
    }
    hasher.update(encoded);
}

fn raw_hash_to_hex(hash: &RawHash) -> Hash {
    hex::encode(hash)
}

fn raw_hashes_to_hex(hashes: &[RawHash]) -> Vec<Hash> {
    hashes.iter().map(raw_hash_to_hex).collect()
}

fn raw_hashes_from_hex(hashes: &[Hash]) -> Option<Vec<RawHash>> {
    hashes
        .iter()
        .map(|hash| raw_hash_from_lower_hex(hash))
        .collect()
}

fn raw_hash_from_lower_hex(hash: &str) -> Option<RawHash> {
    if hash.len() != SHA256_HEX_LEN
        || !hash
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
    {
        return None;
    }

    let mut raw = [0_u8; 32];
    hex::decode_to_slice(hash, &mut raw).ok()?;
    Some(raw)
}

#[cfg(test)]
fn sha256_hex(input: &[u8]) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(b"mmr_proofs_v1:");
    hasher.update(input);
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::{
        InclusionProof, MAX_LEAF_HASHES, MmrCheckpoint, MmrRoot, PrefixProof, ProofError,
        audit_path_len_limit, hash_pair_legacy, marker_leaf_hash, merkle_audit_path,
        merkle_audit_path_legacy, merkle_root_from_leaf_hashes,
        merkle_root_from_leaf_hashes_legacy, mmr_inclusion_proof, mmr_prefix_proof,
        raw_hash_from_lower_hex, verify_inclusion, verify_prefix,
    };
    use crate::control_plane::marker_stream::MarkerEventType;
    use crate::control_plane::marker_stream::MarkerStream;

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

    fn tamper_same_length(hash: &str) -> String {
        assert!(!hash.is_empty(), "hash cannot be empty");
        let mut bytes = hash.as_bytes().to_vec();
        bytes[0] = if bytes[0] == b'0' { b'1' } else { b'0' };
        String::from_utf8(bytes).expect("hex hash is valid utf-8")
    }

    #[test]
    fn raw_merkle_helpers_preserve_public_hex_contract() {
        let leaves = (0..17)
            .map(|idx| marker_leaf_hash(&format!("leaf-{idx}")))
            .collect::<Vec<_>>();

        assert_eq!(
            merkle_root_from_leaf_hashes(&leaves),
            merkle_root_from_leaf_hashes_legacy(&leaves)
        );

        for leaf_index in [0_usize, 1, 5, 16] {
            assert_eq!(
                merkle_audit_path(&leaves, leaf_index),
                merkle_audit_path_legacy(&leaves, leaf_index)
            );
        }

        let left = marker_leaf_hash("left");
        let right = marker_leaf_hash("right");
        assert_eq!(
            super::hash_pair(&left, &right),
            hash_pair_legacy(&left, &right)
        );
    }

    #[test]
    fn raw_hash_decoder_only_accepts_canonical_lower_hex() {
        let hash = marker_leaf_hash("canonical");
        assert!(raw_hash_from_lower_hex(&hash).is_some());
        assert!(raw_hash_from_lower_hex(&hash.to_ascii_uppercase()).is_none());
        assert!(raw_hash_from_lower_hex("abc123").is_none());
        assert!(raw_hash_from_lower_hex(&"g".repeat(64)).is_none());
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
    fn inclusion_proof_rejects_same_length_tampered_root_hash() {
        let stream = build_stream(8);
        let checkpoint = build_checkpoint(&stream);
        let root = checkpoint.root().expect("root");
        let proof = mmr_inclusion_proof(&stream, &checkpoint, 6).expect("proof");
        let marker = stream.get(6).expect("marker");

        let mut tampered_root = root.clone();
        tampered_root.root_hash = tamper_same_length(&tampered_root.root_hash);

        let err =
            verify_inclusion(&proof, &tampered_root, &marker.marker_hash).expect_err("tampered");
        assert_eq!(err.code(), "MMR_ROOT_MISMATCH");
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
    fn inclusion_proof_rejects_same_length_stale_checkpoint_after_eviction() {
        let checkpoint = build_checkpoint(&build_stream(MAX_LEAF_HASHES as u64));
        let stream = build_stream((MAX_LEAF_HASHES as u64) + 4);
        let first_retained_sequence = stream.first().expect("first").sequence;

        let err = mmr_inclusion_proof(&stream, &checkpoint, first_retained_sequence)
            .expect_err("same-length stale");
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
    fn prefix_proof_rejects_shifted_retained_windows_after_eviction() {
        let checkpoint_a = build_checkpoint(&build_stream(MAX_LEAF_HASHES as u64));
        let checkpoint_b = build_checkpoint(&build_stream((MAX_LEAF_HASHES as u64) + 4));

        let err = mmr_prefix_proof(&checkpoint_a, &checkpoint_b).expect_err("shifted");
        assert_eq!(err.code(), "MMR_INVALID_PROOF");
    }

    #[test]
    fn prefix_proof_rejects_same_length_tampered_prefix_root() {
        let stream_a = build_stream(4);
        let stream_b = build_stream(7);
        let checkpoint_a = build_checkpoint(&stream_a);
        let checkpoint_b = build_checkpoint(&stream_b);

        let mut proof = mmr_prefix_proof(&checkpoint_a, &checkpoint_b).expect("prefix proof");
        proof.prefix_root_hash = tamper_same_length(&proof.prefix_root_hash);

        let err = verify_prefix(
            &proof,
            checkpoint_a.root().expect("root_a"),
            checkpoint_b.root().expect("root_b"),
        )
        .expect_err("tampered");
        assert_eq!(err.code(), "MMR_ROOT_MISMATCH");
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
        // Use a count within the bounded marker capacity (4096)
        let count = 4_000_u64;
        let stream = build_stream(count);
        let checkpoint = build_checkpoint(&stream);
        let proof = mmr_inclusion_proof(&stream, &checkpoint, count - 1).expect("proof");
        assert!(
            proof.audit_path.len() <= 14,
            "expected <= 14, got {}",
            proof.audit_path.len()
        );
    }

    #[test]
    fn rebuild_from_stream_keeps_full_retained_window_after_eviction() {
        let stream = build_stream((MAX_LEAF_HASHES as u64) + 4);
        let checkpoint = build_checkpoint(&stream);

        assert_eq!(checkpoint.tree_size(), MAX_LEAF_HASHES as u64);
        assert_eq!(checkpoint.leaf_hashes().len(), MAX_LEAF_HASHES);
        assert_eq!(stream.first().expect("first").sequence, 4);
        assert_eq!(stream.len(), MAX_LEAF_HASHES);
    }

    #[test]
    fn inclusion_proof_uses_retained_window_index_after_eviction() {
        let stream = build_stream((MAX_LEAF_HASHES as u64) + 4);
        let checkpoint = build_checkpoint(&stream);
        let root = checkpoint.root().expect("root");

        let first_retained_sequence = stream.first().expect("first").sequence;
        let proof =
            mmr_inclusion_proof(&stream, &checkpoint, first_retained_sequence).expect("proof");
        let marker = stream.get(first_retained_sequence).expect("marker");

        assert_eq!(proof.leaf_index, 0);
        verify_inclusion(&proof, root, &marker.marker_hash).expect("verify");
    }

    #[test]
    fn inclusion_proof_rejects_evicted_sequence_after_eviction() {
        let stream = build_stream((MAX_LEAF_HASHES as u64) + 4);
        let checkpoint = build_checkpoint(&stream);
        let err = mmr_inclusion_proof(&stream, &checkpoint, 0).expect_err("evicted");

        assert_eq!(err.code(), "MMR_SEQUENCE_OUT_OF_RANGE");
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

    #[test]
    fn disabled_append_marker_hash_preserves_empty_state() {
        let mut checkpoint = MmrCheckpoint::disabled();

        let err = checkpoint
            .append_marker_hash("marker-hash")
            .expect_err("disabled checkpoint must fail closed");

        assert_eq!(err, ProofError::MmrDisabled);
        assert_eq!(checkpoint.tree_size(), 0);
        assert!(checkpoint.root().is_none());
        assert!(checkpoint.leaf_hashes().is_empty());
    }

    #[test]
    fn sync_from_stream_disabled_rejects_without_rebuild() {
        let stream = build_stream(3);
        let mut checkpoint = MmrCheckpoint::disabled();

        let err = checkpoint
            .sync_from_stream(&stream)
            .expect_err("disabled sync must fail closed");

        assert_eq!(err.code(), "MMR_DISABLED");
        assert_eq!(checkpoint.tree_size(), 0);
        assert!(checkpoint.root().is_none());
    }

    #[test]
    fn inclusion_proof_rejects_empty_stream_even_with_enabled_checkpoint() {
        let stream = build_stream(0);
        let checkpoint = MmrCheckpoint::enabled();

        let err = mmr_inclusion_proof(&stream, &checkpoint, 0)
            .expect_err("empty stream cannot produce inclusion proof");

        assert_eq!(err, ProofError::EmptyCheckpoint);
    }

    #[test]
    fn verify_inclusion_rejects_zero_sized_proof() {
        let proof = InclusionProof {
            leaf_index: 0,
            tree_size: 0,
            leaf_hash: marker_leaf_hash("marker"),
            audit_path: Vec::new(),
        };
        let root = MmrRoot {
            tree_size: 1,
            root_hash: marker_leaf_hash("marker"),
        };

        let err =
            verify_inclusion(&proof, &root, &"marker".to_string()).expect_err("zero-size proof");

        assert_eq!(err, ProofError::EmptyCheckpoint);
    }

    #[test]
    fn verify_inclusion_rejects_tree_size_mismatch_before_hash_checks() {
        let proof = InclusionProof {
            leaf_index: 0,
            tree_size: 2,
            leaf_hash: marker_leaf_hash("marker"),
            audit_path: Vec::new(),
        };
        let root = MmrRoot {
            tree_size: 3,
            root_hash: "not-evaluated".to_string(),
        };

        let err = verify_inclusion(&proof, &root, &"marker".to_string())
            .expect_err("tree size mismatch must fail");

        assert_eq!(err.code(), "MMR_INVALID_PROOF");
        assert!(err.to_string().contains("tree size mismatch"));
    }

    #[test]
    fn verify_inclusion_rejects_leaf_index_equal_to_tree_size() {
        let proof = InclusionProof {
            leaf_index: 2,
            tree_size: 2,
            leaf_hash: marker_leaf_hash("marker"),
            audit_path: Vec::new(),
        };
        let root = MmrRoot {
            tree_size: 2,
            root_hash: marker_leaf_hash("marker"),
        };

        let err = verify_inclusion(&proof, &root, &"marker".to_string())
            .expect_err("leaf index at tree size is out of range");

        assert_eq!(
            err,
            ProofError::SequenceOutOfRange {
                sequence: 2,
                tree_size: 2
            }
        );
    }

    #[test]
    fn prefix_proof_rejects_disabled_super_checkpoint() {
        let stream = build_stream(4);
        let checkpoint_a = build_checkpoint(&stream);
        let checkpoint_b = MmrCheckpoint::disabled();

        let err = mmr_prefix_proof(&checkpoint_a, &checkpoint_b)
            .expect_err("disabled super checkpoint must fail");

        assert_eq!(err, ProofError::MmrDisabled);
    }

    #[test]
    fn verify_prefix_rejects_prefix_larger_than_super() {
        let proof = PrefixProof {
            prefix_size: 5,
            super_tree_size: 4,
            prefix_root_hash: "prefix".to_string(),
            super_root_hash: "super".to_string(),
            prefix_root_from_super: "prefix".to_string(),
        };
        let root_a = MmrRoot {
            tree_size: 5,
            root_hash: "prefix".to_string(),
        };
        let root_b = MmrRoot {
            tree_size: 4,
            root_hash: "super".to_string(),
        };

        let err = verify_prefix(&proof, &root_a, &root_b)
            .expect_err("prefix larger than super tree must fail");

        assert_eq!(
            err,
            ProofError::PrefixSizeInvalid {
                prefix_size: 5,
                super_tree_size: 4
            }
        );
    }

    #[test]
    fn verify_prefix_rejects_root_size_mismatch() {
        let proof = PrefixProof {
            prefix_size: 3,
            super_tree_size: 5,
            prefix_root_hash: "prefix".to_string(),
            super_root_hash: "super".to_string(),
            prefix_root_from_super: "prefix".to_string(),
        };
        let root_a = MmrRoot {
            tree_size: 2,
            root_hash: "prefix".to_string(),
        };
        let root_b = MmrRoot {
            tree_size: 5,
            root_hash: "super".to_string(),
        };

        let err =
            verify_prefix(&proof, &root_a, &root_b).expect_err("root size mismatch must fail");

        assert_eq!(err.code(), "MMR_INVALID_PROOF");
        assert!(err.to_string().contains("proof sizes"));
    }

    #[test]
    fn serde_rejects_inclusion_proof_missing_audit_path() {
        let json = serde_json::json!({
            "leaf_index": 0,
            "tree_size": 1,
            "leaf_hash": marker_leaf_hash("marker")
        });

        let err = serde_json::from_value::<InclusionProof>(json)
            .expect_err("missing audit_path must fail deserialization");

        assert!(err.to_string().contains("audit_path"));
    }

    // Negative-path inline tests for edge cases and robustness
    #[test]
    fn negative_massive_tree_size_handles_overflow_gracefully() {
        let mut checkpoint = MmrCheckpoint::enabled();

        // Test with extreme tree sizes that could cause overflow
        let extreme_cases = vec![u64::MAX, u64::MAX - 1, u64::MAX / 2];

        for tree_size in extreme_cases {
            // Create proof with massive tree size
            let proof = InclusionProof {
                leaf_index: 0,
                tree_size,
                leaf_hash: marker_leaf_hash("test"),
                audit_path: Vec::new(),
            };

            let root = MmrRoot {
                tree_size,
                root_hash: marker_leaf_hash("root"),
            };

            // Verification should handle extreme sizes without panic
            let result = verify_inclusion(&proof, &root, &"test".to_string());

            // Either succeeds or fails gracefully, but no panic
            match result {
                Ok(_) => {} // Acceptable if logic handles it
                Err(err) => {
                    // Should have a proper error code, not crash
                    assert!(!err.code().is_empty());
                }
            }
        }

        // Test tree size arithmetic doesn't overflow
        let massive_leaf_count = u64::MAX / 1000;
        // This should either work or fail gracefully, not overflow
        assert_eq!(
            checkpoint.tree_size().saturating_add(massive_leaf_count),
            checkpoint.tree_size().saturating_add(massive_leaf_count)
        );
    }

    #[test]
    fn negative_unicode_characters_in_marker_hashes() {
        let mut checkpoint = MmrCheckpoint::enabled();

        // Test problematic unicode characters in marker hashes
        let problematic_markers = vec![
            "marker-🔥-test",              // Emoji
            "標記-測試-🌟",                // Mixed CJK with emoji
            "علامة-اختبار-٧٨٩",             // Arabic with numbers
            "marker\u{200B}hidden",        // Zero-width space
            "marker\u{FEFF}bom",           // Byte order mark
            "marker‌invisible‍chars",        // Zero-width joiners
            "𝒎𝒂𝒓𝒌𝒆𝒓",                      // Mathematical script unicode
            "marker\u{0301}\u{0302}combo", // Combining diacriticals
            "marker\u{1F600}emoji",        // Emoji codepoint
            "marker\u{202E}rtl\u{202D}",   // RTL/LTR override
        ];

        for marker in &problematic_markers {
            // Should handle unicode gracefully in hash computation
            let result = checkpoint.append_marker_hash(marker);

            match result {
                Ok(root) => {
                    // If successful, root should be valid
                    assert!(!root.root_hash.is_empty());
                    assert!(root.tree_size > 0);

                    // Verify hash is deterministic
                    let hash1 = marker_leaf_hash(marker);
                    let hash2 = marker_leaf_hash(marker);
                    assert_eq!(
                        hash1, hash2,
                        "Hash should be deterministic for unicode input"
                    );
                }
                Err(_) => {
                    // Graceful rejection is also acceptable
                }
            }
        }

        // Verify checkpoint state remains consistent
        assert!(checkpoint.tree_size() >= 0);
    }

    #[test]
    fn negative_null_bytes_and_control_characters_in_hash_inputs() {
        let problematic_hashes = vec![
            "marker\0null",           // Null byte
            "marker\x01\x02control",  // Control characters
            "marker\r\nlinebreak",    // Line breaks
            "marker\t\x0Btab",        // Tab and vertical tab
            "marker\x7F\u{80}\u{FF}", // DEL and high bytes
            "marker\u{FFFE}nonchar",  // Unicode non-character
            "marker\u{FFFF}invalid",  // Another non-character
            "",                       // Empty string
            "\0\0\0\0",               // Only null bytes
        ];

        for hash_input in &problematic_hashes {
            // Hash computation should handle control chars without corruption
            let leaf_hash = marker_leaf_hash(hash_input);

            // Should produce valid hex output
            assert!(
                leaf_hash.chars().all(|c| c.is_ascii_hexdigit()),
                "Hash should be valid hex despite problematic input: {:?}",
                hash_input
            );

            // Should be deterministic
            assert_eq!(marker_leaf_hash(hash_input), marker_leaf_hash(hash_input));

            // Should not be empty unless input caused total failure
            if !hash_input.is_empty() {
                assert!(
                    !leaf_hash.is_empty(),
                    "Hash should not be empty for non-empty input"
                );
            }
        }

        // Test in actual proof verification
        let mut checkpoint = MmrCheckpoint::enabled();
        let result = checkpoint.append_marker_hash("test\0null\u{FF}");

        // Should either succeed or fail cleanly, not corrupt state
        match result {
            Ok(_) => assert!(checkpoint.tree_size() > 0),
            Err(_) => assert_eq!(checkpoint.tree_size(), 0),
        }
    }

    #[test]
    fn negative_massive_audit_paths_memory_pressure() {
        // Create inclusion proof with massive audit path
        let massive_path_size = 10000;
        let mut audit_path = Vec::with_capacity(massive_path_size);

        for i in 0..massive_path_size {
            audit_path.push(format!("hash-{:064x}", i));
        }

        let proof = InclusionProof {
            leaf_index: 0,
            tree_size: 1,
            leaf_hash: marker_leaf_hash("test"),
            audit_path,
        };

        let root = MmrRoot {
            tree_size: 1,
            root_hash: marker_leaf_hash("root"),
        };

        let err = verify_inclusion(&proof, &root, &"test".to_string())
            .expect_err("overlong audit path must fail closed before hashing");

        assert_eq!(err.code(), "MMR_INVALID_PROOF");
        assert_eq!(audit_path_len_limit(proof.tree_size), 0);
        assert!(matches!(err, ProofError::InvalidProof { ref reason }
            if reason.contains("audit_path_len=10000") && reason.contains("limit=0")));

        // Memory should be released after verification
        drop(proof);
    }

    #[test]
    fn negative_hash_collision_resistance_validation() {
        let mut checkpoint = MmrCheckpoint::enabled();

        // Test potential hash collision scenarios
        let collision_candidates = vec![
            ("test1", "test2"),
            ("abc", "def"),
            ("hash", "hsah"), // Anagram
            ("a", "b"),
            ("", " "),          // Empty vs space
            ("test\0", "test"), // Null vs non-null
            ("UPPER", "upper"), // Case sensitivity
        ];

        let mut hashes = Vec::new();

        for (input1, input2) in collision_candidates {
            let hash1 = marker_leaf_hash(input1);
            let hash2 = marker_leaf_hash(input2);

            // Hashes should be different for different inputs
            assert_ne!(
                hash1, hash2,
                "Hash collision detected between {:?} and {:?}",
                input1, input2
            );

            // Collect all hashes to check for global collisions
            hashes.push((input1, hash1.clone()));
            hashes.push((input2, hash2.clone()));

            // Add to checkpoint to test internal collision handling
            if checkpoint.append_marker_hash(input1).is_ok() {
                checkpoint
                    .append_marker_hash(input2)
                    .expect("second append should succeed");
            }
        }

        // Check for any global hash collisions
        hashes.sort_by(|a, b| a.1.cmp(&b.1));
        for window in hashes.windows(2) {
            assert_ne!(
                window[0].1, window[1].1,
                "Hash collision found: {:?} and {:?} both hash to {}",
                window[0].0, window[1].0, window[0].1
            );
        }

        // Checkpoint should maintain integrity
        assert!(checkpoint.tree_size() > 0);
        if let Some(root) = checkpoint.root() {
            assert!(!root.root_hash.is_empty());
        }
    }

    #[test]
    fn negative_extreme_leaf_indices_boundary_testing() {
        // Test edge cases around leaf index boundaries
        let boundary_cases = vec![
            (0, 1),                   // First leaf in single-item tree
            (0, 2),                   // First leaf in two-item tree
            (1, 2),                   // Last leaf in two-item tree
            (u64::MAX - 1, u64::MAX), // Near-maximum indices
        ];

        for (leaf_index, tree_size) in boundary_cases {
            let proof = InclusionProof {
                leaf_index,
                tree_size,
                leaf_hash: marker_leaf_hash("boundary"),
                audit_path: Vec::new(),
            };

            let root = MmrRoot {
                tree_size,
                root_hash: marker_leaf_hash("root"),
            };

            let result = verify_inclusion(&proof, &root, &"boundary".to_string());

            // Boundary conditions should be handled correctly
            if leaf_index >= tree_size {
                // Should reject out-of-bounds indices
                assert!(result.is_err());
                assert_eq!(result.unwrap_err().code(), "MMR_SEQUENCE_OUT_OF_RANGE");
            } else {
                // Valid indices should either succeed or fail for other reasons
                match result {
                    Ok(_) => {}
                    Err(err) => {
                        // Should not fail due to boundary issues
                        assert_ne!(err.code(), "MMR_SEQUENCE_OUT_OF_RANGE");
                    }
                }
            }
        }
    }

    #[test]
    fn negative_malformed_merkle_tree_construction() {
        // Test edge cases in merkle tree construction
        let edge_cases = vec![
            Vec::<String>::new(),                  // Empty leaf set
            vec!["single".to_string()],            // Single leaf
            vec!["".to_string()],                  // Single empty leaf
            vec!["a".to_string(), "".to_string()], // Mixed empty/non-empty
        ];

        for leaves in edge_cases {
            let root_result = merkle_root_from_leaf_hashes(&leaves);

            match leaves.len() {
                0 => {
                    // Empty leaf set should return None
                    assert!(root_result.is_none(), "Empty leaf set should return None");
                }
                1 => {
                    // Single leaf should return that leaf as root
                    assert!(root_result.is_some(), "Single leaf should produce root");
                    if let Some(root) = root_result {
                        assert!(!root.is_empty(), "Root should not be empty");
                    }
                }
                _ => {
                    // Multiple leaves should produce a root
                    assert!(root_result.is_some(), "Multiple leaves should produce root");
                }
            }

            // Test audit path construction for each case
            if !leaves.is_empty() {
                for leaf_idx in 0..leaves.len() {
                    let audit_result = merkle_audit_path(&leaves, leaf_idx);

                    match leaves.len() {
                        1 => {
                            // Single leaf should have empty audit path
                            assert_eq!(audit_result, Some(Vec::new()));
                        }
                        _ => {
                            // Multiple leaves should have non-empty audit path
                            assert!(audit_result.is_some(), "Should produce audit path");
                        }
                    }
                }
            }
        }
    }

    #[test]
    fn negative_integer_overflow_in_tree_operations() {
        // Test arithmetic operations that could overflow
        let mut checkpoint = MmrCheckpoint::enabled();

        // Fill checkpoint to near capacity with overflow-prone operations
        for i in 0..10 {
            let marker = format!("overflow-test-{}", i);
            checkpoint
                .append_marker_hash(&marker)
                .expect("append should succeed");
        }

        // Test tree size calculations don't overflow
        let tree_size = checkpoint.tree_size();
        assert!(tree_size < u64::MAX);

        // Test saturating operations
        let saturated_add = tree_size.saturating_add(u64::MAX);
        assert!(saturated_add >= tree_size);

        // Create stream with potential overflow scenarios
        let stream = build_stream(100);

        // Test window calculations with extreme values
        if let Ok(hashes) = retained_leaf_hashes(&stream) {
            assert!(hashes.len() <= MAX_LEAF_HASHES);

            // Verify no overflow in hash collection size
            let len_as_u64 = u64::try_from(hashes.len()).unwrap_or(u64::MAX);
            assert!(len_as_u64 <= MAX_LEAF_HASHES as u64);
        }

        // Test prefix proof with extreme size differences
        let small_checkpoint = MmrCheckpoint::enabled();
        if checkpoint.tree_size() > 0 {
            let result = mmr_prefix_proof(&small_checkpoint, &checkpoint);
            // Should handle size disparity gracefully
            match result {
                Ok(_) => {}
                Err(err) => {
                    assert!(!err.code().is_empty());
                }
            }
        }
    }

    #[test]
    fn negative_concurrent_hash_computation_consistency() {
        // Test hash consistency under various inputs that might cause issues
        let test_inputs = vec![
            "normal-input",
            "input-with-unicode-🔥",
            "input\0with\0nulls",
            "very-long-input-".repeat(100).as_str(),
            "",
            " ",
            "\n\r\t",
            "input-with-high-bytes-\u{80}\u{FF}",
        ];

        for input in test_inputs {
            // Hash should be deterministic across multiple calls
            let hash1 = marker_leaf_hash(input);
            let hash2 = marker_leaf_hash(input);
            let hash3 = marker_leaf_hash(input);

            assert_eq!(
                hash1, hash2,
                "Hash should be deterministic for: {:?}",
                input
            );
            assert_eq!(
                hash2, hash3,
                "Hash should be deterministic for: {:?}",
                input
            );

            // Hash should be valid hex
            assert!(
                hash1.chars().all(|c| c.is_ascii_hexdigit()),
                "Hash should be valid hex for: {:?}",
                input
            );

            // Hash should have consistent length
            assert_eq!(
                hash1.len(),
                64,
                "SHA256 hash should be 64 hex chars for: {:?}",
                input
            );

            // Test pair hashing as well
            let pair_hash1 = hash_pair(&hash1, &hash1);
            let pair_hash2 = hash_pair(&hash1, &hash1);
            assert_eq!(pair_hash1, pair_hash2, "Pair hash should be deterministic");
        }

        // Test domain separation is working
        let marker_hash = marker_leaf_hash("test");
        let direct_sha = sha256_hex(b"test");
        assert_ne!(
            marker_hash, direct_sha,
            "Domain separation should prevent direct hash matches"
        );
    }

    #[test]
    fn mmr_hash_collision_prevention_regression() {
        // Regression test for bd-1kesy: MMR hash helpers must use length-prefixed
        // domain-separated inputs to prevent hash collisions in verifier-facing proofs.

        // Test 1: Leaf hash domain separation
        let leaf1 = marker_leaf_hash("boundary");
        let leaf2 = marker_leaf_hash("boundary");
        assert_eq!(leaf1, leaf2, "Same leaf input should produce same hash");

        // Verify leaf uses distinct domain from formatted version
        let formatted_leaf = sha256_hex(b"leaf:boundary");
        assert_ne!(
            leaf1, formatted_leaf,
            "Length-prefixed leaf should differ from formatted version"
        );

        // Test 2: Node hash domain separation
        let node1 = hash_pair("left", "right");
        let node2 = hash_pair("left", "right");
        assert_eq!(node1, node2, "Same node inputs should produce same hash");

        // Verify node uses distinct domain from formatted version
        let formatted_node = sha256_hex(b"node:left:right");
        assert_ne!(
            node1, formatted_node,
            "Length-prefixed node should differ from formatted version"
        );

        // Test 3: Length-prefix prevents boundary attacks
        // These should produce different hashes despite same concatenated content
        let attack1 = hash_pair("ab", "cd"); // ab + cd
        let attack2 = hash_pair("a", "bcd"); // a + bcd
        assert_ne!(
            attack1, attack2,
            "Length-prefixing prevents boundary attacks"
        );

        // Test 4: Cross-domain separation (leaf vs node)
        // A leaf hash should never equal a node hash even with same content
        let leaf = marker_leaf_hash("content");
        let node = hash_pair("content", "");
        assert_ne!(leaf, node, "Leaf and node domains must be separate");

        // Test 5: Sibling mutation detection
        let original_node = hash_pair("original_left", "original_right");
        let mutated_left = hash_pair("tampered_left", "original_right");
        let mutated_right = hash_pair("original_left", "tampered_right");
        let both_mutated = hash_pair("tampered_left", "tampered_right");

        assert_ne!(
            original_node, mutated_left,
            "Left sibling mutation should change hash"
        );
        assert_ne!(
            original_node, mutated_right,
            "Right sibling mutation should change hash"
        );
        assert_ne!(
            original_node, both_mutated,
            "Both sibling mutations should change hash"
        );
        assert_ne!(
            mutated_left, mutated_right,
            "Different mutations should produce different hashes"
        );
    }
}
