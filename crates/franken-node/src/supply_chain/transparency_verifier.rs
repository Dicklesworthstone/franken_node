//! Transparency-log inclusion proof checks (bd-1z9s).
//!
//! Verifies Merkle tree inclusion proofs for connector install/update
//! pipelines. Install/update fails if the required proof is missing
//! or invalid. Log roots are pinned per policy.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;

use crate::security::constant_time::ct_eq_bytes;

const RESERVED_ARTIFACT_ID: &str = "<unknown>";

// ── Hash helper ─────────────────────────────────────────────────────

/// Compute a deterministic hash of two hex strings combined.
/// Uses full-width SHA-256 output (64 hex chars) to avoid weakened collision
/// resistance from truncation.
fn hash_pair(left: &str, right: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"transparency_interior_v1:");
    h.update(len_to_u64(left.len()).to_le_bytes());
    h.update(left.as_bytes());
    h.update(len_to_u64(right.len()).to_le_bytes());
    h.update(right.as_bytes());
    let digest = h.finalize();
    format!("{:x}", digest)
}

/// Compute the leaf hash for a piece of data.
pub fn leaf_hash(data: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"transparency_verifier_leaf_v1:");
    h.update(len_to_u64(data.len()).to_le_bytes());
    h.update(data.as_bytes());
    let digest = h.finalize();
    format!("{:x}", digest)
}

fn len_to_u64(len: usize) -> u64 {
    u64::try_from(len).unwrap_or(u64::MAX)
}

// ── Types ───────────────────────────────────────────────────────────

/// A pinned log root checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LogRoot {
    pub tree_size: u64,
    pub root_hash: String,
}

/// A Merkle inclusion proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InclusionProof {
    pub leaf_index: u64,
    pub tree_size: u64,
    pub leaf_hash: String,
    pub audit_path: Vec<String>,
}

/// Policy for transparency log verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransparencyPolicy {
    pub required: bool,
    pub pinned_roots: Vec<LogRoot>,
}

impl TransparencyPolicy {
    /// Check if a `(tree_size, root_hash)` checkpoint is in the pinned set.
    pub fn is_checkpoint_pinned(&self, tree_size: u64, root_hash: &str) -> bool {
        self.pinned_roots.iter().fold(false, |acc, r| {
            let size_match = r.tree_size == tree_size;
            let hash_match = ct_eq_bytes(r.root_hash.as_bytes(), root_hash.as_bytes());
            acc | (size_match & hash_match)
        })
    }
}

/// Result of inclusion proof verification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofReceipt {
    pub connector_id: String,
    pub artifact_id: String,
    pub verified: bool,
    pub log_root_matched: bool,
    pub proof_valid: bool,
    pub failure_reason: Option<ProofFailure>,
    pub trace_id: String,
    pub timestamp: String,
}

/// Reason for proof verification failure.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofFailure {
    ProofMissing,
    RootNotPinned { root_hash: String },
    PathInvalid { computed: String, expected: String },
    LeafMismatch { expected: String, actual: String },
    InvalidArtifactId { reason: String },
    InvalidConnectorId { reason: String },
}

impl fmt::Display for ProofFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProofMissing => write!(f, "TLOG_PROOF_MISSING"),
            Self::RootNotPinned { root_hash } => {
                write!(f, "TLOG_ROOT_NOT_PINNED: {root_hash}")
            }
            Self::PathInvalid { computed, expected } => {
                write!(
                    f,
                    "TLOG_PATH_INVALID: computed={computed}, expected={expected}"
                )
            }
            Self::LeafMismatch { expected, actual } => {
                write!(
                    f,
                    "TLOG_LEAF_MISMATCH: expected={expected}, actual={actual}"
                )
            }
            Self::InvalidArtifactId { reason } => {
                write!(f, "TLOG_ARTIFACT_INVALID: {reason}")
            }
            Self::InvalidConnectorId { reason } => {
                write!(f, "TLOG_CONNECTOR_INVALID: {reason}")
            }
        }
    }
}

// ── Merkle path verification ────────────────────────────────────────

/// Recompute the Merkle root from a leaf and its audit path.
///
/// At each level, if the current index is even we hash (current || sibling),
/// if odd we hash (sibling || current). Then shift the index right by 1.
pub fn recompute_root(proof: &InclusionProof) -> String {
    let mut current = proof.leaf_hash.clone();
    let mut index = proof.leaf_index;

    for sibling in &proof.audit_path {
        if index.is_multiple_of(2) {
            current = hash_pair(&current, sibling);
        } else {
            current = hash_pair(sibling, &current);
        }
        index /= 2;
    }

    current
}

/// Verify an inclusion proof against a policy.
pub fn verify_inclusion(
    policy: &TransparencyPolicy,
    proof: Option<&InclusionProof>,
    artifact_hash: &str,
    connector_id: &str,
    artifact_id: &str,
    trace_id: &str,
    timestamp: &str,
) -> ProofReceipt {
    if let Some(reason) = invalid_artifact_id_reason(artifact_id) {
        return ProofReceipt {
            connector_id: connector_id.into(),
            artifact_id: artifact_id.into(),
            verified: false,
            log_root_matched: false,
            proof_valid: false,
            failure_reason: Some(ProofFailure::InvalidArtifactId { reason }),
            trace_id: trace_id.into(),
            timestamp: timestamp.into(),
        };
    }

    if let Some(reason) = invalid_connector_id_reason(connector_id) {
        return ProofReceipt {
            connector_id: connector_id.into(),
            artifact_id: artifact_id.into(),
            verified: false,
            log_root_matched: false,
            proof_valid: false,
            failure_reason: Some(ProofFailure::InvalidConnectorId { reason }),
            trace_id: trace_id.into(),
            timestamp: timestamp.into(),
        };
    }

    // Check if proof is provided
    let proof = match proof {
        Some(p) => p,
        None => {
            if policy.required {
                return ProofReceipt {
                    connector_id: connector_id.into(),
                    artifact_id: artifact_id.into(),
                    verified: false,
                    log_root_matched: false,
                    proof_valid: false,
                    failure_reason: Some(ProofFailure::ProofMissing),
                    trace_id: trace_id.into(),
                    timestamp: timestamp.into(),
                };
            }
            // Not required, not provided → pass
            return ProofReceipt {
                connector_id: connector_id.into(),
                artifact_id: artifact_id.into(),
                verified: true,
                log_root_matched: true,
                proof_valid: true,
                failure_reason: None,
                trace_id: trace_id.into(),
                timestamp: timestamp.into(),
            };
        }
    };

    // Validate proof metadata bounds before any hash work.
    if proof.tree_size == 0 || proof.leaf_index >= proof.tree_size {
        return ProofReceipt {
            connector_id: connector_id.into(),
            artifact_id: artifact_id.into(),
            verified: false,
            log_root_matched: false,
            proof_valid: false,
            failure_reason: Some(ProofFailure::PathInvalid {
                computed: format!(
                    "leaf_index={}, tree_size={}",
                    proof.leaf_index, proof.tree_size
                ),
                expected: "0 <= leaf_index < tree_size".into(),
            }),
            trace_id: trace_id.into(),
            timestamp: timestamp.into(),
        };
    }

    // Check leaf hash matches artifact hash
    if !ct_eq_bytes(proof.leaf_hash.as_bytes(), artifact_hash.as_bytes()) {
        return ProofReceipt {
            connector_id: connector_id.into(),
            artifact_id: artifact_id.into(),
            verified: false,
            log_root_matched: false,
            proof_valid: false,
            failure_reason: Some(ProofFailure::LeafMismatch {
                expected: artifact_hash.into(),
                actual: proof.leaf_hash.clone(),
            }),
            trace_id: trace_id.into(),
            timestamp: timestamp.into(),
        };
    }

    // Recompute root
    let computed_root = recompute_root(proof);

    // Check if root is pinned
    let root_pinned = policy.is_checkpoint_pinned(proof.tree_size, &computed_root);
    if !root_pinned {
        return ProofReceipt {
            connector_id: connector_id.into(),
            artifact_id: artifact_id.into(),
            verified: false,
            log_root_matched: false,
            proof_valid: false,
            failure_reason: Some(ProofFailure::RootNotPinned {
                root_hash: computed_root,
            }),
            trace_id: trace_id.into(),
            timestamp: timestamp.into(),
        };
    }

    ProofReceipt {
        connector_id: connector_id.into(),
        artifact_id: artifact_id.into(),
        verified: true,
        log_root_matched: true,
        proof_valid: true,
        failure_reason: None,
        trace_id: trace_id.into(),
        timestamp: timestamp.into(),
    }
}

fn invalid_artifact_id_reason(artifact_id: &str) -> Option<String> {
    let trimmed = artifact_id.trim();
    if trimmed.is_empty() {
        return Some("artifact_id is empty".to_string());
    }
    if trimmed == RESERVED_ARTIFACT_ID {
        return Some(format!("artifact_id is reserved: {:?}", artifact_id));
    }
    if artifact_id.contains('\0') {
        return Some("artifact_id contains null byte".to_string());
    }
    if trimmed != artifact_id {
        return Some("artifact_id contains leading or trailing whitespace".to_string());
    }
    None
}

fn invalid_connector_id_reason(connector_id: &str) -> Option<String> {
    let trimmed = connector_id.trim();
    if trimmed.is_empty() {
        return Some("connector_id is empty".to_string());
    }
    if trimmed == RESERVED_ARTIFACT_ID {
        return Some(format!("connector_id is reserved: {:?}", connector_id));
    }
    if connector_id.contains('\0') {
        return Some("connector_id contains null byte".to_string());
    }
    if trimmed != connector_id {
        return Some("connector_id contains leading or trailing whitespace".to_string());
    }
    None
}

// ── Errors ──────────────────────────────────────────────────────────

/// Errors for transparency log operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TransparencyError {
    #[serde(rename = "TLOG_PROOF_MISSING")]
    ProofMissing,
    #[serde(rename = "TLOG_ROOT_NOT_PINNED")]
    RootNotPinned { root_hash: String },
    #[serde(rename = "TLOG_PATH_INVALID")]
    PathInvalid { computed: String, expected: String },
    #[serde(rename = "TLOG_LEAF_MISMATCH")]
    LeafMismatch { expected: String, actual: String },
}

impl fmt::Display for TransparencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ProofMissing => write!(f, "TLOG_PROOF_MISSING"),
            Self::RootNotPinned { root_hash } => {
                write!(f, "TLOG_ROOT_NOT_PINNED: {root_hash}")
            }
            Self::PathInvalid { computed, expected } => {
                write!(
                    f,
                    "TLOG_PATH_INVALID: computed={computed}, expected={expected}"
                )
            }
            Self::LeafMismatch { expected, actual } => {
                write!(
                    f,
                    "TLOG_LEAF_MISMATCH: expected={expected}, actual={actual}"
                )
            }
        }
    }
}

impl std::error::Error for TransparencyError {}

// ── Test helpers ────────────────────────────────────────────────────

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items
            .len()
            .saturating_sub(cap)
            .saturating_add(1)
            .min(items.len());
        items.drain(0..overflow);
    }
    items.push(item);
}

/// Build a small Merkle tree from leaves and return (root, proofs).
pub fn build_test_tree(leaves: &[&str]) -> (String, Vec<InclusionProof>) {
    let n = leaves.len();
    if n == 0 {
        return ("".into(), vec![]);
    }

    let leaf_hashes: Vec<String> = leaves.iter().map(|l| leaf_hash(l)).collect();

    // Pad to next power of 2
    let size = n.next_power_of_two();
    let mut level: Vec<String> = leaf_hashes.clone();
    while level.len() < size {
        push_bounded(&mut level, level.last().cloned().unwrap_or_default(), 1024);
    }

    // Build tree bottom-up, collecting sibling info for proofs
    let mut levels = vec![level.clone()];
    while level.len() > 1 {
        let mut next = Vec::new();
        for chunk in level.chunks(2) {
            let h = if chunk.len() == 2 {
                hash_pair(&chunk[0], &chunk[1])
            } else {
                chunk[0].clone()
            };
            push_bounded(&mut next, h, 512);
        }
        level = next;
        levels.push(level.clone());
    }

    let root = level[0].clone();

    // Build inclusion proofs for each original leaf
    let mut proofs = Vec::new();
    for (i, leaf_hash) in leaf_hashes.iter().enumerate() {
        let mut audit_path = Vec::new();
        let mut idx = i;
        for lvl in &levels[..levels.len() - 1] {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            if sibling_idx < lvl.len() {
                push_bounded(&mut audit_path, lvl[sibling_idx].clone(), 256);
            }
            idx /= 2;
        }
        proofs.push(InclusionProof {
            leaf_index: len_to_u64(i),
            tree_size: len_to_u64(n),
            leaf_hash: leaf_hash.clone(),
            audit_path,
        });
    }

    (root, proofs)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy(root: &str, tree_size: u64) -> TransparencyPolicy {
        TransparencyPolicy {
            required: true,
            pinned_roots: vec![LogRoot {
                tree_size,
                root_hash: root.to_string(),
            }],
        }
    }

    fn tamper_same_length_hash(input: &str) -> String {
        let mut chars: Vec<char> = input.chars().collect();
        let idx = chars
            .iter()
            .position(|ch| *ch != '0')
            .unwrap_or(chars.len().saturating_sub(1));
        chars[idx] = if chars[idx] == '0' { '1' } else { '0' };
        chars.into_iter().collect()
    }

    // === Merkle basics ===

    #[test]
    fn leaf_hash_deterministic() {
        assert_eq!(leaf_hash("hello"), leaf_hash("hello"));
    }

    #[test]
    fn leaf_hash_different_data() {
        assert_ne!(leaf_hash("hello"), leaf_hash("world"));
    }

    #[test]
    fn hashes_use_full_sha256_width() {
        assert_eq!(leaf_hash("hello").len(), 64);
        assert_eq!(hash_pair("a", "b").len(), 64);
    }

    #[test]
    fn hash_pair_deterministic() {
        assert_eq!(hash_pair("a", "b"), hash_pair("a", "b"));
    }

    #[test]
    fn hash_pair_order_matters() {
        assert_ne!(hash_pair("a", "b"), hash_pair("b", "a"));
    }

    // === build_test_tree ===

    #[test]
    fn build_tree_returns_valid_proofs() {
        let (root, proofs) = build_test_tree(&["a", "b", "c", "d"]);
        for proof in &proofs {
            let computed = recompute_root(proof);
            assert_eq!(computed, root, "proof for leaf {} failed", proof.leaf_index);
        }
    }

    #[test]
    fn build_tree_two_leaves() {
        let (root, proofs) = build_test_tree(&["x", "y"]);
        assert_eq!(proofs.len(), 2);
        assert_eq!(recompute_root(&proofs[0]), root);
        assert_eq!(recompute_root(&proofs[1]), root);
    }

    // === verify_inclusion ===

    #[test]
    fn valid_proof_verifies() {
        let (root, proofs) = build_test_tree(&["a", "b", "c", "d"]);
        let policy = test_policy(&root, proofs[0].tree_size);
        let receipt = verify_inclusion(
            &policy,
            Some(&proofs[0]),
            &proofs[0].leaf_hash,
            "conn-1",
            "art-1",
            "t1",
            "ts",
        );
        assert!(receipt.verified);
        assert!(receipt.proof_valid);
        assert!(receipt.log_root_matched);
    }

    #[test]
    fn missing_proof_fails_when_required() {
        let policy = TransparencyPolicy {
            required: true,
            pinned_roots: vec![],
        };
        let receipt = verify_inclusion(&policy, None, "hash", "conn-1", "art-1", "t2", "ts");
        assert!(!receipt.verified);
        assert_eq!(receipt.failure_reason, Some(ProofFailure::ProofMissing));
    }

    #[test]
    fn missing_proof_ok_when_not_required() {
        let policy = TransparencyPolicy {
            required: false,
            pinned_roots: vec![],
        };
        let receipt = verify_inclusion(&policy, None, "hash", "conn-1", "art-1", "t3", "ts");
        assert!(receipt.verified);
    }

    #[test]
    fn invalid_artifact_id_rejected() {
        let (root, proofs) = build_test_tree(&["a"]);
        let policy = test_policy(&root, proofs[0].tree_size);
        let receipt = verify_inclusion(
            &policy,
            Some(&proofs[0]),
            &proofs[0].leaf_hash,
            "conn-1",
            "",
            "t3a",
            "ts",
        );
        assert!(!receipt.verified);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::InvalidArtifactId { .. })
        ));
    }

    #[test]
    fn invalid_connector_id_rejected() {
        let (root, proofs) = build_test_tree(&["a"]);
        let policy = test_policy(&root, proofs[0].tree_size);
        let receipt = verify_inclusion(
            &policy,
            Some(&proofs[0]),
            &proofs[0].leaf_hash,
            " conn-1 ",
            "art-1",
            "t3b",
            "ts",
        );
        assert!(!receipt.verified);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::InvalidConnectorId { .. })
        ));
    }

    #[test]
    fn unpinned_root_rejected() {
        let (_, proofs) = build_test_tree(&["a", "b", "c", "d"]);
        let policy = test_policy("wrong_root_hash", proofs[0].tree_size);
        let receipt = verify_inclusion(
            &policy,
            Some(&proofs[0]),
            &proofs[0].leaf_hash,
            "conn-1",
            "art-1",
            "t4",
            "ts",
        );
        assert!(!receipt.verified);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::RootNotPinned { .. })
        ));
    }

    #[test]
    fn leaf_mismatch_rejected() {
        let (root, proofs) = build_test_tree(&["a", "b", "c", "d"]);
        let policy = test_policy(&root, proofs[0].tree_size);
        let receipt = verify_inclusion(
            &policy,
            Some(&proofs[0]),
            "wrong_leaf_hash",
            "conn-1",
            "art-1",
            "t5",
            "ts",
        );
        assert!(!receipt.verified);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::LeafMismatch { .. })
        ));
    }

    #[test]
    fn leaf_mismatch_same_length_rejected() {
        let (root, proofs) = build_test_tree(&["a", "b", "c", "d"]);
        let policy = test_policy(&root, proofs[0].tree_size);
        let tampered_hash = tamper_same_length_hash(&proofs[0].leaf_hash);
        let receipt = verify_inclusion(
            &policy,
            Some(&proofs[0]),
            &tampered_hash,
            "conn-1",
            "art-1",
            "t5b",
            "ts",
        );
        assert!(!receipt.verified);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::LeafMismatch { .. })
        ));
    }

    #[test]
    fn tampered_proof_fails() {
        let (root, proofs) = build_test_tree(&["a", "b", "c", "d"]);
        let policy = test_policy(&root, proofs[0].tree_size);
        let mut bad_proof = proofs[0].clone();
        if !bad_proof.audit_path.is_empty() {
            bad_proof.audit_path[0] = "tampered".into();
        }
        let receipt = verify_inclusion(
            &policy,
            Some(&bad_proof),
            &bad_proof.leaf_hash,
            "conn-1",
            "art-1",
            "t6",
            "ts",
        );
        assert!(!receipt.verified);
    }

    #[test]
    fn deterministic_verification() {
        let (root, proofs) = build_test_tree(&["a", "b"]);
        let policy = test_policy(&root, proofs[0].tree_size);
        let r1 = verify_inclusion(
            &policy,
            Some(&proofs[0]),
            &proofs[0].leaf_hash,
            "conn-1",
            "art-1",
            "t7a",
            "ts",
        );
        let r2 = verify_inclusion(
            &policy,
            Some(&proofs[0]),
            &proofs[0].leaf_hash,
            "conn-1",
            "art-1",
            "t7b",
            "ts",
        );
        assert_eq!(r1.verified, r2.verified);
        assert_eq!(r1.proof_valid, r2.proof_valid);
    }

    #[test]
    fn receipt_has_trace_id() {
        let (root, proofs) = build_test_tree(&["a", "b"]);
        let policy = test_policy(&root, proofs[0].tree_size);
        let receipt = verify_inclusion(
            &policy,
            Some(&proofs[0]),
            &proofs[0].leaf_hash,
            "conn-1",
            "art-1",
            "trace-xyz",
            "ts",
        );
        assert_eq!(receipt.trace_id, "trace-xyz");
    }

    #[test]
    fn checkpoint_size_mismatch_rejected() {
        let (root, proofs) = build_test_tree(&["a", "b"]);
        let policy = test_policy(&root, proofs[0].tree_size.saturating_add(1));
        let receipt = verify_inclusion(
            &policy,
            Some(&proofs[0]),
            &proofs[0].leaf_hash,
            "conn-1",
            "art-1",
            "t8",
            "ts",
        );
        assert!(!receipt.verified);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::RootNotPinned { .. })
        ));
    }

    #[test]
    fn out_of_bounds_leaf_index_rejected() {
        let (root, proofs) = build_test_tree(&["a", "b", "c", "d"]);
        let policy = test_policy(&root, proofs[0].tree_size);
        let mut bad_proof = proofs[0].clone();
        bad_proof.leaf_index = bad_proof.tree_size;
        let receipt = verify_inclusion(
            &policy,
            Some(&bad_proof),
            &bad_proof.leaf_hash,
            "conn-1",
            "art-1",
            "t9",
            "ts",
        );
        assert!(!receipt.verified);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::PathInvalid { .. })
        ));
    }

    #[test]
    fn zero_tree_size_rejected() {
        let (root, proofs) = build_test_tree(&["a", "b", "c", "d"]);
        let policy = test_policy(&root, proofs[0].tree_size);
        let mut bad_proof = proofs[0].clone();
        bad_proof.tree_size = 0;
        bad_proof.leaf_index = 0;
        let receipt = verify_inclusion(
            &policy,
            Some(&bad_proof),
            &bad_proof.leaf_hash,
            "conn-1",
            "art-1",
            "t10",
            "ts",
        );
        assert!(!receipt.verified);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::PathInvalid { .. })
        ));
    }

    #[test]
    fn reserved_artifact_id_rejected_before_proof_evaluation() {
        let (root, proofs) = build_test_tree(&["a", "b"]);
        let policy = test_policy(&root, proofs[0].tree_size);
        let receipt = verify_inclusion(
            &policy,
            Some(&proofs[0]),
            "not-the-leaf-hash",
            "conn-1",
            RESERVED_ARTIFACT_ID,
            "reserved-artifact",
            "ts",
        );

        assert!(!receipt.verified);
        assert!(!receipt.log_root_matched);
        assert!(!receipt.proof_valid);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::InvalidArtifactId { .. })
        ));
    }

    #[test]
    fn artifact_id_with_trailing_whitespace_rejected() {
        let (root, proofs) = build_test_tree(&["a"]);
        let policy = test_policy(&root, proofs[0].tree_size);
        let receipt = verify_inclusion(
            &policy,
            Some(&proofs[0]),
            &proofs[0].leaf_hash,
            "conn-1",
            "artifact-1 ",
            "artifact-whitespace",
            "ts",
        );

        assert!(!receipt.verified);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::InvalidArtifactId { reason }) if reason.contains("whitespace")
        ));
    }

    #[test]
    fn empty_connector_id_rejected_before_missing_proof() {
        let policy = TransparencyPolicy {
            required: true,
            pinned_roots: vec![],
        };
        let receipt = verify_inclusion(
            &policy,
            None,
            "irrelevant-hash",
            "   ",
            "artifact-1",
            "empty-connector",
            "ts",
        );

        assert!(!receipt.verified);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::InvalidConnectorId { reason }) if reason.contains("empty")
        ));
    }

    #[test]
    fn reserved_connector_id_rejected() {
        let (root, proofs) = build_test_tree(&["a"]);
        let policy = test_policy(&root, proofs[0].tree_size);
        let receipt = verify_inclusion(
            &policy,
            Some(&proofs[0]),
            &proofs[0].leaf_hash,
            RESERVED_ARTIFACT_ID,
            "artifact-1",
            "reserved-connector",
            "ts",
        );

        assert!(!receipt.verified);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::InvalidConnectorId { reason }) if reason.contains("reserved")
        ));
    }

    #[test]
    fn optional_policy_still_rejects_invalid_artifact_id() {
        let policy = TransparencyPolicy {
            required: false,
            pinned_roots: vec![],
        };
        let receipt = verify_inclusion(
            &policy,
            None,
            "irrelevant-hash",
            "conn-1",
            "\t",
            "optional-invalid-artifact",
            "ts",
        );

        assert!(!receipt.verified);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::InvalidArtifactId { reason }) if reason.contains("empty")
        ));
    }

    #[test]
    fn max_leaf_index_rejected_before_leaf_mismatch() {
        let (root, proofs) = build_test_tree(&["a", "b"]);
        let policy = test_policy(&root, proofs[0].tree_size);
        let mut bad_proof = proofs[0].clone();
        bad_proof.leaf_index = u64::MAX;
        bad_proof.leaf_hash = "wrong-leaf-hash".to_string();
        let receipt = verify_inclusion(
            &policy,
            Some(&bad_proof),
            "expected-leaf-hash",
            "conn-1",
            "artifact-1",
            "max-index",
            "ts",
        );

        assert!(!receipt.verified);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::PathInvalid { .. })
        ));
    }

    #[test]
    fn missing_audit_path_for_multi_leaf_tree_rejected() {
        let (root, proofs) = build_test_tree(&["a", "b", "c", "d"]);
        let policy = test_policy(&root, proofs[0].tree_size);
        let mut bad_proof = proofs[0].clone();
        bad_proof.audit_path.clear();
        let receipt = verify_inclusion(
            &policy,
            Some(&bad_proof),
            &bad_proof.leaf_hash,
            "conn-1",
            "artifact-1",
            "empty-path",
            "ts",
        );

        assert!(!receipt.verified);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::RootNotPinned { .. })
        ));
    }

    #[test]
    fn path_tamper_to_valid_leaf_hash_is_still_rejected() {
        let (root, proofs) = build_test_tree(&["a", "b", "c", "d"]);
        let policy = test_policy(&root, proofs[0].tree_size);
        let mut bad_proof = proofs[0].clone();
        bad_proof.audit_path[0] = proofs[2].leaf_hash.clone();
        let receipt = verify_inclusion(
            &policy,
            Some(&bad_proof),
            &bad_proof.leaf_hash,
            "conn-1",
            "artifact-1",
            "valid-hash-wrong-path",
            "ts",
        );

        assert!(!receipt.verified);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::RootNotPinned { .. })
        ));
    }

    #[test]
    fn connector_id_with_leading_whitespace_rejected() {
        let (root, proofs) = build_test_tree(&["a"]);
        let policy = test_policy(&root, proofs[0].tree_size);

        let receipt = verify_inclusion(
            &policy,
            Some(&proofs[0]),
            &proofs[0].leaf_hash,
            " conn-1",
            "artifact-1",
            "connector-leading-space",
            "ts",
        );

        assert!(!receipt.verified);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::InvalidConnectorId { reason }) if reason.contains("whitespace")
        ));
    }

    #[test]
    fn optional_policy_still_rejects_invalid_connector_id() {
        let policy = TransparencyPolicy {
            required: false,
            pinned_roots: Vec::new(),
        };

        let receipt = verify_inclusion(
            &policy,
            None,
            "unused-hash",
            "\n",
            "artifact-1",
            "optional-invalid-connector",
            "ts",
        );

        assert!(!receipt.verified);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::InvalidConnectorId { reason }) if reason.contains("empty")
        ));
    }

    #[test]
    fn optional_policy_rejects_provided_invalid_proof() {
        let (_, proofs) = build_test_tree(&["a", "b"]);
        let policy = TransparencyPolicy {
            required: false,
            pinned_roots: Vec::new(),
        };

        let receipt = verify_inclusion(
            &policy,
            Some(&proofs[0]),
            &proofs[0].leaf_hash,
            "conn-1",
            "artifact-1",
            "optional-invalid-proof",
            "ts",
        );

        assert!(!receipt.verified);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::RootNotPinned { .. })
        ));
    }

    #[test]
    fn tree_size_smaller_than_leaf_index_rejected_before_leaf_mismatch() {
        let (root, proofs) = build_test_tree(&["a", "b", "c"]);
        let policy = test_policy(&root, proofs[0].tree_size);
        let mut bad_proof = proofs[0].clone();
        bad_proof.tree_size = 1;
        bad_proof.leaf_index = 2;
        bad_proof.leaf_hash = "wrong-leaf-hash".to_string();

        let receipt = verify_inclusion(
            &policy,
            Some(&bad_proof),
            "expected-leaf-hash",
            "conn-1",
            "artifact-1",
            "small-tree-invalid-index",
            "ts",
        );

        assert!(!receipt.verified);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::PathInvalid { .. })
        ));
    }

    #[test]
    fn checkpoint_not_pinned_when_tree_size_differs_even_if_hash_matches() {
        let (root, proofs) = build_test_tree(&["a", "b"]);
        let policy = TransparencyPolicy {
            required: true,
            pinned_roots: vec![LogRoot {
                tree_size: proofs[0].tree_size.saturating_add(1),
                root_hash: root.clone(),
            }],
        };

        assert!(!policy.is_checkpoint_pinned(proofs[0].tree_size, &root));
    }

    #[test]
    fn artifact_id_with_null_byte_rejected_before_leaf_mismatch() {
        let (root, proofs) = build_test_tree(&["a", "b"]);
        let policy = test_policy(&root, proofs[0].tree_size);
        let receipt = verify_inclusion(
            &policy,
            Some(&proofs[0]),
            "not-the-leaf-hash",
            "conn-1",
            "artifact\0shadow",
            "artifact-null-byte",
            "ts",
        );

        assert!(!receipt.verified);
        assert!(!receipt.log_root_matched);
        assert!(!receipt.proof_valid);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::InvalidArtifactId { reason }) if reason.contains("null byte")
        ));
    }

    #[test]
    fn connector_id_with_null_byte_rejected_before_missing_proof() {
        let policy = TransparencyPolicy {
            required: true,
            pinned_roots: Vec::new(),
        };
        let receipt = verify_inclusion(
            &policy,
            None,
            "unused-hash",
            "conn\0shadow",
            "artifact-1",
            "connector-null-byte",
            "ts",
        );

        assert!(!receipt.verified);
        assert!(!receipt.log_root_matched);
        assert!(!receipt.proof_valid);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::InvalidConnectorId { reason }) if reason.contains("null byte")
        ));
    }

    #[test]
    fn checkpoint_hash_same_length_tamper_is_not_pinned() {
        let (root, proofs) = build_test_tree(&["a", "b"]);
        let tampered_root = tamper_same_length_hash(&root);
        let policy = TransparencyPolicy {
            required: true,
            pinned_roots: vec![LogRoot {
                tree_size: proofs[0].tree_size,
                root_hash: tampered_root.clone(),
            }],
        };

        assert!(!policy.is_checkpoint_pinned(proofs[0].tree_size, &root));
        assert!(policy.is_checkpoint_pinned(proofs[0].tree_size, &tampered_root));
    }

    #[test]
    fn root_hash_with_trailing_whitespace_not_pinned() {
        let (root, proofs) = build_test_tree(&["a", "b"]);
        let policy = TransparencyPolicy {
            required: true,
            pinned_roots: vec![LogRoot {
                tree_size: proofs[0].tree_size,
                root_hash: format!("{root} "),
            }],
        };

        assert!(!policy.is_checkpoint_pinned(proofs[0].tree_size, &root));
    }

    #[test]
    fn hash_pair_length_prefix_prevents_boundary_collision() {
        let first = hash_pair("ab", "c");
        let second = hash_pair("a", "bc");

        assert_ne!(first, second);
    }

    #[test]
    fn single_leaf_wrong_pinned_root_rejected() {
        let (root, proofs) = build_test_tree(&["solo"]);
        let tampered_root = tamper_same_length_hash(&root);
        let policy = TransparencyPolicy {
            required: true,
            pinned_roots: vec![LogRoot {
                tree_size: proofs[0].tree_size,
                root_hash: tampered_root,
            }],
        };
        let receipt = verify_inclusion(
            &policy,
            Some(&proofs[0]),
            &proofs[0].leaf_hash,
            "conn-1",
            "artifact-1",
            "single-leaf-root-mismatch",
            "ts",
        );

        assert!(!receipt.verified);
        assert!(!receipt.log_root_matched);
        assert!(!receipt.proof_valid);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::RootNotPinned { .. })
        ));
    }

    #[test]
    fn optional_policy_rejects_provided_leaf_mismatch_before_root_check() {
        let (root, proofs) = build_test_tree(&["a", "b"]);
        let policy = TransparencyPolicy {
            required: false,
            pinned_roots: vec![LogRoot {
                tree_size: proofs[0].tree_size,
                root_hash: root,
            }],
        };
        let tampered_leaf = tamper_same_length_hash(&proofs[0].leaf_hash);
        let receipt = verify_inclusion(
            &policy,
            Some(&proofs[0]),
            &tampered_leaf,
            "conn-1",
            "artifact-1",
            "optional-leaf-mismatch",
            "ts",
        );

        assert!(!receipt.verified);
        assert!(!receipt.log_root_matched);
        assert!(!receipt.proof_valid);
        assert!(matches!(
            receipt.failure_reason,
            Some(ProofFailure::LeafMismatch { .. })
        ));
    }

    #[test]
    fn serde_rejects_inclusion_proof_missing_leaf_hash() {
        let json = serde_json::json!({
            "leaf_index": 0,
            "tree_size": 1,
            "audit_path": []
        });

        let err = serde_json::from_value::<InclusionProof>(json).unwrap_err();

        assert!(err.to_string().contains("leaf_hash"));
    }

    #[test]
    fn serde_rejects_unknown_proof_failure_variant() {
        let err =
            serde_json::from_str::<ProofFailure>(r#""hash_algorithm_downgrade""#).unwrap_err();

        assert!(err.to_string().contains("unknown variant"));
    }

    #[test]
    fn empty_tree_builds_empty_root_and_no_proofs() {
        let (root, proofs) = build_test_tree(&[]);

        assert!(root.is_empty());
        assert!(proofs.is_empty());
    }

    // === Serde ===

    #[test]
    fn serde_roundtrip_receipt() {
        let receipt = ProofReceipt {
            connector_id: "conn-1".into(),
            artifact_id: "art-1".into(),
            verified: true,
            log_root_matched: true,
            proof_valid: true,
            failure_reason: None,
            trace_id: "t1".into(),
            timestamp: "ts".into(),
        };
        let json = serde_json::to_string(&receipt).expect("should succeed");
        let parsed: ProofReceipt = serde_json::from_str(&json).expect("should succeed");
        assert_eq!(receipt, parsed);
    }

    #[test]
    fn serde_roundtrip_proof() {
        let (_, proofs) = build_test_tree(&["a", "b"]);
        let json = serde_json::to_string(&proofs[0]).expect("should succeed");
        let parsed: InclusionProof = serde_json::from_str(&json).expect("should succeed");
        assert_eq!(proofs[0], parsed);
    }

    // === Error display ===

    #[test]
    fn error_display_messages() {
        let e1 = TransparencyError::ProofMissing;
        assert!(e1.to_string().contains("TLOG_PROOF_MISSING"));

        let e2 = TransparencyError::RootNotPinned {
            root_hash: "abc".into(),
        };
        assert!(e2.to_string().contains("TLOG_ROOT_NOT_PINNED"));

        let e3 = TransparencyError::PathInvalid {
            computed: "a".into(),
            expected: "b".into(),
        };
        assert!(e3.to_string().contains("TLOG_PATH_INVALID"));

        let e4 = TransparencyError::LeafMismatch {
            expected: "a".into(),
            actual: "b".into(),
        };
        assert!(e4.to_string().contains("TLOG_LEAF_MISMATCH"));
    }

    // === ProofFailure display ===

    #[test]
    fn failure_display() {
        assert!(
            ProofFailure::ProofMissing
                .to_string()
                .contains("TLOG_PROOF_MISSING")
        );
        let f = ProofFailure::RootNotPinned {
            root_hash: "x".into(),
        };
        assert!(f.to_string().contains("TLOG_ROOT_NOT_PINNED"));
        let f2 = ProofFailure::InvalidArtifactId {
            reason: "bad".into(),
        };
        assert!(f2.to_string().contains("TLOG_ARTIFACT_INVALID"));
        let f3 = ProofFailure::InvalidConnectorId {
            reason: "bad".into(),
        };
        assert!(f3.to_string().contains("TLOG_CONNECTOR_INVALID"));
    }
}
