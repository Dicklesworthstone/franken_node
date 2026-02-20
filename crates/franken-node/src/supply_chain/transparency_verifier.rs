//! Transparency-log inclusion proof checks (bd-1z9s).
//!
//! Verifies Merkle tree inclusion proofs for connector install/update
//! pipelines. Install/update fails if the required proof is missing
//! or invalid. Log roots are pinned per policy.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::hash::{DefaultHasher, Hash, Hasher};

// ── Hash helper ─────────────────────────────────────────────────────

/// Compute a deterministic hash of two hex strings combined.
/// In production this would use SHA-256; here we use SipHash.
fn hash_pair(left: &str, right: &str) -> String {
    let mut hasher = DefaultHasher::new();
    left.hash(&mut hasher);
    right.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

/// Compute the leaf hash for a piece of data.
pub fn leaf_hash(data: &str) -> String {
    let mut hasher = DefaultHasher::new();
    "leaf:".hash(&mut hasher);
    data.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
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
    /// Check if a root hash is in the pinned set.
    pub fn is_root_pinned(&self, root_hash: &str) -> bool {
        self.pinned_roots.iter().any(|r| r.root_hash == root_hash)
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
        if index % 2 == 0 {
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

    // Check leaf hash matches artifact hash
    if proof.leaf_hash != artifact_hash {
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
    let root_pinned = policy.is_root_pinned(&computed_root);
    if !root_pinned {
        return ProofReceipt {
            connector_id: connector_id.into(),
            artifact_id: artifact_id.into(),
            verified: false,
            log_root_matched: false,
            proof_valid: true,
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
        level.push(level.last().cloned().unwrap_or_default());
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
            next.push(h);
        }
        level = next;
        levels.push(level.clone());
    }

    let root = level[0].clone();

    // Build inclusion proofs for each original leaf
    let mut proofs = Vec::new();
    for i in 0..n {
        let mut audit_path = Vec::new();
        let mut idx = i;
        for lvl in &levels[..levels.len() - 1] {
            let sibling_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            if sibling_idx < lvl.len() {
                audit_path.push(lvl[sibling_idx].clone());
            }
            idx /= 2;
        }
        proofs.push(InclusionProof {
            leaf_index: i as u64,
            tree_size: n as u64,
            leaf_hash: leaf_hashes[i].clone(),
            audit_path,
        });
    }

    (root, proofs)
}

// ── Tests ───────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy(root: &str) -> TransparencyPolicy {
        TransparencyPolicy {
            required: true,
            pinned_roots: vec![LogRoot {
                tree_size: 4,
                root_hash: root.to_string(),
            }],
        }
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
        let policy = test_policy(&root);
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
    fn unpinned_root_rejected() {
        let (_, proofs) = build_test_tree(&["a", "b", "c", "d"]);
        let policy = test_policy("wrong_root_hash");
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
        let policy = test_policy(&root);
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
    fn tampered_proof_fails() {
        let (root, proofs) = build_test_tree(&["a", "b", "c", "d"]);
        let policy = test_policy(&root);
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
        let policy = test_policy(&root);
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
        let policy = test_policy(&root);
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
        let json = serde_json::to_string(&receipt).unwrap();
        let parsed: ProofReceipt = serde_json::from_str(&json).unwrap();
        assert_eq!(receipt, parsed);
    }

    #[test]
    fn serde_roundtrip_proof() {
        let (_, proofs) = build_test_tree(&["a", "b"]);
        let json = serde_json::to_string(&proofs[0]).unwrap();
        let parsed: InclusionProof = serde_json::from_str(&json).unwrap();
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
    }
}
