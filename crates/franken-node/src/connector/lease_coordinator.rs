//! bd-2vs4: Deterministic lease coordinator selection and quorum verification.
//!
//! Coordinator selection is deterministic via weighted hashing.
//! Quorum thresholds vary by safety tier. Failures are classified.

use std::collections::BTreeSet;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

/// A candidate node for coordinator selection.
#[derive(Debug, Clone)]
pub struct CoordinatorCandidate {
    pub node_id: String,
    pub weight: u64,
}

/// Result of deterministic coordinator selection.
#[derive(Debug, Clone)]
pub struct CoordinatorSelection {
    pub candidates: Vec<String>,
    pub lease_id: String,
    pub selected: String,
    pub trace_id: String,
}

/// Quorum thresholds per safety tier.
#[derive(Debug, Clone)]
pub struct QuorumConfig {
    pub standard_threshold: u32,
    pub risky_threshold: u32,
    pub dangerous_threshold: u32,
}

impl QuorumConfig {
    pub fn default_config() -> Self {
        Self {
            standard_threshold: 1,
            risky_threshold: 2,
            dangerous_threshold: 3,
        }
    }

    pub fn threshold_for_tier(&self, tier: &str) -> u32 {
        match tier {
            "Standard" => self.standard_threshold,
            "Risky" => self.risky_threshold,
            "Dangerous" => self.dangerous_threshold,
            _ => self.dangerous_threshold, // default to strictest
        }
    }
}

/// A signature from a quorum member.
#[derive(Debug, Clone)]
pub struct QuorumSignature {
    pub signer_id: String,
    pub signature: String,
}

/// Classification of verification failures.
///
/// Error codes: `LC_BELOW_QUORUM`, `LC_INVALID_SIGNATURE`, `LC_UNKNOWN_SIGNER`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VerificationFailure {
    BelowQuorum { required: u32, received: u32 },
    InvalidSignature { signer_id: String },
    UnknownSigner { signer_id: String },
}

impl VerificationFailure {
    pub fn code(&self) -> &'static str {
        match self {
            Self::BelowQuorum { .. } => "LC_BELOW_QUORUM",
            Self::InvalidSignature { .. } => "LC_INVALID_SIGNATURE",
            Self::UnknownSigner { .. } => "LC_UNKNOWN_SIGNER",
        }
    }
}

/// Result of quorum verification.
#[derive(Debug, Clone)]
pub struct QuorumVerification {
    pub lease_id: String,
    pub tier: String,
    pub required: u32,
    pub received: u32,
    pub passed: bool,
    pub failures: Vec<VerificationFailure>,
    pub trace_id: String,
    pub timestamp: String,
}

/// Error for coordinator operations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinatorError {
    NoCandidates,
}

impl CoordinatorError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::NoCandidates => "LC_NO_CANDIDATES",
        }
    }
}

impl std::fmt::Display for CoordinatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoCandidates => write!(f, "LC_NO_CANDIDATES"),
        }
    }
}

/// Deterministic coordinator selection via weighted hash.
///
/// INV-LC-DETERMINISTIC: same inputs → same selection.
/// INV-LC-REPLAY: identical on replay.
pub fn select_coordinator(
    candidates: &[CoordinatorCandidate],
    lease_id: &str,
    trace_id: &str,
) -> Result<CoordinatorSelection, CoordinatorError> {
    if candidates.is_empty() {
        return Err(CoordinatorError::NoCandidates);
    }

    // Deterministic: hash(lease_id || node_id) * weight → highest score wins
    let mut best_node = String::new();
    let mut best_score: u64 = 0;

    for candidate in candidates {
        let mut hasher = DefaultHasher::new();
        lease_id.hash(&mut hasher);
        candidate.node_id.hash(&mut hasher);
        let hash = hasher.finish();
        // Multiply by weight to favor higher-weighted candidates
        let score = hash.wrapping_mul(candidate.weight.max(1));
        if best_node.is_empty() || score > best_score {
            best_score = score;
            best_node = candidate.node_id.clone();
        }
    }

    Ok(CoordinatorSelection {
        candidates: candidates.iter().map(|c| c.node_id.clone()).collect(),
        lease_id: lease_id.to_string(),
        selected: best_node,
        trace_id: trace_id.to_string(),
    })
}

/// Verify quorum signatures for a lease operation.
///
/// INV-LC-QUORUM-TIER: threshold depends on safety tier.
/// INV-LC-VERIFY-CLASSIFIED: failures are classified by type.
#[allow(clippy::too_many_arguments)]
pub fn verify_quorum(
    config: &QuorumConfig,
    lease_id: &str,
    tier: &str,
    signatures: &[QuorumSignature],
    known_signers: &[String],
    expected_content_hash: &str,
    trace_id: &str,
    timestamp: &str,
) -> QuorumVerification {
    let threshold = config.threshold_for_tier(tier);
    let known_set: BTreeSet<&str> = known_signers.iter().map(|s| s.as_str()).collect();
    let mut failures = Vec::new();
    let mut valid_count: u32 = 0;
    let mut seen_signers = BTreeSet::new();

    for sig in signatures {
        // Check for unknown signer
        if !known_set.contains(sig.signer_id.as_str()) {
            failures.push(VerificationFailure::UnknownSigner {
                signer_id: sig.signer_id.clone(),
            });
            continue;
        }

        // Skip duplicate signers
        if !seen_signers.insert(sig.signer_id.clone()) {
            continue;
        }

        // Simulate signature verification: H(signer_id || ":" || content_hash)
        let mut hasher = DefaultHasher::new();
        sig.signer_id.hash(&mut hasher);
        ":".hash(&mut hasher);
        expected_content_hash.hash(&mut hasher);
        let expected_sig = format!("{:016x}", hasher.finish());

        if sig.signature == expected_sig {
            valid_count += 1;
        } else {
            failures.push(VerificationFailure::InvalidSignature {
                signer_id: sig.signer_id.clone(),
            });
        }
    }

    if valid_count < threshold {
        failures.push(VerificationFailure::BelowQuorum {
            required: threshold,
            received: valid_count,
        });
    }

    let passed = valid_count >= threshold
        && failures
            .iter()
            .all(|f| !matches!(f, VerificationFailure::BelowQuorum { .. }));

    QuorumVerification {
        lease_id: lease_id.to_string(),
        tier: tier.to_string(),
        required: threshold,
        received: valid_count,
        passed,
        failures,
        trace_id: trace_id.to_string(),
        timestamp: timestamp.to_string(),
    }
}

/// Helper: compute a simulated signature for testing.
pub fn compute_test_signature(signer_id: &str, content_hash: &str) -> String {
    let mut hasher = DefaultHasher::new();
    signer_id.hash(&mut hasher);
    ":".hash(&mut hasher);
    content_hash.hash(&mut hasher);
    format!("{:016x}", hasher.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn candidates() -> Vec<CoordinatorCandidate> {
        vec![
            CoordinatorCandidate {
                node_id: "node-a".into(),
                weight: 10,
            },
            CoordinatorCandidate {
                node_id: "node-b".into(),
                weight: 5,
            },
            CoordinatorCandidate {
                node_id: "node-c".into(),
                weight: 8,
            },
        ]
    }

    fn qconfig() -> QuorumConfig {
        QuorumConfig::default_config()
    }

    fn valid_sig(signer: &str, content: &str) -> QuorumSignature {
        QuorumSignature {
            signer_id: signer.into(),
            signature: compute_test_signature(signer, content),
        }
    }

    #[test]
    fn deterministic_selection() {
        let s1 = select_coordinator(&candidates(), "lease-1", "tr").unwrap();
        let s2 = select_coordinator(&candidates(), "lease-1", "tr").unwrap();
        assert_eq!(s1.selected, s2.selected);
    }

    #[test]
    fn different_lease_may_select_different() {
        let s1 = select_coordinator(&candidates(), "lease-1", "tr").unwrap();
        let s2 = select_coordinator(&candidates(), "lease-2", "tr").unwrap();
        // May or may not differ, but both should succeed
        assert!(!s1.selected.is_empty());
        assert!(!s2.selected.is_empty());
    }

    #[test]
    fn no_candidates_errors() {
        let err = select_coordinator(&[], "lease-1", "tr").unwrap_err();
        assert_eq!(err.code(), "LC_NO_CANDIDATES");
    }

    #[test]
    fn single_candidate_selected() {
        let cands = vec![CoordinatorCandidate {
            node_id: "only".into(),
            weight: 1,
        }];
        let s = select_coordinator(&cands, "lease-1", "tr").unwrap();
        assert_eq!(s.selected, "only");
    }

    #[test]
    fn quorum_passes_standard() {
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", "hash1")];
        let v = verify_quorum(
            &qconfig(),
            "l1",
            "Standard",
            &sigs,
            &known,
            "hash1",
            "tr",
            "ts",
        );
        assert!(v.passed);
        assert_eq!(v.required, 1);
        assert_eq!(v.received, 1);
    }

    #[test]
    fn quorum_passes_risky() {
        let known = vec!["s1".to_string(), "s2".to_string()];
        let sigs = vec![valid_sig("s1", "hash1"), valid_sig("s2", "hash1")];
        let v = verify_quorum(
            &qconfig(),
            "l1",
            "Risky",
            &sigs,
            &known,
            "hash1",
            "tr",
            "ts",
        );
        assert!(v.passed);
        assert_eq!(v.required, 2);
    }

    #[test]
    fn quorum_fails_below_threshold() {
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", "hash1")];
        let v = verify_quorum(
            &qconfig(),
            "l1",
            "Risky",
            &sigs,
            &known,
            "hash1",
            "tr",
            "ts",
        );
        assert!(!v.passed);
        let below = v
            .failures
            .iter()
            .any(|f| matches!(f, VerificationFailure::BelowQuorum { .. }));
        assert!(below);
    }

    #[test]
    fn unknown_signer_classified() {
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", "h"), valid_sig("unknown", "h")];
        let v = verify_quorum(&qconfig(), "l1", "Standard", &sigs, &known, "h", "tr", "ts");
        let unknown = v
            .failures
            .iter()
            .any(|f| matches!(f, VerificationFailure::UnknownSigner { .. }));
        assert!(unknown);
    }

    #[test]
    fn invalid_signature_classified() {
        let known = vec!["s1".to_string()];
        let sigs = vec![QuorumSignature {
            signer_id: "s1".into(),
            signature: "wrong".into(),
        }];
        let v = verify_quorum(&qconfig(), "l1", "Standard", &sigs, &known, "h", "tr", "ts");
        let invalid = v
            .failures
            .iter()
            .any(|f| matches!(f, VerificationFailure::InvalidSignature { .. }));
        assert!(invalid);
    }

    #[test]
    fn dangerous_requires_three() {
        let known = vec!["s1".to_string(), "s2".to_string()];
        let sigs = vec![valid_sig("s1", "h"), valid_sig("s2", "h")];
        let v = verify_quorum(
            &qconfig(),
            "l1",
            "Dangerous",
            &sigs,
            &known,
            "h",
            "tr",
            "ts",
        );
        assert!(!v.passed);
        assert_eq!(v.required, 3);
    }

    #[test]
    fn dangerous_passes_with_three() {
        let known = vec!["s1".to_string(), "s2".to_string(), "s3".to_string()];
        let sigs = vec![
            valid_sig("s1", "h"),
            valid_sig("s2", "h"),
            valid_sig("s3", "h"),
        ];
        let v = verify_quorum(
            &qconfig(),
            "l1",
            "Dangerous",
            &sigs,
            &known,
            "h",
            "tr",
            "ts",
        );
        assert!(v.passed);
        assert_eq!(v.received, 3);
    }

    #[test]
    fn duplicate_signers_ignored() {
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", "h"), valid_sig("s1", "h")];
        let v = verify_quorum(&qconfig(), "l1", "Standard", &sigs, &known, "h", "tr", "ts");
        assert_eq!(v.received, 1); // deduped
    }

    #[test]
    fn default_config_tiers() {
        let c = QuorumConfig::default_config();
        assert_eq!(c.standard_threshold, 1);
        assert_eq!(c.risky_threshold, 2);
        assert_eq!(c.dangerous_threshold, 3);
    }

    #[test]
    fn verification_has_trace() {
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", "h")];
        let v = verify_quorum(
            &qconfig(),
            "l1",
            "Standard",
            &sigs,
            &known,
            "h",
            "trace-x",
            "ts",
        );
        assert_eq!(v.trace_id, "trace-x");
    }

    #[test]
    fn failure_codes_correct() {
        assert_eq!(
            VerificationFailure::BelowQuorum {
                required: 0,
                received: 0
            }
            .code(),
            "LC_BELOW_QUORUM"
        );
        assert_eq!(
            VerificationFailure::InvalidSignature {
                signer_id: "x".into()
            }
            .code(),
            "LC_INVALID_SIGNATURE"
        );
        assert_eq!(
            VerificationFailure::UnknownSigner {
                signer_id: "x".into()
            }
            .code(),
            "LC_UNKNOWN_SIGNER"
        );
    }

    #[test]
    fn selection_replay_identical() {
        let c = candidates();
        let r1 = select_coordinator(&c, "lease-replay", "tr").unwrap();
        let r2 = select_coordinator(&c, "lease-replay", "tr").unwrap();
        assert_eq!(r1.selected, r2.selected);
        assert_eq!(r1.candidates, r2.candidates);
    }
}
