//! bd-2vs4: Deterministic lease coordinator selection and quorum verification.
//!
//! Coordinator selection is deterministic via weighted hashing.
//! Quorum thresholds vary by safety tier. Failures are classified.

use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};

// Hardening: bounded capacity for failure collections
const MAX_VERIFICATION_FAILURES: usize = 256;

fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len() - cap + 1;
        items.drain(0..overflow);
    }
    items.push(item);
}

/// A candidate node for coordinator selection.
#[derive(Debug, Clone)]
pub struct CoordinatorCandidate {
    pub node_id: String,
    /// Zero weight means the candidate is ineligible for selection.
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
        let configured = match tier {
            "Standard" => self.standard_threshold,
            "Risky" => self.risky_threshold,
            "Dangerous" => self.dangerous_threshold,
            _ => self.dangerous_threshold, // default to strictest
        };
        configured.max(1)
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

#[derive(Debug, Clone, Copy, Default)]
struct SignerVerificationState {
    has_valid_signature: bool,
    has_invalid_signature: bool,
}

fn identity_is_canonical(identity: &str) -> bool {
    let trimmed = identity.trim();
    !trimmed.is_empty()
        && trimmed == identity
        && !identity.contains('\0')
        && !identity.chars().any(char::is_whitespace)
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
    if !identity_is_canonical(lease_id) || !identity_is_canonical(trace_id) {
        return Err(CoordinatorError::NoCandidates);
    }

    let mut eligible_candidates: Vec<&CoordinatorCandidate> = candidates
        .iter()
        .filter(|candidate| candidate.weight > 0 && identity_is_canonical(&candidate.node_id))
        .collect();

    eligible_candidates.sort_by(|left, right| {
        left.node_id
            .cmp(&right.node_id)
            .then(left.weight.cmp(&right.weight))
    });

    if eligible_candidates.is_empty() {
        return Err(CoordinatorError::NoCandidates);
    }

    // Deterministic: hash(lease_id || node_id) * weight → highest score wins
    let mut best_node = String::new();
    let mut best_score: u128 = 0;

    for candidate in &eligible_candidates {
        let mut h = Sha256::new();
        h.update(b"lease_coord_hash_v1:");
        h.update(
            u64::try_from(lease_id.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        h.update(lease_id.as_bytes());
        h.update(
            u64::try_from(candidate.node_id.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        h.update(candidate.node_id.as_bytes());
        let digest = h.finalize();
        let hash = u64::from_le_bytes(digest[..8].try_into().unwrap_or([0u8; 8]));
        // Multiply by weight to favor higher-weighted candidates
        let score = u128::from(hash) * u128::from(candidate.weight);
        if best_node.is_empty()
            || score > best_score
            || (score == best_score && candidate.node_id < best_node)
        {
            best_score = score;
            best_node = candidate.node_id.clone();
        }
    }

    Ok(CoordinatorSelection {
        candidates: eligible_candidates
            .iter()
            .map(|candidate| candidate.node_id.clone())
            .collect(),
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
    let known_set: BTreeSet<&str> = known_signers
        .iter()
        .map(|s| s.as_str())
        .filter(|signer_id| identity_is_canonical(signer_id))
        .collect();
    let mut failures = Vec::new();
    let mut signer_states: BTreeMap<String, SignerVerificationState> = BTreeMap::new();
    let mut unknown_signers = BTreeSet::new();
    let lease_id_is_canonical = identity_is_canonical(lease_id);
    let tier_is_canonical = identity_is_canonical(tier);
    let content_hash_is_canonical = identity_is_canonical(expected_content_hash);
    let trace_id_is_canonical = identity_is_canonical(trace_id);
    let timestamp_is_canonical = identity_is_canonical(timestamp);

    for sig in signatures {
        // Check for unknown signer
        if !identity_is_canonical(sig.signer_id.as_str())
            || !known_set.contains(sig.signer_id.as_str())
        {
            unknown_signers.insert(sig.signer_id.clone());
            continue;
        }

        let signer_state = signer_states.entry(sig.signer_id.clone()).or_default();
        if !lease_id_is_canonical
            || !tier_is_canonical
            || !content_hash_is_canonical
            || !trace_id_is_canonical
            || !timestamp_is_canonical
        {
            signer_state.has_invalid_signature = true;
            continue;
        }

        // Simulate signature verification: H(signer_id || content_hash) length-prefixed
        let mut h = Sha256::new();
        h.update(b"lease_coord_sign_v1:");
        h.update(
            u64::try_from(sig.signer_id.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        h.update(sig.signer_id.as_bytes());
        h.update(
            u64::try_from(expected_content_hash.len())
                .unwrap_or(u64::MAX)
                .to_le_bytes(),
        );
        h.update(expected_content_hash.as_bytes());
        let digest = h.finalize();
        let expected_sig = hex::encode(digest);

        if crate::security::constant_time::ct_eq_bytes(
            sig.signature.as_bytes(),
            expected_sig.as_bytes(),
        ) {
            signer_state.has_valid_signature = true;
        } else {
            signer_state.has_invalid_signature = true;
        }
    }

    // Hardening: use bounded pushes to prevent unbounded failure collection growth
    for signer_id in unknown_signers {
        push_bounded(
            &mut failures,
            VerificationFailure::UnknownSigner { signer_id },
            MAX_VERIFICATION_FAILURES,
        );
    }

    for (signer_id, state) in &signer_states {
        if state.has_invalid_signature {
            push_bounded(
                &mut failures,
                VerificationFailure::InvalidSignature {
                    signer_id: signer_id.clone(),
                },
                MAX_VERIFICATION_FAILURES,
            );
        }
    }

    let valid_count = signer_states
        .values()
        .filter(|state| state.has_valid_signature)
        .count()
        .try_into()
        .unwrap_or(u32::MAX);

    if valid_count < threshold {
        // Hardening: use bounded push to prevent unbounded failure collection growth
        push_bounded(
            &mut failures,
            VerificationFailure::BelowQuorum {
                required: threshold,
                received: valid_count,
            },
            MAX_VERIFICATION_FAILURES,
        );
    }

    // Fail closed if any verification failure was classified, even when the
    // batch also contains enough valid signatures to meet the quorum count.
    let passed = valid_count >= threshold && failures.is_empty();

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
    let mut h = Sha256::new();
    h.update(b"lease_coord_sign_v1:");
    h.update(
        u64::try_from(signer_id.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    h.update(signer_id.as_bytes());
    h.update(
        u64::try_from(content_hash.len())
            .unwrap_or(u64::MAX)
            .to_le_bytes(),
    );
    h.update(content_hash.as_bytes());
    let digest = h.finalize();
    hex::encode(digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::constant_time;

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
    fn negative_test_signature_is_bound_to_signer_identity() {
        assert_ne!(
            compute_test_signature("s1", "payload-a"),
            compute_test_signature("s2", "payload-a")
        );
    }

    #[test]
    fn negative_test_signature_is_bound_to_payload_identity() {
        assert_ne!(
            compute_test_signature("s1", "payload-a"),
            compute_test_signature("s1", "payload-b")
        );
    }

    #[test]
    fn negative_test_signature_length_prefix_prevents_concatenation_collision() {
        assert_ne!(
            compute_test_signature("ab", "c"),
            compute_test_signature("a", "bc")
        );
    }

    #[test]
    fn negative_test_signature_preserves_leading_space_in_signer() {
        assert_ne!(
            compute_test_signature("s1", "payload-a"),
            compute_test_signature(" s1", "payload-a")
        );
    }

    #[test]
    fn negative_test_signature_preserves_trailing_space_in_payload() {
        assert_ne!(
            compute_test_signature("s1", "payload-a"),
            compute_test_signature("s1", "payload-a ")
        );
    }

    #[test]
    fn negative_test_signature_preserves_empty_payload_boundary() {
        assert_ne!(
            compute_test_signature("s1", ""),
            compute_test_signature("s", "1")
        );
    }

    #[test]
    fn negative_test_signature_preserves_empty_signer_boundary() {
        assert_ne!(
            compute_test_signature("", "s1"),
            compute_test_signature("s", "1")
        );
    }

    fn is_unknown_for(failure: &VerificationFailure, expected: &str) -> bool {
        let observed = match failure {
            VerificationFailure::UnknownSigner { signer_id } => signer_id.as_str(),
            _ => return false,
        };
        observed == expected
    }

    fn is_invalid_for(failure: &VerificationFailure, expected: &str) -> bool {
        let observed = match failure {
            VerificationFailure::InvalidSignature { signer_id } => signer_id.as_str(),
            _ => return false,
        };
        observed == expected
    }

    #[test]
    fn negative_empty_identity_is_not_canonical() {
        assert!(!identity_is_canonical(""));
    }

    #[test]
    fn negative_space_only_identity_is_not_canonical() {
        assert!(!identity_is_canonical("   "));
    }

    #[test]
    fn negative_tab_only_identity_is_not_canonical() {
        assert!(!identity_is_canonical("\t"));
    }

    #[test]
    fn negative_newline_only_identity_is_not_canonical() {
        assert!(!identity_is_canonical("\n"));
    }

    #[test]
    fn negative_leading_space_identity_is_not_canonical() {
        assert!(!identity_is_canonical(" node-a"));
    }

    #[test]
    fn negative_trailing_space_identity_is_not_canonical() {
        assert!(!identity_is_canonical("node-a "));
    }

    #[test]
    fn negative_tab_padded_identity_is_not_canonical() {
        assert!(!identity_is_canonical("\tnode-a\t"));
    }

    #[test]
    fn negative_internal_space_identity_is_not_canonical() {
        assert!(!identity_is_canonical("node a"));
    }

    #[test]
    fn negative_internal_tab_identity_is_not_canonical() {
        assert!(!identity_is_canonical("node\ta"));
    }

    #[test]
    fn negative_internal_newline_identity_is_not_canonical() {
        assert!(!identity_is_canonical("node\na"));
    }

    #[test]
    fn negative_internal_carriage_return_identity_is_not_canonical() {
        assert!(!identity_is_canonical("node\ra"));
    }

    #[test]
    fn negative_crlf_identity_is_not_canonical() {
        assert!(!identity_is_canonical("node\r\na"));
    }

    #[test]
    fn negative_form_feed_identity_is_not_canonical() {
        assert!(!identity_is_canonical("node\u{000c}a"));
    }

    fn custom_threshold_config() -> QuorumConfig {
        QuorumConfig {
            standard_threshold: 2,
            risky_threshold: 5,
            dangerous_threshold: 7,
        }
    }

    fn zero_threshold_config() -> QuorumConfig {
        QuorumConfig {
            standard_threshold: 0,
            risky_threshold: 0,
            dangerous_threshold: 0,
        }
    }

    #[test]
    fn negative_empty_tier_uses_dangerous_threshold() {
        assert_eq!(custom_threshold_config().threshold_for_tier(""), 7);
    }

    #[test]
    fn negative_space_only_tier_uses_dangerous_threshold() {
        assert_eq!(custom_threshold_config().threshold_for_tier("   "), 7);
    }

    #[test]
    fn negative_leading_space_standard_tier_uses_dangerous_threshold() {
        assert_eq!(custom_threshold_config().threshold_for_tier(" Standard"), 7);
    }

    #[test]
    fn negative_trailing_space_risky_tier_uses_dangerous_threshold() {
        assert_eq!(custom_threshold_config().threshold_for_tier("Risky "), 7);
    }

    #[test]
    fn negative_tab_padded_dangerous_tier_uses_dangerous_threshold() {
        assert_eq!(
            custom_threshold_config().threshold_for_tier("\tDangerous\t"),
            7
        );
    }

    #[test]
    fn negative_lowercase_standard_tier_uses_dangerous_threshold() {
        assert_eq!(custom_threshold_config().threshold_for_tier("standard"), 7);
    }

    #[test]
    fn negative_newline_risky_tier_uses_dangerous_threshold() {
        assert_eq!(custom_threshold_config().threshold_for_tier("Risky\n"), 7);
    }

    #[test]
    fn negative_internal_space_standard_tier_uses_dangerous_threshold() {
        assert_eq!(custom_threshold_config().threshold_for_tier("Stan dard"), 7);
    }

    #[test]
    fn negative_internal_tab_standard_tier_uses_dangerous_threshold() {
        assert_eq!(
            custom_threshold_config().threshold_for_tier("Stan\tdard"),
            7
        );
    }

    #[test]
    fn negative_internal_newline_standard_tier_uses_dangerous_threshold() {
        assert_eq!(
            custom_threshold_config().threshold_for_tier("Stan\ndard"),
            7
        );
    }

    #[test]
    fn negative_internal_carriage_standard_tier_uses_dangerous_threshold() {
        assert_eq!(
            custom_threshold_config().threshold_for_tier("Stan\rdard"),
            7
        );
    }

    #[test]
    fn negative_internal_crlf_standard_tier_uses_dangerous_threshold() {
        assert_eq!(
            custom_threshold_config().threshold_for_tier("Stan\r\ndard"),
            7
        );
    }

    #[test]
    fn negative_internal_form_feed_standard_tier_uses_dangerous_threshold() {
        assert_eq!(
            custom_threshold_config().threshold_for_tier("Stan\u{000c}dard"),
            7
        );
    }

    #[test]
    fn negative_zero_standard_threshold_is_clamped_to_one() {
        assert_eq!(zero_threshold_config().threshold_for_tier("Standard"), 1);
    }

    #[test]
    fn negative_zero_risky_threshold_is_clamped_to_one() {
        assert_eq!(zero_threshold_config().threshold_for_tier("Risky"), 1);
    }

    #[test]
    fn negative_zero_dangerous_threshold_is_clamped_to_one() {
        assert_eq!(zero_threshold_config().threshold_for_tier("Dangerous"), 1);
    }

    #[test]
    fn negative_zero_unknown_tier_threshold_is_clamped_to_one() {
        assert_eq!(zero_threshold_config().threshold_for_tier("Unknown"), 1);
    }

    #[test]
    fn negative_zero_empty_tier_threshold_is_clamped_to_one() {
        assert_eq!(zero_threshold_config().threshold_for_tier(""), 1);
    }

    #[test]
    fn negative_zero_padded_standard_tier_threshold_is_clamped_to_one() {
        assert_eq!(zero_threshold_config().threshold_for_tier(" Standard "), 1);
    }

    #[test]
    fn negative_zero_lowercase_dangerous_tier_threshold_is_clamped_to_one() {
        assert_eq!(zero_threshold_config().threshold_for_tier("dangerous"), 1);
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
        assert!(!v.passed, "unknown signers must fail quorum verification");
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
        assert!(
            !v.passed,
            "invalid signatures must fail quorum verification"
        );
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
    fn invalid_duplicate_before_valid_signature_fails_closed() {
        let known = vec!["s1".to_string()];
        let sigs = vec![
            QuorumSignature {
                signer_id: "s1".into(),
                signature: "wrong".into(),
            },
            valid_sig("s1", "h"),
        ];
        let v = verify_quorum(&qconfig(), "l1", "Standard", &sigs, &known, "h", "tr", "ts");
        assert!(
            !v.passed,
            "a signer with any forged duplicate must fail quorum verification"
        );
        assert_eq!(v.received, 1);
        assert!(
            v.failures
                .iter()
                .any(|f| matches!(f, VerificationFailure::InvalidSignature { .. }))
        );
        assert!(
            !v.failures
                .iter()
                .any(|f| matches!(f, VerificationFailure::BelowQuorum { .. })),
            "meeting the threshold should not mask duplicate-signature tampering as below-quorum"
        );
    }

    #[test]
    fn invalid_duplicate_after_valid_signature_fails_closed() {
        let known = vec!["s1".to_string()];
        let sigs = vec![
            valid_sig("s1", "h"),
            QuorumSignature {
                signer_id: "s1".into(),
                signature: "wrong".into(),
            },
        ];
        let v = verify_quorum(&qconfig(), "l1", "Standard", &sigs, &known, "h", "tr", "ts");
        assert!(
            !v.passed,
            "a later forged duplicate must not be washed out by an earlier valid signature"
        );
        assert_eq!(v.received, 1);
        assert!(
            v.failures
                .iter()
                .any(|f| matches!(f, VerificationFailure::InvalidSignature { signer_id } if signer_id == "s1"))
        );
        assert!(
            !v.failures
                .iter()
                .any(|f| matches!(f, VerificationFailure::BelowQuorum { .. })),
            "meeting the threshold should not mask duplicate-signature tampering as below-quorum"
        );
    }

    #[test]
    fn mixed_valid_and_invalid_signatures_fail_closed() {
        let known = vec!["s1".to_string(), "s2".to_string()];
        let sigs = vec![
            valid_sig("s1", "h"),
            QuorumSignature {
                signer_id: "s2".into(),
                signature: "wrong".into(),
            },
        ];

        let v = verify_quorum(&qconfig(), "l1", "Standard", &sigs, &known, "h", "tr", "ts");

        assert!(
            !v.passed,
            "any invalid signature should fail quorum verification"
        );
        assert_eq!(
            v.received, 1,
            "valid quorum count should still be reported accurately"
        );
        assert!(
            v.failures
                .iter()
                .any(|f| matches!(f, VerificationFailure::InvalidSignature { signer_id } if signer_id == "s2"))
        );
        assert!(
            !v.failures
                .iter()
                .any(|f| matches!(f, VerificationFailure::BelowQuorum { .. })),
            "meeting the threshold should not mask the invalid-signature failure as below-quorum"
        );
    }

    #[test]
    fn mixed_valid_and_unknown_signers_fail_closed() {
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", "h"), valid_sig("stranger", "h")];

        let v = verify_quorum(&qconfig(), "l1", "Standard", &sigs, &known, "h", "tr", "ts");

        assert!(!v.passed, "unknown signers should fail quorum verification");
        assert_eq!(
            v.received, 1,
            "only known valid signers should count toward quorum"
        );
        assert!(
            v.failures
                .iter()
                .any(|f| matches!(f, VerificationFailure::UnknownSigner { signer_id } if signer_id == "stranger"))
        );
        assert!(
            !v.failures
                .iter()
                .any(|f| matches!(f, VerificationFailure::BelowQuorum { .. })),
            "threshold satisfaction should not override unknown-signer failure"
        );
    }

    #[test]
    fn default_config_tiers() {
        let c = QuorumConfig::default_config();
        assert_eq!(c.standard_threshold, 1);
        assert_eq!(c.risky_threshold, 2);
        assert_eq!(c.dangerous_threshold, 3);
    }

    #[test]
    fn zero_threshold_configuration_fails_closed() {
        let config = QuorumConfig {
            standard_threshold: 0,
            risky_threshold: 0,
            dangerous_threshold: 0,
        };
        let known = vec!["s1".to_string()];
        let sigs = Vec::<QuorumSignature>::new();

        let v = verify_quorum(&config, "l1", "Standard", &sigs, &known, "h", "tr", "ts");

        assert!(!v.passed, "zero threshold config must not disable quorum");
        assert_eq!(
            v.required, 1,
            "threshold should clamp to at least one signer"
        );
        assert_eq!(v.received, 0);
        assert!(v.failures.iter().any(|f| matches!(
            f,
            VerificationFailure::BelowQuorum {
                required: 1,
                received: 0
            }
        )));
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

    #[test]
    fn selection_is_order_invariant_for_same_candidate_set() {
        let forward = vec![
            CoordinatorCandidate {
                node_id: "node-a".into(),
                weight: 10,
            },
            CoordinatorCandidate {
                node_id: "node-c".into(),
                weight: 8,
            },
            CoordinatorCandidate {
                node_id: "node-b".into(),
                weight: 5,
            },
        ];
        let reversed = vec![
            CoordinatorCandidate {
                node_id: "node-b".into(),
                weight: 5,
            },
            CoordinatorCandidate {
                node_id: "node-c".into(),
                weight: 8,
            },
            CoordinatorCandidate {
                node_id: "node-a".into(),
                weight: 10,
            },
        ];

        let left = select_coordinator(&forward, "lease-order", "tr").unwrap();
        let right = select_coordinator(&reversed, "lease-order", "tr").unwrap();

        assert_eq!(left.selected, right.selected);
        assert_eq!(left.candidates, right.candidates);
        assert_eq!(
            left.candidates,
            vec![
                "node-a".to_string(),
                "node-b".to_string(),
                "node-c".to_string()
            ]
        );
    }

    #[test]
    fn higher_weight_beats_wraparound_artifact() {
        let cands = vec![
            CoordinatorCandidate {
                node_id: "node-a".into(),
                weight: 2,
            },
            CoordinatorCandidate {
                node_id: "node-b".into(),
                weight: 1,
            },
        ];

        let selected = select_coordinator(&cands, "lease-wrap", "tr")
            .expect("selection should succeed")
            .selected;

        assert_eq!(
            selected, "node-a",
            "weighting must not be distorted by u64 wraparound"
        );
    }

    #[test]
    fn zero_weight_candidate_is_ineligible_for_selection() {
        let cands = vec![
            CoordinatorCandidate {
                node_id: "zero".into(),
                weight: 0,
            },
            CoordinatorCandidate {
                node_id: "one".into(),
                weight: 1,
            },
        ];

        let selection = select_coordinator(&cands, "lease-zero-3", "tr")
            .expect("positive-weight candidate should still be selectable");

        assert_eq!(selection.selected, "one");
        assert_eq!(selection.candidates, vec!["one".to_string()]);
    }

    #[test]
    fn all_zero_weight_candidates_error() {
        let cands = vec![
            CoordinatorCandidate {
                node_id: "zero-a".into(),
                weight: 0,
            },
            CoordinatorCandidate {
                node_id: "zero-b".into(),
                weight: 0,
            },
        ];

        let err = select_coordinator(&cands, "lease-zero-only", "tr")
            .expect_err("zero-weight candidates must not be silently promoted");
        assert_eq!(err, CoordinatorError::NoCandidates);
    }

    #[test]
    fn negative_empty_lease_id_is_rejected_for_selection() {
        let err = select_coordinator(&candidates(), "", "trace-empty-lease")
            .expect_err("empty lease identity must not seed coordinator selection");

        assert_eq!(err, CoordinatorError::NoCandidates);
        assert_eq!(err.code(), "LC_NO_CANDIDATES");
    }

    #[test]
    fn negative_space_only_lease_id_is_rejected_for_selection() {
        let err = select_coordinator(&candidates(), "   ", "trace-space-lease")
            .expect_err("space-only lease identity must not seed coordinator selection");

        assert_eq!(err, CoordinatorError::NoCandidates);
    }

    #[test]
    fn negative_newline_only_lease_id_is_rejected_for_selection() {
        let err = select_coordinator(&candidates(), "\n", "trace-newline-lease")
            .expect_err("newline-only lease identity must not seed coordinator selection");

        assert_eq!(err, CoordinatorError::NoCandidates);
    }

    #[test]
    fn negative_leading_space_lease_id_is_rejected_for_selection() {
        let err = select_coordinator(&candidates(), " lease-padded", "trace-leading-lease")
            .expect_err("leading whitespace must not be normalized into a lease identity");

        assert_eq!(err, CoordinatorError::NoCandidates);
    }

    #[test]
    fn negative_trailing_space_lease_id_is_rejected_for_selection() {
        let err = select_coordinator(&candidates(), "lease-padded ", "trace-trailing-lease")
            .expect_err("trailing whitespace must not be normalized into a lease identity");

        assert_eq!(err, CoordinatorError::NoCandidates);
    }

    #[test]
    fn negative_tab_padded_lease_id_is_rejected_for_selection() {
        let err = select_coordinator(&candidates(), "\tlease-padded\t", "trace-tab-lease")
            .expect_err("tab-padded lease identity must not seed coordinator selection");

        assert_eq!(err, CoordinatorError::NoCandidates);
    }

    #[test]
    fn negative_invalid_lease_id_is_not_hidden_by_valid_candidates() {
        let cands = vec![
            CoordinatorCandidate {
                node_id: "node-a".to_string(),
                weight: u32::MAX,
            },
            CoordinatorCandidate {
                node_id: "node-b".to_string(),
                weight: 1,
            },
        ];

        let err = select_coordinator(&cands, " lease-with-valid-candidates ", "trace-cands")
            .expect_err("valid candidates must not hide a malformed lease identity");

        assert_eq!(err, CoordinatorError::NoCandidates);
    }

    #[test]
    fn negative_empty_trace_id_is_rejected_for_selection() {
        let err = select_coordinator(&candidates(), "lease-trace-empty", "")
            .expect_err("empty trace identity must not be copied into selection receipts");

        assert_eq!(err, CoordinatorError::NoCandidates);
        assert_eq!(err.code(), "LC_NO_CANDIDATES");
    }

    #[test]
    fn negative_space_only_trace_id_is_rejected_for_selection() {
        let err = select_coordinator(&candidates(), "lease-trace-space", "   ")
            .expect_err("space-only trace identity must not be copied into selection receipts");

        assert_eq!(err, CoordinatorError::NoCandidates);
    }

    #[test]
    fn negative_newline_only_trace_id_is_rejected_for_selection() {
        let err = select_coordinator(&candidates(), "lease-trace-newline", "\n")
            .expect_err("newline-only trace identity must not be copied into selection receipts");

        assert_eq!(err, CoordinatorError::NoCandidates);
    }

    #[test]
    fn negative_leading_space_trace_id_is_rejected_for_selection() {
        let err = select_coordinator(&candidates(), "lease-trace-leading", " trace-padded")
            .expect_err("leading whitespace must not be normalized into a trace identity");

        assert_eq!(err, CoordinatorError::NoCandidates);
    }

    #[test]
    fn negative_trailing_space_trace_id_is_rejected_for_selection() {
        let err = select_coordinator(&candidates(), "lease-trace-trailing", "trace-padded ")
            .expect_err("trailing whitespace must not be normalized into a trace identity");

        assert_eq!(err, CoordinatorError::NoCandidates);
    }

    #[test]
    fn negative_tab_padded_trace_id_is_rejected_for_selection() {
        let err = select_coordinator(&candidates(), "lease-trace-tab", "\ttrace-padded\t")
            .expect_err("tab-padded trace identity must not be copied into selection receipts");

        assert_eq!(err, CoordinatorError::NoCandidates);
    }

    #[test]
    fn negative_invalid_trace_id_is_not_hidden_by_valid_candidates() {
        let cands = vec![
            CoordinatorCandidate {
                node_id: "node-a".to_string(),
                weight: u32::MAX,
            },
            CoordinatorCandidate {
                node_id: "node-b".to_string(),
                weight: 1,
            },
        ];

        let err = select_coordinator(&cands, "lease-with-valid-candidates", " trace-cands ")
            .expect_err("valid candidates must not hide a malformed trace identity");

        assert_eq!(err, CoordinatorError::NoCandidates);
    }

    #[test]
    fn negative_empty_node_id_candidate_is_ineligible_for_selection() {
        let cands = vec![
            CoordinatorCandidate {
                node_id: String::new(),
                weight: 10,
            },
            CoordinatorCandidate {
                node_id: "node-valid".to_string(),
                weight: 1,
            },
        ];

        let selection = select_coordinator(&cands, "lease-empty-node", "trace-empty-node")
            .expect("valid candidate should remain selectable");

        assert_eq!(selection.selected, "node-valid");
        assert_eq!(selection.candidates, vec!["node-valid".to_string()]);
    }

    #[test]
    fn negative_space_only_node_id_candidate_is_ineligible_for_selection() {
        let cands = vec![
            CoordinatorCandidate {
                node_id: "   ".to_string(),
                weight: 10,
            },
            CoordinatorCandidate {
                node_id: "node-valid".to_string(),
                weight: 1,
            },
        ];

        let selection = select_coordinator(&cands, "lease-space-node", "trace-space-node")
            .expect("valid candidate should remain selectable");

        assert_eq!(selection.selected, "node-valid");
        assert_eq!(selection.candidates, vec!["node-valid".to_string()]);
    }

    #[test]
    fn negative_tab_only_node_id_candidate_is_ineligible_for_selection() {
        let cands = vec![
            CoordinatorCandidate {
                node_id: "\t".to_string(),
                weight: 10,
            },
            CoordinatorCandidate {
                node_id: "node-valid".to_string(),
                weight: 1,
            },
        ];

        let selection = select_coordinator(&cands, "lease-tab-node", "trace-tab-node")
            .expect("valid candidate should remain selectable");

        assert_eq!(selection.selected, "node-valid");
        assert_eq!(selection.candidates, vec!["node-valid".to_string()]);
    }

    #[test]
    fn negative_newline_only_node_id_candidate_is_ineligible_for_selection() {
        let cands = vec![
            CoordinatorCandidate {
                node_id: "\n".to_string(),
                weight: 10,
            },
            CoordinatorCandidate {
                node_id: "node-valid".to_string(),
                weight: 1,
            },
        ];

        let selection = select_coordinator(&cands, "lease-newline-node", "trace-newline-node")
            .expect("valid candidate should remain selectable");

        assert_eq!(selection.selected, "node-valid");
        assert_eq!(selection.candidates, vec!["node-valid".to_string()]);
    }

    #[test]
    fn negative_all_blank_node_id_candidates_error() {
        let cands = vec![
            CoordinatorCandidate {
                node_id: String::new(),
                weight: 1,
            },
            CoordinatorCandidate {
                node_id: "   ".to_string(),
                weight: 2,
            },
            CoordinatorCandidate {
                node_id: "\t".to_string(),
                weight: 3,
            },
        ];

        let err = select_coordinator(&cands, "lease-all-blank-node", "trace-all-blank-node")
            .expect_err("blank node identities must not be selectable");

        assert_eq!(err, CoordinatorError::NoCandidates);
        assert_eq!(err.code(), "LC_NO_CANDIDATES");
    }

    #[test]
    fn negative_blank_node_id_and_zero_weight_valid_candidate_error() {
        let cands = vec![
            CoordinatorCandidate {
                node_id: "   ".to_string(),
                weight: 10,
            },
            CoordinatorCandidate {
                node_id: "node-zero".to_string(),
                weight: 0,
            },
        ];

        let err = select_coordinator(&cands, "lease-blank-zero", "trace-blank-zero")
            .expect_err("blank and zero-weight candidates are both ineligible");

        assert_eq!(err, CoordinatorError::NoCandidates);
    }

    #[test]
    fn negative_leading_space_node_id_candidate_is_ineligible_for_selection() {
        let cands = vec![
            CoordinatorCandidate {
                node_id: " node-padded".to_string(),
                weight: 10,
            },
            CoordinatorCandidate {
                node_id: "node-valid".to_string(),
                weight: 1,
            },
        ];

        let selection = select_coordinator(&cands, "lease-leading-space-node", "trace-node")
            .expect("valid candidate should remain selectable");

        assert_eq!(selection.selected, "node-valid");
        assert_eq!(selection.candidates, vec!["node-valid".to_string()]);
    }

    #[test]
    fn negative_trailing_space_node_id_candidate_is_ineligible_for_selection() {
        let cands = vec![
            CoordinatorCandidate {
                node_id: "node-padded ".to_string(),
                weight: 10,
            },
            CoordinatorCandidate {
                node_id: "node-valid".to_string(),
                weight: 1,
            },
        ];

        let selection = select_coordinator(&cands, "lease-trailing-space-node", "trace-node")
            .expect("valid candidate should remain selectable");

        assert_eq!(selection.selected, "node-valid");
        assert_eq!(selection.candidates, vec!["node-valid".to_string()]);
    }

    #[test]
    fn negative_tab_padded_node_id_candidate_is_ineligible_for_selection() {
        let cands = vec![
            CoordinatorCandidate {
                node_id: "\tnode-padded\t".to_string(),
                weight: 10,
            },
            CoordinatorCandidate {
                node_id: "node-valid".to_string(),
                weight: 1,
            },
        ];

        let selection = select_coordinator(&cands, "lease-tab-padded-node", "trace-node")
            .expect("valid candidate should remain selectable");

        assert_eq!(selection.selected, "node-valid");
        assert_eq!(selection.candidates, vec!["node-valid".to_string()]);
    }

    #[test]
    fn negative_internal_space_lease_id_is_rejected_for_selection() {
        let err = select_coordinator(&candidates(), "lease bad", "trace-internal-lease")
            .expect_err("embedded whitespace must not seed coordinator selection");

        assert_eq!(err, CoordinatorError::NoCandidates);
    }

    #[test]
    fn negative_internal_tab_lease_id_is_rejected_for_selection() {
        let err = select_coordinator(&candidates(), "lease\tbad", "trace-internal-lease")
            .expect_err("embedded tabs must not seed coordinator selection");

        assert_eq!(err, CoordinatorError::NoCandidates);
    }

    #[test]
    fn negative_internal_newline_trace_id_is_rejected_for_selection() {
        let err = select_coordinator(&candidates(), "lease-internal-trace", "trace\nbad")
            .expect_err("embedded newline must not be copied into selection receipts");

        assert_eq!(err, CoordinatorError::NoCandidates);
    }

    #[test]
    fn negative_internal_carriage_return_trace_id_is_rejected_for_selection() {
        let err = select_coordinator(&candidates(), "lease-internal-trace", "trace\rbad")
            .expect_err("embedded carriage return must not be copied into selection receipts");

        assert_eq!(err, CoordinatorError::NoCandidates);
    }

    #[test]
    fn negative_internal_space_node_id_candidate_is_ineligible_for_selection() {
        let cands = vec![
            CoordinatorCandidate {
                node_id: "node bad".to_string(),
                weight: 10,
            },
            CoordinatorCandidate {
                node_id: "node-valid".to_string(),
                weight: 1,
            },
        ];

        let selection = select_coordinator(&cands, "lease-internal-space-node", "trace-node")
            .expect("valid candidate should remain selectable");

        assert_eq!(selection.selected, "node-valid");
        assert_eq!(selection.candidates, vec!["node-valid".to_string()]);
    }

    #[test]
    fn negative_internal_tab_node_id_candidate_is_ineligible_for_selection() {
        let cands = vec![
            CoordinatorCandidate {
                node_id: "node\tbad".to_string(),
                weight: 10,
            },
            CoordinatorCandidate {
                node_id: "node-valid".to_string(),
                weight: 1,
            },
        ];

        let selection = select_coordinator(&cands, "lease-internal-tab-node", "trace-node")
            .expect("valid candidate should remain selectable");

        assert_eq!(selection.selected, "node-valid");
        assert_eq!(selection.candidates, vec!["node-valid".to_string()]);
    }

    fn assert_only_malformed_candidate_id_is_rejected(node_id: &str, lease_id: &str) {
        let cands = vec![CoordinatorCandidate {
            node_id: node_id.to_string(),
            weight: 10,
        }];

        let err = select_coordinator(&cands, lease_id, "trace-only-malformed-node")
            .expect_err("malformed candidate identity must not be selected");

        assert_eq!(err, CoordinatorError::NoCandidates);
        assert_eq!(err.code(), "LC_NO_CANDIDATES");
    }

    #[test]
    fn negative_only_internal_space_node_id_candidate_errors() {
        assert_only_malformed_candidate_id_is_rejected("node bad", "lease-only-internal-space");
    }

    #[test]
    fn negative_only_internal_tab_node_id_candidate_errors() {
        assert_only_malformed_candidate_id_is_rejected("node\tbad", "lease-only-internal-tab");
    }

    #[test]
    fn negative_only_internal_newline_node_id_candidate_errors() {
        assert_only_malformed_candidate_id_is_rejected("node\nbad", "lease-only-internal-newline");
    }

    #[test]
    fn negative_only_internal_carriage_node_id_candidate_errors() {
        assert_only_malformed_candidate_id_is_rejected("node\rbad", "lease-only-internal-carriage");
    }

    #[test]
    fn negative_only_internal_crlf_node_id_candidate_errors() {
        assert_only_malformed_candidate_id_is_rejected("node\r\nbad", "lease-only-internal-crlf");
    }

    #[test]
    fn negative_only_internal_form_feed_node_id_candidate_errors() {
        assert_only_malformed_candidate_id_is_rejected("node\u{000c}bad", "lease-only-internal-ff");
    }

    #[test]
    fn negative_unknown_tier_defaults_to_dangerous_quorum() {
        let known = vec!["s1".to_string(), "s2".to_string()];
        let sigs = vec![valid_sig("s1", "payload-a"), valid_sig("s2", "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            "lease-unknown-tier",
            "Unrecognized",
            &sigs,
            &known,
            "payload-a",
            "trace-unknown-tier",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.required, 3);
        assert_eq!(v.received, 2);
        assert!(v.failures.iter().any(|failure| matches!(
            failure,
            VerificationFailure::BelowQuorum {
                required: 3,
                received: 2
            }
        )));
    }

    #[test]
    fn negative_empty_known_signers_classifies_signatures_as_unknown() {
        let sigs = vec![valid_sig("s1", "payload-a"), valid_sig("s2", "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            "lease-no-known",
            "Standard",
            &sigs,
            &[],
            "payload-a",
            "trace-no-known",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_unknown_for(failure, "s1"))
        );
        assert!(v.failures.iter().any(|failure| matches!(
            failure,
            VerificationFailure::BelowQuorum {
                required: 1,
                received: 0
            }
        )));
    }

    #[test]
    fn negative_empty_signer_id_cannot_satisfy_quorum_even_if_known() {
        let known = vec!["".to_string()];
        let sigs = vec![valid_sig("", "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            "lease-empty-signer",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-empty-signer",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(v.failures.iter().any(|failure| is_unknown_for(failure, "")));
        assert!(v.failures.iter().any(|failure| matches!(
            failure,
            VerificationFailure::BelowQuorum {
                required: 1,
                received: 0
            }
        )));
    }

    #[test]
    fn negative_empty_known_signer_entry_does_not_make_other_signatures_known() {
        let known = vec!["".to_string()];
        let sigs = vec![valid_sig("s1", "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            "lease-empty-known-entry",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-empty-known-entry",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_unknown_for(failure, "s1"))
        );
    }

    #[test]
    fn negative_mixed_empty_and_valid_signer_still_counts_only_valid_identity() {
        let known = vec!["".to_string(), "s1".to_string()];
        let sigs = vec![valid_sig("", "payload-a"), valid_sig("s1", "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            "lease-mixed-empty-valid",
            "Risky",
            &sigs,
            &known,
            "payload-a",
            "trace-mixed-empty-valid",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.required, 2);
        assert_eq!(v.received, 1);
        assert!(v.failures.iter().any(|failure| is_unknown_for(failure, "")));
        assert!(v.failures.iter().any(|failure| matches!(
            failure,
            VerificationFailure::BelowQuorum {
                required: 2,
                received: 1
            }
        )));
    }

    #[test]
    fn negative_duplicate_empty_signer_ids_report_one_unknown_failure() {
        let known = vec!["".to_string()];
        let sigs = vec![
            valid_sig("", "payload-a"),
            QuorumSignature {
                signer_id: String::new(),
                signature: "not-valid".to_string(),
            },
        ];

        let v = verify_quorum(
            &qconfig(),
            "lease-duplicate-empty",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-duplicate-empty",
            "ts",
        );

        let empty_unknown_count = v
            .failures
            .iter()
            .filter(|failure| is_unknown_for(failure, ""))
            .count();
        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert_eq!(empty_unknown_count, 1);
    }

    #[test]
    fn negative_empty_signer_id_is_not_classified_as_invalid_known_signature() {
        let known = vec!["".to_string()];
        let sigs = vec![QuorumSignature {
            signer_id: String::new(),
            signature: "not-valid".to_string(),
        }];

        let v = verify_quorum(
            &qconfig(),
            "lease-empty-not-invalid",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-empty-not-invalid",
            "ts",
        );

        assert!(!v.passed);
        assert!(v.failures.iter().any(|failure| is_unknown_for(failure, "")));
        assert!(
            !v.failures
                .iter()
                .any(|failure| matches!(failure, VerificationFailure::InvalidSignature { .. }))
        );
    }

    #[test]
    fn negative_empty_signer_still_fails_when_threshold_config_is_zero() {
        let config = QuorumConfig {
            standard_threshold: 0,
            risky_threshold: 0,
            dangerous_threshold: 0,
        };
        let known = vec!["".to_string()];
        let sigs = vec![valid_sig("", "payload-a")];

        let v = verify_quorum(
            &config,
            "lease-empty-zero-threshold",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-empty-zero-threshold",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.required, 1);
        assert_eq!(v.received, 0);
        assert!(v.failures.iter().any(|failure| is_unknown_for(failure, "")));
    }

    #[test]
    fn negative_space_only_signer_id_cannot_satisfy_quorum_even_if_known() {
        let known = vec!["   ".to_string()];
        let sigs = vec![valid_sig("   ", "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            "lease-space-signer",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-space-signer",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_unknown_for(failure, "   "))
        );
    }

    #[test]
    fn negative_tab_only_signer_id_cannot_satisfy_quorum_even_if_known() {
        let known = vec!["\t".to_string()];
        let sigs = vec![valid_sig("\t", "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            "lease-tab-signer",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-tab-signer",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_unknown_for(failure, "\t"))
        );
    }

    #[test]
    fn negative_newline_only_signer_id_cannot_satisfy_quorum_even_if_known() {
        let known = vec!["\n".to_string()];
        let sigs = vec![valid_sig("\n", "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            "lease-newline-signer",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-newline-signer",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_unknown_for(failure, "\n"))
        );
    }

    #[test]
    fn negative_duplicate_whitespace_signer_ids_report_one_unknown_failure() {
        let known = vec!["   ".to_string()];
        let sigs = vec![
            valid_sig("   ", "payload-a"),
            QuorumSignature {
                signer_id: "   ".to_string(),
                signature: "not-valid".to_string(),
            },
        ];

        let v = verify_quorum(
            &qconfig(),
            "lease-duplicate-whitespace",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-duplicate-whitespace",
            "ts",
        );

        let blank_unknown_count = v
            .failures
            .iter()
            .filter(|failure| is_unknown_for(failure, "   "))
            .count();
        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert_eq!(blank_unknown_count, 1);
    }

    #[test]
    fn negative_mixed_whitespace_and_valid_signer_counts_only_valid_identity() {
        let known = vec!["   ".to_string(), "s1".to_string()];
        let sigs = vec![valid_sig("   ", "payload-a"), valid_sig("s1", "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            "lease-mixed-whitespace-valid",
            "Risky",
            &sigs,
            &known,
            "payload-a",
            "trace-mixed-whitespace-valid",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.required, 2);
        assert_eq!(v.received, 1);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_unknown_for(failure, "   "))
        );
    }

    #[test]
    fn negative_whitespace_signer_id_is_not_classified_as_invalid_known_signature() {
        let known = vec!["   ".to_string()];
        let sigs = vec![QuorumSignature {
            signer_id: "   ".to_string(),
            signature: "not-valid".to_string(),
        }];

        let v = verify_quorum(
            &qconfig(),
            "lease-whitespace-not-invalid",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-whitespace-not-invalid",
            "ts",
        );

        assert!(!v.passed);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_unknown_for(failure, "   "))
        );
        assert!(
            !v.failures
                .iter()
                .any(|failure| matches!(failure, VerificationFailure::InvalidSignature { .. }))
        );
    }

    #[test]
    fn negative_leading_space_signer_id_cannot_satisfy_quorum_even_if_known() {
        let known = vec![" s1".to_string()];
        let sigs = vec![valid_sig(" s1", "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            "lease-leading-space-signer",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-leading-space-signer",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_unknown_for(failure, " s1"))
        );
    }

    #[test]
    fn negative_trailing_space_signer_id_cannot_satisfy_quorum_even_if_known() {
        let known = vec!["s1 ".to_string()];
        let sigs = vec![valid_sig("s1 ", "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            "lease-trailing-space-signer",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-trailing-space-signer",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_unknown_for(failure, "s1 "))
        );
    }

    #[test]
    fn negative_tab_padded_signer_id_cannot_satisfy_quorum_even_if_known() {
        let known = vec!["\ts1\t".to_string()];
        let sigs = vec![valid_sig("\ts1\t", "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            "lease-tab-padded-signer",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-tab-padded-signer",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_unknown_for(failure, "\ts1\t"))
        );
    }

    fn assert_embedded_whitespace_signer_is_unknown(signer_id: &str, lease_id: &str) {
        let known = vec![signer_id.to_string()];
        let sigs = vec![valid_sig(signer_id, "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            lease_id,
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-embedded-signer",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_unknown_for(failure, signer_id))
        );
    }

    #[test]
    fn negative_internal_space_signer_id_cannot_satisfy_quorum_even_if_known() {
        assert_embedded_whitespace_signer_is_unknown("s 1", "lease-internal-space-signer");
    }

    #[test]
    fn negative_internal_tab_signer_id_cannot_satisfy_quorum_even_if_known() {
        assert_embedded_whitespace_signer_is_unknown("s\t1", "lease-internal-tab-signer");
    }

    #[test]
    fn negative_internal_newline_signer_id_cannot_satisfy_quorum_even_if_known() {
        assert_embedded_whitespace_signer_is_unknown("s\n1", "lease-internal-newline-signer");
    }

    #[test]
    fn negative_internal_carriage_return_signer_id_cannot_satisfy_quorum_even_if_known() {
        assert_embedded_whitespace_signer_is_unknown("s\r1", "lease-internal-carriage-signer");
    }

    #[test]
    fn negative_internal_crlf_signer_id_cannot_satisfy_quorum_even_if_known() {
        assert_embedded_whitespace_signer_is_unknown("s\r\n1", "lease-internal-crlf-signer");
    }

    #[test]
    fn negative_internal_form_feed_signer_id_cannot_satisfy_quorum_even_if_known() {
        assert_embedded_whitespace_signer_is_unknown("s\u{000c}1", "lease-internal-ff-signer");
    }

    fn assert_malformed_known_signer_does_not_authorize_clean_signer(
        known_signer: &str,
        clean_signer: &str,
        lease_id: &str,
    ) {
        let known = vec![known_signer.to_string()];
        let sigs = vec![valid_sig(clean_signer, "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            lease_id,
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-known-alias",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_unknown_for(failure, clean_signer))
        );
        assert!(v.failures.iter().any(|failure| matches!(
            failure,
            VerificationFailure::BelowQuorum {
                required: 1,
                received: 0
            }
        )));
    }

    #[test]
    fn negative_internal_space_known_signer_does_not_authorize_clean_signer() {
        assert_malformed_known_signer_does_not_authorize_clean_signer(
            "s 1",
            "s1",
            "lease-known-internal-space",
        );
    }

    #[test]
    fn negative_internal_tab_known_signer_does_not_authorize_clean_signer() {
        assert_malformed_known_signer_does_not_authorize_clean_signer(
            "s\t1",
            "s1",
            "lease-known-internal-tab",
        );
    }

    #[test]
    fn negative_internal_newline_known_signer_does_not_authorize_clean_signer() {
        assert_malformed_known_signer_does_not_authorize_clean_signer(
            "s\n1",
            "s1",
            "lease-known-internal-newline",
        );
    }

    #[test]
    fn negative_internal_carriage_known_signer_does_not_authorize_clean_signer() {
        assert_malformed_known_signer_does_not_authorize_clean_signer(
            "s\r1",
            "s1",
            "lease-known-internal-carriage",
        );
    }

    #[test]
    fn negative_internal_crlf_known_signer_does_not_authorize_clean_signer() {
        assert_malformed_known_signer_does_not_authorize_clean_signer(
            "s\r\n1",
            "s1",
            "lease-known-internal-crlf",
        );
    }

    #[test]
    fn negative_internal_form_feed_known_signer_does_not_authorize_clean_signer() {
        assert_malformed_known_signer_does_not_authorize_clean_signer(
            "s\u{000c}1",
            "s1",
            "lease-known-internal-ff",
        );
    }

    fn assert_malformed_lease_id_fails_quorum(lease_id: &str, trace_id: &str) {
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            lease_id,
            "Standard",
            &sigs,
            &known,
            "payload-a",
            trace_id,
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
    }

    #[test]
    fn negative_empty_lease_id_cannot_pass_quorum() {
        assert_malformed_lease_id_fails_quorum("", "trace-empty-quorum-lease");
    }

    #[test]
    fn negative_space_only_lease_id_cannot_pass_quorum() {
        assert_malformed_lease_id_fails_quorum("   ", "trace-space-quorum-lease");
    }

    #[test]
    fn negative_newline_only_lease_id_cannot_pass_quorum() {
        assert_malformed_lease_id_fails_quorum("\n", "trace-newline-quorum-lease");
    }

    #[test]
    fn negative_leading_space_lease_id_cannot_pass_quorum() {
        assert_malformed_lease_id_fails_quorum(" lease-padded", "trace-leading-quorum-lease");
    }

    #[test]
    fn negative_trailing_space_lease_id_cannot_pass_quorum() {
        assert_malformed_lease_id_fails_quorum("lease-padded ", "trace-trailing-quorum-lease");
    }

    #[test]
    fn negative_tab_padded_lease_id_cannot_pass_quorum() {
        assert_malformed_lease_id_fails_quorum("\tlease-padded\t", "trace-tab-quorum-lease");
    }

    #[test]
    fn negative_internal_space_lease_id_cannot_pass_quorum() {
        assert_malformed_lease_id_fails_quorum("lease bad", "trace-internal-space-lease");
    }

    #[test]
    fn negative_internal_tab_lease_id_cannot_pass_quorum() {
        assert_malformed_lease_id_fails_quorum("lease\tbad", "trace-internal-tab-lease");
    }

    #[test]
    fn negative_invalid_lease_id_is_not_hidden_by_zero_threshold_config() {
        let config = QuorumConfig {
            standard_threshold: 0,
            risky_threshold: 0,
            dangerous_threshold: 0,
        };
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", "payload-a")];

        let v = verify_quorum(
            &config,
            " lease-zero-threshold ",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-zero-threshold-lease",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.required, 1);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
    }

    fn assert_malformed_trace_id_fails_quorum(trace_id: &str) {
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            "lease-trace-metadata",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            trace_id,
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
    }

    #[test]
    fn negative_empty_trace_id_cannot_pass_quorum() {
        assert_malformed_trace_id_fails_quorum("");
    }

    #[test]
    fn negative_space_only_trace_id_cannot_pass_quorum() {
        assert_malformed_trace_id_fails_quorum("   ");
    }

    #[test]
    fn negative_newline_only_trace_id_cannot_pass_quorum() {
        assert_malformed_trace_id_fails_quorum("\n");
    }

    #[test]
    fn negative_leading_space_trace_id_cannot_pass_quorum() {
        assert_malformed_trace_id_fails_quorum(" trace-padded");
    }

    #[test]
    fn negative_trailing_space_trace_id_cannot_pass_quorum() {
        assert_malformed_trace_id_fails_quorum("trace-padded ");
    }

    #[test]
    fn negative_tab_padded_trace_id_cannot_pass_quorum() {
        assert_malformed_trace_id_fails_quorum("\ttrace-padded\t");
    }

    #[test]
    fn negative_internal_newline_trace_id_cannot_pass_quorum() {
        assert_malformed_trace_id_fails_quorum("trace\nbad");
    }

    #[test]
    fn negative_invalid_trace_id_is_not_hidden_by_zero_threshold_config() {
        let config = QuorumConfig {
            standard_threshold: 0,
            risky_threshold: 0,
            dangerous_threshold: 0,
        };
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", "payload-a")];

        let v = verify_quorum(
            &config,
            "lease-zero-threshold-trace",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            " trace-zero-threshold ",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.required, 1);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
    }

    fn assert_malformed_timestamp_fails_quorum(timestamp: &str) {
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            "lease-timestamp-metadata",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-timestamp-metadata",
            timestamp,
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
    }

    #[test]
    fn negative_empty_timestamp_cannot_pass_quorum() {
        assert_malformed_timestamp_fails_quorum("");
    }

    #[test]
    fn negative_space_only_timestamp_cannot_pass_quorum() {
        assert_malformed_timestamp_fails_quorum("   ");
    }

    #[test]
    fn negative_newline_only_timestamp_cannot_pass_quorum() {
        assert_malformed_timestamp_fails_quorum("\n");
    }

    #[test]
    fn negative_leading_space_timestamp_cannot_pass_quorum() {
        assert_malformed_timestamp_fails_quorum(" ts-padded");
    }

    #[test]
    fn negative_trailing_space_timestamp_cannot_pass_quorum() {
        assert_malformed_timestamp_fails_quorum("ts-padded ");
    }

    #[test]
    fn negative_tab_padded_timestamp_cannot_pass_quorum() {
        assert_malformed_timestamp_fails_quorum("\tts-padded\t");
    }

    #[test]
    fn negative_internal_space_timestamp_cannot_pass_quorum() {
        assert_malformed_timestamp_fails_quorum("ts bad");
    }

    #[test]
    fn negative_invalid_timestamp_is_not_hidden_by_zero_threshold_config() {
        let config = QuorumConfig {
            standard_threshold: 0,
            risky_threshold: 0,
            dangerous_threshold: 0,
        };
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", "payload-a")];

        let v = verify_quorum(
            &config,
            "lease-zero-threshold-timestamp",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-zero-threshold-timestamp",
            " ts-zero-threshold ",
        );

        assert!(!v.passed);
        assert_eq!(v.required, 1);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
    }

    fn assert_malformed_tier_fails_quorum(tier: &str) {
        let known = vec!["s1".to_string(), "s2".to_string(), "s3".to_string()];
        let sigs = vec![
            valid_sig("s1", "payload-a"),
            valid_sig("s2", "payload-a"),
            valid_sig("s3", "payload-a"),
        ];

        let v = verify_quorum(
            &qconfig(),
            "lease-tier-metadata",
            tier,
            &sigs,
            &known,
            "payload-a",
            "trace-tier-metadata",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.required, 3);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
    }

    #[test]
    fn negative_empty_tier_cannot_pass_quorum() {
        assert_malformed_tier_fails_quorum("");
    }

    #[test]
    fn negative_space_only_tier_cannot_pass_quorum() {
        assert_malformed_tier_fails_quorum("   ");
    }

    #[test]
    fn negative_newline_only_tier_cannot_pass_quorum() {
        assert_malformed_tier_fails_quorum("\n");
    }

    #[test]
    fn negative_leading_space_tier_cannot_pass_quorum() {
        assert_malformed_tier_fails_quorum(" Standard");
    }

    #[test]
    fn negative_trailing_space_tier_cannot_pass_quorum() {
        assert_malformed_tier_fails_quorum("Standard ");
    }

    #[test]
    fn negative_tab_padded_tier_cannot_pass_quorum() {
        assert_malformed_tier_fails_quorum("\tStandard\t");
    }

    #[test]
    fn negative_internal_space_tier_cannot_pass_quorum() {
        assert_malformed_tier_fails_quorum("Stan dard");
    }

    #[test]
    fn negative_invalid_tier_is_not_hidden_by_zero_threshold_config() {
        let config = QuorumConfig {
            standard_threshold: 0,
            risky_threshold: 0,
            dangerous_threshold: 0,
        };
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", "payload-a")];

        let v = verify_quorum(
            &config,
            "lease-zero-threshold-tier",
            " Standard ",
            &sigs,
            &known,
            "payload-a",
            "trace-zero-threshold-tier",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.required, 1);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
    }

    #[test]
    fn negative_empty_content_hash_cannot_be_quorum_payload() {
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", "")];

        let v = verify_quorum(
            &qconfig(),
            "lease-empty-content-hash",
            "Standard",
            &sigs,
            &known,
            "",
            "trace-empty-content-hash",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
    }

    #[test]
    fn negative_space_only_content_hash_cannot_be_quorum_payload() {
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", "   ")];

        let v = verify_quorum(
            &qconfig(),
            "lease-space-content-hash",
            "Standard",
            &sigs,
            &known,
            "   ",
            "trace-space-content-hash",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
    }

    #[test]
    fn negative_padded_content_hash_cannot_be_quorum_payload() {
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", " payload-a ")];

        let v = verify_quorum(
            &qconfig(),
            "lease-padded-content-hash",
            "Standard",
            &sigs,
            &known,
            " payload-a ",
            "trace-padded-content-hash",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
    }

    fn assert_malformed_content_hash_fails_quorum(content_hash: &str) {
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", content_hash)];

        let v = verify_quorum(
            &qconfig(),
            "lease-content-metadata",
            "Standard",
            &sigs,
            &known,
            content_hash,
            "trace-content-metadata",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
    }

    #[test]
    fn negative_newline_only_content_hash_cannot_be_quorum_payload() {
        assert_malformed_content_hash_fails_quorum("\n");
    }

    #[test]
    fn negative_tab_only_content_hash_cannot_be_quorum_payload() {
        assert_malformed_content_hash_fails_quorum("\t");
    }

    #[test]
    fn negative_leading_tab_content_hash_cannot_be_quorum_payload() {
        assert_malformed_content_hash_fails_quorum("\tpayload-a");
    }

    #[test]
    fn negative_trailing_tab_content_hash_cannot_be_quorum_payload() {
        assert_malformed_content_hash_fails_quorum("payload-a\t");
    }

    #[test]
    fn negative_newline_padded_content_hash_cannot_be_quorum_payload() {
        assert_malformed_content_hash_fails_quorum("\npayload-a\n");
    }

    #[test]
    fn negative_mixed_whitespace_content_hash_cannot_be_quorum_payload() {
        assert_malformed_content_hash_fails_quorum(" \tpayload-a\n");
    }

    #[test]
    fn negative_internal_space_content_hash_cannot_be_quorum_payload() {
        assert_malformed_content_hash_fails_quorum("payload bad");
    }

    #[test]
    fn negative_invalid_content_hash_metadata_does_not_count_valid_second_signer() {
        let known = vec!["s1".to_string(), "s2".to_string()];
        let sigs = vec![
            valid_sig("s1", "\tpayload-a"),
            valid_sig("s2", "\tpayload-a"),
        ];

        let v = verify_quorum(
            &qconfig(),
            "lease-content-two-signers",
            "Risky",
            &sigs,
            &known,
            "\tpayload-a",
            "trace-content-two-signers",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.required, 2);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s2"))
        );
    }

    #[test]
    fn negative_invalid_content_hash_fails_even_when_risky_threshold_signatures_match() {
        let known = vec!["s1".to_string(), "s2".to_string()];
        let sigs = vec![valid_sig("s1", ""), valid_sig("s2", "")];

        let v = verify_quorum(
            &qconfig(),
            "lease-risky-empty-content-hash",
            "Risky",
            &sigs,
            &known,
            "",
            "trace-risky-empty-content-hash",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.required, 2);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s2"))
        );
    }

    #[test]
    fn negative_invalid_content_hash_with_unknown_signer_still_reports_unknown() {
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("unknown", "")];

        let v = verify_quorum(
            &qconfig(),
            "lease-unknown-empty-content-hash",
            "Standard",
            &sigs,
            &known,
            "",
            "trace-unknown-empty-content-hash",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_unknown_for(failure, "unknown"))
        );
    }

    #[test]
    fn negative_invalid_content_hash_is_not_hidden_by_zero_threshold_config() {
        let config = QuorumConfig {
            standard_threshold: 0,
            risky_threshold: 0,
            dangerous_threshold: 0,
        };
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", "")];

        let v = verify_quorum(
            &config,
            "lease-zero-threshold-empty-content-hash",
            "Standard",
            &sigs,
            &known,
            "",
            "trace-zero-threshold-empty-content-hash",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.required, 1);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
    }

    #[test]
    fn negative_signature_bound_to_different_payload_is_invalid() {
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            "lease-payload-swap",
            "Standard",
            &sigs,
            &known,
            "payload-b",
            "trace-payload-swap",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
    }

    #[test]
    fn negative_uppercase_signature_is_not_normalized() {
        let known = vec!["s1".to_string()];
        let sigs = vec![QuorumSignature {
            signer_id: "s1".to_string(),
            signature: compute_test_signature("s1", "payload-a").to_uppercase(),
        }];

        let v = verify_quorum(
            &qconfig(),
            "lease-uppercase",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-uppercase",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
    }

    #[test]
    fn negative_same_length_signature_mutation_is_invalid() {
        let known = vec!["s1".to_string()];
        let mut signature = compute_test_signature("s1", "payload-a");
        let replacement = match signature.as_bytes().first().copied() {
            Some(b'0') => "1",
            _ => "0",
        };
        signature.replace_range(0..1, replacement);
        let sigs = vec![QuorumSignature {
            signer_id: "s1".to_string(),
            signature,
        }];

        let v = verify_quorum(
            &qconfig(),
            "lease-mutated-sig",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-mutated-sig",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
    }

    #[test]
    fn negative_duplicate_unknown_signer_reports_once() {
        let sigs = vec![
            valid_sig("intruder", "payload-a"),
            QuorumSignature {
                signer_id: "intruder".to_string(),
                signature: "not-valid".to_string(),
            },
        ];

        let v = verify_quorum(
            &qconfig(),
            "lease-duplicate-unknown",
            "Standard",
            &sigs,
            &[],
            "payload-a",
            "trace-duplicate-unknown",
            "ts",
        );

        let unknown_count = v
            .failures
            .iter()
            .filter(|failure| is_unknown_for(failure, "intruder"))
            .count();
        assert!(!v.passed);
        assert_eq!(unknown_count, 1);
    }

    #[test]
    fn negative_failure_collection_is_bounded_for_unknown_signer_flood() {
        let sigs: Vec<QuorumSignature> = (0..300)
            .map(|idx| valid_sig(&format!("unknown-{idx:03}"), "payload-a"))
            .collect();

        let v = verify_quorum(
            &qconfig(),
            "lease-unknown-flood",
            "Standard",
            &sigs,
            &[],
            "payload-a",
            "trace-unknown-flood",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert_eq!(v.failures.len(), MAX_VERIFICATION_FAILURES);
        assert!(v.failures.iter().any(|failure| matches!(
            failure,
            VerificationFailure::BelowQuorum {
                required: 1,
                received: 0
            }
        )));
    }

    #[test]
    fn negative_custom_zero_unknown_tier_threshold_still_requires_one() {
        let config = QuorumConfig {
            standard_threshold: 0,
            risky_threshold: 0,
            dangerous_threshold: 0,
        };

        let v = verify_quorum(
            &config,
            "lease-zero-unknown-tier",
            "Unrecognized",
            &[],
            &[],
            "payload-a",
            "trace-zero-unknown-tier",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.required, 1);
        assert_eq!(v.received, 0);
    }

    #[test]
    fn negative_empty_candidate_slice_and_zero_weight_candidates_share_error_code() {
        let zero_weight = vec![CoordinatorCandidate {
            node_id: "node-zero".to_string(),
            weight: 0,
        }];

        let empty_err = select_coordinator(&[], "lease-empty", "trace-empty")
            .expect_err("empty candidate set must fail");
        let zero_err = select_coordinator(&zero_weight, "lease-zero", "trace-zero")
            .expect_err("zero-weight candidate set must fail");

        assert_eq!(empty_err.code(), "LC_NO_CANDIDATES");
        assert_eq!(zero_err.code(), "LC_NO_CANDIDATES");
    }

    #[test]
    fn negative_push_bounded_zero_capacity_drops_existing_and_new_failures() {
        let mut failures = vec![VerificationFailure::BelowQuorum {
            required: 2,
            received: 1,
        }];

        push_bounded(
            &mut failures,
            VerificationFailure::UnknownSigner {
                signer_id: "intruder".to_string(),
            },
            0,
        );

        assert!(failures.is_empty());
    }

    #[test]
    fn negative_push_bounded_cap_one_keeps_only_new_failure() {
        let mut failures = vec![VerificationFailure::BelowQuorum {
            required: 2,
            received: 1,
        }];

        push_bounded(
            &mut failures,
            VerificationFailure::UnknownSigner {
                signer_id: "intruder".to_string(),
            },
            1,
        );

        assert_eq!(
            failures,
            vec![VerificationFailure::UnknownSigner {
                signer_id: "intruder".to_string()
            }]
        );
    }

    #[test]
    fn negative_push_bounded_exactly_full_cap_drops_oldest_failure() {
        let mut failures = vec![
            VerificationFailure::UnknownSigner {
                signer_id: "old".to_string(),
            },
            VerificationFailure::InvalidSignature {
                signer_id: "bad".to_string(),
            },
        ];

        push_bounded(
            &mut failures,
            VerificationFailure::BelowQuorum {
                required: 3,
                received: 1,
            },
            2,
        );

        assert_eq!(
            failures,
            vec![
                VerificationFailure::InvalidSignature {
                    signer_id: "bad".to_string()
                },
                VerificationFailure::BelowQuorum {
                    required: 3,
                    received: 1
                }
            ]
        );
    }

    #[test]
    fn negative_push_bounded_overfull_failure_list_drains_to_capacity() {
        let mut failures = vec![
            VerificationFailure::UnknownSigner {
                signer_id: "one".to_string(),
            },
            VerificationFailure::UnknownSigner {
                signer_id: "two".to_string(),
            },
            VerificationFailure::UnknownSigner {
                signer_id: "three".to_string(),
            },
            VerificationFailure::UnknownSigner {
                signer_id: "four".to_string(),
            },
        ];

        push_bounded(
            &mut failures,
            VerificationFailure::UnknownSigner {
                signer_id: "five".to_string(),
            },
            2,
        );

        assert_eq!(
            failures,
            vec![
                VerificationFailure::UnknownSigner {
                    signer_id: "four".to_string()
                },
                VerificationFailure::UnknownSigner {
                    signer_id: "five".to_string()
                }
            ]
        );
    }

    #[test]
    fn negative_push_bounded_overfull_cap_one_discards_all_old_failures() {
        let mut failures = vec![
            VerificationFailure::UnknownSigner {
                signer_id: "one".to_string(),
            },
            VerificationFailure::InvalidSignature {
                signer_id: "two".to_string(),
            },
            VerificationFailure::BelowQuorum {
                required: 3,
                received: 1,
            },
        ];

        push_bounded(
            &mut failures,
            VerificationFailure::UnknownSigner {
                signer_id: "latest".to_string(),
            },
            1,
        );

        assert_eq!(
            failures,
            vec![VerificationFailure::UnknownSigner {
                signer_id: "latest".to_string()
            }]
        );
    }

    #[test]
    fn negative_push_bounded_repeated_failure_pushes_never_exceed_cap() {
        let mut failures = Vec::new();

        for idx in 0..10 {
            push_bounded(
                &mut failures,
                VerificationFailure::UnknownSigner {
                    signer_id: format!("unknown-{idx}"),
                },
                3,
            );
            assert!(failures.len() <= 3);
        }

        assert_eq!(
            failures,
            vec![
                VerificationFailure::UnknownSigner {
                    signer_id: "unknown-7".to_string()
                },
                VerificationFailure::UnknownSigner {
                    signer_id: "unknown-8".to_string()
                },
                VerificationFailure::UnknownSigner {
                    signer_id: "unknown-9".to_string()
                }
            ]
        );
    }

    #[test]
    fn negative_push_bounded_zero_capacity_remains_empty_after_repeated_failures() {
        let mut failures = Vec::new();

        for idx in 0..10 {
            push_bounded(
                &mut failures,
                VerificationFailure::UnknownSigner {
                    signer_id: format!("unknown-{idx}"),
                },
                0,
            );
        }

        assert!(failures.is_empty());
    }

    #[test]
    fn negative_nul_identity_is_not_canonical() {
        assert!(!identity_is_canonical("node\0a"));
    }

    #[test]
    fn negative_nul_lease_id_is_rejected_for_selection() {
        let err = select_coordinator(&candidates(), "lease\0bad", "trace-nul-lease")
            .expect_err("embedded NUL must not seed coordinator selection");

        assert_eq!(err, CoordinatorError::NoCandidates);
        assert_eq!(err.code(), "LC_NO_CANDIDATES");
    }

    #[test]
    fn negative_nul_trace_id_is_rejected_for_selection() {
        let err = select_coordinator(&candidates(), "lease-nul-trace", "trace\0bad")
            .expect_err("embedded NUL must not be copied into selection receipts");

        assert_eq!(err, CoordinatorError::NoCandidates);
        assert_eq!(err.code(), "LC_NO_CANDIDATES");
    }

    #[test]
    fn negative_nul_node_id_candidate_is_ineligible_for_selection() {
        let cands = vec![
            CoordinatorCandidate {
                node_id: "node\0bad".to_string(),
                weight: u64::MAX,
            },
            CoordinatorCandidate {
                node_id: "node-valid".to_string(),
                weight: 1,
            },
        ];

        let selection = select_coordinator(&cands, "lease-nul-node", "trace-nul-node")
            .expect("valid candidate should remain selectable");

        assert_eq!(selection.selected, "node-valid");
        assert_eq!(selection.candidates, vec!["node-valid".to_string()]);
    }

    #[test]
    fn negative_only_nul_node_id_candidate_errors() {
        let cands = vec![CoordinatorCandidate {
            node_id: "node\0bad".to_string(),
            weight: 10,
        }];

        let err = select_coordinator(&cands, "lease-only-nul-node", "trace-only-nul-node")
            .expect_err("NUL-bearing node identity must not be selectable");

        assert_eq!(err, CoordinatorError::NoCandidates);
    }

    #[test]
    fn negative_nul_signer_id_cannot_satisfy_quorum_even_if_known() {
        let known = vec!["s\u{0}1".to_string()];
        let sigs = vec![valid_sig("s\u{0}1", "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            "lease-nul-signer",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-nul-signer",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_unknown_for(failure, "s\u{0}1"))
        );
    }

    #[test]
    fn negative_nul_known_signer_does_not_authorize_clean_signer() {
        let known = vec!["s1\0shadow".to_string()];
        let sigs = vec![valid_sig("s1", "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            "lease-nul-known-signer",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-nul-known-signer",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_unknown_for(failure, "s1"))
        );
    }

    #[test]
    fn negative_nul_content_identity_marks_known_signature_invalid() {
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", "payload\0a")];

        let v = verify_quorum(
            &qconfig(),
            "lease-nul-content",
            "Standard",
            &sigs,
            &known,
            "payload\0a",
            "trace-nul-content",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
    }

    #[test]
    fn negative_nul_tier_marks_known_signature_invalid() {
        let known = vec!["s1".to_string(), "s2".to_string(), "s3".to_string()];
        let sigs = vec![
            valid_sig("s1", "payload-a"),
            valid_sig("s2", "payload-a"),
            valid_sig("s3", "payload-a"),
        ];

        let v = verify_quorum(
            &qconfig(),
            "lease-nul-tier",
            "Standard\0shadow",
            &sigs,
            &known,
            "payload-a",
            "trace-nul-tier",
            "ts",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
    }

    #[test]
    fn negative_nul_timestamp_marks_known_signature_invalid() {
        let known = vec!["s1".to_string()];
        let sigs = vec![valid_sig("s1", "payload-a")];

        let v = verify_quorum(
            &qconfig(),
            "lease-nul-timestamp",
            "Standard",
            &sigs,
            &known,
            "payload-a",
            "trace-nul-timestamp",
            "ts\0shadow",
        );

        assert!(!v.passed);
        assert_eq!(v.received, 0);
        assert!(
            v.failures
                .iter()
                .any(|failure| is_invalid_for(failure, "s1"))
        );
    }
}
