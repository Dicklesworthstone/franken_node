//! bd-al8i: L2 engine-boundary N-version semantic oracle.
//!
//! Differential harness that compares franken_engine outputs against reference
//! runtimes, classifies boundary divergences by risk tier, and enforces release
//! gates on high-risk unresolved deltas.  Low-risk deltas require explicit
//! policy receipts that link back to L1 product-oracle results.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

use crate::security::constant_time;

use crate::capacity_defaults::aliases::MAX_REFERENCE_RUNTIMES;
const MAX_DIVERGENCES: usize = 4096;
const MAX_BLOCK_REASONS: usize = 256;

// ── Schema version ─────────────────────────────────────────────────────

pub const SCHEMA_VERSION: &str = "n-version-oracle-v1.0";

// ── Event codes ────────────────────────────────────────────────────────

pub mod event_codes {
    pub const ORACLE_HARNESS_START: &str = "ORACLE_HARNESS_START";
    pub const ORACLE_DIVERGENCE_CLASSIFIED: &str = "ORACLE_DIVERGENCE_CLASSIFIED";
    pub const ORACLE_RISK_TIER_ASSIGNED: &str = "ORACLE_RISK_TIER_ASSIGNED";
    pub const ORACLE_RELEASE_BLOCKED: &str = "ORACLE_RELEASE_BLOCKED";
    pub const ORACLE_POLICY_RECEIPT_ISSUED: &str = "ORACLE_POLICY_RECEIPT_ISSUED";
}

// ── Error codes ────────────────────────────────────────────────────────

pub mod error_codes {
    pub const ERR_ORACLE_HIGH_RISK_DELTA: &str = "ERR_ORACLE_HIGH_RISK_DELTA";
    pub const ERR_ORACLE_MISSING_RECEIPT: &str = "ERR_ORACLE_MISSING_RECEIPT";
    pub const ERR_ORACLE_HARNESS_TIMEOUT: &str = "ERR_ORACLE_HARNESS_TIMEOUT";
    pub const ERR_ORACLE_REFERENCE_UNAVAILABLE: &str = "ERR_ORACLE_REFERENCE_UNAVAILABLE";
    pub const ERR_ORACLE_CLASSIFICATION_AMBIGUOUS: &str = "ERR_ORACLE_CLASSIFICATION_AMBIGUOUS";
    pub const ERR_ORACLE_L1_LINK_BROKEN: &str = "ERR_ORACLE_L1_LINK_BROKEN";
}

// ── Invariants ─────────────────────────────────────────────────────────

pub mod invariants {
    pub const INV_ORACLE_HIGH_RISK_BLOCKS: &str = "INV-ORACLE-HIGH-RISK-BLOCKS";
    pub const INV_ORACLE_LOW_RISK_RECEIPTED: &str = "INV-ORACLE-LOW-RISK-RECEIPTED";
    pub const INV_ORACLE_DETERMINISTIC_CLASSIFICATION: &str =
        "INV-ORACLE-DETERMINISTIC-CLASSIFICATION";
    pub const INV_ORACLE_L1_LINKAGE: &str = "INV-ORACLE-L1-LINKAGE";
}

// ── Domain types ───────────────────────────────────────────────────────

/// Risk tier assigned to a boundary divergence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    /// Safe – divergence is cosmetic / ordering-only.
    Low,
    /// Moderate – divergence may affect non-critical paths.
    Medium,
    /// Release-blocking – divergence affects correctness/security.
    High,
}

impl RiskTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// Identifies a reference runtime against which franken_engine is compared.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ReferenceRuntime {
    pub runtime_id: String,
    pub version: String,
}

/// A single divergence detected between franken_engine and a reference runtime.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BoundaryDivergence {
    pub divergence_id: String,
    pub boundary_name: String,
    pub franken_engine_output_digest: String,
    pub reference_output_digest: String,
    pub reference_runtime: ReferenceRuntime,
    pub risk_tier: RiskTier,
    pub classification_reason: String,
    pub l1_oracle_link: Option<String>,
}

/// Receipt that explicitly acknowledges a low/medium-risk delta.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyReceipt {
    pub receipt_id: String,
    pub divergence_id: String,
    pub risk_tier: RiskTier,
    pub justification: String,
    pub l1_oracle_result_link: String,
    pub issuer: String,
    pub issued_epoch_ms: u64,
}

/// Reason why the release gate blocked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseBlockReason {
    HighRiskUnresolved { divergence_ids: Vec<String> },
    MissingReceipt { divergence_ids: Vec<String> },
    L1LinkBroken { divergence_ids: Vec<String> },
    HarnessTimeout { elapsed_ms: u64, limit_ms: u64 },
    ReferenceUnavailable { runtime_id: String },
    ClassificationAmbiguous { divergence_id: String },
}

impl ReleaseBlockReason {
    pub fn error_code(&self) -> &'static str {
        match self {
            Self::HighRiskUnresolved { .. } => error_codes::ERR_ORACLE_HIGH_RISK_DELTA,
            Self::MissingReceipt { .. } => error_codes::ERR_ORACLE_MISSING_RECEIPT,
            Self::L1LinkBroken { .. } => error_codes::ERR_ORACLE_L1_LINK_BROKEN,
            Self::HarnessTimeout { .. } => error_codes::ERR_ORACLE_HARNESS_TIMEOUT,
            Self::ReferenceUnavailable { .. } => error_codes::ERR_ORACLE_REFERENCE_UNAVAILABLE,
            Self::ClassificationAmbiguous { .. } => {
                error_codes::ERR_ORACLE_CLASSIFICATION_AMBIGUOUS
            }
        }
    }
}

/// Outcome of the release gate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleaseVerdict {
    Passed,
    Blocked { reasons: Vec<ReleaseBlockReason> },
}

/// Result of running the N-version semantic oracle.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleResult {
    pub schema_version: String,
    pub verdict: ReleaseVerdict,
    pub divergences: Vec<BoundaryDivergence>,
    pub receipts: Vec<PolicyReceipt>,
    pub stats: OracleStats,
}

/// Summary statistics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OracleStats {
    pub total_boundaries_tested: usize,
    pub total_divergences: usize,
    pub high_risk_count: usize,
    pub medium_risk_count: usize,
    pub low_risk_count: usize,
    pub receipted_count: usize,
    pub unresolved_high_risk: usize,
}

// ── Harness configuration ──────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HarnessConfig {
    pub reference_runtimes: Vec<ReferenceRuntime>,
    pub timeout_ms: u64,
    pub require_l1_links: bool,
}

impl HarnessConfig {
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            reference_runtimes: Vec::new(),
            timeout_ms,
            require_l1_links: true,
        }
    }

    pub fn with_reference(mut self, runtime: ReferenceRuntime) -> Self {
        push_bounded(
            &mut self.reference_runtimes,
            runtime,
            MAX_REFERENCE_RUNTIMES,
        );
        self
    }
}

// ── Boundary sample (input/output pair for one boundary) ───────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BoundarySample {
    pub boundary_name: String,
    pub input: Vec<u8>,
    pub franken_engine_output: Vec<u8>,
    pub reference_outputs: BTreeMap<String, Vec<u8>>,
}

// ── Core harness logic ─────────────────────────────────────────────────

fn digest_bytes(data: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(b"n_version_oracle_v1:");
    h.update((data.len() as u64).to_le_bytes());
    h.update(data);
    hex::encode(h.finalize())
}

/// Classify divergence risk tier deterministically.
///
/// INV-ORACLE-DETERMINISTIC-CLASSIFICATION: same inputs always yield same tier.
pub fn classify_divergence(
    _boundary_name: &str,
    franken_digest: &str,
    reference_digest: &str,
    reference_count: usize,
    references_agree: bool,
) -> RiskTier {
    // If all references agree and disagree with franken_engine → high risk.
    // If references themselves disagree → medium risk.
    // If digests match → would not be called, but treat as low.
    if constant_time::ct_eq(franken_digest, reference_digest) {
        return RiskTier::Low;
    }
    if !references_agree || reference_count <= 1 {
        RiskTier::Medium
    } else {
        RiskTier::High
    }
}

/// Run the differential harness.
///
/// INV-ORACLE-HIGH-RISK-BLOCKS: high-risk unresolved deltas block release.
/// INV-ORACLE-LOW-RISK-RECEIPTED: low/medium risk deltas require receipts.
/// INV-ORACLE-L1-LINKAGE: receipts must link to L1 product-oracle results.
pub fn run_harness(
    config: &HarnessConfig,
    samples: &[BoundarySample],
    receipts: &[PolicyReceipt],
) -> OracleResult {
    let mut divergences = Vec::new();
    let mut div_counter = 0u64;

    // ORACLE_HARNESS_START
    let _ = event_codes::ORACLE_HARNESS_START;

    if config.reference_runtimes.is_empty() {
        return OracleResult {
            schema_version: SCHEMA_VERSION.to_string(),
            verdict: ReleaseVerdict::Blocked {
                reasons: vec![ReleaseBlockReason::ReferenceUnavailable {
                    runtime_id: "(none configured)".to_string(),
                }],
            },
            divergences: Vec::new(),
            receipts: receipts.to_vec(),
            stats: OracleStats {
                total_boundaries_tested: samples.len(),
                total_divergences: 0,
                high_risk_count: 0,
                medium_risk_count: 0,
                low_risk_count: 0,
                receipted_count: 0,
                unresolved_high_risk: 0,
            },
        };
    }

    // Build receipt index
    let receipt_index: BTreeMap<&str, &PolicyReceipt> = receipts
        .iter()
        .map(|r| (r.divergence_id.as_str(), r))
        .collect();

    let mut block_reasons: Vec<ReleaseBlockReason> = Vec::new();
    let mut high_risk_unresolved = Vec::new();
    let mut missing_receipt = Vec::new();
    let mut broken_l1 = Vec::new();

    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;
    let mut receipted = 0usize;

    for sample in samples {
        let fe_digest = digest_bytes(&sample.franken_engine_output);

        let mut available_refs = Vec::new();
        for rt in &config.reference_runtimes {
            if let Some(o) = sample.reference_outputs.get(&rt.runtime_id) {
                available_refs.push((rt.clone(), digest_bytes(o)));
            }
        }

        let references_agree = if available_refs.is_empty() {
            true
        } else {
            let first_ref_digest = &available_refs[0].1;
            available_refs
                .iter()
                .all(|(_, d)| constant_time::ct_eq(first_ref_digest, d))
        };

        for (rt, ref_digest) in available_refs {
            if !constant_time::ct_eq(&fe_digest, &ref_digest) {
                div_counter = div_counter.saturating_add(1);
                let risk_tier = classify_divergence(
                    &sample.boundary_name,
                    &fe_digest,
                    &ref_digest,
                    config.reference_runtimes.len(),
                    references_agree,
                );

                // ORACLE_DIVERGENCE_CLASSIFIED + ORACLE_RISK_TIER_ASSIGNED
                let _ = event_codes::ORACLE_DIVERGENCE_CLASSIFIED;
                let _ = event_codes::ORACLE_RISK_TIER_ASSIGNED;

                let reason = match risk_tier {
                    RiskTier::High => format!(
                        "High: divergence at {} against {} ({} reference runtime(s) configured)",
                        sample.boundary_name,
                        rt.runtime_id,
                        config.reference_runtimes.len()
                    ),
                    RiskTier::Medium => format!(
                        "Medium: single-reference divergence at {} against {}",
                        sample.boundary_name, rt.runtime_id
                    ),
                    RiskTier::Low => format!(
                        "Low: divergence below threshold at {} against {}",
                        sample.boundary_name, rt.runtime_id
                    ),
                };

                let div = BoundaryDivergence {
                    divergence_id: format!("div-{div_counter:04}"),
                    boundary_name: sample.boundary_name.clone(),
                    franken_engine_output_digest: fe_digest.clone(),
                    reference_output_digest: ref_digest,
                    reference_runtime: rt.clone(),
                    risk_tier,
                    classification_reason: reason,
                    l1_oracle_link: None,
                };

                match div.risk_tier {
                    RiskTier::High => {
                        high = high.saturating_add(1);
                        // INV-ORACLE-HIGH-RISK-BLOCKS: high risk always blocks.
                        push_bounded(
                            &mut high_risk_unresolved,
                            div.divergence_id.clone(),
                            MAX_DIVERGENCES,
                        );
                    }
                    RiskTier::Medium | RiskTier::Low => {
                        match div.risk_tier {
                            RiskTier::Medium => medium = medium.saturating_add(1),
                            RiskTier::Low => low = low.saturating_add(1),
                            _ => unreachable!("outer arm constrains to Medium|Low"),
                        }
                        match receipt_index.get(div.divergence_id.as_str()) {
                            Some(&receipt) => {
                                if receipt_invalid_for_divergence(receipt, &div) {
                                    push_bounded(
                                        &mut block_reasons,
                                        ReleaseBlockReason::ClassificationAmbiguous {
                                            divergence_id: div.divergence_id.clone(),
                                        },
                                        MAX_BLOCK_REASONS,
                                    );
                                } else if config.require_l1_links
                                    && receipt.l1_oracle_result_link.trim().is_empty()
                                {
                                    push_bounded(
                                        &mut broken_l1,
                                        div.divergence_id.clone(),
                                        MAX_DIVERGENCES,
                                    );
                                } else {
                                    // ORACLE_POLICY_RECEIPT_ISSUED
                                    let _ = event_codes::ORACLE_POLICY_RECEIPT_ISSUED;
                                    receipted = receipted.saturating_add(1);
                                }
                            }
                            None => {
                                // INV-ORACLE-LOW-RISK-RECEIPTED
                                push_bounded(
                                    &mut missing_receipt,
                                    div.divergence_id.clone(),
                                    MAX_DIVERGENCES,
                                );
                            }
                        }
                    }
                }

                push_bounded(&mut divergences, div, MAX_DIVERGENCES);
            }
        }
    }

    if !high_risk_unresolved.is_empty() {
        // ORACLE_RELEASE_BLOCKED
        let _ = event_codes::ORACLE_RELEASE_BLOCKED;
        push_bounded(
            &mut block_reasons,
            ReleaseBlockReason::HighRiskUnresolved {
                divergence_ids: high_risk_unresolved.clone(),
            },
            MAX_BLOCK_REASONS,
        );
    }
    if !missing_receipt.is_empty() {
        push_bounded(
            &mut block_reasons,
            ReleaseBlockReason::MissingReceipt {
                divergence_ids: missing_receipt,
            },
            MAX_BLOCK_REASONS,
        );
    }
    if !broken_l1.is_empty() {
        push_bounded(
            &mut block_reasons,
            ReleaseBlockReason::L1LinkBroken {
                divergence_ids: broken_l1,
            },
            MAX_BLOCK_REASONS,
        );
    }

    let verdict = if block_reasons.is_empty() {
        ReleaseVerdict::Passed
    } else {
        ReleaseVerdict::Blocked {
            reasons: block_reasons,
        }
    };

    OracleResult {
        schema_version: SCHEMA_VERSION.to_string(),
        verdict,
        divergences,
        receipts: receipts.to_vec(),
        stats: OracleStats {
            total_boundaries_tested: samples.len(),
            total_divergences: high + medium + low,
            high_risk_count: high,
            medium_risk_count: medium,
            low_risk_count: low,
            receipted_count: receipted,
            unresolved_high_risk: high_risk_unresolved.len(),
        },
    }
}

fn receipt_invalid_for_divergence(
    receipt: &PolicyReceipt,
    divergence: &BoundaryDivergence,
) -> bool {
    receipt.risk_tier != divergence.risk_tier
        || receipt.receipt_id.trim().is_empty()
        || receipt.justification.trim().is_empty()
        || receipt.issuer.trim().is_empty()
        || contains_nul(&receipt.receipt_id)
        || contains_nul(&receipt.justification)
        || contains_nul(&receipt.issuer)
        || contains_nul(&receipt.l1_oracle_result_link)
}

fn contains_nul(value: &str) -> bool {
    value.as_bytes().contains(&0)
}

/// Push an item to a bounded Vec, evicting oldest entries if at capacity.
fn push_bounded<T>(vec: &mut Vec<T>, item: T, max: usize) {
    if max == 0 {
        vec.clear();
        return;
    }
    if vec.len() >= max {
        let overflow = vec.len().saturating_sub(max).saturating_add(1);
        vec.drain(0..overflow.min(vec.len()));
    }
    vec.push(item);
}

// ── Unit tests ─────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_config() -> HarnessConfig {
        HarnessConfig::new(5000)
            .with_reference(ReferenceRuntime {
                runtime_id: "ref-a".into(),
                version: "1.0.0".into(),
            })
            .with_reference(ReferenceRuntime {
                runtime_id: "ref-b".into(),
                version: "1.0.0".into(),
            })
    }

    fn matching_sample() -> BoundarySample {
        let output = b"identical-output".to_vec();
        let mut refs = BTreeMap::new();
        refs.insert("ref-a".to_string(), output.clone());
        refs.insert("ref-b".to_string(), output.clone());
        BoundarySample {
            boundary_name: "boundary::state_transition".into(),
            input: b"input-1".to_vec(),
            franken_engine_output: output,
            reference_outputs: refs,
        }
    }

    fn diverging_sample() -> BoundarySample {
        let fe_out = b"franken-output".to_vec();
        let ref_out = b"reference-output".to_vec();
        let mut refs = BTreeMap::new();
        refs.insert("ref-a".to_string(), ref_out.clone());
        refs.insert("ref-b".to_string(), ref_out);
        BoundarySample {
            boundary_name: "boundary::event_encoding".into(),
            input: b"input-2".to_vec(),
            franken_engine_output: fe_out,
            reference_outputs: refs,
        }
    }

    fn low_risk_sample() -> BoundarySample {
        let fe_out = b"franken-low".to_vec();
        let ref_out = b"reference-low".to_vec();
        let mut refs = BTreeMap::new();
        // Only one reference runtime → classify_divergence returns Medium
        // We use a single-runtime config for this test.
        refs.insert("ref-a".to_string(), ref_out);
        BoundarySample {
            boundary_name: "boundary::ordering_hint".into(),
            input: b"input-3".to_vec(),
            franken_engine_output: fe_out,
            reference_outputs: refs,
        }
    }

    #[test]
    fn no_divergences_pass() {
        let cfg = sample_config();
        let result = run_harness(&cfg, &[matching_sample()], &[]);
        assert_eq!(result.verdict, ReleaseVerdict::Passed);
        assert_eq!(result.stats.total_divergences, 0);
    }

    #[test]
    fn high_risk_divergence_blocks_release() {
        // INV-ORACLE-HIGH-RISK-BLOCKS
        let cfg = sample_config();
        let result = run_harness(&cfg, &[diverging_sample()], &[]);
        match &result.verdict {
            ReleaseVerdict::Blocked { reasons } => {
                assert!(
                    reasons
                        .iter()
                        .any(|r| matches!(r, ReleaseBlockReason::HighRiskUnresolved { .. }))
                );
            }
            _ => unreachable!("expected blocked verdict"),
        }
        assert!(result.stats.high_risk_count > 0);
        assert!(result.stats.unresolved_high_risk > 0);
    }

    #[test]
    fn low_risk_without_receipt_blocks() {
        // INV-ORACLE-LOW-RISK-RECEIPTED
        let cfg = HarnessConfig::new(5000).with_reference(ReferenceRuntime {
            runtime_id: "ref-a".into(),
            version: "1.0.0".into(),
        });
        let result = run_harness(&cfg, &[low_risk_sample()], &[]);
        match &result.verdict {
            ReleaseVerdict::Blocked { reasons } => {
                assert!(
                    reasons
                        .iter()
                        .any(|r| matches!(r, ReleaseBlockReason::MissingReceipt { .. }))
                );
            }
            _ => unreachable!("expected blocked verdict for missing receipt"),
        }
    }

    #[test]
    fn low_risk_with_valid_receipt_passes() {
        let cfg = HarnessConfig::new(5000).with_reference(ReferenceRuntime {
            runtime_id: "ref-a".into(),
            version: "1.0.0".into(),
        });
        let samples = vec![low_risk_sample()];
        // First run to get divergence id
        let preliminary = run_harness(&cfg, &samples, &[]);
        assert!(!preliminary.divergences.is_empty());

        let div_id = preliminary.divergences[0].divergence_id.clone();
        let receipt = PolicyReceipt {
            receipt_id: "rcpt-001".into(),
            divergence_id: div_id,
            risk_tier: RiskTier::Medium,
            justification: "Ordering difference is cosmetic".into(),
            l1_oracle_result_link: "https://l1-oracle.example/result/42".into(),
            issuer: "policy-team".into(),
            issued_epoch_ms: 1_700_000_000_000,
        };
        let result = run_harness(&cfg, &samples, &[receipt]);
        assert_eq!(result.verdict, ReleaseVerdict::Passed);
        assert_eq!(result.stats.receipted_count, 1);
    }

    #[test]
    fn receipt_for_unknown_divergence_does_not_satisfy_gate() {
        let cfg = HarnessConfig::new(5000).with_reference(ReferenceRuntime {
            runtime_id: "ref-a".into(),
            version: "1.0.0".into(),
        });
        let receipt = PolicyReceipt {
            receipt_id: "rcpt-wrong-divergence".into(),
            divergence_id: "div-9999".into(),
            risk_tier: RiskTier::Medium,
            justification: "Receipt does not match the observed divergence".into(),
            l1_oracle_result_link: "https://l1-oracle.example/result/wrong".into(),
            issuer: "policy-team".into(),
            issued_epoch_ms: 1_700_000_000_000,
        };

        let result = run_harness(&cfg, &[low_risk_sample()], &[receipt]);

        assert_eq!(result.stats.receipted_count, 0);
        match &result.verdict {
            ReleaseVerdict::Blocked { reasons } => assert!(reasons.iter().any(|reason| {
                matches!(
                    reason,
                    ReleaseBlockReason::MissingReceipt { divergence_ids }
                        if divergence_ids == &vec!["div-0001".to_string()]
                )
            })),
            ReleaseVerdict::Passed => unreachable!("wrong divergence receipt must not pass"),
        }
    }

    #[test]
    fn receipt_with_broken_l1_link_blocks() {
        // INV-ORACLE-L1-LINKAGE
        let cfg = HarnessConfig::new(5000).with_reference(ReferenceRuntime {
            runtime_id: "ref-a".into(),
            version: "1.0.0".into(),
        });
        let samples = vec![low_risk_sample()];
        let preliminary = run_harness(&cfg, &samples, &[]);
        let div_id = preliminary.divergences[0].divergence_id.clone();
        let receipt = PolicyReceipt {
            receipt_id: "rcpt-002".into(),
            divergence_id: div_id,
            risk_tier: RiskTier::Medium,
            justification: "Ordering harmless".into(),
            l1_oracle_result_link: "".into(), // broken link
            issuer: "policy-team".into(),
            issued_epoch_ms: 1_700_000_000_000,
        };
        let result = run_harness(&cfg, &samples, &[receipt]);
        match &result.verdict {
            ReleaseVerdict::Blocked { reasons } => {
                assert!(
                    reasons
                        .iter()
                        .any(|r| matches!(r, ReleaseBlockReason::L1LinkBroken { .. }))
                );
            }
            _ => unreachable!("expected blocked verdict for broken L1 link"),
        }
    }

    #[test]
    fn broken_l1_link_is_not_counted_as_receipted() {
        let cfg = HarnessConfig::new(5000).with_reference(ReferenceRuntime {
            runtime_id: "ref-a".into(),
            version: "1.0.0".into(),
        });
        let samples = vec![low_risk_sample()];
        let preliminary = run_harness(&cfg, &samples, &[]);
        let receipt = PolicyReceipt {
            receipt_id: "rcpt-broken-l1".into(),
            divergence_id: preliminary.divergences[0].divergence_id.clone(),
            risk_tier: RiskTier::Medium,
            justification: "No linked L1 oracle result".into(),
            l1_oracle_result_link: String::new(),
            issuer: "policy-team".into(),
            issued_epoch_ms: 1_700_000_000_000,
        };

        let result = run_harness(&cfg, &samples, &[receipt]);

        assert_eq!(result.stats.receipted_count, 0);
        assert!(matches!(
            result.verdict,
            ReleaseVerdict::Blocked { reasons }
                if reasons.iter().any(|reason| matches!(reason, ReleaseBlockReason::L1LinkBroken { .. }))
        ));
    }

    #[test]
    fn high_risk_divergence_blocks_even_with_matching_receipts() {
        let cfg = sample_config();
        let samples = vec![diverging_sample()];
        let preliminary = run_harness(&cfg, &samples, &[]);
        let receipts = preliminary
            .divergences
            .iter()
            .map(|divergence| PolicyReceipt {
                receipt_id: format!("rcpt-{}", divergence.divergence_id),
                divergence_id: divergence.divergence_id.clone(),
                risk_tier: divergence.risk_tier,
                justification: "Attempted override for high risk divergence".into(),
                l1_oracle_result_link: "https://l1-oracle.example/result/high-risk".into(),
                issuer: "policy-team".into(),
                issued_epoch_ms: 1_700_000_000_000,
            })
            .collect::<Vec<_>>();

        let result = run_harness(&cfg, &samples, &receipts);

        assert_eq!(result.stats.receipted_count, 0);
        assert!(matches!(
            result.verdict,
            ReleaseVerdict::Blocked { reasons }
                if reasons.iter().any(|reason| matches!(reason, ReleaseBlockReason::HighRiskUnresolved { .. }))
        ));
    }

    #[test]
    fn receipt_for_only_one_medium_divergence_leaves_other_blocked() {
        let cfg = sample_config();
        let sample = BoundarySample {
            boundary_name: "boundary::reference_disagreement".into(),
            input: b"input-disagree".to_vec(),
            franken_engine_output: b"franken-output".to_vec(),
            reference_outputs: BTreeMap::from([
                ("ref-a".to_string(), b"reference-a".to_vec()),
                ("ref-b".to_string(), b"reference-b".to_vec()),
            ]),
        };
        let preliminary = run_harness(&cfg, std::slice::from_ref(&sample), &[]);
        let receipt = PolicyReceipt {
            receipt_id: "rcpt-one-medium".into(),
            divergence_id: preliminary.divergences[0].divergence_id.clone(),
            risk_tier: RiskTier::Medium,
            justification: "One reference disagreement was reviewed".into(),
            l1_oracle_result_link: "https://l1-oracle.example/result/medium".into(),
            issuer: "policy-team".into(),
            issued_epoch_ms: 1_700_000_000_000,
        };

        let result = run_harness(&cfg, &[sample], &[receipt]);

        assert_eq!(result.stats.medium_risk_count, 2);
        assert_eq!(result.stats.receipted_count, 1);
        assert!(matches!(
            result.verdict,
            ReleaseVerdict::Blocked { reasons }
                if reasons.iter().any(|reason| matches!(
                    reason,
                    ReleaseBlockReason::MissingReceipt { divergence_ids }
                        if divergence_ids == &vec!["div-0002".to_string()]
                ))
        ));
    }

    #[test]
    fn reference_disagreement_classifies_single_delta_as_medium_not_high() {
        let cfg = sample_config();
        let sample = BoundarySample {
            boundary_name: "boundary::split_vote".into(),
            input: b"input-split".to_vec(),
            franken_engine_output: b"franken-output".to_vec(),
            reference_outputs: BTreeMap::from([
                ("ref-a".to_string(), b"franken-output".to_vec()),
                ("ref-b".to_string(), b"reference-b".to_vec()),
            ]),
        };

        let result = run_harness(&cfg, &[sample], &[]);

        assert_eq!(result.stats.high_risk_count, 0);
        assert_eq!(result.stats.medium_risk_count, 1);
        assert!(matches!(
            result.verdict,
            ReleaseVerdict::Blocked { reasons }
                if reasons.iter().any(|reason| matches!(reason, ReleaseBlockReason::MissingReceipt { .. }))
        ));
    }

    #[test]
    fn configured_reference_without_sample_output_produces_no_false_pass_receipt_count() {
        let cfg = sample_config();
        let sample = BoundarySample {
            boundary_name: "boundary::missing_reference_output".into(),
            input: b"input-missing-ref".to_vec(),
            franken_engine_output: b"franken-output".to_vec(),
            reference_outputs: BTreeMap::from([("ref-a".to_string(), b"franken-output".to_vec())]),
        };
        let stale_receipt = PolicyReceipt {
            receipt_id: "rcpt-stale".into(),
            divergence_id: "div-0001".into(),
            risk_tier: RiskTier::Medium,
            justification: "Stale receipt should not be counted without divergence".into(),
            l1_oracle_result_link: "https://l1-oracle.example/result/stale".into(),
            issuer: "policy-team".into(),
            issued_epoch_ms: 1_700_000_000_000,
        };

        let result = run_harness(&cfg, &[sample], &[stale_receipt]);

        assert_eq!(result.verdict, ReleaseVerdict::Passed);
        assert_eq!(result.stats.total_divergences, 0);
        assert_eq!(result.stats.receipted_count, 0);
    }

    #[test]
    fn no_reference_runtimes_blocks() {
        let cfg = HarnessConfig::new(5000);
        let result = run_harness(&cfg, &[matching_sample()], &[]);
        match &result.verdict {
            ReleaseVerdict::Blocked { reasons } => {
                assert!(
                    reasons
                        .iter()
                        .any(|r| matches!(r, ReleaseBlockReason::ReferenceUnavailable { .. }))
                );
            }
            _ => unreachable!("expected blocked when no references configured"),
        }
    }

    #[test]
    fn classification_is_deterministic() {
        // INV-ORACLE-DETERMINISTIC-CLASSIFICATION
        let tier1 = classify_divergence("b1", "aaa", "bbb", 2, true);
        let tier2 = classify_divergence("b1", "aaa", "bbb", 2, true);
        assert_eq!(tier1, tier2);
    }

    #[test]
    fn risk_tier_ordering() {
        assert!(RiskTier::Low < RiskTier::Medium);
        assert!(RiskTier::Medium < RiskTier::High);
    }

    #[test]
    fn oracle_stats_counts_are_accurate() {
        let cfg = sample_config();
        let samples = vec![matching_sample(), diverging_sample()];
        let result = run_harness(&cfg, &samples, &[]);
        assert_eq!(result.stats.total_boundaries_tested, 2);
        // diverging_sample diverges against 2 references → 2 divergences
        assert!(result.stats.total_divergences >= 1);
    }

    #[test]
    fn release_block_reason_error_codes() {
        assert_eq!(
            ReleaseBlockReason::HighRiskUnresolved {
                divergence_ids: vec![]
            }
            .error_code(),
            error_codes::ERR_ORACLE_HIGH_RISK_DELTA
        );
        assert_eq!(
            ReleaseBlockReason::MissingReceipt {
                divergence_ids: vec![]
            }
            .error_code(),
            error_codes::ERR_ORACLE_MISSING_RECEIPT
        );
        assert_eq!(
            ReleaseBlockReason::HarnessTimeout {
                elapsed_ms: 0,
                limit_ms: 0
            }
            .error_code(),
            error_codes::ERR_ORACLE_HARNESS_TIMEOUT
        );
        assert_eq!(
            ReleaseBlockReason::ReferenceUnavailable {
                runtime_id: String::new()
            }
            .error_code(),
            error_codes::ERR_ORACLE_REFERENCE_UNAVAILABLE
        );
        assert_eq!(
            ReleaseBlockReason::ClassificationAmbiguous {
                divergence_id: String::new()
            }
            .error_code(),
            error_codes::ERR_ORACLE_CLASSIFICATION_AMBIGUOUS
        );
        assert_eq!(
            ReleaseBlockReason::L1LinkBroken {
                divergence_ids: vec![]
            }
            .error_code(),
            error_codes::ERR_ORACLE_L1_LINK_BROKEN
        );
    }

    #[test]
    fn schema_version_is_set() {
        let cfg = sample_config();
        let result = run_harness(&cfg, &[], &[]);
        assert_eq!(result.schema_version, SCHEMA_VERSION);
    }

    mod n_version_oracle_additional_negative_tests {
        use super::*;

        fn single_reference_config(require_l1_links: bool) -> HarnessConfig {
            let mut cfg = HarnessConfig::new(5000).with_reference(ReferenceRuntime {
                runtime_id: "ref-a".into(),
                version: "1.0.0".into(),
            });
            cfg.require_l1_links = require_l1_links;
            cfg
        }

        fn receipt(divergence_id: String, l1_link: &str) -> PolicyReceipt {
            PolicyReceipt {
                receipt_id: format!("rcpt-{divergence_id}"),
                divergence_id,
                risk_tier: RiskTier::Medium,
                justification: "reviewed medium-risk oracle delta".into(),
                l1_oracle_result_link: l1_link.into(),
                issuer: "policy-team".into(),
                issued_epoch_ms: 1_700_000_000_000,
            }
        }

        fn observed_divergence() -> (HarnessConfig, BoundarySample, String) {
            let cfg = single_reference_config(true);
            let sample = low_risk_sample();
            let preliminary = run_harness(&cfg, std::slice::from_ref(&sample), &[]);
            let divergence_id = preliminary.divergences[0].divergence_id.clone();
            (cfg, sample, divergence_id)
        }

        fn assert_classification_ambiguous(result: &OracleResult, divergence_id: &str) {
            assert_eq!(result.stats.receipted_count, 0);
            assert!(matches!(
                &result.verdict,
                ReleaseVerdict::Blocked { reasons }
                    if reasons.iter().any(|reason| matches!(
                        reason,
                        ReleaseBlockReason::ClassificationAmbiguous { divergence_id: id }
                            if id.as_str() == divergence_id
                    ))
            ));
        }

        #[test]
        fn push_bounded_zero_capacity_discards_without_panic() {
            let mut values = vec!["old-a".to_string(), "old-b".to_string()];

            push_bounded(&mut values, "new".to_string(), 0);

            assert!(values.is_empty());
        }

        #[test]
        fn push_bounded_over_capacity_retains_latest_window() {
            let mut values = vec![1, 2, 3, 4];

            push_bounded(&mut values, 99, 2);

            assert_eq!(values, vec![4, 99]);
        }

        #[test]
        fn receipt_with_whitespace_only_l1_link_blocks() {
            let cfg = single_reference_config(true);
            let sample = low_risk_sample();
            let preliminary = run_harness(&cfg, std::slice::from_ref(&sample), &[]);
            let receipt = receipt(preliminary.divergences[0].divergence_id.clone(), " \t\n ");

            let result = run_harness(&cfg, &[sample], &[receipt]);

            assert_eq!(result.stats.receipted_count, 0);
            assert!(matches!(
                result.verdict,
                ReleaseVerdict::Blocked { reasons }
                    if reasons.iter().any(|reason| matches!(
                        reason,
                        ReleaseBlockReason::L1LinkBroken { divergence_ids }
                            if divergence_ids == &vec!["div-0001".to_string()]
                    ))
            ));
        }

        #[test]
        fn duplicate_receipt_with_later_broken_l1_link_does_not_pass() {
            let cfg = single_reference_config(true);
            let sample = low_risk_sample();
            let preliminary = run_harness(&cfg, std::slice::from_ref(&sample), &[]);
            let divergence_id = preliminary.divergences[0].divergence_id.clone();
            let valid_receipt = receipt(
                divergence_id.clone(),
                "https://l1-oracle.example/result/valid",
            );
            let broken_receipt = receipt(divergence_id, "");

            let result = run_harness(&cfg, &[sample], &[valid_receipt, broken_receipt]);

            assert_eq!(result.stats.receipted_count, 0);
            assert!(matches!(
                result.verdict,
                ReleaseVerdict::Blocked { reasons }
                    if reasons.iter().any(|reason| matches!(
                        reason,
                        ReleaseBlockReason::L1LinkBroken { .. }
                    ))
            ));
        }

        #[test]
        fn empty_l1_link_is_accepted_only_when_linkage_not_required() {
            let cfg = single_reference_config(false);
            let sample = low_risk_sample();
            let preliminary = run_harness(&cfg, std::slice::from_ref(&sample), &[]);
            let receipt = receipt(preliminary.divergences[0].divergence_id.clone(), "");

            let result = run_harness(&cfg, &[sample], &[receipt]);

            assert_eq!(result.verdict, ReleaseVerdict::Passed);
            assert_eq!(result.stats.receipted_count, 1);
        }

        #[test]
        fn digest_bytes_distinguishes_empty_from_zero_byte_payload() {
            let empty_digest = digest_bytes(b"");
            let zero_digest = digest_bytes(&[0]);

            assert!(!constant_time::ct_eq(&empty_digest, &zero_digest));
        }

        #[test]
        fn digest_bytes_distinguishes_rebound_payload_bytes() {
            let joined_digest = digest_bytes(b"ab");
            let separated_digest = digest_bytes(b"a\0b");

            assert!(!constant_time::ct_eq(&joined_digest, &separated_digest));
        }

        #[test]
        fn single_reference_mismatch_is_never_classified_high_risk() {
            let tier = classify_divergence("boundary::single", "franken", "reference", 1, true);

            assert_eq!(tier, RiskTier::Medium);
        }

        #[test]
        fn receipt_with_mismatched_risk_tier_is_rejected() {
            let (cfg, sample, divergence_id) = observed_divergence();
            let mut mismatched_receipt = receipt(divergence_id.clone(), "https://l1/result/ok");
            mismatched_receipt.risk_tier = RiskTier::Low;

            let result = run_harness(&cfg, &[sample], &[mismatched_receipt]);

            assert_classification_ambiguous(&result, &divergence_id);
        }

        #[test]
        fn receipt_with_blank_receipt_id_is_rejected() {
            let (cfg, sample, divergence_id) = observed_divergence();
            let mut malformed_receipt = receipt(divergence_id.clone(), "https://l1/result/ok");
            malformed_receipt.receipt_id = " \t ".to_string();

            let result = run_harness(&cfg, &[sample], &[malformed_receipt]);

            assert_classification_ambiguous(&result, &divergence_id);
        }

        #[test]
        fn receipt_with_blank_issuer_is_rejected() {
            let (cfg, sample, divergence_id) = observed_divergence();
            let mut malformed_receipt = receipt(divergence_id.clone(), "https://l1/result/ok");
            malformed_receipt.issuer.clear();

            let result = run_harness(&cfg, &[sample], &[malformed_receipt]);

            assert_classification_ambiguous(&result, &divergence_id);
        }

        #[test]
        fn receipt_with_blank_justification_is_rejected() {
            let (cfg, sample, divergence_id) = observed_divergence();
            let mut malformed_receipt = receipt(divergence_id.clone(), "https://l1/result/ok");
            malformed_receipt.justification = "\n\t ".to_string();

            let result = run_harness(&cfg, &[sample], &[malformed_receipt]);

            assert_classification_ambiguous(&result, &divergence_id);
        }

        #[test]
        fn receipt_with_nul_in_receipt_id_is_rejected() {
            let (cfg, sample, divergence_id) = observed_divergence();
            let mut malformed_receipt = receipt(divergence_id.clone(), "https://l1/result/ok");
            malformed_receipt.receipt_id = "rcpt\0bad".to_string();

            let result = run_harness(&cfg, &[sample], &[malformed_receipt]);

            assert_classification_ambiguous(&result, &divergence_id);
        }

        #[test]
        fn receipt_with_nul_l1_link_is_rejected_even_when_link_not_required() {
            let mut cfg = single_reference_config(false);
            cfg.require_l1_links = false;
            let sample = low_risk_sample();
            let preliminary = run_harness(&cfg, std::slice::from_ref(&sample), &[]);
            let divergence_id = preliminary.divergences[0].divergence_id.clone();
            let malformed_receipt = receipt(divergence_id.clone(), "https://l1/result\0bad");

            let result = run_harness(&cfg, &[sample], &[malformed_receipt]);

            assert_classification_ambiguous(&result, &divergence_id);
        }

        #[test]
        fn receipt_with_nul_in_issuer_is_rejected() {
            let (cfg, sample, divergence_id) = observed_divergence();
            let mut malformed_receipt = receipt(divergence_id.clone(), "https://l1/result/ok");
            malformed_receipt.issuer = "policy\0team".to_string();

            let result = run_harness(&cfg, &[sample], &[malformed_receipt]);

            assert_classification_ambiguous(&result, &divergence_id);
        }

        #[test]
        fn receipt_with_nul_in_justification_is_rejected() {
            let (cfg, sample, divergence_id) = observed_divergence();
            let mut malformed_receipt = receipt(divergence_id.clone(), "https://l1/result/ok");
            malformed_receipt.justification = "reviewed\0delta".to_string();

            let result = run_harness(&cfg, &[sample], &[malformed_receipt]);

            assert_classification_ambiguous(&result, &divergence_id);
        }

        #[test]
        fn receipt_with_nul_l1_link_is_rejected_when_link_required() {
            let (cfg, sample, divergence_id) = observed_divergence();
            let malformed_receipt = receipt(divergence_id.clone(), "https://l1/result\0bad");

            let result = run_harness(&cfg, &[sample], &[malformed_receipt]);

            assert_classification_ambiguous(&result, &divergence_id);
        }

        #[test]
        fn duplicate_receipt_with_later_mismatched_risk_tier_is_rejected() {
            let (cfg, sample, divergence_id) = observed_divergence();
            let valid_receipt = receipt(divergence_id.clone(), "https://l1/result/ok");
            let mut later_receipt = receipt(divergence_id.clone(), "https://l1/result/ok");
            later_receipt.risk_tier = RiskTier::High;

            let result = run_harness(&cfg, &[sample], &[valid_receipt, later_receipt]);

            assert_classification_ambiguous(&result, &divergence_id);
        }

        #[test]
        fn duplicate_receipt_with_later_empty_justification_is_rejected() {
            let (cfg, sample, divergence_id) = observed_divergence();
            let valid_receipt = receipt(divergence_id.clone(), "https://l1/result/ok");
            let mut later_receipt = receipt(divergence_id.clone(), "https://l1/result/ok");
            later_receipt.justification.clear();

            let result = run_harness(&cfg, &[sample], &[valid_receipt, later_receipt]);

            assert_classification_ambiguous(&result, &divergence_id);
        }

        #[test]
        fn receipt_with_valid_fields_but_wrong_divergence_id_keeps_missing_receipt() {
            let (cfg, sample, divergence_id) = observed_divergence();
            let wrong_receipt = receipt("div-9999".to_string(), "https://l1/result/ok");

            let result = run_harness(&cfg, &[sample], &[wrong_receipt]);

            assert_eq!(result.stats.receipted_count, 0);
            assert!(matches!(
                result.verdict,
                ReleaseVerdict::Blocked { reasons }
                    if reasons.iter().any(|reason| matches!(
                        reason,
                        ReleaseBlockReason::MissingReceipt { divergence_ids }
                            if divergence_ids == &vec![divergence_id.clone()]
                    ))
            ));
        }

        #[test]
        fn receipt_with_high_risk_tier_for_medium_divergence_is_rejected() {
            let (cfg, sample, divergence_id) = observed_divergence();
            let mut malformed_receipt = receipt(divergence_id.clone(), "https://l1/result/ok");
            malformed_receipt.risk_tier = RiskTier::High;

            let result = run_harness(&cfg, &[sample], &[malformed_receipt]);

            assert_classification_ambiguous(&result, &divergence_id);
        }
    }
}
