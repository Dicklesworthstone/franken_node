//! Unified evolution-risk scorer (bd-1jpc, section 10.21).
//!
//! Combines four BPET-derived signals — drift, regime shift, hazard, and
//! provenance — into a single explainable risk score with a bootstrap
//! confidence interval and a per-feature contribution breakdown.
//!
//! Design contract:
//!
//! * **Explainability** — every score is paired with an `ExplanationVector`
//!   that reports the weighting policy version, the per-feature
//!   contributions (sorted deterministically), and the single
//!   `dominant_feature` driving the score.
//! * **Fail-closed numerics** — non-finite (`NaN` / `±Inf`) features and
//!   weights are rejected before any arithmetic. There is no silent
//!   sanitization path on the scoring boundary.
//! * **Deterministic bootstrap** — `compute_confidence_interval` uses a
//!   seeded `SmallPrng` so callers can reproduce the same lower/upper
//!   bounds bit-for-bit given identical inputs.
//! * **Weight policy invariant** — every `WeightingPolicy` constructor or
//!   external load goes through `WeightingPolicy::validate`, which enforces
//!   non-negativity, finiteness, and sum-to-one within
//!   [`SUM_TOLERANCE`](self::SUM_TOLERANCE).
//!
//! The default `WeightingPolicy::policy_v1()` weights are
//! `(drift=0.35, regime=0.25, hazard=0.30, provenance=0.10)` per the
//! section 10.21 catalog committed to
//! `artifacts/section_10_21/bd-1jpc/policy_v1_catalog.json`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Audit / observability event codes emitted by the scorer.
pub mod event_codes {
    pub const SCORER_RISK_COMPUTED: &str = "BPET-RISK-001";
    pub const SCORER_CI_COMPUTED: &str = "BPET-RISK-002";
    pub const SCORER_POLICY_VALIDATED: &str = "BPET-RISK-003";
    pub const SCORER_INPUT_REJECTED: &str = "BPET-RISK-004";
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// Schema version stamped onto every `ExplanationVector` for downstream
/// consumers that need to detect policy changes across releases.
pub const SCHEMA_VERSION: &str = "evolution-risk-scorer-v1";

/// Identifier reported by [`WeightingPolicy::policy_v1`].
pub const POLICY_V1_VERSION: &str = "policy_v1";

/// Tolerance used by [`WeightingPolicy::validate`] when checking the
/// sum-to-one invariant on weights.
pub const SUM_TOLERANCE: f64 = 1.0e-9;

/// Lower bound used when clamping bootstrap quantile indices.
const DEFAULT_LOWER_QUANTILE: f64 = 0.025;
/// Upper bound used when clamping bootstrap quantile indices.
const DEFAULT_UPPER_QUANTILE: f64 = 0.975;

/// Feature names — kept as constants so callers / tests can compare against
/// the same string the explanation vector uses.
pub mod feature_names {
    pub const DRIFT: &str = "drift";
    pub const REGIME_SHIFT: &str = "regime_shift";
    pub const HAZARD: &str = "hazard";
    pub const PROVENANCE: &str = "provenance";
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors emitted by the unified evolution-risk scorer.
#[derive(Debug, thiserror::Error)]
pub enum ScorerError {
    #[error("feature `{0}` is not finite (NaN or +/-Inf)")]
    NonFiniteFeature(&'static str),
    #[error("feature `{name}` is outside the permitted range [0, 1]: {value}")]
    FeatureOutOfRange { name: &'static str, value: f64 },
    #[error("weight `{0}` is not finite (NaN or +/-Inf)")]
    NonFiniteWeight(&'static str),
    #[error("weight `{name}` is negative: {value}")]
    NegativeWeight { name: &'static str, value: f64 },
    #[error("weights must sum to 1.0 within {tolerance:e}, got {actual}")]
    WeightsDoNotSumToOne { actual: f64, tolerance: f64 },
    #[error("bootstrap iteration count must be > 0")]
    ZeroBootstrapIterations,
    #[error("noise distribution std_dev must be finite and >= 0, got {0}")]
    InvalidNoiseStdDev(f64),
}

// ---------------------------------------------------------------------------
// FeatureVector
// ---------------------------------------------------------------------------

/// A four-dimensional feature vector consumed by [`compute_risk_score`].
///
/// All fields are expected to be normalized to `[0.0, 1.0]`; values outside
/// the range are rejected during validation.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct FeatureVector {
    pub drift: f64,
    pub regime_shift: f64,
    pub hazard: f64,
    pub provenance: f64,
}

impl FeatureVector {
    /// Construct a feature vector and validate inline.
    pub fn try_new(
        drift: f64,
        regime_shift: f64,
        hazard: f64,
        provenance: f64,
    ) -> Result<Self, ScorerError> {
        let fv = Self {
            drift,
            regime_shift,
            hazard,
            provenance,
        };
        fv.validate()?;
        Ok(fv)
    }

    /// Validate finiteness + [0, 1] range for every field.
    pub fn validate(&self) -> Result<(), ScorerError> {
        check_feature(feature_names::DRIFT, self.drift)?;
        check_feature(feature_names::REGIME_SHIFT, self.regime_shift)?;
        check_feature(feature_names::HAZARD, self.hazard)?;
        check_feature(feature_names::PROVENANCE, self.provenance)?;
        Ok(())
    }

    fn as_pairs(&self) -> [(&'static str, f64); 4] {
        [
            (feature_names::DRIFT, self.drift),
            (feature_names::REGIME_SHIFT, self.regime_shift),
            (feature_names::HAZARD, self.hazard),
            (feature_names::PROVENANCE, self.provenance),
        ]
    }
}

fn check_feature(name: &'static str, value: f64) -> Result<(), ScorerError> {
    if !value.is_finite() {
        return Err(ScorerError::NonFiniteFeature(name));
    }
    if !(0.0..=1.0).contains(&value) {
        return Err(ScorerError::FeatureOutOfRange { name, value });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// WeightingPolicy
// ---------------------------------------------------------------------------

/// A linear weighting policy over the four `FeatureVector` dimensions.
///
/// Validated to be finite, non-negative, and sum-to-one within
/// [`SUM_TOLERANCE`] on every entry point that consumes a policy.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct WeightingPolicy {
    pub drift_weight: f64,
    pub regime_weight: f64,
    pub hazard_weight: f64,
    pub provenance_weight: f64,
}

impl WeightingPolicy {
    /// The catalog `policy_v1` weights documented in
    /// `artifacts/section_10_21/bd-1jpc/policy_v1_catalog.json`.
    pub const fn policy_v1() -> Self {
        Self {
            drift_weight: 0.35,
            regime_weight: 0.25,
            hazard_weight: 0.30,
            provenance_weight: 0.10,
        }
    }

    /// Identifier (`"policy_v1"`) stamped onto explanation vectors derived
    /// from this policy when callers use [`compute_risk_score`].
    pub const fn version_label() -> &'static str {
        POLICY_V1_VERSION
    }

    /// Try to build a policy, validating finiteness + sum-to-one.
    pub fn try_new(
        drift_weight: f64,
        regime_weight: f64,
        hazard_weight: f64,
        provenance_weight: f64,
    ) -> Result<Self, ScorerError> {
        let p = Self {
            drift_weight,
            regime_weight,
            hazard_weight,
            provenance_weight,
        };
        p.validate()?;
        Ok(p)
    }

    /// Validate that all weights are finite, non-negative, and sum to ~1.
    pub fn validate(&self) -> Result<(), ScorerError> {
        check_weight(feature_names::DRIFT, self.drift_weight)?;
        check_weight(feature_names::REGIME_SHIFT, self.regime_weight)?;
        check_weight(feature_names::HAZARD, self.hazard_weight)?;
        check_weight(feature_names::PROVENANCE, self.provenance_weight)?;

        let sum =
            self.drift_weight + self.regime_weight + self.hazard_weight + self.provenance_weight;
        if !sum.is_finite() || (sum - 1.0).abs() > SUM_TOLERANCE {
            return Err(ScorerError::WeightsDoNotSumToOne {
                actual: sum,
                tolerance: SUM_TOLERANCE,
            });
        }
        Ok(())
    }

    fn weight_for(&self, name: &str) -> f64 {
        match name {
            feature_names::DRIFT => self.drift_weight,
            feature_names::REGIME_SHIFT => self.regime_weight,
            feature_names::HAZARD => self.hazard_weight,
            feature_names::PROVENANCE => self.provenance_weight,
            _ => 0.0,
        }
    }
}

impl Default for WeightingPolicy {
    fn default() -> Self {
        Self::policy_v1()
    }
}

fn check_weight(name: &'static str, value: f64) -> Result<(), ScorerError> {
    if !value.is_finite() {
        return Err(ScorerError::NonFiniteWeight(name));
    }
    if value < 0.0 {
        return Err(ScorerError::NegativeWeight { name, value });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ExplanationVector
// ---------------------------------------------------------------------------

/// Per-feature contribution report paired with every risk score.
///
/// `feature_contributions` is a `BTreeMap` so its serialized form is
/// deterministic (sorted by feature name).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExplanationVector {
    pub schema_version: String,
    pub feature_contributions: BTreeMap<String, f64>,
    pub dominant_feature: String,
    pub weighting_policy_version: String,
}

impl ExplanationVector {
    /// The sum of per-feature contributions, used as a sanity check; it
    /// should equal the headline risk score within float precision.
    pub fn total_contribution(&self) -> f64 {
        self.feature_contributions.values().sum()
    }
}

// ---------------------------------------------------------------------------
// ConfidenceInterval
// ---------------------------------------------------------------------------

/// Bootstrap confidence interval around a risk score.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConfidenceInterval {
    pub point: f64,
    pub lower: f64,
    pub upper: f64,
    pub n_bootstrap: usize,
}

impl ConfidenceInterval {
    /// Width of the interval, `upper - lower`.
    pub fn width(&self) -> f64 {
        self.upper - self.lower
    }
}

// ---------------------------------------------------------------------------
// NoiseDistribution
// ---------------------------------------------------------------------------

/// Synthetic feature-perturbation distribution used by
/// [`compute_confidence_interval`]. The bootstrap draws zero-mean Gaussian
/// noise with this standard deviation, clipping each perturbed feature
/// back into `[0, 1]` so the policy invariants hold for every replicate.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct NoiseDistribution {
    pub std_dev: f64,
    pub seed: u64,
}

impl NoiseDistribution {
    pub fn try_new(std_dev: f64, seed: u64) -> Result<Self, ScorerError> {
        if !std_dev.is_finite() || std_dev < 0.0 {
            return Err(ScorerError::InvalidNoiseStdDev(std_dev));
        }
        Ok(Self { std_dev, seed })
    }
}

impl Default for NoiseDistribution {
    fn default() -> Self {
        Self {
            std_dev: 0.05,
            seed: 0xB9E7C0DEC0DE_u64,
        }
    }
}

// ---------------------------------------------------------------------------
// Scoring
// ---------------------------------------------------------------------------

/// Compute the unified evolution-risk score with an explanation vector.
///
/// Returns `(score, explanation)` on success. Inputs are validated up
/// front — non-finite or out-of-range features and invalid weights yield
/// a [`ScorerError`].
pub fn compute_risk_score(
    features: &FeatureVector,
    policy: &WeightingPolicy,
) -> Result<(f64, ExplanationVector), ScorerError> {
    features.validate()?;
    policy.validate()?;

    let mut contributions: BTreeMap<String, f64> = BTreeMap::new();
    let mut score = 0.0_f64;
    let mut dominant = (feature_names::DRIFT, f64::NEG_INFINITY);

    for (name, value) in features.as_pairs().iter() {
        let weight = policy.weight_for(name);
        let contribution = weight * *value;
        score += contribution;
        contributions.insert((*name).to_string(), contribution);
        if contribution > dominant.1 {
            dominant = (*name, contribution);
        }
    }

    // Numeric safety: weighted sum of [0,1] features by non-negative weights
    // summing to 1 is in [0,1] modulo float epsilon; clamp defensively.
    if !score.is_finite() {
        return Err(ScorerError::NonFiniteFeature("aggregate_score"));
    }
    let score = score.clamp(0.0, 1.0);

    let explanation = ExplanationVector {
        schema_version: SCHEMA_VERSION.to_string(),
        feature_contributions: contributions,
        dominant_feature: dominant.0.to_string(),
        weighting_policy_version: WeightingPolicy::version_label().to_string(),
    };

    Ok((score, explanation))
}

/// Compute a percentile-based bootstrap confidence interval around the
/// risk score.
///
/// The bootstrap draws `n_bootstrap` synthetic feature vectors by adding
/// zero-mean Gaussian noise (via Box-Muller from a seeded `SmallPrng`) to
/// each feature, clipping back into `[0, 1]`, and recomputing the score.
/// The returned lower/upper bounds are the 2.5th and 97.5th percentiles of
/// the resulting score distribution; the point estimate is the score
/// computed on the unperturbed features.
pub fn compute_confidence_interval(
    features: &FeatureVector,
    policy: &WeightingPolicy,
    noise_distribution: &NoiseDistribution,
    n_bootstrap: usize,
) -> Result<ConfidenceInterval, ScorerError> {
    features.validate()?;
    policy.validate()?;
    if !noise_distribution.std_dev.is_finite() || noise_distribution.std_dev < 0.0 {
        return Err(ScorerError::InvalidNoiseStdDev(noise_distribution.std_dev));
    }
    if n_bootstrap == 0 {
        return Err(ScorerError::ZeroBootstrapIterations);
    }

    let (point, _) = compute_risk_score(features, policy)?;

    let mut prng = DeterministicPrng::new(noise_distribution.seed);
    let mut samples: Vec<f64> = Vec::with_capacity(n_bootstrap);

    for _ in 0..n_bootstrap {
        let perturbed = FeatureVector {
            drift: perturb(features.drift, noise_distribution.std_dev, &mut prng),
            regime_shift: perturb(features.regime_shift, noise_distribution.std_dev, &mut prng),
            hazard: perturb(features.hazard, noise_distribution.std_dev, &mut prng),
            provenance: perturb(features.provenance, noise_distribution.std_dev, &mut prng),
        };
        // perturb() guarantees the result is finite and in [0, 1], so the
        // policy is invariant-preserved; recompute without validation cost.
        let mut sample = 0.0_f64;
        for (name, value) in perturbed.as_pairs().iter() {
            sample += policy.weight_for(name) * *value;
        }
        sample = sample.clamp(0.0, 1.0);
        if !sample.is_finite() {
            return Err(ScorerError::NonFiniteFeature("bootstrap_sample"));
        }
        samples.push(sample);
    }

    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let lower = quantile(&samples, DEFAULT_LOWER_QUANTILE);
    let upper = quantile(&samples, DEFAULT_UPPER_QUANTILE);

    Ok(ConfidenceInterval {
        point,
        lower,
        upper,
        n_bootstrap,
    })
}

fn quantile(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let q = q.clamp(0.0, 1.0);
    let n = sorted.len();
    // Nearest-rank (R-1) quantile: idx = ceil(q * n) - 1, clamped to [0, n-1].
    let mut idx = (q * n as f64).ceil() as isize - 1;
    if idx < 0 {
        idx = 0;
    }
    let idx = idx as usize;
    sorted[idx.min(n - 1)]
}

/// Perturb a feature with a Gaussian sample and clip into [0, 1].
fn perturb(value: f64, std_dev: f64, prng: &mut DeterministicPrng) -> f64 {
    if std_dev == 0.0 {
        return value.clamp(0.0, 1.0);
    }
    let z = prng.standard_normal();
    let mut perturbed = value + std_dev * z;
    if !perturbed.is_finite() {
        // Defensive: collapse non-finite intermediate to the un-perturbed
        // feature; the outer pipeline still clamps to [0, 1].
        perturbed = value;
    }
    perturbed.clamp(0.0, 1.0)
}

// ---------------------------------------------------------------------------
// Deterministic PRNG (xorshift64*) + Box-Muller normal
// ---------------------------------------------------------------------------
//
// We implement a small deterministic PRNG inline so the scorer does not
// depend on the wider `rand` ecosystem. Two requirements drive this:
//
// 1. Bootstrap reproducibility: same seed must yield same CI.
// 2. `#![forbid(unsafe_code)]`: no unsafe blocks anywhere.
//
// xorshift64* by Marsaglia + a multiplier from Vigna's 2014 note is
// sufficient for bootstrap perturbation; it is *not* a CSPRNG and is not
// used for any cryptographic purpose.

struct DeterministicPrng {
    state: u64,
    cached_normal: Option<f64>,
}

impl DeterministicPrng {
    fn new(seed: u64) -> Self {
        // Avoid the all-zeros fixed point.
        let state = if seed == 0 { 0x9E37_79B9_7F4A_7C15 } else { seed };
        Self {
            state,
            cached_normal: None,
        }
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.state;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.state = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn next_f64_unit(&mut self) -> f64 {
        // 53-bit mantissa worth of uniform [0, 1).
        let bits = self.next_u64() >> 11;
        (bits as f64) * (1.0_f64 / ((1u64 << 53) as f64))
    }

    /// Box-Muller standard-normal sample.
    fn standard_normal(&mut self) -> f64 {
        if let Some(z) = self.cached_normal.take() {
            return z;
        }
        // Reject u1 == 0 to avoid ln(0); the next_f64_unit() draw is in
        // [0, 1) so this is exceedingly rare but handle it deterministically.
        let mut u1 = self.next_f64_unit();
        while u1 <= f64::EPSILON {
            u1 = self.next_f64_unit();
        }
        let u2 = self.next_f64_unit();
        let r = (-2.0 * u1.ln()).sqrt();
        let theta = 2.0 * std::f64::consts::PI * u2;
        let z0 = r * theta.cos();
        let z1 = r * theta.sin();
        self.cached_normal = Some(z1);
        z0
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn features(drift: f64, regime: f64, hazard: f64, provenance: f64) -> FeatureVector {
        FeatureVector {
            drift,
            regime_shift: regime,
            hazard,
            provenance,
        }
    }

    // -------------------------------------------------------------------
    // Weighting policy invariants
    // -------------------------------------------------------------------

    #[test]
    fn policy_v1_weights_sum_to_one() {
        let p = WeightingPolicy::policy_v1();
        let sum = p.drift_weight + p.regime_weight + p.hazard_weight + p.provenance_weight;
        assert!((sum - 1.0).abs() <= SUM_TOLERANCE, "policy_v1 sum = {sum}");
        assert!(p.validate().is_ok());
    }

    #[test]
    fn policy_v1_matches_section_10_21_catalog() {
        let p = WeightingPolicy::policy_v1();
        assert_eq!(p.drift_weight, 0.35);
        assert_eq!(p.regime_weight, 0.25);
        assert_eq!(p.hazard_weight, 0.30);
        assert_eq!(p.provenance_weight, 0.10);
        assert_eq!(WeightingPolicy::version_label(), "policy_v1");
    }

    #[test]
    fn policy_rejects_non_sum_to_one_weights() {
        let bad = WeightingPolicy::try_new(0.5, 0.5, 0.5, 0.5);
        assert!(matches!(
            bad,
            Err(ScorerError::WeightsDoNotSumToOne { .. })
        ));
    }

    #[test]
    fn policy_rejects_negative_weight() {
        let bad = WeightingPolicy::try_new(-0.1, 0.5, 0.4, 0.2);
        assert!(matches!(bad, Err(ScorerError::NegativeWeight { .. })));
    }

    #[test]
    fn policy_rejects_nan_weight() {
        let bad = WeightingPolicy::try_new(f64::NAN, 0.5, 0.4, 0.1);
        assert!(matches!(bad, Err(ScorerError::NonFiniteWeight(_))));
    }

    #[test]
    fn policy_rejects_inf_weight() {
        let bad = WeightingPolicy::try_new(f64::INFINITY, 0.5, 0.4, 0.1);
        assert!(matches!(bad, Err(ScorerError::NonFiniteWeight(_))));
    }

    // -------------------------------------------------------------------
    // Feature validation
    // -------------------------------------------------------------------

    #[test]
    fn feature_vector_rejects_nan() {
        let fv = features(f64::NAN, 0.2, 0.3, 0.4);
        let err = compute_risk_score(&fv, &WeightingPolicy::policy_v1()).unwrap_err();
        assert!(matches!(err, ScorerError::NonFiniteFeature(_)));
    }

    #[test]
    fn feature_vector_rejects_infinity() {
        let fv = features(0.1, f64::INFINITY, 0.3, 0.4);
        let err = compute_risk_score(&fv, &WeightingPolicy::policy_v1()).unwrap_err();
        assert!(matches!(err, ScorerError::NonFiniteFeature(_)));
    }

    #[test]
    fn feature_vector_rejects_out_of_range() {
        let fv = features(0.1, 0.2, 1.5, 0.4);
        let err = compute_risk_score(&fv, &WeightingPolicy::policy_v1()).unwrap_err();
        assert!(matches!(err, ScorerError::FeatureOutOfRange { .. }));
    }

    // -------------------------------------------------------------------
    // Score correctness + explanation
    // -------------------------------------------------------------------

    #[test]
    fn weighted_sum_matches_hand_computation() {
        let fv = features(0.6, 0.4, 0.5, 0.2);
        let p = WeightingPolicy::policy_v1();
        let (score, _) = compute_risk_score(&fv, &p).unwrap();
        let expected = 0.35 * 0.6 + 0.25 * 0.4 + 0.30 * 0.5 + 0.10 * 0.2;
        assert!((score - expected).abs() < 1e-12, "score={score} expected={expected}");
    }

    #[test]
    fn explanation_contributions_sum_to_score() {
        let fv = features(0.6, 0.4, 0.5, 0.2);
        let (score, exp) = compute_risk_score(&fv, &WeightingPolicy::policy_v1()).unwrap();
        assert!((exp.total_contribution() - score).abs() < 1e-12);
        assert_eq!(exp.schema_version, SCHEMA_VERSION);
        assert_eq!(exp.weighting_policy_version, POLICY_V1_VERSION);
        // All four features represented.
        assert_eq!(exp.feature_contributions.len(), 4);
    }

    #[test]
    fn explanation_identifies_drift_as_dominant_when_drift_is_extreme() {
        let fv = features(1.0, 0.0, 0.0, 0.0);
        let (_, exp) = compute_risk_score(&fv, &WeightingPolicy::policy_v1()).unwrap();
        assert_eq!(exp.dominant_feature, feature_names::DRIFT);
    }

    #[test]
    fn explanation_identifies_hazard_as_dominant_when_hazard_is_extreme() {
        let fv = features(0.0, 0.0, 1.0, 0.0);
        let (_, exp) = compute_risk_score(&fv, &WeightingPolicy::policy_v1()).unwrap();
        assert_eq!(exp.dominant_feature, feature_names::HAZARD);
    }

    // -------------------------------------------------------------------
    // Monotonicity (higher feature -> higher score, ceteris paribus)
    // -------------------------------------------------------------------

    #[test]
    fn higher_drift_yields_higher_score() {
        let p = WeightingPolicy::policy_v1();
        let low = compute_risk_score(&features(0.10, 0.3, 0.3, 0.3), &p)
            .unwrap()
            .0;
        let high = compute_risk_score(&features(0.90, 0.3, 0.3, 0.3), &p)
            .unwrap()
            .0;
        assert!(high > low, "expected monotonic in drift: low={low} high={high}");
    }

    #[test]
    fn higher_hazard_yields_higher_score() {
        let p = WeightingPolicy::policy_v1();
        let low = compute_risk_score(&features(0.3, 0.3, 0.10, 0.3), &p)
            .unwrap()
            .0;
        let high = compute_risk_score(&features(0.3, 0.3, 0.90, 0.3), &p)
            .unwrap()
            .0;
        assert!(high > low);
    }

    #[test]
    fn score_is_in_unit_interval() {
        let p = WeightingPolicy::policy_v1();
        for (d, r, h, pr) in [
            (0.0, 0.0, 0.0, 0.0),
            (1.0, 1.0, 1.0, 1.0),
            (0.5, 0.5, 0.5, 0.5),
            (0.3, 0.7, 0.2, 0.9),
        ] {
            let (score, _) = compute_risk_score(&features(d, r, h, pr), &p).unwrap();
            assert!((0.0..=1.0).contains(&score), "score out of [0,1]: {score}");
        }
    }

    // -------------------------------------------------------------------
    // Bootstrap CI: determinism + bound shape
    // -------------------------------------------------------------------

    #[test]
    fn bootstrap_is_deterministic_under_fixed_seed() {
        let fv = features(0.5, 0.4, 0.6, 0.3);
        let p = WeightingPolicy::policy_v1();
        let noise = NoiseDistribution::try_new(0.05, 42).unwrap();
        let ci_a = compute_confidence_interval(&fv, &p, &noise, 200).unwrap();
        let ci_b = compute_confidence_interval(&fv, &p, &noise, 200).unwrap();
        assert_eq!(ci_a, ci_b, "same seed must yield identical CI");
    }

    #[test]
    fn bootstrap_lower_le_upper_and_point_recorded() {
        let fv = features(0.5, 0.4, 0.6, 0.3);
        let p = WeightingPolicy::policy_v1();
        let noise = NoiseDistribution::try_new(0.05, 7).unwrap();
        let ci = compute_confidence_interval(&fv, &p, &noise, 500).unwrap();
        let (expected_point, _) = compute_risk_score(&fv, &p).unwrap();
        assert!(ci.lower <= ci.upper, "lower>upper: {ci:?}");
        assert!(ci.width() >= 0.0);
        assert_eq!(ci.n_bootstrap, 500);
        // The CI point is exactly the unperturbed score.
        assert!((ci.point - expected_point).abs() < 1e-12);
        // Both bounds land in [0, 1] because samples are clamped.
        assert!((0.0..=1.0).contains(&ci.lower));
        assert!((0.0..=1.0).contains(&ci.upper));
    }

    #[test]
    fn bootstrap_with_zero_noise_collapses_to_point_estimate() {
        let fv = features(0.5, 0.4, 0.6, 0.3);
        let p = WeightingPolicy::policy_v1();
        let noise = NoiseDistribution::try_new(0.0, 9).unwrap();
        let ci = compute_confidence_interval(&fv, &p, &noise, 100).unwrap();
        let (point, _) = compute_risk_score(&fv, &p).unwrap();
        assert!((ci.lower - point).abs() < 1e-12);
        assert!((ci.upper - point).abs() < 1e-12);
        assert!((ci.point - point).abs() < 1e-12);
    }

    #[test]
    fn bootstrap_rejects_zero_iterations() {
        let fv = features(0.5, 0.4, 0.6, 0.3);
        let p = WeightingPolicy::policy_v1();
        let noise = NoiseDistribution::default();
        let err = compute_confidence_interval(&fv, &p, &noise, 0).unwrap_err();
        assert!(matches!(err, ScorerError::ZeroBootstrapIterations));
    }

    #[test]
    fn bootstrap_rejects_non_finite_noise() {
        assert!(matches!(
            NoiseDistribution::try_new(f64::NAN, 1).unwrap_err(),
            ScorerError::InvalidNoiseStdDev(_)
        ));
        assert!(matches!(
            NoiseDistribution::try_new(-0.1, 1).unwrap_err(),
            ScorerError::InvalidNoiseStdDev(_)
        ));
    }

    #[test]
    fn bootstrap_rejects_invalid_features_before_iterating() {
        let bad = features(f64::NAN, 0.4, 0.6, 0.3);
        let p = WeightingPolicy::policy_v1();
        let noise = NoiseDistribution::try_new(0.05, 1).unwrap();
        let err = compute_confidence_interval(&bad, &p, &noise, 100).unwrap_err();
        assert!(matches!(err, ScorerError::NonFiniteFeature(_)));
    }

    #[test]
    fn explanation_contributions_are_deterministically_ordered() {
        let fv = features(0.5, 0.4, 0.6, 0.3);
        let (_, exp) = compute_risk_score(&fv, &WeightingPolicy::policy_v1()).unwrap();
        let keys: Vec<&String> = exp.feature_contributions.keys().collect();
        let mut sorted = keys.clone();
        sorted.sort();
        assert_eq!(keys, sorted, "BTreeMap should iterate in sorted key order");
    }
}
