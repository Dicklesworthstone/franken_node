//! Camouflage detection heuristics (bd-35m7.1 sub-task 2/5).
//!
//! Pure-Rust in-process detector that consumes a
//! [`TrajectorySeries`](crate::security::trajectory_gaming::TrajectorySeries)
//! and emits a bounded list of
//! [`CamouflageHint`](crate::security::trajectory_gaming::CamouflageHint)s
//! describing suspected trajectory-gaming behaviour. The runtime can use this
//! to short-circuit the Python verifier on the hot path; the verifier still
//! provides the ground-truth gate through fixture/report evidence, while
//! `ingest_verifier_hints` converts verifier output into typed runtime hints.
//!
//! Heuristics implemented here:
//!
//! * `detect_phase_shift` — adjacent-window mean-shift on the
//!   observed-capability vector.
//! * `detect_dropout` — declared capabilities that are missing or zero in the
//!   observed vector for >50% of a window.
//! * `detect_distribution_mismatch` — KL divergence between the observed and
//!   declared per-field distributions across the series.
//! * `detect_gradual_creep` — linear-regression slope of the
//!   observed/declared ratio across the series.
//!
//! All `f64` severity values are guarded with `is_finite()` and clamped to
//! `[0.0, 1.0]`. Hint growth is capped via the local `push_bounded` helper at
//! [`MAX_CAMOUFLAGE_HINTS_PER_SERIES`]. No unsafe code.

use std::collections::{BTreeMap, BTreeSet};

use crate::security::trajectory_gaming::{CamouflageHint, CamouflageKind, TrajectorySeries};

/// Hard upper bound on the number of hints a single detection pass may emit.
pub const MAX_CAMOUFLAGE_HINTS_PER_SERIES: usize = 256;

/// Smallest legal value for `min_samples_for_detection`.
///
/// All sub-detectors short-circuit with `NotEnoughSamples` below this floor.
pub const MIN_DETECTION_SAMPLES_FLOOR: usize = 4;

/// Hard upper bound on the size of the sliding analysis window.
pub const MAX_WINDOW_SIZE: usize = 4_096;

/// Configuration knobs for [`detect_camouflage`].
///
/// Every `f64` field must be finite (`is_finite()`) and within the documented
/// inclusive range; [`DetectorConfig::validate`] enforces this on entry to
/// [`detect_camouflage`] so non-finite numerics cannot poison downstream
/// severity arithmetic.
#[derive(Debug, Clone, PartialEq)]
pub struct DetectorConfig {
    /// Minimum delta between two adjacent window means to count as a phase
    /// shift, expressed in observed-capability units. Range: `(0.0, 1e6]`.
    pub phase_shift_threshold: f64,
    /// Fraction of declared capabilities that must be missing or zero in the
    /// observed vector to flag a dropout. Range: `(0.0, 1.0]`.
    pub dropout_threshold: f64,
    /// KL-divergence threshold (nats) above which an
    /// observed-vs-declared distribution pair is flagged. Range: `(0.0, 1e6]`.
    pub distribution_kl_threshold: f64,
    /// Linear-regression slope of the observed/declared ratio above which a
    /// gradual creep is flagged, in ratio-units per sample. Range:
    /// `(0.0, 1e6]`.
    pub creep_slope_threshold: f64,
    /// Minimum number of samples a series must have before any sub-detector
    /// will run. Floored at [`MIN_DETECTION_SAMPLES_FLOOR`].
    pub min_samples_for_detection: usize,
    /// Size of the sliding window used by phase-shift / dropout detectors.
    /// Range: `[2, MAX_WINDOW_SIZE]`.
    pub window_size: usize,
}

impl Default for DetectorConfig {
    fn default() -> Self {
        Self {
            phase_shift_threshold: 0.25,
            dropout_threshold: 0.5,
            distribution_kl_threshold: 0.5,
            creep_slope_threshold: 0.01,
            min_samples_for_detection: MIN_DETECTION_SAMPLES_FLOOR,
            window_size: 8,
        }
    }
}

impl DetectorConfig {
    /// Validate that all `f64` knobs are finite and within their advertised
    /// ranges. Returns [`DetectorError::InvalidConfig`] on the first violation.
    pub fn validate(&self) -> Result<(), DetectorError> {
        fn ok(v: f64, lo_exclusive: f64, hi_inclusive: f64) -> bool {
            v.is_finite() && v > lo_exclusive && v <= hi_inclusive
        }
        if !ok(self.phase_shift_threshold, 0.0, 1e6) {
            return Err(DetectorError::InvalidConfig);
        }
        if !ok(self.dropout_threshold, 0.0, 1.0) {
            return Err(DetectorError::InvalidConfig);
        }
        if !ok(self.distribution_kl_threshold, 0.0, 1e6) {
            return Err(DetectorError::InvalidConfig);
        }
        if !ok(self.creep_slope_threshold, 0.0, 1e6) {
            return Err(DetectorError::InvalidConfig);
        }
        if self.min_samples_for_detection < MIN_DETECTION_SAMPLES_FLOOR {
            return Err(DetectorError::InvalidConfig);
        }
        if self.window_size < 2 || self.window_size > MAX_WINDOW_SIZE {
            return Err(DetectorError::InvalidConfig);
        }
        Ok(())
    }
}

/// Errors produced by the in-process camouflage detector.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum DetectorError {
    #[error("invalid detector configuration (non-finite knob or out-of-range value)")]
    InvalidConfig,
    #[error("non-finite severity in computed hint")]
    NonFiniteSeverity,
    #[error("series has fewer than min_samples_for_detection samples")]
    NotEnoughSamples,
    #[error("computed sample index out of range")]
    IndexOutOfRange,
}

/// Compute camouflage hints for `series` under `config`.
///
/// Returns a bounded `Vec<CamouflageHint>` (≤ [`MAX_CAMOUFLAGE_HINTS_PER_SERIES`]).
/// Sub-detectors are run in deterministic order: phase shift, dropout,
/// distribution mismatch, gradual creep. The function is total over its inputs
/// once [`DetectorConfig::validate`] passes; the only error paths are
/// configuration validation and the sample-count floor.
pub fn detect_camouflage(
    series: &TrajectorySeries,
    config: &DetectorConfig,
) -> Result<Vec<CamouflageHint>, DetectorError> {
    config.validate()?;
    if series.samples.len() < config.min_samples_for_detection {
        return Err(DetectorError::NotEnoughSamples);
    }

    let mut hints: Vec<CamouflageHint> = Vec::new();

    for h in detect_phase_shift(series, config)? {
        push_bounded(&mut hints, h, MAX_CAMOUFLAGE_HINTS_PER_SERIES);
    }
    for h in detect_dropout(series, config)? {
        push_bounded(&mut hints, h, MAX_CAMOUFLAGE_HINTS_PER_SERIES);
    }
    for h in detect_distribution_mismatch(series, config)? {
        push_bounded(&mut hints, h, MAX_CAMOUFLAGE_HINTS_PER_SERIES);
    }
    for h in detect_gradual_creep(series, config)? {
        push_bounded(&mut hints, h, MAX_CAMOUFLAGE_HINTS_PER_SERIES);
    }

    // Final guard: validate every severity is finite + in [0, 1] before
    // returning. Sub-detectors already clamp, but defense-in-depth keeps the
    // contract auditable in one place.
    for h in &hints {
        if !h.severity.is_finite() || h.severity < 0.0 || h.severity > 1.0 {
            return Err(DetectorError::NonFiniteSeverity);
        }
        for &idx in &h.sample_indices {
            if idx >= series.samples.len() {
                return Err(DetectorError::IndexOutOfRange);
            }
        }
    }

    Ok(hints)
}

// ---------------------------------------------------------------------------
// Sub-detector 1: phase shift
// ---------------------------------------------------------------------------

/// Detect adjacent-window mean shifts in the observed-capability vector.
///
/// For each pair of consecutive non-overlapping windows of size `window_size`,
/// compute the per-field mean of the observed capability across each window
/// and emit a hint when any field's |mean(W2) - mean(W1)| exceeds
/// `phase_shift_threshold`.
pub fn detect_phase_shift(
    series: &TrajectorySeries,
    config: &DetectorConfig,
) -> Result<Vec<CamouflageHint>, DetectorError> {
    config.validate()?;
    if series.samples.len() < config.min_samples_for_detection {
        return Err(DetectorError::NotEnoughSamples);
    }
    let w = config.window_size;
    let n = series.samples.len();
    if n < w.saturating_mul(2) {
        return Ok(Vec::new());
    }

    let mut out: Vec<CamouflageHint> = Vec::new();
    let mut start = 0usize;
    while start.saturating_add(w.saturating_mul(2)) <= n {
        let w1_end = start.saturating_add(w);
        let w2_end = w1_end.saturating_add(w);
        let mean1 = window_observed_means(series, start, w1_end);
        let mean2 = window_observed_means(series, w1_end, w2_end);
        let mut max_delta: f64 = 0.0;
        let mut worst_field: Option<String> = None;
        // Union of keys across both windows so a field appearing only in one
        // counts as a delta from zero.
        let mut keys: BTreeSet<&str> = BTreeSet::new();
        for k in mean1.keys() {
            keys.insert(k.as_str());
        }
        for k in mean2.keys() {
            keys.insert(k.as_str());
        }
        for k in keys {
            let m1 = mean1.get(k).copied().unwrap_or(0.0);
            let m2 = mean2.get(k).copied().unwrap_or(0.0);
            if !m1.is_finite() || !m2.is_finite() {
                continue;
            }
            let delta = (m2 - m1).abs();
            if delta.is_finite() && delta > max_delta {
                max_delta = delta;
                worst_field = Some(k.to_string());
            }
        }
        if max_delta > config.phase_shift_threshold {
            let mut evidence: BTreeMap<String, f64> = BTreeMap::new();
            evidence.insert("mean_delta".to_string(), max_delta);
            evidence.insert(
                "window_start".to_string(),
                u32::try_from(start).unwrap_or(u32::MAX) as f64,
            );
            evidence.insert(
                "window_size".to_string(),
                u32::try_from(w).unwrap_or(u32::MAX) as f64,
            );
            if let Some(field) = worst_field {
                // We can't store strings in a BTreeMap<String, f64>; expose
                // the field via a hashed-style sidecar key. Downstream
                // consumers re-derive the field from the series + indices.
                evidence.insert(format!("field_hash::{field}"), 1.0);
            }
            let severity = clamp_unit(max_delta / (config.phase_shift_threshold * 4.0).max(1e-9));
            let mut indices: Vec<usize> = (start..w2_end).collect();
            indices.truncate(MAX_WINDOW_SIZE);
            out.push(CamouflageHint {
                kind: CamouflageKind::PhaseShift,
                severity,
                evidence,
                sample_indices: indices,
            });
        }
        start = start.saturating_add(w);
    }
    Ok(out)
}

fn window_observed_means(
    series: &TrajectorySeries,
    start: usize,
    end: usize,
) -> BTreeMap<String, f64> {
    let mut sums: BTreeMap<String, f64> = BTreeMap::new();
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    let lo = start.min(series.samples.len());
    let hi = end.min(series.samples.len());
    for s in &series.samples[lo..hi] {
        for (k, v) in &s.observed_capability {
            if !v.is_finite() {
                continue;
            }
            let entry = sums.entry(k.clone()).or_insert(0.0);
            *entry += *v;
            let cnt = counts.entry(k.clone()).or_insert(0);
            *cnt = cnt.saturating_add(1);
        }
    }
    let mut means: BTreeMap<String, f64> = BTreeMap::new();
    for (k, sum) in sums {
        let c = counts.get(&k).copied().unwrap_or(0);
        if c == 0 {
            continue;
        }
        let mean = sum / (c as f64);
        if mean.is_finite() {
            means.insert(k, mean);
        }
    }
    means
}

// ---------------------------------------------------------------------------
// Sub-detector 2: dropout
// ---------------------------------------------------------------------------

/// Flag windows where >`dropout_threshold` fraction of declared capabilities
/// are missing or zero in the observed vector.
pub fn detect_dropout(
    series: &TrajectorySeries,
    config: &DetectorConfig,
) -> Result<Vec<CamouflageHint>, DetectorError> {
    config.validate()?;
    if series.samples.len() < config.min_samples_for_detection {
        return Err(DetectorError::NotEnoughSamples);
    }
    let w = config.window_size;
    let n = series.samples.len();
    if w == 0 || n < w {
        return Ok(Vec::new());
    }

    let mut out: Vec<CamouflageHint> = Vec::new();
    let mut start = 0usize;
    while start.saturating_add(w) <= n {
        let end = start.saturating_add(w);
        let (dropouts, total) = window_dropout_ratio(series, start, end);
        if total == 0 {
            start = start.saturating_add(w);
            continue;
        }
        let ratio = (dropouts as f64) / (total as f64);
        if !ratio.is_finite() {
            start = start.saturating_add(w);
            continue;
        }
        if ratio > config.dropout_threshold {
            let mut evidence: BTreeMap<String, f64> = BTreeMap::new();
            evidence.insert("dropout_ratio".to_string(), ratio);
            evidence.insert("dropouts".to_string(), dropouts as f64);
            evidence.insert("declared_total".to_string(), total as f64);
            evidence.insert(
                "window_start".to_string(),
                u32::try_from(start).unwrap_or(u32::MAX) as f64,
            );
            let severity = clamp_unit(ratio);
            let indices: Vec<usize> = (start..end).collect();
            out.push(CamouflageHint {
                kind: CamouflageKind::Dropout,
                severity,
                evidence,
                sample_indices: indices,
            });
        }
        start = start.saturating_add(w);
    }
    Ok(out)
}

/// Returns `(dropouts, total)` where:
/// * `total` is the count of (sample, declared_key) pairs in the window with
///   a non-zero declared value (i.e. the agent claimed it would exercise the
///   capability),
/// * `dropouts` is how many of those pairs had a missing or zero observed
///   value (the agent silently dropped the claimed capability).
fn window_dropout_ratio(series: &TrajectorySeries, start: usize, end: usize) -> (u64, u64) {
    let lo = start.min(series.samples.len());
    let hi = end.min(series.samples.len());
    let mut dropouts: u64 = 0;
    let mut total: u64 = 0;
    for s in &series.samples[lo..hi] {
        for (k, dv) in &s.declared_capability {
            if !dv.is_finite() || *dv == 0.0 {
                continue;
            }
            total = total.saturating_add(1);
            let ov = s.observed_capability.get(k).copied().unwrap_or(0.0);
            if !ov.is_finite() || ov == 0.0 {
                dropouts = dropouts.saturating_add(1);
            }
        }
    }
    (dropouts, total)
}

// ---------------------------------------------------------------------------
// Sub-detector 3: distribution mismatch (KL divergence)
// ---------------------------------------------------------------------------

/// Compute KL(observed || declared) per field across the entire series and
/// emit a hint when any field's KL exceeds `distribution_kl_threshold`.
pub fn detect_distribution_mismatch(
    series: &TrajectorySeries,
    config: &DetectorConfig,
) -> Result<Vec<CamouflageHint>, DetectorError> {
    config.validate()?;
    if series.samples.len() < config.min_samples_for_detection {
        return Err(DetectorError::NotEnoughSamples);
    }
    if series.samples.is_empty() {
        return Ok(Vec::new());
    }

    // Collect all keys appearing in either observed or declared maps.
    let mut keys: BTreeSet<String> = BTreeSet::new();
    for s in &series.samples {
        for k in s.observed_capability.keys() {
            keys.insert(k.clone());
        }
        for k in s.declared_capability.keys() {
            keys.insert(k.clone());
        }
    }

    // Build empirical distributions per field by sample-index bucket: each
    // sample contributes its (clamped, non-negative, finite) value as an
    // unnormalised mass. We then normalise to a probability distribution.
    let n = series.samples.len();
    let mut out: Vec<CamouflageHint> = Vec::new();

    for k in keys {
        let mut obs: Vec<f64> = Vec::with_capacity(n);
        let mut decl: Vec<f64> = Vec::with_capacity(n);
        for s in &series.samples {
            let ov = s.observed_capability.get(&k).copied().unwrap_or(0.0);
            let dv = s.declared_capability.get(&k).copied().unwrap_or(0.0);
            obs.push(if ov.is_finite() { ov.max(0.0) } else { 0.0 });
            decl.push(if dv.is_finite() { dv.max(0.0) } else { 0.0 });
        }
        let kl = kl_divergence(&obs, &decl);
        if !kl.is_finite() {
            continue;
        }
        if kl > config.distribution_kl_threshold {
            let mut evidence: BTreeMap<String, f64> = BTreeMap::new();
            evidence.insert("kl_divergence".to_string(), kl);
            evidence.insert(
                "sample_count".to_string(),
                u32::try_from(n).unwrap_or(u32::MAX) as f64,
            );
            evidence.insert(format!("field_hash::{k}"), 1.0);
            let severity = clamp_unit(kl / (config.distribution_kl_threshold * 4.0).max(1e-9));
            // Reference every sample index since this divergence is series-wide.
            let mut indices: Vec<usize> = (0..n).collect();
            indices.truncate(MAX_WINDOW_SIZE);
            out.push(CamouflageHint {
                kind: CamouflageKind::DistributionMismatch,
                severity,
                evidence,
                sample_indices: indices,
            });
        }
    }
    Ok(out)
}

/// KL(p || q) over two unnormalised non-negative vectors of equal length.
///
/// Uses Laplace smoothing (`eps = 1e-9`) on both distributions to keep the
/// computation finite when either side has empty mass. Returns 0.0 if either
/// vector is empty or both are entirely zero after smoothing (degenerate
/// "no information" case).
fn kl_divergence(p_raw: &[f64], q_raw: &[f64]) -> f64 {
    if p_raw.is_empty() || q_raw.is_empty() || p_raw.len() != q_raw.len() {
        return 0.0;
    }
    let eps = 1e-9_f64;
    let p_sum: f64 = p_raw.iter().map(|v| v.max(0.0) + eps).sum();
    let q_sum: f64 = q_raw.iter().map(|v| v.max(0.0) + eps).sum();
    if !p_sum.is_finite() || !q_sum.is_finite() || p_sum <= 0.0 || q_sum <= 0.0 {
        return 0.0;
    }
    let mut kl = 0.0_f64;
    for (pv, qv) in p_raw.iter().zip(q_raw.iter()) {
        let p = (pv.max(0.0) + eps) / p_sum;
        let q = (qv.max(0.0) + eps) / q_sum;
        if !p.is_finite() || !q.is_finite() || p <= 0.0 || q <= 0.0 {
            continue;
        }
        let term = p * (p / q).ln();
        if term.is_finite() {
            kl += term;
        }
    }
    if kl.is_finite() { kl.max(0.0) } else { 0.0 }
}

// ---------------------------------------------------------------------------
// Sub-detector 4: gradual creep
// ---------------------------------------------------------------------------

/// Fit a least-squares linear regression of the observed/declared ratio over
/// the entire series and emit a hint when |slope| > `creep_slope_threshold`.
pub fn detect_gradual_creep(
    series: &TrajectorySeries,
    config: &DetectorConfig,
) -> Result<Vec<CamouflageHint>, DetectorError> {
    config.validate()?;
    if series.samples.len() < config.min_samples_for_detection {
        return Err(DetectorError::NotEnoughSamples);
    }
    let n = series.samples.len();
    if n < 2 {
        return Ok(Vec::new());
    }

    // For each field present in `declared_capability` of any sample, build
    // the per-sample ratio observed/declared. Aggregate ratios across fields
    // by averaging at each sample index, yielding a scalar time series we
    // can regress against the sample index.
    let mut ratios: Vec<f64> = Vec::with_capacity(n);
    for s in &series.samples {
        let mut sum = 0.0_f64;
        let mut cnt: u64 = 0;
        for (k, dv) in &s.declared_capability {
            if !dv.is_finite() || *dv == 0.0 {
                continue;
            }
            let ov = s.observed_capability.get(k).copied().unwrap_or(0.0);
            if !ov.is_finite() {
                continue;
            }
            let r = ov / *dv;
            if r.is_finite() {
                sum += r;
                cnt = cnt.saturating_add(1);
            }
        }
        let avg = if cnt == 0 { 0.0 } else { sum / (cnt as f64) };
        ratios.push(if avg.is_finite() { avg } else { 0.0 });
    }

    let slope = linreg_slope(&ratios);
    if !slope.is_finite() {
        return Ok(Vec::new());
    }
    if slope.abs() > config.creep_slope_threshold {
        let mut evidence: BTreeMap<String, f64> = BTreeMap::new();
        evidence.insert("slope".to_string(), slope);
        evidence.insert("abs_slope".to_string(), slope.abs());
        evidence.insert(
            "sample_count".to_string(),
            u32::try_from(n).unwrap_or(u32::MAX) as f64,
        );
        let severity = clamp_unit(slope.abs() / (config.creep_slope_threshold * 4.0).max(1e-9));
        let mut indices: Vec<usize> = (0..n).collect();
        indices.truncate(MAX_WINDOW_SIZE);
        return Ok(vec![CamouflageHint {
            kind: CamouflageKind::GradualCreep,
            severity,
            evidence,
            sample_indices: indices,
        }]);
    }
    Ok(Vec::new())
}

/// Least-squares slope of `y` vs. index `i = 0..y.len()`.
/// Returns 0.0 on degenerate input (len < 2, zero variance, non-finite values).
fn linreg_slope(y: &[f64]) -> f64 {
    let n = y.len();
    if n < 2 {
        return 0.0;
    }
    let n_f = n as f64;
    let mut sx = 0.0_f64;
    let mut sy = 0.0_f64;
    let mut sxy = 0.0_f64;
    let mut sxx = 0.0_f64;
    for (i, &yv) in y.iter().enumerate() {
        if !yv.is_finite() {
            return 0.0;
        }
        let x = i as f64;
        sx += x;
        sy += yv;
        sxy += x * yv;
        sxx += x * x;
    }
    let denom = n_f * sxx - sx * sx;
    if !denom.is_finite() || denom.abs() < 1e-12 {
        return 0.0;
    }
    let slope = (n_f * sxy - sx * sy) / denom;
    if slope.is_finite() { slope } else { 0.0 }
}

// ---------------------------------------------------------------------------
// Local helpers (bounded growth + severity clamp)
// ---------------------------------------------------------------------------

/// Local bounded-growth helper. Mirrors `crate::push_bounded` but is defined
/// here so the module compiles cleanly under `#[cfg(test)]` (the crate-level
/// helper lives in `lib.rs`, which is gated `cfg(not(test))`).
fn push_bounded<T>(items: &mut Vec<T>, item: T, cap: usize) {
    if cap == 0 {
        items.clear();
        return;
    }
    if items.len() >= cap {
        let overflow = items.len().saturating_sub(cap).saturating_add(1);
        let drain = overflow.min(items.len());
        items.drain(0..drain);
    }
    items.push(item);
}

/// Clamp `x` into `[0.0, 1.0]`, treating non-finite inputs as 0.0.
fn clamp_unit(x: f64) -> f64 {
    if !x.is_finite() {
        return 0.0;
    }
    x.clamp(0.0, 1.0)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::trajectory_gaming::{TrajectorySample, TrajectorySeries, append_sample};

    type SampleRow = (i64, BTreeMap<String, f64>, BTreeMap<String, f64>);

    fn cap(pairs: &[(&str, f64)]) -> BTreeMap<String, f64> {
        let mut m = BTreeMap::new();
        for (k, v) in pairs {
            m.insert((*k).to_string(), *v);
        }
        m
    }

    fn build_series(samples: &[SampleRow]) -> TrajectorySeries {
        let mut s = TrajectorySeries::new(0, i64::MAX).expect("valid window");
        for (ts, obs, decl) in samples {
            let sample =
                TrajectorySample::new(*ts, obs.clone(), decl.clone()).expect("finite values");
            append_sample(&mut s, sample).expect("append ok");
        }
        s
    }

    /// Generate `n` samples where the observed value is `low` for the first
    /// half and `high` for the second half — a classic phase shift.
    fn phase_shift_series(n: usize, low: f64, high: f64) -> TrajectorySeries {
        let mut rows: Vec<SampleRow> = Vec::new();
        for i in 0..n {
            let v = if i < n / 2 { low } else { high };
            rows.push((
                i as i64,
                cap(&[("net.egress", v)]),
                cap(&[("net.egress", 0.5)]),
            ));
        }
        build_series(&rows)
    }

    /// Generate `n` benign samples where observed ≈ declared and there is
    /// no drift, no dropout, and no distribution mismatch.
    fn benign_series(n: usize) -> TrajectorySeries {
        let mut rows: Vec<SampleRow> = Vec::new();
        for i in 0..n {
            rows.push((
                i as i64,
                cap(&[("net.egress", 0.30), ("fs.write", 0.10)]),
                cap(&[("net.egress", 0.30), ("fs.write", 0.10)]),
            ));
        }
        build_series(&rows)
    }

    #[test]
    fn synthetic_phase_shift_is_detected_at_correct_window() {
        let series = phase_shift_series(16, 0.05, 0.95);
        let config = DetectorConfig {
            phase_shift_threshold: 0.3,
            window_size: 4,
            min_samples_for_detection: 4,
            ..DetectorConfig::default()
        };
        let hints = detect_phase_shift(&series, &config).unwrap();
        assert!(
            hints.iter().any(|h| h.kind == CamouflageKind::PhaseShift),
            "expected at least one PhaseShift hint, got {hints:?}"
        );
        // The boundary window pair should reference samples around the midpoint.
        let mid_hint = hints
            .iter()
            .find(|h| h.sample_indices.contains(&7) && h.sample_indices.contains(&8))
            .expect("hint covering the midpoint");
        assert!(mid_hint.severity > 0.0 && mid_hint.severity <= 1.0);
    }

    #[test]
    fn non_camouflaged_series_returns_no_hints() {
        let series = benign_series(32);
        let hints = detect_camouflage(&series, &DetectorConfig::default()).unwrap();
        assert!(
            hints.is_empty(),
            "benign series should produce no hints, got {hints:?}"
        );
    }

    #[test]
    fn dropout_pattern_in_observed_capability_is_detected() {
        // 16 samples: declared has two capabilities; observed drops both
        // (zero) for the second half of every window.
        let mut rows: Vec<SampleRow> = Vec::new();
        for i in 0..16 {
            let obs = if i % 2 == 0 {
                cap(&[("net.egress", 0.30), ("fs.write", 0.10)])
            } else {
                cap(&[("net.egress", 0.0), ("fs.write", 0.0)])
            };
            rows.push((
                i as i64,
                obs,
                cap(&[("net.egress", 0.30), ("fs.write", 0.10)]),
            ));
        }
        let series = build_series(&rows);
        let config = DetectorConfig {
            dropout_threshold: 0.4,
            window_size: 4,
            min_samples_for_detection: 4,
            ..DetectorConfig::default()
        };
        let hints = detect_dropout(&series, &config).unwrap();
        assert!(
            hints.iter().any(|h| h.kind == CamouflageKind::Dropout),
            "expected Dropout hint, got {hints:?}"
        );
        for h in &hints {
            assert!(h.severity.is_finite());
            assert!(h.severity > 0.0 && h.severity <= 1.0);
        }
    }

    #[test]
    fn dropout_below_threshold_not_flagged() {
        // Only 10% of declared capabilities drop -> below 50% threshold.
        let mut rows: Vec<SampleRow> = Vec::new();
        for i in 0..20 {
            let obs = if i == 7 {
                cap(&[("net.egress", 0.0), ("fs.write", 0.10)])
            } else {
                cap(&[("net.egress", 0.30), ("fs.write", 0.10)])
            };
            rows.push((
                i as i64,
                obs,
                cap(&[("net.egress", 0.30), ("fs.write", 0.10)]),
            ));
        }
        let series = build_series(&rows);
        let config = DetectorConfig {
            dropout_threshold: 0.5,
            window_size: 4,
            min_samples_for_detection: 4,
            ..DetectorConfig::default()
        };
        let hints = detect_dropout(&series, &config).unwrap();
        assert!(
            hints.is_empty(),
            "low-dropout series should not flag, got {hints:?}"
        );
    }

    #[test]
    fn distribution_mismatch_via_kl_divergence_above_threshold() {
        // Observed concentrates all mass at one sample; declared is uniform.
        let mut rows: Vec<SampleRow> = Vec::new();
        for i in 0..16 {
            let obs_v = if i == 0 { 1.0 } else { 0.0 };
            rows.push((
                i as i64,
                cap(&[("net.egress", obs_v)]),
                cap(&[("net.egress", 1.0 / 16.0)]),
            ));
        }
        let series = build_series(&rows);
        let config = DetectorConfig {
            distribution_kl_threshold: 0.3,
            window_size: 4,
            min_samples_for_detection: 4,
            ..DetectorConfig::default()
        };
        let hints = detect_distribution_mismatch(&series, &config).unwrap();
        assert!(
            hints
                .iter()
                .any(|h| h.kind == CamouflageKind::DistributionMismatch),
            "expected DistributionMismatch hint, got {hints:?}"
        );
        for h in &hints {
            assert!(h.severity.is_finite() && (0.0..=1.0).contains(&h.severity));
        }
    }

    #[test]
    fn gradual_creep_linear_slope_above_threshold_detected() {
        // observed / declared ratio grows linearly from ~0.5 to ~1.5 over 20
        // samples, giving slope ≈ 0.05 per sample.
        let mut rows: Vec<SampleRow> = Vec::new();
        for i in 0..20 {
            let ratio = 0.5 + (i as f64) * 0.05;
            rows.push((
                i as i64,
                cap(&[("net.egress", ratio * 0.30)]),
                cap(&[("net.egress", 0.30)]),
            ));
        }
        let series = build_series(&rows);
        let config = DetectorConfig {
            creep_slope_threshold: 0.01,
            min_samples_for_detection: 4,
            window_size: 4,
            ..DetectorConfig::default()
        };
        let hints = detect_gradual_creep(&series, &config).unwrap();
        assert!(
            hints.iter().any(|h| h.kind == CamouflageKind::GradualCreep),
            "expected GradualCreep hint, got {hints:?}"
        );
        let h = &hints[0];
        let slope = h.evidence.get("slope").copied().unwrap();
        assert!(slope.is_finite());
        assert!(
            slope.abs() > 0.01,
            "slope below detection threshold: {slope}"
        );
    }

    #[test]
    fn gradual_creep_below_slope_threshold_not_flagged() {
        // Flat ratio = no creep.
        let mut rows: Vec<SampleRow> = Vec::new();
        for i in 0..20 {
            rows.push((
                i as i64,
                cap(&[("net.egress", 0.30)]),
                cap(&[("net.egress", 0.30)]),
            ));
        }
        let series = build_series(&rows);
        let config = DetectorConfig {
            creep_slope_threshold: 0.01,
            min_samples_for_detection: 4,
            window_size: 4,
            ..DetectorConfig::default()
        };
        let hints = detect_gradual_creep(&series, &config).unwrap();
        assert!(
            hints.is_empty(),
            "flat ratio should not flag, got {hints:?}"
        );
    }

    #[test]
    fn too_few_samples_returns_not_enough_samples() {
        let series = benign_series(2);
        let err = detect_camouflage(&series, &DetectorConfig::default()).unwrap_err();
        assert_eq!(err, DetectorError::NotEnoughSamples);
    }

    #[test]
    fn nan_threshold_in_config_rejected() {
        let mut bad = DetectorConfig::default();
        bad.phase_shift_threshold = f64::NAN;
        assert_eq!(bad.validate().unwrap_err(), DetectorError::InvalidConfig);

        let mut bad2 = DetectorConfig::default();
        bad2.dropout_threshold = f64::INFINITY;
        assert_eq!(bad2.validate().unwrap_err(), DetectorError::InvalidConfig);

        let mut bad3 = DetectorConfig::default();
        bad3.creep_slope_threshold = -0.1;
        assert_eq!(bad3.validate().unwrap_err(), DetectorError::InvalidConfig);

        let mut bad4 = DetectorConfig::default();
        bad4.distribution_kl_threshold = 0.0;
        assert_eq!(bad4.validate().unwrap_err(), DetectorError::InvalidConfig);

        let mut bad5 = DetectorConfig::default();
        bad5.window_size = 1;
        assert_eq!(bad5.validate().unwrap_err(), DetectorError::InvalidConfig);

        let mut bad6 = DetectorConfig::default();
        bad6.min_samples_for_detection = 1;
        assert_eq!(bad6.validate().unwrap_err(), DetectorError::InvalidConfig);

        // Surface the same error via the public entry point.
        let series = benign_series(32);
        let mut bad7 = DetectorConfig::default();
        bad7.phase_shift_threshold = f64::NAN;
        let err = detect_camouflage(&series, &bad7).unwrap_err();
        assert_eq!(err, DetectorError::InvalidConfig);
    }

    #[test]
    fn bounded_growth_caps_hints_at_256() {
        // Drive the bounded helper directly: feeding > MAX hints must cap.
        let mut hints: Vec<CamouflageHint> = Vec::new();
        for i in 0..(MAX_CAMOUFLAGE_HINTS_PER_SERIES + 50) {
            let h = CamouflageHint {
                kind: CamouflageKind::PhaseShift,
                severity: 0.5,
                evidence: BTreeMap::from([("idx".to_string(), i as f64)]),
                sample_indices: vec![],
            };
            push_bounded(&mut hints, h, MAX_CAMOUFLAGE_HINTS_PER_SERIES);
        }
        assert_eq!(hints.len(), MAX_CAMOUFLAGE_HINTS_PER_SERIES);
        // FIFO eviction: oldest entries dropped first; final entry retained.
        let last_idx = hints.last().unwrap().evidence.get("idx").copied().unwrap();
        assert!(
            (last_idx - ((MAX_CAMOUFLAGE_HINTS_PER_SERIES + 49) as f64)).abs() < 1e-9,
            "last hint idx = {last_idx}"
        );
    }

    #[test]
    fn detector_deterministic_same_input_same_output() {
        // Build an adversarial-shaped series with all four signal types active
        // and assert two runs produce byte-identical hint vectors.
        let mut rows: Vec<SampleRow> = Vec::new();
        for i in 0..32 {
            let phase_v = if i < 16 { 0.1 } else { 0.9 };
            let creep_ratio = 0.3 + (i as f64) * 0.02;
            rows.push((
                i as i64,
                cap(&[("net.egress", phase_v), ("fs.write", creep_ratio * 0.20)]),
                cap(&[("net.egress", 0.5), ("fs.write", 0.20)]),
            ));
        }
        let series = build_series(&rows);
        let config = DetectorConfig::default();
        let a = detect_camouflage(&series, &config).unwrap();
        let b = detect_camouflage(&series, &config).unwrap();
        assert_eq!(a, b);
        assert!(!a.is_empty(), "expected at least one hint from rich input");
    }

    #[test]
    fn sample_indices_in_hints_are_in_range() {
        let series = phase_shift_series(20, 0.05, 0.95);
        let config = DetectorConfig {
            phase_shift_threshold: 0.2,
            window_size: 4,
            min_samples_for_detection: 4,
            ..DetectorConfig::default()
        };
        let hints = detect_camouflage(&series, &config).unwrap();
        assert!(!hints.is_empty());
        let n = series.samples.len();
        for h in &hints {
            for &idx in &h.sample_indices {
                assert!(idx < n, "hint refs out-of-range idx {idx} (len {n})");
            }
        }
    }

    #[test]
    fn clamp_unit_handles_non_finite_and_extremes() {
        assert_eq!(clamp_unit(f64::NAN), 0.0);
        assert_eq!(clamp_unit(f64::INFINITY), 0.0);
        assert_eq!(clamp_unit(f64::NEG_INFINITY), 0.0);
        assert_eq!(clamp_unit(-1.0), 0.0);
        assert_eq!(clamp_unit(2.0), 1.0);
        assert!((clamp_unit(0.4) - 0.4).abs() < 1e-9);
    }

    #[test]
    fn kl_divergence_zero_when_distributions_match() {
        let p = [0.1, 0.2, 0.3, 0.4];
        let q = [0.1, 0.2, 0.3, 0.4];
        let kl = kl_divergence(&p, &q);
        assert!(kl.is_finite());
        assert!(
            kl < 1e-6,
            "KL of identical distributions should be ~0, got {kl}"
        );
    }

    #[test]
    fn linreg_slope_recovers_known_slope() {
        let y: Vec<f64> = (0..20).map(|i| 1.0 + 0.5 * (i as f64)).collect();
        let slope = linreg_slope(&y);
        assert!(
            (slope - 0.5).abs() < 1e-9,
            "expected slope 0.5, got {slope}"
        );
    }
}
