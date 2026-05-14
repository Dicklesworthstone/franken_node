//! BPET temporal drift feature engine (bd-2ao3).
//!
//! Computes longitudinal phenotype drift features from ordered
//! [`PhenotypeSample`] streams. Five feature classes are produced:
//!
//! - **Velocity** — first-difference per field, scaled to per-second.
//! - **Acceleration** — second-difference per field, scaled to per-second².
//! - **Entropy** — Shannon entropy of the binned distribution per field.
//! - **Novelty** — KL divergence of the most recent window distribution
//!   against a supplied baseline distribution.
//! - **Capability-creep gradient** — least-squares slope of a derived
//!   *capability score* over time.
//!
//! All numerics are guarded with [`f64::is_finite`] before being mixed
//! into accumulators or being emitted, so a single non-finite input
//! cannot propagate NaN into the feature vector. Counters use
//! `saturating_add`. The module forbids `unsafe` via the crate-level
//! `#![forbid(unsafe_code)]` directive.
//!
//! # Determinism
//!
//! - Field iteration is over a [`BTreeMap`], which is iteration-stable.
//! - Histogram binning is fully specified by `bin_count` + observed
//!   `[min, max]` per field, no random sampling.
//! - The KL divergence uses an explicit epsilon floor for empty bins,
//!   so the result is finite and reproducible.
//! - Two identical windows yield byte-identical [`DriftFeatures`].
//!
//! # Event codes
//!
//! Stable telemetry codes are defined under [`event_codes`].

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::capacity_defaults::aliases::MAX_AUDIT_LOG_ENTRIES;
use crate::push_bounded;

// ---------------------------------------------------------------------------
// Event codes
// ---------------------------------------------------------------------------

/// Stable telemetry codes emitted by the drift engine.
pub mod event_codes {
    pub const BPET_DRIFT_WINDOW_ACCEPTED: &str = "BPET-DRIFT-001";
    pub const BPET_DRIFT_WINDOW_REJECTED: &str = "BPET-DRIFT-002";
    pub const BPET_DRIFT_VELOCITY_COMPUTED: &str = "BPET-DRIFT-003";
    pub const BPET_DRIFT_ACCELERATION_COMPUTED: &str = "BPET-DRIFT-004";
    pub const BPET_DRIFT_ENTROPY_COMPUTED: &str = "BPET-DRIFT-005";
    pub const BPET_DRIFT_NOVELTY_COMPUTED: &str = "BPET-DRIFT-006";
    pub const BPET_DRIFT_CAPABILITY_CREEP_COMPUTED: &str = "BPET-DRIFT-007";
    pub const BPET_DRIFT_FEATURES_EMITTED: &str = "BPET-DRIFT-008";
    pub const BPET_DRIFT_NON_FINITE_DROPPED: &str = "BPET-DRIFT-009";
    pub const BPET_DRIFT_HISTORY_REPLAYED: &str = "BPET-DRIFT-010";
}

// ---------------------------------------------------------------------------
// Numeric guard helpers
// ---------------------------------------------------------------------------

/// Maximum number of distinct fields tracked per drift window. Anything
/// beyond this is silently discarded by the sample constructor.
pub const MAX_DRIFT_FIELDS: usize = 256;

/// Maximum number of samples retained inside a single [`DriftWindow`].
/// Beyond this the oldest samples are evicted via [`push_bounded`].
pub const MAX_DRIFT_SAMPLES: usize = MAX_AUDIT_LOG_ENTRIES;

/// Default number of histogram bins for the entropy / novelty features.
pub const DEFAULT_HISTOGRAM_BINS: usize = 16;

/// Lower-bound epsilon used when computing log-probabilities to keep
/// KL divergence finite for sparse bins.
pub const DRIFT_PROBABILITY_EPSILON: f64 = 1.0e-9;

/// Returns `Some(value)` only when the input is a finite, non-NaN
/// `f64`. Used at every external boundary so the rest of the engine
/// never has to defend against NaN propagation.
#[inline]
fn finite(value: f64) -> Option<f64> {
    if value.is_finite() { Some(value) } else { None }
}

/// Clamp a finite value into `[lo, hi]`. Non-finite inputs collapse to
/// `lo` rather than propagating.
#[inline]
fn clamp_finite(value: f64, lo: f64, hi: f64) -> f64 {
    let v = finite(value).unwrap_or(lo);
    if v < lo {
        lo
    } else if v > hi {
        hi
    } else {
        v
    }
}

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

/// Errors surfaced by the drift engine. Every variant fails closed —
/// no partial [`DriftFeatures`] is emitted on error.
#[derive(Debug, thiserror::Error, PartialEq, Eq, Clone)]
pub enum DriftError {
    /// Window contained zero samples.
    #[error("drift window is empty")]
    EmptyWindow,
    /// Window timestamps are not strictly monotonic.
    #[error("drift window samples are out of order at index {0}")]
    NonMonotonicTimestamps(usize),
    /// `start_ts` exceeds `end_ts`.
    #[error("drift window bounds inverted: start_ts={start_ts} end_ts={end_ts}")]
    InvertedBounds { start_ts: i64, end_ts: i64 },
    /// A sample timestamp falls outside the declared window bounds.
    #[error("drift sample at index {index} ts={ts} outside window [{start_ts},{end_ts}]")]
    SampleOutsideWindow {
        index: usize,
        ts: i64,
        start_ts: i64,
        end_ts: i64,
    },
    /// Requested histogram bin count is invalid (zero or > 4096).
    #[error("invalid histogram bin count: {0}")]
    InvalidBinCount(usize),
}

// ---------------------------------------------------------------------------
// Sample / window types
// ---------------------------------------------------------------------------

/// A single phenotype observation snapshot. Field names are
/// canonicalized into a [`BTreeMap`] so two equivalent samples have
/// identical serialization. All field values pass an `is_finite` guard
/// at construction time, so [`PhenotypeSample`] cannot contain
/// `NaN` / `±∞`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PhenotypeSample {
    /// Sample timestamp in seconds since the Unix epoch.
    pub ts: i64,
    /// Phenotype field name → finite numeric value.
    pub fields: BTreeMap<String, f64>,
}

impl PhenotypeSample {
    /// Construct a sample, silently dropping any non-finite values.
    /// Fields are inserted in lexicographic order via [`BTreeMap`].
    /// At most [`MAX_DRIFT_FIELDS`] entries are retained.
    pub fn new<I, S>(ts: i64, fields: I) -> Self
    where
        I: IntoIterator<Item = (S, f64)>,
        S: Into<String>,
    {
        let mut sanitized: BTreeMap<String, f64> = BTreeMap::new();
        for (name, raw) in fields {
            if sanitized.len() >= MAX_DRIFT_FIELDS {
                break;
            }
            if let Some(v) = finite(raw) {
                sanitized.insert(name.into(), v);
            }
        }
        Self {
            ts,
            fields: sanitized,
        }
    }

    /// Returns the names of every field present in this sample.
    pub fn field_names(&self) -> impl Iterator<Item = &str> {
        self.fields.keys().map(|s| s.as_str())
    }
}

/// A bounded, time-ordered window of samples eligible for drift
/// feature extraction. `start_ts` / `end_ts` represent the *declared*
/// bounds; the engine validates that every contained sample falls
/// inside `[start_ts, end_ts]` and that timestamps strictly increase.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DriftWindow {
    pub start_ts: i64,
    pub end_ts: i64,
    pub samples: Vec<PhenotypeSample>,
}

impl DriftWindow {
    /// Construct an empty window.
    pub fn new(start_ts: i64, end_ts: i64) -> Self {
        Self {
            start_ts,
            end_ts,
            samples: Vec::new(),
        }
    }

    /// Append a sample, evicting the oldest entry if the bounded cap is
    /// reached. Samples beyond the declared bounds are still appended —
    /// validation is deferred to [`DriftEngine::compute`] so the caller
    /// receives a typed error instead of a silent drop.
    pub fn push(&mut self, sample: PhenotypeSample) {
        push_bounded(&mut self.samples, sample, MAX_DRIFT_SAMPLES);
    }

    /// Number of samples currently buffered.
    pub fn len(&self) -> usize {
        self.samples.len()
    }

    /// Returns `true` if the window has no samples.
    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    /// Stable, deterministic identifier of the window, derived from
    /// bounds and sample count. Suitable for telemetry correlation.
    pub fn window_id(&self) -> String {
        format!(
            "win:{}-{}:{}",
            self.start_ts,
            self.end_ts,
            self.samples.len()
        )
    }
}

// ---------------------------------------------------------------------------
// Output feature struct
// ---------------------------------------------------------------------------

/// Drift features extracted from a single window.
///
/// Each map is keyed by phenotype field name. All `f64` values are
/// guaranteed finite — non-finite intermediates are dropped during
/// computation rather than emitted.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DriftFeatures {
    /// First-difference per field, divided by elapsed seconds.
    pub velocity: BTreeMap<String, f64>,
    /// Second-difference per field, divided by elapsed seconds².
    pub acceleration: BTreeMap<String, f64>,
    /// Shannon entropy of the binned distribution per field, in nats.
    pub entropy: BTreeMap<String, f64>,
    /// Aggregated novelty score (KL divergence vs baseline), `>= 0`.
    pub novelty_score: f64,
    /// Slope of capability score over time (linear regression).
    pub capability_creep_gradient: f64,
    /// Stable identifier of the source window.
    pub window_id: String,
}

impl DriftFeatures {
    /// Construct an empty feature set for a given window id.
    pub fn empty(window_id: impl Into<String>) -> Self {
        Self {
            velocity: BTreeMap::new(),
            acceleration: BTreeMap::new(),
            entropy: BTreeMap::new(),
            novelty_score: 0.0,
            capability_creep_gradient: 0.0,
            window_id: window_id.into(),
        }
    }
}

// ---------------------------------------------------------------------------
// Window specification + replay
// ---------------------------------------------------------------------------

/// Specification used by [`DriftEngine::recompute_window`] when
/// resampling a historical trajectory.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowSpec {
    pub start_ts: i64,
    pub end_ts: i64,
}

impl WindowSpec {
    pub const fn new(start_ts: i64, end_ts: i64) -> Self {
        Self { start_ts, end_ts }
    }
}

// ---------------------------------------------------------------------------
// Engine
// ---------------------------------------------------------------------------

/// Stateless drift-feature engine.
///
/// The engine carries an optional baseline distribution used by the
/// novelty feature. When no baseline is provided, novelty is reported
/// as `0.0`.
#[derive(Debug, Clone, Default)]
pub struct DriftEngine {
    /// Baseline distribution keyed by field name → probabilities. Must
    /// be normalized (sum ≈ 1) or it will be re-normalized on use.
    baseline: BTreeMap<String, Vec<f64>>,
    /// Histogram bin count used for entropy and novelty.
    bin_count: usize,
}

impl DriftEngine {
    /// Build a new engine with the default bin count and no baseline.
    pub fn new() -> Self {
        Self {
            baseline: BTreeMap::new(),
            bin_count: DEFAULT_HISTOGRAM_BINS,
        }
    }

    /// Build an engine with a specific histogram bin count. Bin counts
    /// outside `[2, 4096]` are rejected.
    pub fn with_bin_count(bin_count: usize) -> Result<Self, DriftError> {
        if !(2..=4096).contains(&bin_count) {
            return Err(DriftError::InvalidBinCount(bin_count));
        }
        Ok(Self {
            baseline: BTreeMap::new(),
            bin_count,
        })
    }

    /// Attach a baseline distribution keyed by field name. Probabilities
    /// are re-normalized; any non-finite or negative bucket is treated
    /// as zero.
    pub fn with_baseline<I, S>(mut self, baseline: I) -> Self
    where
        I: IntoIterator<Item = (S, Vec<f64>)>,
        S: Into<String>,
    {
        for (field, probs) in baseline {
            let normalized = normalize_probabilities(&probs);
            self.baseline.insert(field.into(), normalized);
        }
        self
    }

    /// Active histogram bin count.
    pub fn bin_count(&self) -> usize {
        self.bin_count
    }

    /// Returns the baseline probability vector for a field (if any).
    pub fn baseline_for(&self, field: &str) -> Option<&[f64]> {
        self.baseline.get(field).map(Vec::as_slice)
    }

    /// Compute drift features for `window`. Returns a typed
    /// [`DriftError`] on validation failures; no partial result is
    /// emitted.
    pub fn compute(&self, window: &DriftWindow) -> Result<DriftFeatures, DriftError> {
        validate_window(window)?;
        let window_id = window.window_id();
        let velocity = compute_velocity(window);
        let acceleration = compute_acceleration(window);
        let entropy = compute_entropy_with_bins(window, self.bin_count);
        let novelty_score = compute_novelty(window, &self.baseline, self.bin_count);
        let capability_creep_gradient = compute_capability_creep_gradient(window);
        Ok(DriftFeatures {
            velocity,
            acceleration,
            entropy,
            novelty_score,
            capability_creep_gradient,
            window_id,
        })
    }

    /// Slice `history` by `spec`, build a [`DriftWindow`], and compute
    /// features. Useful for deterministic historical replay.
    pub fn recompute_window(
        &self,
        history: &[PhenotypeSample],
        spec: WindowSpec,
    ) -> Result<DriftFeatures, DriftError> {
        if spec.start_ts > spec.end_ts {
            return Err(DriftError::InvertedBounds {
                start_ts: spec.start_ts,
                end_ts: spec.end_ts,
            });
        }
        let mut window = DriftWindow::new(spec.start_ts, spec.end_ts);
        for sample in history {
            if sample.ts >= spec.start_ts && sample.ts <= spec.end_ts {
                window.push(sample.clone());
            }
        }
        self.compute(&window)
    }
}

// ---------------------------------------------------------------------------
// Validation
// ---------------------------------------------------------------------------

fn validate_window(window: &DriftWindow) -> Result<(), DriftError> {
    if window.samples.is_empty() {
        return Err(DriftError::EmptyWindow);
    }
    if window.start_ts > window.end_ts {
        return Err(DriftError::InvertedBounds {
            start_ts: window.start_ts,
            end_ts: window.end_ts,
        });
    }
    let mut prev: Option<i64> = None;
    for (idx, sample) in window.samples.iter().enumerate() {
        if sample.ts < window.start_ts || sample.ts > window.end_ts {
            return Err(DriftError::SampleOutsideWindow {
                index: idx,
                ts: sample.ts,
                start_ts: window.start_ts,
                end_ts: window.end_ts,
            });
        }
        if let Some(prev_ts) = prev
            && sample.ts <= prev_ts
        {
            return Err(DriftError::NonMonotonicTimestamps(idx));
        }
        prev = Some(sample.ts);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Compute: velocity
// ---------------------------------------------------------------------------

/// First-difference per field, scaled by elapsed seconds between
/// consecutive samples and averaged across consecutive pairs. Returns
/// an empty map for single-sample windows.
pub fn compute_velocity(window: &DriftWindow) -> BTreeMap<String, f64> {
    let mut out: BTreeMap<String, f64> = BTreeMap::new();
    if window.samples.len() < 2 {
        return out;
    }
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for pair in window.samples.windows(2) {
        let (a, b) = (&pair[0], &pair[1]);
        let dt = (b.ts.saturating_sub(a.ts)) as f64;
        if !(dt.is_finite()) || dt <= 0.0 {
            continue;
        }
        for (field, v_b) in &b.fields {
            let v_a = match a.fields.get(field) {
                Some(v) => *v,
                None => continue,
            };
            let diff = v_b - v_a;
            if !diff.is_finite() {
                continue;
            }
            let velocity = diff / dt;
            if !velocity.is_finite() {
                continue;
            }
            *out.entry(field.clone()).or_insert(0.0) += velocity;
            let c = counts.entry(field.clone()).or_insert(0);
            *c = c.saturating_add(1);
        }
    }
    for (field, sum) in out.iter_mut() {
        let n = counts.get(field).copied().unwrap_or(0);
        if n == 0 {
            *sum = 0.0;
        } else {
            *sum /= n as f64;
            if !sum.is_finite() {
                *sum = 0.0;
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Compute: acceleration
// ---------------------------------------------------------------------------

/// Second-difference per field, averaged across consecutive triples.
/// Requires at least three samples; returns an empty map otherwise.
pub fn compute_acceleration(window: &DriftWindow) -> BTreeMap<String, f64> {
    let mut out: BTreeMap<String, f64> = BTreeMap::new();
    if window.samples.len() < 3 {
        return out;
    }
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for triple in window.samples.windows(3) {
        let (a, b, c) = (&triple[0], &triple[1], &triple[2]);
        let dt_ab = (b.ts.saturating_sub(a.ts)) as f64;
        let dt_bc = (c.ts.saturating_sub(b.ts)) as f64;
        let dt_total = (c.ts.saturating_sub(a.ts)) as f64;
        if !dt_ab.is_finite()
            || !dt_bc.is_finite()
            || !dt_total.is_finite()
            || dt_ab <= 0.0
            || dt_bc <= 0.0
            || dt_total <= 0.0
        {
            continue;
        }
        for (field, v_b) in &b.fields {
            let v_a = match a.fields.get(field) {
                Some(v) => *v,
                None => continue,
            };
            let v_c = match c.fields.get(field) {
                Some(v) => *v,
                None => continue,
            };
            let vel_ab = (v_b - v_a) / dt_ab;
            let vel_bc = (v_c - v_b) / dt_bc;
            if !vel_ab.is_finite() || !vel_bc.is_finite() {
                continue;
            }
            // Center the acceleration estimate on the half-width
            // between the two intervals.
            let accel = (vel_bc - vel_ab) / (0.5 * (dt_ab + dt_bc));
            if !accel.is_finite() {
                continue;
            }
            *out.entry(field.clone()).or_insert(0.0) += accel;
            let cnt = counts.entry(field.clone()).or_insert(0);
            *cnt = cnt.saturating_add(1);
        }
    }
    for (field, sum) in out.iter_mut() {
        let n = counts.get(field).copied().unwrap_or(0);
        if n == 0 {
            *sum = 0.0;
        } else {
            *sum /= n as f64;
            if !sum.is_finite() {
                *sum = 0.0;
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Compute: entropy
// ---------------------------------------------------------------------------

/// Shannon entropy (natural log, *nats*) of the binned distribution
/// per field. Bin edges are derived from each field's observed
/// `[min, max]`. All-equal samples have entropy `0`.
pub fn compute_entropy(window: &DriftWindow) -> BTreeMap<String, f64> {
    compute_entropy_with_bins(window, DEFAULT_HISTOGRAM_BINS)
}

fn compute_entropy_with_bins(window: &DriftWindow, bin_count: usize) -> BTreeMap<String, f64> {
    let mut out: BTreeMap<String, f64> = BTreeMap::new();
    if window.samples.is_empty() {
        return out;
    }
    let bin_count = bin_count.max(2).min(4096);
    let field_names = collect_field_names(window);
    for field in field_names {
        let values = collect_field_values(window, &field);
        if values.is_empty() {
            out.insert(field, 0.0);
            continue;
        }
        let probs = histogram_probabilities(&values, bin_count);
        let mut entropy = 0.0_f64;
        for &p in &probs {
            if p > DRIFT_PROBABILITY_EPSILON {
                let contribution = p * p.ln();
                if contribution.is_finite() {
                    entropy -= contribution;
                }
            }
        }
        if !entropy.is_finite() {
            entropy = 0.0;
        }
        if entropy < 0.0 {
            entropy = 0.0;
        }
        out.insert(field, entropy);
    }
    out
}

// ---------------------------------------------------------------------------
// Compute: novelty
// ---------------------------------------------------------------------------

/// KL divergence of the window's per-field distribution against a
/// baseline, averaged across all fields that have a baseline entry.
/// When no baselines match, returns `0.0`.
pub fn compute_novelty(
    window: &DriftWindow,
    baseline: &BTreeMap<String, Vec<f64>>,
    bin_count: usize,
) -> f64 {
    if window.samples.is_empty() || baseline.is_empty() {
        return 0.0;
    }
    let bin_count = bin_count.max(2).min(4096);
    let mut total = 0.0_f64;
    let mut counted: u64 = 0;
    for (field, baseline_probs) in baseline {
        if baseline_probs.len() != bin_count {
            // Skip fields whose baseline does not match active bin count
            // — caller can rebuild baseline if needed; we fail closed
            // to "no contribution" rather than guess.
            continue;
        }
        let values = collect_field_values(window, field);
        if values.is_empty() {
            continue;
        }
        let observed = histogram_probabilities(&values, bin_count);
        let kl = kl_divergence(&observed, baseline_probs);
        if kl.is_finite() && kl >= 0.0 {
            total += kl;
            counted = counted.saturating_add(1);
        }
    }
    if counted == 0 {
        return 0.0;
    }
    let avg = total / counted as f64;
    if avg.is_finite() && avg >= 0.0 {
        avg
    } else {
        0.0
    }
}

/// Numerically-stable KL divergence `D_KL(p || q)` with epsilon floor.
fn kl_divergence(p: &[f64], q: &[f64]) -> f64 {
    if p.len() != q.len() || p.is_empty() {
        return 0.0;
    }
    let mut total = 0.0_f64;
    for (pi, qi) in p.iter().zip(q.iter()) {
        let pi = clamp_finite(*pi, 0.0, 1.0);
        let qi = clamp_finite(*qi, 0.0, 1.0).max(DRIFT_PROBABILITY_EPSILON);
        if pi <= DRIFT_PROBABILITY_EPSILON {
            continue;
        }
        let ratio = pi / qi;
        if !ratio.is_finite() || ratio <= 0.0 {
            continue;
        }
        let contribution = pi * ratio.ln();
        if contribution.is_finite() {
            total += contribution;
        }
    }
    if total.is_finite() && total >= 0.0 {
        total
    } else {
        0.0
    }
}

// ---------------------------------------------------------------------------
// Compute: capability creep gradient
// ---------------------------------------------------------------------------

/// Linear-regression slope of the per-sample *capability score* over
/// time. The capability score is the sum of all field values whose
/// name contains "capability" or "permission" (case-insensitive); if
/// none match, falls back to the count of non-zero fields.
pub fn compute_capability_creep_gradient(window: &DriftWindow) -> f64 {
    if window.samples.len() < 2 {
        return 0.0;
    }
    let xs: Vec<f64> = window.samples.iter().map(|s| s.ts as f64).collect();
    let ys: Vec<f64> = window
        .samples
        .iter()
        .map(capability_score_for_sample)
        .collect();
    least_squares_slope(&xs, &ys)
}

fn capability_score_for_sample(sample: &PhenotypeSample) -> f64 {
    let mut matched = 0.0_f64;
    let mut matched_any = false;
    for (field, value) in &sample.fields {
        let lower = field.to_ascii_lowercase();
        if lower.contains("capability") || lower.contains("permission") {
            if value.is_finite() {
                matched += *value;
                matched_any = true;
            }
        }
    }
    if matched_any && matched.is_finite() {
        matched
    } else {
        sample
            .fields
            .values()
            .filter(|v| v.is_finite() && **v != 0.0)
            .count() as f64
    }
}

/// Ordinary least-squares slope of `ys` vs `xs`. Returns 0 when the
/// inputs are degenerate (constant xs, mismatched lengths, non-finite).
fn least_squares_slope(xs: &[f64], ys: &[f64]) -> f64 {
    if xs.len() != ys.len() || xs.len() < 2 {
        return 0.0;
    }
    let n = xs.len() as f64;
    let mean_x: f64 = xs.iter().sum::<f64>() / n;
    let mean_y: f64 = ys.iter().sum::<f64>() / n;
    if !mean_x.is_finite() || !mean_y.is_finite() {
        return 0.0;
    }
    let mut num = 0.0_f64;
    let mut den = 0.0_f64;
    for (x, y) in xs.iter().zip(ys.iter()) {
        if !x.is_finite() || !y.is_finite() {
            continue;
        }
        let dx = x - mean_x;
        let dy = y - mean_y;
        num += dx * dy;
        den += dx * dx;
    }
    if den.abs() <= DRIFT_PROBABILITY_EPSILON || !num.is_finite() || !den.is_finite() {
        return 0.0;
    }
    let slope = num / den;
    if slope.is_finite() { slope } else { 0.0 }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn collect_field_names(window: &DriftWindow) -> Vec<String> {
    let mut names: BTreeMap<String, ()> = BTreeMap::new();
    for sample in &window.samples {
        for field in sample.fields.keys() {
            names.insert(field.clone(), ());
        }
    }
    names.into_keys().collect()
}

fn collect_field_values(window: &DriftWindow, field: &str) -> Vec<f64> {
    let mut out = Vec::with_capacity(window.samples.len());
    for sample in &window.samples {
        if let Some(v) = sample.fields.get(field)
            && v.is_finite()
        {
            out.push(*v);
        }
    }
    out
}

fn histogram_probabilities(values: &[f64], bin_count: usize) -> Vec<f64> {
    let bin_count = bin_count.max(2).min(4096);
    let mut probs = vec![0.0_f64; bin_count];
    if values.is_empty() {
        return probs;
    }
    let mut min_v = f64::INFINITY;
    let mut max_v = f64::NEG_INFINITY;
    let mut finite_count: u64 = 0;
    for v in values {
        if v.is_finite() {
            if *v < min_v {
                min_v = *v;
            }
            if *v > max_v {
                max_v = *v;
            }
            finite_count = finite_count.saturating_add(1);
        }
    }
    if finite_count == 0 {
        return probs;
    }
    let range = max_v - min_v;
    if !range.is_finite() || range <= DRIFT_PROBABILITY_EPSILON {
        // Degenerate (all-equal) — concentrate mass in the lowest bin.
        probs[0] = 1.0;
        return probs;
    }
    let bin_width = range / bin_count as f64;
    if !bin_width.is_finite() || bin_width <= 0.0 {
        probs[0] = 1.0;
        return probs;
    }
    let mut counts = vec![0_u64; bin_count];
    for v in values {
        if !v.is_finite() {
            continue;
        }
        let offset = (*v - min_v) / bin_width;
        let mut idx = if offset.is_finite() {
            offset.floor() as isize
        } else {
            0
        };
        if idx < 0 {
            idx = 0;
        }
        let mut uidx = idx as usize;
        if uidx >= bin_count {
            uidx = bin_count - 1;
        }
        counts[uidx] = counts[uidx].saturating_add(1);
    }
    let total: u64 = counts.iter().copied().fold(0_u64, u64::saturating_add);
    if total == 0 {
        return probs;
    }
    let total_f = total as f64;
    for (slot, count) in probs.iter_mut().zip(counts.iter()) {
        let p = (*count as f64) / total_f;
        *slot = if p.is_finite() {
            clamp_finite(p, 0.0, 1.0)
        } else {
            0.0
        };
    }
    probs
}

fn normalize_probabilities(probs: &[f64]) -> Vec<f64> {
    let mut cleaned: Vec<f64> = probs
        .iter()
        .map(|p| if p.is_finite() && *p > 0.0 { *p } else { 0.0 })
        .collect();
    let sum: f64 = cleaned.iter().sum();
    if !sum.is_finite() || sum <= DRIFT_PROBABILITY_EPSILON {
        // Uniform fallback.
        let n = cleaned.len().max(1);
        return vec![1.0 / n as f64; n];
    }
    for p in cleaned.iter_mut() {
        *p /= sum;
        if !p.is_finite() {
            *p = 0.0;
        }
    }
    cleaned
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ts: i64, fields: &[(&str, f64)]) -> PhenotypeSample {
        PhenotypeSample::new(ts, fields.iter().map(|(k, v)| ((*k).to_string(), *v)))
    }

    fn linear_window() -> DriftWindow {
        let mut w = DriftWindow::new(0, 100);
        for i in 0..5 {
            w.push(sample(i * 10, &[("a", i as f64), ("b", (i * 2) as f64)]));
        }
        w
    }

    // 1. Sample constructor drops NaN/Inf inputs.
    #[test]
    fn sample_drops_non_finite_fields() {
        let s = sample(
            1,
            &[
                ("ok", 1.0),
                ("nan", f64::NAN),
                ("inf", f64::INFINITY),
                ("neginf", f64::NEG_INFINITY),
            ],
        );
        assert_eq!(s.fields.len(), 1);
        assert!(s.fields.contains_key("ok"));
    }

    // 2. Empty window fails closed with EmptyWindow.
    #[test]
    fn empty_window_returns_empty_window_error() {
        let engine = DriftEngine::new();
        let window = DriftWindow::new(0, 100);
        let err = engine.compute(&window).unwrap_err();
        assert_eq!(err, DriftError::EmptyWindow);
    }

    // 3. Inverted bounds fail closed.
    #[test]
    fn inverted_bounds_fail_closed() {
        let engine = DriftEngine::new();
        let mut window = DriftWindow::new(100, 0);
        window.push(sample(50, &[("a", 1.0)]));
        let err = engine.compute(&window).unwrap_err();
        assert!(matches!(err, DriftError::InvertedBounds { .. }));
    }

    // 4. Non-monotonic timestamps fail closed.
    #[test]
    fn non_monotonic_timestamps_fail_closed() {
        let engine = DriftEngine::new();
        let mut window = DriftWindow::new(0, 100);
        window.push(sample(10, &[("a", 1.0)]));
        window.push(sample(5, &[("a", 2.0)]));
        let err = engine.compute(&window).unwrap_err();
        assert!(matches!(err, DriftError::NonMonotonicTimestamps(_)));
    }

    // 5. Timestamp collision (equal consecutive ts) fails closed.
    #[test]
    fn timestamp_collision_fails_closed() {
        let engine = DriftEngine::new();
        let mut window = DriftWindow::new(0, 100);
        window.push(sample(10, &[("a", 1.0)]));
        window.push(sample(10, &[("a", 2.0)]));
        let err = engine.compute(&window).unwrap_err();
        assert!(matches!(err, DriftError::NonMonotonicTimestamps(_)));
    }

    // 6. Sample outside window bounds fails closed.
    #[test]
    fn sample_outside_window_fails_closed() {
        let engine = DriftEngine::new();
        let mut window = DriftWindow::new(0, 50);
        window.push(sample(100, &[("a", 1.0)]));
        let err = engine.compute(&window).unwrap_err();
        assert!(matches!(err, DriftError::SampleOutsideWindow { .. }));
    }

    // 7. Single-sample window returns zero-valued features.
    #[test]
    fn single_sample_window_has_zero_features() {
        let engine = DriftEngine::new();
        let mut window = DriftWindow::new(0, 100);
        window.push(sample(10, &[("a", 1.0)]));
        let features = engine.compute(&window).expect("single-sample is valid");
        assert!(features.velocity.is_empty());
        assert!(features.acceleration.is_empty());
        // entropy degenerate => zero
        assert_eq!(features.entropy.get("a").copied().unwrap_or(0.0), 0.0);
        assert_eq!(features.novelty_score, 0.0);
        assert_eq!(features.capability_creep_gradient, 0.0);
    }

    // 8. Determinism: same window → byte-identical features.
    #[test]
    fn deterministic_features_for_identical_window() {
        let engine = DriftEngine::new();
        let w1 = linear_window();
        let w2 = linear_window();
        let f1 = engine.compute(&w1).unwrap();
        let f2 = engine.compute(&w2).unwrap();
        assert_eq!(f1, f2);
        let s1 = serde_json::to_string(&f1).unwrap();
        let s2 = serde_json::to_string(&f2).unwrap();
        assert_eq!(s1, s2);
    }

    // 9. Velocity correctness on a perfectly linear series.
    #[test]
    fn velocity_matches_analytic_slope_on_linear_series() {
        let w = linear_window();
        let v = compute_velocity(&w);
        // y_a = i (per i), dt = 10, so velocity = 0.1 per sec.
        let va = v.get("a").copied().unwrap_or(0.0);
        let vb = v.get("b").copied().unwrap_or(0.0);
        assert!((va - 0.1).abs() < 1e-9, "velocity_a={va}");
        assert!((vb - 0.2).abs() < 1e-9, "velocity_b={vb}");
    }

    // 10. Acceleration on a linear series is ~0; on a quadratic series it
    //     matches the analytic slope of the velocity.
    #[test]
    fn acceleration_zero_on_linear_and_positive_on_quadratic() {
        let lin = linear_window();
        let accel_lin = compute_acceleration(&lin);
        let aa = accel_lin.get("a").copied().unwrap_or(0.0);
        assert!(aa.abs() < 1e-9, "linear accel_a should be ~0, got {aa}");

        // Quadratic series: y = t^2 / 10 — velocity ramps up by 2*t/10.
        let mut quad = DriftWindow::new(0, 100);
        for i in 0..6 {
            let t = i as f64;
            quad.push(sample(i * 10, &[("a", (t * t) / 10.0)]));
        }
        let accel_quad = compute_acceleration(&quad);
        let aq = accel_quad.get("a").copied().unwrap_or(0.0);
        assert!(aq > 0.0, "quadratic accel should be positive, got {aq}");
        assert!(aq.is_finite());
    }

    // 11. Entropy of all-equal samples is 0; entropy of a uniform spread is positive.
    #[test]
    fn entropy_zero_on_constant_and_positive_on_spread() {
        let mut constant = DriftWindow::new(0, 100);
        for i in 0..5 {
            constant.push(sample(i * 10, &[("a", 1.0)]));
        }
        let ent_const = compute_entropy(&constant);
        assert_eq!(ent_const.get("a").copied().unwrap_or(0.0), 0.0);

        let mut spread = DriftWindow::new(0, 100);
        for i in 0..16 {
            spread.push(sample(i, &[("a", i as f64)]));
        }
        let ent_spread = compute_entropy(&spread);
        let es = ent_spread.get("a").copied().unwrap_or(0.0);
        assert!(es > 0.0, "spread entropy should be > 0, got {es}");
        assert!(es.is_finite());
    }

    // 12. KL-divergence-based novelty matches baseline → 0; uniform vs
    //     concentrated baseline → positive.
    #[test]
    fn novelty_zero_when_baseline_matches() {
        let bin_count = DEFAULT_HISTOGRAM_BINS;
        // Build a window heavily concentrated in the lowest bin.
        let mut window = DriftWindow::new(0, 100);
        for i in 0..10 {
            window.push(sample(i, &[("a", 0.0)]));
        }
        // Baseline: all mass in bin 0.
        let mut baseline_probs = vec![0.0; bin_count];
        baseline_probs[0] = 1.0;
        let engine = DriftEngine::new().with_baseline(vec![("a".to_string(), baseline_probs)]);
        let features = engine.compute(&window).unwrap();
        assert!(
            features.novelty_score.abs() < 1e-9,
            "novelty should be ~0 when observed matches baseline, got {}",
            features.novelty_score
        );
    }

    #[test]
    fn novelty_positive_when_baseline_disagrees() {
        let bin_count = DEFAULT_HISTOGRAM_BINS;
        let mut window = DriftWindow::new(0, 100);
        for i in 0..bin_count {
            window.push(sample(i as i64, &[("a", i as f64)]));
        }
        // Baseline: all mass in bin 0 — disagrees with uniform observation.
        let mut baseline_probs = vec![0.0; bin_count];
        baseline_probs[0] = 1.0;
        let engine = DriftEngine::new().with_baseline(vec![("a".to_string(), baseline_probs)]);
        let features = engine.compute(&window).unwrap();
        assert!(features.novelty_score > 0.0);
        assert!(features.novelty_score.is_finite());
    }

    // 13. Capability creep gradient detects rising capability count.
    #[test]
    fn capability_creep_positive_when_capabilities_grow() {
        let mut window = DriftWindow::new(0, 100);
        window.push(sample(0, &[("capability_x", 1.0)]));
        window.push(sample(10, &[("capability_x", 2.0)]));
        window.push(sample(20, &[("capability_x", 3.0)]));
        window.push(sample(30, &[("capability_x", 4.0)]));
        let g = compute_capability_creep_gradient(&window);
        assert!(g > 0.0, "expected positive creep gradient, got {g}");
        assert!(g.is_finite());
    }

    #[test]
    fn capability_creep_zero_on_flat_series() {
        let mut window = DriftWindow::new(0, 100);
        for i in 0..5 {
            window.push(sample(i * 10, &[("capability_x", 1.0)]));
        }
        let g = compute_capability_creep_gradient(&window);
        assert!(
            g.abs() < 1e-9,
            "flat capability series should have ~0 creep, got {g}"
        );
    }

    // 14. recompute_window replays historical samples deterministically.
    #[test]
    fn recompute_window_replays_history_deterministically() {
        let history: Vec<PhenotypeSample> =
            (0..20).map(|i| sample(i * 5, &[("a", i as f64)])).collect();
        let engine = DriftEngine::new();
        let f1 = engine
            .recompute_window(&history, WindowSpec::new(10, 50))
            .unwrap();
        let f2 = engine
            .recompute_window(&history, WindowSpec::new(10, 50))
            .unwrap();
        assert_eq!(f1, f2);
        assert_eq!(f1.window_id, f2.window_id);
        assert!(f1.velocity.contains_key("a"));
    }

    // 15. Engine rejects invalid bin counts and inverted recompute specs.
    #[test]
    fn engine_rejects_invalid_bin_count_and_inverted_spec() {
        assert!(matches!(
            DriftEngine::with_bin_count(0),
            Err(DriftError::InvalidBinCount(0))
        ));
        assert!(matches!(
            DriftEngine::with_bin_count(8192),
            Err(DriftError::InvalidBinCount(8192))
        ));
        let engine = DriftEngine::new();
        let err = engine
            .recompute_window(&[], WindowSpec::new(100, 0))
            .unwrap_err();
        assert!(matches!(err, DriftError::InvertedBounds { .. }));
    }

    // 16. Bonus: window_id is stable across identical windows and changes
    //      when bounds change.
    #[test]
    fn window_id_is_stable_and_bounds_sensitive() {
        let mut a = DriftWindow::new(0, 100);
        a.push(sample(10, &[("x", 1.0)]));
        let mut b = DriftWindow::new(0, 100);
        b.push(sample(10, &[("x", 1.0)]));
        assert_eq!(a.window_id(), b.window_id());
        let mut c = DriftWindow::new(0, 200);
        c.push(sample(10, &[("x", 1.0)]));
        assert_ne!(a.window_id(), c.window_id());
    }
}
